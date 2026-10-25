// MCP/OAuthのresolverが通常Bearer専用であることを、本物の固定oidc-provider（connect-kms-development profile・通信0）と限定adapter
// （ConnectStorage＋fake Firestore＋KMS port(operation=context.current)＋合成AES-GCM）で確かめる。公開SDK APIで保存したopaque AccessTokenの
// うち、通常のものは解決し、own jkt / x5t#S256（通常値・空・null・両方）を持つものはnullで、Grant/owner読取り0。元abortの固定非成功・
// 所有timer/listener 0・借用close 0も維持する。出力は試験名と件数だけ。
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { after, test } from 'node:test';

import { ConnectStorage } from '../dist/connect/firestore.js';
import { createConnectKmsSealingPort } from '../dist/connect/kms-port.js';
import { createOAuthProvider, resourceFor } from '../dist/oauth/provider.js';
import { createRequestAuthContext, createRequestScopedOAuthOwnerResolver, RequestAuthContextError } from '../dist/oauth/request-auth-runtime.js';
import { PRODUCT_POLICY } from '../dist/policy.js';
import { crc32c } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';

const PROJECT = 'demo-sttd-auth-bearer';
const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
const ISSUER = 'https://connect.sttd-auth.invalid';
const RESOURCE = resourceFor(ISSUER);
const CLIENT_ID = 'https://client.sttd-auth.invalid/client.json';
const NS = `t256_${randomUUID()}`;
const DAY = 86_400_000;

let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
const timeouts = () => process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
const baselineTimeouts = timeouts();
const clock = { now: () => Date.now() };
const op = (overrides = {}) => ({ deadlineAt: Date.now() + 20_000, signal: new AbortController().signal, ...overrides });

// ---------- 限定fake Firestore（get/set/deleteだけ、読取りの順を記録） ----------
const borrowed = { closes: 0 };
const docs = new Map();
const log = [];
function refOf(path) {
  return {
    path,
    id: path.split('/').pop(),
    collection: (name) => ({ doc: (id) => refOf(`${path}/${name}/${id}`) }),
    async set(data) {
      docs.set(path, structuredClone(data));
    },
    async update(partial) {
      docs.set(path, { ...docs.get(path), ...structuredClone(partial) });
    },
    async delete() {
      docs.delete(path);
    },
    async get() {
      log.push(path);
      const data = docs.get(path);
      return { exists: data !== undefined, updateTime: undefined, get: (field) => data?.[field], data: () => (data === undefined ? undefined : structuredClone(data)) };
    },
  };
}
const db = {
  collection: (name) => ({ doc: (id) => refOf(`${name}/${id}`) }),
  doc: (path) => refOf(path),
  runTransaction() {
    throw new Error('fake: no transaction in this unit');
  },
  terminate() {
    borrowed.closes += 1;
  },
};
const kindOf = (path) => (path.includes('/oidc/AccessToken_') ? 'token' : path.includes('/oidc/Grant_') ? 'grant' : path.includes('/owners/') ? 'owner' : 'other');

// ---------- 合成AES-GCM KMS ----------
const kmsKey = randomBytes(32);
const kmsStats = { encrypt: 0, decrypt: 0 };
const transport = {
  async encrypt(request) {
    kmsStats.encrypt += 1;
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kmsKey, iv);
    cipher.setAAD(request.additionalAuthenticatedData);
    const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
    const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
    return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
  },
  async decrypt(request) {
    kmsStats.decrypt += 1;
    const raw = request.ciphertext;
    const decipher = createDecipheriv('aes-256-gcm', kmsKey, raw.subarray(0, 12));
    decipher.setAAD(request.additionalAuthenticatedData);
    decipher.setAuthTag(raw.subarray(12, 28));
    const plaintext = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
    return { plaintext, plaintextCrc32c: crc32c(plaintext), protectionLevel: 'SOFTWARE' };
  },
};

// ---------- 組立て: context → KMS port(operation=context.current) → ConnectStorage → 本物Provider → 新resolver ----------
const ctx = createRequestAuthContext({ clock });
const box = createConnectKmsSealingPort({ kms: { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', namespace: NS, cryptoKey: KEY, writeVersion: 1, readVersions: [1], transport, clock }, operation: ctx.current });
const connect = new ConnectStorage({ db, namespace: NS, hasher: createHmacHasher(randomBytes(32)), box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
const signingKey = { ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', kid: randomUUID() };
const provider = createOAuthProvider({
  profile: {
    kind: 'connect-kms-development',
    issuer: ISSUER,
    adapter: connect.adapterFactory,
    jwks: { keys: [signingKey] },
    cookieKeys: [randomBytes(32)],
    client: { clientId: CLIENT_ID, redirectUri: 'https://client.sttd-auth.invalid/callback', jwksUri: 'https://client.sttd-auth.invalid/jwks.json' },
    egress: {
      getJson: async () => {
        throw new Error('mcp-auth-bearer unit: no egress');
      },
    },
    assertionReplay: connect.assertionReplay,
    clock,
  },
  policy: PRODUCT_POLICY,
  isOwnerActive: async () => true,
});
const resolver = createRequestScopedOAuthOwnerResolver({ provider, connect, context: ctx, resource: RESOURCE });

const ownerId = randomUUID();
docs.set(`sttdConnect/${NS}/owners/${ownerId}`, { identityHash: 'f'.repeat(64), sealedUid: 'sealed', createdAt: Date.now(), lastActiveAt: Date.now(), revokedAt: null });

/** 公開SDK APIでslotの中からGrantとopaque access tokenを保存し、同じslotでfindした結果のown propertyを返す。 */
function issue(extra = {}) {
  return ctx.run(op(), async () => {
    const grant = new provider.Grant({ accountId: ownerId, clientId: CLIENT_ID });
    grant.addResourceScope(RESOURCE, 'sttd:events');
    const grantId = await grant.save();
    const token = new provider.AccessToken({ accountId: ownerId, clientId: CLIENT_ID, grantId, scope: 'sttd:events', aud: RESOURCE, gty: 'authorization_code', ...extra });
    const value = await token.save();
    const found = await provider.AccessToken.find(value);
    const own = Object.fromEntries(['jkt', 'x5t#S256'].map((key) => [key, Object.hasOwn(found, key) ? { value: found[key] } : null]));
    return { value, grantId, own };
  });
}
async function resolveCounted(value, operation = op()) {
  const start = log.length;
  const decrypts = kmsStats.decrypt;
  let result;
  try {
    result = { ok: true, value: await resolver(value, operation) };
  } catch (error) {
    result = { ok: false, error };
  }
  return { ...result, reads: log.slice(start).map(kindOf), decrypts: kmsStats.decrypt - decrypts };
}

after(() => {
  ctx.dispose();
  process.stdout.write(`# MCP_AUTH_BEARER_COUNTS encrypt=${kmsStats.encrypt} decrypt=${kmsStats.decrypt} reads=${log.length} unhandled=${unhandled} borrowedCloses=${borrowed.closes} timeouts=${timeouts() - baselineTimeouts}\n`);
  assert.equal(unhandled, 0);
  assert.equal(borrowed.closes, 0);
  assert.equal(timeouts() - baselineTimeouts, 0);
});

test('K01 control: a normal Bearer opaque token saved/found by the real Provider resolves (token -> grant -> owner)', async () => {
  const issued = await issue();
  assert.deepEqual(issued.own, { jkt: null, 'x5t#S256': null }, 'no own sender-constraint property on a normal token');
  const result = await resolveCounted(issued.value);
  assert.ok(result.ok && result.value?.ownerId === ownerId && result.value.grantId === issued.grantId);
  assert.deepEqual(result.reads, ['token', 'grant', 'owner']);
  assert.equal(result.decrypts, 2);
});

test('K02 sender-constrained tokens (own jkt / x5t#S256: normal value, empty, null, both) -> null, no Grant/owner read', async () => {
  const thumbprint = randomBytes(32).toString('base64url');
  const cases = {
    jktValue: { jkt: thumbprint },
    jktEmpty: { jkt: '' },
    jktNull: { jkt: null },
    x5tValue: { 'x5t#S256': thumbprint },
    x5tEmpty: { 'x5t#S256': '' },
    x5tNull: { 'x5t#S256': null },
    both: { jkt: thumbprint, 'x5t#S256': thumbprint },
  };
  for (const [name, extra] of Object.entries(cases)) {
    const issued = await issue(extra);
    for (const [key, value] of Object.entries(extra)) assert.deepEqual(issued.own[key], { value }, `${name}: the SDK token found from storage carries own ${key}`);
    const result = await resolveCounted(issued.value);
    assert.ok(result.ok && result.value === null, name);
    assert.deepEqual(result.reads, ['token'], name);
    assert.equal(result.decrypts, 1, `${name}: only the AccessToken open`);
  }
});

test('K03 original abort is kept: pre-aborted / aborted operation on a constrained token is the fixed aborted failure with no I/O and no listener left', async () => {
  const issued = await issue({ jkt: 'x' });
  const parent = new AbortController();
  parent.abort();
  const result = await resolveCounted(issued.value, op({ signal: parent.signal }));
  assert.ok(!result.ok && result.error instanceof RequestAuthContextError && result.error.code === 'aborted' && result.error.cause === undefined);
  assert.deepEqual(result.reads, []);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0);
});
