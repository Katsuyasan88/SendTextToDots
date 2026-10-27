// 本文暗号化の合成結合（T075）。既存の個別試験（encryption-keys/api/commands/reissue）の断片を繰り返さず、次の経路を1本で通す:
//   実HTTP GET /v2/encryption-key → 独立client（Node WebCrypto: RSA-OAEP/SHA-256・AES-GCM、protected文字列をAAD。製品のhelperは使わない）
//   → 実HTTP POST /v2/encrypted-commands → 実の暗号文endpoint・鍵store → 実KmsRequestDeliveryService → 実KmsRequestDeliveryStore
//   → 実createCommandDeliveryAttempt（Standard Webhooks署名）→ 実createSafeEgress → 合成CAの所有loopback TLS受信機。
// 合成で代替するのはDB（in-memory）・Firebase Auth（token表）・KMS codec（callback URL/secretを返す）・Secret source・connect adapterだけ。
// 実SDK・実Cloud・実Dots・外部callbackは0で、ここでの成功は実SDKのend-to-endではない。Apple OSでの相互運用は未確認。
//   I01 独立WebCryptoの暗号文が実経路で1回届き、本文・署名が一致（日本語混在／制御文字4096byteの2入力）。負例（tag改ざん・wire超過）は送出0。
//   I02 固定ベクトル（test/fixtures/encrypted-payload-vectors.json、合成専用鍵）: 正例2を製品の解析/復号とWebCryptoの両方で開ける・
//       WebCryptoのAES-GCMが同じ暗号文を作る。負例6（tag/AAD/nonce/kid/UTF-8/最大長）を拒否する。
//   I03 off（暗号化のportなし・追加秘密なし）: 公開鍵/暗号文の入口は404、平文POSTは同じ実経路で届き署名が一致する。

import assert from 'node:assert/strict';
import { createHmac, createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { Webhook } from 'standardwebhooks';

import { createCommandDeliveryAttempt } from '../dist/commands/delivery-attempt.js';
import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { KmsRequestDeliveryService } from '../dist/delivery/kms-service.js';
import { KmsRequestDeliveryStore } from '../dist/delivery/kms-store.js';
import { createSafeEgress } from '../dist/egress/safe-egress.js';
import { createEncryptionKeyEndpoint } from '../dist/encryption/api.js';
import { createEncryptedCommandEndpoint, decryptCompactJwe, parseCompactJwe } from '../dist/encryption/commands.js';
import { wrapPrivateKey } from '../dist/encryption/crypto.js';
import { createEncryptionSecretProvider } from '../dist/encryption/secret-provider.js';
import { EncryptionKeyService } from '../dist/encryption/service.js';
import { EncryptionKeyStore } from '../dist/encryption/store.js';
import { KMS_CAPSULE_PREFIX } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument, kmsStateDocument, kmsVersionName } from '../dist/storage/firestore/kms-subscription-format.js';
import { CALLBACK_HOST, createTlsFixture, fixtureConnector, startReceiver } from './egress-helpers.mjs';

const VECTORS = JSON.parse(readFileSync(new URL('./fixtures/encrypted-payload-vectors.json', import.meta.url), 'utf8'));
const subtle = globalThis.crypto.subtle;
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64 = (text) => new Uint8Array(Buffer.from(text, 'base64url'));
const utf8 = (text) => new TextEncoder().encode(text);

const servers = [];
after(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

// ---- 独立client（WebCrypto） ----

async function webSeal(key, fields) {
  const header = { alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'sttd-command+jwe', kid: key.kid, sttdVersion: 1, scope: key.scope, commandId: fields.commandId, createdAt: fields.createdAt, expiresAt: fields.expiresAt };
  const protectedPart = b64(utf8(JSON.stringify(header)));
  const rsa = await subtle.importKey('jwk', { kty: 'RSA', n: key.publicJwk.n, e: key.publicJwk.e, alg: 'RSA-OAEP-256', ext: true }, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const cek = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const aes = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(protectedPart), tagLength: 128 }, aes, utf8(fields.text)));
  const encryptedKey = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, rsa, cek));
  cek.fill(0);
  return [protectedPart, b64(encryptedKey), b64(iv), b64(sealed.slice(0, -16)), b64(sealed.slice(-16))].join('.');
}

// ---- 合成DB・本人・購読と、実の配送経路 ----

function world(t, receiver, tlsCa) {
  const clock = { now: () => Date.now() };
  const docs = new Map();
  const db = {
    collection: (name) => collectionOf(name),
    async runTransaction(fn) {
      const writes = [];
      const read = (ref) => snapshotOf(ref.path);
      const tx = {
        get: async (ref) => read(ref),
        getAll: async (...refs) => refs.map(read),
        set: (ref, data) => writes.push(['set', ref.path, structuredClone(data)]),
        create: (ref, data) => writes.push(['create', ref.path, structuredClone(data)]),
        update: (ref, data) => writes.push(['update', ref.path, structuredClone(data)]),
        delete: (ref) => writes.push(['delete', ref.path]),
      };
      const result = await fn(tx);
      for (const [kind, path, data] of writes) {
        if (kind === 'delete') docs.delete(path);
        else docs.set(path, kind === 'update' ? { ...docs.get(path), ...data } : data);
      }
      return result;
    },
  };
  function snapshotOf(path) {
    const data = docs.get(path);
    return { id: path.split('/').pop(), ref: refOf(path), exists: data !== undefined, data: () => (data === undefined ? undefined : structuredClone(data)) };
  }
  function refOf(path) {
    return { firestore: db, path, id: path.split('/').pop(), collection: (name) => collectionOf(`${path}/${name}`), get: async () => snapshotOf(path) };
  }
  function collectionOf(path) {
    return { doc: (id) => refOf(`${path}/${id}`) };
  }
  const hashKey = randomBytes(32);
  const hasher = createHmacHasher(randomBytes(32));
  const hash = (purpose, value) => createHmac('sha256', hashKey).update(purpose).update('\0').update(value).digest('hex');
  const environment = {
    projectId: 'synthetic-project',
    projectNumber: '123456',
    databaseId: '(default)',
    connectNamespace: `t256_${randomUUID()}`,
    deliveryNamespace: `t270_${randomUUID()}`,
    encryptionNamespace: `t280_${randomUUID()}`,
  };
  const protection = randomBytes(32).toString('base64url');
  const secrets = createEncryptionSecretProvider(
    { read: async () => Buffer.from(protection, 'latin1') },
    { secret: 'projects/123456/secrets/synthetic-payload-protection', writeSecretVersion: 1, readSecretVersions: [1] },
  );
  const keyStore = new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: 1, clock });
  const keys = new EncryptionKeyService({ environment, store: keyStore, secrets, hasher, clock });
  const policy = createKmsSubscriptionPolicy({
    environment: 'development',
    projectId: environment.projectId,
    databaseId: environment.databaseId,
    namespace: `t268_${randomUUID()}`,
    cryptoKey: 'projects/synthetic-project/locations/us-central1/keyRings/synthetic-ring/cryptoKeys/synthetic-key',
    writeVersion: 1,
    readVersions: [1],
  });
  const connectRoot = `sttdConnect/${environment.connectNamespace}`;
  const connect = {
    ownerDocRef: (ownerId) => refOf(`${connectRoot}/owners/${ownerId}`),
    grantDocRef: (grantId) => refOf(`${connectRoot}/grants/${grantId}`),
    ownerDocActive: (data) => data !== undefined && data.revokedAt === null,
    grantDocLive: () => true,
    accessDocRefForOwner: (data) => (typeof data?.identityHash === 'string' ? refOf(`${connectRoot}/access/${data.identityHash}`) : null),
    grantMetaDocRef: (grantId) => refOf(`${connectRoot}/grantMeta/${grantId}`),
    accessUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
    grantUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
  };
  const store = new KmsRequestDeliveryStore({ db, namespace: environment.deliveryNamespace, connect, hash, clock, policy });
  docs.set(`sttdAuth/${policy.namespace}/config/kms-subscription`, kmsMarkerDocument(policy));
  const capsule = () => `${KMS_CAPSULE_PREFIX}${b64(Buffer.from(JSON.stringify([kmsVersionName(policy.cryptoKey, 1), b64(randomBytes(48))]), 'utf8'))}`;
  // 実の署名送出: createCommandDeliveryAttempt → createSafeEgress → 合成CA・127.0.0.1だけのconnector。
  const egress = createSafeEgress(fixtureConnector({ dns: { [CALLBACK_HOST]: ['127.0.0.1'] }, port: receiver.port, ca: tlsCa }));
  const attempt = createCommandDeliveryAttempt({ egress, clock });
  t.after(() => attempt.dispose());
  const callbackSecret = randomBytes(32);
  let attempts = 0;
  const lifetime = new AbortController();
  t.after(() => lifetime.abort());
  const logs = [];
  const service = new KmsRequestDeliveryService({
    store,
    codec: { open: async (binding) => Buffer.from(binding.purpose === 'callback-url' ? `https://${CALLBACK_HOST}/hook` : `whsec_${callbackSecret.toString('base64')}`, 'utf8') },
    hash,
    digestKey: randomBytes(32),
    send: (request) => attempt.send(request),
    clock,
    newAttemptId: () => `attempt-${(attempts += 1)}`,
    log: (entry) => logs.push(entry),
    budgetMs: 20_000,
    lifetime: lifetime.signal,
    hooks: {},
  });
  const tokens = new Map();
  const ownerOfUid = new Map();
  const identity = {
    projectId: environment.projectId,
    async verifyIdToken(token) {
      const uid = tokens.get(token);
      if (uid === undefined) throw new Error('bad token');
      return { projectId: environment.projectId, uid, authTimeSec: Math.floor(Date.now() / 1000) };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const handlerOf = (encrypted) =>
    createIngressOperationDeliveryRequestHandler({
      identity,
      findOwner: async (verified) => ownerOfUid.get(verified.uid),
      service,
      clock,
      log: (entry) => logs.push(entry),
      lifetime: lifetime.signal,
      ingress: () => {
        const now = Date.now();
        return { receivedAt: now, deadlineAt: now + 20_000, signal: new AbortController().signal };
      },
      ...(encrypted
        ? {
            encryptionKeys: createEncryptionKeyEndpoint(keys),
            encryptedCommands: createEncryptedCommandEndpoint({ environment, store: keyStore, secrets, hasher, clock, delivery: service }),
          }
        : {}),
    });
  const enroll = (uid) => {
    const now = Date.now();
    const identityHash = connectIdentityHash(hasher, environment.connectNamespace, { projectId: environment.projectId, uid });
    const ownerId = randomUUID();
    docs.set(`${connectRoot}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: now });
    docs.set(`${connectRoot}/identities/${identityHash}`, { ownerId, createdAt: now });
    docs.set(`${connectRoot}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: now, lastActiveAt: now, revokedAt: null });
    const subscriptionId = `sub_${hash('subscription', ownerId)}`;
    docs.set(
      `sttdAuth/${policy.namespace}/subscriptions/${ownerId}`,
      kmsStateDocument(ownerId, {
        active: { id: subscriptionId, ownerId, grantId: `grant-${ownerId}`, sealedUrl: capsule(), sealedSecret: capsule(), secretHash: 'c'.repeat(64), previousSecret: null, expiresAt: null },
        knownDestinationId: subscriptionId,
        pending: null,
        lastEnded: null,
      }),
    );
    ownerOfUid.set(uid, ownerId);
    const token = `tok.${randomBytes(12).toString('base64url')}.sig`;
    tokens.set(token, uid);
    return { uid, token };
  };
  const verify = (record) => new Webhook(`whsec_${callbackSecret.toString('base64')}`).verify(record.body, record.headers);
  return { handlerOf, enroll, verify, docs, logs };
}

async function serve(handler) {
  const server = createServer((req, res) => void handler(req, res));
  servers.push(server);
  await new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  return server.address().port;
}
function request(port, method, path, { token, headers = [], body = '' } = {}) {
  const payload = Buffer.from(body, 'utf8');
  const lines = [`${method} ${path} HTTP/1.1`, 'Host: 127.0.0.1', ...(token ? [`Authorization: Bearer ${token}`] : []), ...headers.map(([k, v]) => `${k}: ${v}`), 'Connection: close'];
  if (payload.length > 0 || method === 'POST') lines.push(`Content-Length: ${payload.length}`);
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => {
      const all = Buffer.concat(chunks).toString('utf8');
      const split = all.indexOf('\r\n\r\n');
      let json = null;
      try {
        json = JSON.parse(all.slice(split + 4));
      } catch {
        json = null;
      }
      resolve({ status: Number(all.split('\r\n')[0].split(' ')[1]), json, raw: all });
    });
    socket.write(Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), payload]));
  });
}
const fieldsNow = (text) => {
  const now = Date.now();
  return { commandId: randomUUID(), text, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString() };
};
const postEncrypted = (port, user, wire, commandId) =>
  request(port, 'POST', '/v2/encrypted-commands', { token: user.token, headers: [['Content-Type', 'application/jose'], ['Idempotency-Key', commandId]], body: wire });

test('I01: 独立WebCryptoの暗号文が実HTTP→共通service/store→署名送出→所有TLSへ1回届き、本文・署名が一致。負例は送出0', { timeout: 60_000 }, async (t) => {
  const tls = createTlsFixture();
  const receiver = await startReceiver(t, tls.good);
  const w = world(t, receiver, tls.ca);
  const port = await serve(w.handlerOf(true));
  const a = w.enroll('synthetic-uid-integration');
  const got = await request(port, 'GET', '/v2/encryption-key', { token: a.token });
  assert.equal(got.status, 200);
  const key = got.json;
  for (const text of ['日本語と絵文字😀\n  空白\tと改行\r\n', '\u0001'.repeat(4096)]) {
    const fields = fieldsNow(text);
    const response = await postEncrypted(port, a, await webSeal(key, fields), fields.commandId);
    assert.equal(response.status, 200);
    assert.equal(response.json.state, 'delivered');
    const record = receiver.requests.at(-1);
    assert.equal(JSON.parse(record.body).data.text, text);
    assert.equal(w.verify(record).data.text, text);
  }
  assert.equal(receiver.requests.length, 2);
  // 負例: tagの改ざんとwire超過は送出0。
  const fields = fieldsNow('negative');
  const parts = (await webSeal(key, fields)).split('.');
  const tag = Buffer.from(parts[4], 'base64url');
  tag[0] ^= 1;
  assert.equal((await postEncrypted(port, a, [...parts.slice(0, 4), b64(tag)].join('.'), fields.commandId)).status, 400);
  assert.equal((await postEncrypted(port, a, 'A'.repeat(12_289), randomUUID())).status, 400);
  assert.equal(receiver.requests.length, 2);
  // 保存・logに本文なし。
  const stored = JSON.stringify([...w.docs.values()]);
  assert.ok(!stored.includes('日本語と絵文字') && !JSON.stringify(w.logs).includes('日本語と絵文字'));
});

test('I02: 固定ベクトル（合成専用鍵）の正例2と負例6', async () => {
  assert.match(VECTORS.description, /SYNTHETIC TEST-ONLY/);
  const pkcs8 = Buffer.from(VECTORS.key.syntheticTestOnlyPkcs8Base64url, 'base64url');
  const webKey = await subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  for (const vector of VECTORS.positives) {
    // 製品の解析・復号。
    const parsed = parseCompactJwe(Buffer.from(vector.compact, 'latin1'));
    assert.equal(parsed.header.kid, VECTORS.key.kid);
    const bytes = decryptCompactJwe(parsed, pkcs8);
    assert.equal(new TextDecoder('utf-8', { fatal: true }).decode(bytes), vector.text, vector.name);
    parsed.dispose();
    // 独立のWebCrypto: CEKを開き、本文を開き、同じCEK/IVでAES-GCMが同じ暗号文・tagを作る。
    const [protectedPart, encryptedKey, iv, ciphertext, tag] = vector.compact.split('.');
    const cek = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, webKey, fromB64(encryptedKey)));
    assert.equal(b64(cek), vector.cek);
    assert.equal(iv, vector.iv);
    const aes = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const sealed = new Uint8Array([...fromB64(ciphertext), ...fromB64(tag)]);
    const opened = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv), additionalData: utf8(protectedPart), tagLength: 128 }, aes, sealed));
    assert.equal(new TextDecoder().decode(opened), vector.text);
    const again = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: fromB64(iv), additionalData: utf8(protectedPart), tagLength: 128 }, aes, utf8(vector.text)));
    assert.equal(b64(again), b64(sealed));
  }
  const byName = Object.fromEntries(VECTORS.negatives.map((vector) => [vector.name, vector]));
  assert.deepEqual(Object.keys(byName).sort(), ['aad', 'kid', 'max-length', 'nonce', 'tag', 'utf8']);
  for (const name of ['tag', 'aad', 'nonce']) {
    const parsed = parseCompactJwe(Buffer.from(byName[name].compact, 'latin1'));
    assert.throws(() => decryptCompactJwe(parsed, pkcs8), name);
    parsed.dispose();
  }
  // kid: 鍵ringに無いkid（サーバーは開かずに400。実経路の拒否はencryption-commandsのE02/E03）。
  assert.notEqual(parseCompactJwe(Buffer.from(byName.kid.compact, 'latin1')).header.kid, VECTORS.key.kid);
  // UTF-8: 認証は通るがfatalなUTF-8で拒否。
  const utf = parseCompactJwe(Buffer.from(byName.utf8.compact, 'latin1'));
  assert.throws(() => new TextDecoder('utf-8', { fatal: true }).decode(decryptCompactJwe(utf, pkcs8)));
  // 最大長: ciphertext 4097byteは形の検査で拒否。
  assert.throws(() => parseCompactJwe(Buffer.from(byName['max-length'].compact, 'latin1')));
});

test('I02b: 固定ベクトルの正例2・負例6を製品の暗号文endpointへ投入（合成ringへ固定鍵を束縛）。負例は全て400で配送0', async () => {
  // 合成環境: 固定ベクトルのcreatedAtの直後の合成clock。scopeは製品のencryptionScopeが使う用途（`t280:<namespace>:scope`）だけを、
  // 固定ベクトルのscopeになる合成のidentifierKey関数で計算する（他の用途は通常のHMAC）。製品のscope照合・ring照合・復号・本文検査は迂回しない。
  const base = Date.parse(VECTORS.positives[0].createdAt);
  const clock = { now: () => base + 1_000 };
  const environment = {
    projectId: 'synthetic-project',
    projectNumber: '123456',
    databaseId: '(default)',
    connectNamespace: `t256_${randomUUID()}`,
    deliveryNamespace: `t270_${randomUUID()}`,
    encryptionNamespace: `t280_${randomUUID()}`,
  };
  const hmac = createHmacHasher(randomBytes(32));
  const scopePurpose = `t280:${environment.encryptionNamespace}:scope`;
  const hasher = { hash: (purpose, value) => (purpose === scopePurpose ? Buffer.from(VECTORS.key.scope, 'base64url').toString('hex') : hmac.hash(purpose, value)) };
  const docs = new Map();
  const refOf = (path) => ({ path, id: path.split('/').pop(), collection: (name) => ({ doc: (id) => refOf(`${path}/${name}/${id}`) }), get: async () => snapshotOf(path) });
  const snapshotOf = (path) => ({ exists: docs.has(path), data: () => structuredClone(docs.get(path)) });
  const db = {
    collection: (name) => ({ doc: (id) => refOf(`${name}/${id}`) }),
    async runTransaction(fn) {
      const writes = [];
      const result = await fn({ get: async (ref) => snapshotOf(ref.path), set: (ref, data) => writes.push([ref.path, data]), create: (ref, data) => writes.push([ref.path, data]), update: (ref, data) => writes.push([ref.path, { ...docs.get(ref.path), ...data }]) });
      for (const [path, data] of writes) docs.set(path, structuredClone(data));
      return result;
    },
  };
  const protection = randomBytes(32);
  const secrets = createEncryptionSecretProvider(
    { read: async () => Buffer.from(protection.toString('base64url'), 'latin1') },
    { secret: 'projects/123456/secrets/synthetic-payload-protection', writeSecretVersion: 1, readSecretVersions: [1] },
  );
  const keyStore = new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: 1, clock });
  // 既存owner・明示許可と、固定鍵を束縛したring（wrapは製品のwrapPrivateKey、AADは同じ束縛）。
  const uid = 'synthetic-uid-vectors';
  const identityHash = connectIdentityHash(hasher, environment.connectNamespace, { projectId: environment.projectId, uid });
  const ownerId = randomUUID();
  const connectRoot = `sttdConnect/${environment.connectNamespace}`;
  docs.set(`${connectRoot}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: base });
  docs.set(`${connectRoot}/identities/${identityHash}`, { ownerId, createdAt: base });
  docs.set(`${connectRoot}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: base, lastActiveAt: base, revokedAt: null });
  const pkcs8 = Buffer.from(VECTORS.key.syntheticTestOnlyPkcs8Base64url, 'base64url');
  const publicKeySpki = createPublicKey(createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).toString('base64url');
  const scope = VECTORS.key.scope;
  const binding = { ...environment, identityHash, ownerId, scope, kid: VECTORS.key.kid, secretVersion: 1, publicKeySpki };
  delete binding.projectId;
  const wrappedPrivateKey = wrapPrivateKey(pkcs8, protection, binding);
  docs.set(`sttdEncryption/${environment.encryptionNamespace}/rings/${scope}`, {
    schemaVersion: 1,
    scope,
    identityHash,
    ownerId,
    generation: 1,
    activeKid: VECTORS.key.kid,
    keys: [{ kid: VECTORS.key.kid, publicJwk: VECTORS.key.publicJwk, publicKeySpki, createdAt: base, state: 'active', decryptUntil: null, retireAfter: null, secretVersion: 1, formatVersion: 1, wrappedPrivateKey }],
    reissues: [],
    createdAt: base,
    updatedAt: base,
    lastUsedAt: base,
  });
  const delivered = [];
  const endpoint = createEncryptedCommandEndpoint({
    environment,
    store: keyStore,
    secrets,
    hasher,
    clock,
    delivery: { postValidated: async (owner, input) => (delivered.push(input.fields.text), { status: 200, body: { commandId: input.commandId, state: 'delivered' } }) },
  });
  const post = (compact) => {
    const header = JSON.parse(Buffer.from(compact.split('.')[0], 'base64url').toString('utf8'));
    return endpoint.post({ projectId: environment.projectId, uid }, header.commandId, Buffer.from(compact, 'latin1'), base + 1_000, Object.freeze({ deadlineAt: base + 20_000, signal: new AbortController().signal }));
  };
  for (const vector of VECTORS.positives) {
    const response = await post(vector.compact);
    assert.equal(response.status, 200, vector.name);
    assert.equal(delivered.at(-1), vector.text, vector.name);
  }
  assert.equal(delivered.length, 2);
  for (const vector of VECTORS.negatives) {
    const response = await post(vector.compact);
    assert.equal(response.status, 400, vector.name);
    assert.equal(response.body.error.code, 'invalid_encrypted_request', vector.name);
  }
  assert.equal(delivered.length, 2, 'no negative vector reaches delivery');
});

test('I03: off（暗号化のportなし・追加秘密なし）は404で、平文は同じ実経路で届く', { timeout: 60_000 }, async (t) => {
  const tls = createTlsFixture();
  const receiver = await startReceiver(t, tls.good);
  const w = world(t, receiver, tls.ca);
  const port = await serve(w.handlerOf(false));
  const a = w.enroll('synthetic-uid-plain');
  assert.equal((await request(port, 'GET', '/v2/encryption-key', { token: a.token })).status, 404);
  assert.equal((await postEncrypted(port, a, 'a.b.c.d.e', randomUUID())).status, 404);
  assert.equal((await request(port, 'POST', '/v2/encryption-key/reissue', { token: a.token, headers: [['Content-Type', 'application/json']], body: '{}' })).status, 404);
  const fields = fieldsNow('plain text through the same path');
  const response = await request(port, 'POST', '/v2/commands', {
    token: a.token,
    headers: [['Content-Type', 'application/json'], ['Idempotency-Key', fields.commandId]],
    body: JSON.stringify({ schemaVersion: 2, ...fields }),
  });
  assert.equal(response.status, 200);
  assert.equal(response.json.state, 'delivered');
  assert.equal(receiver.requests.length, 1);
  assert.equal(w.verify(receiver.requests[0]).data.text, fields.text);
  assert.ok(![...w.docs.keys()].some((path) => path.startsWith('sttdEncryption/')));
});
