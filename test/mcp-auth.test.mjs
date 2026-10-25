// MCP/OAuthの要求context（AsyncLocalStorage slot）と実AS resolverを、本物の固定oidc-provider（createOAuthProviderの
// connect-kms-development profile・通信0）と限定adapter（ConnectStorage＋fake Firestore＋KMS port＋合成AES-GCM transport）で確かめる。
// AccessToken/Grantは固定SDKの公開API（new provider.Grant/AccessToken・save）でslotの中から発行し、AS payloadの封緘・開封は
// KMS portのoperation=context.currentだけで行う（fixture resolver・同期boxへのfallback 0）。通信・emulator・子process 0。
// 確かめる点: token→Grant→ownerの解決と他owner・他Grantの分離、資格不備はnull・内部失敗は固定unavailable、元期限・中断・dispose、並行要求の分離。
// 出力は試験名と件数だけ（token・owner・Grant・capsuleを出さない）。
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { after, test } from 'node:test';

import Provider from 'oidc-provider';

import { ConnectStorage } from '../dist/connect/firestore.js';
import { createConnectKmsSealingPort } from '../dist/connect/kms-port.js';
import * as authModule from '../dist/oauth/request-auth-runtime.js';
import { createOAuthProvider, resourceFor } from '../dist/oauth/provider.js';
import { PRODUCT_POLICY } from '../dist/policy.js';
import { crc32c } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';

const { createRequestAuthContext, createRequestScopedOAuthOwnerResolver, RequestAuthConfigError, RequestAuthContextError } = authModule;

const PROJECT = 'demo-sttd-auth';
const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
const ISSUER = 'https://connect.sttd-auth.invalid';
const RESOURCE = resourceFor(ISSUER);
const CLIENT_ID = 'https://client.sttd-auth.invalid/client.json';
const NS = `t256_${randomUUID()}`;
const DAY = 86_400_000;
const TOKEN_TTL_SEC = 600;
const SHORT_TTL_SEC = 5;
const CTX_MESSAGES = {
  invalid_input: 'request auth context: invalid input',
  unavailable: 'request auth context: unavailable',
  timed_out: 'request auth context: timed out',
  aborted: 'request auth context: aborted',
  closed: 'request auth context: closed',
  no_context: 'request auth context: no context',
};

let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
const secrets = new Set();
const remember = (value) => {
  if (typeof value === 'string' && value.length >= 8) secrets.add(value);
  return value;
};
const errorsSeen = [];
const timeouts = () => process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
const baselineTimeouts = timeouts();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------- 制御した時計（実時刻の近くから始める。SDKのisValid/isExpiredは実時刻、ASの残りはこの時計） ----------
const clockState = { value: Math.floor(Date.now()), calls: 0, onNow: null };
const clock = {
  now() {
    clockState.calls += 1;
    if (clockState.onNow) return clockState.onNow(clockState.calls);
    return clockState.value;
  },
};
const advance = (ms) => {
  clockState.value += ms;
};
/** 制御clockを実時刻へ合わせ直す（SDKのexpは実時刻から決まるため、期限を比べる試験の前後だけ）。 */
const sync = () => {
  clockState.value = Math.floor(Date.now());
};
const op = (overrides = {}) => ({ deadlineAt: clockState.value + 3_600_000, signal: new AbortController().signal, ...overrides });

// ---------- 限定fake Firestore（ConnectStorageのoidc/owner文書のget/set/update/deleteだけ） ----------
const borrowed = { closes: 0 };
function fakeDb() {
  const docs = new Map();
  let tick = 0;
  const stats = { gets: 0, sets: 0, deletes: 0, log: [] };
  const control = { onGet: null, failGet: null };
  function snapshot(path) {
    const entry = docs.get(path);
    return {
      exists: entry !== undefined,
      updateTime: entry?.updateTime,
      get: (field) => entry?.data[field],
      data: () => (entry === undefined ? undefined : structuredClone(entry.data)),
    };
  }
  function refOf(path) {
    return {
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      async set(data) {
        stats.sets += 1;
        tick += 1;
        docs.set(path, { data: structuredClone(data), updateTime: { seconds: tick, nanoseconds: 0, isEqual: () => false } });
      },
      async update(partial) {
        stats.sets += 1;
        const previous = docs.get(path);
        if (!previous) throw new Error('fake: NOT_FOUND');
        docs.set(path, { data: { ...previous.data, ...structuredClone(partial) }, updateTime: previous.updateTime });
      },
      async delete() {
        stats.deletes += 1;
        docs.delete(path);
      },
      async get() {
        stats.gets += 1;
        stats.log.push(path);
        if (control.failGet?.(path)) throw new Error(`fake db failure ${path}`);
        if (control.onGet) await control.onGet(path);
        return snapshot(path);
      },
    };
  }
  function collectionOf(path) {
    return { doc: (id) => refOf(`${path}/${id}`) };
  }
  return {
    docs,
    stats,
    control,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    runTransaction() {
      throw new Error('fake: no transaction in this unit');
    },
    terminate() {
      borrowed.closes += 1;
    },
    close() {
      borrowed.closes += 1;
    },
  };
}
const kindOf = (path) => (path.includes('/oidc/AccessToken_') ? 'token' : path.includes('/oidc/Grant_') ? 'grant' : path.includes('/owners/') ? 'owner' : 'other');

// ---------- 合成AES-GCM KMS（decryptの保留・失敗・呼出しoptionsの記録） ----------
function aesKms(key) {
  const stats = { encrypt: 0, decrypt: 0, options: [] };
  const control = { decryptHolds: [], failDecrypt: false };
  const transport = {
    async encrypt(request, options) {
      stats.encrypt += 1;
      stats.options.push(options);
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(request.additionalAuthenticatedData);
      const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
      const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
      return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
    },
    async decrypt(request, options) {
      stats.decrypt += 1;
      stats.options.push(options);
      const hold = control.decryptHolds.shift();
      if (hold) {
        hold.options = options;
        hold.reached();
        const action = await hold.promise;
        if (action === 'throw') throw new Error('late kms failure');
      }
      if (control.failDecrypt) throw new Error(`kms failure ${randomUUID()}`);
      const raw = request.ciphertext;
      const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
      decipher.setAAD(request.additionalAuthenticatedData);
      decipher.setAuthTag(raw.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
      return { plaintext, plaintextCrc32c: crc32c(plaintext), protectionLevel: 'SOFTWARE' };
    },
    close() {
      borrowed.closes += 1;
    },
  };
  return { stats, control, transport };
}
function gate() {
  let release;
  let reached;
  const whenReached = new Promise((resolve) => {
    reached = resolve;
  });
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, reached, release: (value) => release(value), whenReached, options: null };
}

// ---------- 組立て: context → KMS port(operation=context.current) → ConnectStorage → 本物Provider → resolver ----------
const hasher = createHmacHasher(randomBytes(32));
const kmsKey = randomBytes(32);
const baseKms = { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: KEY, writeVersion: 1, readVersions: [1] };
const signingKey = { ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', kid: randomUUID() };

function assemble({ ctx = createRequestAuthContext({ clock }), portContext = ctx, ttlSec = TOKEN_TTL_SEC } = {}) {
  const db = fakeDb();
  const kms = aesKms(kmsKey);
  const box = createConnectKmsSealingPort({ kms: { ...baseKms, namespace: NS, transport: kms.transport, clock }, operation: portContext.current });
  const connect = new ConnectStorage({ db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
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
          throw new Error('mcp-auth unit: no egress');
        },
      },
      assertionReplay: connect.assertionReplay,
      clock,
    },
    policy: { ...PRODUCT_POLICY, accessTokenTtlSec: ttlSec },
    isOwnerActive: async () => true,
  });
  const resolver = createRequestScopedOAuthOwnerResolver({ provider, connect, context: ctx, resource: RESOURCE });
  return { ctx, db, kms, connect, provider, resolver };
}
const main = assemble();
const contexts = [main.ctx];

const ownerPath = (ownerId) => `sttdConnect/${NS}/owners/${ownerId}`;
async function newOwner(env = main, extra = {}) {
  const ownerId = randomUUID();
  await env.db.doc(ownerPath(ownerId)).set({ identityHash: 'f'.repeat(64), sealedUid: 'sealed', createdAt: clockState.value, lastActiveAt: clockState.value, revokedAt: null, ...extra });
  return ownerId;
}
/** 固定SDKの公開APIで、slotの中からGrantとopaque access tokenを発行する（AS payloadはKMS portで封緘）。 */
function issue(env, ownerId, spec = {}) {
  return env.ctx.run(op(), async () => {
    const grant = new env.provider.Grant({ accountId: spec.grantAccount ?? ownerId, clientId: spec.grantClient ?? CLIENT_ID });
    if (spec.grantScope !== '') grant.addResourceScope(spec.grantResource ?? RESOURCE, spec.grantScope ?? 'sttd:events');
    if (spec.rejected) grant.rejectResourceScope(RESOURCE, spec.rejected);
    const grantId = await grant.save();
    const token = new env.provider.AccessToken({
      accountId: spec.tokenAccount ?? ownerId,
      clientId: spec.tokenClient ?? CLIENT_ID,
      grantId: spec.tokenGrant ?? grantId,
      scope: spec.scope ?? 'sttd:events',
      aud: spec.aud ?? RESOURCE,
      gty: 'authorization_code',
    });
    const value = remember(await token.save());
    remember(grantId);
    return { grantId, value, grant };
  });
}
async function outcome(promise) {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    errorsSeen.push(error);
    return { ok: false, error };
  }
}
function isFixed(error, code) {
  return error instanceof RequestAuthContextError && error.code === code && error.message === CTX_MESSAGES[code] && error.cause === undefined && error.name === 'RequestAuthContextError';
}
function throwsConfig(fn) {
  try {
    fn();
    return false;
  } catch (error) {
    return error instanceof RequestAuthConfigError && error.code === 'request_auth_config_invalid' && error.message === 'request_auth_config_invalid' && error.cause === undefined;
  }
}

after(() => {
  for (const ctx of contexts) ctx.dispose();
  const leaked = [...secrets].filter((value) => errorsSeen.some((error) => `${error?.message}\n${error?.stack}`.includes(value))).length;
  process.stdout.write(
    `# MCP_AUTH_COUNTS encrypt=${main.kms.stats.encrypt} decrypt=${main.kms.stats.decrypt} dbGets=${main.db.stats.gets} errors=${errorsSeen.length} leaked=${leaked} unhandled=${unhandled} borrowedCloses=${borrowed.closes} timeouts=${timeouts() - baselineTimeouts}\n`,
  );
  assert.equal(leaked, 0);
  assert.equal(unhandled, 0);
  assert.equal(borrowed.closes, 0);
  assert.equal(timeouts() - baselineTimeouts, 0);
});

test('U01 exports and factories: exact options, fixed config error before side effects, brand/Proxy/fake Provider/connect refused, frozen, no I/O', () => {
  assert.deepEqual(Object.keys(authModule).sort(), ['RequestAuthConfigError', 'RequestAuthContextError', 'createRequestAuthContext', 'createRequestScopedOAuthOwnerResolver']);
  let getterCalls = 0;
  const trap = new Proxy({}, { get: () => (getterCalls += 1) });
  for (const bad of [undefined, null, {}, { clock, extra: 1 }, { clock: {} }, { clock: { get now() { getterCalls += 1; return () => 0; } } }, new Proxy({ clock }, {}), Object.create({ clock }), { clock: trap }]) {
    assert.ok(throwsConfig(() => createRequestAuthContext(bad)));
  }
  assert.ok(throwsConfig(() => createRequestAuthContext({ get clock() { getterCalls += 1; return clock; } })));
  const ctx = main.ctx;
  assert.ok(Object.isFrozen(ctx) && Object.isFrozen(main.resolver) && typeof main.resolver === 'function');
  const good = { provider: main.provider, connect: main.connect, context: ctx, resource: RESOURCE };
  const fakeProvider = Object.create(Provider.prototype);
  const fakeConnect = { isOwnerActive: async () => true };
  for (const bad of [
    undefined,
    {},
    { ...good, extra: 1 },
    { provider: good.provider, connect: good.connect, context: ctx },
    { ...good, provider: new Proxy(main.provider, {}) },
    { ...good, provider: fakeProvider },
    { ...good, provider: { AccessToken: main.provider.AccessToken, Grant: main.provider.Grant } },
    { ...good, connect: fakeConnect },
    { ...good, connect: new Proxy(main.connect, {}) },
    { ...good, context: { ...ctx } },
    { ...good, context: new Proxy(ctx, {}) },
    { ...good, context: { run: ctx.run, current: ctx.current, dispose: ctx.dispose } },
    { ...good, resource: '' },
    { ...good, resource: 'not a url' },
    { ...good, resource: 42 },
  ]) {
    assert.ok(throwsConfig(() => createRequestScopedOAuthOwnerResolver(bad)));
  }
  assert.ok(throwsConfig(() => createRequestScopedOAuthOwnerResolver({ ...good, get resource() { getterCalls += 1; return RESOURCE; } })));
  assert.equal(getterCalls, 0);
  const before = { gets: main.db.stats.gets, dec: main.kms.stats.decrypt, enc: main.kms.stats.encrypt };
  const extra = createRequestScopedOAuthOwnerResolver(good);
  assert.ok(Object.isFrozen(extra));
  assert.deepEqual({ gets: main.db.stats.gets, dec: main.kms.stats.decrypt, enc: main.kms.stats.encrypt }, before);
});

test('U02 run/current: slot deadline = min(original, start+20000), same frozen object per slot, current outside -> no_context, invalid operation/work -> invalid_input, work error -> fixed unavailable', async () => {
  const ctx = main.ctx;
  assert.throws(() => ctx.current(), (error) => isFixed(error, 'no_context'));
  const start = clockState.value;
  const parent = new AbortController();
  const seen = await ctx.run({ deadlineAt: start + 3_600_000, signal: parent.signal }, async () => {
    const a = ctx.current();
    await sleep(1);
    const b = ctx.current();
    return { a, b };
  });
  assert.ok(seen.a === seen.b && Object.isFrozen(seen.a) && seen.a.deadlineAt === start + 20_000 && seen.a.signal instanceof AbortSignal && seen.a.signal !== parent.signal);
  assert.deepEqual(Object.keys(seen.a).sort(), ['deadlineAt', 'signal']);
  assert.ok(seen.a.signal.aborted, 'the slot child signal is aborted after run');
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0);
  const short = await ctx.run({ deadlineAt: start + 5_000, signal: parent.signal }, () => ctx.current().deadlineAt);
  assert.equal(short, start + 5_000);
  assert.equal(await ctx.run(op(), () => 7), 7);

  const fakeSignal = Object.create(AbortSignal.prototype);
  for (const bad of [
    undefined,
    {},
    { deadlineAt: start + 1_000 },
    { deadlineAt: start + 1_000, signal: parent.signal, extra: 1 },
    { deadlineAt: 1.5, signal: parent.signal },
    { deadlineAt: -1, signal: parent.signal },
    { deadlineAt: 8_640_000_000_000_001, signal: parent.signal },
    { deadlineAt: String(start + 1_000), signal: parent.signal },
    { deadlineAt: start + 1_000, signal: { aborted: false } },
    { deadlineAt: start + 1_000, signal: new Proxy(parent.signal, {}) },
    new Proxy({ deadlineAt: start + 1_000, signal: parent.signal }, {}),
    Object.freeze(Object.create({ deadlineAt: start + 1_000, signal: parent.signal })),
  ]) {
    const result = await outcome(ctx.run(bad, () => 1));
    assert.ok(!result.ok && isFixed(result.error, 'invalid_input'));
  }
  // instanceofだけを満たす偽signalは、brandを持たないgetterの失敗で固定unavailable（timer/listener 0）。
  const fake = await outcome(ctx.run({ deadlineAt: start + 1_000, signal: fakeSignal }, () => 1));
  assert.ok(!fake.ok && isFixed(fake.error, 'unavailable'));
  for (const work of [undefined, 1, new Proxy(() => 1, {})]) {
    const result = await outcome(ctx.run(op(), work));
    assert.ok(!result.ok && isFixed(result.error, 'invalid_input'));
  }
  const secret = remember(`work-secret-${randomUUID()}`);
  const thrown = await outcome(ctx.run(op(), () => {
    throw new Error(secret);
  }));
  const rejected = await outcome(ctx.run(op(), async () => {
    throw Object.assign(new Error(secret), { cause: secret });
  }));
  assert.ok(!thrown.ok && isFixed(thrown.error, 'unavailable') && !rejected.ok && isFixed(rejected.error, 'unavailable'));
});

test('U03 nested slot: minimum of the outer deadline, cannot extend; outer abort/end stops the inner; no context switch', async () => {
  const ctx = main.ctx;
  const start = clockState.value;
  const outerParent = new AbortController();
  let innerDeadline;
  let innerShort;
  await ctx.run({ deadlineAt: start + 10_000, signal: outerParent.signal }, async () => {
    innerDeadline = await ctx.run({ deadlineAt: start + 3_600_000, signal: new AbortController().signal }, () => ctx.current().deadlineAt);
    innerShort = await ctx.run({ deadlineAt: start + 4_000, signal: new AbortController().signal }, () => ctx.current().deadlineAt);
    assert.equal(ctx.current().deadlineAt, start + 10_000);
  });
  assert.equal(innerDeadline, start + 10_000);
  assert.equal(innerShort, start + 4_000);

  // 外側の元signalのabortで、進行中の内側も止まる。
  const parent = new AbortController();
  let innerPromise;
  const outerPromise = ctx.run({ deadlineAt: start + 60_000, signal: parent.signal }, () => {
    innerPromise = outcome(ctx.run(op(), () => new Promise(() => {})));
    return new Promise(() => {});
  });
  await sleep(1);
  parent.abort();
  const outer = await outcome(outerPromise);
  const inner = await innerPromise;
  assert.ok(!outer.ok && isFixed(outer.error, 'aborted') && !inner.ok && isFixed(inner.error, 'aborted'));

  // 外側の終了後に、その子孫が始めた内側のrunは新しいcontextを作らない（no_context）。
  // slotの中で予約した継続（timer→then）は、そのslotのasync contextを持ったまま終了後に走る。
  const kick = {};
  await ctx.run(op(), () => {
    kick.promise = sleep(20).then(() => outcome(ctx.run(op(), () => 'never')));
    return 'outer done';
  });
  const late = await kick.promise;
  assert.ok(!late.ok && isFixed(late.error, 'no_context'));
});

test('U04 slot end: late async descendants get no_context, late AccessToken.find opens nothing (slot外open拒否), never-settling work -> timed_out, late success not adopted', async () => {
  const env = main;
  const ownerId = await newOwner();
  const issued = await issue(env, ownerId);
  const ctx = env.ctx;
  const lateCurrent = {};
  const lateFind = {};
  await ctx.run(op(), () => {
    lateCurrent.promise = new Promise((resolve) => {
      setTimeout(() => {
        try {
          ctx.current();
          resolve('ok');
        } catch (error) {
          resolve(error);
        }
      }, 20);
    });
    lateFind.promise = (async () => {
      await sleep(20);
      return outcome(env.provider.AccessToken.find(issued.value));
    })();
    return 'done';
  });
  const decryptBefore = env.kms.stats.decrypt;
  const current = await lateCurrent.promise;
  const found = await lateFind.promise;
  assert.ok(isFixed(current, 'no_context'));
  assert.ok(!found.ok && found.error?.name === 'KmsSealingError' && found.error.code === 'unavailable');
  // 要求外（slotなし）のfindも開封しない。
  const outside = await outcome(env.provider.AccessToken.find(issued.value));
  assert.ok(!outside.ok && outside.error?.code === 'unavailable');
  assert.equal(env.kms.stats.decrypt, decryptBefore, 'no KMS decrypt outside a live slot');

  // 決着しないworkは元期限で打ち切り、後から来た成功を採用しない。
  let settleLate;
  const result = await outcome(ctx.run(op({ deadlineAt: clockState.value + 40 }), () => new Promise((resolve) => {
    settleLate = resolve;
  })));
  settleLate('late value');
  await sleep(1);
  assert.ok(!result.ok && isFixed(result.error, 'timed_out'));
});

test('U05 real Provider opaque token -> Grant -> owner: frozen ResolvedOAuthOwner, order token/grant/owner once each, owner activity not extended, no DB write', async () => {
  const env = main;
  const ownerId = await newOwner();
  const issued = await issue(env, ownerId);
  const before = { gets: env.db.stats.gets, sets: env.db.stats.sets, dec: env.kms.stats.decrypt, log: env.db.stats.log.length };
  const ownerBefore = env.db.docs.get(ownerPath(ownerId)).data.lastActiveAt;
  const resolved = await env.resolver(issued.value, op());
  const reads = env.db.stats.log.slice(before.log).map(kindOf);
  assert.ok(Object.isFrozen(resolved) && Object.isFrozen(resolved.scopes));
  assert.deepEqual(Object.keys(resolved).sort(), ['clientId', 'expiresAt', 'grantId', 'ownerId', 'scopes']);
  assert.ok(resolved.ownerId === ownerId && resolved.grantId === issued.grantId && resolved.clientId === CLIENT_ID && resolved.scopes.length === 1 && resolved.scopes[0] === 'sttd:events');
  assert.ok(Number.isSafeInteger(resolved.expiresAt) && resolved.expiresAt * 1000 > clockState.value);
  assert.deepEqual(reads, ['token', 'grant', 'owner']);
  assert.equal(env.kms.stats.decrypt - before.dec, 2, 'AccessToken and Grant are opened through the KMS port once each');
  assert.equal(env.db.stats.sets, before.sets, 'resolve writes nothing');
  assert.equal(env.db.docs.get(ownerPath(ownerId)).data.lastActiveAt, ownerBefore);
  // 同じtokenの2回目も同じ結果（状態を持たない）。
  const again = await env.resolver(issued.value, op());
  assert.ok(again.ownerId === ownerId && again.grantId === issued.grantId && again !== resolved);
});

test('U06 credential failures are null only: shape/size, unknown, aud, scope, Grant scope/rejected/client/account/deleted, owner format/inactive/missing; I/O stops at the failing stage', async () => {
  const env = main;
  const resolveWith = async (token) => {
    const log = env.db.stats.log.length;
    const dec = env.kms.stats.decrypt;
    const result = await outcome(env.resolver(token, op()));
    return { ...result, reads: env.db.stats.log.slice(log).map(kindOf), decrypts: env.kms.stats.decrypt - dec };
  };
  for (const token of [123, undefined, {}, '', 'x'.repeat(8193), 'é'.repeat(4097)]) {
    const result = await resolveWith(token);
    assert.ok(result.ok && result.value === null && result.reads.length === 0 && result.decrypts === 0);
  }
  const unknown = await resolveWith(remember(`unknown-${randomBytes(16).toString('base64url')}`));
  assert.ok(unknown.ok && unknown.value === null && unknown.reads.join() === 'token' && unknown.decrypts === 0);

  const owner = await newOwner();
  const cases = {
    wrongAud: { aud: 'https://other.sttd-auth.invalid/mcp', stop: 'token' },
    noScope: { scope: 'other:scope', stop: 'token' },
    grantNoResourceScope: { grantScope: '', stop: 'token,grant' },
    grantOtherResource: { grantResource: 'https://other.sttd-auth.invalid/mcp', stop: 'token,grant' },
    grantRejected: { rejected: 'sttd:events', stop: 'token,grant' },
    grantOtherClient: { grantClient: 'https://client2.sttd-auth.invalid/client.json', stop: 'token,grant' },
    grantOtherAccount: { grantAccount: randomUUID(), stop: 'token,grant' },
  };
  for (const [name, spec] of Object.entries(cases)) {
    const issued = await issue(env, owner, spec);
    const result = await resolveWith(issued.value);
    assert.ok(result.ok && result.value === null, name);
    assert.equal(result.reads.join(), spec.stop, name);
  }
  // 既存owner形式でないaccountIdはGrant/ownerを読まずにnull。
  const badOwner = await issue(env, 'not-a-uuid');
  const badOwnerResult = await resolveWith(badOwner.value);
  assert.ok(badOwnerResult.ok && badOwnerResult.value === null && badOwnerResult.reads.join() === 'token');
  // Grantの削除（取消）→ null。
  const deleted = await issue(env, owner);
  await env.ctx.run(op(), () => deleted.grant.destroy());
  const deletedResult = await resolveWith(deleted.value);
  assert.ok(deletedResult.ok && deletedResult.value === null && deletedResult.reads.join() === 'token,grant');
  // ownerの失効・不在 → null（Grantまでは読む）。
  const revoked = await newOwner(env, { revokedAt: clockState.value });
  const revokedToken = await issue(env, revoked);
  const missingToken = await issue(env, randomUUID());
  for (const token of [revokedToken.value, missingToken.value]) {
    const result = await resolveWith(token);
    assert.ok(result.ok && result.value === null && result.reads.join() === 'token,grant,owner');
  }
  // 時計でtokenの期限を過ぎたもの → null。
  sync();
  const expiring = await issue(env, owner);
  advance(TOKEN_TTL_SEC * 1000 + 1);
  const expired = await resolveWith(expiring.value);
  sync();
  assert.ok(expired.ok && expired.value === null);
});

test('U07 internal failures are a fixed unavailable (not null): KMS decrypt error, DB read error at Grant/owner, foreign context of the KMS port; no cause/secret', async () => {
  const env = main;
  const owner = await newOwner();
  const issued = await issue(env, owner);
  env.kms.control.failDecrypt = true;
  const kmsFail = await outcome(env.resolver(issued.value, op()));
  env.kms.control.failDecrypt = false;
  assert.ok(!kmsFail.ok && isFixed(kmsFail.error, 'unavailable'));
  for (const stage of ['grant', 'owner']) {
    env.db.control.failGet = (path) => kindOf(path) === stage;
    const result = await outcome(env.resolver(issued.value, op()));
    env.db.control.failGet = null;
    assert.ok(!result.ok && isFixed(result.error, 'unavailable'), stage);
  }
  // KMS portが別contextのcurrentを使う構成: 要求slotへ切り替えずに開封を拒否 → unavailable（nullにしない）。
  const other = createRequestAuthContext({ clock });
  contexts.push(other);
  const foreign = assemble({ portContext: other });
  contexts.push(foreign.ctx);
  const ownerF = await newOwner(foreign);
  const issueEnv = { ...foreign, ctx: other };
  const issuedF = await issue(issueEnv, ownerF);
  const dec = foreign.kms.stats.decrypt;
  const foreignResult = await outcome(foreign.resolver(issuedF.value, op()));
  assert.ok(!foreignResult.ok && isFixed(foreignResult.error, 'unavailable') && foreign.kms.stats.decrypt === dec);
  // 正しい組合せなら同じtokenは解決できる（対照）。
  const control = createRequestScopedOAuthOwnerResolver({ provider: foreign.provider, connect: foreign.connect, context: other, resource: RESOURCE });
  const ok = await control(issuedF.value, op());
  assert.ok(ok?.ownerId === ownerF);
  // 正常なtokenで内部例外を起こしても、無効tokenのnullとは区別される。
  const nullResult = await outcome(env.resolver(remember(`unknown-${randomUUID()}`), op()));
  assert.ok(nullResult.ok && nullResult.value === null);
});

test('U08 original deadline/abort/dispose: before I/O, during the AccessToken open (held KMS), late values not adopted, KMS call signal aborted, closed afterwards', async () => {
  const env = main;
  const owner = await newOwner();
  const issued = await issue(env, owner);
  const log0 = env.db.stats.log.length;
  const pre = new AbortController();
  pre.abort();
  const aborted = await outcome(env.resolver(issued.value, op({ signal: pre.signal })));
  const late = await outcome(env.resolver(issued.value, op({ deadlineAt: clockState.value })));
  assert.ok(!aborted.ok && isFixed(aborted.error, 'aborted') && !late.ok && isFixed(late.error, 'timed_out'));
  assert.equal(env.db.stats.log.length, log0, 'no I/O before the slot is live');

  // AccessTokenの開封中の元abort → aborted。保留したKMS呼出しのsignalもabort、後着の値でGrantへ進まない。
  const hold = gate();
  env.kms.control.decryptHolds.push(hold);
  const parent = new AbortController();
  const pending = outcome(env.resolver(issued.value, op({ signal: parent.signal })));
  await hold.whenReached;
  const log1 = env.db.stats.log.length;
  parent.abort();
  const abortedDuring = await pending;
  hold.release('ok');
  await sleep(5);
  assert.ok(!abortedDuring.ok && isFixed(abortedDuring.error, 'aborted') && hold.options.signal.aborted === true);
  assert.equal(env.db.stats.log.length, log1, 'no Grant read after the late token');
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0);

  // 元期限（短い）で打ち切る。後着のrejectは処理される（未処理0）。
  const hold2 = gate();
  env.kms.control.decryptHolds.push(hold2);
  const timed = outcome(env.resolver(issued.value, op({ deadlineAt: clockState.value + 60 })));
  await hold2.whenReached;
  const timedOut = await timed;
  hold2.release('throw');
  await sleep(5);
  assert.ok(!timedOut.ok && isFixed(timedOut.error, 'timed_out') && hold2.options.signal.aborted === true);

  // dispose中 → closed、以後のrun/resolverはI/O 0のclosed。disposeは冪等。
  const own = assemble();
  contexts.push(own.ctx);
  const ownerD = await newOwner(own);
  const issuedD = await issue(own, ownerD);
  const hold3 = gate();
  own.kms.control.decryptHolds.push(hold3);
  const disposing = outcome(own.resolver(issuedD.value, op()));
  await hold3.whenReached;
  own.ctx.dispose();
  own.ctx.dispose();
  const closed = await disposing;
  hold3.release('ok');
  const logD = own.db.stats.log.length;
  const after1 = await outcome(own.resolver(issuedD.value, op()));
  const after2 = await outcome(own.ctx.run(op(), () => 1));
  assert.ok(!closed.ok && isFixed(closed.error, 'closed') && !after1.ok && isFixed(after1.error, 'closed') && !after2.ok && isFixed(after2.error, 'closed'));
  assert.equal(own.db.stats.log.length, logD);
});

test('U09 clock re-entrance: abort/dispose during the slot-opening clock read or the wait clock read creates no timer/listener; non-finite/invalid clock is fixed', async () => {
  const ctx = main.ctx;
  // (a) slotを開く時計の読取りで元abort → aborted、timer/listener 0。
  const parentA = new AbortController();
  const timersA = timeouts();
  clockState.onNow = () => {
    clockState.onNow = null;
    parentA.abort();
    return clockState.value;
  };
  const a = await outcome(ctx.run({ deadlineAt: clockState.value + 60_000, signal: parentA.signal }, () => 'never'));
  assert.ok(!a.ok && isFixed(a.error, 'aborted') && timeouts() === timersA && getEventListeners(parentA.signal, 'abort').length === 0);

  // (b) 同じ読取りでdispose → closed、timer 0（別context）。
  const own = createRequestAuthContext({ clock });
  contexts.push(own);
  const timersB = timeouts();
  clockState.onNow = () => {
    clockState.onNow = null;
    own.dispose();
    return clockState.value;
  };
  const parentB = new AbortController();
  const b = await outcome(own.run({ deadlineAt: clockState.value + 60_000, signal: parentB.signal }, () => 'never'));
  assert.ok(!b.ok && isFixed(b.error, 'closed') && timeouts() === timersB && getEventListeners(parentB.signal, 'abort').length === 0);

  // (c) workの後、待機のlistenerを作る直前の時計の読取りで元abort → aborted、slotのsignalへlistenerを残さない。
  const parentC = new AbortController();
  let captured;
  let reads = 0;
  clockState.onNow = () => {
    reads += 1;
    // 1回目: slotを開く、2回目: work内のcurrent、3回目: 待機の直前。
    if (reads === 3) {
      clockState.onNow = null;
      parentC.abort();
    }
    return clockState.value;
  };
  const c = await outcome(ctx.run({ deadlineAt: clockState.value + 60_000, signal: parentC.signal }, () => {
    captured = ctx.current();
    return new Promise(() => {});
  }));
  clockState.onNow = null;
  assert.ok(!c.ok && isFixed(c.error, 'aborted') && reads === 3);
  assert.ok(captured.signal.aborted && getEventListeners(captured.signal, 'abort').length === 0 && getEventListeners(parentC.signal, 'abort').length === 0);

  // 開始時の時計の不正: 例外/非有限/小数/負/ISO域外 → 全て固定unavailable（timed_outと区別、I/O 0）。
  for (const [value, code] of [[() => { throw new Error('clock secret'); }, 'unavailable'], [() => Number.NaN, 'unavailable'], [() => Number.POSITIVE_INFINITY, 'unavailable'], [() => 1.5, 'unavailable'], [() => -1, 'unavailable'], [() => 8_640_000_000_000_001, 'unavailable']]) {
    clockState.onNow = value;
    const result = await outcome(ctx.run(op(), () => 'never'));
    clockState.onNow = null;
    assert.ok(!result.ok && isFixed(result.error, code), code);
  }
});

test('U10 concurrent requests keep their own slot/owner/Grant: aborting one (held) does not affect the other, no global mixing', async () => {
  const env = main;
  const ownerA = await newOwner();
  const ownerB = await newOwner();
  const tokenA = await issue(env, ownerA);
  const tokenB = await issue(env, ownerB);
  const hold = gate();
  env.kms.control.decryptHolds.push(hold);
  const parentA = new AbortController();
  const parentB = new AbortController();
  const pA = outcome(env.resolver(tokenA.value, op({ signal: parentA.signal })));
  await hold.whenReached;
  const rB = await env.resolver(tokenB.value, op({ signal: parentB.signal }));
  assert.ok(rB.ownerId === ownerB && rB.grantId === tokenB.grantId);
  parentA.abort();
  const rA = await pA;
  hold.release('ok');
  assert.ok(!rA.ok && isFixed(rA.error, 'aborted') && !parentB.signal.aborted);

  // 2つの並行runのcurrentは、それぞれ自分のslot（期限・signal）だけ。
  const ctx = env.ctx;
  const start = clockState.value;
  const gateA = gate();
  const gateB = gate();
  const runA = ctx.run({ deadlineAt: start + 7_000, signal: new AbortController().signal }, async () => {
    await gateA.promise;
    return ctx.current().deadlineAt;
  });
  const runB = ctx.run({ deadlineAt: start + 9_000, signal: new AbortController().signal }, async () => {
    await gateB.promise;
    return ctx.current().deadlineAt;
  });
  gateB.release();
  gateA.release();
  assert.deepEqual(await Promise.all([runA, runB]), [start + 7_000, start + 9_000]);
  const both = await Promise.all([env.resolver(tokenA.value, op()), env.resolver(tokenB.value, op())]);
  assert.ok(both[0].ownerId === ownerA && both[1].ownerId === ownerB && both[0].grantId === tokenA.grantId && both[1].grantId === tokenB.grantId);
});

test('U11 re-check right before returning: token expiry passed during the owner read -> null; late owner result after abort is not adopted', async () => {
  // 短いtoken寿命（5秒）の別Provider: 元slot（20秒）の内でtokenの期限だけを過ぎさせる。
  const env = assemble({ ttlSec: SHORT_TTL_SEC });
  contexts.push(env.ctx);
  const owner = await newOwner(env);
  sync();
  const control = await issue(env, owner);
  assert.equal((await env.resolver(control.value, op()))?.ownerId, owner, 'control: resolves without the clock change');
  const issued = await issue(env, owner);
  env.db.control.onGet = async (path) => {
    if (kindOf(path) !== 'owner') return;
    env.db.control.onGet = null;
    advance(SHORT_TTL_SEC * 1000 + 1_000);
  };
  const result = await outcome(env.resolver(issued.value, op()));
  sync();
  assert.ok(result.ok && result.value === null);

  const issued2 = await issue(env, owner);
  const hold = gate();
  env.db.control.onGet = async (path) => {
    if (kindOf(path) !== 'owner') return;
    env.db.control.onGet = null;
    hold.reached();
    await hold.promise;
  };
  const parent = new AbortController();
  const pending = outcome(env.resolver(issued2.value, op({ signal: parent.signal })));
  await hold.whenReached;
  parent.abort();
  const aborted = await pending;
  hold.release();
  await sleep(5);
  assert.ok(!aborted.ok && isFixed(aborted.error, 'aborted'));
});

test('U12 invalid clock observations during the request are a fixed unavailable: no later I/O, no success, no timer/listener left; abort/dispose in the same observation take priority', async () => {
  const env = main;
  const owner = await newOwner();
  const bads = [['negative', () => -1], ['fraction', () => clockState.value + 0.5], ['nan', () => Number.NaN], ['infinity', () => Number.POSITIVE_INFINITY], ['beyond-iso', () => 8_640_000_000_000_001], ['throw', () => { throw new Error('clock secret'); }]];
  // (a) AccessToken文書の読取りの後から時計が不正 → unavailable（nullでない）、開封・Grant/owner読取り0。
  for (const [name, bad] of bads) {
    const issued = await issue(env, owner);
    const parent = new AbortController();
    const timersBefore = timeouts();
    const log = env.db.stats.log.length;
    const dec = env.kms.stats.decrypt;
    env.db.control.onGet = async (path) => {
      if (kindOf(path) !== 'token') return;
      env.db.control.onGet = null;
      clockState.onNow = bad;
    };
    let result;
    try {
      result = await outcome(env.resolver(issued.value, op({ signal: parent.signal })));
    } finally {
      clockState.onNow = null;
      env.db.control.onGet = null;
    }
    assert.ok(!result.ok && isFixed(result.error, 'unavailable'), name);
    assert.deepEqual(env.db.stats.log.slice(log).map(kindOf), ['token'], name);
    assert.equal(env.kms.stats.decrypt, dec, name);
    assert.ok(timeouts() === timersBefore && getEventListeners(parent.signal, 'abort').length === 0, name);
  }
  // (b) ownerの読取りの後（正常返却の直前の段階）で不正 → unavailable、成功0。
  for (const [name, bad] of bads.slice(0, 2)) {
    const issued = await issue(env, owner);
    env.db.control.onGet = async (path) => {
      if (kindOf(path) !== 'owner') return;
      env.db.control.onGet = null;
      clockState.onNow = bad;
    };
    let result;
    try {
      result = await outcome(env.resolver(issued.value, op()));
    } finally {
      clockState.onNow = null;
      env.db.control.onGet = null;
    }
    assert.ok(!result.ok && isFixed(result.error, 'unavailable'), name);
  }
  // (c) 公開run: workの中のcurrent()は同期の固定unavailable、返却直前の不正な観測ではworkの値を採用しない。
  const ctx = env.ctx;
  const inner = await outcome(ctx.run(op(), async () => {
    await sleep(1);
    clockState.onNow = () => -5;
    try {
      ctx.current();
      return 'adopted';
    } catch (error) {
      return error;
    } finally {
      clockState.onNow = null;
    }
  }));
  assert.ok(inner.ok && isFixed(inner.value, 'unavailable'));
  const returning = await outcome(ctx.run(op(), async () => {
    await sleep(1);
    clockState.onNow = () => Number.NaN;
    return 'late value';
  }));
  clockState.onNow = null;
  assert.ok(!returning.ok && isFixed(returning.error, 'unavailable'));
  // (d) resolverの検査（ownerの読取り後の1回目はConnectStorage自身の時計、2回目がresolverのlive）の不正な観測の中の元abort → aborted、
  // dispose → closed（中止・閉鎖が優先）。timer/listener 0。
  const armSecond = (action, value) => {
    let reads = 0;
    clockState.onNow = () => {
      reads += 1;
      if (reads < 2) return clockState.value;
      clockState.onNow = null;
      action();
      return value;
    };
  };
  const issuedD = await issue(env, owner);
  const parentD = new AbortController();
  const timersD = timeouts();
  env.db.control.onGet = async (path) => {
    if (kindOf(path) !== 'owner') return;
    env.db.control.onGet = null;
    armSecond(() => parentD.abort(), Number.NaN);
  };
  const abortedD = await outcome(env.resolver(issuedD.value, op({ signal: parentD.signal })));
  clockState.onNow = null;
  env.db.control.onGet = null;
  assert.ok(!abortedD.ok && isFixed(abortedD.error, 'aborted') && timeouts() === timersD && getEventListeners(parentD.signal, 'abort').length === 0);
  const own = assemble();
  contexts.push(own.ctx);
  const ownerE = await newOwner(own);
  const issuedE = await issue(own, ownerE);
  const parentE = new AbortController();
  own.db.control.onGet = async (path) => {
    if (kindOf(path) !== 'owner') return;
    own.db.control.onGet = null;
    armSecond(() => own.ctx.dispose(), -1);
  };
  const closedE = await outcome(own.resolver(issuedE.value, op({ signal: parentE.signal })));
  clockState.onNow = null;
  own.db.control.onGet = null;
  assert.ok(!closedE.ok && isFixed(closedE.error, 'closed') && getEventListeners(parentE.signal, 'abort').length === 0);
  // 時計が正常に戻れば同じtokenは解決できる（不正を恒久状態にしない）。
  const recovered = await env.resolver(issuedD.value, op());
  assert.equal(recovered?.ownerId, owner);
});
