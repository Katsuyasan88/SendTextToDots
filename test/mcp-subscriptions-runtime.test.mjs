// 購読runtime（createKmsSubscriptionRegistrationRuntime）を、通信なしのfake Firestore（参照・snapshot・全読取り後にまとめて書く
// transaction・同じdataのsetは版を変えない）・合成AES-GCM KMS transport・制御した時計・試験の代替verificationSender（関数。HTTPなし）で
// 確かめる。Grant文書はConnectStorageのupsert（KMS port・固定codec）で封緘し、markerはlocal namespaceへfixtureが書く。
// 確かめる点: 購読・延長・宛先変更・解除、callback検証の単回送出、owner・Grant・要求の分離、元期限・中断・dispose、内部失敗の固定化。
// 実SDK・emulator・listen・接続・外部送信・子process 0。出力は試験名と結果・件数だけ（owner・Grant・URL・secret・capsule・payload・hashを出さない）。
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { readFileSync } from 'node:fs';
import { after, test } from 'node:test';

import { ConnectStorage } from '../dist/connect/firestore.js';
import { createConnectKmsSealingPort } from '../dist/connect/kms-port.js';
import { EVENT_NAME, eventsListResult } from '../dist/events/contract.js';
import * as runtimeModule from '../dist/events/kms-subscription-runtime.js';
import { SubscribeError, VerificationSendError } from '../dist/events/subscriptions.js';
import { crc32c, createKmsSealingCodec } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument } from '../dist/storage/firestore/kms-subscription-format.js';

const { createKmsSubscriptionRegistrationRuntime, KmsSubscriptionRuntimeConfigError, KmsSubscriptionRuntimeError } = runtimeModule;

const PROJECT = 'demo-sttd-subscriptions';
const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
const RESOURCE = 'https://mcp.sttd-subscriptions.invalid/mcp';
const NS = `t256_${randomUUID()}`;
const SUB_NS = `t268_${randomUUID()}`;
const DAY = 86_400_000;
const BASE = 1_900_000_000_000;
const GRACE = 300_000;
const EVENT = 'text.submitted';
/** 0.2.0のイベント名。0.3.0では未知のイベント名として扱う。 */
const OLD_EVENT = 'shortcut.triggered';
const RT_MESSAGES = {
  invalid_input: 'kms subscription runtime: invalid input',
  unavailable: 'kms subscription runtime: unavailable',
  timed_out: 'kms subscription runtime: timed out',
  aborted: 'kms subscription runtime: aborted',
  closed: 'kms subscription runtime: closed',
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
const errors = [];
const timeouts = () => process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
const baselineTimeouts = timeouts();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------- 制御した時計 ----------
const clockState = { value: BASE, calls: 0, onNow: null };
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
const op = (overrides = {}) => ({ deadlineAt: clockState.value + 3_600_000, signal: new AbortController().signal, ...overrides });

// ---------- fake Firestore ----------
const canonical = (value) =>
  JSON.stringify(value, (key, inner) =>
    inner && typeof inner === 'object' && !Array.isArray(inner) ? Object.fromEntries(Object.entries(inner).sort(([a], [b]) => (a < b ? -1 : 1))) : inner,
  );
const borrowed = { closes: 0 };
function fakeDb(projectId = PROJECT) {
  const docs = new Map();
  let tick = 0;
  const stats = { transactions: 0, closures: 0, txWrites: 0, maxAttempts: [], getAll: 0 };
  const control = { holdGetAll: null, inClosure: 0 };
  function stamp() {
    tick += 1;
    return { seconds: 1_900_000_000 + tick, nanoseconds: 123_000_001 + tick };
  }
  function write(path, data) {
    const previous = docs.get(path);
    if (previous && canonical(previous.data) === canonical(data)) return;
    docs.set(path, { data: structuredClone(data), updateTime: stamp() });
  }
  function snapshot(path) {
    const entry = docs.get(path);
    return {
      ref: refOf(path),
      exists: entry !== undefined,
      updateTime: entry === undefined ? undefined : { ...entry.updateTime },
      data() {
        return entry === undefined ? undefined : structuredClone(entry.data);
      },
    };
  }
  function collectionOf(path) {
    return { doc: (id) => refOf(`${path}/${id}`) };
  }
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      async set(data) {
        write(path, data);
      },
      async update(partial) {
        const previous = docs.get(path);
        if (!previous) throw new Error('fake: NOT_FOUND');
        write(path, { ...previous.data, ...structuredClone(partial) });
      },
      async delete() {
        docs.delete(path);
      },
      async get() {
        return snapshot(path);
      },
    };
  }
  const db = {
    projectId,
    docs,
    stats,
    control,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    write,
    snapshot,
    terminate() {
      borrowed.closes += 1;
    },
    close() {
      borrowed.closes += 1;
    },
    async runTransaction(fn, options) {
      stats.transactions += 1;
      stats.maxAttempts.push(options?.maxAttempts);
      const writes = [];
      const tx = {
        async getAll(...refs) {
          stats.getAll += 1;
          const hold = control.holdGetAll;
          if (hold) {
            control.holdGetAll = null;
            hold.reached();
            await hold.promise;
          }
          return refs.map((ref) => snapshot(ref.path));
        },
        set(ref, data) {
          writes.push(['set', ref.path, structuredClone(data)]);
          return tx;
        },
        update(ref, partial) {
          writes.push(['update', ref.path, structuredClone(partial)]);
          return tx;
        },
        create(ref, data) {
          writes.push(['create', ref.path, structuredClone(data)]);
          return tx;
        },
        delete(ref) {
          writes.push(['delete', ref.path]);
          return tx;
        },
      };
      stats.closures += 1;
      control.inClosure += 1;
      let result;
      try {
        result = await fn(tx);
      } finally {
        control.inClosure -= 1;
      }
      for (const [kind, path, data] of writes) {
        stats.txWrites += 1;
        if (kind === 'update') {
          const previous = docs.get(path);
          if (!previous) throw new Error('fake: NOT_FOUND');
          write(path, { ...previous.data, ...data });
        } else if (kind === 'delete') docs.delete(path);
        else write(path, data);
      }
      return result;
    },
  };
  return db;
}

// ---------- 合成AES-GCM KMS（閉包の中の呼出し・encryptへ渡った平文を数える） ----------
let activeDb = null;
function aesKms(key) {
  const stats = { encrypt: 0, decrypt: 0, inTransaction: 0 };
  const control = { holdEncrypt: null, onEncrypt: null };
  const inTx = () => (activeDb !== null && activeDb.control.inClosure > 0 ? 1 : 0);
  const transport = {
    async encrypt(request) {
      stats.encrypt += 1;
      stats.inTransaction += inTx();
      control.onEncrypt?.(request);
      const hold = control.holdEncrypt;
      if (hold) {
        control.holdEncrypt = null;
        hold.reached();
        await hold.promise;
      }
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(request.additionalAuthenticatedData);
      const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
      const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
      return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
    },
    async decrypt(request) {
      stats.decrypt += 1;
      stats.inTransaction += inTx();
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
  return { promise, reached, release: (value) => release(value), whenReached };
}

// ---------- 代替のverificationSender（HTTPなし）。既定はchallengeを正しくechoする。 ----------
const sent = [];
const senderState = { behavior: null };
const echo = (request) => ({ status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) });
function verificationSender(request, signal) {
  sent.push({ request, signal, args: arguments.length });
  if (senderState.behavior) return senderState.behavior(request, signal);
  return Promise.resolve(echo(request));
}

// ---------- fixture ----------
const hmacKey = randomBytes(32);
const baseHasher = createHmacHasher(hmacKey);
const hasher = {
  hash: (purpose, value) => baseHasher.hash(purpose, value),
  close() {
    borrowed.closes += 1;
  },
  dispose() {
    borrowed.closes += 1;
  },
};
const kmsKey = randomBytes(32);
const kms = aesKms(kmsKey);
const db = fakeDb();
activeDb = db;
const otherDb = fakeDb(PROJECT);
const baseKms = { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: KEY, writeVersion: 1, readVersions: [1] };
const connectKms = () => ({ ...baseKms, namespace: NS, transport: kms.transport });
const subscriptionKms = () => ({ ...baseKms, namespace: SUB_NS, transport: kms.transport });
const box = createConnectKmsSealingPort({ kms: { ...connectKms(), clock }, operation: () => ({ deadlineAt: Math.floor(clockState.value) + 60_000 }) });
const connectOf = (instance) =>
  new ConnectStorage({ db: instance, namespace: NS, hasher: baseHasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
const connect = connectOf(db);
const grantsAdapter = connect.adapterFactory('Grant');
const clockOption = {
  now: () => clock.now(),
  close() {
    borrowed.closes += 1;
  },
};
const optionsOf = (overrides = {}) => ({ db, connect, connectNamespace: NS, resource: RESOURCE, kms: subscriptionKms(), hasher, clock: clockOption, verificationSender, ...overrides });
const runtimes = [];
const makeRuntime = (overrides = {}) => {
  const runtime = createKmsSubscriptionRegistrationRuntime(optionsOf(overrides));
  runtimes.push(runtime);
  return runtime;
};
const rt = makeRuntime();
const policy = createKmsSubscriptionPolicy({ ...baseKms, namespace: SUB_NS });
db.write(`sttdAuth/${SUB_NS}/config/kms-subscription`, kmsMarkerDocument(policy));
// 試験側の独立の開封（同じ鍵・同じt268 policy、runtimeとは別のtransportと計数）。
const openerKms = aesKms(kmsKey);
const opener = createKmsSealingCodec({ ...baseKms, namespace: SUB_NS, transport: openerKms.transport, clock: { now: () => Date.now() } });
remember(RESOURCE);

const subPath = (ownerId) => `sttdAuth/${SUB_NS}/subscriptions/${ownerId}`;
const ownerPath = (ownerId) => `sttdConnect/${NS}/owners/${ownerId}`;
const dataOf = (path) => (db.docs.get(path) ? structuredClone(db.docs.get(path).data) : undefined);
const versionOf = (path) => (db.docs.get(path) ? `${db.docs.get(path).updateTime.seconds}.${db.docs.get(path).updateTime.nanoseconds}` : 'none');
const newUrl = (label = 'h') => remember(`https://hooks.sttd-subscriptions.example/${label}/${randomBytes(6).toString('hex')}`);
const newSecret = (bytes = 32) => remember(`whsec_${randomBytes(bytes).toString('base64')}`);
const idOf = (ownerId, url) => `sub_${baseHasher.hash('subscription.id', JSON.stringify([ownerId, EVENT, '{}', url]))}`;
const hashOf = (secret) => baseHasher.hash('subscription.secret', secret);

// 利用許可（合成）: ownerごとに別のidentityHashと許可record（active・世代）を置き、Grantの同意記録へ同じ世代を束縛する。
const accessOf = new Map();
const accessPath = (identityHash) => `sttdConnect/${NS}/access/${identityHash}`;
const metaPath = (grantId) => `sttdConnect/${NS}/grantMeta/${baseHasher.hash(`t256:${NS}:grant`, grantId)}`;
function setAccess(ownerId, state, generation = randomUUID()) {
  const entry = accessOf.get(ownerId);
  entry.generation = generation;
  db.write(accessPath(entry.identityHash), { version: 1, state, generation, updatedAt: Math.floor(clockState.value) });
  return generation;
}
function newOwner(extra = {}) {
  const ownerId = remember(randomUUID());
  const now = Math.floor(clockState.value);
  const identityHash = randomBytes(32).toString('hex');
  db.write(ownerPath(ownerId), { identityHash, sealedUid: remember(`sealed-uid-${randomUUID()}`), createdAt: now, lastActiveAt: now, revokedAt: null, ...extra });
  accessOf.set(ownerId, { identityHash, generation: null });
  setAccess(ownerId, 'active');
  return ownerId;
}
const payloadOf = (ownerId, grantId, overrides = {}) => {
  const nowSec = Math.floor(clockState.value / 1000);
  return { iat: nowSec, exp: nowSec + 3600, accountId: ownerId, clientId: 'https://client.sttd-subscriptions.invalid/meta.json', kind: 'Grant', jti: grantId, resources: { [RESOURCE]: 'sttd:events' }, ...overrides };
};
async function newGrant(ownerId, overrides = {}, grantId = remember(`grant-${randomBytes(9).toString('base64url')}`), meta = {}) {
  const payload = payloadOf(ownerId, grantId, overrides);
  remember(JSON.stringify(payload));
  await grantsAdapter.upsert(grantId, payload, 3600);
  const generation = accessOf.get(ownerId)?.generation;
  if (generation !== undefined) {
    db.write(metaPath(grantId), { ownerId, authTimeSec: Math.floor(clockState.value / 1000), createdAt: Math.floor(clockState.value), accessGeneration: generation, ...meta });
  }
  return grantId;
}
async function who() {
  const ownerId = newOwner();
  const grantId = await newGrant(ownerId);
  return { ownerId, grantId };
}
function classify(error) {
  if (error instanceof SubscribeError) return `sub:${error.failure.kind}${error.failure.reason ? `:${error.failure.reason}` : ''}`;
  if (error instanceof KmsSubscriptionRuntimeError) return `rt:${error.code}`;
  if (error instanceof KmsSubscriptionRuntimeConfigError) return 'config';
  return `other:${error?.name}`;
}
async function outcome(promise) {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    errors.push(error);
    return { ok: false, kind: classify(error), error };
  }
}
const subscribe = (auth, input, operation = op(), runtime = rt) => outcome(runtime.service.subscribe(auth, input, operation));
const unsubscribe = (auth, identity, operation = op(), runtime = rt) => outcome(runtime.service.unsubscribe(auth, identity, operation));
const input = (url, secret, extra = {}) => ({ name: EVENT, url, secret, ...extra });
function expectRt(result, code) {
  assert.equal(result.ok, false, `expected rt:${code}`);
  assert.equal(result.kind, `rt:${code}`);
  assert.equal(result.error.message, RT_MESSAGES[code]);
  assert.equal(result.error.cause, undefined);
}
/** 計数の差分（KMS・transaction・challenge）。 */
function counter() {
  const start = { encrypt: kms.stats.encrypt, decrypt: kms.stats.decrypt, tx: db.stats.transactions, sent: sent.length, writes: db.stats.txWrites };
  return () => ({
    encrypt: kms.stats.encrypt - start.encrypt,
    decrypt: kms.stats.decrypt - start.decrypt,
    tx: db.stats.transactions - start.tx,
    sent: sent.length - start.sent,
    writes: db.stats.txWrites - start.writes,
  });
}
/** 標準webhookの署名（公式libraryと同じ式）をsecretで計算し、headerの値と比べる。 */
function signatureValid(secret, request) {
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': signature } = request.headers;
  const expected = `v1,${createHmac('sha256', key).update(`${id}.${timestamp}.${request.body}`).digest('base64')}`;
  key.fill(0);
  return signature === expected;
}
const bindingOf = (purpose, ownerId, id, secretHash = null) => ({ purpose, model: 'Subscription', recordId: id, ownerBinding: `id:${ownerId}`, secretHash });
async function openText(binding, capsule) {
  const plaintext = await opener.open(binding, capsule, { deadlineAt: Date.now() + 20_000 });
  try {
    return plaintext.toString('utf8');
  } finally {
    plaintext.fill(0);
  }
}
/** 公開入力から作った所有Buffer（URL・secretのUTF-8）を記録する。終了後に全て0であることを見る。 */
function watchOwnedBuffers(values) {
  const original = Buffer.from;
  const seen = [];
  Buffer.from = function patchedFrom(...args) {
    const result = Reflect.apply(original, this, args);
    if (typeof args[0] === 'string' && values.includes(args[0])) seen.push(result);
    return result;
  };
  return () => {
    Buffer.from = original;
    return seen;
  };
}

after(() => {
  for (const runtime of runtimes) runtime.dispose();
  const leaked = errors.filter((error) => [...secrets].some((value) => `${error.message}\n${error.stack}`.includes(value))).length;
  process.stdout.write(
    `# MCP_SUBSCRIPTIONS_COUNTS encrypt=${kms.stats.encrypt} decrypt=${kms.stats.decrypt} kmsInTransaction=${kms.stats.inTransaction} challenges=${sent.length} transactions=${db.stats.transactions} txWrites=${db.stats.txWrites} maxAttempts=${JSON.stringify([...new Set(db.stats.maxAttempts)])} errors=${errors.length} leaked=${leaked} unhandled=${unhandled} borrowedCloses=${borrowed.closes} timeouts=${timeouts() - baselineTimeouts}\n`,
  );
  assert.equal(kms.stats.inTransaction, 0, 'KMS inside transaction closures');
  assert.deepEqual([...new Set(db.stats.maxAttempts)], [5]);
  assert.equal(leaked, 0);
  assert.equal(unhandled, 0);
  assert.equal(borrowed.closes, 0);
});

test('U01 factory: exact options, fixed config error before side effects, frozen {service, dispose}, no I/O', { timeout: 10_000 }, () => {
  const count = counter();
  const built = makeRuntime();
  assert.ok(Object.isFrozen(built) && Object.isFrozen(built.service));
  assert.deepEqual(Object.keys(built).sort(), ['dispose', 'service']);
  assert.deepEqual(Object.keys(built.service).sort(), ['subscribe', 'unsubscribe']);
  assert.deepEqual(Object.keys(runtimeModule).sort(), ['KmsSubscriptionRuntimeConfigError', 'KmsSubscriptionRuntimeError', 'createKmsSubscriptionRegistrationRuntime']);
  let getterCalls = 0;
  const withGetter = optionsOf();
  Object.defineProperty(withGetter, 'hasher', { enumerable: true, get: () => ((getterCalls += 1), hasher) });
  const { verificationSender: _omit, ...missing } = optionsOf();
  const kmsWithClock = { ...subscriptionKms(), clock };
  const bad = [
    null,
    [],
    missing,
    { ...optionsOf(), extra: 1 },
    { ...optionsOf(), [Symbol('x')]: 1 },
    withGetter,
    new Proxy(optionsOf(), {}),
    optionsOf({ verificationSender: 'nope' }),
    optionsOf({ verificationSender: new Proxy(verificationSender, {}) }),
    optionsOf({ hasher: {} }),
    optionsOf({ clock: {} }),
    optionsOf({ connect: {} }),
    optionsOf({ db: {} }),
    optionsOf({ connectNamespace: 't256_not-uuid' }),
    optionsOf({ resource: 'http://mcp.example/mcp' }),
    optionsOf({ kms: kmsWithClock }),
    optionsOf({ kms: { ...subscriptionKms(), namespace: NS } }),
    optionsOf({ kms: { ...subscriptionKms(), transport: { decrypt: kms.transport.decrypt } } }),
    optionsOf({ kms: { ...subscriptionKms(), readVersions: [2] } }),
  ];
  for (const options of bad) {
    assert.throws(
      () => createKmsSubscriptionRegistrationRuntime(options),
      (error) => error instanceof KmsSubscriptionRuntimeConfigError && error.code === 'subscription_runtime_config_invalid' && error.message === 'subscription_runtime_config_invalid' && error.cause === undefined,
    );
  }
  assert.equal(getterCalls, 0);
  assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 });
  // class instance（ConnectStorage）のmethodは元instanceへ束縛される（後のprototype差替えでも同じmethod）。
  built.dispose();
  built.dispose();
});

test('U02 initial subscribe: one signed challenge, two seals with the fixed binding, one activate; result/DB/owned buffers', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u02');
  const secret = newSecret();
  const count = counter();
  const stop = watchOwnedBuffers([url, secret]);
  const result = await subscribe(auth, input(url, secret, { ttlMs: 60_000 }));
  const owned = stop();
  assert.equal(result.ok, true, result.kind);
  const id = idOf(auth.ownerId, url);
  assert.deepEqual(Object.keys(result.value).sort(), ['id', 'refreshBefore']);
  assert.ok(Object.isFrozen(result.value));
  assert.equal(result.value.id, id);
  assert.equal(result.value.refreshBefore, new Date(clockState.value + 60_000).toISOString());
  const c = count();
  assert.deepEqual({ encrypt: c.encrypt, decrypt: c.decrypt, tx: c.tx, sent: c.sent }, { encrypt: 2, decrypt: 1, tx: 3, sent: 1 });
  const challenge = sent.at(-1);
  assert.equal(challenge.args, 2);
  assert.ok(challenge.signal instanceof AbortSignal && challenge.signal.aborted, 'challenge signal aborted after completion');
  assert.ok(Object.isFrozen(challenge.request) && Object.isFrozen(challenge.request.headers));
  assert.equal(challenge.request.url, url);
  assert.deepEqual(Object.keys(challenge.request.headers).sort(), ['content-type', 'webhook-id', 'webhook-signature', 'webhook-timestamp', 'x-mcp-subscription-id']);
  assert.equal(challenge.request.headers['content-type'], 'application/json');
  assert.equal(challenge.request.headers['x-mcp-subscription-id'], id);
  assert.match(challenge.request.headers['webhook-id'], /^msg_[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge.request.headers['webhook-timestamp'], String(Math.floor(clockState.value / 1000)));
  const body = JSON.parse(challenge.request.body);
  assert.deepEqual(Object.keys(body), ['type', 'challenge']);
  assert.equal(body.type, 'verification');
  assert.match(body.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(signatureValid(secret, challenge.request), 'challenge signed with the subscription secret');
  assert.ok(!signatureValid(newSecret(), challenge.request));
  const doc = dataOf(subPath(auth.ownerId));
  assert.equal(doc.version, 2);
  assert.equal(doc.active.id, id);
  assert.equal(doc.active.grantId, auth.grantId);
  assert.equal(doc.active.secretHash, hashOf(secret));
  assert.equal(doc.active.previousSecret, null);
  assert.equal(doc.active.expiresAt, clockState.value + 60_000);
  assert.equal(doc.knownDestinationId, id);
  assert.equal(await openText(bindingOf('callback-url', auth.ownerId, id), doc.active.sealedUrl), url);
  assert.equal(await openText(bindingOf('callback-secret', auth.ownerId, id, hashOf(secret)), doc.active.sealedSecret), secret);
  await assert.rejects(openText(bindingOf('callback-url', randomUUID(), id), doc.active.sealedUrl));
  const stored = JSON.stringify(doc);
  assert.ok(!stored.includes(url) && !stored.includes(secret) && !stored.includes(body.challenge));
  assert.equal(owned.length, 2, 'owned UTF-8 buffers for URL and secret');
  assert.ok(owned.every((buffer) => buffer.every((byte) => byte === 0)), 'owned buffers zeroed');
});

test('U03 extend: same URL/secret/Grant -> extended without challenge/seal; TTL omitted=24h, cap 24h, null=unbounded', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u03');
  const secret = newSecret();
  assert.equal((await subscribe(auth, input(url, secret, { ttlMs: 1_000 }))).ok, true);
  for (const [ttl, expected] of [
    [undefined, clockState.value + DAY],
    [999_999_999, clockState.value + DAY],
    [5_000, clockState.value + 5_000],
    [null, null],
  ]) {
    const count = counter();
    const extra = ttl === undefined ? {} : { ttlMs: ttl };
    const result = await subscribe(auth, input(url, secret, extra));
    assert.equal(result.ok, true, result.kind);
    assert.equal(result.value.refreshBefore, expected === null ? null : new Date(expected).toISOString());
    assert.equal(dataOf(subPath(auth.ownerId)).active.expiresAt, expected);
    const c = count();
    assert.deepEqual({ encrypt: c.encrypt, sent: c.sent, tx: c.tx }, { encrypt: 0, sent: 0, tx: 2 });
  }
  const explicitUndefined = await subscribe(auth, input(url, secret, { ttlMs: undefined, cursor: undefined }));
  assert.equal(explicitUndefined.value.refreshBefore, new Date(clockState.value + DAY).toISOString());
  const nullCursor = await subscribe(auth, input(url, secret, { cursor: null }));
  assert.equal(nullCursor.ok, true);
});

test('U04 different destination -> destination_change_pending; no challenge/seal (request Grant decrypt only)', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u04');
  assert.equal((await subscribe(auth, input(url, newSecret()))).ok, true);
  const before = dataOf(subPath(auth.ownerId));
  const count = counter();
  const other = newUrl('u04b');
  const result = await subscribe(auth, input(other, newSecret()));
  assert.equal(result.kind, 'sub:destination_change_pending');
  const c = count();
  assert.deepEqual({ encrypt: c.encrypt, sent: c.sent }, { encrypt: 0, sent: 0 });
  assert.ok(c.decrypt >= 1);
  const after = dataOf(subPath(auth.ownerId));
  assert.equal(after.pending.id, idOf(auth.ownerId, other));
  assert.deepEqual(after.active, before.active);
});

test('U05 public input boundaries: invalid_request / unknown_event / cursor_unsupported with DB/KMS/challenge 0', { timeout: 30_000 }, async () => {
  const auth = await who();
  const secret = newSecret();
  const url = newUrl('u05');
  const lone = `https://hooks.sttd-subscriptions.example/${String.fromCharCode(0xd800)}x`;
  const long2049 = `https://h.example/${'a'.repeat(2049 - 18)}`;
  const multi2050 = `https://h.example/${'é'.repeat(1016)}`;
  let getterCalls = 0;
  const getterInput = input(url, secret);
  Object.defineProperty(getterInput, 'url', { enumerable: true, get: () => ((getterCalls += 1), url) });
  const invalid = [
    null,
    'x',
    [],
    { url, secret },
    { name: EVENT, url },
    { ...input(url, secret), extra: 1 },
    { ...input(url, secret), [Symbol('s')]: 1 },
    getterInput,
    new Proxy(input(url, secret), {}),
    { name: 1, url, secret },
    input(1, secret),
    input(url, 1),
    input('http://hooks.sttd-subscriptions.example/x', secret),
    input('https://hooks.sttd-subscriptions.example:8443/x', secret),
    input('https://user:pass@hooks.sttd-subscriptions.example/x', secret),
    input('https://hooks.sttd-subscriptions.example/x#frag', secret),
    input('https://hooks.sttd-subscriptions.example/a b', secret),
    input('https://hooks.sttd-subscriptions.example/a\\b', secret),
    input(`https://hooks.sttd-subscriptions.example/a${String.fromCharCode(7)}`, secret),
    input('https://hooks.sttd-subscriptions.example./x', secret),
    input('', secret),
    input(lone, secret),
    input(long2049, secret),
    input(multi2050, secret),
    input(url, 'secret'),
    input(url, `whsec_${randomBytes(23).toString('base64')}`),
    input(url, `whsec_${randomBytes(65).toString('base64')}`),
    input(url, `whsec_${randomBytes(32).toString('base64')}!`),
    ...[0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '1', true, {}, Number.MAX_SAFE_INTEGER + 1].map((ttlMs) => input(url, secret, { ttlMs })),
    input(url, secret, { cursor: 5 }),
    input(url, secret, { cursor: {} }),
  ];
  const count = counter();
  for (const value of invalid) {
    const result = await subscribe(auth, value);
    assert.equal(result.kind, 'sub:invalid_request', `case ${invalid.indexOf(value)}`);
  }
  assert.equal(getterCalls, 0);
  assert.equal((await subscribe(auth, { ...input(url, secret), name: 'other.event' })).kind, 'sub:unknown_event');
  assert.equal((await subscribe(auth, input(url, secret, { cursor: 'abc' }))).kind, 'sub:cursor_unsupported');
  assert.equal((await subscribe(auth, input(url, secret, { cursor: '' }))).kind, 'sub:cursor_unsupported');
  // unsubscribeはexact {name, url}だけ
  for (const identity of [{ name: EVENT, url, secret }, { name: EVENT }, { name: EVENT, url: 'http://x.example/' }, null, { name: EVENT, url: lone }]) {
    assert.equal((await unsubscribe(auth, identity)).kind, 'sub:invalid_request');
  }
  assert.equal((await unsubscribe(auth, { name: 'other.event', url })).kind, 'sub:unknown_event');
  // 信頼済みcontextの不正は内部invalid_input
  for (const badAuth of [{ ownerId: 'x', grantId: auth.grantId }, { ownerId: auth.ownerId }, { ...auth, extra: 1 }, null]) expectRt(await subscribe(badAuth, input(url, secret)), 'invalid_input');
  const signal = new AbortController().signal;
  for (const badOp of [
    { deadlineAt: clockState.value + 1000 },
    { deadlineAt: clockState.value + 1000, signal: { aborted: false } },
    { deadlineAt: clockState.value + 1000.5, signal },
    { deadlineAt: String(clockState.value + 1000), signal },
    { deadlineAt: clockState.value + 1000, signal, extra: 1 },
    new Proxy({ deadlineAt: clockState.value + 1000, signal }, {}),
  ]) {
    expectRt(await subscribe(auth, input(url, secret), badOp), 'invalid_input');
    expectRt(await unsubscribe(auth, { name: EVENT, url }, badOp), 'invalid_input');
  }
  assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 });
  // 境界の正の対照: 2048byte（ASCII）・2048byte（2byte文字）は入力を通り、challengeまで進む（500で止める）。
  senderState.behavior = async () => ({ status: 500, body: '' });
  try {
    const ascii2048 = `https://h.example/${'a'.repeat(2048 - 18)}`;
    const multi2048 = `https://h.example/${'é'.repeat(1015)}`;
    assert.equal(Buffer.byteLength(ascii2048) + Buffer.byteLength(multi2048), 4096);
    assert.equal((await subscribe(auth, input(ascii2048, secret))).kind, 'sub:callback_endpoint:http_5xx');
    assert.equal(sent.at(-1).request.url, ascii2048);
    assert.equal((await subscribe(auth, input(multi2048, secret))).kind, 'sub:callback_endpoint:http_5xx');
    assert.equal(sent.at(-1).request.url, multi2048, 'original URL is used (no canonicalization)');
    assert.equal(sent.at(-1).request.headers['x-mcp-subscription-id'], idOf(auth.ownerId, multi2048));
  } finally {
    senderState.behavior = null;
  }
});

test('U06 challenge outcome classification: status/echo/sender errors, single send, no seal/write on failure', { timeout: 30_000 }, async () => {
  const auth = await who();
  const right = (request, extra = {}) => JSON.stringify({ ...extra, challenge: JSON.parse(request.body).challenge });
  let responseGetter = 0;
  const cases = [
    ['4xx', async () => ({ status: 404, body: '' }), 'sub:callback_endpoint:http_4xx'],
    ['400 with echo', async (r) => ({ status: 400, body: right(r) }), 'sub:callback_endpoint:http_4xx'],
    ['5xx', async () => ({ status: 503, body: '' }), 'sub:callback_endpoint:http_5xx'],
    ['3xx', async (r) => ({ status: 302, body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['1xx', async (r) => ({ status: 101, body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['wrong echo', async () => ({ status: 200, body: JSON.stringify({ challenge: 'x'.repeat(43) }) }), 'sub:callback_endpoint:challenge_failed'],
    ['not json', async () => ({ status: 200, body: 'ok' }), 'sub:callback_endpoint:challenge_failed'],
    ['array', async (r) => ({ status: 200, body: JSON.stringify([JSON.parse(r.body).challenge]) }), 'sub:callback_endpoint:challenge_failed'],
    ['challenge not string', async () => ({ status: 200, body: JSON.stringify({ challenge: 1 }) }), 'sub:callback_endpoint:challenge_failed'],
    ['too large', async (r) => ({ status: 200, body: right(r, { pad: 'a'.repeat(8192) }) }), 'sub:callback_endpoint:challenge_failed'],
    ['lone surrogate', async (r) => ({ status: 200, body: `${right(r).slice(0, -1)},"x":"${String.fromCharCode(0xdc00)}"}` }), 'sub:callback_endpoint:challenge_failed'],
    ['status 99', async (r) => ({ status: 99, body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['status 600', async (r) => ({ status: 600, body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['status 200.5', async (r) => ({ status: 200.5, body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['status string', async (r) => ({ status: '200', body: right(r) }), 'sub:callback_endpoint:challenge_failed'],
    ['body not string', async () => ({ status: 200, body: Buffer.from('x') }), 'sub:callback_endpoint:challenge_failed'],
    ['null response', async () => null, 'sub:callback_endpoint:challenge_failed'],
    ['getter response', async (r) => Object.defineProperty({ status: 200 }, 'body', { get: () => ((responseGetter += 1), right(r)) }), 'sub:callback_endpoint:challenge_failed'],
    ['proxy response', async (r) => new Proxy({ status: 200, body: right(r) }, {}), 'sub:callback_endpoint:challenge_failed'],
    ['send connection_refused', async () => Promise.reject(new VerificationSendError('connection_refused')), 'sub:callback_endpoint:connection_refused'],
    ['send timeout', async () => Promise.reject(new VerificationSendError('timeout')), 'sub:callback_endpoint:timeout'],
    ['send tls_error', async () => Promise.reject(new VerificationSendError('tls_error')), 'sub:callback_endpoint:tls_error'],
    ['send challenge_failed', async () => Promise.reject(new VerificationSendError('challenge_failed')), 'sub:callback_endpoint:challenge_failed'],
    ['send bogus reason', async () => Promise.reject(new VerificationSendError('http_4xx')), 'sub:callback_endpoint:challenge_failed'],
    ['send other error', async () => Promise.reject(new Error(`sender detail ${RESOURCE}`)), 'sub:callback_endpoint:challenge_failed'],
    ['send sync throw', () => {
      throw new Error('sync');
    }, 'sub:callback_endpoint:challenge_failed'],
    ['send forged SubscribeError', async () => Promise.reject(new SubscribeError({ kind: 'grant_inactive' })), 'sub:callback_endpoint:challenge_failed'],
  ];
  for (const [label, behavior, expected] of cases) {
    const url = newUrl('u06');
    senderState.behavior = behavior;
    const count = counter();
    const result = await subscribe(auth, input(url, newSecret()));
    senderState.behavior = null;
    assert.equal(result.kind, expected, label);
    assert.equal(result.error.message, result.error.failure.kind, label);
    const c = count();
    assert.deepEqual({ encrypt: c.encrypt, sent: c.sent, writes: c.writes, tx: c.tx }, { encrypt: 0, sent: 1, writes: 0, tx: 2 }, label);
    assert.ok(sent.at(-1).signal.aborted, `${label}: challenge signal aborted`);
  }
  assert.equal(responseGetter, 0);
  // 余分なJSON fieldは使わず、challengeが正確に一致すれば成功
  senderState.behavior = async (r) => ({ status: 201, body: right(r, { type: 'verification', note: 'x' }) });
  try {
    assert.equal((await subscribe(auth, input(newUrl('u06ok'), newSecret()))).ok, true);
  } finally {
    senderState.behavior = null;
  }
});

test('U07 challenge 10s / child 20s / original deadline boundaries (published value not adopted after the boundary)', { timeout: 30_000 }, async () => {
  // 送出の待機中に時計が開始+10000へ到達（子20秒は有効）→ callback_endpoint timeout、seal 0。
  const advanceIn = (ms) => async (request) => {
    advance(ms);
    return echo(request);
  };
  const cases = [
    [10_000, () => op(), 'sub:callback_endpoint:timeout'],
    [9_999, () => op(), 'ok'],
    [20_000, () => op(), 'rt:timed_out'],
    [3_000, () => op({ deadlineAt: clockState.value + 3_000 }), 'rt:timed_out'],
  ];
  for (const [ms, operationOf, expected] of cases) {
    // ownerごとに分ける（成功した登録が後の別URLを保留にしないように）。
    const fresh = await who();
    senderState.behavior = advanceIn(ms);
    const count = counter();
    const result = await subscribe(fresh, input(newUrl('u07'), newSecret()), operationOf());
    senderState.behavior = null;
    assert.equal(result.ok ? 'ok' : result.kind, expected, `advance ${ms}`);
    const c = count();
    assert.equal(c.sent, 1);
    assert.equal(c.encrypt, expected === 'ok' ? 2 : 0, `advance ${ms}: seals`);
  }
  // 決着しない送出: 呼出しdeadlineの到達でchallenge signalをabortし、callback_endpoint timeout（実時間を待たないよう時計を進めておく）。
  let abortedSeen = false;
  senderState.behavior = (request, signal) => {
    advance(9_990);
    signal.addEventListener('abort', () => {
      abortedSeen = true;
    });
    return new Promise(() => {});
  };
  const begun = Date.now();
  const never = await subscribe(await who(), input(newUrl('u07n'), newSecret()));
  senderState.behavior = null;
  assert.equal(never.kind, 'sub:callback_endpoint:timeout');
  assert.ok(abortedSeen && Date.now() - begun < 2_000);
  // 原期限が先: 決着しない送出を、元期限（子の期限timer）で打ち切る（timed_out）。
  senderState.behavior = () => new Promise(() => {});
  const shortAuth = await who();
  const short = await subscribe(shortAuth, input(newUrl('u07s'), newSecret()), op({ deadlineAt: clockState.value + 150 }));
  senderState.behavior = null;
  expectRt(short, 'timed_out');
});

test('U08 seal boundaries: 5s per seal, abort/dispose during seal, codec failure -> no activate/write', { timeout: 30_000 }, async () => {
  // 各条件はownerを分け、Grantの封緘（encrypt）を観測の前に済ませる。
  const [a1, a2, a3, a4] = [await who(), await who(), await who(), await who()];
  // 1つ目のsealの間に時計が開始+5000へ到達（codecと同じ5秒）→ 内部unavailable、activate 0。
  kms.control.onEncrypt = () => {
    kms.control.onEncrypt = null;
    advance(5_000);
  };
  let count = counter();
  const late = await subscribe(a1, input(newUrl('u08'), newSecret()));
  expectRt(late, 'unavailable');
  assert.deepEqual({ encrypt: count().encrypt, writes: count().writes, tx: count().tx }, { encrypt: 1, writes: 0, tx: 2 });
  // 4999は通る（対照）
  kms.control.onEncrypt = () => {
    kms.control.onEncrypt = null;
    advance(4_999);
  };
  assert.equal((await subscribe(a2, input(newUrl('u08ok'), newSecret()))).ok, true);
  // 2つ目のseal（secret）の間に中止 → aborted、activate 0
  const controller = new AbortController();
  let encrypts = 0;
  kms.control.onEncrypt = () => {
    encrypts += 1;
    if (encrypts === 2) {
      kms.control.onEncrypt = null;
      controller.abort();
    }
  };
  count = counter();
  const aborted = await subscribe(a3, input(newUrl('u08a'), newSecret()), op({ signal: controller.signal }));
  expectRt(aborted, 'aborted');
  assert.deepEqual({ encrypt: count().encrypt, writes: count().writes, tx: count().tx }, { encrypt: 2, writes: 0, tx: 2 });
  // seal中のdispose → closed、以後の新要求もclosed（DB/KMS/challenge 0）
  const local = makeRuntime();
  const hold = gate();
  kms.control.holdEncrypt = hold;
  count = counter();
  const pending = subscribe(a4, input(newUrl('u08d'), newSecret()), op(), local);
  await hold.whenReached;
  local.dispose();
  hold.release();
  expectRt(await pending, 'closed');
  assert.deepEqual({ encrypt: count().encrypt, writes: count().writes }, { encrypt: 1, writes: 0 });
  count = counter();
  expectRt(await subscribe(a4, input(newUrl('u08e'), newSecret()), op(), local), 'closed');
  expectRt(await unsubscribe(a4, { name: EVENT, url: newUrl('u08f') }, op(), local), 'closed');
  assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 });
});

test('U09 original operation: abort/dispose/deadline/clock before and during prepare and challenge; late values not adopted', { timeout: 30_000 }, async () => {
  const auth = await who();
  let count = counter();
  const aborted = new AbortController();
  aborted.abort();
  expectRt(await subscribe(auth, input(newUrl('u09'), newSecret()), op({ signal: aborted.signal })), 'aborted');
  expectRt(await subscribe(auth, input(newUrl('u09'), newSecret()), op({ deadlineAt: clockState.value })), 'timed_out');
  expectRt(await unsubscribe(auth, { name: EVENT, url: newUrl('u09') }, op({ deadlineAt: clockState.value - 1 })), 'timed_out');
  // 時計: 例外/NaN → timed_out、小数/負/ISO域外 → unavailable、ttl加算でISO域外 → unavailable（全てI/O前）
  for (const [value, code] of [
    [() => {
      throw new Error('clock');
    }, 'timed_out'],
    [() => Number.NaN, 'timed_out'],
    [() => BASE + 0.5, 'unavailable'],
    [() => -1, 'unavailable'],
  ]) {
    clockState.onNow = value;
    const result = await subscribe(auth, input(newUrl('u09c'), newSecret()), { deadlineAt: Number.MAX_SAFE_INTEGER, signal: new AbortController().signal });
    clockState.onNow = null;
    expectRt(result, code);
  }
  const savedClock = clockState.value;
  clockState.value = 8_640_000_000_000_000 - 1_000;
  expectRt(await subscribe(auth, input(newUrl('u09i'), newSecret(), { ttlMs: 60_000 }), { deadlineAt: Number.MAX_SAFE_INTEGER, signal: new AbortController().signal }), 'unavailable');
  clockState.value = savedClock;
  assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 });

  // prepareの読取り待機中の中止 → aborted、challenge 0
  const controller = new AbortController();
  const hold = gate();
  db.control.holdGetAll = hold;
  count = counter();
  const pending = subscribe(auth, input(newUrl('u09p'), newSecret()), op({ signal: controller.signal }));
  await hold.whenReached;
  controller.abort();
  expectRt(await pending, 'aborted');
  hold.release();
  await sleep(10);
  assert.deepEqual({ sent: count().sent, writes: count().writes, encrypt: count().encrypt }, { sent: 0, writes: 0, encrypt: 0 });

  // prepareの読取り待機中に元期限 → timed_out（待機は元期限で打ち切る）
  const hold2 = gate();
  db.control.holdGetAll = hold2;
  const startedAt = Date.now();
  const timed = subscribe(auth, input(newUrl('u09t'), newSecret()), op({ deadlineAt: clockState.value + 200 }));
  await hold2.whenReached;
  const timedResult = await timed;
  hold2.release();
  expectRt(timedResult, 'timed_out');
  assert.ok(Date.now() - startedAt < 2_000);

  // challengeの待機中の中止・dispose: challenge signalがabortされ、遅いecho（成功）を採用しない・seal 0
  for (const mode of ['abort', 'dispose']) {
    const local = makeRuntime();
    const c2 = new AbortController();
    const challengeGate = gate();
    let lateResolve;
    senderState.behavior = (request, signal) => {
      challengeGate.reached();
      return new Promise((resolve) => {
        lateResolve = () => resolve(echo(request));
        void signal;
      });
    };
    count = counter();
    const running = subscribe(auth, input(newUrl('u09ch'), newSecret()), op({ signal: c2.signal }), local);
    await challengeGate.whenReached;
    if (mode === 'abort') c2.abort();
    else local.dispose();
    const result = await running;
    lateResolve();
    senderState.behavior = null;
    await sleep(10);
    expectRt(result, mode === 'abort' ? 'aborted' : 'closed');
    assert.ok(sent.at(-1).signal.aborted, `${mode}: challenge signal aborted`);
    assert.deepEqual({ sent: count().sent, encrypt: count().encrypt, writes: count().writes }, { sent: 1, encrypt: 0, writes: 0 }, mode);
    local.dispose();
  }
  // 遅いrejectも未処理rejectにならない
  const c3 = new AbortController();
  let lateReject;
  const rejectGate = gate();
  senderState.behavior = () => {
    rejectGate.reached();
    return new Promise((_, reject) => {
      lateReject = () => reject(new Error('late failure'));
    });
  };
  const rejecting = subscribe(auth, input(newUrl('u09r'), newSecret()), op({ signal: c3.signal }));
  await rejectGate.whenReached;
  c3.abort();
  expectRt(await rejecting, 'aborted');
  lateReject();
  senderState.behavior = null;
  await sleep(10);
  assert.equal(unhandled, 0);
});

test('U10 final authorization at activate: Grant removed / owner revoked / cancelled / re-saved Grant / parallel rotation -> no success, no re-challenge', { timeout: 30_000 }, async () => {
  const during = async (auth, url, secret, action) => {
    const challengeGate = gate();
    let release;
    senderState.behavior = (request) => {
      challengeGate.reached();
      return new Promise((resolve) => {
        release = () => resolve(echo(request));
      });
    };
    const count = counter();
    const running = subscribe(auth, input(url, secret));
    await challengeGate.whenReached;
    senderState.behavior = null;
    await action();
    release();
    const result = await running;
    return { result, counts: count() };
  };
  // 要求Grantの削除
  {
    const auth = await who();
    const { result, counts } = await during(auth, newUrl('u10a'), newSecret(), async () => db.docs.delete(connect.grantDocRef(auth.grantId).path));
    assert.equal(result.kind, 'sub:grant_inactive');
    assert.equal(counts.sent, 1);
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // ownerの失効
  {
    const auth = await who();
    const { result } = await during(auth, newUrl('u10b'), newSecret(), async () => db.write(ownerPath(auth.ownerId), { ...dataOf(ownerPath(auth.ownerId)), revokedAt: clockState.value }));
    assert.equal(result.kind, 'sub:grant_inactive');
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // challenge待機中の取消（同ownerの別Grant・別runtime）→ conflict、世代+1、復活0、再challenge 0
  {
    const auth = await who();
    const other = { ownerId: auth.ownerId, grantId: await newGrant(auth.ownerId) };
    const url = newUrl('u10c');
    const peer = makeRuntime();
    const { result, counts } = await during(auth, url, newSecret(), async () => {
      const cancelled = await unsubscribe(other, { name: EVENT, url }, op(), peer);
      assert.equal(cancelled.ok, true, cancelled.kind);
    });
    assert.equal(result.kind, 'sub:conflict');
    assert.equal(counts.sent, 1);
    assert.equal(dataOf(ownerPath(auth.ownerId)).subscriptionGeneration, 1);
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // 要求Grantの同内容の再保存（refreshで再封緘）→ conflict
  {
    const auth = await who();
    const { result } = await during(auth, newUrl('u10d'), newSecret(), async () => {
      await grantsAdapter.upsert(auth.grantId, payloadOf(auth.ownerId, auth.grantId), 3600);
    });
    assert.equal(result.kind, 'sub:conflict');
  }
  // 並行rotation: 同じURLへ別secretで2要求。後発が先に確定すると、先発の古いplanはconflict（自動の再challenge・取り直し0）。
  {
    const auth = await who();
    const url = newUrl('u10e');
    const first = newSecret();
    assert.equal((await subscribe(auth, input(url, first))).ok, true);
    const loser = newSecret();
    const winner = newSecret();
    const { result, counts } = await during(auth, url, loser, async () => {
      const won = await subscribe(auth, input(url, winner));
      assert.equal(won.ok, true, won.kind);
    });
    assert.equal(result.kind, 'sub:conflict');
    assert.equal(counts.sent, 2, 'loser 1 + winner 1');
    const doc = dataOf(subPath(auth.ownerId));
    assert.equal(doc.active.secretHash, hashOf(winner));
    assert.equal(doc.active.previousSecret.secretHash, hashOf(first));
  }
});

test('U11 rotation keeps the same-snapshot current secret for 5 minutes; capsules open only with their own AAD', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u11');
  const oldSecret = newSecret();
  assert.equal((await subscribe(auth, input(url, oldSecret))).ok, true);
  const before = dataOf(subPath(auth.ownerId)).active;
  advance(1_000);
  const newer = newSecret();
  const count = counter();
  const result = await subscribe(auth, input(url, newer));
  assert.equal(result.ok, true, result.kind);
  assert.equal(count().sent, 1);
  const id = idOf(auth.ownerId, url);
  const active = dataOf(subPath(auth.ownerId)).active;
  assert.equal(active.secretHash, hashOf(newer));
  assert.equal(active.sealedUrl !== before.sealedUrl, true, 'URL re-sealed');
  assert.deepEqual(active.previousSecret, { sealed: before.sealedSecret, secretHash: hashOf(oldSecret), until: clockState.value + GRACE });
  assert.equal(await openText(bindingOf('callback-secret', auth.ownerId, id, hashOf(newer)), active.sealedSecret), newer);
  assert.equal(await openText(bindingOf('callback-secret', auth.ownerId, id, hashOf(oldSecret)), active.previousSecret.sealed), oldSecret);
  await assert.rejects(openText(bindingOf('callback-secret', auth.ownerId, id, hashOf(oldSecret)), active.sealedSecret));
  await assert.rejects(openText(bindingOf('callback-url', auth.ownerId, idOf(auth.ownerId, newUrl('x'))), active.sealedUrl));
});

test('U12 unsubscribe: same id formula, request-Grant cancel; other Grant of the same owner may cancel; generation advances; inactive Grant refused', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u12');
  assert.equal((await subscribe(auth, input(url, newSecret()))).ok, true);
  const other = { ownerId: auth.ownerId, grantId: await newGrant(auth.ownerId) };
  const count = counter();
  const result = await unsubscribe(other, { name: EVENT, url });
  assert.equal(result.ok, true, result.kind);
  assert.equal(result.value, undefined);
  const c = count();
  assert.deepEqual({ encrypt: c.encrypt, decrypt: c.decrypt, sent: c.sent, tx: c.tx }, { encrypt: 0, decrypt: 1, sent: 0, tx: 2 });
  assert.equal(dataOf(subPath(auth.ownerId)).active, null);
  assert.equal(dataOf(ownerPath(auth.ownerId)).subscriptionGeneration, 1);
  // 未知identityの取消も世代を進める
  assert.equal((await unsubscribe(auth, { name: EVENT, url: newUrl('u12x') })).ok, true);
  assert.equal(dataOf(ownerPath(auth.ownerId)).subscriptionGeneration, 2);
  // 失効した要求Grant → grant_inactive・無書込み
  db.docs.delete(connect.grantDocRef(other.grantId).path);
  const version = versionOf(ownerPath(auth.ownerId));
  assert.equal((await unsubscribe(other, { name: EVENT, url })).kind, 'sub:grant_inactive');
  assert.equal(versionOf(ownerPath(auth.ownerId)), version);
});

test('U13 internal failures are fixed: hasher, store unavailable (marker), foreign connect; no leak, cause 0', { timeout: 20_000 }, async () => {
  const auth = await who();
  const url = newUrl('u13');
  const secret = newSecret();
  for (const bad of [{ hash: () => 'XYZ' }, { hash: () => 'a'.repeat(63) }, { hash: () => { throw new Error(`hasher ${secret}`); } }, { hash: () => 7 }]) {
    const local = makeRuntime({ hasher: bad });
    const count = counter();
    expectRt(await subscribe(auth, input(url, secret), op(), local), 'unavailable');
    expectRt(await unsubscribe(auth, { name: EVENT, url }, op(), local), 'unavailable');
    assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 });
  }
  // markerの無い別t268 namespace → store unavailable → 内部unavailable（challenge 0）
  const noMarker = makeRuntime({ kms: { ...subscriptionKms(), namespace: `t268_${randomUUID()}` } });
  const count = counter();
  expectRt(await subscribe(auth, input(url, secret), op(), noMarker), 'unavailable');
  assert.equal(count().sent, 0);
  // 別instanceのconnect（同じproject文字列）→ storeがI/O前に拒否 → 内部unavailable
  const foreign = makeRuntime({ connect: connectOf(otherDb) });
  expectRt(await subscribe(auth, input(url, secret), op(), foreign), 'unavailable');
  for (const error of errors) {
    const text = `${error.message}\n${error.stack}`;
    assert.ok(!text.includes(secret) && !text.includes(url) && !text.includes(auth.ownerId) && !text.includes(auth.grantId));
  }
});

test('U14 concurrent requests keep their own owner/Grant/operation (no global mixing, no owner lock)', { timeout: 20_000 }, async () => {
  const a = await who();
  const b = await who();
  const urlA = newUrl('u14a');
  const urlB = newUrl('u14b');
  const gates = new Map();
  senderState.behavior = (request) =>
    new Promise((resolve) => {
      gates.set(request.url, () => resolve(echo(request)));
    });
  const pa = subscribe(a, input(urlA, newSecret()));
  const pb = subscribe(b, input(urlB, newSecret()));
  for (let i = 0; i < 100 && gates.size < 2; i += 1) await sleep(5);
  senderState.behavior = null;
  assert.equal(gates.size, 2, 'both challenges in flight at once');
  gates.get(urlB)();
  gates.get(urlA)();
  const [ra, rb] = await Promise.all([pa, pb]);
  assert.equal(ra.value.id, idOf(a.ownerId, urlA));
  assert.equal(rb.value.id, idOf(b.ownerId, urlB));
  assert.equal(dataOf(subPath(a.ownerId)).active.grantId, a.grantId);
  assert.equal(dataOf(subPath(b.ownerId)).active.grantId, b.grantId);
});

test('U15 abort or dispose at the clock read of the bounded remaining time right after the sender returns: fixed failure, no seal/save, no owned timer/listener left', { timeout: 20_000 }, async () => {
  for (const mode of ['abort', 'dispose']) {
    const auth = await who();
    const local = mode === 'dispose' ? makeRuntime() : rt;
    const controller = new AbortController();
    let fired = 0;
    let lateSettled = false;
    senderState.behavior = (request) => {
      // senderが応答（promise）を返した直後の、次の1回の時計読取り＝boundedの残時間の観測で、親abort（別対照はdispose）を起こす。
      clockState.onNow = () => {
        clockState.onNow = null;
        fired += 1;
        if (mode === 'abort') controller.abort();
        else local.dispose();
        return clockState.value;
      };
      return new Promise((resolve) => {
        setImmediate(() => {
          lateSettled = true;
          resolve(echo(request));
        });
      });
    };
    const count = counter();
    const timersBefore = timeouts();
    const result = await subscribe(auth, input(newUrl('u15'), newSecret()), op({ signal: controller.signal }), local);
    const timersAfter = timeouts();
    senderState.behavior = null;
    clockState.onNow = null;
    expectRt(result, mode === 'abort' ? 'aborted' : 'closed');
    assert.equal(fired, 1, `${mode}: fired at the remaining-time observation`);
    assert.ok(timersAfter - timersBefore <= 0, `${mode}: owned timers left ${timersAfter - timersBefore}`);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0, `${mode}: parent listeners left`);
    assert.ok(sent.at(-1).signal.aborted, `${mode}: challenge signal aborted`);
    assert.equal(getEventListeners(sent.at(-1).signal, 'abort').length, 0, `${mode}: challenge signal listeners left`);
    const c = count();
    assert.deepEqual({ sent: c.sent, encrypt: c.encrypt, writes: c.writes, tx: c.tx }, { sent: 1, encrypt: 0, writes: 0, tx: 2 }, mode);
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
    await sleep(10);
    assert.ok(lateSettled, `${mode}: late sender value settled without adoption`);
  }
});

test('U16 text.submitted: events/list has exactly the 4-field payload schema; subscribe/unsubscribe use the same name; the old name and near names are unknown_event with DB/KMS/challenge 0', { timeout: 20_000 }, async () => {
  assert.equal(EVENT_NAME, EVENT);
  const listed = eventsListResult();
  assert.deepEqual(Object.keys(listed), ['events']);
  assert.equal(listed.events.length, 1, 'the only event');
  const [event] = listed.events;
  assert.deepEqual(Object.keys(event), ['name', 'description', 'inputSchema', 'payloadSchema', 'delivery']);
  assert.equal(event.name, EVENT);
  assert.deepEqual(event.inputSchema, { type: 'object', properties: {}, additionalProperties: false });
  assert.deepEqual(event.delivery, ['webhook']);
  assert.deepEqual(event.payloadSchema, {
    type: 'object',
    properties: {
      schemaVersion: { type: 'integer', const: 2 },
      commandId: { type: 'string', format: 'uuid' },
      text: { type: 'string', minLength: 1, maxLength: 4096 },
      expiresAt: { type: 'string', format: 'date-time' },
    },
    required: ['schemaVersion', 'commandId', 'text', 'expiresAt'],
    additionalProperties: false,
  });
  assert.deepEqual(Object.keys(event.payloadSchema.properties), ['schemaVersion', 'commandId', 'text', 'expiresAt'], 'fixed order');
  assert.equal(/shortcut|paired|direction|taskId|taskLabel|revision/i.test(JSON.stringify(listed)), false, 'no old name / removed metadata');

  const auth = await who();
  const url = newUrl('u16');
  const secret = newSecret();
  const count = counter();
  for (const name of [OLD_EVENT, 'Text.Submitted', 'text.submitted ', 'text.submitted.v1']) {
    assert.equal((await subscribe(auth, { ...input(url, secret), name })).kind, 'sub:unknown_event', name);
    assert.equal((await unsubscribe(auth, { name, url })).kind, 'sub:unknown_event', name);
  }
  assert.deepEqual(count(), { encrypt: 0, decrypt: 0, tx: 0, sent: 0, writes: 0 }, 'unknown names reach no DB/KMS/challenge');
  assert.equal(dataOf(subPath(auth.ownerId)), undefined);

  // 新名: 購読（challenge 1回）→ 同じidで解除。
  const subscribed = await subscribe(auth, input(url, secret));
  assert.equal(subscribed.ok, true, subscribed.kind);
  assert.equal(subscribed.value.id, idOf(auth.ownerId, url));
  assert.equal(dataOf(subPath(auth.ownerId)).active.id, idOf(auth.ownerId, url));
  assert.equal((await unsubscribe(auth, { name: EVENT, url })).ok, true);
  assert.equal(dataOf(subPath(auth.ownerId)).active, null);

  // MCPの層では、runtimeのunknown_eventを既存のNotFound(-32011, data.kind=event)へ写す（compile後のdistの静的な読取り）。
  const entry = readFileSync(new URL('../dist/mcp/request-scoped-entry.js', import.meta.url), 'utf8');
  const mapping = entry.slice(entry.indexOf("case 'unknown_event':"));
  assert.ok(entry.includes("case 'unknown_event':") && /^case 'unknown_event':\s*return new ProtocolError\(ERROR_NOT_FOUND,\s*'Unknown event',\s*\{\s*kind:\s*'event'\s*\}\)/.test(mapping), 'unknown_event -> NotFound kind=event');
  assert.ok(/ERROR_NOT_FOUND = -32011/.test(readFileSync(new URL('../dist/events/contract.js', import.meta.url), 'utf8')));
});

test('U17 explicit access: challenge-before refusal, stop/re-enable during challenge, legacy/old-generation Grants, invalid record; unsubscribe stays available', { timeout: 30_000 }, async () => {
  // 未許可（disabled）・許可record欠落: challenge前に拒否（送信0・seal0・無書込み）。
  for (const stop of [(ownerId) => setAccess(ownerId, 'disabled'), (ownerId) => db.docs.delete(accessPath(accessOf.get(ownerId).identityHash))]) {
    const auth = await who();
    stop(auth.ownerId);
    const count = counter();
    assert.equal((await subscribe(auth, input(newUrl('u17a'), newSecret()))).kind, 'sub:grant_inactive');
    const c = count();
    assert.deepEqual({ sent: c.sent, encrypt: c.encrypt, writes: c.writes }, { sent: 0, encrypt: 0, writes: 0 });
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // 世代を持たない旧Grant（移行前）・別世代のGrant: 拒否。不正なrecord・同意記録: 一時障害（許可へ読み替えない）。
  {
    const auth = { ownerId: newOwner(), grantId: null };
    auth.grantId = await newGrant(auth.ownerId);
    const meta = dataOf(metaPath(auth.grantId));
    const legacy = { ...meta };
    delete legacy.accessGeneration;
    db.write(metaPath(auth.grantId), legacy);
    assert.equal((await subscribe(auth, input(newUrl('u17b'), newSecret()))).kind, 'sub:grant_inactive');
    db.write(metaPath(auth.grantId), { ...meta, accessGeneration: randomUUID() });
    assert.equal((await subscribe(auth, input(newUrl('u17b'), newSecret()))).kind, 'sub:grant_inactive');
    const count = counter();
    db.write(metaPath(auth.grantId), { ...meta, accessGeneration: 'not-a-generation' });
    expectRt(await subscribe(auth, input(newUrl('u17b'), newSecret())), 'unavailable');
    db.write(metaPath(auth.grantId), meta);
    const identityHash = accessOf.get(auth.ownerId).identityHash;
    db.write(accessPath(identityHash), { version: 2, state: 'active', generation: accessOf.get(auth.ownerId).generation, updatedAt: 1 });
    expectRt(await subscribe(auth, input(newUrl('u17b'), newSecret())), 'unavailable');
    const c = count();
    assert.deepEqual({ sent: c.sent, writes: c.writes }, { sent: 0, writes: 0 });
  }
  // challengeの待機中に停止 → activateの最終transactionで拒否（challengeは1回だけ・保存0）。停止→再登録（新世代）でも同じ。
  for (const change of [(ownerId) => setAccess(ownerId, 'disabled'), (ownerId) => (setAccess(ownerId, 'disabled'), setAccess(ownerId, 'active'))]) {
    const auth = await who();
    const challengeGate = gate();
    let release;
    senderState.behavior = (request) => {
      challengeGate.reached();
      return new Promise((resolve) => {
        release = () => resolve(echo(request));
      });
    };
    const count = counter();
    const running = subscribe(auth, input(newUrl('u17c'), newSecret()));
    await challengeGate.whenReached;
    senderState.behavior = null;
    change(auth.ownerId);
    release();
    const result = await running;
    assert.equal(result.kind, 'sub:grant_inactive');
    assert.equal(count().sent, 1);
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // 購読済み → 停止 → 旧Grantでの延長は拒否、解除（unsubscribe）は利用許可を条件にしない。再有効化後も旧Grantは復活せず、
  // 新世代の同意（新Grant）だけが新規の購読に使える。
  {
    const auth = await who();
    const url = newUrl('u17d');
    const secret = newSecret();
    assert.equal((await subscribe(auth, input(url, secret))).ok, true);
    setAccess(auth.ownerId, 'disabled');
    const count = counter();
    assert.equal((await subscribe(auth, input(url, secret))).kind, 'sub:grant_inactive');
    assert.equal(count().sent, 0);
    assert.equal((await unsubscribe(auth, { name: EVENT, url })).ok, true);
    assert.equal(dataOf(subPath(auth.ownerId)).active, null);
    setAccess(auth.ownerId, 'active');
    assert.equal((await subscribe(auth, input(url, secret))).kind, 'sub:grant_inactive', 'the old-generation Grant does not come back');
    const fresh = { ownerId: auth.ownerId, grantId: await newGrant(auth.ownerId) };
    const renewed = await subscribe(fresh, input(url, secret));
    assert.equal(renewed.ok, true, renewed.kind);
  }
  // 許可recordが不正でも、解除は進む（照会・取消・解除を許可DBに依存させない）。
  {
    const auth = await who();
    const url = newUrl('u17e');
    assert.equal((await subscribe(auth, input(url, newSecret()))).ok, true);
    db.write(accessPath(accessOf.get(auth.ownerId).identityHash), { broken: true });
    assert.equal((await unsubscribe(auth, { name: EVENT, url })).ok, true);
  }
});

test('U18 delivery store reads the same access record and Grant consent generation in prepare/dispatch: stop before dispatch -> no send right, new/same-ID POST refused, old generation refused, invalid record is a fixed state error', { timeout: 30_000 }, async () => {
  const { KmsRequestDeliveryStore } = await import('../dist/delivery/kms-store.js');
  const { DeliveryStateError } = await import('../dist/delivery/contract.js');
  const store = new KmsRequestDeliveryStore({ db, namespace: `t270_${randomUUID()}`, connect, hash: (purpose, value) => baseHasher.hash(purpose, value), clock, policy });
  const request = (ownerId, commandId = randomUUID()) => ({
    ownerId,
    commandKey: store.commandKey(ownerId, commandId),
    digest: randomBytes(32).toString('hex'),
    attemptId: randomUUID(),
    receivedAt: Math.floor(clockState.value),
    expiresAt: Math.floor(clockState.value) + 60_000,
  });
  const auth = await who();
  assert.equal((await subscribe(auth, input(newUrl('u18'), newSecret()))).ok, true);

  // 許可あり: 準備できる。停止が先に確定 → dispatchは送出権を与えず未送信の終端（authorization_lost）。
  const first = request(auth.ownerId);
  assert.equal((await store.prepare(first, op())).kind, 'prepared');
  setAccess(auth.ownerId, 'disabled');
  const refused = await store.dispatch(auth.ownerId, first.commandKey, first.attemptId, null, op());
  assert.equal(refused.kind, 'refused');
  assert.deepEqual([refused.doc.state, refused.doc.reason], ['failed', 'authorization_lost']);
  // 停止中: 新しいPOSTも同じIDの再POSTも利用許可の拒否（接続の失効とは別）。
  assert.deepEqual(await store.prepare(request(auth.ownerId), op()), { kind: 'denied', denial: 'access_denied' });
  assert.deepEqual(await store.prepare({ ...first, attemptId: randomUUID() }, op()), { kind: 'denied', denial: 'access_denied' });
  // 再有効化（新世代）: 旧世代のGrantに束縛した購読では送れない（自動復活なし）。
  setAccess(auth.ownerId, 'active');
  assert.deepEqual(await store.prepare(request(auth.ownerId), op()), { kind: 'denied', denial: 'access_denied' });
  // 不正な許可record: 許可・拒否のどちらへも読み替えない固定の状態error（APIでは503）。
  db.write(accessPath(accessOf.get(auth.ownerId).identityHash), { version: 1, state: 'paused', generation: randomUUID(), updatedAt: 1 });
  await assert.rejects(store.prepare(request(auth.ownerId), op()), (error) => error instanceof DeliveryStateError);

  // dispatchが先に確定: 送出権はそのまま有効（後の停止で取り消さない）。
  const other = await who();
  assert.equal((await subscribe(other, input(newUrl('u18b'), newSecret()))).ok, true);
  const second = request(other.ownerId);
  assert.equal((await store.prepare(second, op())).kind, 'prepared');
  const granted = await store.dispatch(other.ownerId, second.commandKey, second.attemptId, null, op());
  assert.equal(granted.kind, 'granted');
  setAccess(other.ownerId, 'disabled');
  assert.equal((await store.read(other.ownerId, second.commandKey, op()))?.state, 'dispatching');
});

test('U20 receiver reset generation: a Grant of the previous receiver generation cannot create receiver settings (no timestamp involved); the current generation can; malformed values are temporary failures', { timeout: 30_000 }, async () => {
  const auth = await who();
  const meta = dataOf(metaPath(auth.grantId));
  const owner = dataOf(ownerPath(auth.ownerId));
  // 不正な受信reset世代（ownerとGrantの両方）: challenge前に一時障害、書込み0。
  {
    const count = counter();
    db.write(ownerPath(auth.ownerId), { ...owner, receiverGeneration: -1 });
    expectRt(await subscribe(auth, input(newUrl('u20x'), newSecret())), 'unavailable');
    db.write(ownerPath(auth.ownerId), owner);
    db.write(metaPath(auth.grantId), { ...meta, receiverGeneration: 0 });
    expectRt(await subscribe(auth, input(newUrl('u20x'), newSecret())), 'unavailable');
    const c = count();
    assert.deepEqual({ sent: c.sent, writes: c.writes }, { sent: 0, writes: 0 });
  }
  // ownerがresetされた（受信reset世代1）。同じ時刻のままでも、世代0のGrantは受信先設定を作れない。
  db.write(ownerPath(auth.ownerId), { ...owner, receiverGeneration: 1 });
  db.write(metaPath(auth.grantId), meta);
  {
    const count = counter();
    assert.equal((await subscribe(auth, input(newUrl('u20a'), newSecret()))).kind, 'sub:grant_inactive');
    const c = count();
    assert.deepEqual({ sent: c.sent, writes: c.writes }, { sent: 0, writes: 0 });
    assert.equal(dataOf(subPath(auth.ownerId)), undefined);
  }
  // 現在の世代のGrant（resetの後の同意）は、通常のchallengeを経て受信先設定を作れる。
  db.write(metaPath(auth.grantId), { ...meta, receiverGeneration: 1 });
  const ok = await subscribe(auth, input(newUrl('u20b'), newSecret()));
  assert.equal(typeof ok.value?.id, 'string');
  assert.equal(dataOf(subPath(auth.ownerId)).active.id, ok.value.id);
});