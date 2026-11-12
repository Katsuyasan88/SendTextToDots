// 許可元の保存（source/firestore.ts）。合成のin-memory Firestore（transactionは直列化）だけ。実SDK・Cloud・資格・network 0。
//   - 要求の認可: source状態・証明・replayを1 transactionで。同じnonceの同時要求は1つだけ成功し、replay記録はhash IDと期限だけ。
//   - 接続承認: 元interaction以内かつ最大5分、単回消費、別本人/client/resource・消費済み・期限切れ・source停止/世代違いを拒否。
//   - 管理: 新IDで作成、停止→有効化は新世代（旧bindingは復活しない）、削除は墓標（ID再利用・付替え0）。不正record・DB障害は一時障害。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { createHmacHasher } from '../dist/secrets.js';
import { SourceStore, SourceUnavailableError } from '../dist/source/firestore.js';
import { sourceApprovalId, sourceReplayId } from '../dist/source/proof.js';
import { newSourceGeneration, newSourceId, runSourceAdmin } from '../dist/source/admin.js';

export function fakeDb() {
  const docs = new Map();
  const state = { down: false, tx: 0 };
  let lock = Promise.resolve();
  const snap = (path) => {
    const data = docs.get(path);
    return { id: path.split('/').pop(), exists: data !== undefined, data: () => (data === undefined ? undefined : structuredClone(data)) };
  };
  const ref = (path) => ({
    id: path.split('/').pop(),
    path,
    collection: (name) => ({ doc: (id) => ref(`${path}/${name}/${id}`) }),
    get: async () => {
      if (state.down) throw new Error('down');
      return snap(path);
    },
  });
  const db = {
    docs,
    state,
    collection: (name) => ({ doc: (id) => ref(`${name}/${id}`) }),
    runTransaction(fn) {
      const run = lock.then(async () => {
        if (state.down) throw new Error('down');
        state.tx += 1;
        const writes = [];
        const tx = {
          get: async (r) => snap(r.path),
          create: (r, data) => (writes.push(() => {
            if (docs.has(r.path)) throw new Error('exists');
            docs.set(r.path, structuredClone(data));
          }), tx),
          set: (r, data) => (writes.push(() => docs.set(r.path, structuredClone(data))), tx),
          update: (r, data) => (writes.push(() => docs.set(r.path, { ...docs.get(r.path), ...structuredClone(data) })), tx),
          delete: (r) => (writes.push(() => docs.delete(r.path)), tx),
        };
        const result = await fn(tx);
        for (const write of writes) write();
        return result;
      });
      lock = run.catch(() => {});
      return run;
    },
  };
  return db;
}

const NS = `t256_${randomUUID()}`;
const hasher = createHmacHasher(randomBytes(32));
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function setup(now = { value: 1_000_000 }) {
  const db = fakeDb();
  const store = new SourceStore({ db, namespace: NS, clock: { now: () => now.value } });
  return { db, store, now };
}

function developerRecord(overrides = {}) {
  return {
    schemaVersion: 1,
    sourceId: newSourceId(),
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['send', 'connect'],
    publicKey: 'A'.repeat(43),
    identityHash: HASH_A,
    expiresAt: null,
    createdAt: 1,
    updatedAt: 1,
    ...overrides,
  };
}

test('要求の認可: 同じnonceの同時要求は1つだけ成功し、replay記録はhash IDと期限だけ', async () => {
  const { db, store } = setup();
  const record = developerRecord();
  assert.equal(await store.create(record), 'created');
  const replay = { id: sourceReplayId(hasher, NS, record.sourceId, 'n'.repeat(22)), until: 1_090_000 };
  const check = { sourceId: record.sourceId, method: 'developer-key-v1', operation: 'send', identityHash: HASH_A, proofMatches: () => true, replay };
  const results = await Promise.all([store.authorizeRequest(check), store.authorizeRequest(check), store.authorizeRequest(check)]);
  assert.equal(results.filter((r) => r.kind === 'allowed').length, 1);
  assert.equal(results.filter((r) => r.kind === 'rejected' && r.reason === 'replay').length, 2);
  const stored = [...db.docs.entries()].filter(([path]) => path.includes('/sourceReplay/'));
  assert.equal(stored.length, 1);
  assert.deepEqual(Object.keys(stored[0][1]).sort(), ['deleteAfter', 'expiresAt']);
  assert.equal(stored[0][1].deleteAfter.getTime(), 1_090_000 + 24 * 3600_000);
  assert.ok(!stored[0][0].includes('nnnn'));
});

test('要求の認可: 証明不一致・別本人・停止・不存在は拒否し、replay記録を作らない', async () => {
  const { db, store } = setup();
  const record = developerRecord();
  await store.create(record);
  const base = { sourceId: record.sourceId, method: 'developer-key-v1', operation: 'send', identityHash: HASH_A, proofMatches: () => true };
  const replay = (n) => ({ id: sourceReplayId(hasher, NS, record.sourceId, n.repeat(22)), until: 2_000_000 });
  assert.deepEqual(await store.authorizeRequest({ ...base, proofMatches: () => false, replay: replay('a') }), { kind: 'rejected', reason: 'proof' });
  assert.deepEqual(await store.authorizeRequest({ ...base, identityHash: HASH_B, replay: replay('b') }), { kind: 'rejected', reason: 'subject' });
  assert.deepEqual(await store.authorizeRequest({ ...base, sourceId: newSourceId(), replay: replay('c') }), { kind: 'rejected', reason: 'missing' });
  assert.equal([...db.docs.keys()].filter((path) => path.includes('/sourceReplay/')).length, 0);
});

test('不正record・DB障害は一時障害（成功にしない）', async () => {
  const { db, store } = setup();
  const record = developerRecord();
  db.docs.set(`sttdConnect/${NS}/sources/${record.sourceId}`, { ...record, operations: ['everything'] });
  const check = { sourceId: record.sourceId, method: 'developer-key-v1', operation: 'send', identityHash: HASH_A, proofMatches: () => true };
  await assert.rejects(store.authorizeRequest(check), SourceUnavailableError);
  db.state.down = true;
  await assert.rejects(store.authorizeRequest(check), SourceUnavailableError);
  await assert.rejects(store.bindingUsable({ sourceId: record.sourceId, generation: record.generation }), SourceUnavailableError);
});

async function consume(db, store, subject, now) {
  return db.runTransaction(async (tx) => {
    const judge = await store.readApprovalIn(tx, subject);
    const read = judge(now);
    if (read.kind === 'usable') read.apply();
    return read;
  });
}

test('接続承認: 元interaction以内かつ最大5分・単回消費・別本人/client/resourceを拒否', async () => {
  const { db, store, now } = setup();
  const record = developerRecord();
  await store.create(record);
  const binding = { sourceId: record.sourceId, generation: record.generation };
  const subject = { approvalId: sourceApprovalId(hasher, NS, 'interaction-1'), identityHash: HASH_A, clientHash: 'c'.repeat(64), resourceHash: 'd'.repeat(64) };
  assert.deepEqual(await store.recordApproval(subject, binding, now.value + 3_600_000), { kind: 'recorded', expiresAt: now.value + 300_000 });
  assert.deepEqual(await store.recordApproval(subject, binding, now.value + 3_600_000), { kind: 'rejected', reason: 'conflict' });
  const short = { ...subject, approvalId: sourceApprovalId(hasher, NS, 'interaction-2') };
  assert.deepEqual(await store.recordApproval(short, binding, now.value + 60_000), { kind: 'recorded', expiresAt: now.value + 60_000 });
  assert.deepEqual(await store.recordApproval({ ...subject, approvalId: sourceApprovalId(hasher, NS, 'interaction-3') }, binding, now.value), { kind: 'rejected', reason: 'expired' });

  assert.equal((await consume(db, store, { ...subject, identityHash: HASH_B }, now.value)).reason, 'mismatch');
  assert.equal((await consume(db, store, { ...subject, clientHash: 'e'.repeat(64) }, now.value)).reason, 'mismatch');
  const first = await consume(db, store, subject, now.value);
  assert.equal(first.kind, 'usable');
  assert.deepEqual(first.binding, binding);
  assert.equal((await consume(db, store, subject, now.value)).reason, 'consumed');
  assert.equal((await consume(db, store, short, now.value + 60_000)).reason, 'expired');
  const approval = db.docs.get(`sttdConnect/${NS}/sourceApprovals/${subject.approvalId}`);
  assert.ok(!JSON.stringify(approval).includes('interaction-1'));
});

test('管理: 停止→有効化は新世代で旧bindingを拒否、削除は墓標でIDを再利用しない', async () => {
  const { db, store, now } = setup();
  const deps = { store, namespace: NS, projectId: 'sendtexttodots-test', projectNumber: '123456789012', now: () => now.value, hasher };
  const created = await runSourceAdmin({ command: 'register-developer', project: 'p', database: 'd', namespace: NS }, { operations: ['send', 'connect'], uid: 'uid-synthetic', publicKey: 'A'.repeat(43), expiresAt: null }, deps);
  assert.equal(created.code, 'created');
  const id = created.source;
  const first = (await store.status(id)).record;
  const binding = { sourceId: id, generation: first.generation };
  assert.equal((await store.bindingUsable(binding)).kind, 'usable');
  const subject = { approvalId: sourceApprovalId(hasher, NS, 'interaction-x'), identityHash: first.identityHash, clientHash: 'c'.repeat(64), resourceHash: 'd'.repeat(64) };
  await store.recordApproval(subject, binding, now.value + 300_000);

  const status = await runSourceAdmin({ command: 'status', project: 'p', database: 'd', namespace: NS, source: id }, null, deps);
  now.value += 10;
  const disabled = await runSourceAdmin({ command: 'disable', project: 'p', database: 'd', namespace: NS, source: id, expect: status.version }, null, deps);
  assert.equal(disabled.state, 'disabled');
  assert.deepEqual(await store.bindingUsable(binding), { kind: 'rejected', reason: 'disabled' });
  assert.equal((await consume(db, store, subject, now.value)).reason, 'disabled');
  assert.equal((await runSourceAdmin({ command: 'enable', project: 'p', database: 'd', namespace: NS, source: id, expect: status.version }, null, deps)).code, 'conflict');
  now.value += 10;
  const enabled = await runSourceAdmin({ command: 'enable', project: 'p', database: 'd', namespace: NS, source: id, expect: disabled.version }, null, deps);
  assert.equal(enabled.state, 'active');
  assert.deepEqual(await store.bindingUsable(binding), { kind: 'rejected', reason: 'generation' });
  assert.equal((await consume(db, store, subject, now.value)).reason, 'generation');

  now.value += 10;
  // 削除は物理削除: App ID・公開鍵・identityHash・日時を残さず、旧bindingは不在として拒否。復活・付替えの操作は無い。
  const deleted = await runSourceAdmin({ command: 'delete', project: 'p', database: 'd', namespace: NS, source: id, expect: enabled.version }, null, deps);
  assert.equal(deleted.code, 'deleted');
  assert.equal(db.docs.has(`sttdConnect/${NS}/sources/${id}`), false);
  assert.deepEqual(await store.grantUsable('f'.repeat(64)), { kind: 'rejected', reason: 'unbound' });
  assert.equal((await runSourceAdmin({ command: 'enable', project: 'p', database: 'd', namespace: NS, source: id, expect: enabled.version }, null, deps)).code, 'missing');
  assert.equal((await consume(db, store, subject, now.value)).reason, 'missing');
  assert.ok(![...db.docs.values()].some((doc) => JSON.stringify(doc).includes(first.identityHash) && !('consumed' in doc)));
});

// ---- 通常MCPへのプレイグラウンド統合: 利用許可の送信元範囲（Webだけ）とWeb登録の限定操作 ----

const ACCESS_GEN = () => randomUUID();
function appRecord(overrides = {}) {
  return {
    schemaVersion: 1, sourceId: newSourceId(), kind: 'app', state: 'active', generation: newSourceGeneration(),
    operations: ['send', 'keys', 'connect'], appId: '1:123456789012:ios:abcdef', createdAt: 1, updatedAt: 1, ...overrides,
  };
}
const putAccess = (db, hash, extra = {}) => db.docs.set(`sttdConnect/${NS}/access/${hash}`, { version: 1, state: 'active', generation: ACCESS_GEN(), updatedAt: 1, ...extra });

test('送信元範囲: WebだけのUIDは正しいApp Check sourceでも送信・鍵・接続承認・同意を拒否し、既存の通常許可は従来どおり', async () => {
  const { db, store, now } = setup();
  const app = appRecord();
  await store.create(app);
  const base = { sourceId: app.sourceId, method: 'app-check-v1', identityHash: HASH_A, proofMatches: (r) => r.kind === 'app' };
  putAccess(db, HASH_A, { sourceScope: 'web' });
  putAccess(db, HASH_B); // 既存の通常許可（範囲なし）
  for (const operation of ['send', 'keys', 'connect']) {
    assert.deepEqual(await store.authorizeRequest({ ...base, operation }), { kind: 'rejected', reason: 'scope' });
    assert.equal((await store.authorizeRequest({ ...base, operation, identityHash: HASH_B })).kind, 'allowed');
  }
  const binding = { sourceId: app.sourceId, generation: app.generation };
  const subjectA = { approvalId: sourceApprovalId(hasher, NS, 'web-only-1'), identityHash: HASH_A, clientHash: 'c'.repeat(64), resourceHash: 'd'.repeat(64) };
  assert.deepEqual(await store.recordApproval(subjectA, binding, now.value + 60_000), { kind: 'rejected', reason: 'scope' });
  // 承認記録の後にWebだけへ変わった（または流用された）場合も同意の最終txで拒否する
  const subjectB = { ...subjectA, approvalId: sourceApprovalId(hasher, NS, 'web-only-2'), identityHash: HASH_B };
  assert.equal((await store.recordApproval(subjectB, binding, now.value + 60_000)).kind, 'recorded');
  putAccess(db, HASH_B, { sourceScope: 'web' });
  assert.equal((await consume(db, store, subjectB, now.value)).reason, 'scope');
  // Webだけでもdeveloper sourceは使える
  const dev = developerRecord();
  await store.create(dev);
  assert.equal((await store.authorizeRequest({ sourceId: dev.sourceId, method: 'developer-key-v1', operation: 'send', identityHash: HASH_A, proofMatches: () => true })).kind, 'allowed');
  // 未知の範囲値・壊れた許可recordは一時障害（許可へ読み替えない）
  putAccess(db, HASH_A, { sourceScope: 'all' });
  await assert.rejects(store.authorizeRequest({ ...base, operation: 'send' }), SourceUnavailableError);
});

async function register(db, store, input, at) {
  return db.runTransaction(async (tx) => {
    const judge = await store.webRegistrationIn(tx, input);
    const read = judge(at);
    if (read.kind === 'registered') read.apply();
    return read;
  });
}

test('Web登録: 未登録はWebだけの許可とconnect/sendのsourceを作り、既存の通常許可は世代・範囲を変えず、停止・コードUID・世代違いは復活/再作成しない', async () => {
  const { db, store, now } = setup();
  const key = 'B'.repeat(43);
  const fresh = () => ({ sourceId: newSourceId(), generation: newSourceGeneration() });
  const input = (o = {}) => ({ identityHash: HASH_A, publicKey: key, expiresAt: null, existing: null, fresh: fresh(), newAccessGeneration: randomUUID(), codeIdentity: false, ...o });
  const first = await register(db, store, input(), now.value);
  assert.equal(first.kind, 'registered');
  const access = db.docs.get(`sttdConnect/${NS}/access/${HASH_A}`);
  assert.equal(access.sourceScope, 'web');
  const src = db.docs.get(`sttdConnect/${NS}/sources/${first.binding.sourceId}`);
  assert.deepEqual([...src.operations].sort(), ['connect', 'send']);
  assert.equal(src.kind, 'developer');
  // 再実行（保存済みbinding）は同じsourceを返し書込み0
  const before = db.docs.size;
  const again = await register(db, store, input({ existing: first.binding }), now.value);
  assert.deepEqual([again.kind, again.created, again.binding], ['registered', false, first.binding]);
  assert.equal(db.docs.size, before);
  // 既存の通常許可（DPADAA）にWebを追加: 許可の世代・範囲は不変
  putAccess(db, HASH_B, { generation: '11111111-1111-4111-8111-111111111111' });
  const added = await register(db, store, input({ identityHash: HASH_B }), now.value);
  assert.equal(added.kind, 'registered');
  assert.deepEqual(db.docs.get(`sttdConnect/${NS}/access/${HASH_B}`), { version: 1, state: 'active', generation: '11111111-1111-4111-8111-111111111111', updatedAt: 1 });
  // 停止中は登録で復活させない
  const HASH_C = 'c'.repeat(64);
  putAccess(db, HASH_C, { state: 'disabled' });
  assert.deepEqual(await register(db, store, input({ identityHash: HASH_C }), now.value), { kind: 'rejected', reason: 'denied' });
  // コードUIDの許可はコードの有効化だけが作る／コード期限後は拒否
  const HASH_D = 'd'.repeat(64);
  assert.deepEqual(await register(db, store, input({ identityHash: HASH_D, codeIdentity: true }), now.value), { kind: 'rejected', reason: 'denied' });
  putAccess(db, HASH_D, { sourceScope: 'web', codeLoginExpiresAt: now.value + 600_000 });
  assert.equal((await register(db, store, input({ identityHash: HASH_D, codeIdentity: true }), now.value)).kind, 'registered');
  assert.deepEqual(await register(db, store, input({ identityHash: HASH_D, codeIdentity: true }), now.value + 600_000), { kind: 'rejected', reason: 'denied' });
  // 保存済みbindingのsourceが停止・世代違い・鍵違いなら再作成しない
  db.docs.set(`sttdConnect/${NS}/sources/${first.binding.sourceId}`, { ...src, state: 'disabled' });
  assert.deepEqual(await register(db, store, input({ existing: first.binding }), now.value), { kind: 'rejected', reason: 'source_unusable' });
  db.docs.set(`sttdConnect/${NS}/sources/${first.binding.sourceId}`, src);
  assert.deepEqual(await register(db, store, input({ existing: { ...first.binding, generation: newSourceGeneration() } }), now.value), { kind: 'rejected', reason: 'source_unusable' });
  assert.deepEqual(await register(db, store, input({ existing: first.binding, publicKey: 'C'.repeat(43) }), now.value), { kind: 'rejected', reason: 'source_unusable' });
  // 既存IDへの新規作成・壊れた許可recordは拒否/一時障害
  assert.deepEqual(await register(db, store, input({ fresh: first.binding }), now.value), { kind: 'rejected', reason: 'source_unusable' });
  db.docs.set(`sttdConnect/${NS}/access/${HASH_A}`, { version: 1, state: 'active' });
  await assert.rejects(register(db, store, input(), now.value), SourceUnavailableError);
});

// ---- T-240 R1: プレイグラウンドの署名付き限定endpointと送出確定の範囲照合 ----
import { generateKeyPairSync as pgKeys } from 'node:crypto';
import { connectIdentityHash as pgIdentityHash } from '../dist/connect/firestore.js';
import { createPlaygroundEndpoint, createSourceGate } from '../dist/source/http.js';
import { signSourceRequest } from '../dist/source/proof.js';

function playgroundSetup(o = {}) {
  const { db, store, now } = setup();
  const { privateKey, publicKey } = pgKeys('ed25519');
  const registrar = { sourceId: newSourceId(), publicKey: publicKey.export({ format: 'jwk' }).x };
  const audience = 'https://mcp.example.test';
  const issued = [];
  const ids = [];
  const endpoint = createPlaygroundEndpoint({
    store, hasher, namespace: NS, audience, clock: { now: () => now.value }, registrar,
    verifyIdentity: async (t) => { if (!t.startsWith('id-')) throw new Error('bad'); return { projectId: 'p', uid: t.slice(3), authTimeSec: 1, ...(t.startsWith('id-sttdc') ? { method: 'developer_code' } : {}) }; },
    code: { issue: async (input) => (issued.push(input), { code: '123456', operationId: 'o'.repeat(43), issuedAt: now.value, authExpiresAt: now.value + 600_000 }), token: async () => ({ kind: 'pending' }) },
    newIds: () => { const v = { fresh: { sourceId: newSourceId(), generation: newSourceGeneration() }, accessGeneration: randomUUID() }; ids.push(v); return v; },
    ...o,
  });
  let n = 0;
  const call = (path, { body = '{}', bearer, key = privateKey, sourceId = registrar.sourceId, headers = {}, nonce } = {}) => {
    const raw = Buffer.from(body);
    const iat = Math.floor(now.value / 1000);
    const claims = { issuedAt: iat, expiresAt: iat + 60, nonce: nonce ?? `nonce${String(n++).padStart(17, '0')}` };
    const sig = signSourceRequest({ audience, method: 'POST', path, search: '', sourceId, body: raw, bearer: bearer ?? '', idempotencyKey: undefined }, claims, key);
    return { method: 'POST', path, search: '', body: raw, headers: { 'x-sttd-source': sourceId, 'x-sttd-source-signature': sig, ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }), ...headers } };
  };
  return { db, store, now, endpoint, registrar, call, issued, privateKey, audience };
}

test('T240-R1 限定endpoint: 固定BFF署名・本人・connect/sendだけ登録し、再実行は同じsource、再利用/App Check/未知ID/別鍵/過大/改変Bearer/未認証は拒否', async () => {
  const { db, endpoint, call, registrar } = playgroundSetup();
  const ok = await endpoint.handle(call('/v1/playground/register', { bearer: 'id-AppleUid1' }));
  assert.equal(ok.status, 200);
  assert.deepEqual(Object.keys(ok.body).sort(), ['generation', 'sourceId']);
  const identityHash = pgIdentityHash(hasher, NS, { projectId: 'p', uid: 'AppleUid1', authTimeSec: 1 });
  assert.equal(db.docs.get(`sttdConnect/${NS}/access/${identityHash}`).sourceScope, 'web');
  const src = db.docs.get(`sttdConnect/${NS}/sources/${ok.body.sourceId}`);
  assert.deepEqual([src.kind, src.publicKey, src.identityHash, [...src.operations].sort()], ['developer', registrar.publicKey, identityHash, ['connect', 'send']]);
  assert.deepEqual(db.docs.get(`sttdConnect/${NS}/playgroundBindings/${identityHash}`), { version: 1, sourceId: ok.body.sourceId, generation: ok.body.generation });
  // 再実行は同じsource・世代
  assert.deepEqual((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-AppleUid1' }))).body, ok.body);
  // 同じ署名の再利用
  const once = call('/v1/playground/register', { bearer: 'id-AppleUid2' });
  assert.equal((await endpoint.handle(once)).status, 200);
  assert.equal((await endpoint.handle(once)).status, 403);
  // App Checkでの代用・未知ID・別鍵・改変Bearer・過大・未認証・余分query・GET
  assert.equal((await endpoint.handle({ ...call('/v1/playground/register', { bearer: 'id-x' }), headers: { 'x-sttd-source': registrar.sourceId, 'x-firebase-appcheck': 'tok', authorization: 'Bearer id-x' } })).status, 403);
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-x', sourceId: newSourceId() }))).status, 403);
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-x', key: pgKeys('ed25519').privateKey }))).status, 403);
  const tampered = call('/v1/playground/register', { bearer: 'id-x' });
  assert.equal((await endpoint.handle({ ...tampered, headers: { ...tampered.headers, authorization: 'Bearer id-y' } })).status, 403);
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-x', body: `{"a":"${'x'.repeat(1100)}"}` }))).status, 413);
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'bad' }))).status, 401);
  assert.equal((await endpoint.handle(call('/v1/playground/register'))).status, 401);
  assert.equal((await endpoint.handle({ ...call('/v1/playground/register', { bearer: 'id-x' }), search: '?op=keys' })).status, 400);
  assert.equal((await endpoint.handle({ ...call('/v1/playground/register', { bearer: 'id-x' }), method: 'GET' })).status, 405);
  assert.equal((await endpoint.handle(call('/v1/playground/admin', { bearer: 'id-x' }))).status, 404);
  // コードUIDの許可はコード有効化だけ／停止中は復活させない／既存通常許可の世代は不変
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-sttdc_' + 'a'.repeat(32) }))).status, 403);
  const stopped = pgIdentityHash(hasher, NS, { projectId: 'p', uid: 'Stopped', authTimeSec: 1 });
  putAccess(db, stopped, { state: 'disabled' });
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-Stopped' }))).status, 403);
  const normal = pgIdentityHash(hasher, NS, { projectId: 'p', uid: 'Dpadaa', authTimeSec: 1 });
  putAccess(db, normal, { generation: '22222222-2222-4222-8222-222222222222' });
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-Dpadaa' }))).status, 200);
  assert.deepEqual(db.docs.get(`sttdConnect/${NS}/access/${normal}`), { version: 1, state: 'active', generation: '22222222-2222-4222-8222-222222222222', updatedAt: 1 });
  // 停止済みsourceは再作成しない
  const b = db.docs.get(`sttdConnect/${NS}/playgroundBindings/${identityHash}`);
  db.docs.set(`sttdConnect/${NS}/sources/${b.sourceId}`, { ...src, state: 'disabled' });
  assert.equal((await endpoint.handle(call('/v1/playground/register', { bearer: 'id-AppleUid1' }))).status, 409);
});

test('T240-R1 限定endpoint: コード発行は範囲をサーバーが"web"に固定し、claim/issueの本文はexact、未設定のcodeは404', async () => {
  const { endpoint, call, issued } = playgroundSetup();
  const secret = 's'.repeat(43);
  const r = await endpoint.handle(call('/v1/playground/code/issue', { body: JSON.stringify({ claimSecret: secret }) }));
  assert.equal(r.status, 200);
  assert.equal(issued[0].sourceScope, 'web');
  assert.equal((await endpoint.handle(call('/v1/playground/code/issue', { body: JSON.stringify({ claimSecret: secret, sourceScope: 'all' }) }))).status, 400);
  assert.equal((await endpoint.handle(call('/v1/playground/code/claim', { body: JSON.stringify({ claimSecret: secret, operationId: 'o'.repeat(43) }) }))).body.kind, 'pending');
  assert.equal((await endpoint.handle(call('/v1/playground/code/issue', { body: JSON.stringify({ claimSecret: secret }), bearer: 'id-x' }))).status, 400);
  const off = playgroundSetup({ code: null });
  assert.equal((await off.endpoint.handle(off.call('/v1/playground/code/issue', { body: JSON.stringify({ claimSecret: secret }) }))).status, 404);
});

test('T240-R1 送出確定: 同じtxで本人の現在の範囲を読み、Webだけへ変わった本人のApp Check送信は送出0、既存の範囲なし許可とWeb sourceは送出', async () => {
  const { db, store } = setup();
  const gate = createSourceGate({ policy: { mode: 'strict-v1', methods: ['developer-key-v1', 'app-check-v1'] }, store, hasher, namespace: NS, audience: 'https://api.example.test', clock: { now: () => 1_000_000 }, appCheck: { consume: async () => ({ kind: 'rejected', reason: 'x' }) } });
  const app = appRecord();
  await store.create(app);
  const dev = developerRecord();
  await store.create(dev);
  const who = { projectId: 'p', uid: 'U1', authTimeSec: 1 };
  const h = pgIdentityHash(hasher, NS, who);
  putAccess(db, h);
  const run = (b, identity) => db.runTransaction((tx) => gate.dispatchCheck({ sourceId: b.sourceId, generation: b.generation }, 'send', identity)(tx));
  assert.equal(await run(app, who), true);
  assert.equal(await run(dev, who), true);
  putAccess(db, h, { sourceScope: 'web' });
  assert.equal(await run(app, who), false);
  assert.equal(await run(dev, who), true);
  // 旧呼出し（本人なし）は従来の判定のまま
  assert.equal(await run(app, undefined), true);
});
