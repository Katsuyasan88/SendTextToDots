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
    const read = await store.readApprovalIn(tx, subject, now);
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
  const deleted = await runSourceAdmin({ command: 'delete', project: 'p', database: 'd', namespace: NS, source: id, expect: enabled.version }, null, deps);
  assert.equal(deleted.state, 'deleted');
  assert.deepEqual(await store.bindingUsable(binding), { kind: 'rejected', reason: 'deleted' });
  assert.equal((await runSourceAdmin({ command: 'enable', project: 'p', database: 'd', namespace: NS, source: id, expect: deleted.version }, null, deps)).code, 'deleted');
  assert.equal(await store.create({ ...first, sourceId: id }), 'conflict');
  const saved = JSON.stringify(db.docs.get(`sttdConnect/${NS}/sources/${id}`));
  assert.ok(!saved.includes('uid-synthetic'));
});
