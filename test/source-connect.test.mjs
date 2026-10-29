// 許可元strictの接続（実ConnectStorage＋実SourceStore＋実SourceGateの接合）。合成のin-memory Firestore・HMAC・封緘portだけ。
//   - 同じ本人の承認 → 同意（putGrantMeta）の最終txで単回消費とGrant binding。承認なし・別本人・期限切れ（DB待機中を含む）・消費済みは作らない。
//   - code交換/refresh（grantUsable）・MCP入口（grantSourceUsable）: bound Grantだけ可。停止・再有効化（新世代）・削除・旧（unbound）Grantは不可。
//   - 送出確定のtx（gate.dispatchCheck）: 入口で認可した後にsourceを停止すると不可（送出0）。二配置の承認・bindingは混用できない。
// 実SDK・Cloud・資格・network・Dots・配送 0。

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { ConnectStorage, connectIdentityHash } from '../dist/connect/firestore.js';
import { createHmacHasher } from '../dist/secrets.js';
import { newSourceGeneration, newSourceId, runSourceAdmin } from '../dist/source/admin.js';
import { SourceStore } from '../dist/source/firestore.js';
import { createSourceGate } from '../dist/source/http.js';
import { sourceApprovalId } from '../dist/source/proof.js';

const DAY = 86_400_000;
const BASE = 1_900_000_000_000;
const PROJECT = 'sendtexttodots-test';

function fakeDb(clock) {
  const docs = new Map();
  const hooks = { onGet: () => {} };
  const snapshot = (path) => {
    hooks.onGet(path);
    const entry = docs.get(path);
    return { ref: refOf(path), id: path.split('/').pop(), exists: entry !== undefined, data: () => (entry === undefined ? undefined : structuredClone(entry)) };
  };
  const collectionOf = (path) => ({ doc: (id) => refOf(`${path}/${id}`) });
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      get: async () => snapshot(path),
      set: async (data) => void docs.set(path, structuredClone(data)),
      update: async (partial) => void docs.set(path, { ...docs.get(path), ...partial }),
      delete: async () => void docs.delete(path),
    };
  }
  let lock = Promise.resolve();
  const db = {
    docs,
    hooks,
    collection: (name) => collectionOf(name),
    runTransaction(fn) {
      const run = lock.then(async () => {
        const pending = [];
        const tx = {
          get: async (ref) => snapshot(ref.path),
          getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
          set: (ref, data) => (pending.push(() => docs.set(ref.path, structuredClone(data))), tx),
          create: (ref, data) =>
            (pending.push(() => {
              if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
              docs.set(ref.path, structuredClone(data));
            }),
            tx),
          update: (ref, partial) =>
            (pending.push(() => {
              if (!docs.has(ref.path)) throw new Error('NOT_FOUND');
              docs.set(ref.path, { ...docs.get(ref.path), ...structuredClone(partial) });
            }),
            tx),
          delete: (ref) => (pending.push(() => docs.delete(ref.path)), tx),
        };
        const result = await fn(tx);
        for (const apply of pending) apply();
        return result;
      });
      lock = run.catch(() => {});
      return run;
    },
  };
  return db;
}

function deployment(db = undefined) {
  const NS = `t256_${randomUUID()}`;
  const now = { value: BASE };
  const clock = { now: () => now.value };
  const store = db ?? fakeDb(clock);
  const hasher = createHmacHasher(randomBytes(32));
  const box = { seal: (purpose, plaintext) => `sealed:${Buffer.from(plaintext).toString('base64url')}`, open: (purpose, sealed) => Buffer.from(sealed.slice(7), 'base64url').toString() };
  const options = { db: store, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY };
  const storage = new ConnectStorage(options);
  const legacy = new ConnectStorage(options);
  const sources = new SourceStore({ db: store, namespace: NS, clock });
  storage.useSources(sources);
  const identity = (uid) => ({ projectId: PROJECT, uid, authTimeSec: Math.floor(BASE / 1000) });
  const setAccess = (uid) => {
    store.docs.set(`sttdConnect/${NS}/access/${connectIdentityHash(hasher, NS, identity(uid))}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: BASE });
  };
  const approvalRequest = (uid) => ({
    approvalId: sourceApprovalId(hasher, NS, uid),
    clientHash: hasher.hash(`t256:${NS}:source-client`, 'client-1'),
    resourceHash: hasher.hash(`t256:${NS}:source-resource`, 'https://connect.example.org/mcp'),
  });
  const deps = { store: sources, namespace: NS, projectId: PROJECT, projectNumber: '123456789012', now: () => now.value, hasher };
  return { NS, db: store, now, clock, hasher, storage, legacy, sources, identity, setAccess, approvalRequest, deps };
}

/** login済みのinteractionを作り、同意の消費まで進める（同意記録を返す）。 */
async function consented(d, uid, interactionId) {
  d.setAccess(uid);
  const admitted = await d.storage.resolveOwner(d.identity(uid));
  assert.equal(admitted.kind, 'admitted');
  const opened = await d.storage.openInteraction(interactionId);
  assert.equal(await d.storage.bindInteraction(interactionId, opened.csrf, admitted.ownerId, Math.floor(BASE / 1000), admitted.accessGeneration, 'developer_code'), 'ok');
  assert.deepEqual(await d.storage.interactionForApproval(interactionId), { ownerId: admitted.ownerId, expiresAt: BASE + 300_000 });
  const consent = await d.storage.consumeInteractionChecked(interactionId, opened.csrf, '', false);
  assert.equal(typeof consent, 'object');
  return { ownerId: admitted.ownerId, consent };
}

async function registerDeveloper(d, uid) {
  const created = await runSourceAdmin(
    { command: 'register-developer', project: 'p', database: 'd', namespace: d.NS },
    { operations: ['send', 'connect'], uid, publicKey: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, expiresAt: null },
    d.deps,
  );
  assert.equal(created.code, 'created');
  const record = (await d.sources.status(created.source)).record;
  return { sourceId: record.sourceId, generation: record.generation, record };
}

async function approve(d, uid, interactionId, binding) {
  const request = d.approvalRequest(interactionId);
  return d.sources.recordApproval(
    { approvalId: request.approvalId, identityHash: connectIdentityHash(d.hasher, d.NS, d.identity(uid)), clientHash: request.clientHash, resourceHash: request.resourceHash },
    binding,
    BASE + 300_000,
  );
}

test('同意: 承認が無ければGrant metadataを作らず、同じ本人の承認だけを単回消費してGrantへsource/世代を結ぶ', async () => {
  const d = deployment();
  const { ownerId, consent } = await consented(d, 'uid-a', 'ia-1');
  const source = await registerDeveloper(d, 'uid-a');
  const request = d.approvalRequest('ia-1');
  assert.equal(await d.storage.putGrantMeta('grant-0', consent), 'denied');
  assert.equal(await d.storage.putGrantMeta('grant-0', consent, request), 'denied');
  assert.equal(await d.sources.approvalPending(request), false);
  assert.equal((await approve(d, 'uid-a', 'ia-1', source)).kind, 'recorded');
  assert.equal(await d.sources.approvalPending(request), true);
  assert.equal(await d.storage.putGrantMeta('grant-1', consent, request), 'created');
  // 単回: 同じ承認で2つ目のGrantは作れない。
  assert.equal(await d.storage.putGrantMeta('grant-2', consent, request), 'denied');
  assert.equal(await d.sources.approvalPending(request), false);
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-1'), true);
  assert.equal(await d.storage.grantSourceUsable('grant-1'), true);
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-2'), false);
  const bindingDoc = [...d.db.docs.entries()].find(([path]) => path.includes('/sourceGrants/'));
  assert.deepEqual(Object.keys(bindingDoc[1]).sort(), ['generation', 'sourceId']);
  const approvalDoc = [...d.db.docs.entries()].find(([path]) => path.includes('/sourceApprovals/'));
  assert.ok(!JSON.stringify(approvalDoc).includes('uid-a') && !JSON.stringify(approvalDoc).includes('ia-1'));
});

test('同意: 別本人の承認・期限切れ・DB待機中の失効は拒否する', async () => {
  const d = deployment();
  const { consent } = await consented(d, 'uid-a', 'ia-1');
  const source = await registerDeveloper(d, 'uid-b');
  // 別本人（uid-b）の承認ではuid-aの同意に使えない。
  assert.equal((await approve(d, 'uid-b', 'ia-1', source)).kind, 'recorded');
  assert.equal(await d.storage.putGrantMeta('grant-1', consent, d.approvalRequest('ia-1')), 'denied');

  const e = deployment();
  const second = await consented(e, 'uid-a', 'ia-2');
  const sourceE = await registerDeveloper(e, 'uid-a');
  assert.equal((await approve(e, 'uid-a', 'ia-2', sourceE)).kind, 'recorded');
  // 承認を読んだ後（全readの途中）に時計が5分を越える: 最終時刻で期限切れとして拒否する。
  e.db.hooks.onGet = (path) => {
    if (path.includes('/sourceApprovals/')) e.now.value = BASE + 300_001;
  };
  assert.equal(await e.storage.putGrantMeta('grant-1', second.consent, e.approvalRequest('ia-2')), 'denied');
});

test('code交換/refresh・MCP入口: 停止・再有効化（新世代）・削除・旧Grantを拒否し、新しい承認でだけ回復する', async () => {
  const d = deployment();
  const { ownerId, consent } = await consented(d, 'uid-a', 'ia-1');
  const source = await registerDeveloper(d, 'uid-a');
  await approve(d, 'uid-a', 'ia-1', source);
  assert.equal(await d.storage.putGrantMeta('grant-1', consent, d.approvalRequest('ia-1')), 'created');
  // 短期票（承認）の期限後もGrant自体は継続して使える。
  d.now.value = BASE + 600_000;
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-1'), true);
  // strict切替前の旧Grant（bindingなし）は使えない。
  assert.equal(await d.legacy.putGrantMeta('grant-old', consent), 'created');
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-old'), false);
  assert.equal(await d.storage.grantSourceUsable('grant-old'), false);
  // 停止 → 不可。再有効化は新世代で、旧Grantは復活しない。
  const status = await runSourceAdmin({ command: 'status', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId }, null, d.deps);
  const disabled = await runSourceAdmin({ command: 'disable', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId, expect: status.version }, null, d.deps);
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-1'), false);
  const enabled = await runSourceAdmin({ command: 'enable', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId, expect: disabled.version }, null, d.deps);
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-1'), false);
  assert.equal(await d.storage.grantSourceUsable('grant-1'), false);
  // 削除は物理削除（何も残さない）。旧Grantは不在として拒否。
  const deleted = await runSourceAdmin({ command: 'delete', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId, expect: enabled.version }, null, d.deps);
  assert.equal(deleted.code, 'deleted');
  assert.equal(d.db.docs.has(`sttdConnect/${d.NS}/sources/${source.sourceId}`), false);
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-1'), false);
  // 新しいsource登録と新しい承認・同意でだけ回復する。
  d.now.value = BASE;
  const renewed = await consented(d, 'uid-a', 'ia-3');
  const fresh = await registerDeveloper(d, 'uid-a');
  assert.notEqual(fresh.sourceId, source.sourceId);
  await approve(d, 'uid-a', 'ia-3', fresh);
  assert.equal(await d.storage.putGrantMeta('grant-3', renewed.consent, d.approvalRequest('ia-3')), 'created');
  assert.equal(await d.storage.grantUsable(ownerId, 'grant-3'), true);
});

test('送出確定: 入口で認可した後にsourceを停止すると、同じtxの照合で送出しない', async () => {
  const d = deployment();
  const source = await registerDeveloper(d, 'uid-a');
  const gate = createSourceGate({ policy: { mode: 'strict-v1', methods: ['developer-key-v1'] }, store: d.sources, hasher: d.hasher, namespace: d.NS, audience: 'https://api.example.org', clock: d.clock });
  const check = gate.dispatchCheck({ sourceId: source.sourceId, generation: source.generation }, 'send');
  assert.equal(await d.db.runTransaction((tx) => check(tx)), true);
  const status = await runSourceAdmin({ command: 'status', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId }, null, d.deps);
  await runSourceAdmin({ command: 'disable', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId, expect: status.version }, null, d.deps);
  assert.equal(await d.db.runTransaction((tx) => check(tx)), false);
});

test('二配置: Aの承認・Grant bindingはBで使えない', async () => {
  const shared = fakeDb();
  const a = deployment(shared);
  const b = deployment(shared);
  const { consent } = await consented(a, 'uid-a', 'ia-1');
  const source = await registerDeveloper(a, 'uid-a');
  await approve(a, 'uid-a', 'ia-1', source);
  const second = await consented(b, 'uid-a', 'ia-1');
  // 同じinteraction IDでも、Bのnamespace/HMACでは承認が見つからない。
  assert.equal(await b.storage.putGrantMeta('grant-b', second.consent, b.approvalRequest('ia-1')), 'denied');
  assert.equal(await a.storage.putGrantMeta('grant-a', consent, a.approvalRequest('ia-1')), 'created');
  assert.equal(await b.storage.grantSourceUsable('grant-a'), false);
});

test('同意前の確認: 承認後にsourceを停止すると待機中と同じ（同意の消費・受信先設定の削除へ進まない）', async () => {
  const d = deployment();
  await consented(d, 'uid-a', 'ia-1');
  const source = await registerDeveloper(d, 'uid-a');
  await approve(d, 'uid-a', 'ia-1', source);
  const request = d.approvalRequest('ia-1');
  assert.equal(await d.sources.approvalPending(request), true);
  // 別client/resourceの承認としては扱わない。
  assert.equal(await d.sources.approvalPending({ ...request, clientHash: 'e'.repeat(64) }), false);
  const status = await runSourceAdmin({ command: 'status', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId }, null, d.deps);
  await runSourceAdmin({ command: 'disable', project: 'p', database: 'd', namespace: d.NS, source: source.sourceId, expect: status.version }, null, d.deps);
  assert.equal(await d.sources.approvalPending(request), false);
});

test('同意画面: strictだけ参照・承認方法・状態（待機/承認済み/承認なし）を日英で表示し、compatibleは従来どおり', async () => {
  const { renderInteractionConsent } = await import('../dist/connect/pages.js');
  const web = { apiKey: 'synthetic-key', authDomain: 'synthetic.example.org', projectId: PROJECT };
  const compatible = renderInteractionConsent(web, 'ia-ref', 'Dots', 'csrf-1', 'en', null);
  assert.ok(!compatible.includes('sttd-source-approval'));
  for (const [language, expected] of [
    ['en', { waiting: 'waiting for approval', confirmed: 'approved at your trusted source', required: 'no valid approval' }],
    ['ja', { waiting: '承認待ち', confirmed: '承認済み', required: '有効な承認がまだありません' }],
  ]) {
    for (const state of ['waiting', 'confirmed', 'required']) {
      const html = renderInteractionConsent(web, 'ia-ref', 'Dots', 'csrf-1', language, { token: 'tok', confirm: true }, { reference: 'ia-ref', state });
      assert.ok(html.includes('<code id="sttd-source-reference">ia-ref</code>'));
      assert.ok(html.includes(`data-sttd-source-state="${state}"`));
      assert.ok(html.includes(expected[state]), `${language}/${state}`);
      // 既存のCSRF・受信先設定の確認欄は残る。
      assert.ok(html.includes('name="csrf" value="csrf-1"') && html.includes('name="receiverReset"'));
    }
  }
  const escaped = renderInteractionConsent(web, 'x', 'Dots', 'c', 'en', null, { reference: '<script>', state: 'waiting' });
  assert.ok(!escaped.includes('<script>'));
});

test('承認本文: 元operationの期限・中止・切断・超過で清掃して終わり、listenerを残さない', async () => {
  const { PassThrough } = await import('node:stream');
  const { readApprovalBody } = await import('../dist/source/http.js');
  const clock = { now: () => Date.now() };
  const listeners = (stream) => ['data', 'end', 'error', 'aborted', 'close'].reduce((sum, name) => sum + stream.listenerCount(name), 0);
  const op = (ms = 5_000) => {
    const controller = new AbortController();
    return { controller, operation: { deadlineAt: Date.now() + ms, signal: controller.signal } };
  };
  // 正規
  {
    const stream = new PassThrough();
    const { operation } = op();
    const pending = readApprovalBody(stream, operation, clock);
    stream.end('{"approve":true}');
    assert.equal((await pending).toString('utf8'), '{"approve":true}');
    assert.equal(listeners(stream), 0);
  }
  // 遅いbody: 元期限で終わる（延長しない）
  {
    const stream = new PassThrough();
    const { operation } = op(50);
    const started = Date.now();
    assert.equal(await readApprovalBody(stream, operation, clock), null);
    assert.ok(Date.now() - started < 2_000);
    assert.equal(listeners(stream), 0);
  }
  // 中止
  {
    const stream = new PassThrough();
    const { controller, operation } = op();
    const pending = readApprovalBody(stream, operation, clock);
    stream.write('{"appr');
    controller.abort();
    assert.equal(await pending, null);
    assert.equal(listeners(stream), 0);
  }
  // 超過
  {
    const stream = new PassThrough();
    const { operation } = op();
    const pending = readApprovalBody(stream, operation, clock);
    stream.write('x'.repeat(65));
    assert.equal(await pending, null);
    assert.equal(listeners(stream), 0);
  }
  // 切断（completeでないclose）
  {
    const stream = new PassThrough();
    const { operation } = op();
    const pending = readApprovalBody(stream, operation, clock);
    stream.destroy();
    assert.equal(await pending, null);
  }
  // 既に中止済み・期限切れは読み始めない
  {
    const stream = new PassThrough();
    const { controller, operation } = op();
    controller.abort();
    assert.equal(await readApprovalBody(stream, operation, clock), null);
    assert.equal(listeners(stream), 0);
  }
});
