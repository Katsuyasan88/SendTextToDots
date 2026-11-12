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
  const consent = await d.storage.consumeInteractionChecked(interactionId, opened.csrf, '');
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

// ---- 実部品の接合: 本物の固定oidc-provider＋実resolver、実KmsRequestDeliveryStore＋実serviceの送出確定（test/fixtures/source-runtime.mjs） ----

const appRecord = (now, overrides = {}) => ({
  schemaVersion: 1,
  sourceId: newSourceId(),
  kind: 'app',
  state: 'active',
  generation: newSourceGeneration(),
  operations: ['send', 'connect'],
  appId: '1:123456789012:ios:0123abcd',
  createdAt: now,
  updatedAt: now,
  ...overrides,
});

test('T232 本物のMCP resolver: 期限付きcode ownerは期限内だけ解決、期限もkindも無い旧code ownerの既存opaque tokenは拒否（新しい10分は付かない）', async () => {
  const { createResolverRuntime } = await import('./fixtures/source-runtime.mjs');
  const { connectIdentityHash } = await import('../dist/connect/firestore.js');
  const r = createResolverRuntime({ strict: false });
  try {
    const identity = { projectId: 'demo-sttd-source-runtime', uid: `sttdc_${'A'.repeat(32)}`, authTimeSec: 1, method: 'developer_code' };
    const accessPath = `sttdConnect/${r.NS}/access/${connectIdentityHash(r.hasher, r.NS, identity)}`;
    r.db.docs.set(accessPath, { version: 1, state: 'active', generation: globalThis.crypto.randomUUID(), updatedAt: Date.now(), codeLoginExpiresAt: Date.now() + 600_000 });
    const admitted = await r.ctx.run(r.op(), () => r.connect.resolveOwner(identity));
    assert.equal(admitted.kind, 'admitted');
    const issued = await r.issue(admitted.ownerId);
    assert.equal((await r.resolve(issued.value))?.ownerId, admitted.ownerId, 'control: within the deadline the real resolver resolves');
    // この版より前の形（owner文書に期限もkindも無い）へ: 保存済みの封緘UIDがcode形なので、既存opaque tokenは拒否
    const ownerPath = `sttdConnect/${r.NS}/owners/${admitted.ownerId}`;
    const { codeLoginExpiresAt, ...legacy } = r.db.docs.get(ownerPath);
    assert.ok(typeof codeLoginExpiresAt === 'number');
    r.db.docs.set(ownerPath, legacy);
    assert.equal(await r.resolve(issued.value), null, 'legacy code owner is refused by the real resolver');
    // 期限付きでも期限後は拒否（owner文書の期限を過去へ）
    r.db.docs.set(ownerPath, { ...legacy, codeLoginExpiresAt: Date.now() - 1 });
    assert.equal(await r.resolve(issued.value), null, 'expired code owner is refused');
  } finally {
    r.dispose();
  }
});

test('実MCP resolver（本物のoidc-provider）: bound Grantだけ解決し、旧Grant・停止・世代違い・削除はnull、互換は従来どおり', async () => {
  const { createResolverRuntime } = await import('./fixtures/source-runtime.mjs');
  const r = createResolverRuntime({ strict: true });
  const compat = createResolverRuntime({ strict: false });
  try {
    const ownerId = r.addOwner();
    const source = appRecord(Date.now());
    assert.equal(await r.sources.create(source), 'created');
    const issued = await r.issue(ownerId);
    // strict前の旧Grant（binding無し）は使えない。
    assert.equal(await r.resolve(issued.value), null);
    r.bind(issued.grantId, source);
    const resolved = await r.resolve(issued.value);
    assert.equal(resolved?.ownerId, ownerId);
    assert.equal(resolved?.grantId, issued.grantId);
    // 停止 → null。再有効化（新世代）→ 旧bindingはnull。
    const sourcePath = `sttdConnect/${r.NS}/sources/${source.sourceId}`;
    r.db.docs.set(sourcePath, { ...source, state: 'disabled', updatedAt: source.updatedAt + 1 });
    assert.equal(await r.resolve(issued.value), null);
    r.db.docs.set(sourcePath, { ...source, generation: newSourceGeneration(), updatedAt: source.updatedAt + 2 });
    assert.equal(await r.resolve(issued.value), null);
    // 削除（物理削除）→ null。
    r.db.docs.delete(sourcePath);
    assert.equal(await r.resolve(issued.value), null);
    // 互換配置（sourceを結ばない）はbinding無しでも従来どおり解決する。
    const compatOwner = compat.addOwner();
    const compatIssued = await compat.issue(compatOwner);
    assert.equal((await compat.resolve(compatIssued.value))?.ownerId, compatOwner);
  } finally {
    r.dispose();
    compat.dispose();
  }
});

test('実送出確定（実KmsRequestDeliveryStore＋実service）: 要求sourceと購読Grantのsourceが両方有効な時だけ送出し、片方の停止・旧Grant・世代違いは送出0', async () => {
  const { createDeliveryRuntime } = await import('./fixtures/source-runtime.mjs');
  const w = createDeliveryRuntime();
  const requestSource = appRecord(w.clock.t);
  const grantSource = appRecord(w.clock.t);
  assert.equal(await w.sources.create(requestSource), 'created');
  assert.equal(await w.sources.create(grantSource), 'created');
  const owner = w.enroll();
  w.bindGrant(owner.grantId, grantSource);
  const reqBinding = { sourceId: requestSource.sourceId, generation: requestSource.generation };

  // 両方有効（別々のsource）→ 送出。source文書の読取りとCommandの書込み（送出確定）が同じtx。
  const ok = await w.post(owner, reqBinding);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.state, 'delivered');
  assert.equal(w.sent.length, 1);
  const requestPath = `sttdConnect/${w.NS}/sources/${requestSource.sourceId}`;
  const grantPath = `sttdConnect/${w.NS}/sources/${grantSource.sourceId}`;
  const txs = (path) => new Set(w.log.filter((entry) => entry.kind === 'read' && entry.path === path).map((entry) => entry.tx));
  const dispatchTx = [...txs(requestPath)].find((tx) => txs(grantPath).has(tx) && w.log.some((entry) => entry.tx === tx && entry.kind === 'write' && entry.path.includes('/commands/')));
  assert.ok(dispatchTx !== undefined, 'both sources are read in the dispatch transaction that writes the command');

  // 入口認可の後に要求sourceを停止 → 送出0。
  w.clock.t += 1_000;
  w.docs.set(requestPath, { ...requestSource, state: 'disabled', updatedAt: requestSource.updatedAt + 1 });
  const stoppedRequest = await w.post(owner, reqBinding);
  assert.notEqual(stoppedRequest.body.state, 'delivered');
  assert.equal(w.sent.length, 1);
  w.docs.set(requestPath, { ...requestSource, updatedAt: requestSource.updatedAt + 2 });

  // 購読Grantのsourceを停止 → 送出0。
  w.docs.set(grantPath, { ...grantSource, state: 'disabled', updatedAt: grantSource.updatedAt + 1 });
  const stoppedGrant = await w.post(owner, reqBinding);
  assert.notEqual(stoppedGrant.body.state, 'delivered');
  assert.equal(w.sent.length, 1);

  // 購読Grantのsourceが新世代（再有効化）→ 旧bindingの購読は送出0。
  w.docs.set(grantPath, { ...grantSource, generation: newSourceGeneration(), updatedAt: grantSource.updatedAt + 2 });
  assert.notEqual((await w.post(owner, reqBinding)).body.state, 'delivered');
  assert.equal(w.sent.length, 1);

  // 旧（unbound）Grantの購読 → 送出0。
  const legacy = w.enroll();
  assert.notEqual((await w.post(legacy, reqBinding)).body.state, 'delivered');
  assert.equal(w.sent.length, 1);

  // 回復: 購読Grantのsourceを元の世代で有効へ戻した場合だけ再び送出（新世代への付替えはしない）。
  w.docs.set(grantPath, { ...grantSource, updatedAt: grantSource.updatedAt + 3 });
  assert.equal((await w.post(owner, reqBinding)).body.state, 'delivered');
  assert.equal(w.sent.length, 2);
});

test('実購読保存（実registration runtime/storeの最終tx）: bound Grantだけ保存し、旧Grant・停止・世代違いは保存0', async () => {
  const { createSubscriptionRuntime } = await import('./fixtures/source-runtime.mjs');
  const s = await createSubscriptionRuntime();
  try {
    const source = appRecord(Date.now());
    assert.equal(await s.sources.create(source), 'created');
    const sourcePath = `sttdConnect/${s.NS}/sources/${source.sourceId}`;
    // 正規: bound Grantの購読は保存される。
    const good = await s.enroll();
    s.bind(good.grantId, source);
    const saved = await s.subscribe(good);
    assert.equal(saved.ok, true, `bound grant subscribes (${saved.kind})`);
    assert.ok(s.subscriptionOf(good.ownerId)?.active);
    // 旧（unbound）Grant → grant_inactive・保存0。
    const legacy = await s.enroll();
    const refused = await s.subscribe(legacy);
    assert.deepEqual([refused.ok, refused.kind], [false, 'grant_inactive']);
    assert.equal(s.subscriptionOf(legacy.ownerId)?.active ?? null, null);
    // 停止 → 保存0。
    const stopped = await s.enroll();
    s.bind(stopped.grantId, source);
    s.docs.set(sourcePath, { data: { ...source, state: 'disabled', updatedAt: source.updatedAt + 1 }, updateTime: { seconds: 1, nanoseconds: 1 } });
    const stoppedResult = await s.subscribe(stopped);
    assert.deepEqual([stoppedResult.ok, stoppedResult.kind], [false, 'grant_inactive']);
    assert.equal(s.subscriptionOf(stopped.ownerId)?.active ?? null, null);
    // 世代違い（再有効化）→ 保存0。
    s.docs.set(sourcePath, { data: { ...source, generation: newSourceGeneration(), updatedAt: source.updatedAt + 2 }, updateTime: { seconds: 2, nanoseconds: 2 } });
    const renewed = await s.subscribe(stopped);
    assert.deepEqual([renewed.ok, renewed.kind], [false, 'grant_inactive']);
  } finally {
    await s.close();
  }
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
      const html = renderInteractionConsent(web, 'ia-ref', 'Dots', 'csrf-1', language, { token: 'tok', present: true }, { reference: 'ia-ref', state });
      assert.ok(html.includes('<code id="sttd-source-reference">ia-ref</code>'));
      assert.ok(html.includes(`data-sttd-source-state="${state}"`));
      assert.ok(html.includes(expected[state]), `${language}/${state}`);
      // 既存のCSRF・受信先設定の確認欄は残る。
      assert.ok(html.includes('name="csrf" value="csrf-1"') && html.includes('name="receiverToken"'));
      assert.doesNotMatch(html, /name="receiverReset"/);
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

// ---- T-240 R3: Google wrapper経由の通常MCP起動（playgroundRegistrar）と、同じ購読へのApp Check・Web両sourceからの配送 ----
import { DEPLOYMENT_CONFIG as R3_DEPLOYMENT } from './fixtures/synthetic-deployment.mjs';
import { validateDeploymentConfig as r3Validate } from '../dist/config/validate.js';
import { signSourceRequest as r3Sign } from '../dist/source/proof.js';

test('T240-R3 起動: validateDeploymentConfigのplaygroundRegistrarをGoogle wrapper経由で通常MCPへ渡し、署名付きregisterが200、再送・署名不一致は403、未設定は404。compatible・gatewayの配置は設定error', async () => {
  const { startConnectHttpRuntime } = await import('./fixtures/source-runtime.mjs');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const registrar = { sourceId: newSourceId(), publicKey: publicKey.export({ format: 'jwk' }).x };
  const strict = { mode: 'strict-v1', methods: ['developer-key-v1'] };
  const base = structuredClone(R3_DEPLOYMENT);
  assert.throws(() => r3Validate({ ...base, playgroundRegistrar: registrar }));
  assert.throws(() => r3Validate({ ...base, sourceAuthorization: strict, playgroundRegistrar: { ...registrar, publicKey: 'x' } }));
  const deployment = r3Validate({ ...base, sourceAuthorization: strict, playgroundRegistrar: registrar });
  assert.deepEqual(deployment.playgroundRegistrar, registrar);
  assert.equal(r3Validate({ ...base, sourceAuthorization: strict }).playgroundRegistrar, undefined);
  const rt = await startConnectHttpRuntime({ deployment });
  const off = await startConnectHttpRuntime({ deployment: r3Validate({ ...base, sourceAuthorization: strict }) });
  try {
    const path = '/v1/playground/register';
    const signed = (key = privateKey, bearer = 'id-alice', nonce = randomBytes(16).toString('base64url')) => {
      const iat = Math.floor(rt.clock.now() / 1000);
      const sig = r3Sign({ audience: rt.issuer, method: 'POST', path, search: '', sourceId: registrar.sourceId, body: Buffer.from('{}'), bearer, idempotencyKey: undefined }, { issuedAt: iat, expiresAt: iat + 60, nonce }, key);
      return { 'x-sttd-source': registrar.sourceId, 'x-sttd-source-signature': sig, Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' };
    };
    const b = rt.browser();
    const headers = signed();
    const ok = await b.request('POST', path, { headers, body: '{}', cookies: false });
    assert.equal(ok.status, 200, ok.body);
    const reg = JSON.parse(ok.body);
    assert.deepEqual(Object.keys(reg).sort(), ['generation', 'sourceId']);
    const src = rt.docs.get(`${rt.root}/sources/${reg.sourceId}`).data;
    assert.deepEqual([src.kind, src.publicKey, [...src.operations].sort()], ['developer', registrar.publicKey, ['connect', 'send']]);
    // 再実行（新しいnonce）は同じID・世代
    assert.deepEqual(JSON.parse((await b.request('POST', path, { headers: signed(), body: '{}', cookies: false })).body), reg);
    // 同じ署名の再送・別鍵の署名は403
    assert.equal((await b.request('POST', path, { headers, body: '{}', cookies: false })).status, 403);
    assert.equal((await b.request('POST', path, { headers: signed(generateKeyPairSync('ed25519').privateKey), body: '{}', cookies: false })).status, 403);
    // browserのOriginは拒否
    assert.equal((await b.request('POST', path, { headers: { ...signed(), Origin: rt.issuer }, body: '{}', cookies: false })).status, 403);
    // 未設定の配置は404
    assert.equal((await off.browser().request('POST', path, { headers: signed(), body: '{}', cookies: false })).status, 404);
  } finally {
    await rt.close?.();
    await off.close?.();
  }
  // gateway-v1との併用は設定error（今回使わない入口を広げない）
  const gw = (await import('./fixtures/gateway-runtime.mjs')).topologyConfig?.();
  if (gw !== undefined) assert.throws(() => r3Validate({ ...gw, sourceAuthorization: strict, playgroundRegistrar: registrar }));
});

test('T240-R3 同じ購読: 既存の通常許可とApp Check Grantのownerに同じUIDのWeb sourceを追加しても、両方の送信元から同じcallbackへ届き、許可の世代は不変。Webだけ・片方停止・別UIDは送出0', async () => {
  const { createDeliveryRuntime } = await import('./fixtures/source-runtime.mjs');
  const w = createDeliveryRuntime();
  const app = appRecord(w.clock.t);
  assert.equal(await w.sources.create(app), 'created');
  const owner = w.enroll({ uid: 'SameUid' });
  w.bindGrant(owner.grantId, app); // DPADAAで承認した既存Grant
  const accessPath = `sttdConnect/${w.NS}/access/${owner.identityHash}`;
  const accessBefore = structuredClone(w.docs.get(accessPath));
  // 同じUIDのWeb登録（限定routeと同じ store操作）
  const reg = await w.sources.registerPlayground({ identityHash: owner.identityHash, publicKey: 'A'.repeat(43), expiresAt: null, fresh: { sourceId: newSourceId(), generation: newSourceGeneration() }, newAccessGeneration: randomUUID(), codeIdentity: false });
  assert.equal(reg.kind, 'registered');
  assert.deepEqual(w.docs.get(accessPath), accessBefore); // 世代・範囲は不変
  const appBinding = { sourceId: app.sourceId, generation: app.generation };
  const webBinding = reg.binding;
  assert.equal((await w.post(owner, appBinding, owner.identity)).body.state, 'delivered');
  w.clock.t += 10 * 60_000;
  assert.equal((await w.post(owner, webBinding, owner.identity)).body.state, 'delivered');
  assert.equal(w.sent.length, 2); // 同じ購読（同じcallback）へ両方
  // 別UIDはWeb sourceの要求認可で拒否（本人違い）
  const other = await w.sources.authorizeRequest({ sourceId: webBinding.sourceId, method: 'developer-key-v1', operation: 'send', identityHash: 'f'.repeat(64), proofMatches: () => true });
  assert.deepEqual(other, { kind: 'rejected', reason: 'subject' });
  // Web sourceを停止 → Webからは送出0、App Checkからは継続
  const webPath = `sttdConnect/${w.NS}/sources/${webBinding.sourceId}`;
  const web = w.docs.get(webPath);
  w.clock.t += 10 * 60_000;
  w.docs.set(webPath, { ...web, state: 'disabled', updatedAt: web.updatedAt + 1 });
  assert.notEqual((await w.post(owner, webBinding, owner.identity)).body.state, 'delivered');
  assert.equal(w.sent.length, 2); // 停止したWeb sourceからは送出0
  w.clock.t += 10 * 60_000;
  assert.equal((await w.post(owner, appBinding, owner.identity)).body.state, 'delivered');
  assert.equal(w.sent.length, 3);
  w.docs.set(webPath, web);
  // Webだけの本人（範囲web）はApp Check sourceから送出0、Web sourceからは送出
  w.clock.t += 10 * 60_000;
  w.docs.set(accessPath, { ...accessBefore, sourceScope: 'web' });
  assert.notEqual((await w.post(owner, appBinding, owner.identity)).body.state, 'delivered');
  assert.equal(w.sent.length, 3); // Webだけの本人のApp Check要求は送出0
  w.clock.t += 10 * 60_000;
  assert.equal((await w.post(owner, webBinding, owner.identity)).body.state, 'delivered');
  assert.equal(w.sent.length, 4);
});

// ---- T-257: OpenAIのアプリ公開のドメイン確認（/.well-known/openai-apps-challenge）。合成値だけ・実トークン0。 ----
const T257_VALUE = 'synthetic-Challenge_0123.abc~XYZ';
const T257_PATH = '/.well-known/openai-apps-challenge';

test('T257-1 the configured value is returned only for an exact GET without query: 200, text/plain, no-store, exact bytes without newline; other methods/neighbours/query never show it; OAuth discovery and unauthenticated MCP unchanged', async () => {
  const { startConnectHttpRuntime } = await import('./fixtures/source-runtime.mjs');
  const rt = await startConnectHttpRuntime({ openaiAppsChallenge: T257_VALUE });
  try {
    const b = rt.browser();
    const ok = await b.request('GET', T257_PATH, { cookies: false });
    assert.equal(ok.status, 200);
    assert.equal(ok.body, T257_VALUE);
    assert.equal(Buffer.byteLength(ok.body), Buffer.byteLength(T257_VALUE)); // 改行なし
    assert.equal(ok.headers['content-type'], 'text/plain; charset=utf-8');
    assert.equal(ok.headers['cache-control'], 'no-store');
    assert.equal(ok.headers['content-length'], String(Buffer.byteLength(T257_VALUE)));
    for (const method of ['POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']) {
      const r = await b.request(method, T257_PATH, { cookies: false });
      assert.notEqual(r.status, 200, method);
      assert.ok(!r.body.includes(T257_VALUE), method);
    }
    // 空の「?」とドット区間は、正規化前の生のrequest-targetのまま送る（合成browserのrawTarget）。
    for (const near of [`${T257_PATH}?`, '/.well-known/./openai-apps-challenge']) {
      const r = await b.request('GET', near, { cookies: false, rawTarget: true });
      assert.ok(!(r.status === 200 && r.body === T257_VALUE) && !r.body.includes(T257_VALUE), `raw ${near}`);
    }
    for (const near of [`${T257_PATH}/`, `${T257_PATH}.txt`, `${T257_PATH}?x=1`, '/.well-known/OPENAI-APPS-CHALLENGE', '/.well-known/openai-apps-challenge%2F', '/.well-known/openai-apps', '/openai-apps-challenge']) {
      const r = await b.request('GET', near, { cookies: false });
      assert.ok(!(r.status === 200 && r.body === T257_VALUE) && !r.body.includes(T257_VALUE), near);
    }
    // 既存のOAuth/MCP契約
    assert.equal((await b.request('GET', '/.well-known/oauth-protected-resource/mcp', { cookies: false })).status, 200);
    assert.equal((await b.request('GET', '/.well-known/oauth-authorization-server', { cookies: false })).status, 200);
    const mcp = await b.request('POST', '/mcp', { cookies: false, headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' });
    assert.equal(mcp.status, 401);
    assert.ok(!mcp.body.includes(T257_VALUE));
  } finally {
    await rt.close();
  }
});

test('T257-2 without the option the path stays 404 (as before); an explicit invalid value refuses startup with a fixed config error that does not contain the value', async () => {
  const { startConnectHttpRuntime } = await import('./fixtures/source-runtime.mjs');
  const { isOpenAiAppsChallenge, OPENAI_APPS_CHALLENGE_PATH } = await import('../dist/connect/kms-server.js');
  assert.equal(OPENAI_APPS_CHALLENGE_PATH, T257_PATH);
  const off = await startConnectHttpRuntime();
  try {
    const r = await off.browser().request('GET', T257_PATH, { cookies: false });
    assert.equal(r.status, 404);
  } finally {
    await off.close();
  }
  for (const bad of ['', 'has space', 'line\n', 'slash/x', 'quote"x', 'é', 'x'.repeat(257), 42, null]) {
    assert.equal(isOpenAiAppsChallenge(bad), false, String(bad));
    if (typeof bad !== 'string') continue;
    await assert.rejects(startConnectHttpRuntime({ openaiAppsChallenge: bad }), (e) => e.code === 'kms_connect_config_invalid' && !(bad.length > 0 && e.message.includes(bad)));
  }
  assert.equal(isOpenAiAppsChallenge('x'.repeat(256)), true);
  assert.equal(isOpenAiAppsChallenge(T257_VALUE), true);
});

test('T257-3 the Google wrapper forwards the option through its strict allowlist (direct deployment): exact GET 200', async () => {
  const { startConnectHttpRuntime } = await import('./fixtures/source-runtime.mjs');
  const deployment = r3Validate({ ...structuredClone(R3_DEPLOYMENT), sourceAuthorization: { mode: 'strict-v1', methods: ['developer-key-v1'] } });
  const rt = await startConnectHttpRuntime({ deployment, openaiAppsChallenge: T257_VALUE });
  try {
    const r = await rt.browser().request('GET', T257_PATH, { cookies: false });
    assert.deepEqual([r.status, r.body, r.headers['content-type']], [200, T257_VALUE, 'text/plain; charset=utf-8']);
  } finally {
    await rt.close();
  }
});
