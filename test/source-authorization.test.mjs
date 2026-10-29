// 送信API入口（delivery/api.ts）の許可元gate（source/http.ts）。合成のin-memory Firestore・合成本人verifier・合成App Check portだけ。
//   - strict: 平文/暗号文の送信・公開鍵の取得/再発行は証明が必須。欠落/形違いは本人確認・owner・service・DBの前に403。
//   - 開発者署名: 正規要求は通り、replay・本文差替え・別本人・停止は403。App Check: 消費済みは403、結果不明は503（開発者方式へ降格しない）。
//   - 照会/取消は最小回復としてgateなし（現行の本人/owner条件）。互換配置（gateなし）は従来どおり。
// 実SDK・Cloud・資格・network・配送 0。鍵・tokenは合成値。

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { createHmacHasher } from '../dist/secrets.js';
import { newSourceGeneration, newSourceId } from '../dist/source/admin.js';
import { createAppCheckVerifier } from '../dist/source/app-check.js';
import { SourceStore } from '../dist/source/firestore.js';
import { createSourceGate } from '../dist/source/http.js';
import { signSourceRequest } from '../dist/source/proof.js';

function fakeDb() {
  const docs = new Map();
  const state = { down: false, tx: 0 };
  let lock = Promise.resolve();
  const snap = (path) => {
    const data = docs.get(path);
    return { id: path.split('/').pop(), exists: data !== undefined, data: () => (data === undefined ? undefined : structuredClone(data)) };
  };
  const ref = (path) => ({ id: path.split('/').pop(), path, collection: (name) => ({ doc: (id) => ref(`${path}/${name}/${id}`) }), get: async () => snap(path) });
  return {
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
}

const NOW = 1_700_000_000_000;
const AUDIENCE = 'https://sendtexttodotsapi-123456789012.europe-west1.run.app';
const PROJECT_ID = 'sendtexttodots-test';
const PROJECT_NUMBER = '123456789012';
const APP_ID = `1:${PROJECT_NUMBER}:ios:0123abcd`;

function harness({ methods = ['developer-key-v1', 'app-check-v1'], appCheckBehaviour, gate = true } = {}) {
  const NS = `t256_${randomUUID()}`;
  const hasher = createHmacHasher(randomBytes(32));
  const db = fakeDb();
  const clock = { now: () => NOW };
  const store = new SourceStore({ db, namespace: NS, clock });
  const counts = { identity: 0, owner: 0, post: 0, get: 0, cancel: 0, keyGet: 0, reissue: 0, encrypted: 0, appCheck: 0 };
  const identity = {
    projectId: PROJECT_ID,
    async verifyIdToken(token) {
      counts.identity += 1;
      return { projectId: PROJECT_ID, uid: token === 'token.user.b' ? 'uid-b' : 'uid-a', authTimeSec: 1 };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const ok = (state = 'delivered') => ({ status: 200, body: { state } });
  const service = {
    post: async () => ((counts.post += 1), ok()),
    get: async () => ((counts.get += 1), ok()),
    cancel: async () => ((counts.cancel += 1), ok('cancelled')),
  };
  const appCheckPort = {
    async verifyToken(token, options) {
      counts.appCheck += 1;
      assert.deepEqual(options, { consume: true });
      return (appCheckBehaviour ?? (() => ({ appId: APP_ID, token: { iss: `https://firebaseappcheck.googleapis.com/${PROJECT_NUMBER}`, aud: [`projects/${PROJECT_NUMBER}`], sub: APP_ID }, alreadyConsumed: false })))(token);
    },
  };
  const sources = gate
    ? createSourceGate({
        policy: { mode: 'strict-v1', methods },
        store,
        hasher,
        namespace: NS,
        audience: AUDIENCE,
        clock,
        appCheck: methods.includes('app-check-v1') ? createAppCheckVerifier({ appCheck: appCheckPort, projectNumber: PROJECT_NUMBER, projectId: PROJECT_ID }) : undefined,
      })
    : undefined;
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async () => ((counts.owner += 1), 'owner-a'),
    service,
    clock,
    lifetime: new AbortController().signal,
    ingress: () => ({ receivedAt: NOW, deadlineAt: NOW + 20_000, signal: new AbortController().signal }),
    encryptionKeys: Object.freeze({ get: async () => ((counts.keyGet += 1), ok('key')), reissue: async () => ((counts.reissue += 1), ok('key')) }),
    encryptedCommands: Object.freeze({ post: async () => ((counts.encrypted += 1), ok()) }),
    ...(sources !== undefined ? { sources } : {}),
  });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const developer = {
    schemaVersion: 1,
    sourceId: newSourceId(),
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['send', 'keys'],
    publicKey: publicKey.export({ format: 'jwk' }).x,
    identityHash: connectIdentityHash(hasher, NS, { projectId: PROJECT_ID, uid: 'uid-a' }),
    expiresAt: NOW + 3_600_000,
    createdAt: 1,
    updatedAt: 1,
  };
  const app = { schemaVersion: 1, sourceId: newSourceId(), kind: 'app', state: 'active', generation: newSourceGeneration(), operations: ['send'], appId: APP_ID, createdAt: 1, updatedAt: 1 };
  return { NS, db, store, counts, handler, privateKey, developer, app };
}

async function call(handler, { method = 'POST', url = '/v2/commands', headers = {}, body = '{"text":"synthetic"}' } = {}) {
  const req = Object.assign(new EventEmitter(), {
    method,
    url,
    headers: { 'content-type': 'application/json', authorization: 'Bearer token.user.a', ...headers },
    rawBody: Buffer.from(body),
    aborted: false,
    destroyed: false,
    complete: true,
    readableEnded: true,
  });
  const res = Object.assign(new EventEmitter(), {
    headersSent: false,
    writableEnded: false,
    writableFinished: false,
    destroyed: false,
    status: 0,
    payload: undefined,
    writeHead(status) {
      this.status = status;
    },
    end(payload) {
      this.payload = JSON.parse(payload.toString('utf8'));
      this.writableEnded = true;
      this.writableFinished = true;
    },
  });
  await handler(req, res);
  return { status: res.status, code: res.payload?.error?.code };
}

function signed(h, { method = 'POST', url = '/v2/commands', body = '{"text":"synthetic"}', bearer = 'token.user.a', key = 'idem-1', nonce = randomBytes(16).toString('base64url'), sourceId = h.developer.sourceId } = {}) {
  const [path, query] = url.split('?');
  const claims = { issuedAt: NOW / 1000, expiresAt: NOW / 1000 + 60, nonce };
  const signature = signSourceRequest(
    { audience: AUDIENCE, method, path, search: query === undefined ? '' : `?${query}`, sourceId, body: Buffer.from(body), bearer, idempotencyKey: key },
    claims,
    h.privateKey,
  );
  return { 'x-sttd-source': sourceId, 'x-sttd-source-signature': signature, ...(key !== undefined ? { 'idempotency-key': key } : {}) };
}

test('strict: 証明の欠落・形違いは本人確認・owner・service・DBの前に403（全業務route）', async () => {
  const h = harness();
  const routes = [
    { url: '/v2/commands', headers: { 'idempotency-key': 'k' } },
    { url: '/v2/encrypted-commands', headers: { 'content-type': 'application/jose', 'idempotency-key': 'k' }, body: 'a.b.c.d.e' },
    { method: 'GET', url: '/v2/encryption-key', body: '' },
  ];
  for (const route of routes) {
    assert.deepEqual(await call(h.handler, route), { status: 403, code: 'source_required' });
    assert.deepEqual(await call(h.handler, { ...route, headers: { ...route.headers, 'x-sttd-source': 'laptop', 'x-sttd-source-signature': 'x' } }), { status: 403, code: 'source_rejected' });
  }
  assert.deepEqual(h.counts, { identity: 0, owner: 0, post: 0, get: 0, cancel: 0, keyGet: 0, reissue: 0, encrypted: 0, appCheck: 0 });
  assert.equal(h.db.state.tx, 0);
});

test('strict: 登録開発者の正規署名は通り、replay・本文差替え・別本人・停止は403', async () => {
  const h = harness();
  await h.store.create(h.developer);
  const headers = signed(h);
  assert.deepEqual(await call(h.handler, { headers }), { status: 200, code: undefined });
  assert.equal(h.counts.post, 1);
  assert.deepEqual(await call(h.handler, { headers }), { status: 403, code: 'source_rejected' });
  assert.deepEqual(await call(h.handler, { headers: signed(h), body: '{"text":"other"}' }), { status: 403, code: 'source_rejected' });
  assert.deepEqual(await call(h.handler, { headers: { ...signed(h, { bearer: 'token.user.b' }), authorization: 'Bearer token.user.b' } }), { status: 403, code: 'source_rejected' });
  assert.deepEqual(await call(h.handler, { headers: { ...signed(h), 'idempotency-key': 'idem-2' } }), { status: 403, code: 'source_rejected' });
  assert.equal(h.counts.post, 1);
  assert.equal(h.counts.owner, 1);
  const keyHeaders = signed(h, { method: 'GET', url: '/v2/encryption-key', body: '', key: undefined });
  assert.deepEqual(await call(h.handler, { method: 'GET', url: '/v2/encryption-key', body: '', headers: keyHeaders }), { status: 200, code: undefined });
  h.db.docs.set(`sttdConnect/${h.NS}/sources/${h.developer.sourceId}`, { ...h.developer, state: 'disabled', updatedAt: 2 });
  assert.deepEqual(await call(h.handler, { headers: signed(h) }), { status: 403, code: 'source_rejected' });
  assert.equal(h.counts.post, 1);
});

test('strict: 照会/取消は最小回復としてgateなし、互換配置は従来どおり', async () => {
  const h = harness();
  const id = randomUUID();
  assert.equal((await call(h.handler, { method: 'GET', url: `/v2/commands/${id}`, body: '' })).status, 200);
  assert.equal((await call(h.handler, { method: 'POST', url: `/v2/commands/${id}/cancel`, body: '' })).status, 200);
  assert.equal(h.db.state.tx, 0);
  const compatible = harness({ gate: false });
  assert.equal((await call(compatible.handler, { headers: { 'idempotency-key': 'k' } })).status, 200);
});

test('strict: App Checkは毎回consume、消費済みは403、結果不明は503で開発者方式へ降格しない', async () => {
  const h = harness();
  await h.store.create(h.app);
  const headers = { 'x-sttd-source': h.app.sourceId, 'x-firebase-appcheck': 'aaa.bbb.ccc', 'idempotency-key': 'k' };
  assert.deepEqual(await call(h.handler, { headers }), { status: 200, code: undefined });
  const consumed = harness({ appCheckBehaviour: () => ({ appId: APP_ID, token: { iss: `https://firebaseappcheck.googleapis.com/${PROJECT_NUMBER}`, aud: [`projects/${PROJECT_NUMBER}`], sub: APP_ID }, alreadyConsumed: true }) });
  await consumed.store.create(consumed.app);
  assert.deepEqual(await call(consumed.handler, { headers: { ...headers, 'x-sttd-source': consumed.app.sourceId } }), { status: 403, code: 'source_rejected' });
  const down = harness({ appCheckBehaviour: () => { throw new Error('network'); } });
  await down.store.create(down.app);
  const txBefore = down.db.state.tx;
  assert.deepEqual(await call(down.handler, { headers: { ...headers, 'x-sttd-source': down.app.sourceId } }), { status: 503, code: 'temporarily_unavailable' });
  assert.equal(down.counts.post + consumed.counts.post, 0);
  // App Checkの結果不明では、source保存のtransactionも始めない。
  assert.equal(down.db.state.tx, txBefore);
  // 鍵操作を許していないapp source・開発者方式だけの配置でのApp Checkは拒否。
  assert.deepEqual(await call(h.handler, { method: 'GET', url: '/v2/encryption-key', body: '', headers: { 'x-sttd-source': h.app.sourceId, 'x-firebase-appcheck': 'aaa.bbb.ccc' } }), { status: 403, code: 'source_rejected' });
  const devOnly = harness({ methods: ['developer-key-v1'] });
  await devOnly.store.create(devOnly.app);
  assert.deepEqual(await call(devOnly.handler, { headers: { ...headers, 'x-sttd-source': devOnly.app.sourceId } }), { status: 403, code: 'source_rejected' });
  assert.equal(devOnly.counts.appCheck, 0);
});

test('strict: source保存の障害は503（通さない）', async () => {
  const h = harness();
  await h.store.create(h.developer);
  h.db.state.down = true;
  assert.deepEqual(await call(h.handler, { headers: signed(h) }), { status: 503, code: 'temporarily_unavailable' });
  assert.equal(h.counts.post, 0);
});
