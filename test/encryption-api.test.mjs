// 本人の公開鍵取得（GET /v2/encryption-key）。送信APIの実HTTP入口（createIngressOperationDeliveryRequestHandler）→実の公開鍵endpoint・
// 鍵service・store（createEncryptionKeyRuntime）→in-memoryのFirestore代替と、専用Secretの実adapterへ渡した合成GAX client（innerApiCalls）まで。
// 127.0.0.1のloopback・生HTTP/1.1。実Cloud・資格・Secret・SDK通信・network 0。合成identityの成功は実Firebaseの検証ではない。
//   - P01: 200は公開8項目と公開JWK6項目だけ（no-store、createdAtはISO、UID・ownerId・secret名なし）。
//   - P02: 同UIDの2 clientの再取得は同じ結果（生成・Secret読取りは初回だけ）。A/Bは別kid/scope。
//   - P03: 同UIDの並行GETは1つの鍵へ収束。
//   - P04: Bearer無し・Bearerでない資格は401で鍵service・DB・Secret 0（token検証の失敗の401は既存の送信API試験の範囲）。
//   - P05: 他UIDの自己申告（query・body・独自header）は400または無視で、本人以外の鍵を返さない。
//   - P06: owner未作成は409 connection_required（作成0）。
//   - P07: 停止（許可disabled）は403 access_denied、ringの90日無使用は409 encryption_key_unavailable（再初期化0）。
//   - P08: off（encryptionKeys無し）は404で、runtimeの組立てはnull（専用Secretのclientに触れない）。
//   - P09: 専用Secretの障害は503で、同じ入口の平文POST /v2/commandsは成功する。
//   - P10: DB障害は503。
//   - P11: 取得rate（分60）は429＋Retry-After。
//   - P12: cache期限後の再取得で鍵の回転0（generation・kid不変）。
//   - R: runtimeの組立ては専用Secretの読取り0、初回の初期化だけ読み、disposeの後は読まない（503）。
// node:testのtest数とP番号の数は一致しない（1つのtestに複数のPを入れる）。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { createEncryptionKeyRuntime } from '../dist/encryption/api.js';
import { crc32c } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';

const T0 = Date.UTC(2026, 9, 28, 0, 0, 30);
const DAY = 86_400_000;

// ---- in-memory Firestore代替（version付きの楽観transaction） ----

class Snapshot {
  constructor(id, data) {
    this.id = id;
    this.exists = data !== undefined;
    this._data = data;
  }
  data() {
    return this._data === undefined ? undefined : structuredClone(this._data);
  }
}
class Ref {
  constructor(db, path) {
    this.db = db;
    this.path = path;
    this.id = path.split('/').pop();
  }
  collection(name) {
    return { doc: (id) => new Ref(this.db, `${this.path}/${name}/${id}`) };
  }
  async get() {
    return new Snapshot(this.id, this.db.docs.get(this.path));
  }
}
class FakeDb {
  docs = new Map();
  versions = new Map();
  transactions = 0;
  fail = false;
  collection(name) {
    return { doc: (id) => new Ref(this, `${name}/${id}`) };
  }
  async runTransaction(fn, options) {
    if (this.fail) throw new Error('synthetic database failure');
    for (let attempt = 0; attempt < options.maxAttempts; attempt += 1) {
      this.transactions += 1;
      const reads = new Map();
      const writes = [];
      const tx = {
        get: async (ref) => {
          await null;
          reads.set(ref.path, this.versions.get(ref.path) ?? 0);
          return new Snapshot(ref.id, this.docs.get(ref.path));
        },
        set: (ref, data) => writes.push(['set', ref.path, structuredClone(data)]),
        create: (ref, data) => writes.push(['create', ref.path, structuredClone(data)]),
        update: (ref, data) => writes.push(['update', ref.path, structuredClone(data)]),
      };
      const result = await fn(tx);
      await null;
      const stale = [...reads].some(([path, version]) => (this.versions.get(path) ?? 0) !== version);
      if (stale || writes.some(([kind, path]) => kind === 'create' && this.docs.has(path))) continue;
      for (const [kind, path, data] of writes) {
        this.docs.set(path, kind === 'update' ? { ...this.docs.get(path), ...data } : data);
        this.versions.set(path, (this.versions.get(path) ?? 0) + 1);
      }
      return result;
    }
    throw new Error('synthetic transaction aborted');
  }
}

function gaxPromise(produce) {
  const promise = produce();
  Object.defineProperty(promise, 'cancel', { value: () => {}, writable: true, configurable: true, enumerable: false });
  return promise;
}

// ---- 合成の配置・本人・Secret・HTTP ----

const PROJECT_ID = 'synthetic-project';
const PROJECT_NUMBER = '123456';
const SECRET = `projects/${PROJECT_NUMBER}/secrets/synthetic-payload-protection`;

function world({ encryption = true } = {}) {
  const db = new FakeDb();
  const clock = { t: T0, now() { return this.t; } };
  const deployment = {
    projectId: PROJECT_ID,
    projectNumber: PROJECT_NUMBER,
    databaseId: '(default)',
    connectNamespace: `t256_${randomUUID()}`,
    deliveryNamespace: `t270_${randomUUID()}`,
    payloadEncryption: encryption
      ? { mode: 'jwe-rsa-oaep-256-a256gcm-v1', namespace: `t280_${randomUUID()}`, secret: SECRET, writeSecretVersion: 1, readSecretVersions: [1] }
      : 'off',
  };
  const hasher = createHmacHasher(randomBytes(32));
  const secretValue = randomBytes(32).toString('base64url');
  const secret = { calls: [], fail: false };
  const secretClient = {
    innerApiCalls: {
      accessSecretVersion: (request) => {
        secret.calls.push(request.name);
        if (secret.fail) return gaxPromise(() => Promise.reject(new Error('synthetic secret failure SECRET-DETAIL')));
        const data = Uint8Array.from(Buffer.from(secretValue, 'latin1'));
        return gaxPromise(() => Promise.resolve([{ name: request.name, payload: { data, dataCrc32c: crc32c(data) } }]));
      },
    },
  };
  const runtime = createEncryptionKeyRuntime({ db, secretClient, deployment, hasher, clock });
  const tokens = new Map();
  const identity = {
    projectId: PROJECT_ID,
    async verifyIdToken(token) {
      const uid = tokens.get(token);
      if (uid === undefined) throw new Error('bad token');
      return { projectId: PROJECT_ID, uid, authTimeSec: Math.floor(T0 / 1000) };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const commands = { posts: 0 };
  const service = {
    async post() {
      commands.posts += 1;
      return { status: 200, body: { commandId: randomUUID(), state: 'delivered' } };
    },
    async get() {
      return { status: 404, body: { error: { code: 'not_found', retryable: false } } };
    },
    async cancel() {
      return { status: 404, body: { error: { code: 'not_found', retryable: false } } };
    },
  };
  const lifetime = new AbortController();
  const logs = [];
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async () => 'owner-plain',
    service,
    clock,
    log: (entry) => logs.push(entry),
    lifetime: lifetime.signal,
    ingress: () => ({ receivedAt: clock.t, deadlineAt: clock.t + 20_000, signal: new AbortController().signal }),
    ...(runtime !== null ? { encryptionKeys: runtime.endpoint } : {}),
  });
  const connect = `sttdConnect/${deployment.connectNamespace}`;
  const enroll = (uid, { access = 'active', owner = true } = {}) => {
    const identityHash = connectIdentityHash(hasher, deployment.connectNamespace, { projectId: PROJECT_ID, uid });
    db.docs.set(`${connect}/access/${identityHash}`, { version: 1, state: access, generation: randomUUID(), updatedAt: T0 });
    if (owner) {
      const ownerId = randomUUID();
      db.docs.set(`${connect}/identities/${identityHash}`, { ownerId, createdAt: T0 });
      db.docs.set(`${connect}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: T0, lastActiveAt: T0, revokedAt: null });
    }
    const token = `tok.${randomBytes(12).toString('base64url')}.sig`;
    tokens.set(token, uid);
    return { token, identityHash };
  };
  const rings = () => [...db.docs].filter(([path]) => path.includes('/rings/'));
  return { db, clock, runtime, handler, enroll, rings, secret, commands, logs, lifetime, deployment };
}

const servers = [];
async function serve(handler) {
  const server = createServer((req, res) => void handler(req, res));
  servers.push(server);
  await new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  return server.address().port;
}
function request(port, method, path, { token, headers = [], body = '' } = {}) {
  const lines = [`${method} ${path} HTTP/1.1`, 'Host: 127.0.0.1', ...(token ? [`Authorization: Bearer ${token}`] : []), ...headers.map(([k, v]) => `${k}: ${v}`), 'Connection: close'];
  if (body.length > 0 || method === 'POST') lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const chunks = [];
    const timer = setTimeout(() => socket.destroy(), 15_000);
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => {
      clearTimeout(timer);
      const all = Buffer.concat(chunks).toString('utf8');
      const split = all.indexOf('\r\n\r\n');
      const head = all.slice(0, split).split('\r\n');
      const headers = Object.fromEntries(head.slice(1).map((line) => [line.slice(0, line.indexOf(':')).toLowerCase(), line.slice(line.indexOf(':') + 1).trim()]));
      let json = null;
      try {
        json = JSON.parse(all.slice(split + 4));
      } catch {
        json = null;
      }
      resolve({ status: Number(head[0]?.split(' ')[1]), headers, json, raw: all });
    });
    socket.write(`${lines.join('\r\n')}\r\n\r\n${body}`);
  });
}
const KEY_PATH = '/v2/encryption-key';

after(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('P01/P02/P03/P12: 公開8項目だけ、同UIDは同じ鍵、並行GETは収束、cache後の再取得で回転0', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const b = w.enroll('synthetic-uid-b');
  // P03: 同UIDの並行GET（初回）。
  const [x, y] = await Promise.all([request(port, 'GET', KEY_PATH, { token: a.token }), request(port, 'GET', KEY_PATH, { token: a.token })]);
  assert.equal(x.status, 200);
  assert.deepEqual(y.json, x.json);
  assert.equal(w.rings().length, 1);
  // P01: 公開の形だけ。
  assert.deepEqual(Object.keys(x.json).sort(), ['alg', 'createdAt', 'enc', 'kid', 'publicJwk', 'publicKeySpki', 'scope', 'version']);
  assert.deepEqual(Object.keys(x.json.publicJwk).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
  assert.equal(x.json.alg, 'RSA-OAEP-256');
  assert.equal(x.json.enc, 'A256GCM');
  assert.equal(x.json.createdAt, new Date(T0).toISOString());
  assert.equal(x.headers['cache-control'], 'no-store');
  const ring = w.rings()[0][1];
  for (const hidden of ['synthetic-uid-a', ring.ownerId, ring.identityHash, SECRET, ring.keys[0].wrappedPrivateKey.slice(0, 40)]) assert.ok(!x.raw.includes(hidden));
  // P02: 2つ目のclientの再取得は同じ結果で、Secret読取りは初回の1回だけ。
  const reads = w.secret.calls.length;
  const again = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.deepEqual(again.json, x.json);
  assert.equal(w.secret.calls.length, reads);
  const other = await request(port, 'GET', KEY_PATH, { token: b.token });
  assert.equal(other.status, 200);
  assert.notEqual(other.json.kid, x.json.kid);
  assert.notEqual(other.json.scope, x.json.scope);
  // P12: clientのcache（最大5分）を過ぎた再取得でも鍵は回転しない。
  const generation = w.rings()[0][1].generation;
  w.clock.t += 6 * 60_000;
  const later = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.deepEqual(later.json, x.json);
  assert.equal(w.rings()[0][1].generation, generation);
  assert.ok(!w.logs.some((entry) => JSON.stringify(entry).includes('synthetic-uid')));
});

test('P04/P05/P06/P07: 未認証・他UIDの自己申告・owner未作成・停止・ring 90日', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const b = w.enroll('synthetic-uid-b');
  // P04: Bearer無し・不正tokenは401で鍵service・DB・Secret 0。
  assert.equal((await request(port, 'GET', KEY_PATH)).status, 401);
  assert.equal((await request(port, 'GET', KEY_PATH, { headers: [['Authorization', 'Basic synthetic']] })).status, 401);
  assert.equal(w.db.transactions + w.secret.calls.length, 0);
  // P05: queryでの他UID指定・GETの本文は400（鍵service 0）。独自headerは無視して本人の鍵だけ。
  assert.equal((await request(port, 'GET', `${KEY_PATH}?uid=synthetic-uid-b`, { token: a.token })).status, 400);
  assert.equal((await request(port, 'GET', KEY_PATH, { token: a.token, headers: [['Content-Type', 'application/json']], body: '{"uid":"synthetic-uid-b"}' })).status, 400);
  assert.equal(w.db.transactions, 0);
  const own = await request(port, 'GET', KEY_PATH, { token: a.token, headers: [['X-Uid', 'synthetic-uid-b'], ['X-Owner-Id', 'other']] });
  const theirs = await request(port, 'GET', KEY_PATH, { token: b.token });
  assert.notEqual(own.json.kid, theirs.json.kid);
  assert.equal(w.rings().length, 2);
  assert.equal((await request(port, 'POST', KEY_PATH, { token: a.token })).status, 405);
  // P06: owner未作成は409、文書の作成0。
  const none = w.enroll('synthetic-uid-none', { owner: false });
  const off = w.enroll('synthetic-uid-disabled', { access: 'disabled' });
  const docs = w.db.docs.size;
  const missing = await request(port, 'GET', KEY_PATH, { token: none.token });
  assert.equal(missing.status, 409);
  assert.equal(missing.json.error.code, 'connection_required');
  // P07: 許可disabledは403、ringの90日無使用は409 encryption_key_unavailable（再初期化0）。
  const denied = await request(port, 'GET', KEY_PATH, { token: off.token });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.error.code, 'access_denied');
  assert.equal(w.db.docs.size, docs);
  const ringPath = w.rings()[0][0];
  const ringA = w.db.docs.get(ringPath);
  w.db.docs.set(ringPath, { ...ringA, lastUsedAt: T0 - 91 * DAY, createdAt: T0 - 91 * DAY, updatedAt: T0 - 91 * DAY });
  const ownerPaths = [...w.db.docs.keys()].filter((path) => path.includes('/owners/'));
  for (const path of ownerPaths) w.db.docs.set(path, { ...w.db.docs.get(path), lastActiveAt: T0 });
  const expired = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.equal(expired.status, 409);
  assert.equal(expired.json.error.code, 'encryption_key_unavailable');
  assert.equal(w.db.docs.get(ringPath).keys[0].kid, ringA.keys[0].kid);
  assert.equal(w.db.docs.get(ringPath).lastUsedAt, T0 - 91 * DAY);
});

test('P08: offは404でruntimeはnull（専用Secretのclientに触れない）', async () => {
  let touched = 0;
  const trap = new Proxy({}, { get: () => ((touched += 1), undefined), getOwnPropertyDescriptor: () => ((touched += 1), undefined) });
  assert.equal(
    createEncryptionKeyRuntime({ db: trap, secretClient: trap, deployment: { projectId: PROJECT_ID, projectNumber: PROJECT_NUMBER, databaseId: '(default)', connectNamespace: 't256_x', deliveryNamespace: 't270_x', payloadEncryption: 'off' }, hasher: trap, clock: trap }),
    null,
  );
  assert.equal(touched, 0);
  const w = world({ encryption: false });
  assert.equal(w.runtime, null);
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-off');
  const got = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.equal(got.status, 404);
  assert.equal(w.db.transactions + w.secret.calls.length, 0);
});

test('P09/P10/P11: Secret障害は503で平文POSTは成功、DB障害は503、取得rateは429', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-faults');
  w.secret.fail = true;
  const failed = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.equal(failed.status, 503);
  assert.equal(failed.json.error.code, 'temporarily_unavailable');
  assert.ok(!failed.raw.includes('SECRET-DETAIL') && !failed.raw.includes(SECRET));
  assert.equal(w.rings().length, 0);
  const commandId = randomUUID();
  const plain = await request(port, 'POST', '/v2/commands', { token: a.token, headers: [['Content-Type', 'application/json'], ['Idempotency-Key', commandId]], body: '{"schemaVersion":2}' });
  assert.equal(plain.status, 200);
  assert.equal(w.commands.posts, 1);
  w.secret.fail = false;

  // P10: DB障害。
  w.db.fail = true;
  assert.equal((await request(port, 'GET', KEY_PATH, { token: a.token })).status, 503);
  w.db.fail = false;

  // P11: 取得rate（分60）。現在の窓を上限まで使った状態にする。
  assert.equal((await request(port, 'GET', KEY_PATH, { token: a.token })).status, 200);
  const controlsPath = [...w.db.docs.keys()].find((path) => path.includes('/controls/'));
  const controls = w.db.docs.get(controlsPath);
  w.db.docs.set(controlsPath, { ...controls, windows: { ...controls.windows, fetch: { ...controls.windows.fetch, minuteCount: 60 } } });
  const limited = await request(port, 'GET', KEY_PATH, { token: a.token });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers['retry-after'], '30');
  assert.equal(limited.json.error.code, 'rate_limited');
});

test('R: runtimeは起動時の専用Secret読取り0、初期化時だけ読み、dispose後は読まない', async () => {
  const w = world();
  assert.equal(w.secret.calls.length, 0);
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-runtime');
  const b = w.enroll('synthetic-uid-runtime-b');
  assert.equal((await request(port, 'GET', KEY_PATH, { token: a.token })).status, 200);
  assert.deepEqual(w.secret.calls, [`${SECRET}/versions/1`]);
  w.runtime.dispose();
  const after = await request(port, 'GET', KEY_PATH, { token: b.token });
  assert.equal(after.status, 503);
  assert.equal(w.secret.calls.length, 1);
  assert.equal(w.rings().length, 1);
});
