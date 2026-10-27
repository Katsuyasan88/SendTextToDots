// 送信APIの配送: HTTP入口（dist/delivery/api.jsのcreateIngressOperationDeliveryRequestHandler）とKMS配送service（dist/delivery/kms-service.jsの
// KmsRequestDeliveryService）を、127.0.0.1の所有HTTP server・生のHTTP/1.1 socket・模擬identity/findOwner・模擬store/codec/send・制御した時計で
// 確かめる。確かめる点: 単回送出（同じIDの再送0）、元期限＝min(受信+20秒, 親)、中断の伝播と送らない結果の記録、送出中の中断はdelivery_unknown
// （再送0）、ingress・時計の不正は固定503、dispose後の新規処理0。実SDK・Firestore・KMS・TLS・外部callback・子process 0。
// 模擬sendの成功を、実際の署名・TLS・DBでの成功とはしない。出力は試験名・結果・件数だけ。
// V01〜V06（0.3.0の契約）は、本番の入力検証（validateCommandInput）・canonical・buildEventBytes/eventIdFor・署名（signCommandBodyと
// standardwebhooksの検証）と、本番の純粋な判定（delivery/contract.jsのdecidePrepare/decideDispatch/decideFinish/decideAbandon/decideCancel・
// authorize・保存serializerのcommandDocData/parseCommandDoc）をRAMのMapに載せた合成storeで、本文・冪等性・owner・認可・期限・件数・取消を確かめる。
// 合成storeはFirestoreのtransaction・SDKの代わりで、その保存・競合の実挙動を確かめるものではない。本文は全て合成の試験文。
// 本文・秘密の非記録は、JSONの表記ではなく観測値の文字列値・keyを再帰に走査して確かめる（containsText。V07が検出の正例）。
import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { createServer } from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { Webhook } from 'standardwebhooks';

import { CommandApiError } from '../dist/commands/errors.js';
import { resolveNewCommandExpiry, validateCommandInput } from '../dist/commands/input.js';
import { createIngressOperationDeliveryRequestHandler, DeliveryIngressConfigError } from '../dist/delivery/api.js';
import {
  commandDocData,
  decideAbandon,
  decideCancel,
  decideDispatch,
  decideFinish,
  decidePrepare,
  ownerControlData,
  parseCommandDoc,
  parseOwnerControl,
  usable,
} from '../dist/delivery/contract.js';
import { buildEventBytes, eventIdFor } from '../dist/delivery/event.js';
import { KmsRequestDeliveryService } from '../dist/delivery/kms-service.js';
import { EVENT_NAME } from '../dist/events/contract.js';
import { signCommandBody } from '../dist/events/signing.js';
import { createFirebaseAdminVerifier } from '../dist/identity/firebase.js';

const BASE = 1_900_000_000_000;
const HTTP_LIMIT = 110;
const DB_LIMIT = 500;
const KMS_LIMIT = 200;
const SEND_LIMIT = 60;
const TOKEN = `tok.${randomBytes(12).toString('base64url')}.sig`;
const OWNER = `owner-${randomUUID()}`;

let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
const timeouts = () => process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
const baselineTimeouts = timeouts();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tick = () => new Promise((resolve) => setImmediate(resolve));

function gate() {
  let release;
  let reached;
  const whenReached = new Promise((resolve) => {
    reached = resolve;
  });
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, reached: () => reached(), release: (value) => release(value), whenReached };
}

// ---------- 制御した時計 ----------
const clockState = { value: BASE, mode: 'ok' };
const clock = {
  now() {
    if (clockState.mode === 'throw') throw new Error('clock failure');
    if (clockState.mode === 'nan') return Number.NaN;
    if (clockState.mode === 'negative') return -1;
    if (clockState.mode === 'huge') return 8_640_000_000_000_000;
    return clockState.value;
  },
};

// ---------- 計数 ----------
const counts = { http: 0, verify: 0, findOwner: 0, servicePost: 0, serviceGet: 0, serviceCancel: 0, db: 0, kms: 0, send: 0 };
const logs = [];
const log = (entry) => logs.push(entry);
/** 通常logへ出てはならない合成の本文（終了時にlogsの全項目と照合する）。 */
const BODY_TEXTS = new Set(['hello from delivery']);

/**
 * 観測値（object・配列・Map・Set・Buffer・文字列）を再帰に走査し、いずれかの文字列値・keyがneedleを含むか。
 * JSON.stringifyの結果と比べないので、改行・quote・backslashを含む本文もescape表記に関わらず検出する。
 */
function containsText(value, needle, seen = new Set()) {
  if (typeof value === 'string') return value.includes(needle);
  if (Buffer.isBuffer(value)) return value.toString('utf8').includes(needle);
  if (typeof value !== 'object' || value === null || seen.has(value)) return false;
  seen.add(value);
  const inner = value instanceof Map ? [...value.entries()].flat() : value instanceof Set ? [...value] : Object.entries(value).flat();
  return inner.some((item) => containsText(item, needle, seen));
}
/** 通常logの1項目がtoken・合成本文・callback URLのhostを含むか。 */
const leaksInLog = (entry) => [TOKEN, ...BODY_TEXTS, 'receiver.example'].some((needle) => containsText(entry, needle));

// ---------- 模擬identity/findOwner（gateで保持できる） ----------
const identityControl = { hold: null, mode: 'ok' };
const identity = {
  projectId: 'demo-sttd-delivery',
  async verifyIdToken(token) {
    counts.verify += 1;
    const hold = identityControl.hold;
    if (hold) {
      identityControl.hold = null;
      hold.reached();
      await hold.promise;
    }
    if (identityControl.mode === 'fail') throw new Error('identity rejected');
    if (token !== TOKEN) throw new Error('bad token');
    return { projectId: 'demo-sttd-delivery', uid: 'apple-uid-delivery', authTimeSec: Math.floor(BASE / 1000) };
  },
  async accountStatus() {
    return 'active';
  },
};
const findOwner = async () => {
  counts.findOwner += 1;
  return OWNER;
};

// ---------- 生のHTTP/1.1（所有socket） ----------
const sockets = new Set();
const servers = new Set();
/** prepareは同期の観測（listener追加）か、Promise（frameworkのrawBodyを模して本文を読み終えてから渡す）。 */
function startServer(handler, prepare = () => {}) {
  const server = createServer((req, res) => {
    const before = prepare(req);
    if (before instanceof Promise) void before.then(() => handler(req, res));
    else void handler(req, res);
  });
  servers.add(server);
  return new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, () => resolve({ server, port: server.address().port })));
}
const closeServer = (server) =>
  new Promise((resolve) => {
    servers.delete(server);
    server.close(() => resolve());
    server.closeAllConnections();
  });
/** 要求を送る。partialなら本文の一部だけを送り、socketを返す（呼出し側が壊す）。 */
function send(port, method, path, { headers = [], body = '', partial = null } = {}) {
  counts.http += 1;
  assert.ok(counts.http <= HTTP_LIMIT, 'HTTP budget');
  const lines = [`${method} ${path} HTTP/1.1`, 'Host: 127.0.0.1', ...headers.map(([k, v]) => `${k}: ${v}`), 'Connection: close'];
  const length = partial === null ? Buffer.byteLength(body) : partial.declared;
  if (length > 0 || method === 'POST') lines.push(`Content-Length: ${length}`);
  const socket = net.connect({ host: '127.0.0.1', port });
  sockets.add(socket);
  const chunks = [];
  const done = new Promise((resolve) => {
    const timer = setTimeout(() => socket.destroy(), 15_000);
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', () => {});
    socket.on('close', () => {
      clearTimeout(timer);
      sockets.delete(socket);
      const all = Buffer.concat(chunks).toString('utf8');
      const split = all.indexOf('\r\n\r\n');
      if (split < 0) return resolve({ status: null, json: null });
      const status = Number(all.split('\r\n')[0].split(' ')[1]);
      let json = null;
      try {
        json = JSON.parse(all.slice(split + 4));
      } catch {
        json = null;
      }
      resolve({ status, json });
    });
  });
  socket.write(`${lines.join('\r\n')}\r\n\r\n${partial === null ? body : partial.sent}`);
  return { socket, done };
}
const auth = [['Authorization', `Bearer ${TOKEN}`]];
const json = [['Content-Type', 'application/json']];

const iso = (ms) => new Date(ms).toISOString();
function commandBody(commandId) {
  return JSON.stringify({
    schemaVersion: 2,
    commandId,
    text: 'hello from delivery',
    createdAt: iso(BASE),
    expiresAt: iso(BASE + 60_000),
  });
}

after(async () => {
  for (const socket of sockets) socket.destroy();
  for (const server of [...servers]) await closeServer(server);
  await sleep(30);
  const leaked = logs.filter(leaksInLog).length;
  process.stdout.write(
    `# DELIVERY_COUNTS http=${counts.http} verify=${counts.verify} findOwner=${counts.findOwner} servicePost=${counts.servicePost} serviceGet=${counts.serviceGet} serviceCancel=${counts.serviceCancel} db=${counts.db} kms=${counts.kms} send=${counts.send} logs=${logs.length} leaked=${leaked} unhandled=${unhandled} timeouts=${timeouts() - baselineTimeouts}\n`,
  );
  assert.ok(counts.http <= HTTP_LIMIT);
  assert.ok(counts.db <= DB_LIMIT);
  assert.ok(counts.kms <= KMS_LIMIT);
  assert.ok(counts.send <= SEND_LIMIT);
  assert.equal(leaked, 0, 'no token/body/url in logs');
  assert.ok(logs.every((entry) => Object.keys(entry).every((key) => ['event', 'route', 'status', 'state', 'code', 'outcome', 'reason', 'step', 'stopSubscription'].includes(key))), 'fixed log fields');
  assert.equal(unhandled, 0);
  assert.equal(timeouts(), baselineTimeouts, 'no owned timer left');
});

// =====================================================================================================
// KMS配送service（parentOperation・単回送出・中断・不明）
// =====================================================================================================

const DIGEST_KEY = randomBytes(32);
const HASH_KEY = randomBytes(32);
const hash = (purpose, value) => createHmac('sha256', HASH_KEY).update(purpose).update('\0').update(value).digest('hex');
const URL_TEXT = 'https://receiver.example/hook';
const SECRET_TEXT = `whsec_${randomBytes(32).toString('base64')}`;

function kmsFixture() {
  const lifetime = new AbortController();
  const calls = { prepare: [], dispatch: [], finish: [], abandon: [], read: [], cancel: [], open: [], send: [], attempts: 0 };
  const control = { prepareHold: null, openHold: null, dispatchHold: null, sendHold: null, sendMode: 'delivered' };
  const docFor = (ownerId, attemptId, receivedAt) => ({
    version: 1,
    ownerId,
    tombstone: false,
    digest: 'd'.repeat(64),
    state: 'prepared',
    reason: null,
    attemptId,
    destination: { subscriptionId: 'sub_delivery', grantId: 'grant_delivery', secretHash: 'h'.repeat(64) },
    receivedAt,
    expiresAt: receivedAt + 60_000,
    deadlineAt: receivedAt + 20_000,
    updatedAt: receivedAt,
    acknowledgedAt: null,
    purgeAt: receivedAt + 86_400_000,
  });
  /** signalの中止でrejectする保持（実storeの境界と同じ: 中止なら待つのをやめる）。 */
  const held = (hold, signal, value) =>
    new Promise((resolve, reject) => {
      const onAbort = () => reject(new Error('aborted'));
      signal?.addEventListener('abort', onAbort, { once: true });
      hold.reached();
      hold.promise.then(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve(value());
      });
    });
  const store = {
    commandKey: (ownerId, commandId) => hash('command', `${ownerId}\0${commandId}`),
    async prepare(input, operation) {
      counts.db += 1;
      calls.prepare.push({ input, operation });
      const decision = () => ({ kind: 'prepared', doc: docFor(input.ownerId, input.attemptId, input.receivedAt), sealedUrl: 'capsule-url', sealedSecret: 'capsule-secret', previous: null });
      const hold = control.prepareHold;
      if (hold) {
        control.prepareHold = null;
        return held(hold, operation.signal, decision);
      }
      return decision();
    },
    async dispatch(ownerId, commandKey, attemptId, evidence, operation) {
      counts.db += 1;
      calls.dispatch.push({ operation });
      const decision = () => ({ kind: 'granted', doc: { ...docFor(ownerId, attemptId, BASE), state: 'dispatching' }, previousValid: false });
      const hold = control.dispatchHold;
      if (hold) {
        // 送出権の確定は中止を見ずに戻る（commitは既に起きた形）。
        control.dispatchHold = null;
        hold.reached();
        await hold.promise;
      }
      return decision();
    },
    async finish(ownerId, commandKey, attemptId, state, reason, stop, operation) {
      counts.db += 1;
      calls.finish.push({ state, reason, operation });
      return { ...docFor(ownerId, attemptId, BASE), state, reason, acknowledgedAt: state === 'delivered' ? BASE : null };
    },
    async abandon(ownerId, commandKey, attemptId, reason, operation) {
      counts.db += 1;
      calls.abandon.push({ reason, operation });
      return { ...docFor(ownerId, attemptId, BASE), state: 'failed', reason };
    },
    async read(ownerId, commandKey, operation) {
      counts.db += 1;
      calls.read.push({ operation, listenersDuring: getEventListeners(operation.signal, 'abort').length });
      return { ...docFor(ownerId, 'a', BASE), state: 'delivered', acknowledgedAt: BASE };
    },
    async cancel(ownerId, commandKey, operation) {
      counts.db += 1;
      calls.cancel.push({ operation });
      return { kind: 'observed', doc: { ...docFor(ownerId, 'a', BASE), state: 'delivered', acknowledgedAt: BASE } };
    },
  };
  const codec = {
    async open(binding, capsule, operation) {
      counts.kms += 1;
      calls.open.push({ binding: binding.purpose, operation });
      const value = () => Buffer.from(binding.purpose === 'callback-url' ? URL_TEXT : SECRET_TEXT, 'utf8');
      const hold = control.openHold;
      if (hold) {
        control.openHold = null;
        return held(hold, operation.signal, value);
      }
      return value();
    },
  };
  const sendFn = async (request) => {
    counts.send += 1;
    calls.send.push({ leaseUntil: request.leaseUntil, signal: request.signal });
    const hold = control.sendHold;
    if (hold) {
      control.sendHold = null;
      hold.reached();
      await hold.promise;
      if (control.sendMode === 'reject') throw new Error('socket reset');
    }
    return { kind: 'delivered', reason: 'acknowledged', stopSubscription: false };
  };
  const service = new KmsRequestDeliveryService({
    store,
    codec,
    hash,
    digestKey: DIGEST_KEY,
    send: sendFn,
    clock,
    newAttemptId: () => ((calls.attempts += 1), `attempt-${calls.attempts}`),
    log,
    budgetMs: 20_000,
    lifetime: lifetime.signal,
    hooks: {},
  });
  return { service, calls, control, lifetime };
}
const parentOf = (deadlineAt, signal = new AbortController().signal) => Object.freeze({ deadlineAt, signal });
const post = (fx, parent, commandId = randomUUID()) => fx.service.post(OWNER, commandId, Buffer.from(commandBody(commandId)), BASE, ...(parent === undefined ? [] : [parent]));

test('K01 invalid parentOperation (Proxy / accessor / extra / missing or non-AbortSignal signal / non-integer deadline) -> 503 before prepare/attempt id; get/cancel too', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const signal = new AbortController().signal;
  const accessor = {};
  Object.defineProperty(accessor, 'deadlineAt', { enumerable: true, get: () => BASE + 10_000 });
  Object.defineProperty(accessor, 'signal', { enumerable: true, value: signal });
  const invalids = [
    new Proxy({ deadlineAt: BASE + 10_000, signal }, {}),
    accessor,
    { deadlineAt: BASE + 10_000, signal, extra: 1 },
    { deadlineAt: BASE + 10_000 },
    { deadlineAt: BASE + 10_000, signal: { aborted: false, addEventListener() {}, removeEventListener() {} } },
    { deadlineAt: BASE + 10_000.5, signal },
    { deadlineAt: '1', signal },
    null,
  ];
  for (const parent of invalids) {
    const result = await fx.service.post(OWNER, randomUUID(), Buffer.from('{}'), BASE, parent);
    assert.equal(result.status, 503);
    assert.equal((await fx.service.get(OWNER, randomUUID(), BASE, parent)).status, 503);
    assert.equal((await fx.service.cancel(OWNER, randomUUID(), BASE, parent)).status, 503);
  }
  assert.deepEqual([fx.calls.prepare.length, fx.calls.read.length, fx.calls.cancel.length, fx.calls.attempts], [0, 0, 0, 0]);
});

test('K02 started abort / expired parent -> 503 before prepare/read/cancel/attempt id', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const aborted = new AbortController();
  aborted.abort();
  for (const parent of [parentOf(BASE + 15_000, aborted.signal), parentOf(BASE), parentOf(BASE - 1)]) {
    assert.equal((await post(fx, parent)).status, 503);
    assert.equal((await fx.service.get(OWNER, randomUUID(), BASE, parent)).status, 503);
    assert.equal((await fx.service.cancel(OWNER, randomUUID(), BASE, parent)).status, 503);
  }
  assert.deepEqual([fx.calls.prepare.length, fx.calls.read.length, fx.calls.cancel.length, fx.calls.attempts], [0, 0, 0, 0]);
});

test('K03 deadline = min(received+20s, parent.deadlineAt): shortened parent reaches prepare/open/dispatch/send; a later parent never extends; omitted parent unchanged', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const parent = parentOf(BASE + 15_000);
  const result = await post(fx, parent);
  assert.equal(result.status, 200);
  assert.equal(result.body.state, 'delivered');
  assert.equal(fx.calls.prepare[0].operation.deadlineAt, BASE + 15_000);
  assert.ok(fx.calls.open.every((entry) => entry.operation.deadlineAt <= BASE + 15_000));
  assert.equal(fx.calls.dispatch[0].operation.deadlineAt, BASE + 15_000);
  assert.ok(fx.calls.send[0].leaseUntil <= BASE + 15_000);
  assert.notEqual(fx.calls.prepare[0].operation.signal, parent.signal, 'own joined controller');
  assert.notEqual(fx.calls.prepare[0].operation.signal, fx.lifetime.signal);
  // abandon/finishの結果保存はlifetimeのまま。
  assert.equal(fx.calls.finish[0].operation.signal, fx.lifetime.signal);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0, 'parent listener released');

  const later = await post(fx, parentOf(BASE + 60_000));
  assert.equal(later.status, 200);
  assert.equal(fx.calls.prepare[1].operation.deadlineAt, BASE + 20_000, 'never extended');

  const omitted = await post(fx, undefined);
  assert.equal(omitted.status, 200);
  assert.equal(fx.calls.prepare[2].operation.deadlineAt, BASE + 20_000, 'omitted call: old 20s');
  assert.equal((await fx.service.get(OWNER, randomUUID(), BASE)).status, 200);
  assert.equal(fx.calls.read.at(-1).operation.signal, fx.lifetime.signal, 'omitted get keeps the lifetime signal');
  assert.equal(fx.calls.read.at(-1).operation.deadlineAt, BASE + 20_000);
  assert.equal(getEventListeners(fx.lifetime.signal, 'abort').length, 0, 'lifetime listeners released');
});

test('K04 parent abort while prepare waits / while opening / after dispatch before send -> no new open/dispatch/send; not-sent results recorded with lifetime', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  for (const stage of ['prepare', 'open', 'dispatch']) {
    const fx = kmsFixture();
    const parent = new AbortController();
    const hold = gate();
    fx.control[`${stage}Hold`] = hold;
    const pending = post(fx, parentOf(BASE + 15_000, parent.signal));
    await hold.whenReached;
    parent.abort();
    if (stage === 'dispatch') hold.release();
    const result = await pending;
    if (stage !== 'dispatch') hold.release();
    await tick();
    assert.equal(fx.calls.send.length, 0, `${stage}: never sent`);
    if (stage === 'prepare') {
      assert.equal(result.status, 503, 'prepare unknown -> 503, nothing opened');
      assert.equal(fx.calls.open.length, 0);
    } else {
      assert.equal(result.status, 200);
      assert.equal(result.body.state, 'failed', `${stage}: not sent`);
      assert.equal(fx.calls.abandon.length, 1);
      assert.equal(fx.calls.abandon[0].operation.signal, fx.lifetime.signal, 'abandon uses lifetime (record only)');
      assert.ok(fx.calls.abandon[0].operation.deadlineAt <= BASE + 15_000, 'within the original short deadline');
      if (stage === 'open') assert.equal(fx.calls.dispatch.length, 0, 'no dispatch after the abort');
    }
    assert.equal(getEventListeners(parent.signal, 'abort').length, 0, `${stage}: parent listener released`);
    assert.equal(getEventListeners(fx.lifetime.signal, 'abort').length, 0);
  }
});

test('K05 parent abort during send: the abort reaches the send signal once, ambiguous result stays delivery_unknown (no retry/duplicate)', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const parent = new AbortController();
  const hold = gate();
  fx.control.sendHold = hold;
  fx.control.sendMode = 'reject';
  const pending = post(fx, parentOf(BASE + 15_000, parent.signal));
  await hold.whenReached;
  const sendSignal = fx.calls.send[0].signal;
  assert.equal(sendSignal.aborted, false);
  parent.abort();
  assert.equal(sendSignal.aborted, true, 'parent abort propagated to the in-flight send');
  hold.release();
  const result = await pending;
  assert.equal(result.status, 200);
  assert.equal(result.body.state, 'delivery_unknown');
  assert.equal(fx.calls.send.length, 1, 'no duplicate send');
  assert.equal(fx.calls.finish[0].state, 'delivery_unknown');
  assert.equal(fx.calls.finish[0].operation.signal, fx.lifetime.signal);
});

test('K06 get/cancel with parent: joined per-request signal reaches the store, parent abort aborts it, listeners released; a parent abort does not touch another command; dispose stops new work', { timeout: 10_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const parent = new AbortController();
  assert.equal((await fx.service.get(OWNER, randomUUID(), BASE, parentOf(BASE + 15_000, parent.signal))).status, 200);
  const readOp = fx.calls.read[0].operation;
  assert.notEqual(readOp.signal, fx.lifetime.signal);
  assert.equal(readOp.deadlineAt, BASE + 15_000);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0, 'released after get');
  assert.equal((await fx.service.cancel(OWNER, randomUUID(), BASE, parentOf(BASE + 15_000, parent.signal))).status, 200);
  assert.equal(fx.calls.cancel[0].operation.deadlineAt, BASE + 15_000);
  assert.equal(getEventListeners(parent.signal, 'abort').length, 0, 'released after cancel');

  // 2つのcommand: Aの親の中止はBへ伝わらない。
  const parentA = new AbortController();
  const holdA = gate();
  fx.control.prepareHold = holdA;
  const a = post(fx, parentOf(BASE + 15_000, parentA.signal));
  await holdA.whenReached;
  const b = post(fx, parentOf(BASE + 15_000));
  parentA.abort();
  holdA.release();
  const [resultA, resultB] = await Promise.all([a, b]);
  assert.equal(resultA.status, 503);
  assert.equal(resultB.status, 200);
  assert.equal(resultB.body.state, 'delivered');

  fx.lifetime.abort();
  const sendsBefore = fx.calls.send.length;
  assert.equal((await post(fx, parentOf(BASE + 15_000))).status, 503, 'after dispose');
  assert.equal(fx.calls.send.length, sendsBefore);
});

// =====================================================================================================
// HTTP入口（ingress）＋KMS配送service（模擬store/codec/send）
// =====================================================================================================

/** trustedなentryが要求ごとに渡す元ingress（試験では次の要求の値を先に決める）。 */
const ingressState = { next: null, calls: 0 };
const ingressSource = () => {
  ingressState.calls += 1;
  const value = ingressState.next ?? { receivedAt: clockState.value, deadlineAt: clockState.value + 20_000, signal: new AbortController().signal };
  ingressState.next = null;
  return value;
};

test('I01 HTTP + KMS service: a completed POST delivers once, GET/cancel reach the store, routes/methods/auth keep their fixed 404/405/401, and a client disconnect while the capsule is opening sends nothing', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const handler = createIngressOperationDeliveryRequestHandler({ identity, findOwner, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  // trustedなentryの役（要求ごとの元ingress。接続が切れたら中断する）。
  const { server, port } = await startServer(handler, (req) => {
    const controller = new AbortController();
    req.socket.once('close', () => controller.abort());
    ingressState.next = { receivedAt: clockState.value, deadlineAt: clockState.value + 20_000, signal: controller.signal };
  });
  try {
    const commandId = randomUUID();
    const ok = await send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: commandBody(commandId) }).done;
    assert.equal(ok.status, 200);
    assert.equal(ok.json.state, 'delivered');
    assert.equal(fx.calls.send.length, 1);
    assert.equal(fx.calls.prepare[0].operation.deadlineAt, BASE + 20_000);
    assert.equal((await send(port, 'GET', `/v2/commands/${commandId}`, { headers: auth }).done).status, 200);
    assert.equal((await send(port, 'POST', `/v2/commands/${commandId}/cancel`, { headers: auth }).done).status, 200);
    assert.equal((await send(port, 'GET', '/v2/other', { headers: auth }).done).status, 404);
    assert.equal((await send(port, 'GET', '/v2/commands', { headers: auth }).done).status, 405);
    const before = counts.verify;
    assert.equal((await send(port, 'POST', '/v2/commands', { headers: [...json, ['Idempotency-Key', commandId]], body: commandBody(commandId) }).done).status, 401);
    assert.equal(counts.verify, before, 'no identity call without a Bearer token');

    const hold = gate();
    fx.control.openHold = hold;
    const second = randomUUID();
    const request = send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', second]], body: commandBody(second) });
    await hold.whenReached;
    request.socket.destroy();
    await request.done;
    await sleep(50);
    hold.release();
    await sleep(50);
    assert.equal(fx.calls.send.length, 1, 'no send after the disconnect');
    assert.equal(fx.calls.dispatch.length, 1, 'no new dispatch');
  } finally {
    await closeServer(server);
  }
  assert.equal(getEventListeners(fx.lifetime.signal, 'abort').length, 0);
});

test('I02 invalid or stopped ingress (extended / future / expired / aborted / Proxy) and an invalid clock give the fixed 503 before identity, owner and service; an ingress source that is not a function is a config error', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  assert.throws(() => createIngressOperationDeliveryRequestHandler({ identity, findOwner, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: null }), DeliveryIngressConfigError);
  const handler = createIngressOperationDeliveryRequestHandler({ identity, findOwner, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  const { server, port } = await startServer(handler);
  try {
    const aborted = new AbortController();
    aborted.abort();
    const signal = new AbortController().signal;
    const cases = {
      extended: { receivedAt: BASE, deadlineAt: BASE + 20_001, signal },
      future: { receivedAt: BASE + 5_000, deadlineAt: BASE + 10_000, signal },
      expired: { receivedAt: BASE - 30_000, deadlineAt: BASE - 10_000, signal },
      aborted: { receivedAt: BASE, deadlineAt: BASE + 20_000, signal: aborted.signal },
      proxy: new Proxy({ receivedAt: BASE, deadlineAt: BASE + 20_000, signal }, {}),
    };
    const before = { verify: counts.verify, findOwner: counts.findOwner, prepare: fx.calls.prepare.length };
    for (const [name, value] of Object.entries(cases)) {
      ingressState.next = value;
      const commandId = randomUUID();
      const response = await send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: commandBody(commandId) }).done;
      assert.equal(response.status, 503, name);
      assert.deepEqual(response.json, { error: { code: 'temporarily_unavailable', retryable: true } }, name);
    }
    for (const mode of ['throw', 'nan', 'negative', 'huge']) {
      clockState.mode = mode;
      const commandId = randomUUID();
      const response = await send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: commandBody(commandId) }).done;
      clockState.mode = 'ok';
      assert.equal(response.status, 503, mode);
    }
    assert.deepEqual([counts.verify, counts.findOwner, fx.calls.prepare.length], [before.verify, before.findOwner, before.prepare], 'no identity/owner/service');
  } finally {
    clockState.mode = 'ok';
    await closeServer(server);
  }
});

test('I03 the ingress signal aborted while the service sends: the abort reaches the in-flight send once, the response is not adopted (503), and the ambiguous result stays delivery_unknown without a second send', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = kmsFixture();
  const handler = createIngressOperationDeliveryRequestHandler({ identity, findOwner, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  const { server, port } = await startServer(handler);
  try {
    const parent = new AbortController();
    ingressState.next = { receivedAt: BASE, deadlineAt: BASE + 20_000, signal: parent.signal };
    const hold = gate();
    fx.control.sendHold = hold;
    fx.control.sendMode = 'reject';
    const commandId = randomUUID();
    const pending = send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: commandBody(commandId) }).done;
    await hold.whenReached;
    const sendSignal = fx.calls.send[0].signal;
    parent.abort();
    assert.equal(sendSignal.aborted, true, 'ingress abort propagated to the in-flight send');
    hold.release();
    const response = await pending;
    assert.equal(response.status, 503);
    await sleep(30);
    assert.equal(fx.calls.send.length, 1, 'no duplicate send');
    assert.equal(fx.calls.finish[0].state, 'delivery_unknown');
  } finally {
    await closeServer(server);
  }
  assert.equal(getEventListeners(fx.lifetime.signal, 'abort').length, 0);
});

// =====================================================================================================
// 0.3.0の契約: 本番の入力検証・canonical・event・署名と、本番の純粋な判定を載せた合成store
// =====================================================================================================

const FIELDS = ['schemaVersion', 'commandId', 'text', 'createdAt', 'expiresAt'];
const DATA_FIELDS = ['schemaVersion', 'commandId', 'text', 'expiresAt'];
const EVENT_KEYS = ['eventId', 'name', 'timestamp', 'data', 'cursor'];
const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PREVIOUS_SECRET_TEXT = `whsec_${randomBytes(32).toString('base64')}`;
const CURRENT_HASH = 'c'.repeat(64);
const PREVIOUS_HASH = 'e'.repeat(64);
const rawSecret = (text) => Buffer.from(text.slice('whsec_'.length), 'base64');
const v2 = (overrides = {}) => ({ schemaVersion: 2, commandId: randomUUID(), text: 'hello from delivery', createdAt: iso(BASE), expiresAt: iso(BASE + 60_000), ...overrides });
const bytesOf = (body) => (Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8'));
const allZero = (buffers) => buffers.every((buffer) => buffer.every((byte) => byte === 0));
/** 固定のinvalid_requestだけ（入力の値・causeを持たない）。 */
const isInvalid = (error) => error instanceof CommandApiError && error.code === 'invalid_request' && error.message === 'invalid_request' && error.cause === undefined;
const syntheticText = (text) => {
  BODY_TEXTS.add(text);
  return text;
};

/**
 * 本番の判定（decide*）と保存serializer（commandDocData→parseCommandDoc）をRAMのMapへ載せた合成store。読取り→判定→書込みの順は
 * delivery/kms-store.tsのtransactionの関数と同じで、認可の正本（owner・購読・Grant）は試験が持つ合成の状態から作る。
 */
function decisionFixture() {
  const lifetime = new AbortController();
  const docs = new Map();
  const controls = new Map();
  const owners = new Map();
  const calls = { prepare: 0, dispatch: 0, finish: 0, abandon: 0, read: 0, cancel: 0, open: 0, attempts: 0, sent: [], owned: [], responses: [] };
  const control = { afterOpen: null, sendHold: null, sendResult: null };
  const addOwner = (overrides = {}, ownerId = `owner-${randomUUID()}`) => {
    owners.set(ownerId, { ownerActive: true, grantLive: true, access: 'allowed', pending: false, subscription: true, subscriptionExpiresAt: null, previousUntil: null, ...overrides });
    return ownerId;
  };
  const subscriptionOf = (ownerId) => `sub_${hash('subscription', ownerId)}`;
  const viewOf = (ownerId) => {
    const owner = owners.get(ownerId);
    if (owner === undefined) return { ownerActive: false, subscription: undefined, grantLive: false, access: 'denied' };
    const active = owner.subscription
      ? {
          id: subscriptionOf(ownerId),
          ownerId,
          grantId: `grant-${ownerId}`,
          sealedUrl: 'capsule-url',
          sealedSecret: 'capsule-secret',
          secretHash: CURRENT_HASH,
          previousSecret: owner.previousUntil === null ? null : { sealed: 'capsule-previous', until: owner.previousUntil },
          expiresAt: owner.subscriptionExpiresAt,
        }
      : null;
    return {
      ownerActive: owner.ownerActive,
      grantLive: owner.grantLive,
      access: owner.access,
      subscription: { active, knownDestinationId: active?.id ?? null, pending: owner.pending ? { id: 'sub_pending', grantId: 'grant-pending', requestedAt: BASE } : null, lastEnded: null },
    };
  };
  const load = (ownerId, commandKey) => parseCommandDoc(docs.has(commandKey) ? structuredClone(docs.get(commandKey)) : undefined, ownerId);
  const save = (commandKey, doc) => docs.set(commandKey, structuredClone(commandDocData(doc)));
  const release = (ownerId, commandKey) => {
    const current = parseOwnerControl(controls.get(ownerId), ownerId);
    if (current.current?.commandKey === commandKey) controls.set(ownerId, structuredClone(ownerControlData(ownerId, current.rate, null)));
  };
  const store = {
    commandKey: (ownerId, commandId) => hash('command', `${ownerId}\0${commandId}`),
    async prepare(request) {
      calls.prepare += 1;
      counts.db += 1;
      const now = clock.now();
      const view = viewOf(request.ownerId);
      const decision = decidePrepare(usable(load(request.ownerId, request.commandKey), now), parseOwnerControl(controls.get(request.ownerId), request.ownerId), view, request, now);
      if (decision.kind !== 'prepared') return decision;
      save(request.commandKey, decision.doc);
      controls.set(request.ownerId, structuredClone(decision.control));
      const latest = view.subscription.active.previousSecret;
      const previous = decision.previous === null || latest === null ? null : { sealed: latest.sealed, secretHash: PREVIOUS_HASH, until: latest.until };
      return { kind: 'prepared', doc: decision.doc, sealedUrl: decision.sealedUrl, sealedSecret: decision.sealedSecret, previous };
    },
    async dispatch(ownerId, commandKey, attemptId, evidence) {
      calls.dispatch += 1;
      counts.db += 1;
      const now = clock.now();
      const view = viewOf(ownerId);
      const decision = decideDispatch(load(ownerId, commandKey), view, attemptId, evidence?.sealed ?? null, now);
      if (decision.kind !== 'unchanged') save(commandKey, decision.doc);
      if (decision.kind === 'refused') release(ownerId, commandKey);
      if (decision.kind !== 'granted') return decision;
      const latest = view.subscription?.active?.previousSecret ?? null;
      const previousValid = decision.previousValid && evidence !== null && latest !== null && latest.sealed === evidence.sealed && evidence.secretHash === PREVIOUS_HASH && now < latest.until;
      return { kind: 'granted', doc: decision.doc, previousValid };
    },
    async finish(ownerId, commandKey, attemptId, state, reason) {
      calls.finish += 1;
      counts.db += 1;
      const current = load(ownerId, commandKey);
      const next = decideFinish(current, attemptId, state, reason, clock.now());
      if (next === undefined) return current;
      save(commandKey, next);
      release(ownerId, commandKey);
      return next;
    },
    async abandon(ownerId, commandKey, attemptId, reason) {
      calls.abandon += 1;
      counts.db += 1;
      const current = load(ownerId, commandKey);
      const next = decideAbandon(current, attemptId, reason, clock.now());
      if (next === undefined) return current;
      save(commandKey, next);
      release(ownerId, commandKey);
      return next;
    },
    async read(ownerId, commandKey) {
      calls.read += 1;
      counts.db += 1;
      return usable(load(ownerId, commandKey), clock.now());
    },
    async cancel(ownerId, commandKey) {
      calls.cancel += 1;
      counts.db += 1;
      const now = clock.now();
      const current = load(ownerId, commandKey);
      if (!viewOf(ownerId).ownerActive) return 'denied';
      const decision = decideCancel(usable(current, now), ownerId, now);
      if (decision.kind === 'observed') return decision;
      save(commandKey, decision.doc);
      if (decision.kind === 'cancelled') release(ownerId, commandKey);
      return decision;
    },
  };
  const codec = {
    async open(binding) {
      calls.open += 1;
      counts.kms += 1;
      const text = binding.purpose === 'callback-url' ? URL_TEXT : binding.secretHash === PREVIOUS_HASH ? PREVIOUS_SECRET_TEXT : SECRET_TEXT;
      return Buffer.from(text, 'utf8');
    },
  };
  const sendFn = async (request) => {
    counts.send += 1;
    // 送られたbytes・secretの写し（serviceの0上書きの前に試験が持つ）。
    calls.sent.push({ eventBytes: Buffer.from(request.eventBytes), secrets: request.secrets.map((secret) => Buffer.from(secret)), eventId: request.eventId, subscriptionId: request.subscriptionId, url: request.url, signal: request.signal });
    const hold = control.sendHold;
    if (hold) {
      control.sendHold = null;
      hold.reached();
      await hold.promise;
    }
    if (control.sendResult === 'throw') throw new Error('socket reset');
    return control.sendResult ?? { kind: 'delivered', reason: 'acknowledged', stopSubscription: false };
  };
  const service = new KmsRequestDeliveryService({
    store,
    codec,
    hash,
    digestKey: DIGEST_KEY,
    send: sendFn,
    clock,
    newAttemptId: () => ((calls.attempts += 1), `attempt-${calls.attempts}`),
    log,
    budgetMs: 20_000,
    lifetime: lifetime.signal,
    hooks: {
      afterOpen: async () => {
        const run = control.afterOpen;
        control.afterOpen = null;
        if (run) await run();
      },
      onOwned: (buffer) => calls.owned.push(buffer),
    },
  });
  const post = async (ownerId, payload, key = payload.commandId) => {
    const response = await service.post(ownerId, key, bytesOf(payload), BASE);
    calls.responses.push(response);
    return response;
  };
  /** 保存された全文書・controlの写し（文字列化しない。containsTextで走査する）。 */
  const stored = () => structuredClone([...docs.values(), ...controls.values()]);
  const docOf = (ownerId, commandId) => load(ownerId, store.commandKey(ownerId, commandId.toLowerCase()));
  return { service, store, calls, control, lifetime, owners, addOwner, post, stored, docOf, docs, subscriptionOf };
}

/** 状態応答はcommandId・state・expiresAt・acknowledgedAtだけ。エラーは固定のerrorだけ。 */
function checkResponseShape(response) {
  const keys = Object.keys(response.body);
  if (Object.hasOwn(response.body, 'error')) assert.deepEqual(keys, ['error']);
  else for (const key of keys) assert.ok(['commandId', 'state', 'expiresAt', 'acknowledgedAt'].includes(key), key);
}

test('V01 L1 input: exactly the 5 fields; the text is kept as sent; 4096 bytes ok / 4097 not; escaped body over 8192 refused; blank / lone surrogate / invalid UTF-8 / BOM / wrong type / missing / unknown / duplicate / escaped duplicate refused before any store or send', { timeout: 10_000 }, async () => {
  const kept = [
    'こんにちは、Dots',
    '🌏👨‍👩‍👧 絵文字',
    'line1\nline2\r\nline3',
    '  前後の空白  ',
    'e\u0301 か\u3099（結合文字）',
    '\t\u3000混在\u3000 ',
    '</textarea><script>alert(1)</script>',
    'a'.repeat(4096),
    `${'あ'.repeat(1365)}a`,
  ];
  assert.notEqual('e\u0301'.normalize('NFC'), 'e\u0301', 'the combining sample changes under NFC');
  for (const text of kept) {
    const payload = v2({ text });
    const input = validateCommandInput(payload.commandId, bytesOf(payload));
    assert.ok(Object.isFrozen(input.fields));
    assert.deepEqual(Object.keys(input.fields), FIELDS);
    assert.equal(input.fields.text, text, 'kept as sent (no trim / normalize / cut)');
    const canonical = JSON.parse(input.canonicalBytes.toString('utf8'));
    assert.deepEqual(Object.keys(canonical), FIELDS);
    assert.equal(canonical.text, text);
  }
  assert.equal(Buffer.byteLength(kept.at(-1)), 4096);
  // JSONのescapeで送った本文も、escapeを解いた同じ文字列になる。
  const id = randomUUID();
  const escaped = `{"schemaVersion":2,"commandId":"${id}","text":"\\u3042\\n\\ud83c\\udf0f \\/","createdAt":"${iso(BASE)}","expiresAt":"${iso(BASE + 60_000)}"}`;
  assert.equal(validateCommandInput(id, bytesOf(escaped)).fields.text, 'あ\n🌏 /');
  // Idempotency-Keyとは大小を無視して一致。内部IDは小文字、fieldsは元の表記。
  const upper = randomUUID().toUpperCase();
  const mixed = validateCommandInput(upper.toLowerCase(), bytesOf(v2({ commandId: upper })));
  assert.deepEqual([mixed.commandId, mixed.fields.commandId], [upper.toLowerCase(), upper]);

  const ok = v2();
  const head = `{"schemaVersion":2,"commandId":"${ok.commandId}","text":"`;
  const tail = `","createdAt":"${ok.createdAt}","expiresAt":"${ok.expiresAt}"}`;
  const overEscaped = v2({ text: `x${'"'.repeat(4095)}` });
  assert.equal(Buffer.byteLength(overEscaped.text), 4096);
  assert.ok(bytesOf(overEscaped).length > 8192, 'the wire body exceeds 8192 because of the escapes');
  const without = (name) => Object.fromEntries(Object.entries(ok).filter(([key]) => key !== name));
  const refused = {
    empty: v2({ text: '' }),
    space: v2({ text: ' ' }),
    blank: v2({ text: ' \n\t\r\u3000 ' }),
    loneHigh: `${head}abc\\ud800${tail}`,
    loneLow: `${head}\\udc00${tail}`,
    over4097: v2({ text: 'a'.repeat(4097) }),
    overMultibyte: v2({ text: 'あ'.repeat(1366) }),
    overEscaped,
    invalidUtf8: Buffer.concat([Buffer.from(head), Buffer.from([0xff, 0xfe, 0x41]), Buffer.from(tail)]),
    bom: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytesOf(ok)]),
    textNumber: v2({ text: 1 }),
    textNull: v2({ text: null }),
    textObject: `${head.slice(0, -1)}{"value":"x"}${tail.slice(1)}`,
    textArray: `${head.slice(0, -1)}["x"]${tail.slice(1)}`,
    commandIdNumber: v2({ commandId: 12345 }),
    createdAtNumber: v2({ createdAt: BASE }),
    schemaString: v2({ schemaVersion: '2' }),
    ...Object.fromEntries(FIELDS.map((name) => [`missing_${name}`, without(name)])),
    unknown: v2({ extra: 'x' }),
    duplicateText: `${head}a","text":"b${tail}`,
    escapedDuplicate: `${head}a","\\u0074ext":"b${tail}`,
    notJson: `${head}a${tail.slice(0, -1)}`,
    trailingComma: `${bytesOf(ok).toString().slice(0, -1)},}`,
    trailingGarbage: `${bytesOf(ok).toString()}x`,
    nothing: '',
    array: '[]',
    nullBody: 'null',
    emptyObject: '{}',
  };
  for (const [name, payload] of Object.entries(refused)) assert.throws(() => validateCommandInput(ok.commandId, bytesOf(payload)), isInvalid, name);
  assert.throws(() => validateCommandInput(randomUUID(), bytesOf(ok)), isInvalid, 'Idempotency-Key mismatch');
  assert.throws(() => validateCommandInput('not-a-uuid', bytesOf({ ...ok, commandId: 'not-a-uuid' })), isInvalid, 'non-UUID');

  // 実serviceでも400で、準備・試行ID・開封・送出は0。
  const fx = decisionFixture();
  const owner = fx.addOwner();
  for (const [name, payload] of Object.entries(refused)) {
    if (name === 'nothing') continue;
    const response = await fx.post(owner, payload, ok.commandId);
    assert.deepEqual([response.status, response.body], [400, { error: { code: 'invalid_request', retryable: false } }], name);
  }
  assert.deepEqual([fx.calls.prepare, fx.calls.attempts, fx.calls.open, fx.calls.sent.length, fx.docs.size], [0, 0, 0, 0, 0]);
});

test('V02 L2 old contract refused: schemaVersion 1/3, each removed field (direction/taskId/taskLabel/revision), a metadata object and the full 0.2.0 body are 400 with no side effect; the v1 routes are 404 without identity/service; wrong v2 methods are 405', { timeout: 20_000 }, async () => {
  const old = (commandId) => ({ schemaVersion: 1, commandId, taskId: randomUUID(), taskLabel: 'task', revision: 1, direction: 'up', text: 'hello from delivery', createdAt: iso(BASE), expiresAt: iso(BASE + 60_000) });
  const id = randomUUID();
  const refused = {
    schema1: v2({ commandId: id, schemaVersion: 1 }),
    schema3: v2({ commandId: id, schemaVersion: 3 }),
    direction: v2({ commandId: id, direction: 'up' }),
    taskId: v2({ commandId: id, taskId: randomUUID() }),
    taskLabel: v2({ commandId: id, taskLabel: 'task' }),
    revision: v2({ commandId: id, revision: 1 }),
    metadata: v2({ commandId: id, metadata: { direction: 'up' } }),
    oldBody: old(id),
    oldBodySchema2: { ...old(id), schemaVersion: 2 },
  };
  for (const [name, payload] of Object.entries(refused)) assert.throws(() => validateCommandInput(id, bytesOf(payload)), isInvalid, name);
  const fx = decisionFixture();
  fx.addOwner({}, OWNER);
  for (const [name, payload] of Object.entries(refused)) assert.equal((await fx.post(OWNER, payload, id)).status, 400, name);
  assert.deepEqual([fx.calls.prepare, fx.calls.attempts, fx.calls.sent.length], [0, 0, 0]);

  const counted = { post: 0, get: 0, cancel: 0 };
  const service = {
    post: (...args) => ((counted.post += 1), fx.service.post(...args)),
    get: (...args) => ((counted.get += 1), fx.service.get(...args)),
    cancel: (...args) => ((counted.cancel += 1), fx.service.cancel(...args)),
  };
  clockState.value = BASE;
  const handler = createIngressOperationDeliveryRequestHandler({ identity, findOwner, service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  const { server, port } = await startServer(handler);
  try {
    const verifyBefore = counts.verify;
    const commandId = randomUUID();
    const valid = JSON.stringify(v2({ commandId }));
    const v1 = [
      ['POST', '/v1/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: valid }],
      ['GET', `/v1/commands/${commandId}`, { headers: auth }],
      ['POST', `/v1/commands/${commandId}/cancel`, { headers: auth }],
    ];
    for (const [method, path, options] of v1) {
      const response = await send(port, method, path, options).done;
      assert.deepEqual([response.status, response.json], [404, { error: { code: 'not_found', retryable: false } }], `${method} ${path}`);
    }
    const wrong = [
      ['GET', '/v2/commands'],
      ['PUT', '/v2/commands'],
      ['POST', `/v2/commands/${commandId}`],
      ['DELETE', `/v2/commands/${commandId}`],
      ['GET', `/v2/commands/${commandId}/cancel`],
    ];
    for (const [method, path] of wrong) {
      const response = await send(port, method, path, { headers: auth }).done;
      assert.deepEqual([response.status, response.json?.error?.code], [405, 'method_not_allowed'], `${method} ${path}`);
    }
    assert.deepEqual([counted.post, counted.get, counted.cancel, counts.verify - verifyBefore], [0, 0, 0, 0], 'no identity / service for v1 or a wrong method');
    // v2へ旧形式の本文 → 400（serviceの入力検証）、準備0。
    const oldId = randomUUID();
    const oldResponse = await send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', oldId]], body: JSON.stringify(old(oldId)) }).done;
    assert.deepEqual([oldResponse.status, oldResponse.json?.error?.code, fx.calls.prepare], [400, 'invalid_request', 0]);
    // 正の対照: v2の5項目は配送され、同じIDのGET・cancelもv2で読める。
    const okResponse = await send(port, 'POST', '/v2/commands', { headers: [...auth, ...json, ['Idempotency-Key', commandId]], body: valid }).done;
    assert.deepEqual([okResponse.status, okResponse.json.state, okResponse.json.commandId], [200, 'delivered', commandId]);
    assert.equal((await send(port, 'GET', `/v2/commands/${commandId}`, { headers: auth }).done).json.state, 'delivered');
    assert.equal((await send(port, 'POST', `/v2/commands/${commandId}/cancel`, { headers: auth }).done).json.state, 'delivered');
    assert.deepEqual([counted.post, counted.get, counted.cancel, fx.calls.sent.length], [2, 1, 1, 1]);
  } finally {
    await closeServer(server);
  }
});

test('V03 L3 canonical and idempotency: exactly 5 fields in a fixed order; key order / whitespace / escapes give the same digest, value changes do not; the production decidePrepare returns the stored state for the same content, 409 for different text/time/ID spelling, keeps owners apart, keeps a first-arrived cancel tombstone; never sends twice', { timeout: 20_000 }, async () => {
  const id = randomUUID();
  const text = syntheticText('あ/"\\ 冪等性の本文');
  const base = v2({ commandId: id, text });
  const compact = JSON.stringify(base);
  const reordered = `{ "expiresAt" : "${base.expiresAt}",\n\t"text":"\\u3042\\/\\"\\\\ \\u51aa\\u7b49\\u6027\\u306e\\u672c\\u6587", "createdAt":"${base.createdAt}" ,\r\n "commandId":"${id}","schemaVersion":2 }`;
  const canonicalOf = (payload, key = id) => validateCommandInput(key, bytesOf(payload)).canonicalBytes;
  const expected = JSON.stringify({ schemaVersion: 2, commandId: id, text, createdAt: base.createdAt, expiresAt: base.expiresAt });
  assert.equal(canonicalOf(compact).toString('utf8'), expected, 'canonical = the 5 fields in the fixed order');
  assert.ok(canonicalOf(reordered).equals(canonicalOf(compact)), 'same canonical for key order / whitespace / escapes');
  const changed = {
    text: v2({ commandId: id, text: `${text} ` }),
    createdAt: v2({ commandId: id, text, createdAt: iso(BASE + 1000), expiresAt: iso(BASE + 61_000) }),
    expiresAtMs: v2({ commandId: id, text, createdAt: iso(BASE + 1), expiresAt: iso(BASE + 60_001) }),
    commandIdCase: v2({ commandId: id.toUpperCase(), text }),
  };
  for (const [name, payload] of Object.entries(changed)) assert.equal(canonicalOf(payload).equals(canonicalOf(compact)), false, name);

  clockState.value = BASE;
  const fx = decisionFixture();
  const ownerA = fx.addOwner();
  const ownerB = fx.addOwner();
  const first = await fx.post(ownerA, compact, id);
  assert.deepEqual([first.status, first.body.state], [200, 'delivered']);
  assert.equal(fx.calls.sent.length, 1);
  const storedA = JSON.stringify(fx.docOf(ownerA, id));
  assert.equal(containsText(fx.docOf(ownerA, id), text), false);
  const again = await fx.post(ownerA, reordered, id);
  assert.deepEqual([again.status, again.body], [200, first.body], 'stored state only');
  for (const [name, payload] of Object.entries(changed)) {
    const response = await fx.post(ownerA, payload, id);
    assert.deepEqual([response.status, response.body], [409, { error: { code: 'idempotency_conflict', retryable: false } }], name);
  }
  assert.equal(fx.calls.sent.length, 1, 'no second send for the same ID');
  assert.equal(JSON.stringify(fx.docOf(ownerA, id)), storedA, 'the stored state is not rewritten');
  // 他ownerの同じIDは独立（新規に受け付けて配送）、Aの状態は変わらない。
  const otherOwner = await fx.post(ownerB, compact, id);
  assert.deepEqual([otherOwner.status, otherOwner.body.state, fx.calls.sent.length], [200, 'delivered', 2]);
  assert.equal(JSON.stringify(fx.docOf(ownerA, id)), storedA);
  // 処理中の同じ内容は202 in_flight、違う内容は409。どちらも送らない。
  const busyId = randomUUID();
  const busy = v2({ commandId: busyId, text: syntheticText('処理中の本文') });
  const hold = gate();
  fx.control.sendHold = hold;
  const pending = fx.post(ownerA, busy);
  await hold.whenReached;
  const inFlight = await fx.post(ownerA, busy);
  assert.deepEqual([inFlight.status, inFlight.body.state, inFlight.body.commandId], [202, 'in_flight', busyId]);
  assert.equal((await fx.post(ownerA, { ...busy, text: '違う本文' })).status, 409);
  hold.release();
  assert.equal((await pending).body.state, 'delivered');
  assert.equal(fx.calls.sent.length, 3);
  // 先着の取消（tombstone）は、後から来たPOSTの本文に関わらずcancelled、送らない。
  const lateId = randomUUID();
  const tombstone = await fx.service.cancel(ownerA, lateId, BASE);
  assert.deepEqual([tombstone.status, tombstone.body], [200, { commandId: lateId, state: 'cancelled' }]);
  for (const payload of [v2({ commandId: lateId }), v2({ commandId: lateId, text: '別の本文' })]) {
    const response = await fx.post(ownerA, payload);
    assert.deepEqual([response.status, response.body], [200, { commandId: lateId, state: 'cancelled' }]);
  }
  assert.equal(fx.docOf(ownerA, lateId).tombstone, true);
  assert.equal(fx.calls.sent.length, 3, 'never sent twice');
  assert.equal(containsText(fx.stored(), text), false, 'no body in the stored documents');
  assert.equal(containsText(fx.calls.responses.map((response) => response.body), text), false, 'no body in the responses');
  for (const response of fx.calls.responses) checkResponseShape(response);
});

test('V04 L4 event bytes and signatures: data has exactly 4 fields (schemaVersion 2) with the submitted text; receipt timestamp, effective expiresAt, owner-specific stable eventId; the real signCommandBody verifies with the standardwebhooks library, a 1-byte change and another secret do not; current+previous secrets both verify; the service sends exactly these bytes', { timeout: 20_000 }, async () => {
  assert.equal(EVENT_NAME, 'text.submitted');
  const textA = syntheticText('Eventsの本文A\n2行目 🌏 e\u0301');
  const upper = randomUUID().toUpperCase();
  const input = validateCommandInput(upper.toLowerCase(), bytesOf(v2({ commandId: upper, text: textA, createdAt: iso(BASE - 5000), expiresAt: iso(BASE + 55_000) })));
  const effective = resolveNewCommandExpiry(input, BASE, BASE);
  assert.equal(effective, BASE + 55_000);
  const ownerX = `owner-${randomUUID()}`;
  const eventId = eventIdFor({ hash }, ownerX, input.commandId);
  assert.match(eventId, UUID_V8);
  assert.equal(eventIdFor({ hash }, ownerX, input.commandId), eventId, 'stable for the same owner/ID');
  assert.notEqual(eventIdFor({ hash }, `owner-${randomUUID()}`, input.commandId), eventId, 'differs for another owner');
  const bytes = buildEventBytes(input.fields, eventId, BASE, effective);
  const event = JSON.parse(bytes.toString('utf8'));
  assert.deepEqual(Object.keys(event), EVENT_KEYS);
  assert.deepEqual(Object.keys(event.data), DATA_FIELDS, 'exactly 4 data fields in order');
  assert.deepEqual(event, { eventId, name: 'text.submitted', timestamp: iso(BASE), data: { schemaVersion: 2, commandId: upper, text: textA, expiresAt: iso(BASE + 55_000) }, cursor: null });
  for (const removed of ['direction', 'taskId', 'taskLabel', 'revision', 'createdAt']) assert.equal(Object.hasOwn(event.data, removed), false, removed);
  // 実効期限は受信+60秒を超えない。
  const later = validateCommandInput(upper.toLowerCase(), bytesOf(v2({ commandId: upper, text: textA, createdAt: iso(BASE + 10_000), expiresAt: iso(BASE + 70_000) })));
  assert.equal(JSON.parse(buildEventBytes(later.fields, eventId, BASE, resolveNewCommandExpiry(later, BASE, BASE)).toString()).data.expiresAt, iso(BASE + 60_000));

  const current = rawSecret(SECRET_TEXT);
  const previous = rawSecret(PREVIOUS_SECRET_TEXT);
  const keep = [Buffer.from(current), Buffer.from(previous), Buffer.from(bytes)];
  const signedAt = new Date();
  const verifier = (secret) => new Webhook(Buffer.from(secret), { format: 'raw' });
  const single = signCommandBody(eventId, bytes, signedAt, [current]);
  assert.deepEqual(Object.keys(single).sort(), ['webhook-id', 'webhook-signature', 'webhook-timestamp']);
  assert.equal(single['webhook-id'], eventId);
  assert.equal(verifier(current).verify(bytes.toString('utf8'), single).data.text, textA, 'verifies the original bytes');
  const altered = Buffer.from(bytes);
  altered[altered.indexOf('"cursor"') + 2] ^= 0x01;
  assert.throws(() => verifier(current).verify(altered.toString('utf8'), single), 'a 1-byte change is refused');
  assert.throws(() => verifier(randomBytes(32)).verify(bytes.toString('utf8'), single), 'another secret is refused');
  const rotated = signCommandBody(eventId, bytes, signedAt, [current, previous]);
  assert.equal(rotated['webhook-signature'].split(' ').length, 2);
  for (const secret of [current, previous]) assert.equal(verifier(secret).verify(bytes.toString('utf8'), rotated).data.commandId, upper);
  assert.throws(() => verifier(randomBytes(32)).verify(bytes.toString('utf8'), rotated));
  assert.ok(keep[0].equals(current) && keep[1].equals(previous) && keep[2].equals(bytes), 'borrowed bytes/secrets unchanged');

  // serviceが送るbytes: 旧secretの猶予中は新旧2つ、猶予切れは現行だけ。送ったbytesそのものが署名・検証できる。
  clockState.value = BASE;
  const fx = decisionFixture();
  const rotating = fx.addOwner({ previousUntil: BASE + 300_000 });
  const settled = fx.addOwner({ previousUntil: BASE });
  const textB = syntheticText('Eventsの本文B（購読先へそのまま）');
  for (const [owner, keys] of [
    [rotating, 2],
    [settled, 1],
  ]) {
    const commandId = randomUUID();
    const before = fx.calls.owned.length;
    const response = await fx.post(owner, v2({ commandId, text: textB, createdAt: iso(BASE - 2000), expiresAt: iso(BASE + 58_000) }));
    assert.deepEqual([response.status, response.body.state], [200, 'delivered']);
    const sent = fx.calls.sent.at(-1);
    const delivered = JSON.parse(sent.eventBytes.toString('utf8'));
    assert.deepEqual(Object.keys(delivered.data), DATA_FIELDS);
    assert.deepEqual(delivered, { eventId: eventIdFor({ hash }, owner, commandId), name: 'text.submitted', timestamp: iso(BASE), data: { schemaVersion: 2, commandId, text: textB, expiresAt: iso(BASE + 58_000) }, cursor: null });
    assert.equal(sent.eventId, delivered.eventId);
    assert.equal(sent.subscriptionId, fx.subscriptionOf(owner));
    assert.equal(sent.secrets.length, keys);
    assert.ok(sent.secrets[0].equals(current));
    if (keys === 2) assert.ok(sent.secrets[1].equals(previous));
    const headers = signCommandBody(sent.eventId, sent.eventBytes, new Date(), sent.secrets);
    for (const secret of sent.secrets) assert.equal(verifier(secret).verify(sent.eventBytes.toString('utf8'), headers).data.text, textB);
    const owned = fx.calls.owned.slice(before);
    assert.ok(owned.length >= 2 + keys, 'url/secret/event buffers observed');
    assert.ok(allZero(owned), 'owned buffers (URL, secrets, event bytes) zeroed after the request');
  }
  assert.equal(containsText(fx.stored(), textB), false);
});

test('V05 L6 owner / authorization / time / rate with the production decisions: revoked owner 403, no or expired subscription and a lost Grant 409, change pending 409, future >30 s and remaining <10 s 422 (boundaries pass), 60 s difference enforced, burst 3 then 429; other owner and absent GET 404; the real Firebase verifier refuses non-Apple/revoked/expired/other-project tokens and an unlinked UID gets 403', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = decisionFixture();
  const denials = [
    ['ownerRevoked', { ownerActive: false }, 403, 'connection_revoked'],
    ['noSubscription', { subscription: false }, 409, 'subscription_required'],
    ['subscriptionExpired', { subscriptionExpiresAt: BASE }, 409, 'subscription_required'],
    ['grantRevoked', { grantLive: false }, 409, 'subscription_required'],
    ['changePending', { pending: true }, 409, 'destination_change_pending'],
  ];
  for (const [name, overrides, status, code] of denials) {
    const owner = fx.addOwner(overrides);
    const response = await fx.post(owner, v2());
    assert.deepEqual([response.status, response.body], [status, { error: { code, retryable: false } }], name);
  }
  assert.deepEqual([fx.calls.sent.length, fx.calls.open, fx.docs.size], [0, 0, 0], 'denied before any open/send/document');

  const at = (createdMs) => v2({ createdAt: iso(createdMs), expiresAt: iso(createdMs + 60_000) });
  const timing = [
    ['future30001', at(BASE + 30_001), 422, 'clock_skew'],
    ['future30000', at(BASE + 30_000), 200, null],
    ['remaining9999', at(BASE - 50_001), 422, 'command_expired'],
    ['remaining10000', at(BASE - 50_000), 200, null],
    ['lifetime59999', v2({ expiresAt: iso(BASE + 59_999) }), 400, 'invalid_request'],
    ['lifetime60001', v2({ expiresAt: iso(BASE + 60_001) }), 400, 'invalid_request'],
  ];
  for (const [name, payload, status, code] of timing) {
    const response = await fx.post(fx.addOwner(), payload);
    assert.equal(response.status, status, name);
    if (code === null) assert.equal(response.body.state, 'delivered', name);
    else assert.equal(response.body.error.code, code, name);
  }
  assert.equal(fx.calls.sent.length, 2, 'only the two boundary cases were sent');

  const busy = fx.addOwner();
  for (let index = 0; index < 3; index += 1) assert.equal((await fx.post(busy, v2())).body.state, 'delivered');
  const limited = await fx.post(busy, v2());
  assert.deepEqual([limited.status, limited.body.error.code, limited.body.error.retryable], [429, 'rate_limited', true]);
  assert.match(limited.headers['Retry-After'], /^[1-9][0-9]?$/);
  assert.equal(fx.calls.sent.length, 5);

  const ownerA = fx.addOwner();
  const ownerB = fx.addOwner();
  const id = randomUUID();
  assert.equal((await fx.post(ownerA, v2({ commandId: id }))).body.state, 'delivered');
  assert.deepEqual((await fx.service.get(ownerA, id, BASE)).body, { commandId: id, state: 'delivered', expiresAt: iso(BASE + 60_000), acknowledgedAt: iso(BASE) });
  for (const [owner, commandId] of [
    [ownerB, id],
    [ownerA, randomUUID()],
  ]) {
    assert.deepEqual(await fx.service.get(owner, commandId, BASE), { status: 404, body: { error: { code: 'not_found', retryable: false } } });
  }
  // 他ownerの取消は自分の側のtombstoneだけで、Aの状態を変えない。
  assert.equal((await fx.service.cancel(ownerB, id, BASE)).body.state, 'cancelled');
  assert.equal((await fx.service.get(ownerA, id, BASE)).body.state, 'delivered');
  // 失効したownerの取消は403。
  fx.owners.get(ownerA).ownerActive = false;
  assert.equal((await fx.service.cancel(ownerA, id, BASE)).status, 403);

  // HTTP: 実際のFirebase Admin検証adapter（Apple provider・同project・失効確認）と、作らないowner照会。
  const PROJECT = 'demo-sttd-delivery';
  const checkRevoked = [];
  const decoded = (provider, overrides = {}) => ({ aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, firebase: { sign_in_provider: provider }, sub: 'uid-apple', auth_time: Math.floor(BASE / 1000), ...overrides });
  const adminAuth = {
    async verifyIdToken(token, revoked) {
      checkRevoked.push(revoked);
      switch (token) {
        case 'tok.apple.sig':
          return decoded('apple.com');
        case 'tok.unlinked.sig':
          return decoded('apple.com', { sub: 'uid-unlinked' });
        case 'tok.google.sig':
          return decoded('google.com');
        case 'tok.project.sig':
          return decoded('apple.com', { aud: 'other-project-x', iss: 'https://securetoken.google.com/other-project-x' });
        case 'tok.revoked.sig':
          throw Object.assign(new Error('revoked'), { code: 'auth/id-token-revoked' });
        default:
          throw Object.assign(new Error('expired'), { code: 'auth/id-token-expired' });
      }
    },
    async getUser() {
      return { disabled: false };
    },
  };
  const verifier = createFirebaseAdminVerifier({ auth: adminAuth, projectId: PROJECT });
  const linked = fx.addOwner();
  const lookups = [];
  const lookup = async (verified) => (lookups.push(verified.uid), verified.uid === 'uid-apple' ? linked : undefined);
  const handler = createIngressOperationDeliveryRequestHandler({ identity: verifier, findOwner: lookup, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  const { server, port } = await startServer(handler);
  try {
    const postWith = async (token) => {
      const commandId = randomUUID();
      const headers = [...(token === null ? [] : [['Authorization', `Bearer ${token}`]]), ...json, ['Idempotency-Key', commandId]];
      return send(port, 'POST', '/v2/commands', { headers, body: JSON.stringify(v2({ commandId })) }).done;
    };
    const sentBefore = fx.calls.sent.length;
    const expected = [
      ['tok.apple.sig', 200],
      ['tok.google.sig', 401],
      ['tok.revoked.sig', 401],
      ['tok.expired.sig', 401],
      ['tok.project.sig', 401],
      ['tok.unlinked.sig', 403],
      [null, 401],
    ];
    for (const [token, status] of expected) {
      const response = await postWith(token);
      assert.equal(response.status, status, String(token));
      if (status === 200) assert.equal(response.json.state, 'delivered');
      if (status === 401) assert.deepEqual(response.json, { error: { code: 'authentication_required', retryable: false } });
      if (status === 403) assert.deepEqual(response.json, { error: { code: 'connection_revoked', retryable: false } });
    }
    assert.equal(fx.calls.sent.length - sentBefore, 1, 'only the linked Apple identity was delivered');
    assert.deepEqual(lookups, ['uid-apple', 'uid-unlinked'], 'owner lookup only after a verified Apple identity');
    assert.ok(checkRevoked.length === 6 && checkRevoked.every((value) => value === true), 'revocation is always checked');
  } finally {
    await closeServer(server);
  }
  for (const response of fx.calls.responses) checkResponseShape(response);
});

test('V06 L7 cancel / dispatch race / deadline / outcome classes: cancel before dispatch sends nothing; cancel after the grant is delivery_unknown and aborts the in-flight send once; a Grant lost before dispatch or a deadline passed while opening sends nothing; external results keep their classes without retry; no text in stored state / responses / logs; owned buffers zeroed', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = decisionFixture();
  const texts = [];
  const post = (owner, overrides = {}) => {
    const text = syntheticText(`取消と分類の本文 ${randomUUID()}\n改行`);
    texts.push(text);
    return fx.post(owner, v2({ text, ...overrides }));
  };

  // 送出権の前（開封の後）の取消: 中止へ確定、送らない。
  const ownerA = fx.addOwner();
  const beforeId = randomUUID();
  let cancelResponse;
  fx.control.afterOpen = async () => {
    cancelResponse = await fx.service.cancel(ownerA, beforeId, BASE);
  };
  const cancelled = await post(ownerA, { commandId: beforeId });
  assert.deepEqual([cancelled.status, cancelled.body.state, cancelResponse.body.state], [200, 'cancelled', 'cancelled']);
  assert.deepEqual([fx.docOf(ownerA, beforeId).state, fx.docOf(ownerA, beforeId).reason], ['cancelled', 'cancelled_before_dispatch']);
  assert.equal(fx.calls.sent.length, 0);

  // 送出権の確定後の取消: 結果不明、送出中のsignalを1回中断、再送0。
  const afterId = randomUUID();
  const hold = gate();
  fx.control.sendHold = hold;
  fx.control.sendResult = 'throw';
  const pending = post(ownerA, { commandId: afterId });
  await hold.whenReached;
  const afterCancel = await fx.service.cancel(ownerA, afterId, BASE);
  assert.equal(afterCancel.body.state, 'delivery_unknown');
  assert.equal(fx.calls.sent.at(-1).signal.aborted, true, 'the in-flight send was aborted');
  hold.release();
  const unknown = await pending;
  fx.control.sendResult = null;
  assert.equal(unknown.body.state, 'delivery_unknown');
  assert.equal(fx.docOf(ownerA, afterId).state, 'delivery_unknown');
  assert.equal(fx.calls.sent.length, 1);

  // 開封の後にGrantが失効: 送出権の再照合で送らずに失敗。
  const ownerB = fx.addOwner();
  fx.control.afterOpen = async () => {
    fx.owners.get(ownerB).grantLive = false;
  };
  const lostId = randomUUID();
  const lost = await post(ownerB, { commandId: lostId });
  assert.deepEqual([lost.body.state, fx.docOf(ownerB, lostId).reason], ['failed', 'authorization_lost']);
  assert.equal(fx.calls.sent.length, 1);

  // 開封の間に残りが10秒未満: 送らずに失敗。
  const ownerC = fx.addOwner();
  fx.control.afterOpen = async () => {
    clockState.value = BASE + 10_001;
  };
  try {
    const lateId = randomUUID();
    const late = await post(ownerC, { commandId: lateId });
    assert.deepEqual([late.body.state, fx.docOf(ownerC, lateId).reason], ['failed', 'deadline_passed']);
  } finally {
    clockState.value = BASE;
  }
  assert.equal(fx.calls.sent.length, 1);

  // 外部結果の分類（各1回だけ送る）。
  const classes = [
    [{ kind: 'delivered', reason: 'acknowledged', stopSubscription: false }, 'delivered'],
    [{ kind: 'retry', reason: 'server_error', stopSubscription: false }, 'delivery_unknown'],
    [{ kind: 'retry', reason: 'rate_limited', stopSubscription: false }, 'failed'],
    [{ kind: 'retry', reason: 'network_unavailable', stopSubscription: false }, 'failed'],
    [{ kind: 'failed', reason: 'client_error', stopSubscription: false }, 'failed'],
    [{ kind: 'uncertain', reason: 'transport_ambiguous', stopSubscription: false }, 'delivery_unknown'],
  ];
  for (const [result, state] of classes) {
    const owner = fx.addOwner();
    const commandId = randomUUID();
    const before = fx.calls.sent.length;
    fx.control.sendResult = result;
    const response = await post(owner, { commandId });
    assert.deepEqual([response.body.state, fx.docOf(owner, commandId).state, fx.calls.sent.length - before], [state, state, 1], `${result.kind}/${result.reason}`);
  }
  fx.control.sendResult = null;

  // 平文が保存・応答に無いこと、所有Bufferの0上書き。
  const stored = fx.stored();
  const answered = fx.calls.responses.map((response) => response.body);
  assert.ok(texts.length > 0 && texts.every((text) => text.includes('\n')), 'the samples contain a newline');
  for (const needle of [...texts, URL_TEXT, SECRET_TEXT]) {
    assert.equal(containsText(stored, needle), false, 'not in stored state');
    assert.equal(containsText(answered, needle), false, 'not in responses');
  }
  for (const response of fx.calls.responses) checkResponseShape(response);
  assert.ok(fx.calls.owned.length > 0 && allZero(fx.calls.owned), 'owned buffers zeroed');
  assert.equal(fx.calls.sent.length, 1 + classes.length, 'one send per granted command, no retry');
});

test('V07 privacy detector positive control: a synthetic text with newline / quote / backslash / Japanese that is actually held in a stored document, a response body, a log entry, a Map key or a Buffer is detected (the JSON-string comparison would miss it); absent values stay false', { timeout: 10_000 }, () => {
  const text = syntheticText('対照の本文\n"引用" と \\ バックスラッシュ\t末尾');
  const absent = '保存していない本文\n"x" \\ y';
  for (const mark of ['\n', '"', '\\']) assert.ok(text.includes(mark), JSON.stringify(mark));
  // 試験が合成storeのMapへ直接置いた対照（本番sourceの保存処理は使わない）。
  const fx = decisionFixture();
  fx.docs.set('control-key', { version: 1, nested: { list: ['other', text] } });
  const response = { status: 200, body: { commandId: randomUUID(), state: 'delivered', note: text } };
  const logEntry = { event: 'delivery.sent', reason: text };
  const holders = {
    stored: fx.stored(),
    response: [response.body],
    log: logEntry,
    mapKey: new Map([[text, 1]]),
    objectKey: { [text]: true },
    buffer: [Buffer.from(text, 'utf8')],
  };
  for (const [name, holder] of Object.entries(holders)) {
    assert.equal(containsText(holder, text), true, `${name}: detected`);
    assert.equal(containsText(holder, absent), false, `${name}: absent stays false`);
  }
  assert.equal(leaksInLog(logEntry), true, 'the log predicate used at the end of this suite detects it');
  assert.equal(leaksInLog({ event: 'delivery.sent', reason: 'acknowledged' }), false);
  // 旧方式（JSON.stringifyした結果へ生の本文をincludes）では、同じ対照を見逃す。
  for (const holder of [holders.stored, holders.response, holders.log]) assert.equal(JSON.stringify(holder).includes(text), false, 'JSON escaping hides the raw text');
  // 循環参照でも止まる。
  const cyclic = { a: [] };
  cyclic.a.push(cyclic, text);
  assert.equal(containsText(cyclic, text), true);
});
test('V08 explicit access with the production decisions: not permitted -> 403 access_denied (not connection_revoked) before open/send/document; same-ID re-POST refused while stopped but GET/cancel by the owner still work; a stop after prepare sends nothing; a stop after the send right keeps the single send', { timeout: 20_000 }, async () => {
  clockState.value = BASE;
  const fx = decisionFixture();
  const denied = fx.addOwner({ access: 'denied' });
  const refused = await fx.post(denied, v2());
  assert.deepEqual([refused.status, refused.body], [403, { error: { code: 'access_denied', retryable: false } }]);
  // 失効したowner（接続の失効）は従来どおりconnection_revokedを優先する。
  const revoked = await fx.post(fx.addOwner({ ownerActive: false, access: 'denied' }), v2());
  assert.deepEqual([revoked.status, revoked.body.error.code], [403, 'connection_revoked']);
  assert.deepEqual([fx.calls.sent.length, fx.calls.open, fx.docs.size], [0, 0, 0], 'refused before any open/send/document');

  // 受付済みの同IDは、停止中の再POSTでは拒否し、本人のGET・取消は利用許可を条件にしない。
  const owner = fx.addOwner();
  const hold = gate();
  fx.control.sendHold = hold;
  const commandId = randomUUID();
  const pending = fx.post(owner, v2({ commandId }));
  await hold.whenReached;
  fx.owners.get(owner).access = 'denied';
  const again = await fx.post(owner, v2({ commandId }));
  assert.deepEqual([again.status, again.body.error.code], [403, 'access_denied']);
  const during = await fx.service.get(owner, commandId, BASE);
  assert.deepEqual([during.status, during.body.state], [200, 'in_flight']);
  hold.release();
  // 送出権の後の停止: 既に始めた単回の送出はそのまま（再送・取消の偽装なし）。
  const delivered = await pending;
  assert.deepEqual([delivered.status, delivered.body.state], [200, 'delivered']);
  assert.equal(fx.calls.sent.length, 1);
  const status = await fx.service.get(owner, commandId, BASE);
  assert.deepEqual([status.status, status.body.state], [200, 'delivered']);
  assert.equal((await fx.service.cancel(owner, commandId, BASE)).status, 200, 'the owner can still ask to cancel (observed state)');

  // 準備の後（開封の後）に停止: 送出権の再照合で拒否し、送らずに失敗（authorization_lost）。
  const late = fx.addOwner();
  fx.control.afterOpen = async () => {
    fx.owners.get(late).access = 'denied';
  };
  const lateId = randomUUID();
  const lost = await fx.post(late, v2({ commandId: lateId }));
  assert.deepEqual([lost.status, lost.body.state], [200, 'failed']);
  assert.deepEqual([fx.docOf(late, lateId).state, fx.docOf(late, lateId).reason], ['failed', 'authorization_lost']);
  assert.equal(fx.calls.sent.length, 1, 'no send after the stop');
});


// ---------- 開発者向けコード（T-065）: コード登録→code identity→接続保存のowner→送信API→KMS配送serviceで本文2件 ----------
// 実物: 予約/消費/確定（DeveloperLoginStore）、交換（createDeveloperCodeExchange）、共通verifier（createFirebaseAdminVerifier＋code照合）、
// 接続保存の利用許可/owner解決（ConnectStorage.resolveOwner/findOwner）、送信HTTP入口とKMS配送service。合成: Firestore（in-memory）、
// Firebase Auth（ID token検証の結果）、配送の保存・封緘・送出（この試験fileのkmsFixture）。OAuth同意画面/Grant metadata/購読登録の実処理は通さない。

import { Timestamp } from '@google-cloud/firestore';
import { ConnectStorage, connectIdentityHash } from '../dist/connect/firestore.js';
import { createCodeIdentityLookup, createDeveloperCodeExchange } from '../dist/identity/developer-code-identity.js';
import { DEVELOPER_LOGIN_PURPOSE, defaultRandom, developerLoginKeys } from '../dist/identity/developer-login.js';
import { DeveloperLoginStore } from '../dist/identity/developer-login-store.js';

function miniFirestore() {
  const docs = new Map();
  let version = 1;
  let lock = Promise.resolve();
  const snap = (ref) => {
    const entry = docs.get(ref.path);
    return { ref, id: ref.id, exists: entry !== undefined, data: () => (entry === undefined ? undefined : { ...entry.data }), updateTime: entry === undefined ? undefined : Timestamp.fromMillis(entry.version) };
  };
  const refOf = (path) => ({
    path,
    id: path.slice(path.lastIndexOf('/') + 1),
    collection: (name) => ({ doc: (id) => refOf(`${path}/${name}/${id}`) }),
    get: async () => snap(refOf(path)),
  });
  const db = {
    collection: (name) => ({ doc: (id) => refOf(`${name}/${id}`) }),
    async runTransaction(fn, options = {}) {
      const previous = lock;
      let release;
      lock = new Promise((resolve) => (release = resolve));
      await previous;
      try {
        for (let attempt = 0; attempt < (options.maxAttempts ?? 5); attempt += 1) {
          const reads = new Map();
          const writes = [];
          const tx = {
            async get(ref) {
              if (writes.length > 0) throw new Error('read after write');
              reads.set(ref.path, docs.get(ref.path)?.version ?? 0);
              return snap(ref);
            },
            create: (ref, data) => writes.push(['create', ref.path, data]),
            set: (ref, data) => writes.push(['set', ref.path, data]),
            update: (ref, data) => writes.push(['update', ref.path, data]),
          };
          const result = await fn(tx);
          if ([...reads].some(([path, v]) => (docs.get(path)?.version ?? 0) !== v)) continue;
          for (const [kind, path, data] of writes) {
            const existing = docs.get(path);
            if (kind === 'create' && existing) throw new Error('exists');
            if (kind === 'update' && !existing) throw new Error('missing');
            version += 1;
            docs.set(path, { data: kind === 'update' ? { ...existing.data, ...data } : { ...data }, version });
          }
          return result;
        }
        throw new Error('contention');
      } finally {
        release();
      }
    },
  };
  return db;
}

test('T065 code identity: issue -> exchange -> owner admitted -> two texts through the send API reach the sender; reissue stops the old code connection', async () => {
  clockState.value = BASE;
  const projectId = 'demo-sttd-delivery';
  const namespace = 't256_2b3c4d5e-6f70-4a81-9b2c-3d4e5f607182';
  const db = miniFirestore();
  const codeClock = { now: () => clockState.value };
  const keys = developerLoginKeys(randomBytes(32));
  const connectKey = randomBytes(32);
  const connectHasher = { hash: (purpose, value) => createHmac('sha256', connectKey).update(`${purpose}\0${value}`).digest('hex') };
  const store = new DeveloperLoginStore({ db, scope: { projectId, databaseId: '(default)', namespace, purpose: DEVELOPER_LOGIN_PURPOSE }, hasher: keys.hasher, sealer: keys.sealer, clock: codeClock, random: defaultRandom });
  const storage = new ConnectStorage({
    db,
    namespace,
    hasher: connectHasher,
    box: { seal: async (purpose, plaintext) => `s:${Buffer.from(plaintext).toString('base64url')}`, open: async (purpose, sealed) => Buffer.from(sealed.slice(2), 'base64url').toString() },
    clock: codeClock,
    ownerInactivityMs: 90 * 24 * 60 * 60_000,
    interactionTtlMs: 10 * 60_000,
  });
  const customTokens = new Map();
  const users = new Set();
  const auth = {
    async createUser({ uid }) {
      users.add(uid);
    },
    async createCustomToken(uid, claims) {
      const token = `ct.${randomUUID()}`;
      customTokens.set(token, { uid, claims });
      return token;
    },
  };
  const exchange = createDeveloperCodeExchange({ store, auth, clock: codeClock, accessIdentityHash: (uid) => connectIdentityHash(connectHasher, namespace, { projectId, uid }) });
  const claimSecret = randomBytes(32).toString('base64url');
  const issued = await store.issue({ claimSecret });
  const exchanged = await exchange.exchange({ code: issued.code, interactionKey: 'interaction-delivery', sourceKey: '127.0.0.1' });
  assert.equal(exchanged.kind, 'token');
  assert.equal(users.size, 1);

  // custom tokenでSDKログインした後のID token（合成。署名検証はFirebase SDKの役で、ここでは結果だけ）。
  const { uid, claims } = customTokens.get(exchanged.customToken);
  const idTokens = new Map();
  const codeIdToken = `code.${randomBytes(12).toString('base64url')}.sig`;
  idTokens.set(codeIdToken, { aud: projectId, iss: `https://securetoken.google.com/${projectId}`, sub: uid, auth_time: Math.floor(BASE / 1000), firebase: { sign_in_provider: 'custom' }, ...claims });
  const verifier = createFirebaseAdminVerifier({
    auth: {
      async verifyIdToken(token) {
        const decoded = idTokens.get(token);
        if (decoded === undefined) throw Object.assign(new Error('x'), { code: 'auth/invalid-id-token' });
        return decoded;
      },
      async getUser() {
        return { disabled: false };
      },
    },
    projectId,
    codeIdentities: createCodeIdentityLookup(store),
  });
  // 接続server側のlogin相当: 予定UID1件だけの利用許可でownerを作る（Appleのownerへ紐付けない）。
  const admission = await storage.resolveOwner(await verifier.verifyIdToken(codeIdToken));
  assert.equal(admission.kind, 'admitted');

  const fx = kmsFixture();
  const findCodeOwner = async (verified) => storage.findOwner(verified);
  const handler = createIngressOperationDeliveryRequestHandler({ identity: verifier, findOwner: findCodeOwner, service: fx.service, clock, log, lifetime: fx.lifetime.signal, ingress: ingressSource });
  const { port } = await startServer(handler, (req) => {
    const controller = new AbortController();
    req.socket.once('close', () => controller.abort());
    ingressState.next = { receivedAt: clockState.value, deadlineAt: clockState.value + 20_000, signal: controller.signal };
  });
  const bearer = [['Authorization', `Bearer ${codeIdToken}`]];
  const post = (text) => {
    const commandId = randomUUID();
    return send(port, 'POST', '/v2/commands', {
      headers: [...bearer, ...json, ['Idempotency-Key', commandId]],
      body: JSON.stringify({ schemaVersion: 2, commandId, text, createdAt: iso(BASE), expiresAt: iso(BASE + 60_000) }),
    }).done;
  };
  for (const text of ['first text via code', 'second text via code']) {
    const response = await post(text);
    assert.equal(response.status, 200);
    assert.equal(response.json.state, 'delivered');
  }
  assert.equal(fx.calls.send.length, 2, 'two texts reached the sender');
  assert.equal(fx.calls.prepare.length, 2);
  assert.ok(JSON.stringify(fx.calls.prepare).includes(admission.ownerId), 'delivered for the code owner');

  // 同じ発行元の再発行: 旧familyの接続は止まり、送出は増えない。
  await store.issue({ claimSecret, previousOperationId: issued.operationId });
  const after = await post('third text after reissue');
  assert.equal(after.status, 401);
  assert.equal(fx.calls.send.length, 2);
});
