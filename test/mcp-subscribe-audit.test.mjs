// MCP入口の購読の診断通知（onSubscribe）を、合成のportと通信なしのHTTP（memoryのsocket対）で確かめる。
// 確かめる点: 1回の`events/subscribe`につき固定分類1回、通知の有無・例外で応答が変わらない、別methodから出ない、期限はcontext_unavailable、
// 診断sinkを通すと固定の1行だけ（URL・secret・owner・Grant・token・messageが出ない）。実listen・外部送信・Cloud 0。
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { Duplex } from 'node:stream';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { EVENT_NAME } from '../dist/events/contract.js';
import { SubscribeError } from '../dist/events/subscriptions.js';
import { createDiagnosticLogSink } from '../dist/http/log.js';
import { createRequestScopedMcpEntry, McpRequestEntryConfigError } from '../dist/mcp/request-scoped-entry.js';
import { STTD_SCOPE } from '../dist/oauth/provider.js';

const ISSUER = 'https://connect.sttd-audit.invalid';
const RESOURCE = `${ISSUER}/mcp`;
const OWNER = 'synthetic-owner-0001';
const GRANT = 'synthetic-grant-0001';
const CALLBACK = 'https://callback.sttd-audit.invalid/hook?k=synthetic-query';
const SECRET = `synthetic-secret-${'x'.repeat(32)}`;
const TOKEN = 'synthetic-access-token';
const CALLBACK_REASONS = ['connection_refused', 'timeout', 'tls_error', 'http_4xx', 'http_5xx', 'challenge_failed'];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** listenしないsocketの対（片方をserverの'connection'へ、もう片方をclientのcreateConnectionへ渡す）。 */
function socketPair() {
  let a;
  let b;
  const side = (peer) =>
    new Duplex({
      read() {},
      write(chunk, _encoding, callback) {
        peer().push(chunk);
        callback();
      },
      final(callback) {
        peer().push(null);
        callback();
      },
      destroy(error, callback) {
        peer().destroy();
        callback(error);
      },
    });
  a = side(() => b);
  b = side(() => a);
  return [a, b];
}

function build({ subscribe = async () => ({ id: 'synthetic-sub-id', refreshBefore: null }), audit, budgetMs, resolveNull = false } = {}) {
  const errors = [];
  const calls = { subscribe: 0, unsubscribe: 0 };
  const entry = createRequestScopedMcpEntry(
    {
      issuer: ISSUER,
      resource: RESOURCE,
      clock: { now: () => Date.now() },
      // SDKのverifyBearerTokenはexpiresAtを秒で比べる（expiresAt < Date.now() / 1000）。
      resolveOAuthOwner: async () => (resolveNull ? null : { ownerId: OWNER, grantId: GRANT, clientId: 'synthetic-client', scopes: [STTD_SCOPE], expiresAt: Math.floor(Date.now() / 1000) + 3600 }),
      subscriptions: {
        subscribe: (...args) => {
          calls.subscribe += 1;
          return subscribe(...args);
        },
        unsubscribe: async () => {
          calls.unsubscribe += 1;
        },
      },
      onError: (category) => errors.push(category),
      ...(budgetMs === undefined ? {} : { budgetMs }),
    },
    audit,
  );
  return { entry, errors, calls };
}

// contractのdeliveryは`mode: 'webhook'`が必須（subscribe・unsubscribeとも）。
const subscribeParams = () => ({ name: EVENT_NAME, delivery: { mode: 'webhook', url: CALLBACK, secret: SECRET } });

/** 2026-07-28の要求ごとの_meta（SDKが必須とする版とclientCapabilities）。 */
const ENVELOPE = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };

/** JSON-RPCの応答を読む（resultかerrorのどちらか1つ、id 1）。 */
function reply(response) {
  const message = JSON.parse(response.body);
  assert.equal(message.jsonrpc, '2.0');
  assert.equal(message.id, 1);
  assert.equal('result' in message, !('error' in message));
  return message;
}

/** 1要求をmemoryのsocketで送り、statusと本文だけを返す（接続の破棄はstatus 0）。 */
function rpc(entry, method, params) {
  const server = createServer((req, res) => {
    entry.handle(req, res).catch(() => {});
  });
  const [client, side] = socketPair();
  server.emit('connection', side);
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: ENVELOPE } });
  return new Promise((resolve) => {
    const req = request(
      {
        createConnection: () => client,
        method: 'POST',
        path: '/mcp',
        host: 'connect.sttd-audit.invalid',
        headers: {
          authorization: `Bearer ${TOKEN}`,
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2026-07-28',
          'mcp-method': method,
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', () => resolve({ status: 0, body: '' }));
      },
    );
    req.on('error', () => resolve({ status: 0, body: '' }));
    req.end(body);
  });
}

const failing = (failure) => async () => {
  throw new SubscribeError(failure);
};

const CASES = [
  ['ok', undefined],
  ...['invalid_request', 'unknown_event', 'cursor_unsupported', 'destination_change_pending', 'grant_inactive', 'conflict'].map((kind) => [kind, failing({ kind })]),
  ...CALLBACK_REASONS.map((reason) => [`callback_endpoint.${reason}`, failing({ kind: 'callback_endpoint', reason })]),
  ['other', failing({ kind: 'callback_endpoint', reason: 'synthetic-unknown-reason' })],
  ['other', failing({ kind: 'synthetic-unknown-kind' })],
  [
    'other',
    async () => {
      throw new Error(`synthetic message ${CALLBACK} ${SECRET}`);
    },
  ],
  ['other', async () => ({ id: 1, refreshBefore: null })],
];

test('each subscribe is notified once with its fixed outcome, and the response equals the one without the audit', async () => {
  for (const [expected, subscribe] of CASES) {
    const notes = [];
    const audited = build({ subscribe, audit: { onSubscribe: (outcome) => notes.push(outcome) } });
    const plain = build({ subscribe });
    const a = await rpc(audited.entry, 'events/subscribe', subscribeParams());
    const p = await rpc(plain.entry, 'events/subscribe', subscribeParams());
    // handlerへ届き、portを1回呼んだ上での比較（入口の手前の拒否ではpassしない）。
    assert.deepEqual([audited.calls.subscribe, plain.calls.subscribe], [1, 1], `${expected} status=${a.status} body=${a.body.slice(0, 300)}`);
    const message = reply(a);
    assert.equal('result' in message, expected === 'ok', expected);
    if (expected === 'ok') assert.equal(message.result.id, 'synthetic-sub-id');
    assert.equal(a.status, p.status, expected);
    assert.equal(a.body, p.body, expected);
    assert.deepEqual(audited.errors, plain.errors, expected);
    assert.deepEqual(notes, [expected], `${expected} status=${a.status} body=${a.body.slice(0, 300)}`);
  }
});

test('a throwing audit does not change the response, and other methods are not notified', async () => {
  for (const [subscribe, ok] of [[undefined, true], [failing({ kind: 'grant_inactive' }), false]]) {
    const plainBuilt = build({ subscribe });
    const plain = await rpc(plainBuilt.entry, 'events/subscribe', subscribeParams());
    const thrownBuilt = build({
      subscribe,
      audit: {
        onSubscribe: () => {
          throw new Error('synthetic audit failure');
        },
      },
    });
    const thrown = await rpc(thrownBuilt.entry, 'events/subscribe', subscribeParams());
    assert.deepEqual([plainBuilt.calls.subscribe, thrownBuilt.calls.subscribe], [1, 1]);
    assert.equal('result' in reply(thrown), ok);
    assert.equal(thrown.status, plain.status);
    assert.equal(thrown.body, plain.body);
  }
  const notes = [];
  const { entry, calls } = build({ audit: { onSubscribe: (outcome) => notes.push(outcome) } });
  for (const [method, params] of [
    ['tools/list', {}],
    ['events/list', {}],
    ['events/unsubscribe', { name: EVENT_NAME, delivery: { mode: 'webhook', url: CALLBACK } }],
  ]) {
    const response = await rpc(entry, method, params);
    assert.ok('result' in reply(response), `${method} status=${response.status} body=${response.body.slice(0, 300)}`);
  }
  assert.deepEqual(calls, { subscribe: 0, unsubscribe: 1 });
  assert.deepEqual(notes, []);
});

test('a subscribe cut by the request deadline is notified once as context_unavailable', async () => {
  const notes = [];
  const { entry, calls } = build({ subscribe: () => new Promise(() => {}), budgetMs: 200, audit: { onSubscribe: (outcome) => notes.push(outcome) } });
  const response = await rpc(entry, 'events/subscribe', subscribeParams());
  await sleep(50);
  // SDKへ渡した後の期限は、応答を書かずに接続を終える。
  assert.equal(response.status, 0);
  assert.equal(calls.subscribe, 1);
  assert.deepEqual(notes, ['context_unavailable']);
});

test('a subscribe rejected before the handler is notified once as request_rejected; port 0; other methods are not', async () => {
  const bad = { name: EVENT_NAME, delivery: { mode: 'webhook', url: CALLBACK } };
  const rejected = [
    // SDKのparams検証（secretなし）: JSON-RPCのInvalid params。
    [{}, 'events/subscribe', bad, (response) => assert.equal(reply(response).error.code, -32602)],
    // 認証の失敗（resolverがnull）: SDKのBearerの401。
    [{ resolveNull: true }, 'events/subscribe', subscribeParams(), (response) => assert.equal(response.status, 401)],
  ];
  for (const [options, method, params, check] of rejected) {
    const notes = [];
    const built = build({ audit: { onSubscribe: (outcome) => notes.push(outcome) }, ...options });
    const plain = build(options);
    const a = await rpc(built.entry, method, params);
    const p = await rpc(plain.entry, method, params);
    check(a);
    assert.equal(a.status, p.status);
    assert.equal(a.body, p.body);
    assert.deepEqual([built.calls.subscribe, plain.calls.subscribe], [0, 0]);
    assert.deepEqual(notes, ['request_rejected']);
  }
  // 別methodの不正な要求は通知しない。
  const notes = [];
  const { entry } = build({ audit: { onSubscribe: (outcome) => notes.push(outcome) } });
  assert.equal(reply(await rpc(entry, 'events/unsubscribe', { name: EVENT_NAME, delivery: { url: CALLBACK } })).error.code, -32602);
  assert.deepEqual(notes, []);
});

test('the audit option is plain data with only onSubscribe as a function', () => {
  const f = () => {};
  for (const audit of [{}, { onSubscribe: undefined }, { onSubscribe: f }]) assert.doesNotThrow(() => build({ audit }));
  const getter = Object.defineProperty({}, 'onSubscribe', { get: () => f, enumerable: true });
  for (const audit of [{ onSubscribe: 1 }, { onSubscribe: f, other: f }, getter, Object.create({ onSubscribe: f }), [f], null]) {
    assert.throws(() => build({ audit }), McpRequestEntryConfigError);
  }
});

test('through the diagnostic sink only fixed lines are written; unknown categories become other; no synthetic values', async () => {
  const lines = [];
  const now = Date.now();
  const sink = createDiagnosticLogSink({ until: new Date(now + 10 * 60_000).toISOString(), now: () => Date.now(), write: (line) => lines.push(line) });
  // kms-serverの配線と同じ写し方（ok→events.subscribed、他→events.subscribe_failed＋category）。
  const onSubscribe = (outcome) => sink(outcome === 'ok' ? { event: 'events.subscribed' } : { event: 'events.subscribe_failed', category: outcome });
  for (const [, subscribe] of [CASES[0], CASES[5], CASES[8], CASES[15]]) {
    const built = build({ subscribe, audit: { onSubscribe } });
    reply(await rpc(built.entry, 'events/subscribe', subscribeParams()));
    assert.equal(built.calls.subscribe, 1);
  }
  sink({ event: 'events.subscribe_failed', category: 'synthetic-free-text', url: CALLBACK, ownerId: OWNER });
  sink({ event: 'events.subscribed', category: 'grant_inactive', grantId: GRANT });
  assert.deepEqual(
    lines.map((line) => JSON.parse(line)),
    [
      { event: 'events.subscribed' },
      { event: 'events.subscribe_failed', category: 'grant_inactive' },
      { event: 'events.subscribe_failed', category: 'callback_endpoint.timeout' },
      { event: 'events.subscribe_failed', category: 'other' },
      { event: 'events.subscribe_failed', category: 'other' },
      { event: 'events.subscribed' },
    ],
  );
  assert.ok(!lines.join('\n').match(/synthetic|invalid|secret|owner|grant-|token|message|url/i));
  const server = readFileSync(new URL('../dist/connect/kms-server.js', import.meta.url), 'utf8');
  assert.ok(server.includes("'events.subscribed'") && server.includes("'events.subscribe_failed'"));
});
