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

function build({ subscribe = async () => ({ id: 'synthetic-sub-id', refreshBefore: null }), audit, budgetMs, resolveNull = false, receivingStatus, resolved, clock = { now: () => Date.now() } } = {}) {
  const errors = [];
  const calls = { subscribe: 0, unsubscribe: 0 };
  // 照会portの呼出しは非列挙で持つ（既存のcallsの完全一致の検査を変えない）。
  Object.defineProperty(calls, 'status', { value: [], enumerable: false });
  const entry = createRequestScopedMcpEntry(
    {
      issuer: ISSUER,
      resource: RESOURCE,
      clock,
      // SDKのverifyBearerTokenはexpiresAtを秒で比べる（expiresAt < Date.now() / 1000）。
      resolveOAuthOwner: async () =>
        resolveNull ? null : { ownerId: OWNER, grantId: GRANT, clientId: 'synthetic-client', scopes: [STTD_SCOPE], expiresAt: Math.floor(Date.now() / 1000) + 3600, ...resolved },
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
      ...(receivingStatus === undefined
        ? {}
        : {
            receivingStatus: {
              statusFor: (...args) => {
                calls.status.push(args);
                return receivingStatus(...args);
              },
            },
          }),
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
function rpc(entry, method, params, extraHeaders = {}) {
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
          ...extraHeaders,
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

// ---------- get_receiving_status（状態照会portを渡された入口だけ） ----------
const TOOL = 'get_receiving_status';
const callTool = (entry, params) => rpc(entry, 'tools/call', params, { 'mcp-name': typeof params.name === 'string' ? params.name : 'x' });
const EXPECTED_TOOL = {
  name: TOOL,
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  outputSchema: { type: 'object', properties: { state: { type: 'string', enum: ['change_pending', 'subscribed', 'expired', 'linked'] } }, required: ['state'], additionalProperties: false },
  annotations: { title: 'Get receiving status', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

test('R01 discovery: without a status port tools/list stays empty and tools/call is not provided; with the port exactly one read-only tool', async () => {
  const plain = build();
  const listed = reply(await rpc(plain.entry, 'tools/list', {}));
  assert.deepEqual(listed.result.tools, []);
  const missing = reply(await callTool(plain.entry, { name: TOOL }));
  assert.ok('error' in missing);
  assert.equal(missing.error.code, -32601, 'method not found without the port');

  const withPort = build({ receivingStatus: async () => 'linked' });
  const tools = reply(await rpc(withPort.entry, 'tools/list', {})).result.tools;
  assert.equal(tools.length, 1);
  const [tool] = tools;
  assert.deepEqual({ name: tool.name, inputSchema: tool.inputSchema, outputSchema: tool.outputSchema, annotations: tool.annotations }, EXPECTED_TOOL);
  assert.equal(tool.title, 'Get receiving status');
  assert.match(tool.description, /receiving status|ready to receive/i);
  assert.match(tool.description, /account-level/);
  assert.match(tool.description, /read-only/i);
  assert.deepEqual(withPort.calls.status, [], 'listing performs no status I/O');
  // 状態照会portは決まった形だけ（statusForのmethod）。
  for (const receivingStatus of [{}, { statusFor: 1 }, Object.defineProperty({}, 'statusFor', { get: () => async () => 'linked' })]) {
    assert.throws(
      () =>
        createRequestScopedMcpEntry({
          issuer: ISSUER,
          resource: RESOURCE,
          clock: { now: () => Date.now() },
          resolveOAuthOwner: async () => null,
          subscriptions: { subscribe: async () => ({}), unsubscribe: async () => {} },
          onError: () => {},
          receivingStatus,
        }),
      McpRequestEntryConfigError,
    );
  }
});

test('R02 call: arguments omitted and {} both succeed; structured and text results carry the same single state; the port gets only the authenticated owner/Grant and the request operation', async () => {
  for (const state of ['linked', 'subscribed', 'expired', 'change_pending']) {
    for (const params of [{ name: TOOL }, { name: TOOL, arguments: {} }]) {
      const built = build({ receivingStatus: async () => state });
      const response = await callTool(built.entry, params);
      const message = reply(response);
      assert.ok('result' in message, `${state} ${response.body.slice(0, 300)}`);
      const { result } = message;
      assert.deepEqual(result.structuredContent, { state });
      assert.equal(result.isError, false);
      assert.deepEqual(result.content, [{ type: 'text', text: JSON.stringify({ state }) }]);
      assert.equal(built.calls.status.length, 1);
      const [auth, operation] = built.calls.status[0];
      assert.deepEqual(auth, { ownerId: OWNER, grantId: GRANT });
      assert.ok(Object.isFrozen(auth));
      assert.deepEqual(Object.keys(operation).sort(), ['deadlineAt', 'signal']);
      assert.ok(operation.signal instanceof AbortSignal);
      assert.ok(!response.body.includes(OWNER) && !response.body.includes(GRANT) && !response.body.includes(TOKEN));
    }
  }
});

test('R03 unknown tool, extra or mistyped arguments: errors with status I/O 0', async () => {
  const built = build({ receivingStatus: async () => 'subscribed' });
  for (const params of [
    { name: 'get_receiving_status_v2' },
    { name: 'send_text' },
    { name: TOOL, arguments: { owner: OWNER } },
    { name: TOOL, arguments: { state: 'subscribed' } },
    { name: TOOL, arguments: [] },
    { name: TOOL, arguments: 'x' },
    { name: TOOL, arguments: null },
    { name: 1 },
  ]) {
    const response = await callTool(built.entry, params);
    const message = JSON.parse(response.body || '{}');
    assert.ok(response.status !== 200 || 'error' in message, `${JSON.stringify(params)} ${response.body.slice(0, 200)}`);
    assert.ok(!('result' in message));
    assert.ok(!/subscribed|linked|expired|change_pending/.test(response.body.replace(/"state"/g, '')), 'no state in the error');
  }
  assert.equal(built.calls.status.length, 0);
});

test('R04 port failures and request end: fixed errors without a state or internal values; revoked -> existing Forbidden access_revoked; deadline/close -> no success', async () => {
  const leak = `${OWNER} ${GRANT} ${CALLBACK} ${SECRET}`;
  const cases = [
    [async () => Promise.reject(new SubscribeError({ kind: 'grant_inactive' })), (error) => assert.equal(error.data?.reason, 'access_revoked')],
    [async () => Promise.reject(new SubscribeError({ kind: 'conflict' })), (error) => assert.equal(error.message, 'Subscription changed concurrently')],
    [async () => Promise.reject(new Error(`synthetic ${leak}`)), (error) => assert.equal(error.message, 'Internal error')],
    [async () => 'unlinked', (error) => assert.equal(error.message, 'Internal error')],
    [async () => ({ state: 'subscribed' }), (error) => assert.equal(error.message, 'Internal error')],
  ];
  for (const [receivingStatus, check] of cases) {
    const built = build({ receivingStatus });
    const response = await callTool(built.entry, { name: TOOL });
    const message = reply(response);
    assert.ok('error' in message, response.body.slice(0, 300));
    check(message.error);
    assert.equal(built.calls.status.length, 1);
    assert.ok(!response.body.includes('synthetic') && !response.body.includes(OWNER) && !response.body.includes(GRANT));
    assert.ok(!/"state"/.test(response.body));
  }
  // grant_inactiveは既存のForbidden（events/subscribeと同じcode・reason）。
  const revoked = build({ receivingStatus: async () => Promise.reject(new SubscribeError({ kind: 'grant_inactive' })) });
  const subscribeRevoked = build({ subscribe: failing({ kind: 'grant_inactive' }) });
  const a = reply(await callTool(revoked.entry, { name: TOOL })).error;
  const b = reply(await rpc(subscribeRevoked.entry, 'events/subscribe', subscribeParams())).error;
  assert.deepEqual([a.code, a.message, a.data], [b.code, b.message, b.data]);
  // 期限: 応答を書かずに接続を終える（成功を返さない）。
  const late = build({ receivingStatus: () => new Promise(() => {}), budgetMs: 200 });
  assert.equal((await callTool(late.entry, { name: TOOL })).status, 0);
  // 遅い成功: portの値が返る前に期限を過ぎたら採用しない。
  const slow = build({ receivingStatus: () => new Promise((resolve) => setTimeout(() => resolve('subscribed'), 400)), budgetMs: 200 });
  const slowResponse = await callTool(slow.entry, { name: TOOL });
  assert.equal(slowResponse.status, 0);
  // close: 進行中の照会は成功を返さず、以後は固定の503。
  let started;
  const reached = new Promise((resolve) => {
    started = resolve;
  });
  const closing = build({
    receivingStatus: () =>
      new Promise((resolve) => {
        started();
        setTimeout(() => resolve('subscribed'), 100);
      }),
  });
  const pending = callTool(closing.entry, { name: TOOL });
  await reached;
  await closing.entry.close();
  const closed = await pending;
  assert.ok(closed.status === 0 || !/"result"/.test(closed.body), `${closed.status} ${closed.body.slice(0, 200)}`);
  assert.equal((await callTool(closing.entry, { name: TOOL })).status, 503);
  // 未認証: SDKの401（port 0）。scope不足・別resourceはSDKのBearer検証で拒否（port 0）。
  const unauth = build({ resolveNull: true, receivingStatus: async () => 'linked' });
  assert.equal((await callTool(unauth.entry, { name: TOOL })).status, 401);
  const noScope = build({ resolved: { scopes: ['openid'] }, receivingStatus: async () => 'linked' });
  assert.equal((await callTool(noScope.entry, { name: TOOL })).status, 403);
  const expired = build({ resolved: { expiresAt: Math.floor(Date.now() / 1000) - 10 }, receivingStatus: async () => 'linked' });
  assert.equal((await callTool(expired.entry, { name: TOOL })).status, 401);
  assert.deepEqual([unauth.calls.status.length, noScope.calls.status.length, expired.calls.status.length], [0, 0, 0]);
});

test('R05 access token expiry during the query: the token was valid at the start; the synthetic clock reaches exactly its expiresAt while the port is pending; the port succeeds but no state is returned', async () => {
  // SDKのBearer検証（実時計・秒）を通る期限。入口の捕捉clockだけを合成のoffsetで進める（要求期限20秒の内側）。
  const expiresAt = Math.floor(Date.now() / 1000) + 10;
  const offset = { ms: 0 };
  const clock = { now: () => Date.now() + offset.ms };
  const resolved = { expiresAt };
  const toExpiry = () => {
    offset.ms = expiresAt * 1000 - Date.now();
  };
  // 照会中に期限と等しい時刻へ進める → portの成功値を採用しない。
  const during = build({
    clock,
    resolved,
    receivingStatus: async () => {
      toExpiry();
      return 'subscribed';
    },
  });
  const response = await callTool(during.entry, { name: TOOL });
  const message = reply(response);
  assert.ok('error' in message, response.body.slice(0, 300));
  assert.equal(message.error.message, 'Access token expired');
  assert.equal(during.calls.status.length, 1, 'the port was called and succeeded');
  assert.ok(!/"state"|subscribed/.test(response.body));
  // 対照: 同じ期限のtokenで時計を進めなければ状態を返す。
  offset.ms = 0;
  const control = build({ clock, resolved, receivingStatus: async () => 'subscribed' });
  assert.deepEqual(reply(await callTool(control.entry, { name: TOOL })).result.structuredContent, { state: 'subscribed' });
  // 照会の開始前に入口の時計が期限へ達していれば、portを呼ばない（状態なし）。
  const before = build({ clock: { now: () => expiresAt * 1000 }, resolved, receivingStatus: async () => 'subscribed' });
  const refused = reply(await callTool(before.entry, { name: TOOL }));
  assert.equal(refused.error?.message, 'Access token expired');
  assert.equal(before.calls.status.length, 0);
  // 通常のイベントは従来どおり（tokenの期限検査を追加しない）: 同じ時計でもevents/listは成功する。
  assert.ok('result' in reply(await rpc(before.entry, 'events/list', {})));
});
