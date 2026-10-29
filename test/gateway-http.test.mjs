// gatewayのHTTP中継（dist/gateway/http.js・google-iam.js）を、所有の127.0.0.1 listener（gateway・合成echo backend）と合成IAM portで
// 検査する。転送の保持（method・生target・本文bytes・利用者header・多値）と除去/再構成（Forwarded・内部header・hop-by-hop）、応答の保持
// （status・複数Set-Cookie・WWW-Authenticate・Location・CORS）・redirect/再送0、拒否（route・framing・上限・rate・slot・IAM失敗/期限・
// 切断・backend名の露出）でbackend到達0・token取得0を確かめる。実IAM・Cloud・SDK・外部network 0。listenerは各run最大20。

import assert from 'node:assert/strict';
import http from 'node:http';
import { after, test } from 'node:test';

import { createIdTokenSource } from '../dist/gateway/google-iam.js';
import { createGatewayHandler } from '../dist/gateway/http.js';
import { BACKEND, closeAll, echoBackend, iamFetcher, listen, listenerCount, rawRequest, request, syntheticIdToken } from './fixtures/gateway-runtime.mjs';

after(async () => {
  await closeAll();
  assert.ok(listenerCount() <= 20);
});

const BACKEND_HOST = new URL(BACKEND.api).host;
const clock = { now: () => Date.now() };

/** gateway（API role・固定backend）を所有listenerで起動する。 */
async function gatewayFor(backendPort, { role = 'api', limits = {}, fetcher, fetchLimitMs, publicAuthority, now = clock } = {}) {
  const iam = iamFetcher(fetcher);
  const tokens = createIdTokenSource({ audience: role === 'api' ? BACKEND.api : BACKEND.connect, fetcher: iam.fetcher, clock: now, ...(fetchLimitMs !== undefined ? { fetchLimitMs } : {}) });
  const handler = createGatewayHandler({
    role,
    backendOrigin: role === 'api' ? BACKEND.api : BACKEND.connect,
    publicAuthority,
    limits: { maxBodyBytes: 1024, maxConcurrent: 4, ratePerSecond: 100, burst: 100, ...limits },
    tokens,
    clock: now,
    transport: (options, onResponse) => http.request(options, onResponse),
    connectTo: { host: '127.0.0.1', port: backendPort },
  });
  const { port } = await listen((req, res) => void handler.handle(req, res));
  return { port, handler, iam };
}

const pairs = (raw) => {
  const out = [];
  for (let index = 0; index < raw.length; index += 2) out.push([raw[index].toLowerCase(), raw[index + 1]]);
  return out;
};

test('正規中継: method・生target・本文bytes・利用者header（多値・順序）を保ち、転送/内部headerは除去して作り直す', async () => {
  const backend = await echoBackend();
  const gw = await gatewayFor(backend.port);
  const body = '{"text":"あ synthetic","n":1}';
  const res = await rawRequest(
    gw.port,
    [
      'POST /v2/commands?b=%2F..&a=1 HTTP/1.1',
      'Host: api.public.example.com',
      'Authorization: Bearer user-token',
      'Idempotency-Key: idem-1',
      'X-STTD-Source: src_1',
      'X-STTD-Source-Signature: sig-1',
      'Cookie: a=1',
      'Cookie: b=2',
      'Origin: https://connect.example.com',
      'Forwarded: for=203.0.113.9;host=evil.example',
      'X-Forwarded-For: 203.0.113.9',
      'X-Forwarded-Host: evil.example',
      'X-Serverless-Authorization: Bearer forged',
      'X-STTD-Gateway-Budget-Ms: 99999',
      'Connection: close, X-Drop-Me',
      'X-Drop-Me: 1',
      'Content-Type: application/json',
      `Content-Length: ${Buffer.byteLength(body)}`,
      '',
      body,
    ].join('\r\n'),
  );
  assert.equal(res.status, 200, res.text);
  assert.equal(backend.seen.length, 1);
  const seen = backend.seen[0];
  assert.equal(seen.method, 'POST');
  assert.equal(seen.url, '/v2/commands?b=%2F..&a=1');
  assert.equal(seen.body.toString('utf8'), body);
  const headers = pairs(seen.rawHeaders);
  const all = (name) => headers.filter(([key]) => key === name).map(([, value]) => value);
  assert.deepEqual(all('host'), [BACKEND_HOST]);
  assert.deepEqual(all('authorization'), ['Bearer user-token']);
  assert.deepEqual(all('idempotency-key'), ['idem-1']);
  assert.deepEqual(all('x-sttd-source'), ['src_1']);
  assert.deepEqual(all('x-sttd-source-signature'), ['sig-1']);
  assert.deepEqual(all('cookie'), ['a=1', 'b=2']);
  assert.deepEqual(all('origin'), ['https://connect.example.com']);
  assert.deepEqual(all('content-length'), [String(Buffer.byteLength(body))]);
  for (const name of ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-drop-me']) assert.deepEqual(all(name), [], name);
  // 利用者のConnection列挙は渡さない（残るのはgatewayの転送自身のclose指定だけ）。
  assert.ok(all('connection').every((value) => value.toLowerCase() === 'close'));
  const iam = all('x-serverless-authorization');
  assert.equal(iam.length, 1);
  assert.notEqual(iam[0], 'Bearer forged');
  assert.match(iam[0], /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const budget = all('x-sttd-gateway-budget-ms');
  assert.equal(budget.length, 1);
  assert.ok(Number(budget[0]) >= 1 && Number(budget[0]) <= 20_000);
  // 固定audienceだけ・tokenは共有（2回目は再取得しない）。
  assert.deepEqual(gw.iam.calls.audiences, [BACKEND.api]);
  assert.equal((await request(gw.port, { method: 'GET', path: '/v2/encryption-key', headers: { Authorization: 'Bearer user-token' } })).status, 200);
  assert.equal(gw.iam.calls.count, 1);
  assert.equal(backend.seen.length, 2);
  assert.deepEqual(pairs(backend.seen[1].rawHeaders).filter(([key]) => key === 'content-length'), [], 'GET without body has no Content-Length');
});

test('応答: status・複数Set-Cookie・WWW-Authenticate・Location・CORSを保持し、redirect追跡・401/503の再送0', async () => {
  let mode = 'redirect';
  const backend = await echoBackend((req, res) => {
    if (mode === 'redirect') {
      res.writeHead(303, [
        'Location', 'https://connect.example.com/interaction/abc',
        'Set-Cookie', '_interaction=1; Path=/interaction/abc; HttpOnly; Secure',
        'Set-Cookie', '_interaction_resume=2; Path=/oauth/authorize/abc; HttpOnly; Secure',
        'Access-Control-Allow-Origin', 'https://connect.example.com',
        'Vary', 'Origin',
        'Content-Length', '0',
      ]);
      res.end();
    } else {
      res.writeHead(mode === '401' ? 401 : 503, { 'WWW-Authenticate': 'Bearer resource_metadata="https://connect.example.com/.well-known/oauth-protected-resource/mcp"', 'Content-Type': 'application/json' });
      res.end('{"error":"x"}');
    }
  });
  const gw = await gatewayFor(backend.port, { role: 'connect', publicAuthority: 'connect.example.com' });
  const redirected = await request(gw.port, { path: '/oauth/authorize?x=1', headers: { Host: 'connect.example.com' } });
  assert.equal(redirected.status, 303);
  assert.equal(redirected.headers.location, 'https://connect.example.com/interaction/abc');
  assert.deepEqual(redirected.headers['set-cookie'], ['_interaction=1; Path=/interaction/abc; HttpOnly; Secure', '_interaction_resume=2; Path=/oauth/authorize/abc; HttpOnly; Secure']);
  assert.equal(redirected.headers['access-control-allow-origin'], 'https://connect.example.com');
  assert.equal(backend.seen.length, 1, 'redirect is not followed');
  for (const status of ['401', '503']) {
    mode = status;
    const res = await request(gw.port, { method: 'POST', path: '/mcp', headers: { Host: 'connect.example.com', 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(res.status, Number(status));
    assert.match(res.headers['www-authenticate'], /^Bearer resource_metadata=/);
    assert.equal(res.body, '{"error":"x"}');
  }
  assert.equal(backend.seen.length, 3, 'no automatic retry');
  // MCPの公開Host以外は転送前に400。
  assert.equal((await request(gw.port, { path: '/mcp', headers: { Host: 'evil.example' } })).status, 400);
  assert.equal(backend.seen.length, 3);
});

test('応答headerにbackendのauthorityが出たら返さずに固定502', async () => {
  const backend = await echoBackend((req, res) => {
    res.writeHead(302, { Location: `${BACKEND.api}/v2/commands/x` });
    res.end();
  });
  const gw = await gatewayFor(backend.port);
  const res = await request(gw.port, { method: 'GET', path: '/v2/commands/x' });
  assert.equal(res.status, 502);
  assert.equal(res.headers.location, undefined);
  assert.ok(!res.body.includes(BACKEND_HOST));
});

test('拒否: route・target・framing・上限は転送前（backend到達0・token取得0）', async () => {
  const backend = await echoBackend();
  const gw = await gatewayFor(backend.port, { limits: { maxBodyBytes: 16 } });
  const cases = [
    ['GET /health HTTP/1.1\r\nHost: a\r\n\r\n', 404],
    ['GET /v2/commands HTTP/1.1\r\nHost: a\r\n\r\n', 405],
    ['GET //evil/v2/commands HTTP/1.1\r\nHost: a\r\n\r\n', 400],
    ['GET http://evil.example/v2/encryption-key HTTP/1.1\r\nHost: a\r\n\r\n', 400],
    ['GET /v2/encryption-key HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n', 400],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}', 400],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n', 400],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n', 400],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}', 400],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nContent-Length: 18\r\n\r\n{"a":"0123456789"}', 413],
    ['POST /v2/commands HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{"a":"0123456789"}\r\n0\r\n\r\n', 413],
  ];
  for (const [text, status] of cases) {
    const res = await rawRequest(gw.port, text);
    assert.equal(res.status, status, text.split('\r\n')[0]);
    assert.ok(!res.text.includes(BACKEND_HOST));
  }
  assert.equal(backend.seen.length, 0);
  assert.equal(gw.iam.calls.count, 0);
});

test('量の制限: process内rate超過は429、同時slot超過は503（待機列0）', async () => {
  let release;
  const held = new Promise((resolve) => (release = resolve));
  const backend = await echoBackend((req, res, entry) => {
    if (entry.url === '/v2/encryption-key?hold=1') held.then(() => res.end('{}'));
    else res.end('{}');
  });
  const fixed = Date.now();
  const frozen = { now: () => fixed };
  const rate = await gatewayFor(backend.port, { limits: { burst: 2, ratePerSecond: 1 }, now: frozen });
  const statuses = [];
  for (let index = 0; index < 3; index += 1) statuses.push((await request(rate.port, { path: '/v2/encryption-key' })).status);
  assert.deepEqual(statuses, [200, 200, 429]);
  const slot = await gatewayFor(backend.port, { limits: { maxConcurrent: 1 } });
  const first = request(slot.port, { path: '/v2/encryption-key?hold=1' });
  const seenBefore = backend.seen.length;
  while (backend.seen.length === seenBefore) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal((await request(slot.port, { path: '/v2/encryption-key' })).status, 503);
  release();
  assert.equal((await first).status, 200);
  assert.equal(slot.handler.stats.active, 0);
  assert.equal((await request(slot.port, { path: '/v2/encryption-key' })).status, 200);
});

test('IAM: 取得失敗・上限超過・期限切れ・別audienceは固定503で転送0、fallback/再取得0', async () => {
  const backend = await echoBackend();
  const failing = await gatewayFor(backend.port, { fetcher: async () => Promise.reject(new Error('metadata down')) });
  assert.equal((await request(failing.port, { path: '/v2/encryption-key' })).status, 503);
  assert.equal(failing.iam.calls.count, 1);
  const hanging = await gatewayFor(backend.port, { fetcher: () => new Promise(() => undefined), fetchLimitMs: 50 });
  const slow = await request(hanging.port, { path: '/v2/encryption-key' });
  assert.equal(slow.status, 503);
  // 打ち切った取得がsettleしていない間は新しい取得を重ねない。
  assert.equal((await request(hanging.port, { path: '/v2/encryption-key' })).status, 503);
  assert.equal(hanging.iam.calls.count, 1);
  const expired = await gatewayFor(backend.port, { fetcher: async (audience) => syntheticIdToken(audience, Math.floor(Date.now() / 1000) - 10) });
  assert.equal((await request(expired.port, { path: '/v2/encryption-key' })).status, 503);
  const other = await gatewayFor(backend.port, { fetcher: async () => syntheticIdToken(BACKEND.connect, Math.floor(Date.now() / 1000) + 3600) });
  assert.equal((await request(other.port, { path: '/v2/encryption-key' })).status, 503);
  const malformed = await gatewayFor(backend.port, { fetcher: async () => 'not-a-jwt' });
  assert.equal((await request(malformed.port, { path: '/v2/encryption-key' })).status, 503);
  assert.equal(backend.seen.length, 0);
  // 既に切れた元期限・中止済みsignalでは取得しない。
  const iam = iamFetcher();
  const tokens = createIdTokenSource({ audience: BACKEND.api, fetcher: iam.fetcher, clock });
  await assert.rejects(tokens.get(Date.now() - 1, new AbortController().signal), (error) => error.code === 'timed_out');
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(tokens.get(Date.now() + 1000, aborted.signal), (error) => error.code === 'aborted');
  assert.equal(iam.calls.count, 0);
  tokens.close();
  await assert.rejects(tokens.get(Date.now() + 1000, new AbortController().signal), (error) => error.code === 'aborted');
});

test('切断・close: 本文途中の切断は転送0、close後は固定503で新しい転送0', async () => {
  const backend = await echoBackend();
  const gw = await gatewayFor(backend.port);
  await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: gw.port, method: 'POST', path: '/v2/commands', headers: { 'Content-Length': '10' }, agent: false });
    req.on('error', () => resolve());
    req.write('{"a"');
    setTimeout(() => {
      req.destroy();
      setTimeout(resolve, 50);
    }, 30);
  });
  assert.equal(backend.seen.length, 0);
  assert.equal(gw.handler.stats.active, 0);
  gw.handler.close();
  assert.equal((await request(gw.port, { path: '/v2/encryption-key' })).status, 503);
  assert.equal(backend.seen.length, 0);
  assert.equal(gw.iam.calls.count, 0);
});
