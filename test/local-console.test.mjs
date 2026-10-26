// ローカル配信helper（dist/console/local-server.js）をloopbackで起動し、配信・保護・限定中継を合成fetch（上流）で確かめる。実Cloud/資格/Dots/network 0。
//   - P1 設定: 公開client設定の形（https DNS origin・Firebase公開値・未知key拒否・同一origin拒否）、CLI引数。
//   - P2 配信: GET /console（言語・?langだけSet-Cookie・Secureなし・nonce埋込み・CSPは自身とFirebaseだけ）、assets、他pathは404、/connectも404、HEAD/POST拒否。
//     初期配信で上流fetchは0。
//   - P3 中継の保護: Host不一致/重複、絶対形target、nonce欠落/不一致/重複、Origin不一致、Bearer欠落/不正/重複、未許可path/method、本文上限、
//     POST /v2/commandsのContent-Type/Idempotency-Key、本文ありのGET — 全て上流呼出し0で固定の非成功。
//   - P4 中継: 5 routeの上流target/method/転送header（Authorization・Content-Type・Idempotency-Keyだけ。Cookie/Origin/nonce/Forwarded無し）、redirect:'error'、
//     応答status/本文/Content-Type/Retry-Afterの転送とSet-Cookieの非転送、上流失敗は502、browser切断で上流signalがabort、正常終了では誤abortしない。
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { after, test } from 'node:test';

import { LOCAL_NONCE_HEADER, LOCAL_REFUSAL_HEADER } from '../dist/connect/console.js';
import { ConsoleConfigFileError, validateLocalConsoleConfig } from '../dist/console/config.js';
import { DEFAULT_LOCAL_PORT, parseLocalConsoleArgs, startLocalConsole } from '../dist/console/local-server.js';

const CONFIG = {
  apiOrigin: 'https://sendtexttodotsapi-123456789012.europe-west1.run.app',
  mcpOrigin: 'https://sendtexttodots-connect-123456789012.europe-west1.run.app',
  firebase: { apiKey: 'synthetic-web-api-key', authDomain: 'sendtexttodots-test.firebaseapp.com', projectId: 'sendtexttodots-test' },
};
const ID = '0f3c2a1e-5b6d-4c7e-8f90-a1b2c3d4e5f6';
const TOKEN = 'Bearer synthetic-id-token';
const results = {};
const servers = [];
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
after(async () => {
  for (const server of servers) await server.close();
  const timers = process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
  process.stdout.write(`# LOCAL_CONSOLE_COUNTS ${JSON.stringify({ unhandled, timers, results })}\n`);
  assert.deepEqual([unhandled, timers], [0, 0]);
});

/** 合成上流fetch: 呼出しを記録し、modeに従って応答する。 */
function upstream() {
  const calls = [];
  const state = { mode: 'ok', status: 200, body: JSON.stringify({ state: 'subscribed' }), headers: { 'content-type': 'application/json; charset=utf-8', 'set-cookie': 'leak=1; Path=/', 'retry-after': '7' }, held: null };
  const fetch = async (url, init) => {
    const entry = { url, init, aborted: false };
    init.signal.addEventListener('abort', () => (entry.aborted = true), { once: true });
    calls.push(entry);
    if (state.mode === 'hold') {
      await new Promise((resolve, reject) => {
        state.held = resolve;
        init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    }
    if (state.mode === 'fail') throw new TypeError('synthetic upstream failure');
    // 応答本文はstream（chunkごと）。stream modeでは無限に近いchunkを流し、helperが累積上限でcancelすることを観測する。
    const stream = { pulled: 0, cancelled: false };
    entry.stream = stream;
    const bodyBytes = Buffer.from(state.body, 'utf8');
    const chunk = Buffer.alloc(4096, 0x61);
    const body = new ReadableStream({
      pull(controller) {
        stream.pulled += 1;
        if (state.mode === 'stream') {
          if (stream.pulled > 1000) controller.close();
          else controller.enqueue(new Uint8Array(chunk));
          return;
        }
        if (stream.pulled === 1 && bodyBytes.length > 0) controller.enqueue(new Uint8Array(bodyBytes));
        else controller.close();
      },
      cancel() {
        stream.cancelled = true;
      },
    });
    return { status: state.status, headers: { get: (name) => state.headers[name.toLowerCase()] ?? null }, body };
  };
  return { calls, state, fetch };
}

async function start(overrides = {}) {
  const up = upstream();
  const server = await startLocalConsole({ config: CONFIG, port: 0, fetch: up.fetch, ...overrides });
  servers.push(server);
  return { server, up };
}

/** 生のHTTP要求（Host等を自由に指定）。 */
function raw(port, { method = 'GET', path = '/', headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers: { ...headers, Host: host ?? `localhost:${port}` }, setHost: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const code = (response) => JSON.parse(response.body).error.code;

test('P1 config and CLI args: only the public client shape is accepted', () => {
  const ok = validateLocalConsoleConfig(CONFIG);
  assert.deepEqual(ok, CONFIG);
  assert.ok(Object.isFrozen(ok) && Object.isFrozen(ok.firebase));
  const bad = {
    unknownKey: { ...CONFIG, extra: 1 },
    missing: { apiOrigin: CONFIG.apiOrigin, mcpOrigin: CONFIG.mcpOrigin },
    httpOrigin: { ...CONFIG, apiOrigin: 'http://sendtexttodotsapi.example.org' },
    ipOrigin: { ...CONFIG, apiOrigin: 'https://203.0.113.10' },
    pathOrigin: { ...CONFIG, mcpOrigin: `${CONFIG.mcpOrigin}/mcp` },
    localhostOrigin: { ...CONFIG, mcpOrigin: 'https://localhost' },
    sameOrigin: { ...CONFIG, mcpOrigin: CONFIG.apiOrigin },
    firebaseExtra: { ...CONFIG, firebase: { ...CONFIG.firebase, databaseURL: 'x' } },
    firebaseQuote: { ...CONFIG, firebase: { ...CONFIG.firebase, apiKey: 'a"b' } },
    firebaseDomain: { ...CONFIG, firebase: { ...CONFIG.firebase, authDomain: 'localhost' } },
    array: [CONFIG],
    nul: null,
  };
  for (const [name, value] of Object.entries(bad)) assert.throws(() => validateLocalConsoleConfig(value), (error) => error instanceof ConsoleConfigFileError && error.code === 'invalid', name);
  assert.deepEqual(parseLocalConsoleArgs(['--config', 'c.json']), { configPath: 'c.json', port: DEFAULT_LOCAL_PORT });
  assert.deepEqual(parseLocalConsoleArgs(['--port', '9000', '--config', 'c.json']), { configPath: 'c.json', port: 9000 });
  for (const argv of [[], ['--config'], ['--config', 'c.json', '--port', '80'], ['--config', 'c.json', '--origin', 'x'], ['c.json']]) assert.throws(() => parseLocalConsoleArgs(argv), ConsoleConfigFileError, JSON.stringify(argv));
  assert.equal(DEFAULT_LOCAL_PORT, 8765);
  results.P1 = { rejected: Object.keys(bad).length };
});

test('P2 serving: the page, script and style come from localhost only; language by ?lang/cookie/Accept-Language; Set-Cookie only for ?lang and without Secure; nonce embedded; unknown paths (including /connect) are 404; no upstream call for any of it', async () => {
  const { server, up } = await start();
  assert.match(server.origin, /^http:\/\/localhost:\d+$/);
  const page = await raw(server.port, { path: '/console' });
  assert.equal(page.status, 200);
  assert.ok(page.body.startsWith('<!DOCTYPE html>\n<html lang="en">'));
  assert.ok(page.body.includes(`data-sttd-local-nonce="${server.nonce}"`) && /^[a-f0-9]{64}$/.test(server.nonce));
  assert.ok(page.body.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax"'), 'http: no Secure');
  assert.equal(page.headers['set-cookie'], undefined, 'no cookie without an explicit choice');
  const csp = page.headers['content-security-policy'];
  assert.ok(csp.includes("connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com;") && !csp.includes('run.app'), 'the page talks to the helper and Firebase only');
  assert.deepEqual([page.headers['x-frame-options'], page.headers['cache-control']], ['DENY', 'no-store']);
  const ja = await raw(server.port, { path: '/console', headers: { 'Accept-Language': 'ja-JP,ja;q=0.9,en;q=0.5' } });
  assert.ok(ja.body.startsWith('<!DOCTYPE html>\n<html lang="ja">'));
  const chosen = await raw(server.port, { path: '/console?lang=ja', headers: { 'Accept-Language': 'en' } });
  assert.ok(chosen.body.startsWith('<!DOCTYPE html>\n<html lang="ja">'));
  assert.deepEqual(chosen.headers['set-cookie'], ['sttd_language=ja; Path=/; SameSite=Lax']);
  const cookie = await raw(server.port, { path: '/console', headers: { Cookie: 'sttd_language=ja', 'Accept-Language': 'en' } });
  assert.ok(cookie.body.startsWith('<!DOCTYPE html>\n<html lang="ja">'));
  const script = await raw(server.port, { path: '/console/app.js' });
  assert.deepEqual([script.status, script.headers['content-type']], [200, 'text/javascript; charset=utf-8']);
  assert.ok(script.body.includes("import(SDK_BASE + 'firebase-app.js')"), 'the SDK is imported lazily by the script');
  const style = await raw(server.port, { path: '/console/app.css' });
  assert.deepEqual([style.status, style.headers['content-type']], [200, 'text/css; charset=utf-8']);
  for (const path of ['/', '/connect', '/connect/app.js', '/interaction/x', '/mcp', '/oauth/authorize', '/v1/web/other', '/v2/other']) {
    const response = await raw(server.port, { path });
    assert.deepEqual([response.status, code(response)], [404, 'not_found'], path);
  }
  const post = await raw(server.port, { method: 'POST', path: '/console' });
  assert.deepEqual([post.status, code(post)], [405, 'method_not_allowed']);
  // 手順2のプラグイン追加ガイドは、helperの検証済み設定のMCP originへ/mcpを付けた登録先だけを表示する（API originは載せない）。
  assert.ok(page.body.includes(`<code id="sttd-plugin-url" class="sttd-plugin-url">${CONFIG.mcpOrigin}/mcp</code>`));
  assert.equal(page.body.includes(CONFIG.apiOrigin), false, 'the API origin is not offered for registration');
  assert.equal(page.body.includes(`${server.origin}/mcp`), false, 'the local page is not offered for registration');
  assert.equal(up.calls.length, 0, 'serving never calls upstream');
  results.P2 = { nonceLength: server.nonce.length };
});

test('P3 relay protection: every defect is refused before any upstream call', async () => {
  const { server, up } = await start();
  const port = server.port;
  const good = { Authorization: TOKEN, [LOCAL_NONCE_HEADER]: server.nonce };
  const cases = [
    ['host mismatch', { path: '/v1/web/connection', headers: good, host: `127.0.0.1:${port}` }, 400, 'invalid_request'],
    ['host other port', { path: '/v1/web/connection', headers: good, host: `localhost:${port + 1}` }, 400, 'invalid_request'],
    ['host dns rebinding', { path: '/v1/web/connection', headers: good, host: 'attacker.example' }, 400, 'invalid_request'],
    ['absolute target', { path: `http://localhost:${port}/v1/web/connection`, headers: good }, 400, 'invalid_request'],
    // 古いtab（別起動のnonce）・別originは画面の再読込みを案内する固定のlocal code。
    ['nonce missing', { path: '/v1/web/connection', headers: { Authorization: TOKEN } }, 403, 'local_reload_required'],
    ['nonce wrong', { path: '/v1/web/connection', headers: { Authorization: TOKEN, [LOCAL_NONCE_HEADER]: 'b'.repeat(64) } }, 403, 'local_reload_required'],
    ['origin other', { path: '/v1/web/connection', headers: { ...good, Origin: 'http://localhost:1' } }, 403, 'local_reload_required'],
    ['origin https', { path: '/v1/web/connection', headers: { ...good, Origin: `https://localhost:${port}` } }, 403, 'local_reload_required'],
    ['origin null', { path: '/v1/web/connection', headers: { ...good, Origin: 'null' } }, 403, 'local_reload_required'],
    ['bearer missing', { path: '/v1/web/connection', headers: { [LOCAL_NONCE_HEADER]: server.nonce } }, 401, 'authentication_required'],
    ['bearer basic', { path: '/v1/web/connection', headers: { ...good, Authorization: 'Basic abc' } }, 401, 'authentication_required'],
    ['bearer bad chars', { path: '/v1/web/connection', headers: { ...good, Authorization: 'Bearer a b' } }, 401, 'authentication_required'],
    ['method on web route', { method: 'POST', path: '/v1/web/connection', headers: good }, 405, 'method_not_allowed'],
    ['method on disconnect', { method: 'GET', path: '/v1/web/disconnect', headers: good }, 405, 'method_not_allowed'],
    ['method on commands', { method: 'GET', path: '/v2/commands', headers: good }, 405, 'method_not_allowed'],
    ['delete commands', { method: 'DELETE', path: `/v2/commands/${ID}`, headers: good }, 405, 'method_not_allowed'],
    ['unknown api path', { path: '/v2/commands/not-a-uuid', headers: good }, 404, 'not_found'],
    ['v1 commands', { method: 'POST', path: '/v1/commands', headers: { ...good, 'Content-Type': 'application/json' }, body: '{}' }, 404, 'not_found'],
    // GETに本文（chunked）を付けた要求: helperは本文を示すheaderで上流呼出しの前に400を返す（NodeのHTTP parserも後からこの要求を拒否し接続を切るため、応答本文は届かないことがある）。
    ['body on GET', { path: '/v1/web/connection', headers: { ...good, 'Content-Type': 'application/json' }, body: '{}' }, 400, null],
    ['content-length on GET', { path: '/v1/web/connection', headers: { ...good, 'Content-Length': '2' }, body: '{}' }, 400, null],
    ['body on POST without body route', { method: 'POST', path: '/v1/web/disconnect', headers: { ...good, 'Content-Type': 'application/json' }, body: '{}' }, 400, 'invalid_request'],
    ['commands without content-type', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Idempotency-Key': ID }, body: '{}' }, 400, 'invalid_request'],
    ['commands wrong content-type', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'text/plain', 'Idempotency-Key': ID }, body: '{}' }, 400, 'invalid_request'],
    ['commands without idempotency key', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json' }, body: '{}' }, 400, 'invalid_request'],
    ['commands bad idempotency key', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json', 'Idempotency-Key': 'x' }, body: '{}' }, 400, 'invalid_request'],
    ['commands empty body', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json', 'Idempotency-Key': ID } }, 400, 'invalid_request'],
    ['commands oversized (over 32 KiB)', { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json', 'Idempotency-Key': ID }, body: 'x'.repeat(32769) }, 413, 'payload_too_large'],
  ];
  for (const [name, options, status, expectedCode] of cases) {
    const response = await raw(port, options);
    assert.deepEqual([response.status, expectedCode === null ? null : code(response)], [status, expectedCode], name);
    // helper自身の送出前の拒否には固定のlocal headerが付く（画面はこれだけで未送信と判定する）。
    if (expectedCode !== null) assert.equal(response.headers[LOCAL_REFUSAL_HEADER.toLowerCase()], '1', `${name}: helper refusal marker`);
  }
  // 重複header（nonce・Authorization）はrawで2件送る。
  for (const [name, header, value] of [['duplicate nonce', LOCAL_NONCE_HEADER, server.nonce], ['duplicate authorization', 'Authorization', TOKEN]]) {
    const response = await new Promise((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, method: 'GET', path: '/v1/web/connection', setHost: false, headers: { Host: `localhost:${port}`, Authorization: TOKEN, [LOCAL_NONCE_HEADER]: server.nonce } }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject);
      req.setHeader(header, [value, value]);
      req.end();
    });
    assert.equal(response.status, 400, name);
  }
  assert.equal(up.calls.length, 0, 'no upstream call for any refused request');
  results.P3 = { refused: cases.length + 2 };
});

test('P4 relay: each allowed route reaches its fixed upstream with only the fixed headers; redirect error; response status/body/Content-Type/Retry-After forwarded, Set-Cookie not; upstream failure is 502; a client disconnect aborts the upstream; a normal completion does not', async () => {
  const { server, up } = await start();
  const port = server.port;
  const good = { Authorization: TOKEN, [LOCAL_NONCE_HEADER]: server.nonce, Cookie: 'sttd_language=ja; other=1', Origin: server.origin, 'X-Forwarded-For': '203.0.113.9', Referer: `${server.origin}/console` };
  const routes = [
    [{ path: '/v1/web/connection', headers: good }, 'GET', `${CONFIG.mcpOrigin}/v1/web/connection`, undefined],
    [{ method: 'POST', path: '/v1/web/disconnect', headers: good }, 'POST', `${CONFIG.mcpOrigin}/v1/web/disconnect`, undefined],
    [{ method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json; charset=utf-8', 'Idempotency-Key': ID }, body: '{"schemaVersion":2}' }, 'POST', `${CONFIG.apiOrigin}/v2/commands`, '{"schemaVersion":2}'],
    [{ path: `/v2/commands/${ID}`, headers: good }, 'GET', `${CONFIG.apiOrigin}/v2/commands/${ID}`, undefined],
    [{ method: 'POST', path: `/v2/commands/${ID}/cancel`, headers: good }, 'POST', `${CONFIG.apiOrigin}/v2/commands/${ID}/cancel`, undefined],
  ];
  for (const [options, method, target, body] of routes) {
    const response = await raw(port, options);
    const call = up.calls.at(-1);
    assert.deepEqual([call.url, call.init.method, call.init.redirect, call.init.credentials, call.init.cache], [target, method, 'error', 'omit', 'no-store'], options.path);
    const expectedHeaders = body === undefined ? { Authorization: TOKEN } : { Authorization: TOKEN, 'Content-Type': 'application/json', 'Idempotency-Key': ID };
    assert.deepEqual(call.init.headers, expectedHeaders, `${options.path}: only fixed headers forwarded (no Cookie/Origin/nonce/Forwarded/Referer)`);
    assert.equal(call.init.body === undefined ? undefined : Buffer.from(call.init.body).toString('utf8'), body, `${options.path}: body`);
    assert.equal(call.init.signal.aborted, false, 'a normal completion does not abort the upstream');
    assert.deepEqual([response.status, response.body, response.headers['content-type'], response.headers['retry-after']], [200, JSON.stringify({ state: 'subscribed' }), 'application/json; charset=utf-8', '7']);
    assert.equal(response.headers['set-cookie'], undefined, 'Set-Cookie from upstream is not forwarded');
    assert.deepEqual([response.headers['cache-control'], response.headers['x-content-type-options']], ['no-store', 'nosniff']);
  }
  assert.equal(up.calls.length, 5);
  // 上流のstatus/本文はそのまま（429 + Retry-After、404）。
  Object.assign(up.state, { status: 429, body: JSON.stringify({ error: { code: 'rate_limited', retryable: true } }), headers: { 'content-type': 'application/json; charset=utf-8', 'retry-after': '30' } });
  const limited = await raw(port, { path: `/v2/commands/${ID}`, headers: good });
  assert.deepEqual([limited.status, code(limited), limited.headers['retry-after']], [429, 'rate_limited', '30']);
  Object.assign(up.state, { status: 404, body: JSON.stringify({ error: { code: 'not_found', retryable: false } }), headers: { 'content-type': 'application/json; charset=utf-8' } });
  const missing = await raw(port, { path: `/v2/commands/${ID}`, headers: good });
  assert.deepEqual([missing.status, code(missing), missing.headers['retry-after']], [404, 'not_found', undefined]);
  // 上流が同名のheader・codeを返しても転送しない（上流の応答をhelperの送出前拒否に偽装できない）。利用許可の拒否もそのまま。
  Object.assign(up.state, { status: 403, body: JSON.stringify({ error: { code: 'local_reload_required', retryable: false } }), headers: { 'content-type': 'application/json; charset=utf-8', [LOCAL_REFUSAL_HEADER.toLowerCase()]: '1' } });
  const spoofed = await raw(port, { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json', 'Idempotency-Key': ID }, body: '{}' });
  assert.deepEqual([spoofed.status, code(spoofed), spoofed.headers[LOCAL_REFUSAL_HEADER.toLowerCase()]], [403, 'local_reload_required', undefined]);
  Object.assign(up.state, { status: 200, body: JSON.stringify({ state: 'subscribed', access: 'allowed' }), headers: { 'content-type': 'application/json; charset=utf-8' } });
  const withAccess = await raw(port, { path: '/v1/web/connection', headers: good });
  assert.deepEqual([withAccess.status, JSON.parse(withAccess.body), withAccess.headers[LOCAL_REFUSAL_HEADER.toLowerCase()]], [200, { state: 'subscribed', access: 'allowed' }, undefined]);
  // 上流失敗 → 502（固定）。上流を呼んだ後なのでlocalの印は付けない（結果不明のまま）。
  up.state.mode = 'fail';
  const failed = await raw(port, { path: '/v1/web/connection', headers: good });
  assert.deepEqual([failed.status, code(failed), failed.headers[LOCAL_REFUSAL_HEADER.toLowerCase()]], [502, 'upstream_unavailable', undefined]);
  // browser切断 → 上流signalがabort。
  up.state.mode = 'hold';
  const aborted = await new Promise((resolve) => {
    const req = httpRequest({ host: '127.0.0.1', port, method: 'GET', path: '/v1/web/connection', setHost: false, headers: { Host: `localhost:${port}`, ...good } });
    req.on('error', () => resolve('error'));
    req.on('response', () => resolve('response'));
    req.end();
    const wait = setInterval(() => {
      if (up.state.held !== null) {
        clearInterval(wait);
        req.destroy();
      }
    }, 5);
  });
  assert.equal(aborted, 'error');
  for (let i = 0; i < 50 && !up.calls.at(-1).aborted; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(up.calls.at(-1).aborted, true, 'client disconnect propagates to the upstream signal');
  up.state.mode = 'ok';
  up.state.held = null;
  results.P4 = { upstreamCalls: up.calls.length };
});

test('P5 bounds: a legitimate 4096-byte text whose JSON escapes to several times that size is relayed (32 KiB JSON limit); an upstream body that streams past 64 KiB is cancelled at the limit and answered with a fixed 502; a lying Content-Length over the limit is refused before reading', async () => {
  const { server, up } = await start();
  const port = server.port;
  const good = { Authorization: TOKEN, [LOCAL_NONCE_HEADER]: server.nonce };
  // text: 'a' + 4095個の改行 = 4096 UTF-8 byte（空白だけではない）。JSONでは改行が \\n に膨らむ。
  const text = `a${'\n'.repeat(4095)}`;
  assert.equal(Buffer.byteLength(text, 'utf8'), 4096);
  const payload = JSON.stringify({ schemaVersion: 2, commandId: ID, text, createdAt: '2026-10-26T00:00:00Z', expiresAt: '2026-10-26T00:01:00Z' });
  assert.ok(Buffer.byteLength(payload, 'utf8') > 8192 && Buffer.byteLength(payload, 'utf8') <= 32768, `escaped payload ${Buffer.byteLength(payload, 'utf8')} bytes`);
  const quoted = JSON.stringify({ schemaVersion: 2, commandId: ID, text: '"'.repeat(4096), createdAt: '2026-10-26T00:00:00Z', expiresAt: '2026-10-26T00:01:00Z' });
  for (const body of [payload, quoted]) {
    const response = await raw(port, { method: 'POST', path: '/v2/commands', headers: { ...good, 'Content-Type': 'application/json', 'Idempotency-Key': ID }, body });
    assert.equal(response.status, 200, 'legitimate payload relayed');
    assert.equal(Buffer.from(up.calls.at(-1).init.body).toString('utf8'), body, 'body forwarded byte for byte');
  }
  // 上流がstreamで64 KiB超を流す → 上限でcancel/abortし、固定502。読み込みは上限付近で止まる（1000 chunk = 4 MiBは読まない）。
  up.state.mode = 'stream';
  const flooded = await raw(port, { path: `/v2/commands/${ID}`, headers: good });
  assert.deepEqual([flooded.status, code(flooded)], [502, 'upstream_unavailable']);
  const call = up.calls.at(-1);
  assert.ok(call.stream.cancelled && call.aborted, 'reader cancelled and upstream aborted');
  assert.ok(call.stream.pulled >= 17 && call.stream.pulled <= 20, `stopped near the limit (${call.stream.pulled} chunks of 4 KiB)`);
  up.state.mode = 'ok';
  // Content-Lengthが上限超を宣言 → 読む前に502。
  Object.assign(up.state, { headers: { ...up.state.headers, 'content-length': String(65537) } });
  const declared = await raw(port, { path: `/v2/commands/${ID}`, headers: good });
  assert.deepEqual([declared.status, code(declared)], [502, 'upstream_unavailable']);
  // ReadableStreamは構築時にpullを1回先読みするため、helperがreaderを取らなくてもpulledは最大1。それ以上読まれず、上流は中止される。
  assert.ok(up.calls.at(-1).stream.pulled <= 1, `body not consumed when the declared length exceeds the limit (${up.calls.at(-1).stream.pulled})`);
  assert.equal(up.calls.at(-1).aborted, true, 'upstream aborted on a declared length over the limit');
  results.P5 = { escapedPayloadBytes: Buffer.byteLength(payload, 'utf8'), floodedChunks: call.stream.pulled };
});
