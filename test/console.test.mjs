// ローカル送信画面の固定asset・CSP・nonce検査、Functions入口の固定origin CORS、画面scriptの送信規則（同じID・期限・自動再送0）を評価する。
// importするのはpureなdist（connect/console.js・deployment/console-cors.js・connect/pages.js・config/validate.js）だけ。SDK instance・DB・資格・HTTP・子process 0。
// kms-server.js・functions.js・local-server.jsは評価せず、compile後のdist文字列で接合だけを静的に確かめる。fixtureの値は全て合成値。
// 実scriptの合成実行（5段階wizard・送信・解除・言語・コピー）はtest/console-wizard.test.mjs、helperの配信/中継はtest/local-console.test.mjs。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, test } from 'node:test';

import * as consoleModule from '../dist/connect/console.js';
import { pageSecurityHeaders } from '../dist/connect/pages.js';
import { loadDeploymentConfig } from '../dist/config/validate.js';
import { applyConsoleCors, consoleAllowedOrigin, decideConsoleCors } from '../dist/deployment/console-cors.js';

const { consoleAsset, ConsoleConfigError, CONSOLE_SCRIPT, CONSOLE_SDK_BASE, consoleSecurityHeaders, renderConsolePage } = consoleModule;
const PAGE = { nonce: 'f'.repeat(64), secure: false };
const DEPLOYMENT = loadDeploymentConfig();
const MCP = DEPLOYMENT.connect.publicOrigin;
const API = DEPLOYMENT.api.publicOrigin;
const WEB = { apiKey: 'synthetic-web-api-key', authDomain: DEPLOYMENT.web.authDomain, projectId: DEPLOYMENT.web.projectId };
assert.equal(MCP, 'https://sendtexttodots-connect-123456789012.europe-west1.run.app', 'the synthetic deployment config is in place');
const ID = '0f3c2a1e-5b6d-4c7e-8f90-a1b2c3d4e5f6';
const results = {};
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
after(() => {
  const timers = process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
  process.stdout.write(`# CONSOLE_COUNTS ${JSON.stringify({ unhandled, timers, results })}\n`);
  assert.deepEqual([unhandled, timers], [0, 0]);
});
const raw = (...pairs) => pairs.flat();

test('C1 CORS: only the fixed MCP origin on the v2 routes; preflight route/method/headers checked (204), old v1 routes and others refused; no Origin keeps native behaviour; no wildcard or credentials', () => {
  assert.equal(consoleAllowedOrigin(), MCP);
  assert.deepEqual(decideConsoleCors('POST', '/v2/commands', raw(['Authorization', 'Bearer x'])), { kind: 'none' });
  // Originの無い旧routeもCORSは何もしない（API routerの404へ進む）。
  assert.deepEqual(decideConsoleCors('POST', '/v1/commands', raw(['Authorization', 'Bearer x'])), { kind: 'none' });
  const preflight = decideConsoleCors('OPTIONS', '/v2/commands', raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'], ['Access-Control-Request-Headers', 'authorization,content-type,idempotency-key']));
  assert.deepEqual(preflight, {
    kind: 'preflight',
    headers: { 'Access-Control-Allow-Origin': MCP, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'authorization, content-type, idempotency-key', 'Access-Control-Max-Age': '600', Vary: 'Origin' },
  });
  assert.equal(decideConsoleCors('OPTIONS', `/v2/commands/${ID}`, raw(['origin', MCP], ['access-control-request-method', 'GET'], ['access-control-request-headers', 'Authorization'])).kind, 'preflight');
  assert.equal(decideConsoleCors('OPTIONS', `/v2/commands/${ID}/cancel`, raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'], ['Access-Control-Request-Headers', 'authorization'])).kind, 'preflight');
  const refused = {
    otherOrigin: decideConsoleCors('POST', '/v2/commands', raw(['Origin', 'https://evil.example'])),
    otherOriginPreflight: decideConsoleCors('OPTIONS', '/v2/commands', raw(['Origin', 'https://evil.example'], ['Access-Control-Request-Method', 'POST'])),
    nullOrigin: decideConsoleCors('POST', '/v2/commands', raw(['Origin', 'null'])),
    duplicate: decideConsoleCors('POST', '/v2/commands', raw(['Origin', MCP], ['Origin', MCP])),
    wrongMethod: decideConsoleCors('OPTIONS', '/v2/commands', raw(['Origin', MCP], ['Access-Control-Request-Method', 'GET'])),
    extraHeader: decideConsoleCors('OPTIONS', '/v2/commands', raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'], ['Access-Control-Request-Headers', 'authorization, x-debug'])),
    otherRoute: decideConsoleCors('OPTIONS', '/v2/other', raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'])),
    otherRouteReal: decideConsoleCors('GET', '/v1/web/connection', raw(['Origin', MCP])),
    v1Post: decideConsoleCors('POST', '/v1/commands', raw(['Origin', MCP])),
    v1PostPreflight: decideConsoleCors('OPTIONS', '/v1/commands', raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'])),
    v1Get: decideConsoleCors('GET', `/v1/commands/${ID}`, raw(['Origin', MCP])),
    v1Cancel: decideConsoleCors('POST', `/v1/commands/${ID}/cancel`, raw(['Origin', MCP])),
  };
  for (const [name, decision] of Object.entries(refused)) assert.equal(decision.kind, 'reject', name);
  const allow = decideConsoleCors('POST', '/v2/commands', raw(['Origin', MCP], ['Authorization', 'Bearer x']));
  assert.deepEqual(allow, { kind: 'allow', headers: { 'Access-Control-Allow-Origin': MCP, 'Access-Control-Expose-Headers': 'Retry-After', Vary: 'Origin' } });
  for (const decision of [preflight, allow]) {
    const text = JSON.stringify(decision.headers);
    assert.equal(text.includes('*') || text.includes('Credentials'), false, 'no wildcard / credentials');
  }
  results.C1 = { refused: Object.keys(refused).length };
});

test('C2 applyConsoleCors writes 204 / fixed 403 itself (caller stops before SDK init), adds headers for an allowed real request, and leaves native requests untouched', () => {
  const fakeRes = () => {
    const res = { headersSent: false, writableEnded: false, set: {}, written: null, ended: null };
    res.setHeader = (name, value) => (res.set[name] = value);
    res.writeHead = (status, headers) => (res.written = { status, headers });
    res.end = (body) => ((res.ended = body ?? null), (res.writableEnded = true));
    return res;
  };
  const req = (method, url, rawHeaders) => ({ method, url, rawHeaders });
  const pre = fakeRes();
  assert.equal(applyConsoleCors(req('OPTIONS', '/v2/commands', raw(['Origin', MCP], ['Access-Control-Request-Method', 'POST'])), pre), true);
  assert.equal(pre.written.status, 204);
  const bad = fakeRes();
  assert.equal(applyConsoleCors(req('POST', '/v2/commands', raw(['Origin', 'https://evil.example'])), bad), true);
  assert.equal(bad.written.status, 403);
  assert.equal(JSON.parse(bad.ended.toString('utf8')).error.code, 'forbidden');
  const old = fakeRes();
  assert.equal(applyConsoleCors(req('POST', '/v1/commands', raw(['Origin', MCP])), old), true, 'the old v1 route with Origin is refused before SDK init');
  assert.equal(old.written.status, 403);
  const ok = fakeRes();
  assert.equal(applyConsoleCors(req('POST', '/v2/commands', raw(['Origin', MCP])), ok), false);
  assert.deepEqual([ok.set['Access-Control-Allow-Origin'], ok.set.Vary, ok.written], [MCP, 'Origin', null]);
  const native = fakeRes();
  assert.equal(applyConsoleCors(req('POST', '/v2/commands', raw(['Authorization', 'Bearer x'])), native), false);
  assert.deepEqual([native.set, native.written], [{}, null]);
});

test('A1 /console assets (local page): fixed HTML/JS/CSS, empty textarea with an example placeholder, 5 step panels with only step 1 active, no direction UI, data attributes (nonce, firebase, cookie attributes) escaped, no inline script/style; CSP talks to self + Firebase only; the OAuth page CSP is unchanged', () => {
  const page = consoleAsset('/console', WEB, PAGE);
  assert.ok(page.body.startsWith('<!DOCTYPE html>\n<html lang="en">'), 'default language en');
  assert.ok(consoleAsset('/console', WEB, { ...PAGE, language: 'ja' }).body.startsWith('<!DOCTYPE html>\n<html lang="ja">'));
  assert.equal(page.type, 'text/html; charset=utf-8');
  assert.ok(page.body.includes(`data-sttd-local-nonce="${PAGE.nonce}"`) && page.body.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax"'));
  assert.equal(page.body.includes('data-sttd-api-origin'), false, 'the page does not carry the API origin (the helper relays)');
  assert.ok(page.body.includes('<script type="module" src="/console/app.js"></script>') && page.body.includes('<link rel="stylesheet" href="/console/app.css">'));
  assert.equal((page.body.match(/<script/g) ?? []).length, 1, 'single external module script');
  assert.equal(/\sstyle=|<style|\son[a-z]+=/i.test(page.body), false, 'no inline style / handlers');
  const textareas = [...page.body.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g)];
  assert.equal(textareas.length, 1);
  assert.ok(/\sid="sttd-text"/.test(textareas[0][1]) && /\splaceholder="[^"]+"/.test(textareas[0][1]) && /\smaxlength="4096"/.test(textareas[0][1]) && /\sdisabled/.test(textareas[0][1]));
  assert.equal(textareas[0][2], '', 'empty textarea');
  assert.equal(/<select|<option|sttd-direction|方向|上<\/|下<\/|左<\/|右<\/|direction/i.test(page.body), false, 'no direction UI');
  assert.ok(page.body.includes('id="sttd-guide-test-text"') && page.body.includes('id="sttd-guide-operation-text"') && page.body.includes('id="sttd-copy-test"') && page.body.includes('id="sttd-copy-operation"'));
  assert.equal(/<textarea[^>]*value=|<input/i.test(page.body), false, 'no preset input');
  for (const n of [1, 2, 3, 4, 5, 6, 7]) assert.ok(page.body.includes(`id="sttd-panel-${n}"`), `step ${n}`);
  assert.equal((page.body.match(/data-sttd-state="current"/g) ?? []).length, 1, 'exactly one active step at start (its panel; no separate step list)');
  assert.ok(!page.body.includes('id="sttd-steps"') && !page.body.includes('sttd-step-1-head'), 'no separate step list');
  assert.equal((page.body.match(/data-sttd-state="locked"/g) ?? []).length, 6, 'six locked steps (panels only; no separate step list)');
  assert.equal((page.body.match(/<section id="sttd-panel-[1-7]"[^>]*>/g) ?? []).length, 7, 'all seven panels present');
  assert.equal(/<section id="sttd-panel-[1-7]"[^>]*\shidden/.test(page.body), false, 'no panel is hidden; inactive ones are gray');
  assert.ok(page.body.indexOf('id="sttd-complete"') > page.body.lastIndexOf('</section>'), 'the completion banner is below all panels');
  const style = consoleAsset('/console/app.css', WEB, PAGE).body;
  assert.equal(/select/.test(style), false, 'no select-only style');
  for (const name of ['CONSOLE_TASK_ID', 'CONSOLE_TASK_LABEL', 'CONSOLE_DEFAULT_TEXT']) assert.equal(Object.hasOwn(consoleModule, name), false, `no export ${name}`);
  const csp = page.headers['Content-Security-Policy'];
  assert.equal(
    csp,
    `default-src 'none'; script-src 'self' ${CONSOLE_SDK_BASE} https://apis.google.com; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com; frame-src https://${WEB.authDomain}; style-src 'self'; img-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`,
  );
  assert.equal(/unsafe-|\*|https: |run\.app/.test(csp), false);
  assert.deepEqual([page.headers['X-Frame-Options'], page.headers['Referrer-Policy']], ['DENY', 'no-referrer']);
  const oauth = pageSecurityHeaders(WEB)['Content-Security-Policy'];
  assert.ok(oauth.includes("style-src 'none'") && !oauth.includes(API), 'existing OAuth page CSP not widened');
  assert.equal(consoleAsset('/console/app.js', WEB, PAGE).type, 'text/javascript; charset=utf-8');
  assert.equal(consoleAsset('/console/app.css', WEB, PAGE).type, 'text/css; charset=utf-8');
  assert.equal(consoleAsset('/console/other', WEB, PAGE), undefined);
  const escaped = consoleAsset('/console', { ...WEB, apiKey: '"><script>x</script>' }, PAGE).body;
  assert.ok(escaped.includes('&#34;&#62;&#60;script&#62;') && !escaped.includes('"><script>x'), 'web config escaped');
  for (const bad of [undefined, '', 'short', 'g'.repeat(64), '"><script>', 'A'.repeat(64)]) assert.throws(() => renderConsolePage(WEB, { nonce: bad, secure: false }), ConsoleConfigError, String(bad));
  assert.throws(() => consoleSecurityHeaders({ ...WEB, authDomain: 'x" y' }), ConsoleConfigError);
  results.A1 = { htmlBytes: Buffer.byteLength(page.body), csp: csp.split('; ').length };
});

test('S1 the script builds the 5-field v2 command (no task/direction/revision), same-ID Idempotency-Key, 60 s lifetime, 25 s POST / 5 s cancel, credentials omit, and has no storage, URL or polling path', () => {
  const s = CONSOLE_SCRIPT;
  const payloadAt = s.indexOf('const payload = JSON.stringify({');
  const payloadBlock = s.slice(payloadAt, s.indexOf('});', payloadAt));
  const fields = ['schemaVersion: 2,', 'commandId: current.commandId,', 'text,', 'createdAt: new Date(created).toISOString(),', 'expiresAt: new Date(created + LIFETIME_MS).toISOString(),'];
  assert.deepEqual(
    payloadBlock.split('\n').slice(1).map((line) => line.trim()).filter(Boolean),
    fields,
    'exactly the 5 fields in the canonical order',
  );
  for (const needle of ["request('/v2/commands', 'POST'", "request('/v2/commands/' + current.commandId + '/cancel', 'POST'", "request('/v2/commands/' + current.commandId, 'GET'", "'Idempotency-Key': current.commandId", "credentials: 'omit'", "redirect: 'error'", 'const POST_MS = 25000;', 'const CANCEL_MS = 5000;', 'const LIFETIME_MS = 60000;', "new s.OAuthProvider('apple.com')", 'await s.auth.authStateReady();', 'const LONE_SURROGATE = /\\p{Cs}/u;']) {
    assert.ok(s.includes(needle), needle);
  }
  for (const banned of ['/v1/commands', 'TASK_ID', 'TASK_LABEL', 'taskId', 'taskLabel', 'revision', 'direction', 'schemaVersion: 1', 'localStorage', 'sessionStorage', 'indexedDB', 'setInterval', 'location.', 'history.', 'console.log', 'innerHTML', 'addScope', '.normalize(', 'form.submit', '.submit(']) {
    assert.equal(s.includes(banned), false, `no ${banned}`);
  }
  // cookieは表示言語の同期設定（書込み）だけ。読取り・他cookieの操作は無い。
  assert.deepEqual(s.match(/document\.cookie[^\n]*/g), ["document.cookie = LANGUAGE_COOKIE + '=' + next + '; ' + COOKIE_ATTRIBUTES;"], 'the only cookie access is the display-language write');
  // trimは空白だけの判定に使うだけで、送る値は捕捉した`text`のまま（上のpayloadの`text,`）。
  assert.equal((s.match(/\.trim\(\)/g) ?? []).length, 1);
  assert.ok(s.includes("text.trim() === ''"));
  assert.equal((s.match(/signInWithPopup\(/g) ?? []).length, 1, 'one call, inside the click handler only (no automatic popup)');
  results.S1 = { scriptBytes: Buffer.byteLength(s) };
});

test('W1 wiring (static read of the compiled dist): Functions applies CORS before shared start; the Cloud Run server no longer imports or serves the send screen; the local helper imports it', () => {
  const functions = readFileSync(new URL('../dist/deployment/functions.js', import.meta.url), 'utf8');
  const serve = functions.slice(functions.indexOf('async function serve('));
  assert.ok(serve.indexOf('if (applyConsoleCors(req, res))') > 0 && serve.indexOf('if (applyConsoleCors(req, res))') < serve.indexOf('startShared()'));
  const kms = readFileSync(new URL('../dist/connect/kms-server.js', import.meta.url), 'utf8');
  assert.equal(/from ['"]\.\/console\.js['"]/.test(kms), false, 'kms-server does not import the send screen');
  assert.equal(/CONSOLE_PATH|consoleAsset|tryLoadDeploymentConfig/.test(kms), false);
  const local = readFileSync(new URL('../dist/console/local-server.js', import.meta.url), 'utf8');
  assert.ok(/from ['"]\.\.\/connect\/console\.js['"]/.test(local), 'the local helper serves the send screen');
  assert.ok(functions.includes('const M = loadDeploymentConfig();') && functions.includes('region: M.location'), 'the entry reads the validated deployment config at import');
});

test('R1 no automatic resend: one POST per click (the command is fixed before the first await), one fetch site, no retry loop or timer-driven resend; an unknown result stays unknown until the user checks', () => {
  const s = CONSOLE_SCRIPT;
  assert.equal((s.match(/fetch\(path, \{/g) ?? []).length, 1, 'one fetch site (same-origin helper)');
  assert.equal((s.match(/request\('\/v2\/commands', 'POST'/g) ?? []).length, 1, 'one POST call site');
  const sendBody = s.slice(s.indexOf('async function send(lane) {'), s.indexOf('async function cancel(lane) {'));
  assert.equal((sendBody.match(/await request\(/g) ?? []).length, 1, 'send() awaits a single request');
  assert.ok(sendBody.indexOf('setLane(lane, current);') < sendBody.indexOf('await request('), 'the command is fixed before the first await');
  assert.ok(sendBody.includes('if (!sendableNow(n) || !canAct(n) || laneOf(lane) !== null) return;'), 'a second click while one is pending (or from an inactive panel) does nothing');
  assert.equal((sendBody.match(/laneText\(lane\)/g) ?? []).length, 1, 'the text is captured once per click');
  const textBody = s.slice(s.indexOf('function laneText(lane) {'), s.indexOf('async function send(lane) {'));
  assert.ok(textBody.includes("lane === 'test' ? T('wizard.fixedText') : el('sttd-text').value"), 'step 5 sends the fixed text from the dictionary, step 7 the typed text');
  for (const banned of ['setInterval', 'for (;;)', 'while (true)']) assert.equal(s.includes(banned), false, `no ${banned}`);
  assert.equal(/setTimeout\([^)]*request\(/.test(s), false, 'no timer-driven request');
  results.R1 = { sendBytes: Buffer.byteLength(sendBody) };
});
