// /consoleの固定asset・CSP・API origin検査、Functions入口の固定origin CORS、操作画面scriptの送信規則（同じID・期限・自動再送0）を評価する。
// importするのはpureなdist（connect/console.js・deployment/console-cors.js・connect/pages.js・config/validate.js）だけ。SDK instance・DB・資格・HTTP・子process 0。
// kms-server.js・functions.jsは評価せず、compile後のdist文字列でroute接合だけを静的に確かめる。fixtureの値は全て合成値。
// MCP/API originは、scripts/run-tests.mjsが一時copyへ置いた合成の配置設定（test/fixtures/synthetic-deployment.mjs）の値。
// D1は、実際のCONSOLE_SCRIPTを、固定2行のSDK importだけを合成の関数へ差し替えてNode標準のvmで実行し、実際の/console HTMLのid・初期値から
// 作った合成DOMと合成fetchで、入力した本文がそのままv2の5項目で送られること・二重クリック・通信前の拒否を観測する（browser・network 0）。
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { after, test } from 'node:test';
import vm from 'node:vm';

import * as consoleModule from '../dist/connect/console.js';
import { pageSecurityHeaders } from '../dist/connect/pages.js';
import { loadDeploymentConfig } from '../dist/config/validate.js';
import { applyConsoleCors, consoleAllowedOrigin, decideConsoleCors } from '../dist/deployment/console-cors.js';

const { consoleApiOrigin, consoleAsset, ConsoleConfigError, CONSOLE_SCRIPT, CONSOLE_SDK_BASE, consoleSecurityHeaders } = consoleModule;
const DEPLOYMENT = loadDeploymentConfig();
const MCP = DEPLOYMENT.connect.publicOrigin;
const API = DEPLOYMENT.api.publicOrigin;
const WEB = { apiKey: 'synthetic-web-api-key', authDomain: DEPLOYMENT.web.authDomain, projectId: DEPLOYMENT.web.projectId };
assert.equal(MCP, 'https://sendtexttodots-connect-123456789012.europe-west1.run.app', 'the synthetic deployment config is in place');
const ID = '0f3c2a1e-5b6d-4c7e-8f90-a1b2c3d4e5f6';
const FIELDS = ['schemaVersion', 'commandId', 'text', 'createdAt', 'expiresAt'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
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

test('A1 /console assets: fixed HTML/JS/CSS, empty textarea without direction UI or default text, data attributes escaped, no inline script/style; CSP adds only self CSS + the fixed API connect-src; the OAuth page CSP is unchanged', () => {
  const page = consoleAsset('/console', WEB, API);
  assert.ok(page.body.startsWith('<!DOCTYPE html>\n<html lang="en">'), 'default language en');
  assert.ok(consoleAsset('/console', WEB, API, 'ja').body.startsWith('<!DOCTYPE html>\n<html lang="ja">'));
  assert.equal(page.type, 'text/html; charset=utf-8');
  assert.ok(page.body.includes(`data-sttd-api-origin="${API}"`));
  assert.ok(page.body.includes('<script type="module" src="/console/app.js"></script>') && page.body.includes('<link rel="stylesheet" href="/console/app.css">'));
  assert.equal((page.body.match(/<script/g) ?? []).length, 1, 'single external module script');
  assert.equal(/\sstyle=|<style|\son[a-z]+=/i.test(page.body), false, 'no inline style / handlers');
  // 本文欄は空で始まる（例文の自動挿入なし）。方向の選択・固定task・既定本文は無い。
  const textareas = [...page.body.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/g)];
  assert.equal(textareas.length, 1);
  assert.ok(/\sid="sttd-text"/.test(textareas[0][1]) && /\splaceholder="[^"]+"/.test(textareas[0][1]) && /\smaxlength="4096"/.test(textareas[0][1]));
  assert.equal(textareas[0][2], '', 'empty textarea');
  assert.equal(/<select|<option|sttd-direction|方向|上<\/|下<\/|左<\/|右<\/|direction/i.test(page.body), false, 'no direction UI');
  // 受信Dotsの設定案内は表示とボタンだけ（入力欄のpreset・value属性・自動送信の形は無い）。
  assert.ok(page.body.includes('id="sttd-guide-test-text"') && page.body.includes('id="sttd-guide-operation-text"') && page.body.includes('id="sttd-copy-test"') && page.body.includes('id="sttd-copy-operation"'));
  assert.equal(/<textarea[^>]*value=|<input/i.test(page.body), false, 'no preset input');
  const style = consoleAsset('/console/app.css', WEB, API).body;
  assert.equal(/select/.test(style), false, 'no select-only style');
  for (const name of ['CONSOLE_TASK_ID', 'CONSOLE_TASK_LABEL', 'CONSOLE_DEFAULT_TEXT']) assert.equal(Object.hasOwn(consoleModule, name), false, `no export ${name}`);
  const csp = page.headers['Content-Security-Policy'];
  assert.equal(
    csp,
    `default-src 'none'; script-src 'self' ${CONSOLE_SDK_BASE} https://apis.google.com; connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com ${API}; frame-src https://${WEB.authDomain}; style-src 'self'; img-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`,
  );
  assert.equal(/unsafe-|\*|https: /.test(csp), false);
  assert.deepEqual([page.headers['X-Frame-Options'], page.headers['Referrer-Policy']], ['DENY', 'no-referrer']);
  const oauth = pageSecurityHeaders(WEB)['Content-Security-Policy'];
  assert.ok(oauth.includes("style-src 'none'") && !oauth.includes(API), 'existing OAuth page CSP not widened');
  assert.equal(consoleAsset('/console/app.js', WEB, API).type, 'text/javascript; charset=utf-8');
  assert.equal(consoleAsset('/console/app.css', WEB, API).type, 'text/css; charset=utf-8');
  assert.equal(consoleAsset('/console/other', WEB, API), undefined);
  const escaped = consoleAsset('/console', { ...WEB, apiKey: '"><script>x</script>' }, API).body;
  assert.ok(escaped.includes('&#34;&#62;&#60;script&#62;') && !escaped.includes('"><script>x'), 'web config escaped');
  // API originは正規のhttps DNS originか、fixtureのhttp://127.0.0.1:<port>だけ。
  assert.equal(consoleApiOrigin(API), API);
  assert.equal(consoleApiOrigin('http://127.0.0.1:45146'), 'http://127.0.0.1:45146');
  for (const bad of ['http://sttd.example', 'https://sttd.example/path', 'https://sttd.example:8443', 'http://localhost:4000', 'http://127.0.0.1', 'https://sttd.example; script-src *', 'HTTPS://STTD.EXAMPLE', 'https://127.0.0.1']) {
    assert.throws(() => consoleApiOrigin(bad), ConsoleConfigError, bad);
  }
  assert.throws(() => consoleSecurityHeaders({ ...WEB, authDomain: 'x" y' }, API), ConsoleConfigError);
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
  for (const needle of ["request('/v2/commands', 'POST'", "request('/v2/commands/' + current.commandId + '/cancel', 'POST'", "request('/v2/commands/' + current.commandId, 'GET'", "'Idempotency-Key': current.commandId", "credentials: 'omit'", "redirect: 'error'", 'const POST_MS = 25000;', 'const CANCEL_MS = 5000;', 'const LIFETIME_MS = 60000;', "new OAuthProvider('apple.com')", 'await auth.authStateReady();', 'const LONE_SURROGATE = /\\p{Cs}/u;']) {
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

test('W1 wiring (static read of the compiled dist): Functions applies CORS before shared start; MCP serves /console only on the development entry at the fixed MCP origin with the fixed API origin', () => {
  const functions = readFileSync(new URL('../dist/deployment/functions.js', import.meta.url), 'utf8');
  const serve = functions.slice(functions.indexOf('async function serve('));
  assert.ok(serve.indexOf('if (applyConsoleCors(req, res))') > 0 && serve.indexOf('if (applyConsoleCors(req, res))') < serve.indexOf('startShared()'));
  const kms = readFileSync(new URL('../dist/connect/kms-server.js', import.meta.url), 'utf8');
  assert.ok(/from ['"]\.\/console\.js['"]/.test(kms) && kms.includes('deployment !== null && config.publicOrigin === deployment.connect.publicOrigin ? deployment.api.publicOrigin : null'));
  assert.ok(kms.indexOf('consoleApiOriginFor !== null') < kms.indexOf("case '/connect':"));
  assert.ok(functions.includes('const M = loadDeploymentConfig();') && functions.includes('region: M.location'), 'the entry reads the validated deployment config at import');
});

test('R1 no automatic resend: one POST per click (the command is fixed before the first await), one fetch site, no retry loop or timer-driven resend; an unknown result stays unknown until the user checks', () => {
  const s = CONSOLE_SCRIPT;
  assert.equal((s.match(/fetch\(API \+ path,/g) ?? []).length, 1, 'one API fetch site');
  assert.equal((s.match(/request\('\/v2\/commands', 'POST'/g) ?? []).length, 1, 'one POST call site');
  const sendBody = s.slice(s.indexOf('async function send() {'), s.indexOf('async function cancel() {'));
  assert.equal((sendBody.match(/await request\(/g) ?? []).length, 1, 'send() awaits a single request');
  assert.ok(sendBody.indexOf('test = current;') < sendBody.indexOf('await request('), 'the command is fixed before the first await');
  assert.ok(sendBody.includes('if (!sendableNow() || test !== null) return;'), 'a second click while one is pending does nothing');
  assert.equal((sendBody.match(/el\('sttd-text'\)\.value/g) ?? []).length, 1, 'the textarea value is captured once per click');
  for (const banned of ['setInterval', 'for (;;)', 'while (true)']) assert.equal(s.includes(banned), false, `no ${banned}`);
  assert.equal(/setTimeout\([^)]*request\(/.test(s), false, 'no timer-driven request');
  results.R1 = { sendBytes: Buffer.byteLength(sendBody) };
});

// ---------- D1: 実scriptの合成実行 ----------

const SDK_IMPORTS = [
  [`import { initializeApp } from '${CONSOLE_SDK_BASE}firebase-app.js';`, 'const { initializeApp } = __sdk;'],
  [`import { getAuth, OAuthProvider, signInWithPopup, signOut } from '${CONSOLE_SDK_BASE}firebase-auth.js';`, 'const { getAuth, OAuthProvider, signInWithPopup, signOut } = __sdk;'],
];
const unescapeHtml = (value) => value.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));
const settle = async () => {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setImmediate(resolve));
};
function gate() {
  let release;
  const promise = new Promise((resolve) => {
    release = resolve;
  });
  return { promise, release: (value) => release(value) };
}

/** 実際の/console HTMLのid・hidden・disabled・textareaの初期値・data属性と、body.datasetから合成DOMを作る（言語の差し替えに使うsetAttribute・querySelectorAllも持つ）。 */
function domFromHtml(html) {
  const elements = new Map();
  const writes = [];
  for (const match of html.matchAll(/<(\w+)\b([^>]*\sid="(sttd-[^"]+)"[^>]*)>/g)) {
    const [, tag, attrs, id] = match;
    let initial = '';
    if (tag === 'textarea') initial = unescapeHtml(html.slice(match.index + match[0].length, html.indexOf('</textarea>', match.index)));
    let textContent = '';
    const attributes = {};
    for (const [, name, value] of attrs.matchAll(/\s([a-z0-9-]+)="([^"]*)"/g)) attributes[name] = unescapeHtml(value);
    const dataset = {};
    for (const [name, value] of Object.entries(attributes)) if (name.startsWith('data-')) dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
    const element = {
      id,
      tag,
      hidden: /\shidden(\s|$)/.test(attrs),
      disabled: /\sdisabled(\s|$)/.test(attrs),
      value: initial,
      placeholder: attributes.placeholder ?? '',
      dataset,
      onclick: null,
      get textContent() {
        return textContent;
      },
      set textContent(value) {
        textContent = String(value);
        writes.push(textContent);
      },
      setAttribute(name, value) {
        attributes[name] = String(value);
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
      /** browserと同じく、disabled・hiddenのbuttonはclickを処理しない。 */
      click() {
        if (this.disabled || this.hidden || typeof this.onclick !== 'function') return false;
        this.onclick({ preventDefault() {} });
        return true;
      },
    };
    elements.set(id, element);
  }
  const bodyAttrs = /<body([^>]*)>/.exec(html)[1];
  const dataset = {};
  for (const [, name, value] of bodyAttrs.matchAll(/\sdata-([a-z0-9-]+)="([^"]*)"/g)) dataset[name.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = unescapeHtml(value);
  const cookies = { writes: [], reads: 0 };
  const document = {
    body: { dataset },
    documentElement: { lang: /<html lang="([a-z]+)">/.exec(html)[1] },
    title: /<title>([^<]*)<\/title>/.exec(html)[1],
    getElementById: (id) => elements.get(id) ?? null,
    querySelectorAll: () => [...elements.values()].filter((element) => Object.hasOwn(element.dataset, 'sttdI18n')),
    get cookie() {
      cookies.reads += 1;
      return '';
    },
    set cookie(value) {
      cookies.writes.push(String(value));
    },
  };
  return { document, elements, writes, cookies };
}

/** CONSOLE_SCRIPTを合成のSDK・fetchで実行する（日本語表示）。API originへのfetchはonApi(entry)が返す応答（{status, json}かthrowするPromise）。 */
async function runConsole(onApi) {
  const html = consoleAsset('/console', WEB, API, 'ja').body;
  const dom = domFromHtml(html);
  let source = CONSOLE_SCRIPT;
  for (const [line, replacement] of SDK_IMPORTS) {
    assert.ok(source.includes(`${line}\n`), 'the fixed SDK import line is present');
    source = source.replace(line, replacement);
  }
  assert.equal(/^\s*import\s/m.test(source), false, 'no other import');
  const calls = { initialized: [], providers: [], popups: 0, tokens: 0 };
  const auth = {
    currentUser: {
      async getIdToken() {
        calls.tokens += 1;
        return 'synthetic-id-token';
      },
    },
    async authStateReady() {},
  };
  const sdk = {
    initializeApp: (config) => (calls.initialized.push(config), {}),
    getAuth: () => auth,
    OAuthProvider: class {
      constructor(id) {
        calls.providers.push(id);
      }
    },
    signInWithPopup: async () => {
      calls.popups += 1;
    },
    signOut: async () => {},
  };
  const fetches = [];
  const fetch = async (url, init = {}) => {
    const entry = { url, method: init.method ?? 'GET', headers: { ...(init.headers ?? {}) }, body: init.body, credentials: init.credentials, redirect: init.redirect, mode: init.mode, cache: init.cache };
    fetches.push(entry);
    if (url === '/v1/web/connection') return { ok: true, status: 200, json: async () => ({ state: 'subscribed' }) };
    assert.ok(url.startsWith(`${API}/`), 'only the fixed API origin (no language or disconnect request in this scenario)');
    const { status, json } = await onApi(entry);
    return { ok: status >= 200 && status < 300, status, json: async () => json };
  };
  const context = vm.createContext({ document: dom.document, fetch, crypto: { randomUUID }, TextEncoder, setTimeout, clearTimeout, AbortController, __sdk: sdk });
  await vm.runInContext(`(async () => {\n${source}\n})()`, context, { filename: 'console-app.js' });
  await settle();
  const api = () => fetches.filter((entry) => entry.url.startsWith(`${API}/`));
  return { ...dom, calls, fetches, api, el: (id) => dom.elements.get(id) };
}

const bytes = (text) => Buffer.byteLength(text, 'utf8');
function checkPost(entry, text) {
  assert.equal(entry.url, `${API}/v2/commands`);
  assert.equal(entry.method, 'POST');
  assert.deepEqual([entry.credentials, entry.redirect, entry.mode, entry.cache], ['omit', 'error', 'cors', 'no-store']);
  assert.deepEqual(Object.keys(entry.headers).sort(), ['Authorization', 'Content-Type', 'Idempotency-Key']);
  assert.equal(entry.headers.Authorization, 'Bearer synthetic-id-token');
  assert.equal(entry.headers['Content-Type'], 'application/json');
  const payload = JSON.parse(entry.body);
  assert.deepEqual(Object.keys(payload), FIELDS, 'exactly 5 fields in order');
  assert.equal(payload.schemaVersion, 2);
  assert.match(payload.commandId, UUID);
  assert.equal(entry.headers['Idempotency-Key'], payload.commandId);
  assert.equal(payload.text, text, 'the textarea value is sent as is');
  assert.equal(Date.parse(payload.expiresAt) - Date.parse(payload.createdAt), 60_000);
  assert.match(payload.createdAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  return payload;
}

test('D1 the real console script on a synthetic DOM/fetch: empty textarea; inputs A/B are each sent once to /v2 with a new ID and the exact text; double click sends one POST; blank/oversize/lone-surrogate never fetch; HTML-like text is data only; cancel/check use the same ID on v2', { timeout: 20_000 }, async () => {
  const holds = [];
  let mode = 'deliver';
  const ui = await runConsole(async (entry) => {
    if (mode === 'hold') {
      const hold = gate();
      holds.push({ entry, hold });
      return hold.promise;
    }
    if (mode === 'fail') throw new TypeError('synthetic network failure');
    const commandId = entry.method === 'POST' && entry.url === `${API}/v2/commands` ? JSON.parse(entry.body).commandId : entry.url.split('/')[5];
    return { status: 200, json: { commandId, state: entry.url.endsWith('/cancel') ? 'cancelled' : 'delivered' } };
  });
  const { el } = ui;
  // 実HTMLの初期状態と、確認済みの接続（subscribed）で送信可能になること。
  assert.equal(ui.elements.has('sttd-direction'), false);
  assert.equal(el('sttd-text').value, '', 'starts empty (no example text inserted)');
  assert.equal(el('sttd-text').disabled, false);
  assert.equal(el('sttd-send').disabled, false);
  assert.deepEqual(ui.calls.providers, [], 'no automatic popup / provider');
  // vmの別realmのobjectなので、JSONで比べる。
  assert.equal(JSON.stringify(ui.calls.initialized), JSON.stringify([{ apiKey: WEB.apiKey, authDomain: WEB.authDomain, projectId: WEB.projectId }]));
  assert.equal(ui.api().length, 0);

  // 通信前の拒否（fetch 0、入力値は書き換えない）。
  const rejected = {
    empty: '',
    blank: ' \n\t\u3000 ',
    loneHigh: 'abc\ud800',
    loneLow: '\udc00def',
    over4097: 'a'.repeat(4097),
    overMultibyte: 'あ'.repeat(1366),
  };
  for (const [name, text] of Object.entries(rejected)) {
    el('sttd-text').value = text;
    assert.equal(el('sttd-send').click(), true, name);
    await settle();
    assert.equal(ui.api().length, 0, `${name}: no fetch`);
    assert.equal(el('sttd-text').value, text, `${name}: value untouched`);
    assert.ok(el('sttd-result').textContent.includes('4096バイト'), `${name}: shown as not sent`);
  }
  assert.equal(bytes(rejected.overMultibyte) > 4096 && rejected.overMultibyte.length < 4096, true, 'maxlength alone would not catch it');

  // 入力A: 前後空白・改行・日本語・絵文字・結合文字・HTML風の文字列。送信中の二重クリックでもPOSTは1つ。
  const textA = `  こんにちは🌏\n2行目 e\u0301 か\u3099 </textarea><script>alert(1)</script>  `;
  el('sttd-text').value = textA;
  mode = 'hold';
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(el('sttd-send').click(), false, 'disabled while sending');
  el('sttd-send').onclick();
  await settle();
  assert.equal(holds.length, 1, 'double click: one POST');
  assert.equal(ui.api().length, 1);
  assert.equal(el('sttd-text').disabled, true, 'text locked while sending');
  assert.equal(el('sttd-switch').disabled, true, 'account switch locked while sending');
  const payloadA = checkPost(holds[0].entry, textA);
  holds.shift().hold.release({ status: 200, json: { commandId: payloadA.commandId, state: 'delivered' } });
  await settle();
  assert.ok(el('sttd-result').textContent.startsWith('送信先が受領しました。'));
  assert.equal(el('sttd-send').disabled, true, 'no resend until a new test');
  assert.equal(el('sttd-new').hidden, false);
  assert.equal(el('sttd-new').click(), true);
  await settle();

  // 入力B: 別の本文・別のcommandId。
  const textB = 'B: 改行の後\n\n末尾の空白 ';
  el('sttd-text').value = textB;
  mode = 'deliver';
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(ui.api().length, 2);
  const payloadB = checkPost(ui.api()[1], textB);
  assert.notEqual(payloadB.commandId, payloadA.commandId);
  assert.notEqual(payloadB.text, payloadA.text);
  el('sttd-new').click();
  await settle();

  // 4096 byteちょうどは送る（多byte文字）。
  const exact = `${'あ'.repeat(1365)}a`;
  assert.equal(bytes(exact), 4096);
  el('sttd-text').value = exact;
  el('sttd-send').click();
  await settle();
  assert.equal(ui.api().length, 3);
  checkPost(ui.api()[2], exact);
  el('sttd-new').click();
  await settle();

  // 送信中の中止は同じIDのv2 cancelへ。
  el('sttd-text').value = 'cancel me';
  mode = 'hold';
  el('sttd-send').click();
  await settle();
  const pending = holds[0];
  const payloadC = checkPost(pending.entry, 'cancel me');
  mode = 'deliver';
  assert.equal(el('sttd-cancel').click(), true);
  await settle();
  const cancelCall = ui.api().at(-1);
  assert.deepEqual([cancelCall.method, cancelCall.url, cancelCall.body], ['POST', `${API}/v2/commands/${payloadC.commandId}/cancel`, undefined]);
  holds.shift().hold.release({ status: 200, json: { commandId: payloadC.commandId, state: 'cancelled' } });
  await settle();
  assert.ok(el('sttd-result').textContent.startsWith('中止しました'));
  el('sttd-new').click();
  await settle();

  // 結果不明は自動で再送せず、本人のクリックで同じIDをv2で照会する。
  el('sttd-text').value = 'unknown result';
  mode = 'fail';
  el('sttd-send').click();
  await settle();
  const payloadD = checkPost(ui.api().at(-1), 'unknown result');
  const before = ui.api().length;
  await settle();
  assert.equal(ui.api().length, before, 'no automatic resend');
  assert.equal(el('sttd-check').hidden, false);
  mode = 'deliver';
  el('sttd-check').click();
  await settle();
  const checkCall = ui.api().at(-1);
  assert.deepEqual([checkCall.method, checkCall.url, checkCall.body], ['GET', `${API}/v2/commands/${payloadD.commandId}`, undefined]);
  assert.ok(el('sttd-result').textContent.startsWith('送信先が受領しました。'));

  const posts = ui.api().filter((entry) => entry.url === `${API}/v2/commands`);
  assert.equal(posts.length, 5, 'one POST per accepted click');
  assert.equal(new Set(posts.map((entry) => JSON.parse(entry.body).commandId)).size, 5, 'a new ID per test');
  // 本文はtextContentへ出さない（固定文だけ）。HTML風の本文で要素は増えない。
  for (const text of [textA, textB, exact, 'cancel me', 'unknown result']) assert.equal(ui.writes.some((written) => written.includes(text)), false, 'no body in the page text');
  assert.equal(ui.elements.size, [...consoleAsset('/console', WEB, API).body.matchAll(/\sid="sttd-/g)].length);
  assert.deepEqual(ui.cookies, { writes: [], reads: 0 }, 'sending never touches cookies');
  // 受信Dotsの設定案内の固定文はpresetではない（本文欄は上の操作でだけ変わる）。このvmにclipboardは無く、コピーは手動案内で止まり要求を出さない。
  const apiBefore = ui.api().length;
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(ui.api().length, apiBefore);
  assert.ok(el('sttd-copy-result').textContent.length > 0, 'manual-copy guidance shown');
  assert.equal(holds.length, 0);
  results.D1 = { posts: posts.length, apiCalls: ui.api().length, rejected: Object.keys(rejected).length };
});
