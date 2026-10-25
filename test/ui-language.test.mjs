// 表示言語（en/ja）と送信画面の接続解除を、合成入力だけで確かめる。importするのはpureなdist（connect/i18n.js・connect/console.js・
// connect/pages.js・oauth/provider.jsのrender・config/validate.js）だけで、SDK instance・DB・資格・HTTP・子process 0。kms-server.jsは評価せず、
// compile後のdist文字列で言語とcookieの接合だけを静的に確かめる。fixtureの値は全て合成値。
//   - L1/L2: Accept-Languageのq値・不正入力・未対応言語、cookieの欠落/不正/重複、明示選択の優先、Set-Cookieの形（session・Path・SameSite・Secure）。
//   - L3: 各画面（console・connect・OAuthログイン/同意・OAuthエラー）のHTML lang/題名/本文が選択言語で整合し、両言語の辞書キーが一致し、
//     machine code・CSRF・formのaction/methodを翻訳せず、言語リンクがformの外のGETリンクであること。
//   - L4: kms-server.jsの静的接合（HTMLだけ言語を選び、`?lang=`の明示選択だけSet-Cookie、disconnect routeの認可は不変）。
//   - L5/L6: 実CONSOLE_SCRIPTを合成DOM/SDK/fetchで実行。言語切替で文言・langが差し替わり、cookie保存のGETが同originへ1回だけ出て、送信/
//     ログイン/解除を発火しない。送信中の切替は受けない。解除は確認→1回のPOST→状態再確認で、取消/失敗/期限切れで成功を装わず、送信を封鎖する。
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { after, test } from 'node:test';
import vm from 'node:vm';

import { consoleAsset, CONSOLE_SCRIPT, CONSOLE_SDK_BASE } from '../dist/connect/console.js';
import {
  DEFAULT_LANGUAGE,
  LANGUAGE_COOKIE,
  LANGUAGES,
  languageCookie,
  languageFromAcceptLanguage,
  languageFromCookieHeader,
  MESSAGES,
  selectLanguage,
  text,
} from '../dist/connect/i18n.js';
import { CONNECT_SCRIPT, renderConnectPage, renderInteractionConsent, renderInteractionLogin } from '../dist/connect/pages.js';
import { loadDeploymentConfig } from '../dist/config/validate.js';
import { renderOAuthErrorPage } from '../dist/oauth/provider.js';

const DEPLOYMENT = loadDeploymentConfig();
const API = DEPLOYMENT.api.publicOrigin;
const WEB = { apiKey: 'synthetic-web-api-key', authDomain: DEPLOYMENT.web.authDomain, projectId: DEPLOYMENT.web.projectId };
const results = {};
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
after(() => {
  const timers = process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
  process.stdout.write(`# UI_LANGUAGE_COUNTS ${JSON.stringify({ unhandled, timers, results })}\n`);
  assert.deepEqual([unhandled, timers], [0, 0]);
});

test('L1 Accept-Language: q values rank ja against en, ties/unsupported/invalid/missing fall back to en, q=0 never selects', () => {
  const cases = {
    'ja': 'ja',
    'ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7': 'ja',
    'en-US,en;q=0.9,ja;q=0.8': 'en',
    'en;q=0.5,ja;q=0.9': 'ja',
    'ja;q=0.5,en;q=0.5': 'en',
    'ja;q=0,en;q=0.1': 'en',
    'ja;q=0': 'en',
    'fr-FR,fr;q=0.9': 'en',
    'fr;q=0.9,ja;q=0.1': 'ja',
    'zh-CN,ja;q=0.3,en;q=0.2': 'ja',
    '*': 'en',
    '*;q=0.5,ja;q=0.8': 'ja',
    '*;q=0.9,ja;q=0.8': 'en',
    'JA-jp': 'ja',
    'japanese': 'en',
    'ja;q=abc': 'ja',
    'ja;q=1.5': 'ja',
    ';;;,,,': 'en',
    '': 'en',
    ['x'.repeat(2000)]: 'en',
  };
  for (const [header, expected] of Object.entries(cases)) assert.equal(languageFromAcceptLanguage(header), expected, JSON.stringify(header));
  for (const bad of [undefined, null, 1, {}, ['ja'], Symbol('ja')]) assert.equal(languageFromAcceptLanguage(bad), 'en');
  assert.deepEqual([...LANGUAGES], ['en', 'ja']);
  assert.equal(DEFAULT_LANGUAGE, 'en');
  results.L1 = { headers: Object.keys(cases).length };
});

test('L2 cookie and selection: the display cookie wins over Accept-Language, a missing/invalid/duplicated cookie falls back, the explicit query wins over both, and Set-Cookie is a session cookie with Path=/ SameSite=Lax (Secure on https) and no Max-Age/Expires/Domain', () => {
  assert.equal(LANGUAGE_COOKIE, 'sttd_language');
  assert.equal(languageFromCookieHeader('sttd_language=ja'), 'ja');
  assert.equal(languageFromCookieHeader('a=1; sttd_language=en; b=2'), 'en');
  assert.equal(languageFromCookieHeader('sttd_language = ja '), 'ja');
  for (const bad of [undefined, '', 'sttd_language=fr', 'sttd_language=JA', 'sttd_language=', 'sttd_language', 'other=ja', 'sttd_language=ja; sttd_language=en', 'sttd_language=ja; sttd_language=ja', 'xsttd_language=ja', `sttd_language=${'j'.repeat(9000)}`]) {
    assert.equal(languageFromCookieHeader(bad), null, JSON.stringify(bad));
  }
  assert.equal(selectLanguage({ cookie: 'sttd_language=ja', acceptLanguage: 'en' }), 'ja');
  assert.equal(selectLanguage({ cookie: 'sttd_language=en', acceptLanguage: 'ja' }), 'en');
  assert.equal(selectLanguage({ cookie: 'sttd_language=fr', acceptLanguage: 'ja' }), 'ja', 'invalid cookie falls back to Accept-Language');
  assert.equal(selectLanguage({ acceptLanguage: 'ja' }), 'ja');
  assert.equal(selectLanguage({}), 'en');
  assert.equal(selectLanguage({ query: 'en', cookie: 'sttd_language=ja', acceptLanguage: 'ja' }), 'en');
  assert.equal(selectLanguage({ query: 'ja', cookie: 'sttd_language=en', acceptLanguage: 'en' }), 'ja');
  assert.equal(selectLanguage({ query: 'fr', cookie: 'sttd_language=en', acceptLanguage: 'ja' }), 'en', 'unknown query is ignored');
  assert.equal(selectLanguage({ query: '', acceptLanguage: 'ja' }), 'ja');
  assert.equal(languageCookie('ja', true), 'sttd_language=ja; Path=/; SameSite=Lax; Secure');
  assert.equal(languageCookie('en', false), 'sttd_language=en; Path=/; SameSite=Lax');
  for (const value of [languageCookie('ja', true), languageCookie('en', false)]) assert.equal(/Max-Age|Expires|Domain|HttpOnly/i.test(value), false, 'session cookie, display only');
  assert.throws(() => languageCookie('fr', true), TypeError);
  assert.throws(() => languageCookie('<script>', true), TypeError);
});

test('L3 rendering: every page carries html lang, title and body in the selected language; both dictionaries share one key set with non-empty values; machine codes, routes, CSRF and form actions are not translated; language links are GET links outside the forms', () => {
  assert.deepEqual(Object.keys(MESSAGES.ja).sort(), Object.keys(MESSAGES.en).sort(), 'same keys in en and ja');
  for (const lang of ['en', 'ja']) {
    for (const [key, value] of Object.entries(MESSAGES[lang])) {
      assert.ok(typeof value === 'string' && value.length > 0, `${lang}:${key}`);
      assert.equal(/[`<>]/.test(value), false, `${lang}:${key} has no template/HTML characters`);
      assert.equal(text(lang, key), value);
    }
  }
  assert.equal(text('ja', 'not.a.key'), '', 'unknown key renders nothing (never the input)');
  assert.equal(text('fr', 'console.title'), MESSAGES.en['console.title'], 'unknown language falls back to en');
  const pages = {
    console: (lang) => consoleAsset('/console', WEB, API, lang).body,
    connect: (lang) => renderConnectPage(WEB, lang, true),
    connectNoConsole: (lang) => renderConnectPage(WEB, lang, false),
    login: (lang) => renderInteractionLogin(WEB, 'uid-1', 'Client "A"', 'csrf-1', lang),
    consent: (lang) => renderInteractionConsent(WEB, 'uid-1', 'Client "A"', 'csrf-1', lang),
    oauthError: (lang) => renderOAuthErrorPage('access_denied', lang),
  };
  const JAPANESE = /[぀-ヿ一-鿿]/;
  for (const [name, render] of Object.entries(pages)) {
    const en = render('en');
    const ja = render('ja');
    assert.ok(en.startsWith('<!DOCTYPE html>\n<html lang="en">') || en.startsWith('<!DOCTYPE html><html lang="en">'), `${name}: en lang`);
    assert.ok(ja.startsWith('<!DOCTYPE html>\n<html lang="ja">') || ja.startsWith('<!DOCTYPE html><html lang="ja">'), `${name}: ja lang`);
    assert.notEqual(en, ja);
    // 英語画面に日本語の文言が残らない（言語リンクの「日本語」とdata属性のJSON辞書・埋め込み値は除く）。
    const enText = en.replace(/<a id="sttd-lang-ja"[^>]*>[^<]*<\/a>/, '').replace(/<[^>]+>/g, ' ');
    assert.equal(JAPANESE.test(enText), false, `${name}: no Japanese body text in the English page`);
    assert.ok(JAPANESE.test(ja.replace(/<[^>]+>/g, ' ')), `${name}: Japanese body text in the Japanese page`);
    assert.equal(/\sstyle=|<style|\son[a-z]+=/i.test(en + ja), false, `${name}: no inline style/handlers`);
    assert.equal(render(undefined), en, `${name}: default language is en`);
    assert.equal(render('fr'), en, `${name}: unsupported language falls back to en`);
  }
  // 言語リンク: 同じpathへのGETリンクで、formの外。選択中はaria-current。
  for (const [name, path] of [['console', '/console'], ['connect', '/connect'], ['login', '/interaction/uid-1'], ['consent', '/interaction/uid-1']]) {
    for (const lang of ['en', 'ja']) {
      const html = pages[name](lang);
      assert.ok(html.includes(`<a id="sttd-lang-en" href="${path}?lang=en" hreflang="en" lang="en"${lang === 'en' ? ' aria-current="true"' : ''}>English</a>`), `${name}/${lang}: en link`);
      assert.ok(html.includes(`<a id="sttd-lang-ja" href="${path}?lang=ja" hreflang="ja" lang="ja"${lang === 'ja' ? ' aria-current="true"' : ''}>日本語</a>`), `${name}/${lang}: ja link`);
      const formStart = html.indexOf('<form');
      if (formStart >= 0) assert.ok(html.indexOf('id="sttd-lang-ja"') < formStart, `${name}/${lang}: language links are outside the forms`);
    }
  }
  // 同意画面: form・action・csrf・methodは言語で変わらない。
  const consentForms = (lang) => [...pages.consent(lang).matchAll(/<form method="post" action="([^"]+)">\s*<input type="hidden" name="csrf" value="([^"]+)">/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(consentForms('en'), [['/interaction/uid-1/consent', 'csrf-1'], ['/interaction/uid-1/deny', 'csrf-1']]);
  assert.deepEqual(consentForms('ja'), consentForms('en'));
  assert.ok(pages.consent('en').includes('Client &#34;A&#34;') && pages.login('ja').includes('Client &#34;A&#34;'), 'client label escaped, not translated');
  // ログイン画面: interaction uid/csrfのdata属性は言語で変わらない。
  for (const lang of ['en', 'ja']) assert.ok(pages.login(lang).includes(' data-sttd-interaction="uid-1" data-sttd-csrf="csrf-1"'), `login/${lang}: interaction data kept`);
  // OAuthエラー: codeはdata属性だけ、説明文は固定。未知の形はerror。
  assert.ok(pages.oauthError('en').includes('data-sttd-error="access_denied">The connection could not be completed.</p>'));
  assert.ok(pages.oauthError('ja').includes('data-sttd-error="access_denied">接続を完了できませんでした。</p>'));
  assert.ok(renderOAuthErrorPage('Bad <b>', 'en').includes('data-sttd-error="error">'));
  assert.ok(renderOAuthErrorPage(undefined, 'ja').includes('data-sttd-error="error">'));
  // console: 送信画面の見出し・入力欄のplaceholder・解除の確認文・言語。
  const consoleJa = pages.console('ja');
  const consoleEn = pages.console('en');
  assert.ok(consoleJa.includes('<title>SendTextToDots 送信画面</title>') && consoleEn.includes('<title>SendTextToDots send screen</title>'));
  assert.ok(consoleJa.includes(' data-sttd-language="ja"') && consoleEn.includes(' data-sttd-language="en"'));
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="Dotsへ送る文を入力してください（4096バイトまで）"[^>]*><\/textarea>/.test(consoleJa));
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="Enter the text to send to Dots \(up to 4096 bytes\)"[^>]*><\/textarea>/.test(consoleEn));
  for (const id of ['sttd-disconnect', 'sttd-disconnect-confirm', 'sttd-disconnect-yes', 'sttd-disconnect-no', 'sttd-disconnect-result']) assert.ok(consoleEn.includes(`id="${id}"`), id);
  assert.equal(consoleEn.includes('href="/connect"'), false, 'console no longer sends the user to /connect to disconnect');
  assert.equal(/開発用|development send|テスト送信|test send/i.test(consoleEn + consoleJa), false, 'console is presented as the send screen');
  // connect: consoleを配信する構成だけ送信画面へ案内し、配信しない構成では既存機能の案内。
  assert.ok(pages.connect('en').includes('<a id="sttd-console-link" href="/console">Open the send screen</a>'));
  assert.ok(pages.connect('ja').includes('<a id="sttd-console-link" href="/console">送信画面を開く</a>'));
  assert.equal(pages.connectNoConsole('en').includes('href="/console"'), false);
  assert.ok(pages.connectNoConsole('ja').includes('このページは接続画面です'));
  // scriptは辞書を埋め込み、両言語を持つ。machine state名・routeは翻訳しない。
  for (const script of [CONSOLE_SCRIPT, CONNECT_SCRIPT]) {
    assert.ok(script.includes(`const TEXT = ${JSON.stringify(MESSAGES)};`), 'the fixed dictionary is embedded');
    for (const needle of ["'unlinked', 'linked', 'subscribed', 'expired', 'change_pending'", "'/v1/web/connection'", "'/v1/web/disconnect'"]) assert.ok(script.includes(needle), needle);
    for (const banned of ['document.cookie', 'localStorage', 'sessionStorage', 'indexedDB', 'innerHTML']) assert.equal(script.includes(banned), false, `no ${banned}`);
  }
  assert.ok(CONSOLE_SCRIPT.includes("fetch('/console?lang=' + next, { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' })"));
  assert.equal((CONSOLE_SCRIPT.match(/fetch\('\/v1\/web\/disconnect'/g) ?? []).length, 1, 'one disconnect call site');
  results.L3 = { pages: Object.keys(pages).length, keys: Object.keys(MESSAGES.en).length };
});

test('L4 wiring (static read of the compiled dist): HTML routes choose the language from ?lang / cookie / Accept-Language, only an explicit ?lang sets the session cookie, the connect page learns whether /console is served, and the disconnect route keeps Origin + Bearer + no-body checks', () => {
  const kms = readFileSync(new URL('../dist/connect/kms-server.js', import.meta.url), 'utf8');
  assert.ok(kms.includes("selectLanguage({ query, cookie: req.headers.cookie, acceptLanguage: req.headers['accept-language'] })"));
  assert.ok(kms.includes("headers: isLanguage(query) ? { 'Set-Cookie': languageCookie(language, true) } : {}"));
  assert.equal((kms.match(/'Set-Cookie'/g) ?? []).length, 1, 'one Set-Cookie site (pageLanguage)');
  assert.ok(kms.includes("const { language, headers } = path === CONSOLE_PATH ? pageLanguage(req, url) : { language: undefined, headers: {} };"), 'console assets other than the HTML do not read or set the language');
  assert.ok(kms.includes('renderConnectPage(web, language, consoleApiOriginFor !== null)'));
  assert.ok(kms.includes('renderInteractionLogin(web, uid, label, opened.csrf, language)') && kms.includes('renderInteractionConsent(web, uid, label, opened.csrf, language)'));
  const disconnect = kms.slice(kms.indexOf("case '/v1/web/disconnect':"), kms.indexOf("return 'web.disconnect';"));
  for (const needle of ["only('POST')", 'await bearerIdentity(req)', 'assertNoBody(req)', 'storage.revokeOwner(ownerId)']) assert.ok(disconnect.includes(needle), needle);
  assert.match(disconnect, /if \(req\.headers\.origin !== undefined\)\s*requireSameOrigin\(req\);/, 'Origin check kept (tsc may break the line)');
  assert.equal(/language|lang|cookie/i.test(disconnect), false, 'the disconnect route does not read the display language');
  const connection = kms.slice(kms.indexOf("case '/v1/web/connection':"), kms.indexOf("return 'web.connection';"));
  assert.equal(/language|lang|cookie/i.test(connection), false, 'the connection route does not read the display language');
  const provider = readFileSync(new URL('../dist/oauth/provider.js', import.meta.url), 'utf8');
  assert.ok(provider.includes("renderOAuthErrorPage(out.error, selectLanguage({ cookie: ctx.get('cookie'), acceptLanguage: ctx.get('accept-language') }))"));
});

// ---------- L5/L6: 実scriptの合成実行 ----------

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

/** 実際の/console HTMLのid・hidden・disabled・textarea・data-sttd-i18n・placeholderと、body.datasetから合成DOMを作る。 */
function domFromHtml(html) {
  const elements = new Map();
  const writes = [];
  for (const match of html.matchAll(/<(\w+)\b([^>]*\sid="(sttd-[^"]+)"[^>]*)>/g)) {
    const [, tag, attrs, id] = match;
    let initial = '';
    if (tag === 'textarea') initial = unescapeHtml(html.slice(match.index + match[0].length, html.indexOf('</textarea>', match.index)));
    let textContent = tag === 'textarea' ? '' : unescapeHtml(html.slice(match.index + match[0].length, html.indexOf('<', match.index + match[0].length)));
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
      attributes,
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
      /** browserと同じく、disabled・hiddenのbuttonはclickを処理しない。リンクはpreventDefaultの有無を返す。 */
      click() {
        if (this.disabled || this.hidden || typeof this.onclick !== 'function') return false;
        let prevented = false;
        this.onclick({ preventDefault: () => (prevented = true) });
        return tag === 'a' ? prevented : true;
      },
    };
    elements.set(id, element);
  }
  const bodyAttrs = /<body([^>]*)>/.exec(html)[1];
  const dataset = {};
  for (const [, name, value] of bodyAttrs.matchAll(/\sdata-([a-z0-9-]+)="([^"]*)"/g)) dataset[name.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = unescapeHtml(value);
  const documentElement = { lang: /<html lang="([a-z]+)">/.exec(html)[1] };
  const document = {
    body: { dataset },
    documentElement,
    title: /<title>([^<]*)<\/title>/.exec(html)[1],
    getElementById: (id) => elements.get(id) ?? null,
    querySelectorAll: (selector) => {
      assert.equal(selector, '[data-sttd-i18n]');
      return [...elements.values()].filter((element) => Object.hasOwn(element.dataset, 'sttdI18n'));
    },
  };
  return { document, elements, writes };
}

/**
 * CONSOLE_SCRIPTを合成のSDK・fetchで実行する。同originのfetchはonSame(entry)、API originへのfetchはonApi(entry)が返す応答
 * （{status, json}かthrowするPromise）。tokenの取得はhooks.token()で差し替えられる（期限切れの合成）。
 */
async function runConsole(language, { onApi, onSame, token }) {
  const html = consoleAsset('/console', WEB, API, language).body;
  const dom = domFromHtml(html);
  let source = CONSOLE_SCRIPT;
  for (const [line, replacement] of SDK_IMPORTS) {
    assert.ok(source.includes(`${line}\n`), 'the fixed SDK import line is present');
    source = source.replace(line, replacement);
  }
  assert.equal(/^\s*import\s/m.test(source), false, 'no other import');
  const calls = { providers: [], popups: 0, tokens: 0, signOuts: 0 };
  const auth = {
    currentUser: {
      async getIdToken() {
        calls.tokens += 1;
        if (token) return token();
        return 'synthetic-id-token';
      },
    },
    async authStateReady() {},
  };
  const sdk = {
    initializeApp: () => ({}),
    getAuth: () => auth,
    OAuthProvider: class {
      constructor(id) {
        calls.providers.push(id);
      }
    },
    signInWithPopup: async () => {
      calls.popups += 1;
    },
    signOut: async () => {
      calls.signOuts += 1;
    },
  };
  const fetches = [];
  const fetch = async (url, init = {}) => {
    const entry = { url, method: init.method ?? 'GET', headers: { ...(init.headers ?? {}) }, body: init.body, credentials: init.credentials, redirect: init.redirect, mode: init.mode, cache: init.cache };
    fetches.push(entry);
    if (url.startsWith(`${API}/`)) {
      const { status, json } = await onApi(entry);
      return { ok: status >= 200 && status < 300, status, json: async () => json };
    }
    assert.ok(url.startsWith('/'), 'same-origin requests are relative');
    const { status, json, text: bodyText } = await onSame(entry);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (json === undefined) throw new SyntaxError('not json');
        return json;
      },
      text: async () => bodyText ?? '',
    };
  };
  const context = vm.createContext({ document: dom.document, fetch, crypto: { randomUUID }, TextEncoder, setTimeout, clearTimeout, AbortController, __sdk: sdk });
  await vm.runInContext(`(async () => {\n${source}\n})()`, context, { filename: 'console-app.js' });
  await settle();
  const same = (path) => fetches.filter((entry) => entry.url === path || entry.url.startsWith(`${path}?`));
  const api = () => fetches.filter((entry) => entry.url.startsWith(`${API}/`));
  return { ...dom, calls, fetches, api, same, el: (id) => dom.elements.get(id) };
}

const JA = (key) => MESSAGES.ja[key];
const EN = (key) => MESSAGES.en[key];
const i18nTexts = (ui) => Object.fromEntries(ui.document.querySelectorAll('[data-sttd-i18n]').map((node) => [node.dataset.sttdI18n, node.textContent]));

test('L5 language switch in the real console script: the Japanese page switches to English in place (html lang, title, every fixed text, placeholder, dynamic status) with exactly one same-origin GET /console?lang=en that carries the cookie jar and triggers no API call, popup, sign-out or disconnect; clicking the current language does nothing; the switch is refused while sending', { timeout: 20_000 }, async () => {
  let connectionState = 'subscribed';
  const holds = [];
  let mode = 'deliver';
  const ui = await runConsole('ja', {
    onApi: async (entry) => {
      if (mode === 'hold') {
        const hold = gate();
        holds.push({ entry, hold });
        return hold.promise;
      }
      const commandId = JSON.parse(entry.body).commandId;
      return { status: 200, json: { commandId, state: 'delivered' } };
    },
    onSame: async (entry) => {
      if (entry.url === '/v1/web/connection') return { status: 200, json: { state: connectionState } };
      if (entry.url.startsWith('/console?lang=')) return { status: 200, text: '<!DOCTYPE html>' };
      throw new Error(`unexpected same-origin request ${entry.url}`);
    },
  });
  const { el } = ui;
  assert.equal(ui.document.documentElement.lang, 'ja');
  assert.equal(ui.document.title, JA('console.title'));
  assert.equal(el('sttd-state-text').textContent, JA('console.state.subscribed'));
  assert.equal(el('sttd-account-text').textContent, JA('console.accountSignedIn'));
  assert.deepEqual(i18nTexts(ui)['console.heading'], JA('console.heading'));
  assert.equal(el('sttd-lang-ja').getAttribute('aria-current'), 'true');
  assert.equal(el('sttd-lang-en').getAttribute('aria-current'), 'false');
  assert.equal(ui.same('/console').length, 0);

  // 同じ言語のクリックは何もしない（fetch 0）。
  assert.equal(el('sttd-lang-ja').click(), true, 'navigation prevented');
  await settle();
  assert.equal(ui.same('/console').length, 0);

  // Englishへ切替: 画面内で差し替え、cookie保存のGETが1回。API・popup・signOut・解除は0。
  const before = { api: ui.api().length, popups: ui.calls.popups, signOuts: ui.calls.signOuts };
  assert.equal(el('sttd-lang-en').click(), true, 'navigation prevented (in-place switch)');
  await settle();
  assert.equal(ui.document.documentElement.lang, 'en');
  assert.equal(ui.document.title, EN('console.title'));
  const texts = i18nTexts(ui);
  for (const [key, value] of Object.entries(texts)) assert.equal(value, EN(key), key);
  assert.ok(Object.keys(texts).length >= 20, `fixed texts re-rendered (${Object.keys(texts).length})`);
  assert.equal(el('sttd-text').placeholder, EN('console.textPlaceholder'));
  assert.equal(el('sttd-state-text').textContent, EN('console.state.subscribed'), 'dynamic status re-rendered');
  assert.equal(el('sttd-account-text').textContent, EN('console.accountSignedIn'));
  assert.equal(el('sttd-lang-en').getAttribute('aria-current'), 'true');
  assert.equal(el('sttd-lang-ja').getAttribute('aria-current'), 'false');
  const cookieCalls = ui.same('/console');
  assert.equal(cookieCalls.length, 1);
  assert.deepEqual([cookieCalls[0].url, cookieCalls[0].method, cookieCalls[0].credentials, cookieCalls[0].cache, cookieCalls[0].redirect, cookieCalls[0].body], ['/console?lang=en', 'GET', 'same-origin', 'no-store', 'error', undefined]);
  assert.deepEqual(Object.keys(cookieCalls[0].headers), [], 'no Authorization on the language request');
  assert.deepEqual([ui.api().length, ui.calls.popups, ui.calls.signOuts, ui.same('/v1/web/disconnect').length], [before.api, before.popups, before.signOuts, 0]);
  assert.equal(el('sttd-send').disabled, false, 'still sendable after the switch');

  // 入力中の切替で入力は消えない。
  el('sttd-text').value = 'keep me';
  assert.equal(el('sttd-lang-ja').click(), true);
  await settle();
  assert.equal(el('sttd-text').value, 'keep me');
  assert.equal(ui.same('/console').length, 2);
  assert.equal(ui.document.documentElement.lang, 'ja');

  // 送信中は切替を受けない（文言・lang・fetchが変わらない）。送信は1件のまま。
  mode = 'hold';
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(holds.length, 1);
  assert.equal(el('sttd-lang-en').getAttribute('aria-disabled'), 'true');
  assert.equal(el('sttd-lang-en').click(), true, 'prevented, ignored');
  await settle();
  assert.equal(ui.document.documentElement.lang, 'ja');
  assert.equal(ui.same('/console').length, 2, 'no cookie request while sending');
  assert.equal(el('sttd-result').textContent, JA('console.sending'));
  assert.equal(el('sttd-disconnect').disabled, true, 'disconnect locked while sending');
  const payload = JSON.parse(holds[0].entry.body);
  assert.equal(payload.text, 'keep me');
  holds.shift().hold.release({ status: 200, json: { commandId: payload.commandId, state: 'delivered' } });
  await settle();
  assert.equal(el('sttd-result').textContent, JA('console.state.delivered'));
  assert.equal(holds.length, 0);
  // 終端後に切替すると結果の文言も英語になる。
  assert.equal(el('sttd-lang-en').click(), true);
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'));
  assert.equal(ui.api().length, 1, 'one POST in total');
  results.L5 = { cookieRequests: ui.same('/console').length, apiCalls: ui.api().length, fixedTexts: Object.keys(texts).length };
});

test('L6 disconnect in the real console script: confirm first (no request), cancelling the confirmation sends nothing; confirming sends one same-origin POST /v1/web/disconnect with the Bearer token (double click does not add one), locks send/switch/refresh/language meanwhile, re-checks the state and blocks sending until the user re-checks; a failed or expired attempt is not shown as success and also re-checks', { timeout: 20_000 }, async () => {
  let connectionState = 'subscribed';
  let disconnectMode = 'ok';
  const holds = [];
  let tokenMode = 'ok';
  const ui = await runConsole('ja', {
    onApi: async () => {
      throw new Error('no API request expected');
    },
    onSame: async (entry) => {
      if (entry.url === '/v1/web/connection') return { status: 200, json: { state: connectionState } };
      if (entry.url === '/v1/web/disconnect') {
        if (disconnectMode === 'hold') {
          const hold = gate();
          holds.push({ entry, hold });
          return hold.promise;
        }
        if (disconnectMode === 'fail') return { status: 503, json: { error: { code: 'temporarily_unavailable', retryable: true } } };
        if (disconnectMode === 'network') throw new TypeError('synthetic network failure');
        connectionState = 'unlinked';
        return { status: 200, json: { state: 'unlinked' } };
      }
      throw new Error(`unexpected same-origin request ${entry.url}`);
    },
    token: async () => {
      if (tokenMode === 'expired') throw new Error('synthetic token failure');
      return 'synthetic-id-token';
    },
  });
  const { el } = ui;
  const disconnects = () => ui.same('/v1/web/disconnect');
  const connections = () => ui.same('/v1/web/connection');
  assert.equal(el('sttd-disconnect').hidden, false, 'disconnect offered while connected');
  assert.equal(el('sttd-disconnect-confirm').hidden, true);
  assert.equal(connections().length, 1);

  // 確認を開くだけでは何も送らない。取消も送らない。
  assert.equal(el('sttd-disconnect').click(), true);
  await settle();
  assert.equal(el('sttd-disconnect-confirm').hidden, false);
  assert.equal(el('sttd-disconnect').hidden, true, 'the trigger hides while confirming');
  assert.equal(el('sttd-disconnect-question').textContent, JA('common.disconnectConfirm'));
  assert.equal(el('sttd-switch').disabled, true, 'account switch waits for the decision');
  assert.equal(disconnects().length, 0);
  assert.equal(el('sttd-disconnect-no').click(), true);
  await settle();
  assert.equal(el('sttd-disconnect-confirm').hidden, true);
  assert.equal(el('sttd-disconnect').hidden, false);
  assert.deepEqual([disconnects().length, connections().length, el('sttd-send').disabled], [0, 1, false], 'cancelled confirmation: nothing sent, still sendable');

  // 確認して解除（応答保留中は送信・切替・再確認・言語切替・はい/やめるを封鎖。二重クリックでPOSTは1つ）。
  disconnectMode = 'hold';
  el('sttd-disconnect').click();
  await settle();
  assert.equal(el('sttd-disconnect-yes').click(), true);
  await settle();
  assert.equal(disconnects().length, 1);
  assert.equal(el('sttd-disconnect-yes').click(), false, 'disabled while in flight');
  el('sttd-disconnect-yes').onclick();
  await settle();
  assert.equal(disconnects().length, 1, 'double click: one POST');
  const call = disconnects()[0];
  assert.deepEqual([call.method, call.credentials, call.cache, call.redirect, call.body, call.headers], ['POST', 'same-origin', 'no-store', 'error', undefined, { Authorization: 'Bearer synthetic-id-token' }]);
  assert.equal(el('sttd-disconnect-result').textContent, JA('common.disconnecting'));
  for (const id of ['sttd-send', 'sttd-text', 'sttd-switch', 'sttd-refresh']) assert.equal(el(id).disabled, true, `${id} locked while disconnecting`);
  assert.equal(el('sttd-lang-en').getAttribute('aria-disabled'), 'true');
  el('sttd-lang-en').click();
  await settle();
  assert.equal(ui.document.documentElement.lang, 'ja', 'language switch refused while disconnecting');
  assert.equal(ui.same('/console').length, 0);
  connectionState = 'unlinked';
  holds.shift().hold.release({ status: 200, json: { state: 'unlinked' } });
  await settle();
  assert.equal(el('sttd-disconnect-result').textContent, JA('common.disconnectDone'));
  assert.equal(connections().length, 2, 'state re-checked after the disconnect');
  assert.equal(el('sttd-state-text').textContent, JA('common.state.unlinked'));
  assert.equal(el('sttd-disconnect').hidden, true, 'nothing to disconnect any more');
  assert.deepEqual([el('sttd-send').disabled, el('sttd-text').disabled], [true, true], 'sending blocked after the disconnect');
  assert.equal(el('sttd-result').textContent, JA('console.sendDisabled'));
  assert.equal(el('sttd-switch').disabled, false, 'account switch available again');

  // 解除後に購読が戻っても、本人が「状態を再確認」を押すまで送信は封鎖のまま。再確認で解ける。
  connectionState = 'subscribed';
  assert.equal(el('sttd-refresh').click(), true);
  await settle();
  assert.equal(connections().length, 3);
  assert.equal(el('sttd-send').disabled, false, 'sendable after an explicit re-check');
  assert.equal(el('sttd-result').textContent, '');
  assert.equal(el('sttd-disconnect-result').textContent, '');

  // 失敗（503）: 成功を装わず、状態を再確認し、送信は封鎖。
  disconnectMode = 'fail';
  el('sttd-disconnect').click();
  await settle();
  el('sttd-disconnect-yes').click();
  await settle();
  assert.equal(disconnects().length, 2);
  assert.equal(el('sttd-disconnect-result').textContent, JA('common.disconnectFailed'));
  assert.equal(connections().length, 4, 're-checked after the failure');
  assert.deepEqual([el('sttd-state-text').textContent, el('sttd-send').disabled], [JA('console.state.subscribed'), true], 'state shown as is, sending still blocked until re-check');
  el('sttd-refresh').click();
  await settle();
  assert.equal(el('sttd-send').disabled, false);

  // 通信失敗: 同じく失敗として扱う。
  disconnectMode = 'network';
  el('sttd-disconnect').click();
  await settle();
  el('sttd-disconnect-yes').click();
  await settle();
  assert.equal(disconnects().length, 3);
  assert.equal(el('sttd-disconnect-result').textContent, JA('common.disconnectFailed'));
  assert.equal(el('sttd-send').disabled, true);
  el('sttd-refresh').click();
  await settle();

  // 期限切れ/取得失敗のtoken: HTTPを始めず失敗。再確認でもtokenが無いのでログイン操作へ戻る。
  tokenMode = 'expired';
  disconnectMode = 'ok';
  el('sttd-disconnect').click();
  await settle();
  el('sttd-disconnect-yes').click();
  await settle();
  assert.equal(disconnects().length, 3, 'no POST without a token');
  assert.equal(el('sttd-account-text').textContent, JA('common.loginRefresh'));
  assert.equal(el('sttd-login').hidden, false);
  assert.equal(el('sttd-send').disabled, true);
  assert.equal(ui.api().length, 0, 'no API request in the whole scenario');
  assert.deepEqual([ui.calls.popups, ui.calls.signOuts], [0, 0]);
  for (const text of ui.writes) assert.equal(text.includes('synthetic-id-token'), false, 'no token in the page text');
  assert.equal(holds.length, 0);
  results.L6 = { disconnects: disconnects().length, connections: connections().length };
});
