// 表示言語（en/ja）と送信画面の接続解除を、合成入力だけで確かめる。importするのはpureなdist（connect/i18n.js・connect/console.js・
// connect/pages.js・oauth/provider.jsのrender・config/validate.js）だけで、SDK instance・DB・資格・HTTP・子process 0。kms-server.jsは評価しない
// （routing/Origin/Bearer/no-bodyの接合はPMの差分レビュー対象で、ここではHTTP結合試験をしない）。fixtureの値は全て合成値。
//   - L1/L2: Accept-Languageのq値・不正q値の不採用・未対応言語、cookieの欠落/不正/重複、明示選択の優先、Set-Cookieの形（session・Path・SameSite・Secure）。
//   - L3: 各画面（console・connect・OAuthログイン/同意・OAuthエラー）のHTML lang/題名/本文が選択言語で整合し、両言語の辞書キーが一致し、
//     machine code・CSRF・formのaction/methodを翻訳せず、言語リンクがformの外のGETリンクであること。
//   - L5/L6: 実CONSOLE_SCRIPTを合成DOM/SDK/fetchで実行。言語切替で文言・langが差し替わり、表示専用cookieが同期に設定されて連続切替の最後の選択が
//     残り、HTTP/送信/ログイン/解除を発火しない。送信中の切替は受けない。解除は確認→1回のPOST→状態再確認で、取消/失敗/期限切れで成功を装わず、送信を封鎖する。
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, test } from 'node:test';
import vm from 'node:vm';

import { consoleAsset, CONSOLE_SCRIPT, CONSOLE_SDK_BASE } from '../dist/connect/console.js';
import {
  DEFAULT_LANGUAGE,
  LANGUAGE_COOKIE,
  LANGUAGES,
  languageCookie,
  languageCookieAttributes,
  languageFromAcceptLanguage,
  languageFromCookieHeader,
  MESSAGES,
  selectLanguage,
  text,
} from '../dist/connect/i18n.js';
import { INTERACTION_SCRIPT, INTERACTION_SCRIPT_PATH, renderInteractionConsent, renderInteractionLogin } from '../dist/connect/pages.js';
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

test('L1 Accept-Language: q values rank ja against en, ties/unsupported/missing fall back to en, q=0 never selects, and an entry with an invalid q (out of range, too many digits, non-numeric, duplicated q, unknown parameter) is dropped instead of being promoted to q=1', () => {
  const cases = {
    'ja': 'ja',
    'ja;q=abc,en;q=0.8': 'en',
    'ja;q=1.5,en;q=0.8': 'en',
    'ja;q=0,en;q=0.8': 'en',
    'ja;q=0.1234,en;q=0.1': 'en',
    'ja;q=0.5;q=0.9,en;q=0.1': 'en',
    'ja;level=1,en;q=0.1': 'en',
    'ja;q=-0.5,en;q=0.1': 'en',
    'ja;q=.5,en;q=0.1': 'en',
    'ja;q=1.000,en;q=0.999': 'ja',
    'ja;Q=0.9,en;q=0.8': 'ja',
    'ja; q = 0.9 ,en;q=0.8': 'ja',
    'en;q=abc,ja;q=0.1': 'ja',
    'ja;q=abc': 'en',
    'ja;q=abc,en;q=abc': 'en',
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
  assert.deepEqual([languageCookieAttributes(true), languageCookieAttributes(false)], ['Path=/; SameSite=Lax; Secure', 'Path=/; SameSite=Lax']);
  assert.equal(languageCookie('en', true), `sttd_language=en; ${languageCookieAttributes(true)}`, 'the browser-side write uses the same attributes as Set-Cookie');
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
  for (const [name, path] of [['console', '/console'], ['login', '/interaction/uid-1'], ['consent', '/interaction/uid-1']]) {
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
  assert.ok(consoleJa.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax; Secure"') && consoleEn.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax; Secure"'), 'the console passes the fixed cookie attributes (https issuer: Secure)');
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="Dotsへ送る文を入力してください（4096バイトまで）"[^>]*><\/textarea>/.test(consoleJa));
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="Enter the text to send to Dots \(up to 4096 bytes\)"[^>]*><\/textarea>/.test(consoleEn));
  for (const id of ['sttd-disconnect', 'sttd-disconnect-confirm', 'sttd-disconnect-yes', 'sttd-disconnect-no', 'sttd-disconnect-result']) assert.ok(consoleEn.includes(`id="${id}"`), id);
  assert.equal(consoleEn.includes('href="/connect"'), false, 'console no longer sends the user to /connect to disconnect');
  // Dots設定案内: 長い指示文は初期折りたたみのdetails（openなし）内のpreにあり、summaryとコピーボタンは各言語の文言。コピーボタンはdetailsの外（閉じたままでも押せる）。
  for (const [lang, html] of [['en', consoleEn], ['ja', consoleJa]]) {
    for (const kind of ['test', 'operation']) {
      const block = /<details id="sttd-guide-(?:test|operation)"[^>]*>[\s\S]*?<\/details>/g;
      const details = [...html.matchAll(block)].map((m) => m[0]);
      assert.equal(details.length, 2, `${lang}: two details blocks`);
      const own = details.find((d) => d.startsWith(`<details id="sttd-guide-${kind}"`));
      assert.ok(own && !/<details[^>]*\sopen/.test(own), `${lang}/${kind}: collapsed initially`);
      assert.ok(own.includes(`<summary id="sttd-guide-${kind}-summary"`) && own.includes(`<pre id="sttd-guide-${kind}-text"`), `${lang}/${kind}: summary + pre inside`);
      assert.equal(own.includes(`id="sttd-copy-${kind}"`), false, `${lang}/${kind}: the copy button is outside the details`);
      assert.ok(html.indexOf(`id="sttd-copy-${kind}"`) > html.indexOf(own) + own.length, `${lang}/${kind}: copy button follows its details`);
    }
    assert.ok(html.indexOf('id="sttd-guide"') < html.indexOf('id="sttd-send-section"'), `${lang}: guide precedes the send section`);
    assert.ok(html.indexOf('id="sttd-connection"') < html.indexOf('id="sttd-guide"'), `${lang}: guide follows the connection section`);
  }
  assert.ok(consoleJa.includes('>テスト用の指示文を表示（手順1）</summary>') && consoleEn.includes('>Show the operational instructions (step 3)</summary>'));
  assert.equal(/開発用|development send|テスト送信|test send/i.test(consoleEn + consoleJa), false, 'console is presented as the send screen');
  // 旧接続画面は無い: 辞書にconnect.*キーが無く、どの画面も/connectへリンクしない。interaction画面はOAuth専用script（/interaction/app.js）だけを読む。
  assert.deepEqual(Object.keys(MESSAGES.en).filter((key) => key.startsWith('connect.')), [], 'no legacy connection-page dictionary');
  for (const name of Object.keys(pages)) for (const lang of ['en', 'ja']) assert.equal(/href="\/connect|\/connect\/app\.js|sttd-console-link/.test(pages[name](lang)), false, `${name}/${lang}: no link to the removed connection page`);
  assert.equal(INTERACTION_SCRIPT_PATH, '/interaction/app.js');
  for (const lang of ['en', 'ja']) for (const name of ['login', 'consent']) assert.ok(pages[name](lang).includes(`<script type="module" src="${INTERACTION_SCRIPT_PATH}"></script>`), `${name}/${lang}: interaction script`);
  // scriptは辞書を埋め込み、両言語を持つ（動作はL5〜L8の実行で確かめる）。
  for (const script of [CONSOLE_SCRIPT, INTERACTION_SCRIPT]) {
    assert.ok(script.includes(`const TEXT = ${JSON.stringify(MESSAGES)};`), 'the fixed dictionary is embedded');
    for (const banned of ['localStorage', 'sessionStorage', 'indexedDB', 'innerHTML']) assert.equal(script.includes(banned), false, `no ${banned}`);
  }
  assert.equal(INTERACTION_SCRIPT.includes('document.cookie'), false, 'the interaction script does not touch cookies (server links only)');
  assert.equal(/\/v1\/web\//.test(INTERACTION_SCRIPT), false, 'the interaction script has no connection-state or disconnect call (the send screen owns them)');
  results.L3 = { pages: Object.keys(pages).length, keys: Object.keys(MESSAGES.en).length };
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
  /** browserのcookie jarの合成: 書込みを順に記録し、同名の最後の値を保持する。読取りは回数だけ数える（scriptは読まないはず）。 */
  const cookies = { writes: [], reads: 0, jar: new Map() };
  const document = {
    body: { dataset },
    documentElement,
    title: /<title>([^<]*)<\/title>/.exec(html)[1],
    getElementById: (id) => elements.get(id) ?? null,
    querySelectorAll: (selector) => {
      assert.equal(selector, '[data-sttd-i18n]');
      return [...elements.values()].filter((element) => Object.hasOwn(element.dataset, 'sttdI18n'));
    },
    get cookie() {
      cookies.reads += 1;
      return [...cookies.jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    },
    set cookie(value) {
      const text = String(value);
      cookies.writes.push(text);
      const [pair] = text.split(';');
      const index = pair.indexOf('=');
      cookies.jar.set(pair.slice(0, index), pair.slice(index + 1));
    },
  };
  return { document, elements, writes, cookies };
}

/**
 * CONSOLE_SCRIPTを合成のSDK・fetchで実行する。同originのfetchはonSame(entry)、API originへのfetchはonApi(entry)が返す応答
 * （{status, json}かthrowするPromise）。tokenの取得はhooks.token()で差し替えられる（期限切れの合成）。
 */
async function runConsole(language, { onApi, onSame, token, navigator }) {
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
  const globals = { document: dom.document, fetch, crypto: { randomUUID }, TextEncoder, setTimeout, clearTimeout, AbortController, __sdk: sdk };
  if (navigator !== undefined) globals.navigator = navigator;
  const context = vm.createContext(globals);
  await vm.runInContext(`(async () => {\n${source}\n})()`, context, { filename: 'console-app.js' });
  await settle();
  const same = (path) => fetches.filter((entry) => entry.url === path || entry.url.startsWith(`${path}?`));
  const api = () => fetches.filter((entry) => entry.url.startsWith(`${API}/`));
  return { ...dom, calls, fetches, api, same, el: (id) => dom.elements.get(id) };
}

const JA = (key) => MESSAGES.ja[key];
const EN = (key) => MESSAGES.en[key];
const i18nTexts = (ui) => Object.fromEntries(ui.document.querySelectorAll('[data-sttd-i18n]').map((node) => [node.dataset.sttdI18n, node.textContent]));

test('L5 language switch in the real console script: the Japanese page switches to English in place (html lang, title, every fixed text, placeholder, dynamic status) and writes the display cookie synchronously in the fixed form with no HTTP request, API call, popup, sign-out or disconnect; rapid en→ja→en keeps the last choice; the typed text is kept; clicking the current language does nothing; the switch is refused while sending', { timeout: 20_000 }, async () => {
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
      throw new Error(`unexpected same-origin request ${entry.url}`);
    },
  });
  const { el } = ui;
  const COOKIE = (code) => `sttd_language=${code}; Path=/; SameSite=Lax; Secure`;
  assert.equal(ui.document.documentElement.lang, 'ja');
  assert.equal(ui.document.title, JA('console.title'));
  assert.equal(el('sttd-state-text').textContent, JA('console.state.subscribed'));
  assert.equal(el('sttd-account-text').textContent, JA('console.accountSignedIn'));
  assert.deepEqual(i18nTexts(ui)['console.heading'], JA('console.heading'));
  assert.equal(el('sttd-lang-ja').getAttribute('aria-current'), 'true');
  assert.equal(el('sttd-lang-en').getAttribute('aria-current'), 'false');
  assert.deepEqual([ui.cookies.writes, ui.cookies.reads], [[], 0], 'loading touches no cookie');

  // 同じ言語のクリックは何もしない（cookie書込み 0）。
  assert.equal(el('sttd-lang-ja').click(), true, 'navigation prevented');
  await settle();
  assert.deepEqual(ui.cookies.writes, []);

  // Englishへ切替: 画面内で差し替え、表示cookieを同期に1回書く。HTTP・API・popup・signOut・解除は0。
  const before = { api: ui.api().length, popups: ui.calls.popups, signOuts: ui.calls.signOuts, fetches: ui.fetches.length };
  assert.equal(el('sttd-lang-en').click(), true, 'navigation prevented (in-place switch)');
  assert.deepEqual(ui.cookies.writes, [COOKIE('en')], 'the cookie is written synchronously, before any await');
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
  assert.equal(ui.fetches.length, before.fetches, 'no HTTP request for the language change');
  assert.deepEqual([ui.api().length, ui.calls.popups, ui.calls.signOuts, ui.same('/v1/web/disconnect').length], [before.api, before.popups, before.signOuts, 0]);
  assert.equal(ui.cookies.reads, 0, 'the script never reads cookies');
  assert.equal(el('sttd-send').disabled, false, 'still sendable after the switch');

  // 入力中の切替で入力は消えない。連続切替（ja→en→ja）は同期に書くので、最後の選択がcookie jarと画面の両方に残る。
  el('sttd-text').value = 'keep me';
  assert.equal(el('sttd-lang-ja').click(), true);
  assert.equal(el('sttd-lang-en').click(), true);
  assert.equal(el('sttd-lang-ja').click(), true);
  await settle();
  assert.equal(el('sttd-text').value, 'keep me');
  assert.deepEqual(ui.cookies.writes, [COOKIE('en'), COOKIE('ja'), COOKIE('en'), COOKIE('ja')], 'one fixed-form write per change, in order');
  assert.equal(ui.cookies.jar.get('sttd_language'), 'ja', 'the last explicit choice is what the jar holds');
  assert.equal(ui.document.documentElement.lang, 'ja');
  assert.equal(ui.cookies.jar.size, 1, 'no other cookie is written');
  for (const write of ui.cookies.writes) assert.equal(/Max-Age|Expires|Domain|HttpOnly/i.test(write), false, 'session cookie, display only');

  // 送信中は切替を受けない（文言・lang・fetchが変わらない）。送信は1件のまま。
  mode = 'hold';
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(holds.length, 1);
  assert.equal(el('sttd-lang-en').getAttribute('aria-disabled'), 'true');
  assert.equal(el('sttd-lang-en').click(), true, 'prevented, ignored');
  await settle();
  assert.equal(ui.document.documentElement.lang, 'ja');
  assert.equal(ui.cookies.writes.length, 4, 'no cookie write while sending');
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
  assert.equal(ui.cookies.jar.get('sttd_language'), 'en');
  assert.equal(ui.api().length, 1, 'one POST in total');
  assert.equal(ui.fetches.length, 2, 'only the connection check and the one POST left the page');
  results.L5 = { cookieWrites: ui.cookies.writes.length, cookieReads: ui.cookies.reads, apiCalls: ui.api().length, fixedTexts: Object.keys(texts).length };
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
  assert.deepEqual(ui.cookies.writes, [], 'no cookie write while disconnecting');
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
  assert.deepEqual([ui.cookies.writes, ui.cookies.reads], [[], 0], 'disconnecting never touches cookies');
  assert.equal(holds.length, 0);
  results.L6 = { disconnects: disconnects().length, connections: connections().length };
});

test('L7 Dots guide in the real console script: both fixed instruction texts are shown in the selected language and follow a switch; a copy click writes exactly the fixed text of the current language to the clipboard once (nothing read, no permission, no HTTP, no send, textarea untouched); a rejected write or a missing clipboard shows the manual-copy fallback instead of success; delivered never marks a step complete', { timeout: 20_000 }, async () => {
  const clipboard = { writes: [], reads: 0, mode: 'ok' };
  const navigator = {
    clipboard: {
      writeText: (value) => {
        clipboard.writes.push(value);
        return clipboard.mode === 'ok' ? Promise.resolve() : Promise.reject(new Error('synthetic NotAllowedError'));
      },
      readText: () => {
        clipboard.reads += 1;
        return Promise.resolve('');
      },
    },
    permissions: {
      query: () => {
        throw new Error('permission query must not be used');
      },
    },
  };
  const ui = await runConsole('ja', {
    navigator,
    onApi: async (entry) => ({ status: 200, json: { commandId: JSON.parse(entry.body).commandId, state: 'delivered' } }),
    onSame: async (entry) => {
      if (entry.url === '/v1/web/connection') return { status: 200, json: { state: 'subscribed' } };
      throw new Error(`unexpected same-origin request ${entry.url}`);
    },
  });
  const { el } = ui;
  // 表示: 辞書の固定文（docsのcode blockと同文であることはPMが文書照合）。textareaはpresetされず空。
  assert.equal(el('sttd-guide-test-text').textContent, JA('guide.testText'));
  assert.equal(el('sttd-guide-operation-text').textContent, JA('guide.operationText'));
  assert.equal(el('sttd-text').value, '', 'no preset text');
  assert.ok(JA('guide.testText').includes('\n\n1. ') && JA('guide.operationText').includes('\n5. '), 'multi-line instruction texts');
  assert.equal(el('sttd-copy-result').textContent, '');
  assert.deepEqual([el('sttd-copy-test').disabled, el('sttd-copy-operation').disabled], [false, false], 'copy buttons usable without opening the details');
  const fetchesBefore = ui.fetches.length;

  // テスト用をコピー: 固定文だけを1回書く。読取り/permission/HTTP/送信 0。入力中の本文は変えない。
  el('sttd-text').value = 'my draft';
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.deepEqual(clipboard.writes, [JA('guide.testText')]);
  assert.equal(el('sttd-copy-result').textContent, JA('guide.copied'));
  assert.deepEqual([clipboard.reads, ui.fetches.length, ui.api().length, el('sttd-text').value], [0, fetchesBefore, 0, 'my draft']);
  assert.equal(el('sttd-send').disabled, false, 'copying does not change the send state');

  // 言語切替後は表示が英語になり、以前の言語に対する「コピーしました」は残らない。コピー内容も英語文面と一致する。
  assert.equal(el('sttd-lang-en').click(), true);
  await settle();
  assert.equal(el('sttd-guide-test-text').textContent, EN('guide.testText'));
  assert.equal(el('sttd-guide-operation-text').textContent, EN('guide.operationText'));
  assert.equal(el('sttd-guide-test-summary').textContent, EN('guide.showTest'));
  assert.equal(el('sttd-copy-result').textContent, '', 'the previous copied status is cleared on a language change');
  assert.equal(el('sttd-copy-operation').click(), true);
  await settle();
  assert.deepEqual(clipboard.writes, [JA('guide.testText'), EN('guide.operationText')]);
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copied'));

  // 保留中のclipboard Promise: 重ね押し（別mode）は2回目のwriteを出さず、両ボタンと言語切替を封鎖。本文入力・送信はclipboard完了待ちに巻き込まれない。
  const held = gate();
  clipboard.mode = 'hold';
  navigator.clipboard.writeText = (value) => {
    clipboard.writes.push(value);
    if (clipboard.mode === 'hold') return held.promise;
    return clipboard.mode === 'ok' ? Promise.resolve() : Promise.reject(new Error('synthetic NotAllowedError'));
  };
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(clipboard.writes.length, 3);
  assert.equal(el('sttd-copy-result').textContent, '', 'no result while pending');
  assert.deepEqual([el('sttd-copy-test').disabled, el('sttd-copy-operation').disabled], [true, true], 'both copy buttons locked while a copy is pending');
  assert.equal(el('sttd-copy-operation').click(), false);
  el('sttd-copy-operation').onclick();
  el('sttd-copy-test').onclick();
  await settle();
  assert.equal(clipboard.writes.length, 3, 'no second write while pending (re-entry refused)');
  assert.equal(el('sttd-lang-ja').getAttribute('aria-disabled'), 'true');
  assert.equal(el('sttd-lang-ja').click(), true);
  await settle();
  assert.equal(ui.document.documentElement.lang, 'en', 'language switch refused while a copy is pending');
  assert.equal(ui.cookies.writes.length, 1, 'no new cookie write');
  // 保留中でも本文入力と送信はできる（API/本文処理をclipboardへ巻き込まない）。
  el('sttd-text').value = 'while copying';
  assert.equal(el('sttd-send').disabled, false);
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(ui.api().length, 1, 'the POST went out while the copy was still pending');
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'));
  assert.equal(JSON.parse(ui.api()[0].body).text, 'while copying');
  // 完了後: 結果は始めたコピー（英語のテスト用）に対応し、再操作できる。
  held.release();
  await settle();
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copied'));
  assert.deepEqual([el('sttd-copy-test').disabled, el('sttd-copy-operation').disabled], [false, false]);
  assert.equal(el('sttd-lang-ja').getAttribute('aria-disabled'), 'false');
  el('sttd-new').click();
  await settle();

  // 書込みの拒否（保留後にreject）: 成功を装わず手動コピーの案内、終了後は再操作可。
  const heldReject = gate();
  clipboard.mode = 'hold';
  navigator.clipboard.writeText = (value) => {
    clipboard.writes.push(value);
    return heldReject.promise.then(() => Promise.reject(new Error('synthetic NotAllowedError')));
  };
  assert.equal(el('sttd-copy-operation').click(), true);
  await settle();
  assert.equal(clipboard.writes.length, 4);
  assert.equal(clipboard.writes[3], EN('guide.operationText'));
  heldReject.release();
  await settle();
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copyFailed'));
  assert.equal(el('sttd-copy-test').disabled, false, 'operable again after a failure');
  assert.equal(el('sttd-guide-operation-text').textContent, EN('guide.operationText'), 'the text stays visible for manual copy');
  // 同期throwも失敗として扱う。
  navigator.clipboard.writeText = () => {
    clipboard.writes.push('throw');
    throw new TypeError('synthetic sync failure');
  };
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copyFailed'));
  assert.equal(el('sttd-copy-operation').disabled, false);
  clipboard.writes.pop();
  clipboard.mode = 'reject';
  navigator.clipboard.writeText = (value) => {
    clipboard.writes.push(value);
    return Promise.reject(new Error('synthetic NotAllowedError'));
  };
  el('sttd-copy-test').click();
  await settle();
  assert.equal(clipboard.writes.length, 5);
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copyFailed'));

  // 送信してdeliveredになっても、段階の完了・本文一致を自動表示しない（結果欄は配送状態だけ）。
  el('sttd-text').value = 'short test';
  const writesBefore = ui.writes.length;
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'));
  // 送信で書かれる画面文は配送状態・account/接続状態・既存のコピー結果だけ（段階完了・本文一致・切替済みを示す新しい文は無い）。
  const allowed = new Set(['', EN('console.accountSignedIn'), EN('console.state.subscribed'), EN('guide.copyFailed'), EN('console.sending'), EN('console.state.delivered')]);
  const unexpected = ui.writes.slice(writesBefore).filter((written) => !allowed.has(written));
  assert.deepEqual(unexpected, [], 'no automatic step-complete or match message');
  assert.equal(ui.api().length, 2, 'two POSTs, each started only by the send button');
  assert.equal(clipboard.writes.length, 5, 'sending copies nothing');
  for (const written of clipboard.writes) assert.equal(written.includes('short test') || written.includes('my draft') || written.includes('while copying') || written.includes('synthetic-id-token'), false, 'only the fixed instructions reach the clipboard');
  assert.deepEqual([...new Set(clipboard.writes)].sort(), [EN('guide.operationText'), EN('guide.testText'), JA('guide.testText')].sort(), 'only fixed instruction texts were ever written');
  results.L7 = { clipboardWrites: clipboard.writes.length, clipboardReads: clipboard.reads, apiCalls: ui.api().length };
});

test('L8 Dots guide without a clipboard API: the copy button does not throw, shows the manual-copy guidance, writes nothing and starts no request', { timeout: 20_000 }, async () => {
  const ui = await runConsole('en', {
    onApi: async () => {
      throw new Error('no API request expected');
    },
    onSame: async (entry) => {
      if (entry.url === '/v1/web/connection') return { status: 200, json: { state: 'linked' } };
      throw new Error(`unexpected same-origin request ${entry.url}`);
    },
  });
  const { el } = ui;
  const fetchesBefore = ui.fetches.length;
  assert.equal(el('sttd-copy-operation').click(), true);
  await settle();
  assert.equal(el('sttd-copy-result').textContent, EN('guide.copyUnavailable'));
  assert.equal(el('sttd-guide-operation-text').textContent, EN('guide.operationText'));
  assert.equal(ui.fetches.length, fetchesBefore);
  assert.equal(el('sttd-send').disabled, true, 'linked (not subscribed): still not sendable; the guide changes no state');
  assert.equal(el('sttd-lang-ja').click(), true);
  await settle();
  assert.equal(el('sttd-copy-result').textContent, '', 'the copy status is cleared on a language change');
  assert.equal(el('sttd-guide-test-text').textContent, JA('guide.testText'));
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(el('sttd-copy-result').textContent, JA('guide.copyUnavailable'), 'the guidance follows the new language when copying again');
  assert.equal(ui.fetches.length, fetchesBefore);
});
