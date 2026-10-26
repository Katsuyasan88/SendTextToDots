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
import { INTERACTION_SCRIPT, INTERACTION_SCRIPT_PATH, renderInteractionAccessDenied, renderInteractionConsent, renderInteractionLogin } from '../dist/connect/pages.js';
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
    console: (lang) => consoleAsset('/console', WEB, { language: lang, nonce: 'd'.repeat(64), secure: true }).body,
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
  assert.ok(consoleJa.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax; Secure"') && consoleEn.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax; Secure"'), 'the console passes the fixed cookie attributes (secure: true → Secure)');
  assert.ok(consoleAsset('/console', WEB, { language: 'en', nonce: 'd'.repeat(64), secure: false }).body.includes(' data-sttd-cookie-attributes="Path=/; SameSite=Lax"'), 'http localhost: no Secure');
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="例: SendTextToDotsからのテストです"[^>]*><\/textarea>/.test(consoleJa));
  assert.ok(/<textarea id="sttd-text"[^>]*placeholder="Example: Hello from SendTextToDots \(delivery test\)"[^>]*><\/textarea>/.test(consoleEn));
  assert.ok(consoleJa.includes('>送信</button>') && consoleEn.includes('>Send</button>'), 'main button');
  for (const n of [1, 2, 3, 4, 5]) assert.ok(consoleEn.includes(`id="sttd-step-${n}-head"`) && consoleEn.includes(`id="sttd-panel-${n}"`), `step ${n} present`);
  assert.ok(/<li class="sttd-step" id="sttd-step-1" data-sttd-state="current">/.test(consoleEn) && /<li class="sttd-step" id="sttd-step-2" data-sttd-state="locked">/.test(consoleEn), 'only step 1 starts active');
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
    assert.ok(html.indexOf('id="sttd-panel-3"') < html.indexOf('id="sttd-panel-4"') && html.indexOf('id="sttd-panel-4"') < html.indexOf('id="sttd-panel-5"'), `${lang}: step panels in order`);
  }
  assert.ok(consoleJa.includes('>テスト用の指示文を表示</summary>') && consoleEn.includes('>Show the operational instructions</summary>'));
  // 各panelの先頭に可視見出し（wizard.step1〜5）があり、sectionのaria-labelledbyはそれを指す。旧3段階ガイドの番号は画面文言に残らない。
  for (const n of [1, 2, 3, 4, 5]) assert.ok(consoleEn.includes(`<section id="sttd-panel-${n}" class="sttd-panel" aria-labelledby="sttd-panel-${n}-title"`) && consoleEn.includes(`<h2 id="sttd-panel-${n}-title" class="sttd-panel-title" data-sttd-i18n="wizard.step${n}">${MESSAGES.en[`wizard.step${n}`]}</h2>`), `panel ${n} heading`);
  assert.equal(/\((step|Step) [1-3]\)|（手順[1-3]）|>(Step|手順) ?[1-3][:：]/.test(consoleEn.replace(/<h2[^>]*>[^<]*<\/h2>|<button type="button" id="sttd-step-[1-5]-head"[^>]*>[^<]*<\/button>/g, '') + consoleJa.replace(/<h2[^>]*>[^<]*<\/h2>|<button type="button" id="sttd-step-[1-5]-head"[^>]*>[^<]*<\/button>/g, '')), false, 'no legacy sub-step numbers outside the wizard headings');
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
  assert.equal(/\bimport\(/.test(INTERACTION_SCRIPT), false, 'the interaction script keeps its static SDK import');
  assert.equal(/^import /m.test(CONSOLE_SCRIPT), false, 'the local send screen has no static SDK import (loaded on explicit sign-in only)');
  assert.equal(/\/v1\/web\//.test(INTERACTION_SCRIPT), false, 'the interaction script has no connection-state or disconnect call (the send screen owns them)');
  results.L3 = { pages: Object.keys(pages).length, keys: Object.keys(MESSAGES.en).length };
});

test('L7 OAuth access refusal: the login script shows the not-permitted message only for the fixed 403 access_denied (other 403 / malformed / other failures keep the existing message); the consent refusal page is a fixed bilingual notice without forms, CSRF or identifiers', async () => {
  const IMPORTS = [
    `import { initializeApp } from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-app.js';`,
    `import { getAuth, OAuthProvider, signInWithPopup, signOut } from 'https://www.gstatic.com/firebasejs/13.0.0/firebase-auth.js';`,
  ];
  for (const line of IMPORTS) assert.ok(INTERACTION_SCRIPT.includes(line), 'the fixed SDK imports are present');
  const source = IMPORTS.reduce((text, line) => text.replace(line, ''), INTERACTION_SCRIPT);
  const run = async (lang, response) => {
    const nodes = new Map(['sttd-message', 'sttd-continue', 'sttd-apple-login', 'sttd-switch-account'].map((id) => [id, { id, hidden: true, textContent: '', onclick: null }]));
    const fetches = [];
    const reloads = [];
    const context = vm.createContext({
      document: { body: { dataset: { sttdView: 'interaction-login', sttdFirebase: JSON.stringify(WEB), sttdLanguage: lang, sttdInteraction: 'uid-1', sttdCsrf: 'csrf-1' } }, getElementById: (id) => nodes.get(id) ?? null },
      location: { reload: () => reloads.push(1) },
      fetch: async (url, init) => (fetches.push({ url, init }), response),
      initializeApp: () => ({}),
      getAuth: () => ({ currentUser: { getIdToken: async () => 'synthetic-id-token' }, authStateReady: async () => {} }),
      OAuthProvider: class {},
      signInWithPopup: async () => {
        throw new Error('no popup in this test');
      },
      signOut: async () => {},
    });
    await vm.runInContext(`(async () => {\n${source}\n})()`, context);
    await nodes.get('sttd-continue').onclick();
    return { message: nodes.get('sttd-message').textContent, fetches, reloads };
  };
  const json = (status, body) => ({ status, json: async () => body });
  for (const lang of ['en', 'ja']) {
    const refused = await run(lang, json(403, { error: { code: 'access_denied', retryable: false } }));
    assert.equal(refused.message, MESSAGES[lang]['interaction.accessDenied'], `${lang}: fixed refusal`);
    assert.equal(refused.fetches.length, 1);
    for (const other of [json(403, { error: { code: 'forbidden', retryable: false } }), { status: 403, json: async () => JSON.parse('not json') }, json(409, { error: { code: 'access_denied' } }), json(503, { error: { code: 'access_denied' } })]) {
      assert.equal((await run(lang, other)).message, MESSAGES[lang]['interaction.loginConfirmFailed'], `${lang}: not disguised as an access refusal`);
    }
    const ok = await run(lang, { status: 204, json: async () => null });
    assert.deepEqual([ok.reloads.length, ok.message], [1, '']);
  }
  assert.notEqual(MESSAGES.ja['interaction.accessDenied'], MESSAGES.ja['interaction.loginConfirmFailed']);
  assert.ok(MESSAGES.ja['interaction.accessDenied'].includes('このサービスの利用が許可されていません') && MESSAGES.ja['interaction.accessDenied'].includes('運営者'));

  for (const lang of ['en', 'ja']) {
    const page = renderInteractionAccessDenied(WEB, 'uid-1', lang);
    assert.ok(page.startsWith(`<!DOCTYPE html>\n<html lang="${lang}">`));
    assert.ok(page.includes(MESSAGES[lang]['interaction.accessDenied']));
    assert.equal(/<form|csrf|data-sttd-csrf|data-sttd-interaction/i.test(page), false, 'no form, CSRF or interaction binding');
  }
  results.L7 = { languages: 2 };
});
