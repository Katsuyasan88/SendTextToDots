// 本人用のブラウザ送信画面（/console）。Appleログイン（既存Firebase Web SDK 13.0.0・Apple providerのみ・追加scopeなし）・
// 接続/購読状態（同originの既存 /v1/web/connection）・接続解除（同originの既存 POST /v1/web/disconnect。確認してから1回だけ）・
// 利用者が入力した本文の送信・中止・本人のクリックによる同じIDの結果確認。表示はen/ja（connect/i18n.ts）。
//   - 本文欄は空で始まり、例文・定型文・方向の選択・固定taskは無い。入力値をtrim・正規化せずそのままv2の5項目で送る。
//   - 指示・中止・結果確認は、固定Functions originへbrowserから直接送る（MCPは本文を中継しない）。tokenはAuthorizationだけ、credentials:omit。
//   - 本文はRAM/DOMだけ（localStorage・sessionStorage・IndexedDB・URL・ログへ保存0。Firebase SDK自身の認証session保存とは別）。
//   - 空・空白だけ・対にならないsurrogate・4096 UTF-8 byte超は通信前に拒否する（maxlengthは補助で、byte検査の代わりにしない）。
//   - 送信POSTは最大25秒（元期限内）、二重クリックでPOSTを増やさない。送信中は本文・account切替・解除・言語切替を封鎖し中止だけ。
//     終端後は「新しい送信」を明示に押すまで再送しない。自動POST再送・定期poll 0。中止は同commandIdへ最大5秒。
//   - 表示はHTTP statusではなくstate。deliveredは送信先の受領で、同じDotの反応は自動確認しない。未確定は成功扱いしない。
//   - 解除は本人の確認（はい）の後に1回だけPOSTし、処理中は送信・切替・再確認と排他。確認の取消・失敗・期限切れでは成功を装わず、
//     終了後は接続状態を再確認し、本人が「状態を再確認」を押すまで送信を封鎖する。
//   - 言語はサーバーが選んだ初期言語（HTMLのlang・本文）で始まり、English/日本語の明示選択は画面内で文言を差し替え、同じGETの`?lang=`を
//     同originへ1回送って表示専用cookieへ保存する（navigation・form送信・ログイン・解除・送信を起こさない）。送信中・処理中は切替を受けない。
//   - HTML・JS・CSSは固定文字列で、inline script/style・実filesystem読取り・新framework・新依存は無い。動的な値はdata属性へescape、表示はtextContent。
//   - apiOriginとweb configは信頼する呼出元（connect/kms-server.ts）だけが渡す。利用者・argv・envから任意originを選ばせない。
// 各要求の元期限（POST 25秒・中止5秒・同ID確認10秒）に認証取得を含め、期限後のtokenで通信を始めない。
//   backendのdelivery_unknownでも本人クリックの同ID確認を残す。認証切替・接続再確認・解除は排他し、確認済みの現在状態まで送信を封鎖する。
//   httpsのAPI originはDNS hostだけ（IP literal拒否）。

import { DEFAULT_LANGUAGE, isLanguage, languageHref, messagesJson, text, type Language, type MessageKey } from './i18n.js';
import { FIREBASE_POPUP_SCRIPT_ORIGIN, FIREBASE_WEB_SDK_VERSION, type FirebaseWebConfig } from './pages.js';

export const CONSOLE_PATH = '/console';
export const CONSOLE_SCRIPT_PATH = '/console/app.js';
export const CONSOLE_STYLE_PATH = '/console/app.css';
/** 既存の接続画面と同じ公式CDNの固定版。 */
export const CONSOLE_SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;

/** 渡された設定の不正（固定message・値を持たない）。 */
export class ConsoleConfigError extends Error {
  override readonly name = 'ConsoleConfigError';
  constructor() {
    super('console_config_invalid');
  }
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

/**
 * API originの検査。`https://<DNS-host>`（port・path・query・userinfoなし）か、local fixtureの`http://127.0.0.1:<port>`だけ。
 * 正規形でない値・他のloopback表記・任意scheme・CSP区切りになり得る文字は拒否する。
 */
export function consoleApiOrigin(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z0-9.:/-]+$/.test(value)) throw new ConsoleConfigError();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConsoleConfigError();
  }
  // httpsはDNS hostだけ（IPv4 literalを拒否。IPv6 literalは上の文字検査で拒否済み）。
  const https = url.protocol === 'https:' && url.port === '' && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(url.hostname) && !/^[0-9.]+$/.test(url.hostname);
  const loopback = url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port !== '';
  if (!(https || loopback) || url.origin !== value) throw new ConsoleConfigError();
  return value;
}

function checkWeb(web: FirebaseWebConfig): void {
  for (const key of ['apiKey', 'authDomain', 'projectId'] as const) {
    if (typeof web?.[key] !== 'string' || web[key].length === 0) throw new ConsoleConfigError();
  }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(web.authDomain)) throw new ConsoleConfigError();
}

/**
 * /consoleの画面用header。既存の接続画面の固定Firebase SDK/script/iframe許可を再利用し、同originのCSSと固定API originのconnect-srcだけを
 * 加える（unsafe-inline・unsafe-eval・任意httpsなし）。既存OAuth画面のCSP（pageSecurityHeaders）は変えない。
 */
export function consoleSecurityHeaders(web: FirebaseWebConfig, apiOrigin: string): Record<string, string> {
  checkWeb(web);
  const api = consoleApiOrigin(apiOrigin);
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'self' ${CONSOLE_SDK_BASE} ${FIREBASE_POPUP_SCRIPT_ORIGIN}`,
      `connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com ${api}`,
      `frame-src https://${web.authDomain}`,
      "style-src 'self'",
      "img-src 'none'",
      "form-action 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  };
}

/** /consoleのHTML（1画面）。値はdata属性へescapeして渡す。文言は選択言語の辞書から入れ、scriptが同じキーで差し替える。 */
export function renderConsolePage(web: FirebaseWebConfig, apiOrigin: string, language: Language = DEFAULT_LANGUAGE): string {
  checkWeb(web);
  const api = consoleApiOrigin(apiOrigin);
  const lang: Language = isLanguage(language) ? language : DEFAULT_LANGUAGE;
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  /** 固定キーの文言をtextContentとして持つ要素（scriptの言語切替が同じキーで差し替える）。 */
  const i18n = (key: MessageKey) => ` data-sttd-i18n="${key}"`;
  const data = Object.entries({
    'sttd-firebase': JSON.stringify({ apiKey: web.apiKey, authDomain: web.authDomain, projectId: web.projectId }),
    'sttd-api-origin': api,
    'sttd-language': lang,
  })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  const current = (candidate: Language) => (candidate === lang ? ' aria-current="true"' : '');
  return `<!DOCTYPE html>
<html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${t('console.title')}</title>
<link rel="stylesheet" href="${CONSOLE_STYLE_PATH}">
<script type="module" src="${CONSOLE_SCRIPT_PATH}"></script></head>
<body${data}>
<main>
<nav class="sttd-language" aria-labelledby="sttd-language-label">
<span id="sttd-language-label"${i18n('common.language')}>${t('common.language')}</span>
<a id="sttd-lang-en" href="${languageHref(CONSOLE_PATH, 'en')}" hreflang="en" lang="en"${current('en')}>${t('common.languageEnglish')}</a>
<a id="sttd-lang-ja" href="${languageHref(CONSOLE_PATH, 'ja')}" hreflang="ja" lang="ja"${current('ja')}>${t('common.languageJapanese')}</a>
</nav>
<h1 id="sttd-heading"${i18n('console.heading')}>${t('console.heading')}</h1>
<p id="sttd-intro"${i18n('console.intro')}>${t('console.intro')}</p>
<section id="sttd-account" aria-labelledby="sttd-account-title">
<h2 id="sttd-account-title"${i18n('console.account')}>${t('console.account')}</h2>
<p id="sttd-account-text" role="status">${t('console.accountChecking')}</p>
<button type="button" id="sttd-login" hidden${i18n('common.appleLogin')}>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch" hidden${i18n('common.switchAccount')}>${t('common.switchAccount')}</button>
</section>
<section id="sttd-connection" aria-labelledby="sttd-connection-title">
<h2 id="sttd-connection-title"${i18n('console.connection')}>${t('console.connection')}</h2>
<p id="sttd-state-text" role="status">${t('console.connectionSignedOut')}</p>
<p id="sttd-start-guide" hidden${i18n('common.startGuide')}>${t('common.startGuide')}</p>
<div class="sttd-actions">
<button type="button" id="sttd-refresh" hidden${i18n('console.refresh')}>${t('console.refresh')}</button>
<button type="button" id="sttd-disconnect" hidden${i18n('common.disconnect')}>${t('common.disconnect')}</button>
</div>
<div id="sttd-disconnect-confirm" role="group" aria-labelledby="sttd-disconnect-question" hidden>
<p id="sttd-disconnect-question"${i18n('common.disconnectConfirm')}>${t('common.disconnectConfirm')}</p>
<button type="button" id="sttd-disconnect-yes"${i18n('common.disconnectYes')}>${t('common.disconnectYes')}</button>
<button type="button" id="sttd-disconnect-no"${i18n('common.disconnectNo')}>${t('common.disconnectNo')}</button>
</div>
<p id="sttd-disconnect-result" role="status"></p>
</section>
<section id="sttd-send-section" aria-labelledby="sttd-send-title">
<h2 id="sttd-send-title"${i18n('console.send')}>${t('console.send')}</h2>
<label id="sttd-text-label" for="sttd-text"${i18n('console.textLabel')}>${t('console.textLabel')}</label>
<textarea id="sttd-text" rows="4" maxlength="4096" placeholder="${t('console.textPlaceholder')}" disabled></textarea>
<div class="sttd-actions">
<button type="button" id="sttd-send" disabled${i18n('console.sendOne')}>${t('console.sendOne')}</button>
<button type="button" id="sttd-cancel" hidden${i18n('console.cancel')}>${t('console.cancel')}</button>
<button type="button" id="sttd-check" hidden${i18n('console.check')}>${t('console.check')}</button>
<button type="button" id="sttd-new" hidden${i18n('console.new')}>${t('console.new')}</button>
</div>
<p id="sttd-result" role="status"></p>
<p id="sttd-note" class="sttd-note"${i18n('console.note')}>${t('console.note')}</p>
</section>
</main>
</body></html>`;
}

/** 画面のstyle（同originの固定asset）。 */
export const CONSOLE_STYLE = `:root { color-scheme: light; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
body { margin: 0; background: #f5f6f8; color: #1d1f23; }
main { max-width: 40rem; margin: 0 auto; padding: 1rem; box-sizing: border-box; }
h1 { font-size: 1.35rem; margin: 0.5rem 0 1rem; }
h2 { font-size: 1.05rem; margin: 0 0 0.5rem; }
section { background: #fff; border: 1px solid #d9dce1; border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }
label { display: block; font-weight: 600; margin: 0.75rem 0 0.25rem; }
textarea { width: 100%; box-sizing: border-box; font: inherit; padding: 0.5rem; border: 1px solid #b8bdc6; border-radius: 6px; }
button { font: inherit; min-height: 44px; padding: 0.5rem 1rem; margin: 0.5rem 0.5rem 0 0; border-radius: 8px; border: 1px solid #1f5fbf; background: #1f5fbf; color: #fff; }
button:disabled { background: #c9ced6; border-color: #c9ced6; color: #5b616b; }
#sttd-cancel, #sttd-disconnect, #sttd-disconnect-yes { background: #fff; color: #b3261e; border-color: #b3261e; }
#sttd-disconnect-no { background: #fff; color: #1d1f23; border-color: #b8bdc6; }
#sttd-disconnect-confirm { border: 1px solid #b3261e; border-radius: 8px; padding: 0.75rem; margin-top: 0.75rem; }
.sttd-language { display: flex; gap: 0.75rem; align-items: center; justify-content: flex-end; font-size: 0.9rem; min-height: 44px; }
.sttd-language a { color: #1f5fbf; padding: 0.5rem 0.25rem; }
.sttd-language a[aria-current="true"] { font-weight: 700; text-decoration: none; color: #1d1f23; }
.sttd-language a[aria-disabled="true"] { color: #5b616b; pointer-events: none; }
.sttd-actions { display: flex; flex-wrap: wrap; }
#sttd-result, #sttd-disconnect-result { font-weight: 600; min-height: 1.5em; overflow-wrap: anywhere; }
.sttd-note { font-size: 0.85rem; color: #4a5059; }
[hidden] { display: none !important; }
`;

/**
 * 画面のscript（固定asset）。状態の表示・単回送信・中止・本人のクリックでの同ID確認・確認後の接続解除・言語の切替だけ。
 * 自動popup・自動再送・定期pollは無い。文言は埋め込んだ固定辞書（connect/i18n.ts）からキーで引く。
 */
export const CONSOLE_SCRIPT = `import { initializeApp } from '${CONSOLE_SDK_BASE}firebase-app.js';
import { getAuth, OAuthProvider, signInWithPopup, signOut } from '${CONSOLE_SDK_BASE}firebase-auth.js';

const body = document.body;
const API = body.dataset.sttdApiOrigin;
const auth = getAuth(initializeApp(JSON.parse(body.dataset.sttdFirebase)));
const TEXT = ${messagesJson()};
const POST_MS = 25000;
const CANCEL_MS = 5000;
const CHECK_MS = 10000;
const DISCONNECT_MS = 10000;
const LIFETIME_MS = 60000;
const MAX_TEXT_BYTES = 4096;
const LONE_SURROGATE = /\\p{Cs}/u;
const CONNECTION_STATES = ['unlinked', 'linked', 'subscribed', 'expired', 'change_pending'];
const ERROR_STATUSES = [400, 401, 403, 409, 422, 429];
const TERMINAL = ['delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown'];
const RANK = { in_flight: 1, delivery_unknown: 2, failed: 3, expired: 3, cancelled: 3, delivered: 4 };

const el = (id) => document.getElementById(id);
let lang = Object.hasOwn(TEXT, body.dataset.sttdLanguage) ? body.dataset.sttdLanguage : 'en';
/** 固定キーの文言（未知のキーは空文字。入力値を文言にしない）。 */
const T = (key) => (Object.hasOwn(TEXT[lang], key) ? TEXT[lang][key] : '');
let signedIn = false;
let connection = null;
let test = null;
let note = '';
let accountKey = 'console.accountChecking';
let connectionKey = 'console.connectionSignedOut';
// 認証切替・接続の再確認・解除の間は排他し、確認済みの現在状態が戻るまで送信を封鎖する。
let accountBusy = false;
let connectionSeq = 0;
// 解除の確認表示と結果。解除後は本人が「状態を再確認」を押すまで送信を封鎖する。
let confirming = false;
let disconnectKey = '';
let disconnected = false;

function phaseOf(current) {
  if (current.state !== null && TERMINAL.includes(current.state)) return 'settled';
  if (!current.postDone) return 'sending';
  if (current.rejected !== null) return 'settled';
  return 'unknown';
}

/** 本人のクリックで同じIDを1回確認できる時（結果不明・backendのdelivery_unknownを含む）。 */
function checkable(current) {
  return phaseOf(current) === 'unknown' || current.state === 'delivery_unknown';
}

function sendableNow() {
  return signedIn && connection === 'subscribed' && !accountBusy && !disconnected;
}

/** ログイン・切替・再確認・解除を受けない間（送信の1件が終わるまでと、認証切替・再確認・解除の処理中）。 */
function busy() {
  return accountBusy || test !== null;
}

/** 言語の切替を受けない間（送信中・中止の確認中・結果確認中・認証切替・再確認・解除の処理中。終端後の切替は文言の差し替えだけなので受ける）。 */
function languageLocked() {
  return accountBusy || (test !== null && (phaseOf(test) === 'sending' || test.cancel === 'pending' || test.checking));
}

function render() {
  const phase = test === null ? null : phaseOf(test);
  const sendable = sendableNow();
  el('sttd-account-text').textContent = T(accountKey);
  el('sttd-state-text').textContent = T(connectionKey);
  el('sttd-login').hidden = signedIn;
  el('sttd-switch').hidden = !signedIn;
  el('sttd-switch').disabled = busy() || confirming;
  el('sttd-login').disabled = busy();
  el('sttd-refresh').hidden = !signedIn;
  el('sttd-refresh').disabled = busy() || confirming;
  el('sttd-disconnect').hidden = !signedIn || confirming || connection === null || connection === 'unlinked';
  el('sttd-disconnect').disabled = busy();
  el('sttd-disconnect-confirm').hidden = !confirming;
  el('sttd-disconnect-yes').disabled = busy();
  el('sttd-disconnect-no').disabled = busy();
  el('sttd-disconnect-result').textContent = T(disconnectKey);
  el('sttd-text').disabled = !sendable || test !== null;
  el('sttd-send').disabled = !sendable || test !== null;
  el('sttd-cancel').hidden = test === null || (phase !== 'sending' && phase !== 'unknown') || test.cancel === 'answered' || test.cancel === 'unconfirmed';
  el('sttd-cancel').disabled = test !== null && test.cancel === 'pending';
  el('sttd-check').hidden = test === null || !checkable(test);
  el('sttd-check').disabled = test !== null && test.checking;
  el('sttd-new').hidden = test === null || phase === 'sending' || test.cancel === 'pending' || test.checking;
  for (const code of ['en', 'ja']) {
    const link = el('sttd-lang-' + code);
    link.setAttribute('aria-current', code === lang ? 'true' : 'false');
    link.setAttribute('aria-disabled', languageLocked() ? 'true' : 'false');
  }
  const lines = [];
  if (test !== null) {
    if (test.state !== null) lines.push(T('console.state.' + test.state));
    else if (phase === 'sending') lines.push(T('console.sending'));
    else if (test.rejected !== null) lines.push(T(test.rejected));
    else lines.push(T('console.unknown'));
    if (test.cancel === 'pending') lines.push(T('console.cancelPending'));
    if (test.cancel === 'unconfirmed' && test.state !== 'cancelled') lines.push(T('console.cancelUnconfirmed'));
    if (test.checkNote) lines.push(T(test.checkNote));
  } else if (note) {
    lines.push(T(note));
  } else if (disconnected && signedIn) {
    lines.push(T('console.sendDisabled'));
  }
  el('sttd-result').textContent = lines.join(' ');
}

/** 固定キーの文言を持つ要素と入力欄のplaceholder・title・html langを選択言語へ差し替える。 */
function applyLanguage() {
  if (document.documentElement) document.documentElement.lang = lang;
  document.title = T('console.title');
  for (const node of document.querySelectorAll('[data-sttd-i18n]')) node.textContent = T(node.dataset.sttdI18n);
  el('sttd-text').placeholder = T('console.textPlaceholder');
  render();
}

/**
 * 言語の明示選択。送信中・処理中は受けない。画面内で差し替え、同じ画面のGETを同originへ1回送って表示専用cookieへ保存する
 * （応答本文は使わない。navigation・form送信・ログイン・解除・送信は起こさない）。
 */
function chooseLanguage(next) {
  if (languageLocked() || !Object.hasOwn(TEXT, next)) return;
  if (next === lang) return;
  lang = next;
  applyLanguage();
  fetch('/console?lang=' + next, { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' }).catch(() => {});
}

function showConnection(state, key) {
  connection = state;
  connectionKey = key;
  el('sttd-start-guide').hidden = !(state === 'linked' || state === 'expired');
  render();
}

function signedOutView(key) {
  signedIn = false;
  confirming = false;
  accountKey = key || 'console.accountSignedOut';
  showConnection(null, 'console.connectionSignedOut');
}

async function idToken() {
  if (!auth.currentUser) throw new Error('signed_out');
  return auth.currentUser.getIdToken();
}

/** 接続状態の確認（開始時に以前の状態を捨てて送信を封鎖。後から始めた確認がある時の古い結果は採用しない）。 */
async function refreshConnection() {
  const mine = ++connectionSeq;
  connection = null;
  connectionKey = 'console.connectionChecking';
  render();
  let token;
  try {
    token = await idToken();
  } catch {
    if (mine === connectionSeq) signedOutView('common.loginRefresh');
    return;
  }
  if (mine !== connectionSeq) return;
  signedIn = true;
  accountKey = 'console.accountSignedIn';
  render();
  try {
    const response = await fetch('/v1/web/connection', { headers: { Authorization: 'Bearer ' + token }, credentials: 'same-origin', cache: 'no-store' });
    const json = response.ok ? await response.json() : null;
    if (mine !== connectionSeq) return;
    if (json && typeof json.state === 'string' && CONNECTION_STATES.includes(json.state)) {
      return showConnection(json.state, json.state === 'subscribed' ? 'console.state.subscribed' : 'common.state.' + json.state);
    }
  } catch {
    // 下の固定表示へ（状態不明を未接続・未購読と決め付けない）。
  }
  if (mine !== connectionSeq) return;
  showConnection(null, 'console.connectionUnavailable');
}

/** 認証切替・接続の再確認・解除を1つずつ行う（実行中は送信・切替・再確認・解除・言語切替を封鎖。送信中は始めない）。 */
async function exclusive(task) {
  if (accountBusy || test !== null) return;
  accountBusy = true;
  connection = null;
  render();
  try {
    await task();
  } finally {
    accountBusy = false;
    render();
  }
}

function login(switching) {
  return exclusive(async () => {
    confirming = false;
    disconnectKey = '';
    disconnected = false;
    try {
      if (switching) await signOut(auth);
      await signInWithPopup(auth, new OAuthProvider('apple.com'));
    } catch {
      if (!auth.currentUser) return signedOutView('common.loginFailed');
    }
    await refreshConnection();
  });
}

/** 本人の明示操作での再確認（解除後の送信封鎖もここで解く。確認済みの現在状態が戻るまでは封鎖のまま）。 */
function manualRefresh() {
  return exclusive(async () => {
    disconnected = false;
    disconnectKey = '';
    await refreshConnection();
  });
}

/** 期限までに決まった値だけを受け取る（後着の値では何も始めない）。 */
function within(promise, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ late: true }), Math.max(0, ms));
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve({ value });
      },
      () => {
        clearTimeout(timer);
        resolve({ failed: true });
      },
    );
  });
}

/**
 * 1要求（tokenはAuthorizationだけ・credentials omit・redirectを辿らない）。元期限は呼出し時から認証取得・HTTP・JSON待ちを
 * 全て含む。期限内にtokenが無ければHTTPを始めずnot_sent（後着tokenで送らない）。HTTPを始めた後の失敗・timeoutはunknown。
 */
async function request(path, method, ms, headers, payload) {
  const deadline = Date.now() + Math.max(0, ms);
  const got = await within(idToken(), deadline - Date.now());
  if (!Object.hasOwn(got, 'value')) return { kind: 'not_sent' };
  const remaining = deadline - Date.now();
  if (!(remaining > 0)) return { kind: 'not_sent' };
  const token = got.value;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  try {
    const response = await fetch(API + path, {
      method,
      headers: Object.assign({}, headers, { Authorization: 'Bearer ' + token }),
      body: payload,
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    let json = null;
    try {
      json = await response.json();
    } catch {
      json = null;
    }
    return { kind: 'response', status: response.status, json };
  } catch {
    return { kind: 'unknown' };
  } finally {
    clearTimeout(timer);
  }
}

/** 応答のstate（同じcommandIdの既知stateだけ）。 */
function stateOf(current, outcome) {
  const json = outcome.kind === 'response' ? outcome.json : null;
  if (json && json.commandId === current.commandId && typeof json.state === 'string' && Object.hasOwn(RANK, json.state)) return json.state;
  return null;
}

/** 受け取ったstateを反映する（確定した受領を中止・未確定で上書きしない、後着の弱い結果で戻さない）。 */
function apply(current, state) {
  if (current.state !== null && RANK[current.state] >= RANK[state]) return;
  current.state = state;
}

async function send() {
  if (!sendableNow() || test !== null) return;
  // 入力値を一度だけ捕捉し、trim・正規化せずそのまま送る（trimは空白だけの判定に使うだけ）。
  const text = el('sttd-text').value;
  if (typeof text !== 'string' || text.trim() === '' || LONE_SURROGATE.test(text) || new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    note = 'console.inputInvalid';
    return render();
  }
  // 最初のawaitの前にこの1件を確定する（二重クリックで2件目を作らない）。
  const created = Date.now();
  const current = { commandId: crypto.randomUUID(), state: null, postDone: false, rejected: null, cancel: 'none', checking: false, checkNote: '' };
  test = current;
  note = '';
  confirming = false;
  render();
  const payload = JSON.stringify({
    schemaVersion: 2,
    commandId: current.commandId,
    text,
    createdAt: new Date(created).toISOString(),
    expiresAt: new Date(created + LIFETIME_MS).toISOString(),
  });
  const outcome = await request('/v2/commands', 'POST', Math.min(POST_MS, created + LIFETIME_MS - Date.now()), { 'Content-Type': 'application/json', 'Idempotency-Key': current.commandId }, payload);
  if (test !== current) return;
  current.postDone = true;
  const state = stateOf(current, outcome);
  if (state !== null) apply(current, state);
  else if (outcome.kind === 'not_sent') current.rejected = 'console.notSent';
  else if (outcome.kind === 'response' && ERROR_STATUSES.includes(outcome.status)) current.rejected = 'console.error.' + outcome.status;
  render();
}

async function cancel() {
  const current = test;
  if (current === null || current.cancel !== 'none' || phaseOf(current) === 'settled') return;
  current.cancel = 'pending';
  render();
  const outcome = await request('/v2/commands/' + current.commandId + '/cancel', 'POST', CANCEL_MS, {}, undefined);
  if (test !== current) return;
  const state = stateOf(current, outcome);
  if (state !== null) {
    current.cancel = 'answered';
    apply(current, state);
  } else {
    current.cancel = 'unconfirmed';
  }
  render();
}

async function check() {
  const current = test;
  if (current === null || current.checking || !checkable(current)) return;
  current.checking = true;
  current.checkNote = '';
  render();
  const outcome = await request('/v2/commands/' + current.commandId, 'GET', CHECK_MS, {}, undefined);
  if (test !== current) return;
  current.checking = false;
  const state = stateOf(current, outcome);
  if (state !== null) apply(current, state);
  else if (outcome.kind === 'response' && outcome.status === 404) current.checkNote = 'console.checkNotFound';
  else current.checkNote = 'console.checkFailed';
  render();
}

function newTest() {
  const current = test;
  if (current === null || phaseOf(current) === 'sending' || current.cancel === 'pending' || current.checking) return;
  const uncertain = phaseOf(current) === 'unknown' || current.state === 'delivery_unknown' || current.state === 'in_flight' || (current.cancel === 'unconfirmed' && current.state !== 'cancelled');
  test = null;
  note = uncertain ? 'console.duplicateWarning' : '';
  render();
}

/** 解除の確認を開く（送信中・処理中・未ログイン・未接続では開かない。ここでは何も送らない）。 */
function askDisconnect() {
  if (busy() || !signedIn || connection === null || connection === 'unlinked') return;
  confirming = true;
  disconnectKey = '';
  render();
}

/** 確認の取消（何も送らず、状態も変えない）。 */
function keepConnection() {
  if (busy()) return;
  confirming = false;
  render();
}

/**
 * 本人の確認後に1回だけ解除する（排他。期限10秒に認証取得を含める。tokenはAuthorizationだけ、同originのcookieは送る）。
 * 失敗・期限切れ・応答不明では成功を装わず、どの結果でも接続状態を再確認し、本人が再確認するまで送信を封鎖する。
 */
function disconnect() {
  if (!confirming) return;
  return exclusive(async () => {
    confirming = false;
    disconnected = true;
    disconnectKey = 'common.disconnecting';
    render();
    const deadline = Date.now() + DISCONNECT_MS;
    const got = await within(idToken(), DISCONNECT_MS);
    let ok = false;
    if (Object.hasOwn(got, 'value') && deadline - Date.now() > 0) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), deadline - Date.now());
      try {
        const response = await fetch('/v1/web/disconnect', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + got.value },
          credentials: 'same-origin',
          cache: 'no-store',
          redirect: 'error',
          signal: controller.signal,
        });
        let json = null;
        try {
          json = await response.json();
        } catch {
          json = null;
        }
        ok = response.ok && json !== null && typeof json.state === 'string' && CONNECTION_STATES.includes(json.state);
      } catch {
        ok = false;
      } finally {
        clearTimeout(timer);
      }
    }
    disconnectKey = ok ? 'common.disconnectDone' : 'common.disconnectFailed';
    await refreshConnection();
  });
}

async function start() {
  el('sttd-login').onclick = () => login(false);
  el('sttd-switch').onclick = () => login(true);
  el('sttd-refresh').onclick = () => manualRefresh();
  el('sttd-disconnect').onclick = () => askDisconnect();
  el('sttd-disconnect-yes').onclick = () => disconnect();
  el('sttd-disconnect-no').onclick = () => keepConnection();
  el('sttd-send').onclick = () => send();
  el('sttd-cancel').onclick = () => cancel();
  el('sttd-check').onclick = () => check();
  el('sttd-new').onclick = () => newTest();
  for (const code of ['en', 'ja']) {
    el('sttd-lang-' + code).onclick = (event) => {
      if (event && typeof event.preventDefault === 'function') event.preventDefault();
      chooseLanguage(code);
    };
  }
  render();
  await auth.authStateReady();
  if (!auth.currentUser) return signedOutView();
  await exclusive(refreshConnection);
}

await start().catch(() => signedOutView('common.loginUnknown'));
`;

/** 固定3 pathのasset（それ以外はundefined）。 */
export interface ConsoleAsset {
  readonly type: string;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export function consoleAsset(path: string, web: FirebaseWebConfig, apiOrigin: string, language: Language = DEFAULT_LANGUAGE): ConsoleAsset | undefined {
  switch (path) {
    case CONSOLE_PATH:
      return { type: 'text/html; charset=utf-8', body: renderConsolePage(web, apiOrigin, language), headers: consoleSecurityHeaders(web, apiOrigin) };
    case CONSOLE_SCRIPT_PATH:
      return { type: 'text/javascript; charset=utf-8', body: CONSOLE_SCRIPT, headers: {} };
    case CONSOLE_STYLE_PATH:
      return { type: 'text/css; charset=utf-8', body: CONSOLE_STYLE, headers: {} };
    default:
      return undefined;
  }
}
