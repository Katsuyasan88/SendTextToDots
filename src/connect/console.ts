// 本人用の簡易ブラウザ操作画面（/console）。Appleログイン（既存Firebase Web SDK 13.0.0・Apple providerのみ・追加scopeなし）・
// 接続/購読状態（同originの既存 /v1/web/connection）・利用者が入力した本文の送信・中止・本人のクリックによる同じIDの結果確認だけ。
//   - 本文欄は空で始まり、例文・定型文・方向の選択・固定taskは無い。入力値をtrim・正規化せずそのままv2の5項目で送る。
//   - 指示・中止・結果確認は、固定Functions originへbrowserから直接送る（MCPは本文を中継しない）。tokenはAuthorizationだけ、credentials:omit。
//   - 本文はRAM/DOMだけ（localStorage・sessionStorage・IndexedDB・URL・ログへ保存0。Firebase SDK自身の認証session保存とは別）。
//   - 空・空白だけ・対にならないsurrogate・4096 UTF-8 byte超は通信前に拒否する（maxlengthは補助で、byte検査の代わりにしない）。
//   - 送信POSTは最大25秒（元期限内）、二重クリックでPOSTを増やさない。送信中は本文・account切替を封鎖し中止だけ。
//     終端後は「新しいテスト」を明示に押すまで再送しない。自動POST再送・定期poll 0。中止は同commandIdへ最大5秒。
//   - 表示はHTTP statusではなくstate。deliveredは送信先の受領で、同じDotの反応は自動確認しない。未確定は成功扱いしない。
//   - HTML・JS・CSSは固定文字列で、inline script/style・実filesystem読取り・新framework・新依存は無い。動的な値はdata属性へescape、表示はtextContent。
//   - apiOriginとweb configは信頼する呼出元（connect/kms-server.ts）だけが渡す。利用者・argv・envから任意originを選ばせない。
// 各要求の元期限（POST 25秒・中止5秒・同ID確認10秒）に認証取得を含め、期限後のtokenで通信を始めない。
//   backendのdelivery_unknownでも本人クリックの同ID確認を残す。認証切替・接続再確認は排他し、確認済みの現在状態まで送信を封鎖する。
//   httpsのAPI originはDNS hostだけ（IP literal拒否）。

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

/** /consoleのHTML（1画面）。値はdata属性へescapeして渡す。 */
export function renderConsolePage(web: FirebaseWebConfig, apiOrigin: string): string {
  checkWeb(web);
  const api = consoleApiOrigin(apiOrigin);
  const data = Object.entries({ 'sttd-firebase': JSON.stringify({ apiKey: web.apiKey, authDomain: web.authDomain, projectId: web.projectId }), 'sttd-api-origin': api })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  return `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SendTextToDots 操作画面</title>
<link rel="stylesheet" href="${CONSOLE_STYLE_PATH}">
<script type="module" src="${CONSOLE_SCRIPT_PATH}"></script></head>
<body${data}>
<main>
<h1>SendTextToDots 操作画面（開発用）</h1>
<section id="sttd-account" aria-labelledby="sttd-account-title">
<h2 id="sttd-account-title">アカウント</h2>
<p id="sttd-account-text" role="status">ログイン状態を確認しています…</p>
<button type="button" id="sttd-login" hidden>Appleでログイン</button>
<button type="button" id="sttd-switch" hidden>別のAppleアカウントでログイン</button>
</section>
<section id="sttd-connection" aria-labelledby="sttd-connection-title">
<h2 id="sttd-connection-title">接続と受信の状態</h2>
<p id="sttd-state-text" role="status">ログインすると表示します。</p>
<p id="sttd-start-guide" hidden>受信を始めるには、ChatGPTのSendTextToDots接続で「このDotsで受信を開始」と依頼してください。確認が済むと「受信中」になります。</p>
<button type="button" id="sttd-refresh" hidden>状態を再確認</button>
<p><a href="/connect">接続の解除・詳細（接続画面）</a></p>
</section>
<section id="sttd-test" aria-labelledby="sttd-test-title">
<h2 id="sttd-test-title">テスト送信</h2>
<label for="sttd-text">送る文（このページの中だけで使い、保存しません）</label>
<textarea id="sttd-text" rows="4" maxlength="4096" placeholder="Dotsへ送る文を入力してください（4096バイトまで）" disabled></textarea>
<div class="sttd-actions">
<button type="button" id="sttd-send" disabled>1件だけ送信</button>
<button type="button" id="sttd-cancel" hidden>中止</button>
<button type="button" id="sttd-check" hidden>同じIDの結果を確認</button>
<button type="button" id="sttd-new" hidden>新しいテスト</button>
</div>
<p id="sttd-result" role="status"></p>
<p class="sttd-note">「受領」は送信先がSendTextToDotsからの1件を受け取ったという意味です。Dotsの返答はChatGPTの画面で確認してください。</p>
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
#sttd-cancel { background: #fff; color: #b3261e; border-color: #b3261e; }
.sttd-actions { display: flex; flex-wrap: wrap; }
#sttd-result { font-weight: 600; min-height: 1.5em; overflow-wrap: anywhere; }
.sttd-note { font-size: 0.85rem; color: #4a5059; }
[hidden] { display: none !important; }
`;

/**
 * 画面のscript（固定asset）。状態の表示・単回送信・中止・本人のクリックでの同ID確認だけ。自動popup・自動再送・定期pollは無い。
 */
export const CONSOLE_SCRIPT = `import { initializeApp } from '${CONSOLE_SDK_BASE}firebase-app.js';
import { getAuth, OAuthProvider, signInWithPopup, signOut } from '${CONSOLE_SDK_BASE}firebase-auth.js';

const body = document.body;
const API = body.dataset.sttdApiOrigin;
const auth = getAuth(initializeApp(JSON.parse(body.dataset.sttdFirebase)));
const POST_MS = 25000;
const CANCEL_MS = 5000;
const CHECK_MS = 10000;
const LIFETIME_MS = 60000;
const MAX_TEXT_BYTES = 4096;
const LONE_SURROGATE = /\\p{Cs}/u;
const CONNECTION = {
  unlinked: 'ログイン済み・Dotsとの接続はまだありません',
  linked: '接続許可済み・受信開始待ち',
  subscribed: '受信中（テスト送信できます）',
  expired: '受信の期限が切れました。ChatGPTで受信を再開してください',
  change_pending: '送信先の変更確認待ち',
};
const STATE_TEXT = {
  in_flight: '処理中です（結果はまだ確定していません）。',
  delivered: '送信先が受領しました。Dotsの返答を確認してください（Dotsの反応は自動では確認していません）。',
  failed: '送信できませんでした。',
  cancelled: '中止しました（送信されていません）。',
  expired: '期限切れのため送信されませんでした。',
  delivery_unknown: '届いたか分かりません。重複に注意してください。',
};
const ERROR_TEXT = {
  400: '送信内容を受け付けられませんでした（送信されていません）。',
  401: 'ログインを確認できませんでした。もう一度ログインしてください（送信されていません）。',
  403: '接続が無効です。ChatGPTで接続と受信開始をやり直してください（送信されていません）。',
  409: '受信中のDotsが無いか、送信先の確認待ちです（送信されていません）。',
  422: '送信時刻を受け付けられませんでした。端末の時計を確認してください（送信されていません）。',
  429: '混雑しています。しばらく待ってから新しいテストを始めてください（送信されていません）。',
};
const UNKNOWN_TEXT = '結果を確認できません。届いている可能性があります。「同じIDの結果を確認」で確認できます。';
const CANCEL_UNCONFIRMED = '中止を確認できません。届いている可能性があります。';
const DUPLICATE_WARNING = '前のテストは届いている可能性があります。新しいテストは別の1件として送られ、重複して届くことがあります。';
const TERMINAL = ['delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown'];
const RANK = { in_flight: 1, delivery_unknown: 2, failed: 3, expired: 3, cancelled: 3, delivered: 4 };

const el = (id) => document.getElementById(id);
let signedIn = false;
let connection = null;
let test = null;
let note = '';
// 認証切替・接続の再確認の間は排他し、確認済みの現在状態が戻るまで送信を封鎖する。
let accountBusy = false;
let connectionSeq = 0;

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
  return signedIn && connection === 'subscribed' && !accountBusy;
}

function render() {
  const phase = test === null ? null : phaseOf(test);
  const sendable = sendableNow();
  el('sttd-login').hidden = signedIn;
  el('sttd-switch').hidden = !signedIn;
  el('sttd-switch').disabled = test !== null || accountBusy;
  el('sttd-login').disabled = test !== null || accountBusy;
  el('sttd-refresh').hidden = !signedIn;
  el('sttd-refresh').disabled = test !== null || accountBusy;
  el('sttd-text').disabled = !sendable || test !== null;
  el('sttd-send').disabled = !sendable || test !== null;
  el('sttd-cancel').hidden = test === null || (phase !== 'sending' && phase !== 'unknown') || test.cancel === 'answered' || test.cancel === 'unconfirmed';
  el('sttd-cancel').disabled = test !== null && test.cancel === 'pending';
  el('sttd-check').hidden = test === null || !checkable(test);
  el('sttd-check').disabled = test !== null && test.checking;
  el('sttd-new').hidden = test === null || phase === 'sending' || test.cancel === 'pending' || test.checking;
  const lines = [];
  if (test !== null) {
    if (test.state !== null) lines.push(STATE_TEXT[test.state]);
    else if (phase === 'sending') lines.push('送信中です。中止できます。');
    else if (test.rejected !== null) lines.push(test.rejected);
    else lines.push(UNKNOWN_TEXT);
    if (test.cancel === 'pending') lines.push('中止を確認しています…');
    if (test.cancel === 'unconfirmed' && test.state !== 'cancelled') lines.push(CANCEL_UNCONFIRMED);
    if (test.checkNote) lines.push(test.checkNote);
  } else if (note) {
    lines.push(note);
  }
  el('sttd-result').textContent = lines.join(' ');
}

function showConnection(state, text) {
  connection = state;
  el('sttd-state-text').textContent = text;
  el('sttd-start-guide').hidden = !(state === 'linked' || state === 'expired');
  render();
}

function signedOutView(message) {
  signedIn = false;
  el('sttd-account-text').textContent = message || 'ログインしていません。';
  showConnection(null, 'ログインすると表示します。');
}

async function idToken() {
  if (!auth.currentUser) throw new Error('signed_out');
  return auth.currentUser.getIdToken();
}

/** 接続状態の確認（開始時に以前の状態を捨てて送信を封鎖。後から始めた確認がある時の古い結果は採用しない）。 */
async function refreshConnection() {
  const mine = ++connectionSeq;
  connection = null;
  el('sttd-state-text').textContent = '状態を確認しています…';
  render();
  let token;
  try {
    token = await idToken();
  } catch {
    if (mine === connectionSeq) signedOutView('ログイン状態を更新できませんでした。もう一度ログインしてください。');
    return;
  }
  if (mine !== connectionSeq) return;
  signedIn = true;
  el('sttd-account-text').textContent = 'Appleアカウントでログイン中です。';
  render();
  try {
    const response = await fetch('/v1/web/connection', { headers: { Authorization: 'Bearer ' + token }, credentials: 'same-origin', cache: 'no-store' });
    const json = response.ok ? await response.json() : null;
    if (mine !== connectionSeq) return;
    if (json && typeof json.state === 'string' && Object.hasOwn(CONNECTION, json.state)) return showConnection(json.state, CONNECTION[json.state]);
  } catch {
    // 下の固定表示へ（状態不明を未接続・未購読と決め付けない）。
  }
  if (mine !== connectionSeq) return;
  showConnection(null, '接続状態を確認できませんでした（未接続・未購読とは限りません）。送信はできません。');
}

/** 認証切替・接続の再確認を1つずつ行う（実行中は送信・切替・再確認を封鎖。テスト中は始めない）。 */
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
    try {
      if (switching) await signOut(auth);
      await signInWithPopup(auth, new OAuthProvider('apple.com'));
    } catch {
      if (!auth.currentUser) return signedOutView('ログインできませんでした。');
    }
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
    note = '送る文は空白以外の文字を含め、4096バイト以内で入力してください（対にならない文字は送れません。送信されていません）。';
    return render();
  }
  // 最初のawaitの前にこの1件を確定する（二重クリックで2件目を作らない）。
  const created = Date.now();
  const current = { commandId: crypto.randomUUID(), state: null, postDone: false, rejected: null, cancel: 'none', checking: false, checkNote: '' };
  test = current;
  note = '';
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
  else if (outcome.kind === 'not_sent') current.rejected = 'ログイン状態を確認できなかったため送信していません。';
  else if (outcome.kind === 'response' && Object.hasOwn(ERROR_TEXT, outcome.status)) current.rejected = ERROR_TEXT[outcome.status];
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
  else if (outcome.kind === 'response' && outcome.status === 404) current.checkNote = '受付の記録が見つかりませんでした（送信されていない可能性があります）。';
  else current.checkNote = '結果を確認できませんでした。';
  render();
}

function newTest() {
  const current = test;
  if (current === null || phaseOf(current) === 'sending' || current.cancel === 'pending' || current.checking) return;
  const uncertain = phaseOf(current) === 'unknown' || current.state === 'delivery_unknown' || current.state === 'in_flight' || (current.cancel === 'unconfirmed' && current.state !== 'cancelled');
  test = null;
  note = uncertain ? DUPLICATE_WARNING : '';
  render();
}

async function start() {
  el('sttd-login').onclick = () => login(false);
  el('sttd-switch').onclick = () => login(true);
  el('sttd-refresh').onclick = () => exclusive(refreshConnection);
  el('sttd-send').onclick = () => send();
  el('sttd-cancel').onclick = () => cancel();
  el('sttd-check').onclick = () => check();
  el('sttd-new').onclick = () => newTest();
  await auth.authStateReady();
  if (!auth.currentUser) return signedOutView();
  await exclusive(refreshConnection);
}

await start().catch(() => signedOutView('ログイン状態を確認できませんでした。'));
`;

/** 固定3 pathのasset（それ以外はundefined）。 */
export interface ConsoleAsset {
  readonly type: string;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export function consoleAsset(path: string, web: FirebaseWebConfig, apiOrigin: string): ConsoleAsset | undefined {
  switch (path) {
    case CONSOLE_PATH:
      return { type: 'text/html; charset=utf-8', body: renderConsolePage(web, apiOrigin), headers: consoleSecurityHeaders(web, apiOrigin) };
    case CONSOLE_SCRIPT_PATH:
      return { type: 'text/javascript; charset=utf-8', body: CONSOLE_SCRIPT, headers: {} };
    case CONSOLE_STYLE_PATH:
      return { type: 'text/css; charset=utf-8', body: CONSOLE_STYLE, headers: {} };
    default:
      return undefined;
  }
}
