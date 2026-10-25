// SendTextToDots接続Webの最小画面。Appleログイン（Firebase Web SDK、Apple providerのみ・追加scopeなし）・接続許可・状態・受信開始の案内・
// 接続解除。受信開始はChatGPT側の購読（events/subscribe）を待つ案内で、押しただけで購読済みにしない。
// 値はdata属性へescapeして渡し、inline scriptを置かない。Web SDKは公式CDNの固定版だけを読み込む。

export const FIREBASE_WEB_SDK_VERSION = '13.0.0';
const SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
export const CONNECT_SCRIPT_PATH = '/connect/app.js';

/** 公開してよいFirebase Webの設定値だけ（秘密ではない）。 */
export interface FirebaseWebConfig {
  readonly apiKey: string;
  readonly authDomain: string;
  readonly projectId: string;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

/**
 * 固定SDK 13.0.0のpopup経路が読む公式script。popup resolverがGApi loaderを`<script src="https://apis.google.com/js/api.js">`で
 * 入れ、続けて`gapi.iframes`を同じoriginから読む（firebase-js-sdk@13.0.0 packages/auth/src/platform_browser/index.ts・iframe/gapi.ts）。
 * auth iframeは`https://<authDomain>/__/auth/iframe`（frame-src）。reCAPTCHA（電話番号認証だけ）・任意のhttpsは許さない。
 */
export const FIREBASE_POPUP_SCRIPT_ORIGIN = 'https://apis.google.com';

export function pageSecurityHeaders(web: FirebaseWebConfig): Record<string, string> {
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'self' ${SDK_BASE} ${FIREBASE_POPUP_SCRIPT_ORIGIN}`,
      "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
      `frame-src https://${web.authDomain}`,
      "style-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
    'X-Frame-Options': 'DENY',
    // 同意のnative form POSTがOrigin付きで届くよう、同origin内だけRefererを許す。
    'Referrer-Policy': 'same-origin',
  };
}

function shell(web: FirebaseWebConfig, view: string, body: string, attributes: Record<string, string>): string {
  const data = Object.entries({ 'sttd-view': view, 'sttd-firebase': JSON.stringify(web), ...attributes })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  return `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>SendTextToDots 接続</title>
<script type="module" src="${CONNECT_SCRIPT_PATH}"></script></head>
<body${data}>
<h1>SendTextToDots 接続</h1>
${body}
</body></html>`;
}

/** OAuth interactionの1画面目: Appleでログイン。 */
export function renderInteractionLogin(web: FirebaseWebConfig, uid: string, clientLabel: string, csrf: string): string {
  return shell(
    web,
    'interaction-login',
    `<p>接続先: ${escapeHtml(clientLabel)}</p>
<p>送信元アプリと同じAppleアカウントでログインしてください。</p>
<button type="button" id="sttd-continue" hidden>ログイン中のAppleアカウントで続ける</button>
<button type="button" id="sttd-apple-login" hidden>Appleでログイン</button>
<button type="button" id="sttd-switch-account" hidden>別のAppleアカウントでログイン</button>
<p id="sttd-message" role="status"></p>`,
    { 'sttd-interaction': uid, 'sttd-csrf': csrf },
  );
}

/** OAuth interactionの2画面目: 認証済み本人への明示の許可（1画面）。 */
export function renderInteractionConsent(web: FirebaseWebConfig, uid: string, clientLabel: string, csrf: string): string {
  const action = `/interaction/${escapeHtml(uid)}`;
  return shell(
    web,
    'interaction-consent',
    `<p>${escapeHtml(clientLabel)} とSendTextToDotsの接続を許可しますか。許可すると、あなたが購読したDotsだけへ送信できます。</p>
<form method="post" action="${action}/consent">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit">このDotsとの接続を許可</button>
</form>
<form method="post" action="${action}/deny">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit">許可しない</button>
</form>`,
    { 'sttd-csrf': csrf },
  );
}

/** 接続設定ページ（OAuth外）。状態・受信開始の案内・接続解除。状態の取得はログイン後にscriptが行う。 */
export function renderConnectPage(web: FirebaseWebConfig): string {
  return shell(
    web,
    'connect',
    `<button type="button" id="sttd-apple-login" hidden>Appleでログイン</button>
<button type="button" id="sttd-switch-account" hidden>別のAppleアカウントでログイン</button>
<p id="sttd-message" role="status"></p>
<section id="sttd-state" hidden>
<p id="sttd-state-text" role="status"></p>
<p id="sttd-start-guide" hidden>受信を始めるには、ChatGPTのSendTextToDots接続で「このDotsで受信を開始」と依頼してください。ChatGPTが購読を登録し、確認が済むと「受信中」になります。</p>
<button type="button" id="sttd-disconnect" hidden>接続を解除</button>
</section>`,
    {},
  );
}

/**
 * 画面のscript。SDKの復元を待ち、復元済みsessionがあればそのtokenを使ってpopupを開かない（interactionでは本人の
 * 「続ける」操作だけで同じinteractionへ進む）。popupは未ログインか、本人の明示のaccount切替（signOut後）の時だけ。
 * 復元済みsessionのtoken更新に失敗した時は、自動でpopupを開かず、ログインの操作へ戻す。
 * Apple providerへscopeを足さない（氏名・メールを要求しない）。ID tokenはbody/Authorizationだけで送り、URLへ入れない。
 */
export const CONNECT_SCRIPT = `import { initializeApp } from '${SDK_BASE}firebase-app.js';
import { getAuth, OAuthProvider, signInWithPopup, signOut } from '${SDK_BASE}firebase-auth.js';

const body = document.body;
const view = body.dataset.sttdView;
const auth = getAuth(initializeApp(JSON.parse(body.dataset.sttdFirebase)));
const STATE_TEXT = {
  unlinked: 'ログイン済み・Dotsとの接続はまだありません',
  linked: '接続許可済み・受信開始待ち',
  subscribed: '受信中',
  expired: '受信の期限が切れました。ChatGPTで受信を再開してください',
  change_pending: '送信先の変更確認待ち',
};
const RETRY_LOGIN = 'ログイン状態を更新できませんでした。もう一度ログインしてください。';
const el = (id) => document.getElementById(id);

function say(text) {
  const node = el('sttd-message') ?? el('sttd-state-text');
  if (node) node.textContent = text;
}

function show(id, visible) {
  const node = el(id);
  if (node) node.hidden = !visible;
}

function signedOut(message) {
  if (message) say(message);
  show('sttd-continue', false);
  show('sttd-switch-account', false);
  show('sttd-apple-login', true);
}

function run(task, failure) {
  return task().catch(() => signedOut(failure));
}

async function popupIdToken() {
  const result = await signInWithPopup(auth, new OAuthProvider('apple.com'));
  return result.user.getIdToken();
}

async function switchedIdToken() {
  await signOut(auth);
  return popupIdToken();
}

function restoredIdToken() {
  return auth.currentUser.getIdToken();
}

async function interactionLogin(idToken) {
  const response = await fetch('/interaction/' + encodeURIComponent(body.dataset.sttdInteraction) + '/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csrf: body.dataset.sttdCsrf, idToken }),
  });
  if (response.status === 204) location.reload();
  else say('ログインを確認できませんでした。最初からやり直してください。');
}

async function showState(idToken) {
  const response = await fetch('/v1/web/connection', { headers: { Authorization: 'Bearer ' + idToken } });
  if (!response.ok) return say('状態を確認できませんでした。');
  const { state } = await response.json();
  show('sttd-state', true);
  show('sttd-apple-login', false);
  show('sttd-switch-account', true);
  say(STATE_TEXT[state] ?? '状態を確認できませんでした。');
  show('sttd-start-guide', state === 'linked' || state === 'expired');
  show('sttd-disconnect', state !== 'unlinked');
}

const proceed = view === 'interaction-login' ? interactionLogin : showState;

async function start() {
  if (view !== 'interaction-login' && view !== 'connect') return;
  el('sttd-apple-login').onclick = () => run(async () => proceed(await popupIdToken()), 'ログインできませんでした。');
  el('sttd-switch-account').onclick = () => run(async () => proceed(await switchedIdToken()), 'ログインできませんでした。');
  const disconnect = el('sttd-disconnect');
  if (disconnect) {
    disconnect.onclick = () =>
      run(async () => {
        const response = await fetch('/v1/web/disconnect', { method: 'POST', headers: { Authorization: 'Bearer ' + (await restoredIdToken()) } });
        if (!response.ok) return say('接続を解除できませんでした。');
        await showState(await restoredIdToken());
      }, RETRY_LOGIN);
  }
  await auth.authStateReady();
  if (!auth.currentUser) return signedOut();
  show('sttd-switch-account', true);
  if (view === 'connect') return run(async () => showState(await restoredIdToken()), RETRY_LOGIN);
  show('sttd-continue', true);
  el('sttd-continue').onclick = () => run(async () => interactionLogin(await restoredIdToken()), RETRY_LOGIN);
}

await start().catch(() => signedOut('ログイン状態を確認できませんでした。'));
`;
