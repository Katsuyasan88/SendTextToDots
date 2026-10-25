// SendTextToDots接続Webの最小画面。Appleログイン（Firebase Web SDK、Apple providerのみ・追加scopeなし）・接続許可・状態・受信開始の案内・
// 接続解除。受信開始はChatGPT側の購読（events/subscribe）を待つ案内で、押しただけで購読済みにしない。
// 値はdata属性へescapeして渡し、inline scriptを置かない。Web SDKは公式CDNの固定版だけを読み込む。
// 文言はen/jaの固定辞書（connect/i18n.ts）から入れ、各画面にEnglish/日本語の明示選択（同じpathへの`?lang=`のGETリンク）を置く。
// 言語のリンクはform送信・ログイン・同意・拒否・解除を起こさない。/connectは互換のため残し、通常入口の/consoleへ案内する。

import { DEFAULT_LANGUAGE, isLanguage, languageHref, messagesJson, text, type Language, type MessageKey } from './i18n.js';

export const FIREBASE_WEB_SDK_VERSION = '13.0.0';
const SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
export const CONNECT_SCRIPT_PATH = '/connect/app.js';
export const CONNECT_PATH = '/connect';

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

function languageOf(value: unknown): Language {
  return isLanguage(value) ? value : DEFAULT_LANGUAGE;
}

/** 画面上部のEnglish/日本語の明示選択（同じpathへのGETリンク。選択中はaria-current）。 */
function languageNav(path: string, lang: Language): string {
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const current = (candidate: Language) => (candidate === lang ? ' aria-current="true"' : '');
  return `<nav aria-labelledby="sttd-language-label"><span id="sttd-language-label">${t('common.language')}</span>
<a id="sttd-lang-en" href="${languageHref(path, 'en')}" hreflang="en" lang="en"${current('en')}>${t('common.languageEnglish')}</a>
<a id="sttd-lang-ja" href="${languageHref(path, 'ja')}" hreflang="ja" lang="ja"${current('ja')}>${t('common.languageJapanese')}</a></nav>`;
}

function shell(web: FirebaseWebConfig, view: string, lang: Language, path: string, titleKey: MessageKey, body: string, attributes: Record<string, string>): string {
  const data = Object.entries({ 'sttd-view': view, 'sttd-firebase': JSON.stringify(web), 'sttd-language': lang, ...attributes })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  const title = escapeHtml(text(lang, titleKey));
  return `<!DOCTYPE html>
<html lang="${lang}"><head><meta charset="utf-8"><title>${title}</title>
<script type="module" src="${CONNECT_SCRIPT_PATH}"></script></head>
<body${data}>
${languageNav(path, lang)}
<h1>${title}</h1>
${body}
</body></html>`;
}

/** OAuth interactionの1画面目: Appleでログイン。 */
export function renderInteractionLogin(web: FirebaseWebConfig, uid: string, clientLabel: string, csrf: string, language: Language = DEFAULT_LANGUAGE): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  return shell(
    web,
    'interaction-login',
    lang,
    `/interaction/${escapeHtml(uid)}`,
    'connect.title',
    `<p>${t('interaction.client')}${escapeHtml(clientLabel)}</p>
<p>${t('interaction.loginGuide')}</p>
<button type="button" id="sttd-continue" hidden>${t('common.continueSignedIn')}</button>
<button type="button" id="sttd-apple-login" hidden>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch-account" hidden>${t('common.switchAccount')}</button>
<p id="sttd-message" role="status"></p>`,
    { 'sttd-interaction': uid, 'sttd-csrf': csrf },
  );
}

/** OAuth interactionの2画面目: 認証済み本人への明示の許可（1画面）。言語リンクはformの外にあり、同意・拒否を送らない。 */
export function renderInteractionConsent(web: FirebaseWebConfig, uid: string, clientLabel: string, csrf: string, language: Language = DEFAULT_LANGUAGE): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const action = `/interaction/${escapeHtml(uid)}`;
  return shell(
    web,
    'interaction-consent',
    lang,
    action,
    'connect.title',
    `<p>${escapeHtml(clientLabel)}${t('interaction.consentQuestion')}</p>
<form method="post" action="${action}/consent">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit">${t('interaction.allow')}</button>
</form>
<form method="post" action="${action}/deny">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit">${t('interaction.deny')}</button>
</form>`,
    { 'sttd-csrf': csrf },
  );
}

/**
 * 接続設定ページ（OAuth外、互換のため残す）。状態・受信開始の案内・接続解除。状態の取得はログイン後にscriptが行う。
 * consoleを配信する構成（consoleAvailable）では通常入口の/consoleへ案内し、配信しない構成では既存機能だけを案内する。
 */
export function renderConnectPage(web: FirebaseWebConfig, language: Language = DEFAULT_LANGUAGE, consoleAvailable = false): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const guide = consoleAvailable
    ? `<p>${t('connect.consoleGuide')} <a id="sttd-console-link" href="/console">${t('connect.consoleLink')}</a></p>`
    : `<p>${t('connect.consoleUnavailable')}</p>`;
  return shell(
    web,
    'connect',
    lang,
    CONNECT_PATH,
    'connect.title',
    `${guide}
<button type="button" id="sttd-apple-login" hidden>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch-account" hidden>${t('common.switchAccount')}</button>
<p id="sttd-message" role="status"></p>
<section id="sttd-state" hidden>
<p id="sttd-state-text" role="status"></p>
<p id="sttd-start-guide" hidden>${t('common.startGuide')}</p>
<button type="button" id="sttd-disconnect" hidden>${t('common.disconnect')}</button>
</section>`,
    {},
  );
}

/**
 * 画面のscript。SDKの復元を待ち、復元済みsessionがあればそのtokenを使ってpopupを開かない（interactionでは本人の
 * 「続ける」操作だけで同じinteractionへ進む）。popupは未ログインか、本人の明示のaccount切替（signOut後）の時だけ。
 * 復元済みsessionのtoken更新に失敗した時は、自動でpopupを開かず、ログインの操作へ戻す。
 * Apple providerへscopeを足さない（氏名・メールを要求しない）。ID tokenはbody/Authorizationだけで送り、URLへ入れない。
 * 文言はbodyのdata-sttd-language（サーバーが選んだ言語）で、埋め込んだ固定辞書から引く。
 */
export const CONNECT_SCRIPT = `import { initializeApp } from '${SDK_BASE}firebase-app.js';
import { getAuth, OAuthProvider, signInWithPopup, signOut } from '${SDK_BASE}firebase-auth.js';

const body = document.body;
const view = body.dataset.sttdView;
const auth = getAuth(initializeApp(JSON.parse(body.dataset.sttdFirebase)));
const TEXT = ${messagesJson()};
const lang = Object.hasOwn(TEXT, body.dataset.sttdLanguage) ? body.dataset.sttdLanguage : 'en';
const T = (key) => (Object.hasOwn(TEXT[lang], key) ? TEXT[lang][key] : '');
const STATES = ['unlinked', 'linked', 'subscribed', 'expired', 'change_pending'];
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
  else say(T('connect.loginConfirmFailed'));
}

async function showState(idToken) {
  const response = await fetch('/v1/web/connection', { headers: { Authorization: 'Bearer ' + idToken } });
  if (!response.ok) return say(T('common.stateUnavailable'));
  const { state } = await response.json();
  show('sttd-state', true);
  show('sttd-apple-login', false);
  show('sttd-switch-account', true);
  say(STATES.includes(state) ? T('common.state.' + state) : T('common.stateUnavailable'));
  show('sttd-start-guide', state === 'linked' || state === 'expired');
  show('sttd-disconnect', state !== 'unlinked');
}

const proceed = view === 'interaction-login' ? interactionLogin : showState;

async function start() {
  if (view !== 'interaction-login' && view !== 'connect') return;
  el('sttd-apple-login').onclick = () => run(async () => proceed(await popupIdToken()), T('common.loginFailed'));
  el('sttd-switch-account').onclick = () => run(async () => proceed(await switchedIdToken()), T('common.loginFailed'));
  const disconnect = el('sttd-disconnect');
  if (disconnect) {
    disconnect.onclick = () =>
      run(async () => {
        const response = await fetch('/v1/web/disconnect', { method: 'POST', headers: { Authorization: 'Bearer ' + (await restoredIdToken()) } });
        if (!response.ok) return say(T('common.disconnectFailed'));
        await showState(await restoredIdToken());
      }, T('common.loginRefresh'));
  }
  await auth.authStateReady();
  if (!auth.currentUser) return signedOut();
  show('sttd-switch-account', true);
  if (view === 'connect') return run(async () => showState(await restoredIdToken()), T('common.loginRefresh'));
  show('sttd-continue', true);
  el('sttd-continue').onclick = () => run(async () => interactionLogin(await restoredIdToken()), T('common.loginRefresh'));
}

await start().catch(() => signedOut(T('common.loginUnknown')));
`;
