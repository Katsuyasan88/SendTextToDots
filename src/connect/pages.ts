// OAuth interaction（login/consent）の最小画面と、その固定script。Appleログイン（Firebase Web SDK、Apple providerのみ・追加scopeなし）・
// ログイン中accountの継続・明示のaccount切替・本人の明示同意/拒否（native form POST、CSRF）。通常入口の送信画面は connect/console.ts。
// 値はdata属性へescapeして渡し、inline scriptを置かない。Web SDKは公式CDNの固定版だけを読み込む。
// 文言はen/jaの固定辞書（connect/i18n.ts）から入れ、各画面にEnglish/日本語の明示選択（同じpathへの`?lang=`のGETリンク）を置く。
// 言語のリンクはform送信・ログイン・同意・拒否を起こさない。旧接続画面（/connect）は無く、互換route・redirectも置かない。

import { DEFAULT_LANGUAGE, isLanguage, languageHref, messagesJson, text, type Language, type MessageKey } from './i18n.js';
import { GOOGLE_SIGN_IN_LOGO, PROVIDER_BUTTON_STYLE } from './provider-buttons.js';

export const FIREBASE_WEB_SDK_VERSION = '13.0.0';
const SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
/** OAuth interaction画面が読む固定script（同origin）。 */
export const INTERACTION_SCRIPT_PATH = '/interaction/app.js';
export const DISCONNECT_PAGE_PATH = '/disconnect';
export const DISCONNECT_SCRIPT_PATH = '/disconnect/app.js';
export const REVIEWER_DISCONNECT_PAGE_PATH = '/disconnect/review';
export const REVIEWER_DISCONNECT_API_PATH = '/v1/web/disconnect/reviewer';

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

/**
 * OAuth interaction画面の共通見た目。Playgroundと同じCSS変数の配色で、OSのライト/ダーク（prefers-color-scheme）に従う
 * （ダークは濃紺の背景・淡い青の操作）。固定文字列の単一stylesheetだけで、値を差し込まない。
 * CSPはこの文字列のSHA-256だけをstyle-srcに許可する。ブランド画像は同梱し、表示時に外部へ取得しに行かない。
 * 既存試験の文字列検査に誤一致しないよう、attribute selectorの値は引用符で囲まない。
 */
export const INTERACTION_STYLE = `:root{color-scheme:light dark;--ink:#18202b;--muted:#556170;--line:#d9dee6;--bg:#f4f6f9;--card:#fff;--field:#fff;--accent:#1f5fa8;--accent-hover:#174c88;--accent-ink:#fff;--soft:#e8f0fa;--warn:#8a4600;--warn-soft:#fbf0e2;--disabled:#e3e7ed;--disabled-ink:#6b7685;--focus:#f0a400}
@media (prefers-color-scheme:dark){:root{--ink:#e6ebf2;--muted:#9aa7b5;--line:#2e3846;--bg:#10151c;--card:#18202a;--field:#10151c;--accent:#7fb2ec;--accent-hover:#9cc6ef;--accent-ink:#0d1a2a;--soft:#1d2b3c;--warn:#f0b46a;--warn-soft:#33260f;--disabled:#232c38;--disabled-ink:#7d8896}}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;line-height:1.7;overflow-wrap:anywhere}
main{width:100%;max-width:36rem;margin:0 auto;padding:clamp(1rem,4vw,2.5rem) clamp(0.75rem,4vw,1.5rem)}
.sttd-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:clamp(1rem,5vw,1.75rem)}
nav{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:0.25rem 0.5rem;margin-bottom:1rem;font-size:0.9rem;color:var(--muted)}
nav a{color:var(--accent);padding:0.4rem 0.5rem;border-radius:6px}
nav a[aria-current=true]{color:var(--ink);font-weight:700;text-decoration:none}
h1{display:flex;align-items:center;gap:0.6rem;margin:0 0 1rem;font-size:clamp(1.25rem,4vw,1.5rem);line-height:1.35}
h2{margin:1.5rem 0 0.5rem;font-size:1.1rem}
.sttd-mark{flex:none;width:0.8rem;height:0.8rem;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px var(--soft)}
p{margin:0 0 0.9rem}
a{color:var(--accent)}
code{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:0.1rem 0.35rem}
section{border:1px solid var(--line);border-radius:10px;padding:1rem;margin:1rem 0}
form{margin:0.75rem 0 0}
label{font-weight:600}
input:not([type]),input[type=text],input[type=email],input[type=password]{display:block;width:100%;margin:0.4rem 0 0.75rem;padding:0.6rem 0.75rem;font:inherit;color:var(--ink);background:var(--field);border:1px solid var(--line);border-radius:8px}
#sttd-code-input{max-width:12rem;letter-spacing:0.15em}
input:disabled{color:var(--disabled-ink);background:var(--disabled)}
input[type=checkbox]{width:1.2rem;height:1.2rem;vertical-align:middle;accent-color:var(--accent)}
button{display:block;width:100%;min-height:44px;margin:0.6rem 0 0;padding:0.6rem 1rem;font:inherit;font-weight:600;color:var(--accent-ink);background:var(--accent);border:1px solid var(--accent);border-radius:10px;cursor:pointer}
button:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
form+form button,#sttd-switch-account,#sttd-continue-code{color:var(--ink);background:transparent;border-color:var(--line)}
form+form button:hover,#sttd-switch-account:hover,#sttd-continue-code:hover{background:var(--soft);border-color:var(--line)}
button:disabled,button:disabled:hover{cursor:not-allowed;color:var(--disabled-ink);background:var(--disabled);border-color:var(--line)}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
[role=alert]{color:var(--warn);background:var(--warn-soft);border:1px solid var(--warn);border-radius:8px;padding:0.6rem 0.75rem}
#sttd-message{color:var(--ink)}${PROVIDER_BUTTON_STYLE}`;

/**
 * CSPのstyle-srcに入れる、INTERACTION_STYLEと同一文字列のSHA-256（base64）の固定値（pagesは相対moduleだけをimportするためここで計算しない）。
 * INTERACTION_STYLEを変えたら更新する。更新漏れはtest/console.test.mjsがINTERACTION_STYLEから再計算したhashとの完全一致で検出する。
 */
export const INTERACTION_STYLE_HASH = "'sha256-aRXkacl9Ljo4QRF8vZFH+Q/dR0xVs/TsFgn2A4nQXo0='";

export function pageSecurityHeaders(web: FirebaseWebConfig): Record<string, string> {
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'self' ${SDK_BASE} ${FIREBASE_POPUP_SCRIPT_ORIGIN}`,
      "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
      `frame-src https://${web.authDomain}`,
      `style-src ${INTERACTION_STYLE_HASH}`,
      "img-src data:",
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

function shell(web: FirebaseWebConfig, view: string, lang: Language, path: string, body: string, attributes: Record<string, string>, titleKey: MessageKey = 'interaction.title', script = INTERACTION_SCRIPT_PATH): string {
  const data = Object.entries({ 'sttd-view': view, 'sttd-firebase': JSON.stringify(web), 'sttd-language': lang, ...attributes })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  const title = escapeHtml(text(lang, titleKey));
  return `<!DOCTYPE html>
<html lang="${lang}"><head><meta charset="utf-8"><title>${title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${INTERACTION_STYLE}</style>
<script type="module" src="${script}"></script></head>
<body${data}>
<main>
${languageNav(path, lang)}
<div class="sttd-card">
<h1><span class="sttd-mark" aria-hidden="true"></span>${title}</h1>
${body}
</div>
</main>
</body></html>`;
}

function providerButtons(t: (key: MessageKey) => string, attributes: string): string {
  return `<button type="button" id="sttd-apple-login"${attributes} class="sttd-provider sttd-apple"><span class="sttd-provider-label">${t('common.appleLogin')}</span></button>
<button type="button" id="sttd-google-login"${attributes} class="sttd-provider sttd-google"><img src="${GOOGLE_SIGN_IN_LOGO}" alt="" width="20" height="20"><span>${t('common.googleLogin')}</span></button>`;
}

export function renderDisconnect(web: FirebaseWebConfig, lang: Language, reviewer = false): string {
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const signIn = reviewer ? `
<form id="sttd-disconnect-password-form" method="post">
<label for="sttd-disconnect-email">${escapeHtml(REVIEWER_TEXT[lang].email)}</label>
<input id="sttd-disconnect-email" type="email" autocomplete="username" required>
<label for="sttd-disconnect-password">${escapeHtml(REVIEWER_TEXT[lang].password)}</label>
<input id="sttd-disconnect-password" type="password" autocomplete="current-password" required>
<button type="submit" id="sttd-disconnect-password-submit" disabled>${escapeHtml(REVIEWER_TEXT[lang].submit)}</button>
</form>` : providerButtons(t, ' disabled');
  return shell(web, 'disconnect', lang, reviewer ? REVIEWER_DISCONNECT_PAGE_PATH : DISCONNECT_PAGE_PATH, `
<p>${t('disconnect.loginGuide')}</p>
<div id="sttd-disconnect-sign-in">${signIn}</div>
<section id="sttd-disconnect-account" aria-label="${t('disconnect.account')}" hidden>
<p><strong id="sttd-disconnect-identity"></strong></p>
<p>${t('disconnect.confirm')}</p>
<button type="button" id="sttd-disconnect-confirm">${t('disconnect.confirmAction')}</button>
<button type="button" id="sttd-switch-account">${t('common.switchAccount')}</button>
</section>
<p id="sttd-message" role="status" aria-live="polite"></p>`, reviewer ? { 'sttd-disconnect-reviewer': 'on' } : {}, 'common.disconnect', DISCONNECT_SCRIPT_PATH);
}

export const DISCONNECT_SCRIPT = `import { initializeApp } from '${SDK_BASE}firebase-app.js';
import { browserPopupRedirectResolver, GoogleAuthProvider, inMemoryPersistence, initializeAuth, OAuthProvider, signInWithEmailAndPassword, signInWithPopup, signOut } from '${SDK_BASE}firebase-auth.js';

const { sttdFirebase, sttdLanguage, sttdDisconnectReviewer } = document.body.dataset;
const auth = initializeAuth(initializeApp(JSON.parse(sttdFirebase)), { persistence: inMemoryPersistence, popupRedirectResolver: browserPopupRedirectResolver });
const TEXT = ${messagesJson()};
const t = (key) => TEXT[sttdLanguage][key];
const el = (id) => document.getElementById(id);
const reviewer = sttdDisconnectReviewer === 'on';
const apple = reviewer ? null : el('sttd-apple-login');
const google = reviewer ? null : el('sttd-google-login');
const passwordSubmit = reviewer ? el('sttd-disconnect-password-submit') : null;
const email = reviewer ? el('sttd-disconnect-email') : null;
const confirm = el('sttd-disconnect-confirm');
const switchAccount = el('sttd-switch-account');
const status = el('sttd-message');
let account = null;
let busy = false;
let finished = false;

function render() {
  el('sttd-disconnect-sign-in').hidden = account !== null || finished;
  el('sttd-disconnect-account').hidden = account === null || finished;
  for (const button of [apple, google, passwordSubmit, confirm, switchAccount]) {
    if (button) button.disabled = busy;
  }
}

async function login(authenticate, accountLabel) {
  if (busy || account !== null || finished) return;
  busy = true;
  status.textContent = '';
  render();
  try {
    const { user } = await authenticate();
    if (!user || auth.currentUser !== user) throw new Error('user_changed');
    account = user;
    el('sttd-disconnect-identity').textContent = user.email || user.displayName || accountLabel;
  } catch {
    status.textContent = t('disconnect.loginFailed');
  } finally {
    busy = false;
    render();
    if (account !== null) confirm.focus();
  }
}

apple?.addEventListener('click', () => login(() => signInWithPopup(auth, new OAuthProvider('apple.com')), 'Apple'));
google?.addEventListener('click', () => {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return login(() => signInWithPopup(auth, provider), 'Google');
});
if (reviewer) {
  const password = el('sttd-disconnect-password');
  el('sttd-disconnect-password-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (busy || account !== null || finished) return;
    const address = email.value.trim();
    const secret = password.value;
    password.value = '';
    return login(() => signInWithEmailAndPassword(auth, address, secret), address);
  });
}

switchAccount.addEventListener('click', async () => {
  if (busy || account === null) return;
  busy = true;
  render();
  try {
    await signOut(auth);
    account = null;
    status.textContent = '';
  } catch {
    status.textContent = t('disconnect.loginFailed');
  } finally {
    busy = false;
    render();
    if (account === null) (email ?? apple).focus();
  }
});

confirm.addEventListener('click', async () => {
  if (busy || account === null || finished) return;
  const user = account;
  busy = true;
  status.textContent = t('common.disconnecting');
  render();
  try {
    const token = await user.getIdToken();
    if (auth.currentUser !== user) throw new Error('user_changed');
    const response = await fetch(reviewer ? '${REVIEWER_DISCONNECT_API_PATH}' : '/v1/web/disconnect', {
      method: 'POST',
      credentials: 'omit',
      headers: { Authorization: 'Bearer ' + token },
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(18000),
    });
    if (!response.ok || (await response.json()).state !== 'unlinked') throw new Error('disconnect_unconfirmed');
    finished = true;
    account = null;
    status.textContent = t('disconnect.done');
    await signOut(auth).catch(() => {});
  } catch {
    status.textContent = t('disconnect.failed');
  } finally {
    busy = false;
    render();
  }
});

render();`;

/** 開発者向けコードの入力の固定文言（en/ja。画面とscriptで同じ辞書）。 */
export const CODE_TEXT = Object.freeze({
  en: Object.freeze({
    heading: 'Connect with a code',
    guide: 'Enter the 6-digit code issued in your console. A code works once, within 10 minutes of issue.',
    label: '6-digit code',
    submit: 'Connect with this code',
    rejected: 'This code cannot be used to connect. Generate a new code in the console.',
    limited: 'Too many attempts. Wait a while, then generate a new code in the console.',
    failed: 'The connection could not be completed. Generate a new code in the console.',
    locked: 'A wrong code was entered 3 times, so code entry is locked for this connection. Start a new connection from the plugin to try a code again, or sign in with Apple.',
    busy: 'Connecting…',
    continueSaved: 'Continue with the saved code sign-in',
  }),
  ja: Object.freeze({
    heading: 'コードで接続',
    guide: 'コンソールで発行した6桁のコードを入力してください。発行から10分以内に1回だけ使えます。',
    label: '6桁のコード',
    submit: 'このコードで接続',
    rejected: 'このコードでは接続できません。コンソールで新しいコードを発行してください。',
    limited: '試行が多すぎます。しばらく待ってから、コンソールで新しいコードを発行してください。',
    failed: '接続を完了できませんでした。コンソールで新しいコードを発行してください。',
    locked: 'コードを3回間違えたため、この接続ではコード入力をロックしました。コードを再度試すにはプラグインから新しく接続を始めてください。Appleでのログインは引き続き使えます。',
    busy: '接続しています…',
    continueSaved: '保存済みのコード認証で続ける',
  }),
});

/** 審査・テスト専用ログインの固定文言（en/ja。画面とscriptで同じ辞書）。 */
export const REVIEWER_TEXT = Object.freeze({
  en: Object.freeze({
    open: 'App review sign-in',
    heading: 'Sign in with the review account',
    guide: 'For app review and testing only. Use the email and password of the pre-registered review account. Other accounts cannot sign in here.',
    email: 'Email',
    password: 'Password',
    submit: 'Sign in for review',
    missing: 'Enter the email and password of the review account.',
    rejected: 'This account cannot sign in for review.',
    busy: 'Signing in…',
  }),
  ja: Object.freeze({
    open: '審査用のログイン',
    heading: '審査用アカウントでログイン',
    guide: 'アプリの審査・テスト専用です。事前登録された審査用アカウントのメールアドレスとパスワードを使ってください。他のアカウントはここからログインできません。',
    email: 'メールアドレス',
    password: 'パスワード',
    submit: '審査用にログイン',
    missing: '審査用アカウントのメールアドレスとパスワードを入力してください。',
    rejected: 'このアカウントでは審査用にログインできません。',
    busy: 'ログインしています…',
  }),
});

/** OAuth interactionの1画面目: Appleでログイン（開発者向けコードが有効な配置ではコード入力も、審査専用ログインが有効な配置では審査の入口も）。 */
export function renderInteractionLogin(
  web: FirebaseWebConfig,
  uid: string,
  clientLabel: string,
  csrf: string,
  language: Language = DEFAULT_LANGUAGE,
  codeEnabled = false,
  reviewerEnabled = false,
): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const c = (key: keyof (typeof CODE_TEXT)['en']) => escapeHtml(CODE_TEXT[lang][key]);
  const r = (key: keyof (typeof REVIEWER_TEXT)['en']) => escapeHtml(REVIEWER_TEXT[lang][key]);
  // 審査の入口: 機能onでも入力欄は閉じたまま、本人が「審査用のログイン」を明示に選んだ時だけscriptが開く。機能offは区画ごとhidden・無効。
  const off = reviewerEnabled ? '' : ' disabled';
  const reviewerSection = `
<button type="button" id="sttd-reviewer-open" hidden${off}>${r('open')}</button>
<section id="sttd-reviewer-section" aria-labelledby="sttd-reviewer-heading" hidden>
<h2 id="sttd-reviewer-heading">${r('heading')}</h2>
<p>${r('guide')}</p>
<label for="sttd-reviewer-email">${r('email')}</label>
<input id="sttd-reviewer-email" name="email" type="email" autocomplete="username"${off}>
<label for="sttd-reviewer-password">${r('password')}</label>
<input id="sttd-reviewer-password" name="password" type="password" autocomplete="current-password"${off}>
<button type="button" id="sttd-reviewer-submit"${off}>${r('submit')}</button>
</section>`;
  // scriptが参照する要素は常に置き、機能offでは区画ごとhidden・無効（scriptも結び付けず、serverのcode routeは404）。
  const codeSection = `
<section id="sttd-code-section" aria-labelledby="sttd-code-heading"${codeEnabled ? '' : ' hidden'}>
<h2 id="sttd-code-heading">${c('heading')}</h2>
<p>${c('guide')}</p>
<label for="sttd-code-input">${c('label')}</label>
<input id="sttd-code-input" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" minlength="6" required${codeEnabled ? '' : ' disabled'}>
<button type="button" id="sttd-code-submit"${codeEnabled ? '' : ' disabled'}>${c('submit')}</button>
<button type="button" id="sttd-continue-code" hidden${codeEnabled ? '' : ' disabled'}>${c('continueSaved')}</button>
</section>`;
  return shell(
    web,
    'interaction-login',
    lang,
    `/interaction/${escapeHtml(uid)}`,
    `<p>${t('interaction.client')}${escapeHtml(clientLabel)}</p>
<p>${t('interaction.loginGuide')}</p>
<button type="button" id="sttd-continue" hidden>${t('common.continueSignedIn')}</button>
${providerButtons(t, ' hidden')}
<button type="button" id="sttd-switch-account" hidden>${t('common.switchAccount')}</button>${codeSection}${reviewerSection}
<p id="sttd-message" role="status"></p>`,
    { 'sttd-interaction': uid, 'sttd-csrf': csrf, 'sttd-code': codeEnabled ? 'on' : 'off', 'sttd-reviewer': reviewerEnabled ? 'on' : 'off' },
  );
}

/**
 * 同意画面のsnapshot。受信先設定がある時は、接続承認に伴う削除を案内する。
 */
export interface ReceiverResetView {
  readonly token: string;
  readonly present: boolean;
  /** 前の送信が、未確認・設定の変化で何も削除しなかった時の案内。 */
  readonly required?: boolean;
}

/**
 * OAuth interactionの2画面目: 認証済み本人への明示の許可（1画面）。言語リンクはformの外にあり、同意・拒否を送らない。
 * receiverがある時は、以前の受信先設定の削除を明示する。
 */
/**
 * 許可元strictの同意画面の表示（compatibleはnull）。referenceは権限のない接続要求参照（元interaction ID）、stateは承認待ち・承認済み・
 * 承認が無く同意できなかった（再表示）の区別。表示だけで、承認状態の匿名照会・自動pollは無い（通常の再表示で更新）。
 */
export type SourceConsentView =
  | { readonly reference: string; readonly state: 'waiting' | 'confirmed' | 'required' }
  | { readonly state: 'reviewer_unavailable' };

export function renderInteractionConsent(
  web: FirebaseWebConfig,
  uid: string,
  clientLabel: string,
  csrf: string,
  language: Language = DEFAULT_LANGUAGE,
  receiver: ReceiverResetView | null = null,
  source: SourceConsentView | null = null,
): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const action = `/interaction/${escapeHtml(uid)}`;
  let sourceBlock = '';
  if (source?.state === 'reviewer_unavailable') {
    sourceBlock = `<p role="alert">${t('interaction.source.reviewerUnavailable')}</p>\n`;
  } else if (source !== null) {
    sourceBlock = `<section id="sttd-source-approval" data-sttd-source-state="${source.state}">
<h2>${t('interaction.source.title')}</h2>
<p>${t('interaction.source.reference')}<code id="sttd-source-reference">${escapeHtml(source.reference)}</code></p>
<p>${t('interaction.source.howto')}</p>
<p role="status">${t(source.state === 'confirmed' ? 'interaction.source.confirmed' : source.state === 'required' ? 'interaction.source.required' : 'interaction.source.waiting')}</p>
</section>
`;
  }
  const hasReceiver = receiver !== null && receiver.present;
  const reset =
    receiver === null
      ? ''
      : `${receiver.required === true ? `<p role="status">${t('interaction.receiverReset.required')}</p>\n` : ''}<input type="hidden" name="receiverToken" value="${escapeHtml(receiver.token)}">
${
  hasReceiver
    ? `<p role="alert">${t('interaction.receiverReset.notice')}</p>\n`
    : ''
}`;
  return shell(
    web,
    'interaction-consent',
    lang,
    action,
    `${sourceBlock}<p>${escapeHtml(clientLabel)}${t('interaction.consentQuestion')}</p>
<form method="post" action="${action}/consent">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
${reset}<button type="submit">${t(hasReceiver ? 'interaction.receiverReset.allow' : 'interaction.allow')}</button>
</form>
<form method="post" action="${action}/deny">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit">${t('interaction.deny')}</button>
</form>`,
    { 'sttd-csrf': csrf },
  );
}

/**
 * 利用許可の拒否（同意の時点で運営者の明示許可が無い・停止された）の固定案内。403で返し、owner・UID・Grant・世代・CSRFを含めない。
 * 操作（ログイン・同意・拒否）を持たない。
 */
export function renderInteractionAccessDenied(web: FirebaseWebConfig, uid: string, language: Language = DEFAULT_LANGUAGE): string {
  const lang = languageOf(language);
  return shell(web, 'interaction-access-denied', lang, `/interaction/${escapeHtml(uid)}`, `<p role="alert">${escapeHtml(text(lang, 'interaction.accessDenied'))}</p>`, {});
}

/**
 * 受信先設定の削除は確定したが、その後の接続（Grant・metadata・redirect）が完了しなかった（incomplete）か、結果を確認できない（unknown）時の固定案内。
 * 削除済みであることを隠さない。操作・owner・UID・Grant・CSRFを含めない。
 */
export function renderReceiverResetOutcome(web: FirebaseWebConfig, uid: string, outcome: 'incomplete' | 'unknown' | 'reset_unknown', language: Language = DEFAULT_LANGUAGE): string {
  const lang = languageOf(language);
  const key: MessageKey = outcome === 'incomplete' ? 'interaction.receiverReset.incomplete' : outcome === 'unknown' ? 'interaction.receiverReset.unknown' : 'interaction.receiverReset.resetUnknown';
  return shell(web, 'interaction-receiver-reset', lang, `/interaction/${escapeHtml(uid)}`, `<p role="alert">${escapeHtml(text(lang, key))}</p>`, {});
}

/**
 * interaction画面のscript（login画面だけが操作を持つ。consent画面はnative formで、scriptは何もしない）。SDKの復元を待ち、復元済みsessionの
 * 種類（Apple・開発者コード・不明）を区別する。Appleの「続ける」はAppleの時だけで、本人の操作でそのtokenを送る（popupを開かない）。
 * コードの認証は、コードの機能がonの時だけ別の明示操作（保存済みのコード認証で続ける）として残す。不明・匿名はAppleとして復元しない。
 * popupは本人がAppleを選んだ時だけで、保存済みがApple以外なら先にsignOutする。tokenは取得の前後で選んだuserが変わっていない時だけ送り、
 * 認証の操作は同時に1つだけ。失敗した時は自動でpopupを開かず、ログインの操作へ戻す（保存済みのコードのtokenで代替しない）。
 * Apple providerへscopeを足さない（氏名・メールを要求しない）。ID tokenはbodyだけで送り、URLへ入れない。
 * 文言はbodyのdata-sttd-language（サーバーが選んだ言語）で、埋め込んだ固定辞書から引く。接続状態の表示・解除はこの画面に無い（送信画面の役割）。
 */
export const INTERACTION_SCRIPT = `import { initializeApp } from '${SDK_BASE}firebase-app.js';
import { getAuth, GoogleAuthProvider, OAuthProvider, signInWithCustomToken, signInWithPopup, signOut } from '${SDK_BASE}firebase-auth.js';

const body = document.body;
const view = body.dataset.sttdView;
const auth = getAuth(initializeApp(JSON.parse(body.dataset.sttdFirebase)));
const TEXT = ${messagesJson()};
const CODE_TEXT = ${JSON.stringify(CODE_TEXT)};
const lang = Object.hasOwn(TEXT, body.dataset.sttdLanguage) ? body.dataset.sttdLanguage : 'en';
const T = (key) => (Object.hasOwn(TEXT[lang], key) ? TEXT[lang][key] : '');
const el = (id) => document.getElementById(id);

function say(text) {
  const node = el('sttd-message');
  if (node) node.textContent = text;
}

function show(id, visible) {
  const node = el(id);
  if (node) node.hidden = !visible;
}

const codeOn = body.dataset.sttdCode === 'on';
const reviewerOn = body.dataset.sttdReviewer === 'on';
const REVIEWER_TEXT = ${JSON.stringify(REVIEWER_TEXT)};
const R = (key) => (Object.hasOwn(REVIEWER_TEXT[lang], key) ? REVIEWER_TEXT[lang][key] : '');
const AUTH_BUTTONS = ['sttd-continue', 'sttd-apple-login', 'sttd-google-login', 'sttd-switch-account', 'sttd-code-submit', 'sttd-continue-code', 'sttd-reviewer-open', 'sttd-reviewer-submit'];

function signedOut(message) {
  if (message) say(message);
  show('sttd-continue', false);
  show('sttd-switch-account', false);
  show('sttd-continue-code', false);
  show('sttd-apple-login', true);
  show('sttd-google-login', true);
}

// 保存済みの認証の種類（Apple・開発者コード・不明）。UID・メール等は表示・記録しない。コードのUIDは接続server側で固定の接頭辞を持つ。
function savedKind(user) {
  if (!user) return 'none';
  if (user.isAnonymous) return 'unknown';
  if (typeof user.uid === 'string' && user.uid.startsWith('sttdc_')) return 'code';
  const providers = Array.isArray(user.providerData) ? user.providerData.map((entry) => (entry ? entry.providerId : undefined)) : [];
  // Apple・Googleのどちらか一方だけ（両方を持つ等の曖昧な認証は推測しない）。
  const apple = providers.includes('apple.com');
  const google = providers.includes('google.com');
  if (apple && !google) return 'apple';
  if (google && !apple) return 'google';
  return 'unknown';
}

// 認証の操作は同時に1つだけ（二重クリック・別の方式との競合でloginを複数送らない）。実行中は全ての認証ボタンを止める。
let busy = false;
// この接続セッションでコード入力がロックされた（serverが3回誤入力でsession_locked）。以後コード送信は止めたまま（Appleは使える）。
let codeLocked = false;
function setBusy(value) {
  busy = value;
  for (const id of AUTH_BUTTONS) {
    const node = el(id);
    if (!node) continue;
    const codeButton = id === 'sttd-code-submit';
    const reviewerButton = id === 'sttd-reviewer-open' || id === 'sttd-reviewer-submit';
    node.disabled = value || ((codeButton || id === 'sttd-continue-code') && !codeOn) || (codeButton && codeLocked) || (reviewerButton && !reviewerOn);
  }
}
function lockCode() {
  codeLocked = true;
  const input = el('sttd-code-input');
  if (input) input.disabled = true;
  const submit = el('sttd-code-submit');
  if (submit) submit.disabled = true;
  say(C('locked'));
}
function exclusive(task, failure) {
  return async () => {
    if (busy) return;
    setBusy(true);
    try {
      await task();
    } catch (error) {
      // 固定の案内（別方式で登録済み等）だけはその文言を出す。他の失敗は呼出し側の固定文言。
      signedOut(error instanceof LoginGuidance ? error.message : failure);
    } finally {
      setBusy(false);
    }
  };
}

// 選んだuserのtoken。取得の前後でcurrentUserとUIDが変わっていたら（切替・logout・復元中の変更）使わない。
async function tokenOf(user) {
  if (!user || auth.currentUser !== user) throw new Error('user_changed');
  const uid = user.uid;
  const token = await user.getIdToken();
  if (auth.currentUser !== user || user.uid !== uid) throw new Error('user_changed');
  return token;
}

// Appleでのログイン: 保存済みの認証がApple以外なら先にsignOutし、apple.comのpopupだけを開く。結果がAppleでなければ使わない
// （失敗したAppleの代わりに保存済みのコード認証のtokenを送らない）。
async function appleIdToken() {
  await auth.authStateReady();
  if (auth.currentUser) await signOut(auth);
  const result = await signInWithPopup(auth, new OAuthProvider('apple.com'));
  if (savedKind(result.user) !== 'apple') throw new Error('not_apple');
  return tokenOf(result.user);
}

// Googleでのログイン（Firebase公式GoogleAuthProviderのpopup）: 保存済みの別認証は先にsignOutし、結果がGoogleの時だけ使う。
// 同じメールが別の方式で登録済み（account-exists-with-different-credential）は、既存の方式でログインする固定案内だけを出す
// （fetchSignInMethodsForEmail・自動link・メール一致によるUID統合はしない）。
class LoginGuidance extends Error {}
async function googleIdToken() {
  await auth.authStateReady();
  if (auth.currentUser) await signOut(auth);
  let result;
  try {
    result = await signInWithPopup(auth, new GoogleAuthProvider());
  } catch (error) {
    if (error && error.code === 'auth/account-exists-with-different-credential') throw new LoginGuidance(T('common.googleExistsOther'));
    throw error;
  }
  if (savedKind(result.user) !== 'google') throw new Error('not_google');
  return tokenOf(result.user);
}

// 保存済みのApple/Googleで続ける（そのどちらかの時だけ）。
async function restoredAppleIdToken() {
  const user = auth.currentUser;
  const kind = savedKind(user);
  if (kind !== 'apple' && kind !== 'google') throw new Error('not_saved');
  return tokenOf(user);
}

// 保存済みのコード認証で続ける（コードの機能がonで、保存済みがコードの時だけ。新しいコードは発行しない）。
async function restoredCodeIdToken() {
  const user = auth.currentUser;
  if (!codeOn || savedKind(user) !== 'code') throw new Error('not_code');
  return tokenOf(user);
}

// 審査・テスト専用ログイン（機能onで、本人が審査の入口を明示に選んだ時だけ）。メール・パスワードはFirebase Authの公式REST
// （Identity Toolkit）へだけ送り、得たID tokenを審査専用の/reviewerへ送る（SDKのsessionへ保存しない・表示しない・URLへ入れない）。
// 認可（password・事前登録UID・期限）は全てserverが判定する。
async function reviewerIdToken() {
  const email = el('sttd-reviewer-email');
  const password = el('sttd-reviewer-password');
  const address = email ? email.value.trim() : '';
  const secret = password ? password.value : '';
  if (password) password.value = '';
  if (!reviewerOn || address === '' || secret === '') throw new LoginGuidance(R('missing'));
  say(R('busy'));
  const config = JSON.parse(body.dataset.sttdFirebase);
  const response = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=' + encodeURIComponent(config.apiKey), {
    method: 'POST',
    credentials: 'omit',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: address, password: secret, returnSecureToken: true }),
  });
  if (response.status !== 200) throw new LoginGuidance(R('rejected'));
  const parsed = await response.json();
  if (parsed === null || typeof parsed !== 'object' || typeof parsed.idToken !== 'string') throw new LoginGuidance(R('rejected'));
  return parsed.idToken;
}

async function interactionLogin(idToken, entry) {
  const response = await fetch('/interaction/' + encodeURIComponent(body.dataset.sttdInteraction) + (entry === 'reviewer' ? '/reviewer' : '/login'), {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csrf: body.dataset.sttdCsrf, idToken }),
  });
  if (response.status === 204) location.reload();
  else if (entry === 'reviewer' && response.status === 401) say(R('rejected'));
  else say(T((await accessRefused(response)) ? 'interaction.accessDenied' : 'interaction.loginConfirmFailed'));
}

// 利用許可の拒否は固定の403 access_deniedだけ（他の403・失敗を利用許可の拒否として表示しない）。
async function accessRefused(response) {
  if (response.status !== 403) return false;
  try {
    const parsed = await response.json();
    return parsed !== null && typeof parsed === 'object' && parsed.error !== null && typeof parsed.error === 'object' && parsed.error.code === 'access_denied';
  } catch {
    return false;
  }
}

// 開発者向けコード: 本人の明示操作だけで送る（自動送信・pollなし）。成功時の同origin応答のcustom tokenでFirebase SDKにログインし、
// 既存の/loginへID tokenを送る（同意・購読は通常どおり）。tokenを表示・保存・URLへ入れない。他の認証操作とは排他。
const C = (key) => (Object.hasOwn(CODE_TEXT[lang], key) ? CODE_TEXT[lang][key] : '');
async function codeLogin() {
  if (codeLocked) return lockCode();
  const input = el('sttd-code-input');
  const code = input.value.trim();
  if (!/^[0-9]{6}$/.test(code)) return say(C('rejected'));
  say(C('busy'));
  try {
    const response = await fetch('/interaction/' + encodeURIComponent(body.dataset.sttdInteraction) + '/code', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf: body.dataset.sttdCsrf, code }),
    });
    input.value = '';
    if (response.status === 403) {
      // 403は固定error code session_lockedだけをロックとして扱う（他の403は従来どおり失敗表示）。
      let locked = false;
      try {
        const err = await response.json();
        locked = err !== null && typeof err === 'object' && err.error !== null && typeof err.error === 'object' && err.error.code === 'session_locked';
      } catch {
        locked = false;
      }
      return locked ? lockCode() : say(C('failed'));
    }
    if (response.status !== 200) return say(C(response.status === 429 ? 'limited' : response.status === 400 ? 'rejected' : 'failed'));
    const parsed = await response.json();
    if (parsed === null || typeof parsed !== 'object' || typeof parsed.customToken !== 'string') return say(C('failed'));
    if (auth.currentUser) await signOut(auth);
    const credential = await signInWithCustomToken(auth, parsed.customToken);
    await interactionLogin(await tokenOf(credential.user));
  } catch {
    say(C('failed'));
  }
}

async function start() {
  if (view !== 'interaction-login') return;
  setBusy(false);
  if (codeOn) {
    el('sttd-code-submit').onclick = exclusive(() => codeLogin(), C('failed'));
    el('sttd-continue-code').onclick = exclusive(async () => interactionLogin(await restoredCodeIdToken()), C('failed'));
  }
  el('sttd-apple-login').onclick = exclusive(async () => interactionLogin(await appleIdToken()), T('common.loginFailed'));
  const googleButton = el('sttd-google-login');
  if (googleButton) googleButton.onclick = exclusive(async () => interactionLogin(await googleIdToken()), T('common.loginFailed'));
  el('sttd-switch-account').onclick = exclusive(async () => interactionLogin(await appleIdToken()), T('common.loginFailed'));
  el('sttd-continue').onclick = exclusive(async () => interactionLogin(await restoredAppleIdToken()), T('common.loginRefresh'));
  const reviewerOpen = el('sttd-reviewer-open');
  const reviewerSubmit = el('sttd-reviewer-submit');
  if (reviewerOn && reviewerOpen && reviewerSubmit) {
    reviewerOpen.hidden = false;
    // 入力欄は本人が審査の入口を選んだ時だけ開く。
    reviewerOpen.onclick = () => show('sttd-reviewer-section', true);
    reviewerSubmit.onclick = exclusive(async () => interactionLogin(await reviewerIdToken(), 'reviewer'), R('rejected'));
  }
  await auth.authStateReady();
  const kind = savedKind(auth.currentUser);
  if (kind === 'none') return signedOut();
  if (kind === 'apple' || kind === 'google') {
    // 保存済みApple/Googleで続ける。別の方式は明示のボタン（Apple: 別アカウント、Google: Googleでログイン）だけ。
    show('sttd-apple-login', false);
    show('sttd-google-login', kind === 'apple');
    // 保存Googleは方式を明示する（Appleは従来の中立文言のまま。UIDの統合はしない）。
    el('sttd-continue').textContent = T(kind === 'google' ? 'common.continueSignedInGoogle' : 'common.continueSignedIn');
    show('sttd-continue', true);
    show('sttd-switch-account', kind === 'apple');
    if (kind === 'google') show('sttd-apple-login', true);
    return;
  }
  // Apple以外の保存済みの認証は、Appleとして続ける表示にしない。コードの機能がonでコードの認証なら、別の明示操作として残す。
  signedOut(kind === 'code' && codeOn ? '' : T('interaction.savedNotApple'));
  if (kind === 'code' && codeOn) show('sttd-continue-code', true);
}
await start().catch(() => signedOut(T('common.loginUnknown')));
`;
