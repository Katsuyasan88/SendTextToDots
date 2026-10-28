// OAuth interaction（login/consent）の最小画面と、その固定script。Appleログイン（Firebase Web SDK、Apple providerのみ・追加scopeなし）・
// ログイン中accountの継続・明示のaccount切替・本人の明示同意/拒否（native form POST、CSRF）。通常入口の送信画面は connect/console.ts。
// 値はdata属性へescapeして渡し、inline scriptを置かない。Web SDKは公式CDNの固定版だけを読み込む。
// 文言はen/jaの固定辞書（connect/i18n.ts）から入れ、各画面にEnglish/日本語の明示選択（同じpathへの`?lang=`のGETリンク）を置く。
// 言語のリンクはform送信・ログイン・同意・拒否を起こさない。旧接続画面（/connect）は無く、互換route・redirectも置かない。

import { DEFAULT_LANGUAGE, isLanguage, languageHref, messagesJson, text, type Language, type MessageKey } from './i18n.js';

export const FIREBASE_WEB_SDK_VERSION = '13.0.0';
const SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
/** OAuth interaction画面が読む固定script（同origin）。 */
export const INTERACTION_SCRIPT_PATH = '/interaction/app.js';

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

function shell(web: FirebaseWebConfig, view: string, lang: Language, path: string, body: string, attributes: Record<string, string>): string {
  const data = Object.entries({ 'sttd-view': view, 'sttd-firebase': JSON.stringify(web), 'sttd-language': lang, ...attributes })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  const title = escapeHtml(text(lang, 'interaction.title'));
  return `<!DOCTYPE html>
<html lang="${lang}"><head><meta charset="utf-8"><title>${title}</title>
<script type="module" src="${INTERACTION_SCRIPT_PATH}"></script></head>
<body${data}>
${languageNav(path, lang)}
<h1>${title}</h1>
${body}
</body></html>`;
}

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
    busy: '接続しています…',
    continueSaved: '保存済みのコード認証で続ける',
  }),
});

/** OAuth interactionの1画面目: Appleでログイン（開発者向けコードが有効な配置ではコード入力も）。 */
export function renderInteractionLogin(
  web: FirebaseWebConfig,
  uid: string,
  clientLabel: string,
  csrf: string,
  language: Language = DEFAULT_LANGUAGE,
  codeEnabled = false,
): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const c = (key: keyof (typeof CODE_TEXT)['en']) => escapeHtml(CODE_TEXT[lang][key]);
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
<button type="button" id="sttd-apple-login" hidden>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch-account" hidden>${t('common.switchAccount')}</button>${codeSection}
<p id="sttd-message" role="status"></p>`,
    { 'sttd-interaction': uid, 'sttd-csrf': csrf, 'sttd-code': codeEnabled ? 'on' : 'off' },
  );
}

/** 同意画面での受信先設定の削除の確認（Appleのlogin・既存の受信先設定がある時だけ）。tokenはserverが作った不透明値。 */
export interface ReceiverResetView {
  readonly token: string;
  /** 前の送信が、未確認・設定の変化で何も削除しなかった時の案内。 */
  readonly required?: boolean;
}

/**
 * OAuth interactionの2画面目: 認証済み本人への明示の許可（1画面）。言語リンクはformの外にあり、同意・拒否を送らない。
 * receiverがある時は、以前の受信先設定の削除を明示し、初期未選択の確認欄と削除を含む許可の文言にする（未選択なら削除しない）。
 */
export function renderInteractionConsent(
  web: FirebaseWebConfig,
  uid: string,
  clientLabel: string,
  csrf: string,
  language: Language = DEFAULT_LANGUAGE,
  receiver: ReceiverResetView | null = null,
): string {
  const lang = languageOf(language);
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const action = `/interaction/${escapeHtml(uid)}`;
  const reset =
    receiver === null
      ? ''
      : `${receiver.required === true ? `<p role="status">${t('interaction.receiverReset.required')}</p>\n` : ''}<p role="alert">${t('interaction.receiverReset.notice')}</p>
<input type="hidden" name="receiverToken" value="${escapeHtml(receiver.token)}">
<p><input type="checkbox" id="sttd-receiver-reset" name="receiverReset" value="1" required> <label for="sttd-receiver-reset">${t('interaction.receiverReset.confirm')}</label></p>
`;
  return shell(
    web,
    'interaction-consent',
    lang,
    action,
    `<p>${escapeHtml(clientLabel)}${t('interaction.consentQuestion')}</p>
<form method="post" action="${action}/consent">
<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
${reset}<button type="submit">${t(receiver === null ? 'interaction.allow' : 'interaction.receiverReset.allow')}</button>
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
export function renderReceiverResetOutcome(web: FirebaseWebConfig, uid: string, outcome: 'incomplete' | 'unknown', language: Language = DEFAULT_LANGUAGE): string {
  const lang = languageOf(language);
  const key: MessageKey = outcome === 'incomplete' ? 'interaction.receiverReset.incomplete' : 'interaction.receiverReset.unknown';
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
import { getAuth, OAuthProvider, signInWithCustomToken, signInWithPopup, signOut } from '${SDK_BASE}firebase-auth.js';

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
const AUTH_BUTTONS = ['sttd-continue', 'sttd-apple-login', 'sttd-switch-account', 'sttd-code-submit', 'sttd-continue-code'];

function signedOut(message) {
  if (message) say(message);
  show('sttd-continue', false);
  show('sttd-switch-account', false);
  show('sttd-continue-code', false);
  show('sttd-apple-login', true);
}

// 保存済みの認証の種類（Apple・開発者コード・不明）。UID・メール等は表示・記録しない。コードのUIDは接続server側で固定の接頭辞を持つ。
function savedKind(user) {
  if (!user) return 'none';
  if (user.isAnonymous) return 'unknown';
  if (typeof user.uid === 'string' && user.uid.startsWith('sttdc_')) return 'code';
  const providers = Array.isArray(user.providerData) ? user.providerData.map((entry) => (entry ? entry.providerId : undefined)) : [];
  return providers.includes('apple.com') ? 'apple' : 'unknown';
}

// 認証の操作は同時に1つだけ（二重クリック・別の方式との競合でloginを複数送らない）。実行中は全ての認証ボタンを止める。
let busy = false;
function setBusy(value) {
  busy = value;
  for (const id of AUTH_BUTTONS) {
    const node = el(id);
    if (!node) continue;
    const codeButton = id === 'sttd-code-submit' || id === 'sttd-continue-code';
    node.disabled = value || (codeButton && !codeOn);
  }
}
function exclusive(task, failure) {
  return async () => {
    if (busy) return;
    setBusy(true);
    try {
      await task();
    } catch {
      signedOut(failure);
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

// 保存済みのAppleで続ける（Appleの時だけ）。
async function restoredAppleIdToken() {
  const user = auth.currentUser;
  if (savedKind(user) !== 'apple') throw new Error('not_apple');
  return tokenOf(user);
}

// 保存済みのコード認証で続ける（コードの機能がonで、保存済みがコードの時だけ。新しいコードは発行しない）。
async function restoredCodeIdToken() {
  const user = auth.currentUser;
  if (!codeOn || savedKind(user) !== 'code') throw new Error('not_code');
  return tokenOf(user);
}

async function interactionLogin(idToken) {
  const response = await fetch('/interaction/' + encodeURIComponent(body.dataset.sttdInteraction) + '/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csrf: body.dataset.sttdCsrf, idToken }),
  });
  if (response.status === 204) location.reload();
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
  el('sttd-switch-account').onclick = exclusive(async () => interactionLogin(await appleIdToken()), T('common.loginFailed'));
  el('sttd-continue').onclick = exclusive(async () => interactionLogin(await restoredAppleIdToken()), T('common.loginRefresh'));
  await auth.authStateReady();
  const kind = savedKind(auth.currentUser);
  if (kind === 'none') return signedOut();
  if (kind === 'apple') {
    show('sttd-apple-login', false);
    show('sttd-continue', true);
    show('sttd-switch-account', true);
    return;
  }
  // Apple以外の保存済みの認証は、Appleとして続ける表示にしない。コードの機能がonでコードの認証なら、別の明示操作として残す。
  signedOut(kind === 'code' && codeOn ? '' : T('interaction.savedNotApple'));
  if (kind === 'code' && codeOn) show('sttd-continue-code', true);
}
await start().catch(() => signedOut(T('common.loginUnknown')));
`;
