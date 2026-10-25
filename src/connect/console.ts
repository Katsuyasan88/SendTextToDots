// ローカル送信画面（http://localhost:<port>/console）。配信・中継はsrc/console/local-server.ts、このfileはHTML/CSS/固定browser scriptだけ。
//   - 表示・再読込み・言語切替・固定プロンプトの表示/コピーでは、Cloud Run/本番API/認証SDKへ通信しない。Firebase Web SDK 13.0.0は手順1の明示
//     ログイン操作で初めてimport()し、復元済みsessionの確認・ID token取得・接続状態の確認もその後にだけ行う。popupは明示操作だけ。
//   - 認証後の操作（接続確認・解除・送信・中止・同ID確認）は同origin（localhost helper）の限定pathへ、Authorization: Bearer と起動ごとのlocal nonce
//     （X-Sttd-Local-Nonce）を付けて送る。helperが固定のMCP/API originへ中継する。本文はRAM/DOMだけ、保存0。
//   - 5段階wizard: 1 ログイン → 2 接続確認（手動1回） → 3 テスト用Dotsプロンプト（コピー＋本人の「貼り付けて次へ」） → 4 送信（単回POST・同ID・取消。
//     本人の「Dotsで本文一致を確認して次へ」） → 5 運用用Dotsプロンプト（コピー＋「貼り付けて完了」）。初期は1だけ有効。完了済みの前stepは薄く
//     表示して再選択でき、再表示だけでは証跡を消さない。再ログイン開始時は2以降、受信を確認できない時は3以降、テスト設定の再適用は4/5を戻す。
//     未解放のstepはクリックしても進めず通信しない。古いasync結果（世代が違うログイン/確認）で後続を解放しない。完了後は4で通常送信を繰り返せる。
//   - HTTP受領（delivered）だけでwizardを進めない。4の完了は利用者がDotsで一致を確認した明示操作。不明（delivery_unknown/結果不明）はAPI結果を
//     成功へ書き換えず、利用者の確認だけで進める。進行中（in-flight・中止確認中・同ID確認中）は完了不可。
//   - 本文欄は空で始まりplaceholderに非機密の例文、主buttonはja「送信」/en「Send」。空・空白だけ・対にならないsurrogate・4096 UTF-8 byte超は通信前に拒否。
//     送信POSTは最大25秒（元期限内）、二重クリックでPOSTを増やさない。終端後は「新しい送信」まで再送しない。自動再送・定期poll 0。
//   - 言語はサーバーが選んだ初期言語で始まり、明示選択は画面内で差し替え、表示専用cookie sttd_language をbrowserで同期に設定する（属性はhelperが
//     scheme に応じて渡す。http localhostではSecureなし）。言語切替で入力・進捗を消さない。コピー処理中の排他/失敗fallback/旧成功表示クリアを維持。
//   - HTML・JS・CSSは固定文字列で、inline script/style・新framework・新依存は無い。動的な値はdata属性へescape、表示はtextContent。
//     nonce・web configは信頼する呼出元（local-server.ts）だけが渡す。

import {
  DEFAULT_LANGUAGE,
  isLanguage,
  LANGUAGE_COOKIE,
  languageCookieAttributes,
  languageHref,
  messagesJson,
  text,
  type Language,
  type MessageKey,
} from './i18n.js';
import { FIREBASE_POPUP_SCRIPT_ORIGIN, FIREBASE_WEB_SDK_VERSION, type FirebaseWebConfig } from './pages.js';

export const CONSOLE_PATH = '/console';
export const CONSOLE_SCRIPT_PATH = '/console/app.js';
export const CONSOLE_STYLE_PATH = '/console/app.css';
/** 既存のinteraction画面と同じ公式CDNの固定版（明示ログイン時にimport()する）。 */
export const CONSOLE_SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
/** helperへの中継要求に必須のlocal nonce header（起動ごとの乱数。Cloudへは転送しない）。 */
export const LOCAL_NONCE_HEADER = 'X-Sttd-Local-Nonce';

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

function checkWeb(web: FirebaseWebConfig): void {
  for (const key of ['apiKey', 'authDomain', 'projectId'] as const) {
    if (typeof web?.[key] !== 'string' || web[key].length === 0) throw new ConsoleConfigError();
  }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(web.authDomain)) throw new ConsoleConfigError();
}

/** 起動ごとのlocal nonce（hex 32〜128字）。 */
export function checkLocalNonce(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{32,128}$/.test(value)) throw new ConsoleConfigError();
  return value;
}

/** 画面の描画option。 */
export interface ConsolePageOptions {
  readonly language?: Language | undefined;
  /** 起動ごとのlocal nonce。 */
  readonly nonce: string;
  /** 画面がhttpsで配信されるか（表示言語cookieのSecure属性）。localhostのhttpではfalse。 */
  readonly secure: boolean;
}

/**
 * ローカル送信画面のheader。script-srcは同originとFirebase固定SDK/popup、connect-srcは同origin（helper）とFirebase認証endpointだけ。
 * 本番APIのoriginはbrowserから直接呼ばないのでCSPに無い。
 */
export function consoleSecurityHeaders(web: FirebaseWebConfig): Record<string, string> {
  checkWeb(web);
  return {
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'self' ${CONSOLE_SDK_BASE} ${FIREBASE_POPUP_SCRIPT_ORIGIN}`,
      "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com",
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

/** /consoleのHTML（5段階wizard、1画面）。値はdata属性へescapeして渡す。文言は選択言語の辞書から入れ、scriptが同じキーで差し替える。 */
export function renderConsolePage(web: FirebaseWebConfig, options: ConsolePageOptions): string {
  checkWeb(web);
  const nonce = checkLocalNonce(options?.nonce);
  const lang: Language = isLanguage(options.language) ? options.language : DEFAULT_LANGUAGE;
  const t = (key: MessageKey) => escapeHtml(text(lang, key));
  const i18n = (key: MessageKey) => ` data-sttd-i18n="${key}"`;
  const data = Object.entries({
    'sttd-firebase': JSON.stringify({ apiKey: web.apiKey, authDomain: web.authDomain, projectId: web.projectId }),
    'sttd-language': lang,
    'sttd-cookie-attributes': languageCookieAttributes(options.secure === true),
    'sttd-local-nonce': nonce,
  })
    .map(([name, value]) => ` data-${name}="${escapeHtml(value)}"`)
    .join('');
  const current = (candidate: Language) => (candidate === lang ? ' aria-current="true"' : '');
  const stepHead = (n: number, key: MessageKey) =>
    `<li class="sttd-step" id="sttd-step-${n}" data-sttd-state="${n === 1 ? 'current' : 'locked'}"><button type="button" id="sttd-step-${n}-head" class="sttd-step-head" aria-controls="sttd-panel-${n}"${n === 1 ? '' : ' disabled'}${i18n(key)}>${t(key)}</button> <span id="sttd-step-${n}-badge" class="sttd-badge"${i18n(n === 1 ? 'wizard.badgeCurrent' : 'wizard.badgeLocked')}>${t(n === 1 ? 'wizard.badgeCurrent' : 'wizard.badgeLocked')}</span></li>`;
  const instructions = (kind: 'test' | 'operation', showKey: MessageKey, textKey: MessageKey, copyKey: MessageKey, doneKey: MessageKey) => `<div class="sttd-instruction-block">
<details id="sttd-guide-${kind}" class="sttd-instructions-details">
<summary id="sttd-guide-${kind}-summary"${i18n(showKey)}>${t(showKey)}</summary>
<pre id="sttd-guide-${kind}-text" class="sttd-instructions" tabindex="0"${i18n(textKey)}>${t(textKey)}</pre>
</details>
<div class="sttd-actions">
<button type="button" id="sttd-copy-${kind}"${i18n(copyKey)}>${t(copyKey)}</button>
<button type="button" id="sttd-manual-${kind}" hidden${i18n('wizard.manualCopied')}>${t('wizard.manualCopied')}</button>
</div>
<p id="sttd-copy-result-${kind}" role="status"></p>
<button type="button" id="sttd-done-${kind}" disabled${i18n(doneKey)}>${t(doneKey)}</button>
</div>`;
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
<p id="sttd-intro"${i18n('wizard.intro')}>${t('wizard.intro')}</p>
<h2 id="sttd-wizard-title"${i18n('wizard.title')}>${t('wizard.title')}</h2>
<ol id="sttd-steps" class="sttd-steps">
${stepHead(1, 'wizard.step1')}
${stepHead(2, 'wizard.step2')}
${stepHead(3, 'wizard.step3')}
${stepHead(4, 'wizard.step4')}
${stepHead(5, 'wizard.step5')}
</ol>
<p id="sttd-wizard-note" role="status"></p>
<section id="sttd-panel-1" class="sttd-panel" aria-labelledby="sttd-panel-1-title" data-sttd-state="current" tabindex="0">
<h2 id="sttd-panel-1-title" class="sttd-panel-title"${i18n('wizard.step1')}>${t('wizard.step1')}</h2>
<p id="sttd-login-intro"${i18n('wizard.loginIntro')}>${t('wizard.loginIntro')}</p>
<p id="sttd-account-text" role="status">${t('console.accountSignedOut')}</p>
<div class="sttd-actions">
<button type="button" id="sttd-login"${i18n('common.appleLogin')}>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch" hidden${i18n('common.switchAccount')}>${t('common.switchAccount')}</button>
</div>
</section>
<section id="sttd-panel-2" class="sttd-panel" aria-labelledby="sttd-panel-2-title" data-sttd-state="locked" tabindex="0">
<h2 id="sttd-panel-2-title" class="sttd-panel-title"${i18n('wizard.step2')}>${t('wizard.step2')}</h2>
<p id="sttd-state-intro"${i18n('wizard.stateIntro')}>${t('wizard.stateIntro')}</p>
<p id="sttd-state-text" role="status"></p>
<p id="sttd-state-guide"></p>
<div class="sttd-actions">
<button type="button" id="sttd-refresh"${i18n('wizard.checkState')}>${t('wizard.checkState')}</button>
<button type="button" id="sttd-disconnect" hidden${i18n('common.disconnect')}>${t('common.disconnect')}</button>
</div>
<div id="sttd-disconnect-confirm" role="group" aria-labelledby="sttd-disconnect-question" hidden>
<p id="sttd-disconnect-question"${i18n('common.disconnectConfirm')}>${t('common.disconnectConfirm')}</p>
<button type="button" id="sttd-disconnect-yes"${i18n('common.disconnectYes')}>${t('common.disconnectYes')}</button>
<button type="button" id="sttd-disconnect-no"${i18n('common.disconnectNo')}>${t('common.disconnectNo')}</button>
</div>
<p id="sttd-disconnect-result" role="status"></p>
</section>
<section id="sttd-panel-3" class="sttd-panel" aria-labelledby="sttd-panel-3-title" data-sttd-state="locked" tabindex="0">
<h2 id="sttd-panel-3-title" class="sttd-panel-title"${i18n('wizard.step3')}>${t('wizard.step3')}</h2>
<p id="sttd-guide-intro"${i18n('guide.intro')}>${t('guide.intro')}</p>
<p id="sttd-guide-step1"${i18n('guide.step1')}>${t('guide.step1')}</p>
${instructions('test', 'guide.showTest', 'guide.testText', 'guide.copyTest', 'wizard.pastedTestNext')}
</section>
<section id="sttd-panel-4" class="sttd-panel" aria-labelledby="sttd-panel-4-title" data-sttd-state="locked" tabindex="0">
<h2 id="sttd-panel-4-title" class="sttd-panel-title"${i18n('wizard.step4')}>${t('wizard.step4')}</h2>
<p id="sttd-send-intro"${i18n('wizard.sendIntro')}>${t('wizard.sendIntro')}</p>
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
<button type="button" id="sttd-verify-send" disabled${i18n('wizard.sendVerified')}>${t('wizard.sendVerified')}</button>
<p id="sttd-verify-hint" class="sttd-note"${i18n('wizard.sendNotVerifiable')}>${t('wizard.sendNotVerifiable')}</p>
</section>
<section id="sttd-panel-5" class="sttd-panel" aria-labelledby="sttd-panel-5-title" data-sttd-state="locked" tabindex="0">
<h2 id="sttd-panel-5-title" class="sttd-panel-title"${i18n('wizard.step5')}>${t('wizard.step5')}</h2>
<p id="sttd-guide-step3"${i18n('guide.step3')}>${t('guide.step3')}</p>
${instructions('operation', 'guide.showOperation', 'guide.operationText', 'guide.copyOperation', 'wizard.pastedOperationFinish')}
</section>
<p id="sttd-complete" class="sttd-complete" role="status" hidden${i18n('wizard.complete')}>${t('wizard.complete')}</p>
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
.sttd-steps { list-style: none; padding: 0; margin: 0 0 0.75rem; display: flex; flex-direction: column; gap: 0.25rem; }
.sttd-step { display: flex; align-items: center; gap: 0.5rem; }
.sttd-step-head { flex: 1; text-align: left; margin: 0; background: #fff; color: #1d1f23; border-color: #b8bdc6; }
.sttd-step[data-sttd-state="current"] .sttd-step-head { border-color: #1f5fbf; border-width: 2px; font-weight: 700; }
.sttd-step[data-sttd-state="done"] .sttd-step-head { color: #4a5059; background: #f5f6f8; }
.sttd-step[data-sttd-state="locked"] .sttd-step-head { color: #8a9099; background: #eceef1; border-color: #d9dce1; }
.sttd-badge { font-size: 0.8rem; color: #4a5059; min-width: 3.5rem; }
.sttd-panel-title { font-size: 1.05rem; margin: 0 0 0.5rem; }
.sttd-instruction-block { margin-top: 0.75rem; }
.sttd-instructions-details summary { cursor: pointer; font-weight: 600; min-height: 44px; display: flex; align-items: center; }
.sttd-instructions { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; background: #f5f6f8; border: 1px solid #d9dce1; border-radius: 6px; padding: 0.75rem; margin: 0; }
.sttd-actions { display: flex; flex-wrap: wrap; }
#sttd-result, #sttd-disconnect-result, #sttd-wizard-note { font-weight: 600; min-height: 1.5em; overflow-wrap: anywhere; }
.sttd-note { font-size: 0.85rem; color: #4a5059; }
.sttd-panel[data-sttd-state="locked"] { opacity: 0.55; background: #eceef1; }
.sttd-panel[data-sttd-state="done"], .sttd-panel[data-sttd-state="ready"] { opacity: 0.8; background: #f5f6f8; cursor: pointer; }
.sttd-panel[data-sttd-state="current"] { border: 2px solid #1f5fbf; }
.sttd-panel[aria-disabled="true"] button, .sttd-panel[aria-disabled="true"] textarea, .sttd-panel[aria-disabled="true"] details, .sttd-panel[aria-disabled="true"] summary, .sttd-panel[aria-disabled="true"] pre, .sttd-panel[aria-disabled="true"] a { pointer-events: none; }
.sttd-complete { font-weight: 700; border: 2px solid #1f5fbf; border-radius: 8px; padding: 0.75rem; }
[hidden] { display: none !important; }
`;

/**
 * 画面のscript（固定asset）。5段階wizardの状態・単回送信・中止・同ID確認・確認後の解除・固定プロンプトのコピー・言語切替。
 * Firebase SDKは手順1の明示操作でだけimport()する。文言は埋め込んだ固定辞書（connect/i18n.ts）からキーで引く。
 */
export const CONSOLE_SCRIPT = `const body = document.body;
const SDK_BASE = '${CONSOLE_SDK_BASE}';
const FIREBASE = JSON.parse(body.dataset.sttdFirebase);
const NONCE = body.dataset.sttdLocalNonce;
const NONCE_HEADER = '${LOCAL_NONCE_HEADER}';
const TEXT = ${messagesJson()};
const LANGUAGE_COOKIE = '${LANGUAGE_COOKIE}';
const COOKIE_ATTRIBUTES = body.dataset.sttdCookieAttributes;
const POST_MS = 25000;
const CANCEL_MS = 5000;
const CHECK_MS = 10000;
const CONNECTION_MS = 10000;
const DISCONNECT_MS = 10000;
const LIFETIME_MS = 60000;
const MAX_TEXT_BYTES = 4096;
const LONE_SURROGATE = /\\p{Cs}/u;
const CONNECTION_STATES = ['unlinked', 'linked', 'subscribed', 'expired', 'change_pending'];
const ERROR_STATUSES = [400, 401, 403, 409, 422, 429];
const TERMINAL = ['delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown'];
const RANK = { in_flight: 1, delivery_unknown: 2, failed: 3, expired: 3, cancelled: 3, delivered: 4 };
const STEPS = [1, 2, 3, 4, 5];
/** Firebase SDKの読込み（明示ログイン時だけ。固定CDNの2 module）。 */
const loadSdkModules = () => Promise.all([import(SDK_BASE + 'firebase-app.js'), import(SDK_BASE + 'firebase-auth.js')]);

const el = (id) => document.getElementById(id);
let lang = Object.hasOwn(TEXT, body.dataset.sttdLanguage) ? body.dataset.sttdLanguage : 'en';
const T = (key) => (Object.hasOwn(TEXT[lang], key) ? TEXT[lang][key] : '');

// ---- 状態（全てRAM。reloadで初期化） ----
let sdk = null;
let sdkLoading = null;
let loginGeneration = 0;
let checkGeneration = 0;
let signedIn = false;
let accountBusy = false;
let accountKey = 'console.accountSignedOut';
let connection = null;
let connectionKey = '';
let guideKey = '';
let checking = false;
let step = 1;
const done = { 1: false, 2: false, 3: false, 4: false, 5: false };
let noteKey = '';
let test = null;
let sendNote = '';
let confirming = false;
let disconnectKey = '';
let copyKey = '';
let copyFor = '';
let copying = false;
// コピー結果の世代（resetごとに進む。古い成功/失敗で新しい手順の完了条件を満たさない）。
let copyEpoch = 0;
// ログイン確定時のowner（Firebase uid。RAMだけ。DOM/log/storageへ出さない）と認証observerの登録済み印。
let ownerUid = null;
let authObserved = false;
const copied = { test: false, operation: false };
const manual = { test: false, operation: false };

function phaseOf(current) {
  if (current.state !== null && TERMINAL.includes(current.state)) return 'settled';
  if (!current.postDone) return 'sending';
  if (current.rejected !== null) return 'settled';
  return 'unknown';
}

function checkable(current) {
  return phaseOf(current) === 'unknown' || current.state === 'delivery_unknown';
}

/** 認証処理・接続確認・解除の処理中。 */
function busy() {
  return accountBusy || checking;
}

/** 送信中（1件の終端まで）か。 */
function sending() {
  return test !== null && phaseOf(test) === 'sending';
}

/** 送信・中止・結果確認のいずれかが進行中か（この間はtestを壊す操作を拒否する）。 */
function inFlight() {
  return test !== null && (phaseOf(test) === 'sending' || test.cancel === 'pending' || test.checking);
}

/** stepの操作（ボタン）を受けるか: 解放済みで、かつ現在activeなpanelであること（非activeのgray panel内のcontrolは誤操作防止で動かさない）。 */
function canAct(n) {
  return available(n) && step === n;
}

/** stepが使えるか（DOMの見た目に頼らず、各handlerもこれで検査する）。確認中は3以降を一時封鎖。 */
function available(n) {
  if (n === 1) return true;
  if (n === 2) return done[1];
  if (checking) return false;
  if (n === 3) return done[2];
  if (n === 4) return done[3];
  return done[4];
}

function sendableNow() {
  return available(4) && signedIn && connection === 'subscribed' && !busy();
}

function languageLocked() {
  return accountBusy || copying || (test !== null && (phaseOf(test) === 'sending' || test.cancel === 'pending' || test.checking));
}

/** 本人がDotsで一致を確認できる送信終端か（受領/不明。未送信・失敗・中止・期限切れ・進行中は不可）。 */
function verifiable() {
  if (test === null || !test.postDone || test.cancel === 'pending' || test.checking) return false;
  if (test.state === 'delivered' || test.state === 'delivery_unknown') return true;
  return test.state === null && test.rejected === null;
}

/** 手順nから後ろの進捗を戻す（nより前の証跡は消さない）。進行中のコピーの結果はこのresetより前の世代として捨てる。 */
function resetFrom(n) {
  copyEpoch += 1;
  for (const k of STEPS) if (k >= n) done[k] = false;
  if (n <= 2) {
    connection = null;
    connectionKey = '';
    guideKey = '';
    confirming = false;
    disconnectKey = '';
  }
  if (n <= 3) {
    copied.test = false;
    manual.test = false;
  }
  if (n <= 4) {
    test = null;
    sendNote = '';
    el('sttd-text').value = '';
  }
  if (n <= 5) {
    copied.operation = false;
    manual.operation = false;
  }
  if (copyFor !== '' && ((n <= 3 && copyFor === 'test') || (n <= 5 && copyFor === 'operation'))) {
    copyKey = '';
    copyFor = '';
  }
  if (step > n) step = n;
}

function render() {
  const phase = test === null ? null : phaseOf(test);
  for (const n of STEPS) {
    const state = step === n ? 'current' : done[n] ? 'done' : available(n) ? 'ready' : 'locked';
    el('sttd-step-' + n).setAttribute('data-sttd-state', state);
    el('sttd-step-' + n + '-head').disabled = !available(n);
    el('sttd-step-' + n + '-badge').textContent = T(state === 'current' ? 'wizard.badgeCurrent' : state === 'done' ? 'wizard.badgeDone' : state === 'ready' ? '' : 'wizard.badgeLocked');
    // 全panelを順に表示し、非active/未解放はgray。panel自身（done/ready）はクリック/keyboardで再活性化できる。
    const panel = el('sttd-panel-' + n);
    panel.setAttribute('data-sttd-state', state);
    panel.setAttribute('aria-disabled', state === 'current' ? 'false' : 'true');
  }
  el('sttd-wizard-note').textContent = T(noteKey);
  // 非activeのpanel内controlは誤操作防止で全て無効（handlerもcanActで拒否する）。
  const inactive = (n) => step !== n;
  // 1 ログイン
  el('sttd-account-text').textContent = T(accountKey);
  el('sttd-login').hidden = signedIn;
  el('sttd-login').disabled = inactive(1) || busy() || inFlight();
  el('sttd-switch').hidden = !signedIn;
  el('sttd-switch').disabled = inactive(1) || busy() || inFlight() || confirming;
  // 2 接続確認
  el('sttd-state-text').textContent = checking ? T('wizard.checking') : connection === null ? T(connectionKey) : T(connection === 'subscribed' ? 'console.state.subscribed' : 'common.state.' + connection);
  el('sttd-state-guide').textContent = checking ? '' : T(guideKey);
  el('sttd-refresh').disabled = inactive(2) || !available(2) || busy() || inFlight() || confirming;
  el('sttd-disconnect').hidden = !signedIn || confirming || connection === null || connection === 'unlinked';
  el('sttd-disconnect').disabled = inactive(2) || busy() || inFlight();
  el('sttd-disconnect-confirm').hidden = !confirming;
  el('sttd-disconnect-yes').disabled = inactive(2) || busy();
  el('sttd-disconnect-no').disabled = inactive(2) || busy();
  el('sttd-disconnect-result').textContent = T(disconnectKey);
  // 3/5 プロンプト
  for (const kind of ['test', 'operation']) {
    const n = kind === 'test' ? 3 : 5;
    el('sttd-copy-' + kind).disabled = inactive(n) || copying || !available(n);
    el('sttd-manual-' + kind).hidden = !(copyFor === kind && (copyKey === 'guide.copyUnavailable' || copyKey === 'guide.copyFailed')) || manual[kind];
    el('sttd-manual-' + kind).disabled = inactive(n) || copying || !available(n);
    el('sttd-copy-result-' + kind).textContent = copyFor === kind ? T(copyKey) : '';
    el('sttd-done-' + kind).disabled = inactive(n) || copying || !available(n) || !(copied[kind] || manual[kind]) || (kind === 'test' && inFlight());
  }
  // 完了banner（panel5の外、画面下）: done5の間は手順4へ戻っても表示する。
  el('sttd-complete').hidden = !done[5];
  // 4 送信
  const sendable = sendableNow() && !inactive(4);
  el('sttd-text').disabled = !sendable || test !== null;
  el('sttd-send').disabled = !sendable || test !== null;
  el('sttd-cancel').hidden = test === null || (phase !== 'sending' && phase !== 'unknown') || test.cancel === 'answered' || test.cancel === 'unconfirmed';
  el('sttd-cancel').disabled = inactive(4) || (test !== null && test.cancel === 'pending');
  el('sttd-check').hidden = test === null || !checkable(test);
  el('sttd-check').disabled = inactive(4) || (test !== null && test.checking);
  el('sttd-new').hidden = test === null || phase === 'sending' || test.cancel === 'pending' || test.checking;
  el('sttd-new').disabled = inactive(4);
  el('sttd-verify-send').disabled = inactive(4) || !available(4) || busy() || !verifiable();
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
  } else if (sendNote) {
    lines.push(T(sendNote));
  }
  el('sttd-result').textContent = lines.join(' ');
}

function applyLanguage() {
  if (document.documentElement) document.documentElement.lang = lang;
  document.title = T('console.title');
  for (const node of document.querySelectorAll('[data-sttd-i18n]')) node.textContent = T(node.dataset.sttdI18n);
  el('sttd-text').placeholder = T('console.textPlaceholder');
  render();
}

function chooseLanguage(next) {
  if (languageLocked() || !Object.hasOwn(TEXT, next)) return;
  if (next === lang) return;
  lang = next;
  copyKey = '';
  copyFor = '';
  applyLanguage();
  document.cookie = LANGUAGE_COOKIE + '=' + next + '; ' + COOKIE_ATTRIBUTES;
}

function selectStep(n) {
  if (!available(n)) return;
  step = n;
  render();
}

/**
 * panelのクリック/keyboard（Enter/Space）での再活性化。capture phaseでイベント開始時のactive状態を見る:
 *   - 非activeなpanelへの最初のclick/keyは「再選択だけ」。伝播を止め既定動作も止めるので、内部のbutton・summary/detailsは動かない
 *     （未解放なら再選択もせず何も起きない）。
 *   - activeなpanel内のclick（「貼り付けて次へ」「本文一致を確認して次へ」等）はそのまま内部handlerへ届き、stepが次へ移っても
 *     このhandlerはbubbleで再び呼ばれないため、元のpanelが再選択されて戻ることは無い。
 */
function panelCapture(n, event) {
  if (step === n) return;
  if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
  if (event && typeof event.preventDefault === 'function') event.preventDefault();
  if (!available(n)) return;
  selectStep(n);
}

function panelKeyCapture(n, event) {
  if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
  panelCapture(n, event);
}

/** ログイン中accountの変化（別owner・ログアウト・失効）: 以降の要求を止め、2以降を戻してログインからやり直す。古いasync結果は世代で捨てる。 */
function authLost(key) {
  loginGeneration += 1;
  checkGeneration += 1;
  checking = false;
  accountBusy = false;
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  ownerUid = null;
  step = 1;
  accountKey = key || 'common.loginRefresh';
  noteKey = 'wizard.authChanged';
  render();
}

/** 明示ログインの後だけ認証observerを1回登録する（owner変更/ログアウトを検知。ログイン前にはSDKも観測も始めない）。 */
function observeAuth(s) {
  if (authObserved || typeof s.auth.onAuthStateChanged !== 'function') return;
  authObserved = true;
  s.auth.onAuthStateChanged((user) => {
    if (!signedIn || ownerUid === null) return;
    if (!user || user.uid !== ownerUid) authLost('common.loginRefresh');
  });
}

// ---- 1 ログイン（SDKはここで初めて読む） ----

function ensureSdk() {
  if (sdk !== null) return Promise.resolve(sdk);
  if (sdkLoading === null) {
    sdkLoading = loadSdkModules()
      .then(([app, authModule]) => {
        const auth = authModule.getAuth(app.initializeApp(FIREBASE));
        sdk = { auth, OAuthProvider: authModule.OAuthProvider, signInWithPopup: authModule.signInWithPopup, signOut: authModule.signOut };
        return sdk;
      })
      .catch((error) => {
        sdkLoading = null;
        throw error;
      });
  }
  return sdkLoading;
}

function popupBlocked(error) {
  const code = error && typeof error.code === 'string' ? error.code : '';
  return code === 'auth/popup-blocked';
}

/** 明示ログイン（switchingは別account）。開始時に2以降を戻す。世代が変わった古い結果では何も解放しない。 */
async function login(switching) {
  if (!canAct(1) || busy() || inFlight()) return;
  const gen = ++loginGeneration;
  const hadProgress = done[1];
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  ownerUid = null;
  step = 1;
  noteKey = hadProgress ? 'wizard.loginReset' : '';
  accountBusy = true;
  accountKey = sdk === null ? 'wizard.loginLoading' : 'console.accountChecking';
  render();
  try {
    let s;
    try {
      s = await ensureSdk();
    } catch {
      if (gen === loginGeneration) accountKey = 'wizard.loginLoadFailed';
      return;
    }
    if (gen !== loginGeneration) return;
    if (switching && s.auth.currentUser) await s.signOut(s.auth);
    await s.auth.authStateReady();
    if (gen !== loginGeneration) return;
    if (!s.auth.currentUser || switching) {
      try {
        await s.signInWithPopup(s.auth, new s.OAuthProvider('apple.com'));
      } catch (error) {
        if (gen !== loginGeneration) return;
        if (!s.auth.currentUser) {
          accountKey = popupBlocked(error) ? 'wizard.loginPopupBlocked' : 'common.loginFailed';
          return;
        }
      }
    }
    if (gen !== loginGeneration) return;
    const user = s.auth.currentUser;
    if (!user || typeof user.uid !== 'string' || user.uid === '') {
      accountKey = 'common.loginFailed';
      return;
    }
    await user.getIdToken();
    if (gen !== loginGeneration || s.auth.currentUser !== user) return;
    // ログイン確定時のownerへ束縛し、以降の要求はこのownerの現在userからだけtokenを得る。
    ownerUid = user.uid;
    signedIn = true;
    done[1] = true;
    accountKey = 'wizard.loginDone';
    step = 2;
    observeAuth(s);
  } catch {
    if (gen === loginGeneration) accountKey = 'common.loginFailed';
  } finally {
    if (gen === loginGeneration) {
      accountBusy = false;
      render();
    }
  }
}

/** 束縛したownerの現在userからだけtokenを得る。取得の前後で同じowner・同じログイン世代でなければ使わない。 */
async function idToken() {
  const gen = loginGeneration;
  const uid = ownerUid;
  if (sdk === null || uid === null || !signedIn) throw new Error('signed_out');
  const user = sdk.auth.currentUser;
  if (!user || user.uid !== uid) throw new Error('owner_changed');
  const token = await user.getIdToken();
  if (gen !== loginGeneration || ownerUid !== uid || sdk.auth.currentUser !== user || user.uid !== uid) throw new Error('owner_changed');
  return token;
}

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
 * 同origin helperへの1要求（Bearer＋local nonce、credentials omit、redirectを辿らない）。元期限は認証取得・HTTP・JSON待ちを全て含む。
 * 期限内にtokenが無ければHTTPを始めずnot_sent。HTTPを始めた後の失敗・timeoutはunknown。
 */
async function request(path, method, ms, headers, payload) {
  const deadline = Date.now() + Math.max(0, ms);
  const gen = loginGeneration;
  const got = await within(idToken(), deadline - Date.now());
  if (gen !== loginGeneration || !Object.hasOwn(got, 'value')) return { kind: 'not_sent' };
  const remaining = deadline - Date.now();
  if (!(remaining > 0)) return { kind: 'not_sent' };
  const token = got.value;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  try {
    const response = await fetch(path, {
      method,
      headers: Object.assign({}, headers, { Authorization: 'Bearer ' + token, [NONCE_HEADER]: NONCE }),
      body: payload,
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
    if (gen !== loginGeneration) return { kind: 'stale' };
    // 認証失効（401）: 古い進捗を残さずログインからやり直す（呼出し側の続きは世代/testの検査で止まる）。
    if (response.status === 401) authLost('common.loginRefresh');
    return { kind: 'response', status: response.status, json };
  } catch {
    return gen === loginGeneration ? { kind: 'unknown' } : { kind: 'stale' };
  } finally {
    clearTimeout(timer);
  }
}

// ---- 2 接続確認（手動1回。確認中は3以降を封鎖。subscribed継続なら進捗保持、他は3以降を戻す） ----

async function checkConnection(internal) {
  if (!available(2) || busy() || inFlight() || confirming) return;
  if (!internal && !canAct(2)) return;
  const gen = ++checkGeneration;
  const login = loginGeneration;
  checking = true;
  render();
  const outcome = await request('/v1/web/connection', 'GET', CONNECTION_MS, {}, undefined);
  if (gen !== checkGeneration || login !== loginGeneration) return;
  checking = false;
  if (outcome.kind === 'stale') return render();
  if (outcome.kind === 'not_sent') {
    // tokenを得られない（owner変更/失効/未ログイン）: ログインからやり直す。
    authLost('common.loginRefresh');
    return;
  }
  const json = outcome.kind === 'response' ? outcome.json : null;
  if (json && typeof json.state === 'string' && CONNECTION_STATES.includes(json.state)) {
    connection = json.state;
    guideKey = 'wizard.next.' + json.state;
    if (json.state === 'subscribed') {
      const first = !done[2];
      done[2] = true;
      noteKey = '';
      if (first) step = 3;
    } else {
      if (done[3] || done[4] || done[5]) noteKey = 'wizard.stateReset';
      resetFrom(3);
      done[2] = false;
      step = 2;
    }
  } else if (outcome.kind === 'response' && outcome.status === 401) {
    // request()がauthLostを実行済み（世代が進んで上で戻るのが通常。念のため同じ処理）。
    authLost('common.loginRefresh');
    return;
  } else {
    connection = null;
    connectionKey = 'console.connectionUnavailable';
    guideKey = 'wizard.next.unavailable';
    if (done[3] || done[4] || done[5]) noteKey = 'wizard.stateReset';
    resetFrom(3);
    done[2] = false;
    step = 2;
  }
  render();
}

// ---- 解除（確認→1回POST→2以降を戻して再確認） ----

function askDisconnect() {
  if (!canAct(2) || busy() || inFlight() || !signedIn || connection === null || connection === 'unlinked') return;
  confirming = true;
  disconnectKey = '';
  render();
}

function keepConnection() {
  if (!canAct(2) || busy()) return;
  confirming = false;
  render();
}

function disconnect() {
  if (!canAct(2) || !confirming || busy() || inFlight()) return;
  confirming = false;
  accountBusy = true;
  disconnectKey = 'common.disconnecting';
  render();
  const login = loginGeneration;
  return (async () => {
    const outcome = await request('/v1/web/disconnect', 'POST', DISCONNECT_MS, {}, undefined);
    if (login !== loginGeneration || outcome.kind === 'stale') return;
    const json = outcome.kind === 'response' ? outcome.json : null;
    const ok = outcome.kind === 'response' && outcome.status >= 200 && outcome.status < 300 && json !== null && typeof json.state === 'string' && CONNECTION_STATES.includes(json.state);
    accountBusy = false;
    if (done[3] || done[4] || done[5]) noteKey = 'wizard.stateReset';
    resetFrom(2);
    step = 2;
    disconnectKey = ok ? 'common.disconnectDone' : 'common.disconnectFailed';
    connectionKey = '';
    guideKey = '';
    render();
    await checkConnection(true);
  })();
}

// ---- 3/5 固定プロンプトのコピーと完了操作 ----

function copyInstructions(kind) {
  const n = kind === 'test' ? 3 : 5;
  if (copying || !canAct(n)) return;
  const text = T(kind === 'operation' ? 'guide.operationText' : 'guide.testText');
  // この結果はこのresetの世代に束縛する（pending中にreset/再ログイン/再確認があれば捨てる）。
  const epoch = copyEpoch;
  copyFor = kind;
  const clipboard = typeof navigator === 'object' && navigator !== null ? navigator.clipboard : undefined;
  if (!clipboard || typeof clipboard.writeText !== 'function') {
    copyKey = 'guide.copyUnavailable';
    return render();
  }
  copying = true;
  copyKey = '';
  render();
  let pending;
  try {
    pending = Promise.resolve(clipboard.writeText(text));
  } catch {
    pending = Promise.reject(new Error('copy_failed'));
  }
  const finish = (result) => {
    copying = false;
    if (epoch !== copyEpoch) return render();
    copyKey = result;
    if (result === 'guide.copied') copied[kind] = true;
    render();
  };
  return pending.then(
    () => finish('guide.copied'),
    () => finish('guide.copyFailed'),
  );
}

function confirmManualCopy(kind) {
  const n = kind === 'test' ? 3 : 5;
  if (copying || !canAct(n)) return;
  manual[kind] = true;
  copyFor = kind;
  copyKey = 'wizard.manualNoted';
  render();
}

/** 3の完了操作: コピー（または手動確認）済みの時だけ。再適用なら4/5を戻すが、送信・中止・結果確認の進行中は破壊しない（単回送信とcommandIdを保つ）。 */
function completeTest() {
  if (copying || !canAct(3) || busy()) return;
  if (!(copied.test || manual.test)) {
    copyFor = 'test';
    copyKey = 'wizard.copyRequired';
    return render();
  }
  if (inFlight()) {
    noteKey = 'wizard.sendPending';
    return render();
  }
  const reapplied = done[3];
  resetFrom(4);
  done[3] = true;
  noteKey = reapplied ? 'wizard.testReapplied' : '';
  step = 4;
  render();
}

/** 4の完了操作: 本人がDotsで一致を確認した明示操作（受領/不明の終端だけ）。 */
function verifySend() {
  if (!canAct(4) || busy() || !verifiable()) return;
  done[4] = true;
  step = 5;
  render();
}

/** 5の完了操作。 */
function completeOperation() {
  if (copying || !canAct(5) || busy()) return;
  if (!(copied.operation || manual.operation)) {
    copyFor = 'operation';
    copyKey = 'wizard.copyRequired';
    return render();
  }
  done[5] = true;
  noteKey = '';
  render();
}

// ---- 4 送信・中止・同ID確認 ----

function stateOf(current, outcome) {
  const json = outcome.kind === 'response' ? outcome.json : null;
  if (json && json.commandId === current.commandId && typeof json.state === 'string' && Object.hasOwn(RANK, json.state)) return json.state;
  return null;
}

function apply(current, state) {
  if (current.state !== null && RANK[current.state] >= RANK[state]) return;
  current.state = state;
}

async function send() {
  if (!sendableNow() || !canAct(4) || test !== null) return;
  const text = el('sttd-text').value;
  if (typeof text !== 'string' || text.trim() === '' || LONE_SURROGATE.test(text) || new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    sendNote = 'console.inputInvalid';
    return render();
  }
  const created = Date.now();
  const current = { commandId: crypto.randomUUID(), state: null, postDone: false, rejected: null, cancel: 'none', checking: false, checkNote: '' };
  test = current;
  sendNote = '';
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
  sendNote = uncertain ? 'console.duplicateWarning' : '';
  render();
}

function start() {
  for (const n of STEPS) {
    el('sttd-step-' + n + '-head').onclick = () => selectStep(n);
    // 前のpanelのどこをクリックしても（Enter/Spaceでも）再活性化できる。capture phaseで判定し、非activeへのclickは内部操作にしない。
    el('sttd-panel-' + n).addEventListener('click', (event) => panelCapture(n, event), true);
    el('sttd-panel-' + n).addEventListener('keydown', (event) => panelKeyCapture(n, event), true);
  }
  el('sttd-login').onclick = () => login(false);
  el('sttd-switch').onclick = () => login(true);
  el('sttd-refresh').onclick = () => checkConnection();
  el('sttd-disconnect').onclick = () => askDisconnect();
  el('sttd-disconnect-yes').onclick = () => disconnect();
  el('sttd-disconnect-no').onclick = () => keepConnection();
  el('sttd-copy-test').onclick = () => copyInstructions('test');
  el('sttd-copy-operation').onclick = () => copyInstructions('operation');
  el('sttd-manual-test').onclick = () => confirmManualCopy('test');
  el('sttd-manual-operation').onclick = () => confirmManualCopy('operation');
  el('sttd-done-test').onclick = () => completeTest();
  el('sttd-done-operation').onclick = () => completeOperation();
  el('sttd-verify-send').onclick = () => verifySend();
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
  // 初期表示では通信もSDK読込みもしない（手順1だけ有効）。
  render();
}

start();
`;

/** 固定3 pathのasset（それ以外はundefined）。 */
export interface ConsoleAsset {
  readonly type: string;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export function consoleAsset(path: string, web: FirebaseWebConfig, options: ConsolePageOptions): ConsoleAsset | undefined {
  switch (path) {
    case CONSOLE_PATH:
      return { type: 'text/html; charset=utf-8', body: renderConsolePage(web, options), headers: consoleSecurityHeaders(web) };
    case CONSOLE_SCRIPT_PATH:
      return { type: 'text/javascript; charset=utf-8', body: CONSOLE_SCRIPT, headers: {} };
    case CONSOLE_STYLE_PATH:
      return { type: 'text/css; charset=utf-8', body: CONSOLE_STYLE, headers: {} };
    default:
      return undefined;
  }
}
