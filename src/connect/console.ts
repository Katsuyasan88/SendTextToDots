// ローカル送信画面（http://localhost:<port>/console）。配信・中継はsrc/console/local-server.ts、このfileはHTML/CSS/固定browser scriptだけ。
//   - 表示・再読込み・言語切替・固定プロンプトの表示/コピーでは、Cloud Run/本番API/認証SDKへ通信しない。Firebase Web SDK 13.0.0は手順1の明示
//     ログイン操作で初めてimport()し、復元済みsessionの確認・ID token取得・接続状態の確認もその後にだけ行う。popupは明示操作だけ。
//   - 認証後の操作（接続確認・解除・送信・中止・同ID確認）は同origin（localhost helper）の限定pathへ、Authorization: Bearer と起動ごとのlocal nonce
//     （X-Sttd-Local-Nonce）を付けて送る。helperが固定のMCP/API originへ中継する。本文はRAM/DOMだけ、保存0。
//   - 7段階wizard: 1 ログイン → 2 プラグイン追加と接続許可の確認（手動1回。linked/subscribed＋access allowedで3へ。プラグイン追加・OAuth接続の
//     展開ガイドと、helperの検証済みMCP originから作る登録先URLは表示だけで通信しない） → 3 テスト用Dotsプロンプト（受信開始。コピー＋本人の
//     「貼り付けて次へ」） → 4 受信状態の確認（手動1回。subscribed＋allowedだけが5を開く。linkedは4に留めて受信開始を案内） → 5 固定文の送信テスト
//     （編集欄なし。本文は辞書の固定文。単回POST・同ID・取消。本人の「Dotsで本文一致を確認して次へ」） → 6 運用用Dotsプロンプト（コピー＋「貼り付けて
//     完了」でセットアップ完了） → 7 自由送信（通常利用。5とは別の送信状態で、7の結果はセットアップ完了の条件にしない）。初期は1だけ有効。完了済みの前step
//     は薄く表示して再選択でき、再表示だけでは証跡を消さない。再ログイン開始時は2以降、接続許可を確認できない時は3以降、受信中を確認できない時と
//     テスト設定の再適用は4以降を戻す（7も封鎖）。未解放のstepはクリックしても進めず通信しない。古いasync結果（世代が違うログイン/確認）で後続を解放しない。
//     完了後は7で通常送信を繰り返せる。
//   - HTTP受領（delivered）だけでwizardを進めない。5の完了は利用者がDotsで一致を確認した明示操作。不明（delivery_unknown/結果不明）はAPI結果を
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
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { FIREBASE_POPUP_SCRIPT_ORIGIN, FIREBASE_WEB_SDK_VERSION, type FirebaseWebConfig } from './pages.js';

export const CONSOLE_PATH = '/console';
export const CONSOLE_SCRIPT_PATH = '/console/app.js';
export const CONSOLE_STYLE_PATH = '/console/app.css';
/** 既存のinteraction画面と同じ公式CDNの固定版（明示ログイン時にimport()する）。 */
export const CONSOLE_SDK_BASE = `https://www.gstatic.com/firebasejs/${FIREBASE_WEB_SDK_VERSION}/`;
/** helperへの中継要求に必須のlocal nonce header（起動ごとの乱数。Cloudへは転送しない）。 */
export const LOCAL_NONCE_HEADER = 'X-Sttd-Local-Nonce';
/** 手順2のプラグイン追加ガイドから開く公式手順（利用者が明示的に開く普通のリンク。preview・自動遷移なし）。 */
export const PLUGIN_GUIDE_LINKS = Object.freeze({
  connect: 'https://developers.openai.com/plugins/deploy/connect-chatgpt',
  customMcp: 'https://developers.openai.com/api/docs/guides/custom-mcp-server',
});
/**
 * helperが上流を呼ぶ前に自分で拒否した応答にだけ付ける固定header（値は`1`）。helperは上流応答のこの名前のheaderを転送しないので、
 * 画面はこれがある時だけ「未送信（helperの拒否）」と扱う（上流の同名codeでは未送信にしない）。
 */
export const LOCAL_REFUSAL_HEADER = 'X-Sttd-Local-Refusal';

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
  /**
   * helperの検証済み設定のMCP origin（`https://<host>`）。手順2のガイドに登録先`<mcpOrigin>/mcp`として表示する。
   * 未指定ならURLを推定・表示せず、配置のMCP originへ/mcpを付ける案内だけを出す。形が違えばConsoleConfigError。
   */
  readonly mcpOrigin?: string | undefined;
  /** ステップ1の方式選択（Apple/コード）部品のHTML（console/operator-config.tsのrenderOperatorSectionが作るescape済みの値）。 */
  readonly operatorSection?: string | undefined;
  /**
   * operator modeで方式選択が有効な時だけtrue。方式選択をステップ1の先頭に置き、Appleの案内・ログイン操作は選んだ方式に応じて
   * 部品のscriptが表示を切り替える。通常の配信modeでは従来どおりApple操作の後に「設定されていません」だけを置く。
   */
  readonly operatorFirst?: boolean | undefined;
  /** operator modeのコード操作（6桁・残り時間・案内・再発行・接続確認・取消・結果）。手順2の追加方法の後に置く（escape済みの値）。 */
  readonly operatorCodePanel?: string | undefined;
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

/** /consoleのHTML（7段階wizard、1画面）。値はdata属性へescapeして渡す。文言は選択言語の辞書から入れ、scriptが同じキーで差し替える。 */
export function renderConsolePage(web: FirebaseWebConfig, options: ConsolePageOptions): string {
  checkWeb(web);
  const nonce = checkLocalNonce(options?.nonce);
  const mcpOrigin = options.mcpOrigin;
  // 配置設定・helperと同じ既存の判定（http/origin.ts）だけを使い、別の規則を持たない。
  if (mcpOrigin !== undefined && !isDevelopmentPublicOrigin(mcpOrigin)) throw new ConsoleConfigError();
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
<p id="sttd-wizard-note" role="status"></p>
<section id="sttd-panel-1" class="sttd-panel" aria-labelledby="sttd-panel-1-title" data-sttd-state="current" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-1-title" class="sttd-panel-title"${i18n('wizard.step1')}>${t('wizard.step1')}</h2><span id="sttd-skipped-1" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-1" class="sttd-skip" disabled${i18n('wizard.skipResume')}>${t('wizard.skipResume')}</button></div>
${options.operatorFirst === true ? (options.operatorSection ?? '') : ''}
<div id="sttd-apple-panel"${options.operatorFirst === true ? ' hidden' : ''}>
<p id="sttd-login-intro"${i18n('wizard.loginIntro')}>${t('wizard.loginIntro')}</p>
<p id="sttd-account-text" role="status">${t('console.accountSignedOut')}</p>
<div class="sttd-actions">
<button type="button" id="sttd-login"${i18n('common.appleLogin')}>${t('common.appleLogin')}</button>
<button type="button" id="sttd-switch" hidden${i18n('common.switchAccount')}>${t('common.switchAccount')}</button>
</div>
</div>
${options.operatorFirst === true ? '' : (options.operatorSection ?? '')}
</section>
<section id="sttd-panel-2" class="sttd-panel" aria-labelledby="sttd-panel-2-title" data-sttd-state="locked" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-2-title" class="sttd-panel-title"${i18n('wizard.step2')}>${t('wizard.step2')}</h2><span id="sttd-skipped-2" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-2" class="sttd-skip" disabled${i18n('wizard.skip')}>${t('wizard.skip')}</button></div>
<p id="sttd-state-intro"${i18n('wizard.stateIntro')}>${t('wizard.stateIntro')}</p>
<p id="sttd-plugin-intro"${i18n('plugin.intro')}>${t('plugin.intro')}</p>
<details id="sttd-plugin-guide" class="sttd-instructions-details">
<summary id="sttd-plugin-summary"${i18n('plugin.title')}>${t('plugin.title')}</summary>
${
  mcpOrigin === undefined
    ? `<p id="sttd-plugin-url-missing"${i18n('plugin.urlMissing')}>${t('plugin.urlMissing')}</p>`
    : `<p id="sttd-plugin-url-label"${i18n('plugin.urlLabel')}>${t('plugin.urlLabel')}</p>
<p><code id="sttd-plugin-url" class="sttd-plugin-url">${escapeHtml(`${mcpOrigin}/mcp`)}</code></p>`
}
<p id="sttd-plugin-url-note"${i18n('plugin.urlNote')}>${t('plugin.urlNote')}</p>
<ol id="sttd-plugin-steps">
<li id="sttd-plugin-step-1"${i18n('plugin.step1')}>${t('plugin.step1')}</li>
<li id="sttd-plugin-step-2"${i18n('plugin.step2')}>${t('plugin.step2')}</li>
<li id="sttd-plugin-step-3"${i18n('plugin.step3')}>${t('plugin.step3')}</li>
<li id="sttd-plugin-step-4"${i18n('plugin.step4')}>${t('plugin.step4')}</li>
<li id="sttd-plugin-step-5"${i18n('plugin.step5')}>${t('plugin.step5')}</li>
</ol>
<p id="sttd-plugin-labels"${i18n('plugin.labels')}>${t('plugin.labels')}</p>
<ul>
<li><a id="sttd-plugin-doc-connect" href="${PLUGIN_GUIDE_LINKS.connect}" target="_blank" rel="noopener noreferrer"${i18n('plugin.docConnect')}>${t('plugin.docConnect')}</a></li>
<li><a id="sttd-plugin-doc-custom" href="${PLUGIN_GUIDE_LINKS.customMcp}" target="_blank" rel="noopener noreferrer"${i18n('plugin.docCustom')}>${t('plugin.docCustom')}</a></li>
</ul>
</details>
${options.operatorCodePanel ?? ''}
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
<div class="sttd-panel-head"><h2 id="sttd-panel-3-title" class="sttd-panel-title"${i18n('wizard.step3')}>${t('wizard.step3')}</h2><span id="sttd-skipped-3" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-3" class="sttd-skip" disabled${i18n('wizard.skip')}>${t('wizard.skip')}</button></div>
<p id="sttd-guide-intro"${i18n('guide.intro')}>${t('guide.intro')}</p>
<p id="sttd-guide-step1"${i18n('guide.step1')}>${t('guide.step1')}</p>
<p id="sttd-receive-start"${i18n('wizard.receiveStart')}>${t('wizard.receiveStart')}</p>
${instructions('test', 'guide.showTest', 'guide.testText', 'guide.copyTest', 'wizard.pastedTestNext')}
</section>
<section id="sttd-panel-4" class="sttd-panel" aria-labelledby="sttd-panel-4-title" data-sttd-state="locked" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-4-title" class="sttd-panel-title"${i18n('wizard.step4')}>${t('wizard.step4')}</h2><span id="sttd-required-4" class="sttd-required"${i18n('wizard.required')}>${t('wizard.required')}</span></div>
<p id="sttd-receive-intro"${i18n('wizard.receiveIntro')}>${t('wizard.receiveIntro')}</p>
<div class="sttd-actions">
<button type="button" id="sttd-receive-check" disabled${i18n('wizard.receiveCheck')}>${t('wizard.receiveCheck')}</button>
</div>
<p id="sttd-receive-text" role="status"></p>
</section>
<section id="sttd-panel-5" class="sttd-panel" aria-labelledby="sttd-panel-5-title" data-sttd-state="locked" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-5-title" class="sttd-panel-title"${i18n('wizard.step5')}>${t('wizard.step5')}</h2><span id="sttd-skipped-5" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-5" class="sttd-skip" disabled${i18n('wizard.skip')}>${t('wizard.skip')}</button></div>
<p id="sttd-send-intro"${i18n('wizard.sendIntro')}>${t('wizard.sendIntro')}</p>
<p id="sttd-fixed-label"${i18n('wizard.fixedLabel')}>${t('wizard.fixedLabel')}</p>
<p id="sttd-fixed-text" class="sttd-fixed"${i18n('wizard.fixedText')}>${t('wizard.fixedText')}</p>
<div class="sttd-actions">
<button type="button" id="sttd-test-send" disabled${i18n('wizard.sendFixed')}>${t('wizard.sendFixed')}</button>
<button type="button" id="sttd-test-cancel" hidden${i18n('console.cancel')}>${t('console.cancel')}</button>
<button type="button" id="sttd-test-check" hidden${i18n('console.check')}>${t('console.check')}</button>
<button type="button" id="sttd-test-new" hidden${i18n('wizard.sendFixedAgain')}>${t('wizard.sendFixedAgain')}</button>
</div>
<p id="sttd-test-result" role="status"></p>
<p id="sttd-note" class="sttd-note"${i18n('console.note')}>${t('console.note')}</p>
<button type="button" id="sttd-verify-send" disabled${i18n('wizard.sendVerified')}>${t('wizard.sendVerified')}</button>
<p id="sttd-verify-hint" class="sttd-note"${i18n('wizard.sendNotVerifiable')}>${t('wizard.sendNotVerifiable')}</p>
</section>
<section id="sttd-panel-6" class="sttd-panel" aria-labelledby="sttd-panel-6-title" data-sttd-state="locked" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-6-title" class="sttd-panel-title"${i18n('wizard.step6')}>${t('wizard.step6')}</h2><span id="sttd-skipped-6" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-6" class="sttd-skip" disabled${i18n('wizard.skip')}>${t('wizard.skip')}</button></div>
<p id="sttd-guide-step3"${i18n('guide.step3')}>${t('guide.step3')}</p>
${instructions('operation', 'guide.showOperation', 'guide.operationText', 'guide.copyOperation', 'wizard.pastedOperationFinish')}
</section>
<section id="sttd-panel-7" class="sttd-panel" aria-labelledby="sttd-panel-7-title" data-sttd-state="locked" tabindex="0">
<div class="sttd-panel-head"><h2 id="sttd-panel-7-title" class="sttd-panel-title"${i18n('wizard.step7')}>${t('wizard.step7')}</h2><span id="sttd-skipped-7" class="sttd-skipped-label" hidden${i18n('wizard.skippedLabel')}>${t('wizard.skippedLabel')}</span><button type="button" id="sttd-skip-7" class="sttd-skip" disabled${i18n('wizard.skip')}>${t('wizard.skip')}</button></div>
<p id="sttd-free-intro"${i18n('wizard.freeIntro')}>${t('wizard.freeIntro')}</p>
<label id="sttd-text-label" for="sttd-text"${i18n('console.textLabel')}>${t('console.textLabel')}</label>
<textarea id="sttd-text" rows="4" maxlength="4096" placeholder="${t('console.textPlaceholder')}" disabled></textarea>
<div class="sttd-actions">
<button type="button" id="sttd-send" disabled${i18n('console.sendOne')}>${t('console.sendOne')}</button>
<button type="button" id="sttd-cancel" hidden${i18n('console.cancel')}>${t('console.cancel')}</button>
<button type="button" id="sttd-check" hidden${i18n('console.check')}>${t('console.check')}</button>
<button type="button" id="sttd-new" hidden${i18n('console.new')}>${t('console.new')}</button>
</div>
<p id="sttd-result" role="status"></p>
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
.sttd-badge { font-size: 0.8rem; color: #4a5059; min-width: 3.5rem; }
.sttd-panel-title { font-size: 1.05rem; margin: 0 0 0.5rem; }
.sttd-panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
.sttd-skip { font-size: 0.85rem; color: #4a4a4a; background: #f0f0f0; border: 1px solid #8a8a8a; border-radius: 4px; padding: 0.15rem 0.5rem; }
.sttd-required { font-size: 0.85rem; color: #4a4a4a; }
.sttd-skipped-label { font-size: 0.85rem; font-weight: 600; color: #6b3a00; background: #fff4e0; border: 1px dashed #6b3a00; border-radius: 4px; padding: 0.1rem 0.4rem; }
.sttd-panel[data-sttd-state="skipped"] { border: 1px dashed #6b3a00; }
.sttd-instruction-block { margin-top: 0.75rem; }
.sttd-instructions-details summary { cursor: pointer; font-weight: 600; min-height: 44px; display: flex; align-items: center; }
.sttd-instructions { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; background: #f5f6f8; border: 1px solid #d9dce1; border-radius: 6px; padding: 0.75rem; margin: 0; }
.sttd-actions { display: flex; flex-wrap: wrap; }
.sttd-method-choice { border: 0; padding: 0; margin: 0 0 0.25rem; }
.sttd-method-choice legend { font-weight: 600; padding: 0; margin-bottom: 0.25rem; }
.sttd-radio { display: flex; align-items: center; gap: 0.5rem; min-height: 44px; cursor: pointer; }
.sttd-radio input { width: 1.1rem; height: 1.1rem; margin: 0; }
.sttd-plugin-url { overflow-wrap: anywhere; background: #f5f6f8; border: 1px solid #d9dce1; border-radius: 4px; padding: 0.1rem 0.3rem; }
#sttd-result, #sttd-disconnect-result, #sttd-wizard-note { font-weight: 600; min-height: 1.5em; overflow-wrap: anywhere; }
.sttd-note { font-size: 0.85rem; color: #4a5059; }
.sttd-panel[data-sttd-state="locked"] { opacity: 0.55; background: #eceef1; }
.sttd-panel[data-sttd-state="done"], .sttd-panel[data-sttd-state="skipped"], .sttd-panel[data-sttd-state="ready"] { opacity: 0.8; background: #f5f6f8; cursor: pointer; }
.sttd-panel[data-sttd-state="current"] { border: 2px solid #1f5fbf; }
.sttd-panel[aria-disabled="true"] button, .sttd-panel[aria-disabled="true"] textarea, .sttd-panel[aria-disabled="true"] details, .sttd-panel[aria-disabled="true"] summary, .sttd-panel[aria-disabled="true"] pre, .sttd-panel[aria-disabled="true"] a { pointer-events: none; }
.sttd-complete { font-weight: 700; border: 2px solid #1f5fbf; border-radius: 8px; padding: 0.75rem; }
.sttd-fixed { font-weight: 600; border: 1px solid #888; border-radius: 6px; padding: 0.5rem 0.75rem; white-space: pre-wrap; }
[hidden] { display: none !important; }
`;

/**
 * 画面のscript（固定asset）。7段階wizardの状態・単回送信・中止・同ID確認・確認後の解除・固定プロンプトのコピー・言語切替。
 * Firebase SDKは手順1の明示操作でだけimport()する。文言は埋め込んだ固定辞書（connect/i18n.ts）からキーで引く。
 */
export const CONSOLE_SCRIPT = `const body = document.body;
const SDK_BASE = '${CONSOLE_SDK_BASE}';
const FIREBASE = JSON.parse(body.dataset.sttdFirebase);
const NONCE = body.dataset.sttdLocalNonce;
const NONCE_HEADER = '${LOCAL_NONCE_HEADER}';
const LOCAL_REFUSAL_HEADER = '${LOCAL_REFUSAL_HEADER}';
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
const ACCESS_STATES = ['allowed', 'denied', 'unavailable'];
const ERROR_STATUSES = [400, 401, 403, 409, 422, 429];
const TERMINAL = ['delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown'];
const RANK = { in_flight: 1, delivery_unknown: 2, failed: 3, expired: 3, cancelled: 3, delivered: 4 };
const STEPS = [1, 2, 3, 4, 5, 6, 7];
// 送信の2系統: test=手順5の固定文（本文一致の証跡）、free=手順7の自由送信（通常利用。セットアップ完了の条件にしない）。
const LANE_STEP = { test: 5, free: 7 };
// 右上の補助操作で省略できる手順（4は必須の受信確認なので省略できない）。1の省略は保存済みログインの明示復元。
const SKIPPABLE = [1, 2, 3, 5, 6, 7];
// 保存済みコードログインの判定（サーバーの識別検証と同じ形: 専用UID・marker・family）。UIDの接頭辞だけでは信用しない。
const CODE_UID = /^sttdc_[A-Za-z0-9_-]{32}$/;
const CODE_FAMILY = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
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
// 利用許可（接続確認の応答のaccess。allowed/denied/unavailable、欠落は旧サービスのoutdated）。allowedの時だけ新しい送信を解放する。
let access = null;
let connectionKey = '';
let guideKey = '';
let checking = false;
// 実行中の確認の手順（2=接続許可の確認、4=受信状態の確認。どちらも同じ接続APIへの明示1回GET）。
let checkFrom = 2;
// 手順4の受信状態の確認結果（RAMだけ）。
let receiveKey = '';
let step = 1;
const done = { 1: false, 2: false, 3: false, 4: false, 5: false, 6: false, 7: false };
// 省略した手順（doneとは別。未確認を完了・本文一致・貼付済みに見せない）。
const skipped = { 1: false, 2: false, 3: false, 4: false, 5: false, 6: false, 7: false };
let noteKey = '';
let test = null;
let sendNote = '';
// 手順7の自由送信（testとは別の状態。7の失敗で5の証跡を消さない）。
let free = null;
let freeNote = '';
// 結果が確定していない送信をreset（再ログイン・認証喪失・状態の再確認・テスト指示の再適用）で画面から消した時の重複注意（RAMだけ）。
// 次の送信を始めるまで表示し、resetの一般noteで上書きしない。
let duplicateWarning = false;
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

/** 結果が確定していない（届いた可能性がある）送信か。送信中・結果不明・処理中・不明・中止未確認・確認中を保守的に含める。 */
function uncertain(current) {
  const phase = phaseOf(current);
  return (
    phase === 'sending' ||
    phase === 'unknown' ||
    current.state === 'in_flight' ||
    current.state === 'delivery_unknown' ||
    current.cancel === 'pending' ||
    current.checking ||
    (current.cancel === 'unconfirmed' && current.state !== 'cancelled')
  );
}

/** 認証処理・接続確認・解除の処理中。 */
function busy() {
  return accountBusy || checking;
}

/** 送信中（1件の終端まで）か。 */
function sending() {
  return [test, free].some((current) => current !== null && phaseOf(current) === 'sending');
}

/** 送信・中止・結果確認のいずれかが進行中か（この間はtestを壊す操作を拒否する）。 */
function inFlight() {
  return laneBusy(test) || laneBusy(free);
}

function laneBusy(current) {
  return current !== null && (phaseOf(current) === 'sending' || current.cancel === 'pending' || current.checking);
}

/** stepの操作（ボタン）を受けるか: 解放済みで、かつ現在activeなpanelであること（非activeのgray panel内のcontrolは誤操作防止で動かさない）。 */
function canAct(n) {
  return available(n) && step === n;
}

/** stepが使えるか（DOMの見た目に頼らず、各handlerもこれで検査する）。確認中は3以降を一時封鎖。 */
function available(n) {
  if (n === 1) return true;
  if (n === 2) return passed(1) || (method === 'code' && codeIssued);
  if (checking) return false;
  // 手順5以降は、必須の手順4（同じownerでsubscribed＋allowedの明示確認）が済んでいる時だけ。2/3の省略では迂回できない
  if (n >= 5 && !done[4]) return false;
  return passed(n - 1);
}

/** 手順nを完了または省略したか（手順4は省略できない）。 */
function passed(n) {
  return done[n] || (n !== 4 && skipped[n]);
}

/** 手順nより後ろに戻すべき進捗があるか（reset時の注意に使う）。 */
function doneAfter(n) {
  return STEPS.some((k) => k > n && (done[k] || skipped[k]));
}

function sendableNow(n = 5) {
  return available(n) && signedIn && connection === 'subscribed' && access === 'allowed' && !busy();
}

function languageLocked() {
  return accountBusy || copying || inFlight();
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
  for (const k of STEPS) {
    if (k < n) continue;
    done[k] = false;
    skipped[k] = false;
  }
  if (n <= 2) {
    connection = null;
    access = null;
    connectionKey = '';
    guideKey = '';
    confirming = false;
    disconnectKey = '';
  }
  if (n <= 3) {
    copied.test = false;
    manual.test = false;
  }
  if (n <= 4) receiveKey = '';
  if (n <= 5) {
    // 未確定の送信を消す時は重複注意を残す（同IDの自動照会・取消・再送はしない）。
    if (test !== null && uncertain(test)) duplicateWarning = true;
    test = null;
    sendNote = '';
  }
  if (n <= 6) {
    copied.operation = false;
    manual.operation = false;
  }
  if (n <= 7) {
    if (free !== null && uncertain(free)) duplicateWarning = true;
    free = null;
    freeNote = '';
    el('sttd-text').value = '';
  }
  if (copyFor !== '' && ((n <= 3 && copyFor === 'test') || (n <= 6 && copyFor === 'operation'))) {
    copyKey = '';
    copyFor = '';
  }
  if (step > n) step = n;
}

function render() {
  for (const n of STEPS) {
    const state = step === n ? 'current' : done[n] ? 'done' : skipped[n] ? 'skipped' : available(n) ? 'ready' : 'locked';
    // 全panelを順に表示し、非active/未解放はgray。panel自身（done/ready）はクリック/keyboardで再活性化できる。
    const panel = el('sttd-panel-' + n);
    panel.setAttribute('data-sttd-state', state);
    panel.setAttribute('aria-disabled', state === 'current' ? 'false' : 'true');
  }
  el('sttd-wizard-note').textContent = [T(noteKey), duplicateWarning ? T('console.duplicateWarning') : ''].filter((line) => line !== '').join(' ');
  // 非activeのpanel内controlは誤操作防止で全て無効（handlerもcanActで拒否する）。
  const inactive = (n) => step !== n;
  // 1 ログイン
  el('sttd-account-text').textContent = T(accountKey);
  el('sttd-login').hidden = signedIn;
  el('sttd-login').disabled = inactive(1) || busy() || inFlight();
  el('sttd-switch').hidden = !signedIn;
  el('sttd-switch').disabled = inactive(1) || busy() || inFlight() || confirming;
  // 2 接続確認
  el('sttd-state-text').textContent = checking && checkFrom === 2 ? T('wizard.checking') : connection === null ? T(connectionKey) : T(connection === 'subscribed' ? 'console.state.subscribed' : 'common.state.' + connection);
  el('sttd-state-guide').textContent = checking && checkFrom === 2 ? '' : T(guideKey);
  el('sttd-refresh').disabled = inactive(2) || !available(2) || busy() || inFlight() || confirming;
  // コード方式で未認証の間は、コードの接続確認だけ（通常の接続確認は認証後に出す）。追加方法の認証説明も選んだ方式に合わせる
  el('sttd-refresh').hidden = method === 'code' && !signedIn;
  el('sttd-plugin-step-3').textContent = T(method === 'code' ? 'plugin.step3Code' : 'plugin.step3');
  el('sttd-disconnect').hidden = !signedIn || confirming || connection === null || connection === 'unlinked';
  el('sttd-disconnect').disabled = inactive(2) || busy() || inFlight();
  el('sttd-disconnect-confirm').hidden = !confirming;
  el('sttd-disconnect-yes').disabled = inactive(2) || busy();
  el('sttd-disconnect-no').disabled = inactive(2) || busy();
  el('sttd-disconnect-result').textContent = T(disconnectKey);
  // 3/6 プロンプト
  for (const kind of ['test', 'operation']) {
    const n = kind === 'test' ? 3 : 6;
    el('sttd-copy-' + kind).disabled = inactive(n) || copying || !available(n);
    el('sttd-manual-' + kind).hidden = !(copyFor === kind && (copyKey === 'guide.copyUnavailable' || copyKey === 'guide.copyFailed')) || manual[kind];
    el('sttd-manual-' + kind).disabled = inactive(n) || copying || !available(n);
    el('sttd-copy-result-' + kind).textContent = copyFor === kind ? T(copyKey) : '';
    el('sttd-done-' + kind).disabled = inactive(n) || copying || !available(n) || !(copied[kind] || manual[kind]) || (kind === 'test' && inFlight());
  }
  // 完了banner（panel7の外、画面下）: 手順6までを完了または省略（必須の4は確認済み）で表示し、手順7の送信結果には依存しない。
  // 省略した手順があれば「未確認の手順があります」の文面にして、全確認済みと区別する。
  el('sttd-complete').hidden = !(done[4] && passed(6));
  el('sttd-complete').textContent = T(unconfirmed() ? 'wizard.completeSkipped' : 'wizard.complete');
  for (const n of SKIPPABLE) {
    el('sttd-skip-' + n).disabled = !skippable(n);
    // 省略は見出しの横に文字で示す（確認済みになったら消す）。色だけ・bannerだけに頼らない
    el('sttd-skipped-' + n).hidden = !(skipped[n] && !done[n]);
  }
  // 4 受信状態の確認（明示1回GET。自動の再確認はしない）
  el('sttd-receive-check').disabled = inactive(4) || !available(4) || !signedIn || busy() || inFlight() || confirming;
  el('sttd-receive-text').textContent = checking && checkFrom === 4 ? T('wizard.receiveChecking') : T(receiveKey);
  // 5 固定文の送信（編集欄なし）・7 自由送信。どちらも同じ単回POST・中止・同ID確認の部品
  renderLane('test', { send: 'sttd-test-send', cancel: 'sttd-test-cancel', check: 'sttd-test-check', again: 'sttd-test-new', result: 'sttd-test-result' }, inactive);
  renderLane('free', { send: 'sttd-send', cancel: 'sttd-cancel', check: 'sttd-check', again: 'sttd-new', result: 'sttd-result' }, inactive);
  el('sttd-text').disabled = !sendableNow(7) || inactive(7) || free !== null;
  el('sttd-verify-send').disabled = inactive(5) || !available(5) || busy() || !verifiable();
  for (const code of ['en', 'ja']) {
    const link = el('sttd-lang-' + code);
    link.setAttribute('aria-current', code === lang ? 'true' : 'false');
    link.setAttribute('aria-disabled', languageLocked() ? 'true' : 'false');
  }
}

/** 送信系統（test=手順5、free=手順7）の表示。系統ごとに別の状態を持ち、操作は各系統の手順がactiveな時だけ。 */
function renderLane(lane, ids, inactive) {
  const n = LANE_STEP[lane];
  const current = laneOf(lane);
  const phase = current === null ? null : phaseOf(current);
  const sendable = sendableNow(n) && !inactive(n);
  el(ids.send).disabled = !sendable || current !== null;
  el(ids.cancel).hidden = current === null || (phase !== 'sending' && phase !== 'unknown') || current.cancel === 'answered' || current.cancel === 'unconfirmed';
  el(ids.cancel).disabled = inactive(n) || (current !== null && current.cancel === 'pending');
  el(ids.check).hidden = current === null || !checkable(current);
  el(ids.check).disabled = inactive(n) || (current !== null && current.checking);
  el(ids.again).hidden = current === null || phase === 'sending' || current.cancel === 'pending' || current.checking;
  el(ids.again).disabled = inactive(n);
  const lines = [];
  if (current !== null) {
    if (current.state !== null) lines.push(T('console.state.' + current.state));
    else if (phase === 'sending') lines.push(T('console.sending'));
    else if (current.rejected !== null) lines.push(T(current.rejected));
    else lines.push(T('console.unknown'));
    if (current.cancel === 'pending') lines.push(T('console.cancelPending'));
    if (current.cancel === 'unconfirmed' && current.state !== 'cancelled') lines.push(T('console.cancelUnconfirmed'));
    if (current.checkNote) lines.push(T(current.checkNote));
  } else {
    const note = lane === 'test' ? sendNote : freeNote;
    if (note) lines.push(T(note));
    else if (duplicateWarning) lines.push(T('console.duplicateWarning'));
    if (signedIn && connection === 'subscribed' && access !== null && access !== 'allowed') lines.push(T('wizard.access.' + access));
  }
  el(ids.result).textContent = lines.join(' ');
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

// ---- 手順の省略（右上の補助操作）。skippedはdoneと別に持ち、正規controllerのgateだけで次へ進める ----

/** 省略した（未確認の）手順があるか。手順1の省略は保存済みログインの検証済み復元なので数えない。 */
function unconfirmed() {
  return [2, 3, 5, 6].some((k) => skipped[k] && !done[k]);
}

/** 手順nの省略を受けるか: activeで、処理中・送信中・解除確認中でないこと。7は結果が確定していない送信がある間は受けない。 */
function skippable(n) {
  if (!SKIPPABLE.includes(n) || !canAct(n) || busy() || inFlight() || confirming) return false;
  if (n === 7) return !skipped[7] && !(test !== null && uncertain(test)) && !(free !== null && uncertain(free));
  return true;
}

function skipStep(n) {
  if (!skippable(n)) return;
  if (n === 1) return resumeLogin();
  skipped[n] = true;
  if (n === 7) {
    // 何も送らず今回の案内を終える（同じ画面で7を選び直せば送れる）。
    noteKey = 'wizard.skip7Done';
    return render();
  }
  step = n + 1;
  render();
  reveal(n + 1);
}

/**
 * 手順1の省略＝保存済みログインの明示復元（通常のloginとは別経路。保存済みのコードログインをAppleへ切り替えない）。選んだ方式の
 * Firebase既存persistenceだけを使い、popup・signOut・コード発行はしない。ID tokenのclaims（project・tenant・provider・
 * コードのmarker/family/UID）がこの配置と方式に合う時だけ手順2へ進め、以降の確認は通常の手順2/4で行う。
 */
async function resumeLogin() {
  if (!canAct(1) || busy() || inFlight()) return;
  const want = method === 'code' ? 'code' : 'apple';
  const gen = ++loginGeneration;
  const chosen = method;
  const epoch = codeEpoch;
  const stale = () => gen !== loginGeneration || method !== chosen || epoch !== codeEpoch;
  const hadProgress = done[1] || skipped[1];
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  skipped[1] = false;
  ownerUid = null;
  step = 1;
  noteKey = hadProgress ? 'wizard.loginReset' : '';
  accountBusy = true;
  accountKey = sdk === null ? 'wizard.loginLoading' : 'console.accountChecking';
  render();
  let resumed = false;
  try {
    let s;
    try {
      s = await ensureSdk();
    } catch {
      if (!stale()) accountKey = 'wizard.loginLoadFailed';
      return;
    }
    if (stale()) return;
    await s.auth.authStateReady();
    if (stale()) return;
    const user = s.auth.currentUser;
    if (!user || typeof user.getIdTokenResult !== 'function') {
      accountKey = 'wizard.resumeNone';
      return;
    }
    let result;
    try {
      result = await user.getIdTokenResult(true);
    } catch {
      if (!stale()) accountKey = 'wizard.resumeFailed';
      return;
    }
    if (stale() || s.auth.currentUser !== user) return;
    if (!resumable(result, user.uid, want)) {
      accountKey = 'wizard.resumeMismatch';
      return;
    }
    ownerUid = user.uid;
    signedIn = true;
    skipped[1] = true;
    accountKey = 'wizard.resumeDone';
    step = 2;
    resumed = true;
    observeAuth(s);
  } catch {
    if (!stale()) accountKey = 'common.loginFailed';
  } finally {
    if (gen === loginGeneration) {
      accountBusy = false;
      render();
      codeState();
    }
  }
  if (resumed && gen === loginGeneration) reveal(2);
}

/** 復元したID tokenのclaimsが、この配置（project・tenantなし）と選んだ方式に合うか。サーバーの識別検証と同じ条件を見る。 */
function resumable(result, uid, want) {
  const c = result !== null && typeof result === 'object' ? result.claims : null;
  if (c === null || typeof c !== 'object') return false;
  const projectId = FIREBASE.projectId;
  if (typeof projectId !== 'string' || c.aud !== projectId || c.iss !== 'https://securetoken.google.com/' + projectId) return false;
  const fb = c.firebase;
  if (fb === null || typeof fb !== 'object' || fb.tenant !== undefined) return false;
  if (typeof uid !== 'string' || c.sub !== uid) return false;
  if (want === 'code') return fb.sign_in_provider === 'custom' && c.sttd_dlc === 1 && typeof c.sttd_fam === 'string' && CODE_FAMILY.test(c.sttd_fam) && CODE_UID.test(uid);
  return fb.sign_in_provider === 'apple.com' && !CODE_UID.test(uid);
}

/** 正の遷移先panelを表示する（scroll＋focus）。失敗・古い結果・再選択では呼ばない。 */
function reveal(n) {
  const panel = el('sttd-panel-' + n);
  if (panel && typeof panel.scrollIntoView === 'function') panel.scrollIntoView({ block: 'start' });
  if (panel && typeof panel.focus === 'function') panel.focus();
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

/**
 * ログイン中accountの変化（別owner・ログアウト）やログインを確認できない時（401・token取得不能）: 以降の要求を止め、2以降を戻して
 * ログインからやり直す。古いasync結果は世代で捨てる。note省略時はaccountの変化を断定しない再ログイン案内。
 */
function authLost(key, note) {
  loginGeneration += 1;
  checkGeneration += 1;
  checking = false;
  accountBusy = false;
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  skipped[1] = false;
  ownerUid = null;
  step = 1;
  accountKey = key || 'common.loginRefresh';
  noteKey = note || 'wizard.signInAgain';
  render();
}

/** 明示ログインの後だけ認証observerを1回登録する（owner変更/ログアウトを検知。ログイン前にはSDKも観測も始めない）。 */
function observeAuth(s) {
  if (authObserved || typeof s.auth.onAuthStateChanged !== 'function') return;
  authObserved = true;
  s.auth.onAuthStateChanged((user) => {
    if (!signedIn || ownerUid === null) return;
    if (!user || user.uid !== ownerUid) authLost('common.loginRefresh', 'wizard.authChanged');
  });
}

// ---- 1 ログイン（SDKはここで初めて読む） ----

function ensureSdk() {
  if (sdk !== null) return Promise.resolve(sdk);
  if (sdkLoading === null) {
    sdkLoading = loadSdkModules()
      .then(([app, authModule]) => {
        const auth = authModule.getAuth(app.initializeApp(FIREBASE));
        sdk = { auth, OAuthProvider: authModule.OAuthProvider, signInWithPopup: authModule.signInWithPopup, signOut: authModule.signOut, signInWithCustomToken: authModule.signInWithCustomToken };
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
  if (method === 'code') await chooseMethod('apple');
  const gen = ++loginGeneration;
  const hadProgress = done[1] || skipped[1];
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  skipped[1] = false;
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
    if (isCodeUser(s.auth.currentUser)) await s.signOut(s.auth);
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

/** helperが上流を呼ぶ前に拒否した応答か（helperだけが付ける固定headerで判定。codeやstatusだけでは判定しない）。 */
function localRefusal(response) {
  try {
    return response.headers !== null && typeof response.headers === 'object' && typeof response.headers.get === 'function' && response.headers.get(LOCAL_REFUSAL_HEADER) === '1';
  } catch {
    return false;
  }
}

/**
 * 同origin helperへの1要求（Bearer＋local nonce、credentials omit、redirectを辿らない）。元期限は認証取得・HTTP・JSON待ちを全て含む。
 * 期限内にtokenが無ければHTTPを始めずnot_sent。helperが上流の前に拒否した応答はlocal（未送信。古い画面なら再読込みの案内）。
 * HTTPを始めた後の失敗・timeoutはunknown。
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
    if (localRefusal(response)) return { kind: 'local', status: response.status };
    // 認証失効（401）: 古い進捗を残さずログインからやり直す（呼出し側の続きは世代/testの検査で止まる）。accountの変化とは断定しない。
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
  if (!signedIn) return;
  if (!available(2) || busy() || inFlight() || confirming) return;
  if (!internal && !canAct(2)) return;
  const json = await connectionGet(2);
  if (json === undefined) return;
  if (json === null) return render();
  let moveTo = 0;
  if ((json.state === 'linked' || json.state === 'subscribed') && access === 'allowed') {
    // 接続許可（linked）で手順3へ。受信の開始と確認は手順3/4で行う（ここではsubscribedを要求しない）。
    const first = !done[2];
    done[2] = true;
    noteKey = '';
    if (json.state === 'linked' && done[4]) receiveLost();
    // 明示の確認の成功は、既に完了済みでも手順3を表示する。
    if (first || !internal) moveTo = 3;
  } else if ((json.state === 'linked' || json.state === 'subscribed') && done[2]) {
    // 接続のまま利用許可だけが無い: 進捗（前の送信の確認・中止を含む）は残し、新しい送信だけを止める（sendableNowがallowedを要求）。
    if (json.state === 'linked' && done[4]) receiveLost();
  } else {
    connectionLost();
  }
  if (moveTo !== 0) step = moveTo;
  render();
  if (moveTo !== 0) reveal(moveTo);
}

/** 手順4: 受信状態の確認（明示1回GET）。subscribed＋allowedだけが手順5を開く。linkedは手順4に留めて受信開始を案内する。 */
async function checkReceiving() {
  if (!signedIn || !canAct(4) || busy() || inFlight() || confirming) return;
  const json = await connectionGet(4);
  if (json === undefined) return;
  if (json === null) {
    receiveKey = guideKey;
    if (done[4]) receiveLost();
    return render();
  }
  if (json.state === 'subscribed' && access === 'allowed') {
    done[4] = true;
    noteKey = '';
    receiveKey = 'wizard.receive.ok';
    step = 5;
    render();
    reveal(5);
    return;
  } else if (json.state === 'linked') {
    receiveKey = access === 'allowed' ? 'wizard.receive.linked' : 'wizard.access.' + access;
    if (done[4]) receiveLost();
  } else if (json.state === 'subscribed') {
    // 受信中でも利用許可が無ければ5へ進めない。既にある進捗は残し、新しい送信だけを止める。
    receiveKey = 'wizard.access.' + access;
  } else {
    connectionLost();
  }
  render();
}

/** 接続APIへの明示1回GET（手順2/4共通）。undefined=処理済み（古い結果・認証喪失）、null=状態不明（connection/guideを更新済み）、それ以外は既知のstateを持つ応答。 */
async function connectionGet(from) {
  const gen = ++checkGeneration;
  const login = loginGeneration;
  checking = true;
  checkFrom = from;
  render();
  const outcome = await request('/v1/web/connection', 'GET', CONNECTION_MS, {}, undefined);
  if (gen !== checkGeneration || login !== loginGeneration) return undefined;
  checking = false;
  if (outcome.kind === 'stale') {
    render();
    return undefined;
  }
  if (outcome.kind === 'not_sent' || (outcome.kind === 'response' && outcome.status === 401)) {
    // tokenを得られない（owner変更/失効/未ログイン）、または401（request()がauthLost済みが通常。念のため同じ処理）: ログインからやり直す。
    authLost('common.loginRefresh');
    return undefined;
  }
  const json = outcome.kind === 'response' ? outcome.json : null;
  if (outcome.kind !== 'local' && json && typeof json.state === 'string' && CONNECTION_STATES.includes(json.state)) {
    connection = json.state;
    // accessの欠落は利用許可に未対応の旧サービス（更新が必要）。未知の値は確認できないものとして扱う。どちらも新しい送信を解放しない。
    access = !Object.hasOwn(json, 'access') ? 'outdated' : ACCESS_STATES.includes(json.access) ? json.access : 'unavailable';
    guideKey = access === 'allowed' ? 'wizard.next.' + json.state : 'wizard.access.' + access;
    return json;
  }
  // helperが送信前に拒否（古い画面等）・不明な応答: 状態は不明のまま（成功として扱わない）。
  connection = null;
  if (outcome.kind === 'local') access = null;
  connectionKey = 'console.connectionUnavailable';
  guideKey = outcome.kind === 'local' ? 'console.localRefused' : 'wizard.next.unavailable';
  if (from === 2) connectionLost();
  return null;
}

/** 接続許可を確認できない: 手順3以降を戻し、手順2で確認し直す。 */
function connectionLost() {
  if (doneAfter(2)) noteKey = 'wizard.stateReset';
  resetFrom(3);
  done[2] = false;
  skipped[2] = false;
  step = 2;
}

/** 受信中を確認できない: 手順4以降を戻す（手順2/3の進捗は残す）。 */
function receiveLost() {
  const key = receiveKey;
  noteKey = 'wizard.receiveReset';
  resetFrom(4);
  receiveKey = key;
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
    if (doneAfter(2)) noteKey = 'wizard.stateReset';
    resetFrom(2);
    step = 2;
    disconnectKey = ok ? 'common.disconnectDone' : outcome.kind === 'local' ? 'console.localRefused' : 'common.disconnectFailed';
    connectionKey = '';
    guideKey = '';
    render();
    await checkConnection(true);
  })();
}

// ---- 3/5 固定プロンプトのコピーと完了操作 ----

function copyInstructions(kind) {
  const n = kind === 'test' ? 3 : 6;
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
  const n = kind === 'test' ? 3 : 6;
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
  reveal(4);
}

/** 5の完了操作: 本人がDotsで一致を確認した明示操作（受領/不明の終端だけ）。 */
function verifySend() {
  if (!canAct(5) || busy() || !verifiable()) return;
  done[5] = true;
  step = 6;
  render();
}

/** 6の完了操作。 */
function completeOperation() {
  if (copying || !canAct(6) || busy()) return;
  if (!(copied.operation || manual.operation)) {
    copyFor = 'operation';
    copyKey = 'wizard.copyRequired';
    return render();
  }
  done[6] = true;
  noteKey = '';
  step = 7;
  render();
  reveal(7);
}

// ---- 5（固定文）/7（自由入力）の送信・中止・同ID確認 ----

function laneOf(lane) {
  return lane === 'test' ? test : free;
}

function setLane(lane, current) {
  if (lane === 'test') test = current;
  else free = current;
}

function setLaneNote(lane, key) {
  if (lane === 'test') sendNote = key;
  else freeNote = key;
}

/** 送る本文: 手順5は表示中の固定文の正本（辞書）から作り、DOMの入力値を読まない。手順7は本人の入力欄。 */
function laneText(lane) {
  return lane === 'test' ? T('wizard.fixedText') : el('sttd-text').value;
}

function stateOf(current, outcome) {
  const json = outcome.kind === 'response' ? outcome.json : null;
  if (json && json.commandId === current.commandId && typeof json.state === 'string' && Object.hasOwn(RANK, json.state)) return json.state;
  return null;
}

function apply(current, state) {
  if (current.state !== null && RANK[current.state] >= RANK[state]) return;
  current.state = state;
}

async function send(lane) {
  const n = LANE_STEP[lane];
  if (!sendableNow(n) || !canAct(n) || laneOf(lane) !== null) return;
  const text = laneText(lane);
  if (typeof text !== 'string' || text.trim() === '' || LONE_SURROGATE.test(text) || new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    setLaneNote(lane, 'console.inputInvalid');
    return render();
  }
  const created = Date.now();
  const current = { commandId: crypto.randomUUID(), state: null, postDone: false, rejected: null, cancel: 'none', checking: false, checkNote: '' };
  setLane(lane, current);
  setLaneNote(lane, '');
  duplicateWarning = false;
  render();
  const payload = JSON.stringify({
    schemaVersion: 2,
    commandId: current.commandId,
    text,
    createdAt: new Date(created).toISOString(),
    expiresAt: new Date(created + LIFETIME_MS).toISOString(),
  });
  const outcome = await request('/v2/commands', 'POST', Math.min(POST_MS, created + LIFETIME_MS - Date.now()), { 'Content-Type': 'application/json', 'Idempotency-Key': current.commandId }, payload);
  if (laneOf(lane) !== current) return;
  current.postDone = true;
  const state = stateOf(current, outcome);
  if (state !== null) apply(current, state);
  else if (outcome.kind === 'not_sent') current.rejected = 'console.notSent';
  else if (outcome.kind === 'local') current.rejected = 'console.localRefused';
  else if (outcome.kind === 'response' && outcome.status === 403 && errorCode(outcome.json) === 'access_denied') {
    // 上流が利用許可の拒否を確定した: 手動の接続確認でallowedを得るまで新しい送信を封鎖する（照会・取消・解除は残す）。
    current.rejected = 'console.error.access_denied';
    access = 'denied';
    guideKey = 'wizard.access.denied';
  }
  else if (outcome.kind === 'response' && ERROR_STATUSES.includes(outcome.status)) current.rejected = 'console.error.' + outcome.status;
  render();
}

/** 上流の固定error codeだけを読む（無い・形違いは空）。 */
function errorCode(json) {
  return json !== null && typeof json === 'object' && json.error !== null && typeof json.error === 'object' && typeof json.error.code === 'string' ? json.error.code : '';
}

async function cancel(lane) {
  const current = laneOf(lane);
  if (!canAct(LANE_STEP[lane]) || current === null || current.cancel !== 'none' || phaseOf(current) === 'settled') return;
  current.cancel = 'pending';
  render();
  const outcome = await request('/v2/commands/' + current.commandId + '/cancel', 'POST', CANCEL_MS, {}, undefined);
  if (laneOf(lane) !== current) return;
  const state = stateOf(current, outcome);
  if (state !== null) {
    current.cancel = 'answered';
    apply(current, state);
  } else {
    current.cancel = 'unconfirmed';
    if (outcome.kind === 'local') current.checkNote = 'console.localRefused';
  }
  render();
}

async function check(lane) {
  const current = laneOf(lane);
  if (!canAct(LANE_STEP[lane]) || current === null || current.checking || !checkable(current)) return;
  current.checking = true;
  current.checkNote = '';
  render();
  const outcome = await request('/v2/commands/' + current.commandId, 'GET', CHECK_MS, {}, undefined);
  if (laneOf(lane) !== current) return;
  current.checking = false;
  const state = stateOf(current, outcome);
  if (state !== null) apply(current, state);
  else if (outcome.kind === 'local') current.checkNote = 'console.localRefused';
  else if (outcome.kind === 'response' && outcome.status === 404) current.checkNote = 'console.checkNotFound';
  else current.checkNote = 'console.checkFailed';
  render();
}

/** 系統の送信を画面から外して次の送信を可能にする（手順5は固定文の再送信、手順7は新しい本文）。未確定なら重複注意。 */
function newTest(lane) {
  const current = laneOf(lane);
  if (!canAct(LANE_STEP[lane]) || current === null || phaseOf(current) === 'sending' || current.cancel === 'pending' || current.checking) return;
  const warn = uncertain(current);
  setLane(lane, null);
  setLaneNote(lane, warn ? 'console.duplicateWarning' : '');
  render();
}

// ---- 開発者向けコード（operator modeの部品が明示callbackで呼ぶ。通常modeでは呼ばれない） ----

let method = null;
let codeEpoch = 0;
let codeIssued = false;
const codeListeners = [];

function isCodeUser(user) {
  return Boolean(user) && typeof user.uid === 'string' && user.uid.startsWith('sttdc_');
}

function codeState() {
  const state = Object.freeze({ method, epoch: codeEpoch, signedIn, step, codeIssued, resumed: skipped[1] });
  for (const listener of codeListeners) {
    try {
      listener(state);
    } catch {
      // 部品側の失敗で本体の状態を変えない。
    }
  }
}

/**
 * 方式の明示選択（apple / code）。変わったら手順1へ戻し、後続を封鎖し、旧owner・進行中のログイン/確認/コード結果を無効にする
 * （世代を進める）。以前の方式のSDK sessionは閉じる。プラグインの旧接続はここでは止めない（本人の削除・再導入の案内だけ）。
 */
async function chooseMethod(next) {
  if (next !== 'apple' && next !== 'code') return false;
  if (method === next) {
    codeState();
    return true;
  }
  // 送信中だけは切り替えない（ログイン・確認の途中は世代を進めて古い結果を捨てる）。
  if (inFlight()) return false;
  // 未選択（null）は既存のApple方式。Apple認証後の切替でも進捗ありとして再追加の案内を出す
  const hadProgress = done[1] || codeIssued || signedIn;
  method = next;
  codeEpoch += 1;
  codeIssued = false;
  loginGeneration += 1;
  checkGeneration += 1;
  checking = false;
  accountBusy = false;
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  skipped[1] = false;
  ownerUid = null;
  step = 1;
  accountKey = 'console.accountSignedOut';
  noteKey = hadProgress ? 'wizard.loginReset' : '';
  render();
  codeState();
  if (sdk !== null && sdk.auth.currentUser) {
    try {
      await sdk.signOut(sdk.auth);
    } catch {
      // 閉じられなくても、以降のログインはcode/Appleの区別で受理しない。
    }
  }
  return true;
}

/** コード発行の成功（この世代のコード方式だけ）。手順2（プラグイン追加）だけを開く。 */
function codeIssuedFor(epoch) {
  if (method !== 'code' || epoch !== codeEpoch) return false;
  codeIssued = true;
  // 発行に成功したこの世代だけ、手順2（プラグイン追加とコードの接続確認）へ進め、追加方法を開く
  if (step === 1) step = 2;
  const guide = el('sttd-plugin-guide');
  if (guide) guide.open = true;
  render();
  codeState();
  reveal(2);
  return true;
}

/**
 * コードの再発行/取消の成功（この世代のコード方式だけ）。旧コードとその接続はhelper側で終了済みなので、旧owner・後続の進捗（受信確認・送信を含む）を
 * 無効にして手順1へ戻す（再発行は続くissuedで手順2へ）。失敗時は呼ばれず、現在の接続を保持する。
 */
function codeEndedFor(epoch) {
  if (method !== 'code' || epoch !== codeEpoch) return false;
  const hadProgress = done[1] || signedIn;
  codeIssued = false;
  loginGeneration += 1;
  checkGeneration += 1;
  checking = false;
  accountBusy = false;
  confirming = false;
  resetFrom(2);
  signedIn = false;
  done[1] = false;
  skipped[1] = false;
  ownerUid = null;
  step = 1;
  accountKey = 'console.accountSignedOut';
  noteKey = hadProgress ? 'wizard.loginReset' : '';
  render();
  codeState();
  if (sdk !== null && sdk.auth.currentUser) Promise.resolve().then(() => sdk.signOut(sdk.auth)).catch(() => {});
  return true;
}

/** 接続確認で得たcustom tokenによるSDKログイン。世代・方式が変わった遅い結果は採らず、残ったcode sessionも閉じる。 */
async function codeSignIn(epoch, customToken) {
  if (method !== 'code' || epoch !== codeEpoch || typeof customToken !== 'string' || customToken === '') return false;
  if (accountBusy || busy() || inFlight()) return false;
  const gen = ++loginGeneration;
  const stale = () => gen !== loginGeneration || method !== 'code' || epoch !== codeEpoch;
  if (signedIn) {
    // 復元などで別のownerがログイン中: 新しいコードの交換で置き換えるので、旧ownerの後続を戻す（observerが旧ownerの喪失として扱わないよう先に外す）
    resetFrom(2);
    signedIn = false;
    ownerUid = null;
    done[1] = false;
    skipped[1] = false;
  }
  accountBusy = true;
  accountKey = sdk === null ? 'wizard.loginLoading' : 'console.accountChecking';
  render();
  try {
    let s;
    try {
      s = await ensureSdk();
    } catch {
      if (!stale()) accountKey = 'wizard.loginLoadFailed';
      return false;
    }
    if (stale()) return false;
    if (typeof s.signInWithCustomToken !== 'function') {
      accountKey = 'common.loginFailed';
      return false;
    }
    if (s.auth.currentUser) await s.signOut(s.auth);
    await s.signInWithCustomToken(s.auth, customToken);
    const user = s.auth.currentUser;
    if (stale()) {
      if (isCodeUser(user)) await s.signOut(s.auth);
      return false;
    }
    if (!isCodeUser(user)) {
      accountKey = 'common.loginFailed';
      return false;
    }
    await user.getIdToken();
    if (stale() || s.auth.currentUser !== user) return false;
    ownerUid = user.uid;
    signedIn = true;
    done[1] = true;
    // このページが発行したコードで認証した: 復元（省略）の扱いを外し、helperが所有するsessionとして扱う
    skipped[1] = false;
    codeIssued = true;
    accountKey = 'wizard.loginDone';
    step = 2;
    observeAuth(s);
    return true;
  } catch {
    if (!stale()) accountKey = 'common.loginFailed';
    return false;
  } finally {
    if (gen === loginGeneration) {
      accountBusy = false;
      render();
      codeState();
    }
  }
}

/** operator部品への明示の口（同じページのscriptだけが使う。秘密・tokenを保持しない）。 */
globalThis.sttdConsoleCode = Object.freeze({
  chooseMethod: (next) => chooseMethod(next),
  // 方式「Apple」で共通の「続ける」を押した時だけ、既存のAppleログインを始める（選択・初期表示では通信しない）。
  appleLogin: () => login(false),
  // 認証済み・発行済み等の進捗の有無（方式切替時の旧plugin再追加の案内に使う）
  progressed: () => done[1] || skipped[1] || codeIssued || signedIn,
  issued: (epoch) => codeIssuedFor(epoch),
  ended: (epoch) => codeEndedFor(epoch),
  signIn: (epoch, customToken) => codeSignIn(epoch, customToken),
  subscribe(listener) {
    if (typeof listener !== 'function') return;
    codeListeners.push(listener);
    listener(Object.freeze({ method, epoch: codeEpoch, signedIn, step, codeIssued, resumed: skipped[1] }));
  },
});

function start() {
  for (const n of STEPS) {
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
el('sttd-receive-check').onclick = () => checkReceiving();
  for (const n of SKIPPABLE) el('sttd-skip-' + n).onclick = () => skipStep(n);
  el('sttd-test-send').onclick = () => send('test');
  el('sttd-test-cancel').onclick = () => cancel('test');
  el('sttd-test-check').onclick = () => check('test');
  el('sttd-test-new').onclick = () => newTest('test');
  el('sttd-send').onclick = () => send('free');
  el('sttd-cancel').onclick = () => cancel('free');
  el('sttd-check').onclick = () => check('free');
  el('sttd-new').onclick = () => newTest('free');
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
