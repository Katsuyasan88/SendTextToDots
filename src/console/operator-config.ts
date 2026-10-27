// ローカル送信画面の明示operator mode（開発者向け6桁コードの発行）の設定・画面部品・ブラウザscript。I/O・管理SDK 0。
//   - 通常の配信mode（public client設定だけ）は変えない。operator modeは`node dist/console/operator-server.js`で明示的に起動した時だけ。
//   - 設定は固定の配置値（project/database/namespace、identifierKeyのSecret Manager版名、custom tokenの署名SA）だけで、秘密の値・管理鍵JSONを持たない。
//   - 画面: ステップ1の先頭で方式「Apple」「コード」を選ぶ（認証の実行ボタンと区別した選択肢。選択中はaria-pressed）。Apple選択時はAppleの案内・
//     ログインだけ、コード選択時はコード操作だけを表示する。選択だけでは発行しない。発行・接続確認・再発行・取消は本人の明示操作だけで、
//     自動pollしない（残り時間の表示更新は端末内だけ）。送信はFirebaseのログイン・利用許可・同意・購読の確認まで封鎖のまま。

import type { IncomingMessage, ServerResponse } from 'node:http';

import { DEFAULT_LANGUAGE, isLanguage, type Language } from '../connect/i18n.js';
import type { FirebaseWebConfig } from '../connect/pages.js';

export const OPERATOR_SCRIPT_PATH = '/console/operator.js';
export const OPERATOR_PATH_PREFIX = '/v1/operator/code/';
export const OPERATOR_ACTIONS = ['issue', 'reissue', 'status', 'cancel'] as const;
export type OperatorAction = (typeof OPERATOR_ACTIONS)[number];

const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const DATABASE_ID = /^(?:\(default\)|[a-z][a-z0-9-]{0,61}[a-z0-9])$/;
const NAMESPACE = /^t256_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** 配置設定のsecretVersions.identifierKeyと同じ形（project番号・固定の版番号。latestは不可）。 */
const SECRET_VERSION = /^projects\/[1-9][0-9]{0,19}\/secrets\/[A-Za-z0-9_-]{1,255}\/versions\/[1-9][0-9]{0,9}$/;
/** 配置設定のserviceAccountと同じ規則のSA名（小文字6〜30文字）。 */
const SA_LOCAL = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const CONFIG_KEYS = ['version', 'projectId', 'databaseId', 'namespace', 'identifierKeySecretVersion', 'signingServiceAccount'] as const;

/** 同projectの専用SA（`<name>@<projectId>.iam.gserviceaccount.com`）だけ。compute既定SA・他project・URLは形で拒否される。 */
function isProjectServiceAccount(value: string, projectId: string): boolean {
  const suffix = `@${projectId}.iam.gserviceaccount.com`;
  return value.endsWith(suffix) && SA_LOCAL.test(value.slice(0, -suffix.length));
}

export class OperatorConfigError extends Error {
  constructor() {
    super('operator config: invalid');
    this.name = 'OperatorConfigError';
  }
}

export interface OperatorConfig {
  readonly version: 1;
  readonly projectId: string;
  readonly databaseId: string;
  /** 接続保存のnamespace（`t256_<UUID>`）。 */
  readonly namespace: string;
  /**
   * 配置設定の`secretVersions.identifierKey`と同じSecret Manager版名。コードの予約HMAC・予定UID封緘の鍵はこの配置秘密からHKDFで
   * 用途分離して導く（接続server・送信APIと同じ）。値はhelperのRAMだけに読む。
   */
  readonly identifierKeySecretVersion: string;
  /**
   * custom tokenの署名先（Firebase Adminの`serviceAccountId`）。同projectの専用SA emailを配置者が明示する。ADC・metadata・UIDから推測しない
   * （通常のユーザーADCにはSA emailが無く、metadata serverへ進むと手元では署名先が決まらない）。helperの資格がこのSAへの
   * `iam.serviceAccounts.signBlob`を持つ必要がある。
   */
  readonly signingServiceAccount: string;
}

/** 正確なkey集合・形だけを受ける（未知key・欠落・placeholderは拒否）。 */
export function parseOperatorConfig(value: unknown): OperatorConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new OperatorConfigError();
  const keys = Object.keys(value);
  if (keys.length !== CONFIG_KEYS.length || !CONFIG_KEYS.every((key) => Object.hasOwn(value, key))) throw new OperatorConfigError();
  const v = value as Record<string, unknown>;
  if (v.version !== 1) throw new OperatorConfigError();
  if (typeof v.projectId !== 'string' || !PROJECT_ID.test(v.projectId)) throw new OperatorConfigError();
  if (typeof v.databaseId !== 'string' || !DATABASE_ID.test(v.databaseId)) throw new OperatorConfigError();
  if (typeof v.namespace !== 'string' || !NAMESPACE.test(v.namespace)) throw new OperatorConfigError();
  if (typeof v.identifierKeySecretVersion !== 'string' || !SECRET_VERSION.test(v.identifierKeySecretVersion)) throw new OperatorConfigError();
  if (typeof v.signingServiceAccount !== 'string' || !isProjectServiceAccount(v.signingServiceAccount, v.projectId)) throw new OperatorConfigError();
  return Object.freeze({
    version: 1,
    projectId: v.projectId,
    databaseId: v.databaseId,
    namespace: v.namespace,
    identifierKeySecretVersion: v.identifierKeySecretVersion,
    signingServiceAccount: v.signingServiceAccount,
  });
}

/** ローカルhelperがoperator modeの要求を渡す口（Hostはhelperが検査済み）。 */
export interface OperatorRoutes {
  handle(req: IncomingMessage, res: ServerResponse, context: { readonly path: string; readonly method: string; readonly nonce: string; readonly origin: string }): Promise<void>;
}

export const OPERATOR_TEXT = Object.freeze({
  en: Object.freeze({
    methodTitle: 'Choose how to sign in',
    methodApple: 'Sign in with Apple (recommended)',
    methodCode: 'Sign in with a code',
    continue: 'Continue',
    descApple: 'Continue opens the Apple sign-in window.',
    descCode: 'Continue generates a 6-digit code for the plugin connection screen.',
    notConfigured: 'Code issuance is not configured for this deployment.',
    codeGuide:
      'Enter the code in the plugin connection screen within 10 minutes. A code works once. After connecting, the number of texts you send is not limited.',
    issue: 'Generate a code',
    reissue: 'Generate a new code (ends the current code and its connection)',
    confirm: 'Check connection',
    cancel: 'Cancel this code',
    codeLabel: 'Your code',
    remaining: 'Time left',
    expired: 'This code has expired. Generate a new code.',
    pending: 'Not connected yet. Enter the code in the plugin connection screen, then check again.',
    ended: 'This code cannot be used to connect. Generate a new code in the console.',
    connected: 'Connected. Continue with step 2.',
    issueFailed: 'A code could not be issued. Wait and try again.',
    unchanged: 'Your current code and connection were not changed.',
    cancelled: 'The code was cancelled.',
    switchNotice: 'Remove the previous plugin and add it again from step 2. The previous connection will not carry over.',
    step2Unlocked: 'You can now add the plugin (step 2). Sending stays locked until the connection is confirmed.',
  }),
  ja: Object.freeze({
    methodTitle: 'ログイン方法を選ぶ',
    methodApple: 'Appleでログイン（推奨）',
    methodCode: 'コードでログイン',
    continue: '続ける',
    descApple: '「続ける」を押すとAppleのログイン画面を開きます。',
    descCode: '「続ける」を押すと、プラグインの接続画面に入力する6桁のコードを発行します。',
    notConfigured: 'この配置ではコード発行が設定されていません。',
    codeGuide: '10分以内にプラグインの接続画面へ入力してください。使用は1回です。接続後の送信回数は制限しません。',
    issue: 'コードを発行',
    reissue: '再発行（現在のコードと接続を終了して作り直します）',
    confirm: '接続を確認',
    cancel: 'このコードを取消',
    codeLabel: '発行したコード',
    remaining: '残り時間',
    expired: 'このコードは期限切れです。新しいコードを発行してください。',
    pending: 'まだ接続されていません。プラグインの接続画面でコードを入力してから、もう一度確認してください。',
    ended: 'このコードでは接続できません。コンソールで新しいコードを発行してください。',
    connected: '接続しました。ステップ2へ進んでください。',
    issueFailed: 'コードを発行できませんでした。しばらく待ってから再度お試しください。',
    unchanged: '現在のコードと接続は変わっていません。',
    cancelled: 'コードを取り消しました。',
    switchNotice: '以前のプラグインを削除し、ステップ2から追加し直してください。以前の接続は新しい接続へ引き継がれません。',
    step2Unlocked: 'プラグインの追加（ステップ2）へ進めます。接続を確認するまで送信はできません。',
  }),
});

export type OperatorTextKey = keyof (typeof OPERATOR_TEXT)['en'];

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

/**
 * ステップ1の方式選択とコード操作の部品（ローカル送信画面のpanel 1へ入れる）。operator modeでないときは「設定されていません」だけ。
 * 値はdata属性へescapeして渡す（nonce・公開Firebase設定だけ。秘密・コード・UIDは入れない）。
 */
export function renderOperatorSection(input: {
  readonly language?: Language | undefined;
  readonly enabled: boolean;
  readonly nonce: string;
  readonly web: FirebaseWebConfig;
}): string {
  const lang = isLanguage(input.language) ? input.language : DEFAULT_LANGUAGE;
  const t = (key: OperatorTextKey) => escapeHtml(OPERATOR_TEXT[lang][key]);
  if (!input.enabled) {
    return `<section id="sttd-method" aria-labelledby="sttd-method-title"><h3 id="sttd-method-title">${t('methodTitle')}</h3>
<p id="sttd-code-not-configured">${t('notConfigured')}</p></section>`;
  }
  const data = ` data-sttd-operator-nonce="${escapeHtml(input.nonce)}" data-sttd-operator-language="${lang}" data-sttd-operator-firebase="${escapeHtml(JSON.stringify(input.web))}"`;
  return `<section id="sttd-method"${data}>
<fieldset class="sttd-method-choice"><legend>${t('methodTitle')}</legend>
<label class="sttd-radio"><input type="radio" name="sttd-method" id="sttd-method-apple" value="apple" checked> ${t('methodApple')}</label>
<label class="sttd-radio"><input type="radio" name="sttd-method" id="sttd-method-code" value="code"> ${t('methodCode')}</label>
</fieldset>
<p id="sttd-method-desc-apple" class="sttd-note">${t('descApple')}</p>
<p id="sttd-method-desc-code" class="sttd-note" hidden>${t('descCode')}</p>
<div class="sttd-actions"><button type="button" id="sttd-method-continue">${t('continue')}</button></div>
<p id="sttd-method-message" role="status"></p>
<p id="sttd-switch-notice" hidden>${t('switchNotice')}</p>
</section>
<script type="module" src="${OPERATOR_SCRIPT_PATH}"></script>`;
}

/**
 * 手順2に置くコード操作（発行に成功したコード・残り時間・入力案内・再発行・コードの接続確認・取消・結果）。operator modeでないときは空。
 * 発行は手順1の方式「コード」＋「続ける」だけで始まり、成功した時だけ本体controllerが手順2へ進める。
 */
export function renderOperatorCodePanel(input: { readonly language?: Language | undefined; readonly enabled: boolean }): string {
  if (!input.enabled) return '';
  const lang = isLanguage(input.language) ? input.language : DEFAULT_LANGUAGE;
  const t = (key: OperatorTextKey) => escapeHtml(OPERATOR_TEXT[lang][key]);
  return `<div id="sttd-code-panel" hidden>
<p id="sttd-code-display" hidden>${t('codeLabel')}: <code id="sttd-code-value"></code> <span>${t('remaining')}: <span id="sttd-code-remaining"></span></span></p>
<p id="sttd-code-guide" hidden>${t('codeGuide')}</p>
<div class="sttd-actions"><button type="button" id="sttd-code-confirm" hidden>${t('confirm')}</button>
<button type="button" id="sttd-code-reissue" hidden>${t('reissue')}</button>
<button type="button" id="sttd-code-cancel" hidden>${t('cancel')}</button></div>
<p id="sttd-code-message" role="status"></p>
</div>`;
}

/**
 * operator部品のscript（同origin）。helperへnonce付き同originのPOSTだけを送り、送信画面の本体controllerとは明示callback
 * （globalThis.sttdConsoleCode: chooseMethod / issued / signIn / subscribe）で連携する。手順の解放・ログイン状態は本体が内部状態で決め、
 * この部品はDOMの見た目を変えて手順を開けない。方式・世代が変わった後に届いた発行/確認の結果は使わない。自動pollしない。
 * 発行コードは画面に表示するだけで保存・URL・記録へ入れない。custom tokenは表示・保存せず本体へ渡すだけ。
 */
export function operatorScript(nonceHeader: string): string {
  return `const root = document.getElementById('sttd-method');
const bridge = globalThis.sttdConsoleCode;
const TEXT = ${JSON.stringify(OPERATOR_TEXT)};
const lang = root && Object.hasOwn(TEXT, root.dataset.sttdOperatorLanguage) ? root.dataset.sttdOperatorLanguage : 'en';
const T = (key) => (Object.hasOwn(TEXT[lang], key) ? TEXT[lang][key] : '');
const el = (id) => document.getElementById(id);
let expiresAt = 0;
let timer = null;
let chosen = null;
let epoch = -1;
let issuedOnce = false;
let pending = false;

function say(text) { el('sttd-code-message').textContent = text; }
function show(id, visible) { const node = el(id); if (node) node.hidden = !visible; }
// 選んだ方式のradio・説明・操作だけを表示する（未選択は既存のApple方式）。operator modeでは下のApple操作を出さず、共通の「続ける」1つで始める。
let selected = 'apple';
let last = null;
function reflect(m) {
  selected = m === 'code' ? 'code' : 'apple';
  el('sttd-method-apple').checked = selected === 'apple';
  el('sttd-method-code').checked = selected === 'code';
  show('sttd-apple-panel', false);
  show('sttd-method-desc-apple', selected === 'apple');
  show('sttd-method-desc-code', selected === 'code');
  show('sttd-code-panel', selected === 'code');
}
// 認証済み・発行済み等の進捗がある時だけ、方式切替で旧pluginの削除/再追加を案内する（初期・空の切替では出さない）。
function hasProgress() { return (typeof bridge.progressed === 'function' && bridge.progressed() === true) || issuedOnce || (last !== null && (last.signedIn || last.codeIssued)); }
// 発行の失敗は手順1（続ける の近く）にも出す。コードの結果・接続確認は手順2のコード操作に出す
function sayIssue(text) { el('sttd-method-message').textContent = text; say(text); }
function current(at) { return chosen === 'code' && at === epoch; }

async function call(action) {
  const response = await fetch('${OPERATOR_PATH_PREFIX}' + action, {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', '${nonceHeader}': root.dataset.sttdOperatorNonce },
    body: '{}',
  });
  let parsed = null;
  try { parsed = await response.json(); } catch { parsed = null; }
  return { status: response.status, body: parsed !== null && typeof parsed === 'object' ? parsed : {} };
}

function stopTimer() {
  if (timer !== null) { clearInterval(timer); timer = null; }
}

// 10分以内・1回使用の案内は発行に成功したコードがある間だけ（取消・期限切れ・方式切替・接続完了で隠す。発行中/失敗では出さない）
function hideCode() {
  stopTimer();
  show('sttd-code-display', false);
  show('sttd-code-guide', false);
}

function controls() {
  // コードで認証済みになった後は、二重になるコードの接続確認だけを隠す（通常の接続確認を使う）。再発行/取消は手順2に残す
  // 保存済みログインの復元（手順1の省略）はhelperがコードsessionを所有しないので、再発行/取消を出さない（このページで発行した時だけ出す）
  const signed = chosen === 'code' && last !== null && last.signedIn === true && last.resumed !== true;
  show('sttd-code-reissue', issuedOnce || signed);
  show('sttd-code-confirm', issuedOnce && !signed);
  show('sttd-code-cancel', issuedOnce || signed);
}

function tick() {
  const left = Math.max(0, expiresAt - Date.now());
  const s = Math.ceil(left / 1000);
  el('sttd-code-remaining').textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  if (left === 0) { hideCode(); say(T('expired')); }
}

function showCode(code, authExpiresAt, at) {
  el('sttd-code-value').textContent = code;
  expiresAt = authExpiresAt;
  issuedOnce = true;
  controls();
  show('sttd-code-display', true);
  show('sttd-code-guide', true);
  el('sttd-method-message').textContent = '';
  stopTimer();
  timer = setInterval(tick, 1000);
  tick();
  // 手順2の解放は本体の内部状態で（この世代のコード方式だけ）。送信はログイン・許可・同意・購読の確認まで本体が封鎖する。
  if (bridge.issued(at)) say(T('step2Unlocked'));
}

// このページ（helperのRAM）が所有するコードsessionがあるか。保存済みログインの復元だけでは所有しない（再発行・照会・取消の要求0）
function owned() {
  return issuedOnce || (chosen === 'code' && last !== null && last.signedIn === true && last.resumed !== true);
}

async function issue(action) {
  if (pending || chosen !== 'code') return;
  // 新しい発行は明示の「続ける」で可。再発行は所有するsessionがある時だけ
  if (action !== 'issue' && !owned()) return;
  const at = epoch;
  pending = true;
  try {
    const { status, body } = await call(action);
    if (!current(at)) return;
    if (status === 200 && typeof body.code === 'string' && /^[0-9]{6}$/.test(body.code) && Number.isSafeInteger(body.authExpiresAt)) {
      // 再発行の成功は旧コードの接続を終えている: 本体の旧owner・後続・送信を無効にしてから新しいコードを出す
      if (action === 'reissue' && typeof bridge.ended === 'function') bridge.ended(at);
      return showCode(body.code, body.authExpiresAt, at);
    }
    if (status === 409 && body.error && body.error.code === 'use_reissue') {
      issuedOnce = true;
      controls();
    }
    sayIssue(T('issueFailed') + ' ' + T('unchanged'));
  } catch {
    if (current(at)) sayIssue(T('issueFailed') + ' ' + T('unchanged'));
  } finally {
    pending = false;
  }
}

async function confirmConnection() {
  if (pending || chosen !== 'code' || !issuedOnce) return;
  const at = epoch;
  pending = true;
  try {
    const { status, body } = await call('status');
    if (!current(at)) return;
    if (status === 200 && body.state === 'active' && typeof body.customToken === 'string') {
      const ok = await bridge.signIn(at, body.customToken);
      if (!current(at)) return;
      if (ok) hideCode();
      say(T(ok ? 'connected' : 'ended'));
      return;
    }
    say(T(status === 200 && body.state === 'pending' ? 'pending' : 'ended'));
  } catch {
    if (current(at)) say(T('ended'));
  } finally {
    pending = false;
  }
}

async function cancelCode() {
  if (pending || !owned()) return;
  pending = true;
  try {
    const { status } = await call('cancel');
    if (status === 200) {
      // 取消の成功は旧コードの接続を終えている: 本体の旧owner・後続・送信を無効にする（失敗時は現在の接続を保持）
      if (typeof bridge.ended === 'function') bridge.ended(epoch);
      hideCode();
      issuedOnce = false;
      controls();
      say(T('cancelled'));
    } else say(T('ended'));
  } catch {
    say(T('ended'));
  } finally {
    pending = false;
  }
}

async function choose(next) {
  // 方式の切替は本体がステップ1へ戻し後続を封鎖する。旧接続の停止は本人のプラグイン削除・再導入で、ここでは停止済みと表示しない。
  const before = chosen ?? 'apple';
  const progressed = hasProgress();
  if (!(await bridge.chooseMethod(next))) { reflect(chosen); return false; }
  if (before !== next) {
    show('sttd-switch-notice', progressed);
    hideCode();
    issuedOnce = false;
    say('');
    el('sttd-method-message').textContent = '';
  }
  reflect(next);
  if (next === 'code') controls();
  return true;
}

// 共通の「続ける」: Appleなら既存のAppleログイン、コードならコードの発行（以後の確認・再発行・取消はコード操作）。
async function proceed() {
  const m = selected;
  if (!(await choose(m))) return;
  if (m === 'apple') await bridge.appleLogin();
  else if (!issuedOnce) await issue('issue');
}

if (root && bridge) {
  bridge.subscribe((state) => {
    if (state.epoch !== epoch && chosen === 'code') hideCode();
    epoch = state.epoch;
    chosen = state.method;
    last = state;
    if (chosen !== null) reflect(chosen);
    if (chosen === 'code') controls();
  });
  reflect(chosen);
  // radioの選択（click/keyboard）は表示と方式の切替だけで、認証・発行・通信はしない
  el('sttd-method-apple').onclick = () => choose('apple');
  el('sttd-method-code').onclick = () => choose('code');
  el('sttd-method-continue').onclick = () => proceed();
  el('sttd-code-reissue').onclick = () => issue('reissue');
  el('sttd-code-confirm').onclick = () => confirmConnection();
  el('sttd-code-cancel').onclick = () => cancelCode();
}
`;
}
