// ローカル送信画面の実CONSOLE_SCRIPTを合成DOM/SDK/fetch/clipboardで実行し、6段階wizardの意味のある挙動を確かめる（browser・network・実SDK・実Dots 0）。
//   - W1 初期表示: 通信0・SDK読込0、手順1だけ有効、未解放stepのクリック/handlerは何もしない。言語切替・固定文面コピーも上流0。
//   - W2 ログイン: 明示操作でだけSDK読込/popup、成功で2が有効。読込失敗/popup拒否/失敗は1のまま。古い世代の結果は後続を解放しない。再ログインで2以降を戻す。
//   - W3 接続許可の確認: 手動1回のGET、linked/subscribed＋allowedで3へ、それ以外は英日の次の案内で3以降を戻す。確認中は3以降を封鎖。進捗保持。token失敗/401は1へ。
//   - W4 テスト用プロンプト: コピー（または手動確認）＋「貼り付けて次へ」で4（受信状態の確認）を解放。再適用は4〜6を戻す。前stepの再表示は証跡を消さない。
//   - W5 送信: 空/placeholder、「送信」、5項目のPOST（nonce/Bearer）、二重クリック1件、通信前拒否、deliveredだけでは進まず本人の一致確認で6へ。失敗/中止/未送信は確認不可、不明は確認可。
//   - W6 運用用プロンプト: コピー＋「貼り付けて完了」で完了文面。完了後に5へ戻って通常送信。
//   - W16 受信状態の確認: 明示1回GET、subscribed＋allowedだけが5を開く。linked・不明・権限なし・古い結果は通さない。受信の喪失は4以降を戻す。
//   - W7 解除: 確認→1回POST→2以降を戻して再確認。
import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { consoleAsset, LOCAL_NONCE_HEADER, LOCAL_REFUSAL_HEADER, PLUGIN_GUIDE_LINKS } from '../dist/connect/console.js';
import { MESSAGES } from '../dist/connect/i18n.js';
import { loadDeploymentConfig } from '../dist/config/validate.js';
import { gate, runConsole, settle, syntheticSdk } from './fixtures/console-browser.mjs';

const DEPLOYMENT = loadDeploymentConfig();
const WEB = { apiKey: 'synthetic-web-api-key', authDomain: DEPLOYMENT.web.authDomain, projectId: DEPLOYMENT.web.projectId };
const NONCE = 'a'.repeat(64);
const JA = (key) => MESSAGES.ja[key];
const EN = (key) => MESSAGES.en[key];
const FIELDS = ['schemaVersion', 'commandId', 'text', 'createdAt', 'expiresAt'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const results = {};
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
after(() => {
  const timers = process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
  process.stdout.write(`# CONSOLE_WIZARD_COUNTS ${JSON.stringify({ unhandled, timers, results })}\n`);
  assert.deepEqual([unhandled, timers], [0, 0]);
});

const html = (language) => consoleAsset('/console', WEB, { language, nonce: NONCE, secure: false }).body;

/** 合成helper: 接続状態と配送結果を返す。holdでPOSTを保留できる。 */
function helper(initialState = 'subscribed') {
  // accessは接続確認の応答の利用許可（undefinedは旧サービス＝fieldなし）。localは次の要求1件をhelperの送出前拒否にする。
  const state = { connection: initialState, access: 'allowed', mode: 'deliver', holds: [], disconnects: 0, local: null, upstream: 0 };
  const onFetch = async (entry) => {
    assert.equal(entry.headers[LOCAL_NONCE_HEADER], NONCE, 'every relayed request carries the local nonce');
    assert.match(entry.headers.Authorization ?? '', /^Bearer synthetic-id-token$/, 'every relayed request carries the Bearer token');
    assert.deepEqual([entry.credentials, entry.redirect, entry.cache], ['omit', 'error', 'no-store']);
    if (state.local !== null) {
      const { status, code } = state.local;
      state.local = null;
      return { status, json: { error: { code, retryable: false } }, headers: { [LOCAL_REFUSAL_HEADER.toLowerCase()]: '1' } };
    }
    state.upstream += 1;
    if (entry.url === '/v1/web/connection') {
      if (state.mode === 'webFail') return { status: 503, json: { error: { code: 'temporarily_unavailable', retryable: true } } };
      if (state.mode === 'web401') return { status: 401, json: { error: { code: 'authentication_required', retryable: false } } };
      return { status: 200, json: { state: state.connection, ...(state.access === undefined ? {} : { access: state.access }) } };
    }
    if (entry.url === '/v1/web/disconnect') {
      state.disconnects += 1;
      state.connection = 'unlinked';
      return { status: 200, json: { state: 'unlinked' } };
    }
    if (state.mode === 'hold') {
      const hold = gate();
      state.holds.push({ entry, hold });
      return hold.promise;
    }
    if (state.mode === 'fail') throw new TypeError('synthetic network failure');
    if (state.mode === 'reject') return { status: 409, json: { error: { code: 'subscription_required', retryable: false } } };
    if (state.mode === 'accessDenied') return { status: 403, json: { error: { code: 'access_denied', retryable: false } } };
    // 上流が同名のcode・headerを返しても、helperはheaderを転送しない（ここでは上流の応答としてheaderなしで返す）。
    if (state.mode === 'spoof') return { status: 403, json: { error: { code: 'local_reload_required', retryable: false } } };
    if (state.mode === 'unknown') return { status: 502, json: { error: { code: 'upstream_unavailable', retryable: true } } };
    const commandId = entry.method === 'POST' && entry.url === '/v2/commands' ? JSON.parse(entry.body).commandId : entry.url.split('/')[3];
    return { status: 200, json: { commandId, state: entry.url.endsWith('/cancel') ? 'cancelled' : 'delivered' } };
  };
  return { state, onFetch };
}

function clipboardStub() {
  const clipboard = { writes: [], mode: 'ok' };
  const navigator = {
    clipboard: {
      writeText: (value) => {
        clipboard.writes.push(value);
        return clipboard.mode === 'ok' ? Promise.resolve() : Promise.reject(new Error('synthetic NotAllowedError'));
      },
    },
  };
  return { clipboard, navigator };
}

/** 手順1→2→3を済ませる（subscribed）。 */
async function reachStep3(ui, sdk) {
  assert.equal(ui.el('sttd-login').click(), true);
  await settle();
  assert.equal(ui.stepState(2), 'current');
  assert.equal(ui.el('sttd-refresh').click(), true);
  await settle();
  assert.equal(ui.stepState(3), 'current');
}

/** 手順4の受信状態の確認（明示1回GET、subscribed＋allowed）で5へ。 */
async function receive(ui) {
  assert.equal(ui.el('sttd-receive-check').click(), true);
  await settle();
  assert.equal(ui.stepState(5), 'current');
}

test('W1 initial page: nothing is fetched and the SDK is not loaded; only step 1 is usable; locked steps ignore clicks and handlers; language switch and copies stay local', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk({ restoredUser: true });
  const { clipboard, navigator } = clipboardStub();
  const { onFetch } = helper();
  const ui = await runConsole({ html: html('ja'), onFetch, sdk, navigator });
  const { el } = ui;
  assert.deepEqual([ui.fetches.length, sdk.calls.loads, sdk.calls.popups, sdk.calls.tokens], [0, 0, 0, 0], 'no upstream and no SDK on load, even with a restored session');
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui.stepState), ['current', 'locked', 'locked', 'locked', 'locked', 'locked']);
  // 全panelは隠さず順に表示し、非active/未解放はgray（data-sttd-state・aria-disabled）。未解放panelはクリック/keyboard/handlerでも開かず通信しない。
  for (const n of [1, 2, 3, 4, 5, 6]) assert.equal(el('sttd-panel-' + n).hidden, false, `panel ${n} visible`);
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui.panelState), ['current', 'locked', 'locked', 'locked', 'locked', 'locked']);
  assert.equal(el('sttd-panel-1').getAttribute('aria-disabled'), 'false');
  for (const n of [2, 3, 4, 5, 6]) {
    assert.equal(el('sttd-panel-' + n).getAttribute('aria-disabled'), 'true');
    ui.clickPanel(n);
    ui.keyPanel(n, 'Enter');
    assert.equal(ui.panelState(n), 'locked', `step ${n} does not activate through any handler`);
  }
  // 非activeのpanel内controlは無効。
  for (const id of ['sttd-refresh', 'sttd-copy-test', 'sttd-done-test', 'sttd-receive-check', 'sttd-send', 'sttd-verify-send', 'sttd-copy-operation', 'sttd-done-operation']) assert.equal(el(id).disabled, true, `${id} inert`);
  // 未解放のhandlerを直接呼んでも通信しない。
  el('sttd-refresh').onclick();
  el('sttd-send').onclick();
  el('sttd-copy-test').onclick();
  el('sttd-done-test').onclick();
  el('sttd-receive-check').onclick();
  el('sttd-verify-send').onclick();
  el('sttd-copy-operation').onclick();
  el('sttd-done-operation').onclick();
  await settle();
  assert.deepEqual([ui.fetches.length, sdk.calls.loads, clipboard.writes.length], [0, 0, 0]);
  assert.equal(el('sttd-text').value, '', 'empty input');
  assert.equal(el('sttd-text').placeholder, JA('console.textPlaceholder'));
  assert.equal(el('sttd-send').textContent, '送信');
  assert.equal(el('sttd-text').disabled, true);
  // 言語切替はlocal（cookie同期書込みだけ）。
  assert.equal(el('sttd-lang-en').click(), true);
  await settle();
  assert.equal(ui.document.documentElement.lang, 'en');
  assert.equal(el('sttd-send').textContent, 'Send');
  assert.deepEqual(ui.cookies.writes, ['sttd_language=en; Path=/; SameSite=Lax'], 'http localhost: no Secure attribute');
  assert.deepEqual([ui.fetches.length, sdk.calls.loads], [0, 0]);
  results.W1 = { fetches: ui.fetches.length, sdkLoads: sdk.calls.loads };
});

test('W2 sign-in: the explicit button loads the SDK once and opens the popup; a restored session continues without a popup; load failure / blocked popup / failure keep step 1; a stale generation never unlocks; signing in again resets steps 2 to 6', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk });
  const { el } = ui;
  // 読込失敗 → 1のまま。
  sdk.calls.loadMode = 'fail';
  assert.equal(el('sttd-login').click(), true);
  await settle();
  assert.deepEqual([sdk.calls.loads, sdk.calls.popups, ui.stepState(2)], [1, 0, 'locked']);
  assert.equal(el('sttd-account-text').textContent, EN('wizard.loginLoadFailed'));
  // popup拒否 → 再クリック案内、1のまま。
  sdk.calls.loadMode = 'ok';
  sdk.calls.popupMode = 'blocked';
  el('sttd-login').click();
  await settle();
  assert.deepEqual([sdk.calls.loads, sdk.calls.popups, ui.stepState(2)], [2, 1, 'locked']);
  assert.equal(el('sttd-account-text').textContent, EN('wizard.loginPopupBlocked'));
  // 失敗 → 1のまま。
  sdk.calls.popupMode = 'fail';
  el('sttd-login').click();
  await settle();
  assert.deepEqual([sdk.calls.loads, sdk.calls.popups, ui.stepState(2)], [2, 2, 'locked'], 'the SDK is loaded once; later attempts reuse it');
  assert.equal(el('sttd-account-text').textContent, EN('common.loginFailed'));
  // 成功 → 2がcurrent、1はdone。上流への通信は無い。
  sdk.calls.popupMode = 'ok';
  el('sttd-login').click();
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.stepState(3)], ['done', 'current', 'locked']);
  assert.deepEqual(sdk.calls.providers, ['apple.com', 'apple.com', 'apple.com']);
  assert.equal(ui.fetches.length, 0, 'signing in talks to Firebase only, not to the service');
  assert.equal(el('sttd-login').hidden, true);
  assert.equal(el('sttd-switch').hidden, false);
  // 進めてから別accountでやり直す → 2以降を戻し、古い世代の結果では解放しない。
  el('sttd-refresh').click();
  await settle();
  assert.equal(ui.stepState(3), 'current');
  sdk.calls.popupMode = 'fail';
  assert.equal(el('sttd-switch').disabled, true, 'inactive step 1 controls are inert until the panel is re-activated');
  assert.equal(ui.clickPanel(1), true);
  assert.equal(el('sttd-switch').click(), true);
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.stepState(3)], ['current', 'locked', 'locked'], 'retrying resets steps 2+');
  assert.equal(el('sttd-wizard-note').textContent, EN('wizard.loginReset'));
  assert.equal(sdk.calls.signOuts, 1);
  // 復元済みsessionがある別のpage: クリック後にpopupなしで続行。
  const sdk2 = syntheticSdk({ restoredUser: true });
  const ui2 = await runConsole({ html: html('en'), onFetch, sdk: sdk2 });
  assert.equal(ui2.el('sttd-login').click(), true);
  await settle();
  assert.deepEqual([sdk2.calls.loads, sdk2.calls.popups, ui2.stepState(2)], [1, 0, 'current'], 'restored session: no popup, but only after the explicit click');
  results.W2 = { loads: sdk.calls.loads, popups: sdk.calls.popups };
});

test('W3 connection check: one manual GET; linked or subscribed with access allowed advances to step 3; each other state shows its next action and resets steps 3+; the check locks steps 3+ meanwhile; a repeated check keeps progress; a token failure or 401 returns to step 1', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { state, onFetch } = helper('unlinked');
  const ui = await runConsole({ html: html('ja'), onFetch, sdk });
  const { el } = ui;
  el('sttd-login').click();
  await settle();
  assert.equal(ui.web('/v1/web/connection').length, 0, 'no automatic check after sign-in');
  for (const [connection, key] of [['unlinked', 'wizard.next.unlinked'], ['expired', 'wizard.next.expired'], ['change_pending', 'wizard.next.change_pending']]) {
    state.connection = connection;
    assert.equal(el('sttd-refresh').click(), true);
    await settle();
    assert.equal(el('sttd-state-guide').textContent, JA(key), connection);
    assert.deepEqual([ui.stepState(2), ui.stepState(3)], ['current', 'locked'], connection);
  }
  assert.equal(ui.web('/v1/web/connection').length, 3, 'one GET per click, no polling');
  // 正の遷移（2→3、3→4、4→5）だけが表示先panelをscroll/focusする。失敗・留まる結果では動かない。
  const moves = [];
  for (const n of [2, 3, 4, 5]) {
    el('sttd-panel-' + n).scrollIntoView = () => moves.push('scroll' + n);
    el('sttd-panel-' + n).focus = () => moves.push('focus' + n);
  }
  // 接続許可（linked）で3へ。受信の開始は3、受信の確認は4で行う。
  state.connection = 'linked';
  el('sttd-refresh').click();
  await settle();
  assert.deepEqual([ui.stepState(2), ui.stepState(3), ui.stepState(4)], ['done', 'current', 'locked']);
  assert.equal(el('sttd-state-guide').textContent, JA('wizard.next.linked'));
  // clipboardの無いpage: 手動確認で3を完了できる。
  el('sttd-copy-test').click();
  await settle();
  assert.equal(el('sttd-manual-test').hidden, false, 'no clipboard API: manual confirmation offered');
  el('sttd-manual-test').click();
  el('sttd-done-test').click();
  await settle();
  assert.deepEqual([ui.stepState(3), ui.stepState(4), ui.stepState(5)], ['done', 'current', 'locked']);
  // 4: linkedのままでは5を開かず受信開始を案内する。subscribed＋allowedで5へ。
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['current', 'locked', JA('wizard.receive.linked')]);
  state.connection = 'subscribed';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['done', 'current', JA('wizard.receive.ok')]);
  assert.equal(ui.web('/v1/web/connection').length, 6, 'one GET per explicit click');
  assert.deepEqual(moves, ['scroll3', 'focus3', 'scroll4', 'focus4', 'scroll5', 'focus5'], 'linked in step 4 does not move');
  // 手順2の明示確認の成功は、既に完了済みでも手順3を表示する。失敗では動かない。
  assert.equal(ui.clickPanel(2), true);
  el('sttd-refresh').click();
  await settle();
  assert.deepEqual([ui.stepState(3), moves.slice(6)], ['current', ['scroll3', 'focus3']]);
  assert.equal(ui.clickPanel(2), true);
  state.mode = 'webFail';
  el('sttd-refresh').click();
  await settle();
  state.mode = 'deliver';
  assert.deepEqual([ui.stepState(2), moves.length], ['current', 8], 'a failed check does not move');
  // 3を済ませてから再確認（subscribed継続）: 進捗保持。確認中は3以降を封鎖。保留中のGETを合成するため接続応答を遅らせる。
  const held = gate();
  const normal = onFetch;
  let holdNext = true;
  const original = state.connection;
  state.connection = 'subscribed';
  const slowOnFetch = async (entry) => {
    if (holdNext && entry.url === '/v1/web/connection') {
      holdNext = false;
      await held.promise;
    }
    return normal(entry);
  };
  // 新しいpageで保留動作を観測する（fetch関数の差し替え）。
  const sdkB = syntheticSdk();
  const uiB = await runConsole({ html: html('ja'), onFetch: slowOnFetch, sdk: sdkB });
  uiB.el('sttd-login').click();
  await settle();
  holdNext = false;
  uiB.el('sttd-refresh').click();
  await settle();
  assert.equal(uiB.stepState(3), 'current');
  uiB.el('sttd-copy-test').click();
  uiB.el('sttd-manual-test').click();
  uiB.el('sttd-done-test').click();
  await settle();
  assert.equal(uiB.stepState(4), 'current');
  holdNext = true;
  assert.equal(uiB.keyPanel(2, 'Enter'), true, 'a done panel can be re-activated from the keyboard');
  assert.deepEqual([uiB.panelState(2), uiB.stepState(3)], ['current', 'done'], 're-selecting does not erase the evidence');
  assert.equal(uiB.el('sttd-receive-check').disabled, true, 'controls of the now-inactive step 4 are inert');
  uiB.el('sttd-refresh').click();
  await settle();
  assert.equal(uiB.el('sttd-state-text').textContent, JA('wizard.checking'));
  uiB.clickPanel(3);
  uiB.clickPanel(4);
  assert.deepEqual([uiB.panelState(3) === 'current', uiB.panelState(4) === 'current'], [false, false], 'steps 3+ cannot be opened while checking');
  held.release();
  await settle();
  assert.deepEqual([uiB.stepState(2), uiB.stepState(3), uiB.stepState(4)], ['done', 'current', 'ready'], 'subscribed again: progress kept and the explicit success shows step 3');
  // 非subscribedへ変化 → 3以降を戻し案内。
  state.connection = 'expired';
  uiB.clickPanel(2);
  uiB.el('sttd-refresh').click();
  await settle();
  assert.deepEqual([uiB.stepState(3), uiB.stepState(4)], ['locked', 'locked']);
  assert.equal(uiB.el('sttd-wizard-note').textContent, JA('wizard.stateReset'));
  // 確認失敗（503）も3以降を戻す。
  state.connection = 'subscribed';
  uiB.el('sttd-refresh').click();
  await settle();
  assert.equal(uiB.stepState(3), 'current');
  state.mode = 'webFail';
  uiB.clickPanel(2);
  uiB.el('sttd-refresh').click();
  await settle();
  assert.equal(uiB.el('sttd-state-guide').textContent, JA('wizard.next.unavailable'));
  assert.equal(uiB.stepState(3), 'locked');
  // 401 → 1へ。
  state.mode = 'web401';
  uiB.el('sttd-refresh').click();
  await settle();
  assert.deepEqual([uiB.stepState(1), uiB.stepState(2)], ['current', 'locked']);
  assert.equal(uiB.el('sttd-account-text').textContent, JA('common.loginRefresh'));
  // token取得失敗 → 1へ（HTTPは出ない）。
  state.mode = 'deliver';
  sdkB.calls.popupMode = 'ok';
  uiB.el('sttd-login').click();
  await settle();
  const before = uiB.web('/v1/web/connection').length;
  sdkB.calls.tokenMode = 'fail';
  uiB.el('sttd-refresh').click();
  await settle();
  assert.equal(uiB.web('/v1/web/connection').length, before, 'no request without a token');
  assert.equal(uiB.stepState(1), 'current');
  state.connection = original;
  results.W3 = { checks: ui.web('/v1/web/connection').length + uiB.web('/v1/web/connection').length };
});

test('W4 test instructions: copying (or a manual confirmation) plus "pasted, next" unlocks step 4 (receiving check, never skipped); copy failure shows the manual fallback; a re-applied test resets steps 4 to 6 but viewing a done step does not', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  assert.equal(el('sttd-done-test').disabled, true, 'next requires a copy first');
  el('sttd-done-test').onclick();
  assert.equal(el('sttd-copy-result-test').textContent, EN('wizard.copyRequired'));
  assert.equal(ui.stepState(4), 'locked');
  // 失敗 → 手動確認で進める。
  clipboard.mode = 'reject';
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(el('sttd-copy-result-test').textContent, EN('guide.copyFailed'));
  assert.equal(el('sttd-manual-test').hidden, false);
  assert.equal(el('sttd-done-test').disabled, true);
  clipboard.mode = 'ok';
  el('sttd-copy-test').click();
  await settle();
  assert.deepEqual(clipboard.writes, [EN('guide.testText'), EN('guide.testText')]);
  assert.equal(el('sttd-copy-result-test').textContent, EN('guide.copied'));
  assert.equal(el('sttd-done-test').disabled, false);
  assert.equal(el('sttd-done-test').click(), true);
  await settle();
  assert.deepEqual([ui.stepState(3), ui.stepState(4), ui.stepState(5)], ['done', 'current', 'locked']);
  assert.equal(ui.fetches.filter((entry) => entry.url !== '/v1/web/connection').length, 0, 'copying and confirming send nothing');
  assert.equal(ui.web('/v1/web/connection').length, 1, 'no automatic receiving check: subscribed already, but step 4 is not skipped');
  // 4で受信を確認、5で送信して確認、6まで。
  await receive(ui);
  el('sttd-text').value = 'hello';
  el('sttd-send').click();
  await settle();
  el('sttd-verify-send').click();
  await settle();
  assert.deepEqual([ui.stepState(5), ui.stepState(6)], ['done', 'current']);
  // 3を見直すだけでは何も消えない（panel内クリックで再活性化）。
  assert.equal(ui.clickPanel(3), true);
  assert.deepEqual([3, 4, 5, 6].map(ui.stepState), ['current', 'done', 'done', 'ready']);
  // 再適用（コピー＋次へ）→ 4〜6を戻す（受信状態も確認し直す）。
  el('sttd-copy-test').click();
  await settle();
  el('sttd-done-test').click();
  await settle();
  assert.deepEqual([3, 4, 5, 6].map(ui.stepState), ['done', 'current', 'locked', 'locked']);
  assert.equal(el('sttd-wizard-note').textContent, EN('wizard.testReapplied'));
  assert.equal(el('sttd-text').value, '', 'the previous text is cleared with the redo');
  results.W4 = { clipboardWrites: clipboard.writes.length };
});

test('W5 send: empty field with placeholder, "送信", 5-field POST with nonce and Bearer, one POST per click, pre-flight rejections, delivered alone does not advance; the user confirmation does; failure/cancel/not-sent cannot be confirmed; unknown can', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('ja'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  el('sttd-copy-test').click();
  await settle();
  el('sttd-done-test').click();
  await settle();
  await receive(ui);
  assert.deepEqual([el('sttd-text').value, el('sttd-text').disabled, el('sttd-send').disabled, el('sttd-send').textContent], ['', false, false, '送信']);
  assert.equal(el('sttd-verify-send').disabled, true, 'nothing sent yet');
  // 通信前拒否。
  for (const text of ['', ' \n\t　 ', 'abc\ud800', 'a'.repeat(4097)]) {
    el('sttd-text').value = text;
    el('sttd-send').click();
    await settle();
    assert.equal(ui.api().length, 0);
    assert.equal(el('sttd-result').textContent, JA('console.inputInvalid'));
    assert.equal(el('sttd-verify-send').disabled, true);
  }
  // 保留中: 二重クリックで1件、verify不可、中止可。
  state.mode = 'hold';
  const textA = `  こんにちは🌏\n2行目 </textarea><script>x</script>  `;
  el('sttd-text').value = textA;
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(el('sttd-send').click(), false);
  el('sttd-send').onclick();
  await settle();
  assert.equal(state.holds.length, 1, 'one POST');
  const post = state.holds[0].entry;
  assert.deepEqual([post.url, post.method], ['/v2/commands', 'POST']);
  assert.deepEqual(Object.keys(post.headers).sort(), ['Authorization', 'Content-Type', 'Idempotency-Key', LOCAL_NONCE_HEADER].sort());
  const payload = JSON.parse(post.body);
  assert.deepEqual(Object.keys(payload), FIELDS);
  assert.deepEqual([payload.schemaVersion, payload.text, post.headers['Idempotency-Key'] === payload.commandId], [2, textA, true]);
  assert.match(payload.commandId, UUID);
  assert.equal(Date.parse(payload.expiresAt) - Date.parse(payload.createdAt), 60_000);
  assert.equal(el('sttd-verify-send').disabled, true, 'in flight: cannot confirm');
  assert.notEqual(ui.panelState(1), 'locked', 'done steps stay viewable while sending');
  // 送信中にテスト設定を再適用しても、進行中のtest（commandId/中止手段）を失わず、別POSTも始まらない。
  assert.equal(ui.clickPanel(3), true, 'step 3 can be viewed while sending');
  assert.equal(el('sttd-done-test').disabled, true, 're-apply is inert while a send is in flight');
  el('sttd-done-test').onclick();
  await settle();
  assert.deepEqual([el('sttd-wizard-note').textContent, ui.stepState(5), state.holds.length], [JA('wizard.sendPending'), 'ready', 1], 'handler also refuses; the pending POST is kept');
  assert.equal(ui.clickPanel(5), true);
  assert.equal(el('sttd-cancel').hidden, false, 'the cancel control for the pending command is still there');
  state.holds.shift().hold.release({ status: 200, json: { commandId: payload.commandId, state: 'delivered' } });
  await settle();
  assert.equal(el('sttd-result').textContent, JA('console.state.delivered'));
  assert.deepEqual([ui.stepState(5), ui.stepState(6)], ['current', 'locked'], 'delivered alone does not advance');
  assert.equal(el('sttd-verify-send').disabled, false);
  // 失敗した送信は確認不可。
  state.mode = 'deliver';
  el('sttd-new').click();
  await settle();
  state.mode = 'reject';
  el('sttd-text').value = 'again';
  el('sttd-send').click();
  await settle();
  assert.equal(el('sttd-result').textContent, JA('console.error.409'));
  assert.equal(el('sttd-verify-send').disabled, true);
  el('sttd-verify-send').onclick();
  assert.equal(ui.stepState(6), 'locked');
  // 中止も確認不可。
  el('sttd-new').click();
  await settle();
  state.mode = 'hold';
  el('sttd-text').value = 'cancel me';
  el('sttd-send').click();
  await settle();
  state.mode = 'deliver';
  el('sttd-cancel').click();
  await settle();
  const pending = state.holds.shift();
  pending.hold.release({ status: 200, json: { commandId: JSON.parse(pending.entry.body).commandId, state: 'cancelled' } });
  await settle();
  assert.equal(el('sttd-result').textContent, JA('console.state.cancelled'));
  assert.equal(el('sttd-verify-send').disabled, true);
  // 結果不明は本人確認で進める（APIの結果は書き換えない）。
  el('sttd-new').click();
  await settle();
  state.mode = 'fail';
  el('sttd-text').value = 'unknown';
  el('sttd-send').click();
  await settle();
  assert.equal(el('sttd-result').textContent, JA('console.unknown'));
  assert.equal(el('sttd-verify-send').disabled, false);
  assert.equal(el('sttd-verify-send').click(), true);
  await settle();
  assert.deepEqual([ui.stepState(5), ui.stepState(6)], ['done', 'current']);
  assert.equal(el('sttd-result').textContent, JA('console.unknown'), 'the API result is not rewritten to success');
  assert.equal(ui.api().filter((entry) => entry.method === 'POST' && entry.url === '/v2/commands').length, 4);
  results.W5 = { posts: ui.api().length, clipboardWrites: clipboard.writes.length };
});

test('W6 operational instructions and completion: copy + "pasted, finish" shows the completion text; afterwards step 5 can be re-selected for ordinary sends without re-copying; the completion text is the user\'s confirmation, not a server verification', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  el('sttd-copy-test').click();
  await settle();
  el('sttd-done-test').click();
  await settle();
  await receive(ui);
  el('sttd-text').value = 'test one';
  el('sttd-send').click();
  await settle();
  el('sttd-verify-send').click();
  await settle();
  assert.equal(ui.stepState(6), 'current');
  assert.equal(el('sttd-complete').hidden, true);
  assert.equal(el('sttd-done-operation').disabled, true);
  el('sttd-copy-operation').click();
  await settle();
  assert.equal(clipboard.writes.at(-1), EN('guide.operationText'));
  assert.equal(el('sttd-done-operation').click(), true);
  await settle();
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui.stepState), ['done', 'done', 'done', 'done', 'done', 'current']);
  assert.equal(el('sttd-complete').hidden, false);
  assert.equal(el('sttd-complete').textContent, EN('wizard.complete'));
  // 完了後の通常送信: 5へ戻り（panel内クリックで再活性化）、再コピー不要で送れる。完了bannerはpanel6の外にあり、手順5に戻っても表示が続く。
  assert.equal(ui.clickPanel(5), true, 'clicking inside a done panel re-activates it');
  assert.deepEqual([ui.panelState(5), ui.panelState(6)], ['current', 'done']);
  assert.equal(el('sttd-complete').hidden, false, 'completion banner stays while step 5 is active');
  assert.ok(html('en').indexOf('id="sttd-complete"') > html('en').indexOf('</section>', html('en').indexOf('id="sttd-panel-6"')), 'the banner is placed after the last panel (bottom of the page)');
  el('sttd-new').click();
  await settle();
  el('sttd-text').value = 'second message';
  assert.equal(el('sttd-send').click(), true);
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'));
  assert.equal(ui.api().filter((entry) => entry.method === 'POST' && entry.url === '/v2/commands').length, 2);
  assert.equal(clipboard.writes.length, 2, 'no re-copy demanded for ordinary sends');
  assert.deepEqual([1, 2, 3, 4, 6].map(ui.stepState), ['done', 'done', 'done', 'done', 'done']);
  // 言語切替は進捗も入力も消さない。
  el('sttd-new').click();
  await settle();
  el('sttd-text').value = 'kept';
  el('sttd-lang-ja').click();
  await settle();
  assert.deepEqual([el('sttd-text').value, ui.stepState(6), el('sttd-complete').textContent], ['kept', 'done', JA('wizard.complete')]);
  results.W6 = { posts: ui.api().length };
});

test('W8 owner binding: a sign-in change in another tab (other account or sign-out) resets steps 2 to 6 and sends nothing with the new account; a token obtained while the owner changed is not used; a 401 resets to step 1', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  assert.equal(sdk.calls.listeners.length, 1, 'the auth observer is registered once, after the explicit sign-in');
  el('sttd-copy-test').click();
  await settle();
  el('sttd-done-test').click();
  await settle();
  assert.equal(ui.stepState(4), 'current');
  // 別tabでBへ切替 → 2以降を戻し、1へ。以後の操作はBのtokenで送らない。
  sdk.changeUser('uid-b');
  await settle();
  assert.deepEqual([1, 2, 3, 4].map(ui.stepState), ['current', 'locked', 'locked', 'locked']);
  assert.equal(el('sttd-wizard-note').textContent, EN('wizard.authChanged'));
  const before = ui.fetches.length;
  el('sttd-refresh').onclick();
  el('sttd-send').onclick();
  await settle();
  assert.equal(ui.fetches.length, before, 'no request with the other account');
  // Bとして明示ログイン（復元済み）→ 2から。Aの進捗は戻っている。
  el('sttd-login').click();
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.stepState(3)], ['done', 'current', 'locked']);
  // token取得待ちの間にownerが変わる → そのtokenは使わず、要求は出ない。
  state.connection = 'subscribed';
  sdk.calls.tokenGate = gate();
  const web = ui.web('/v1/web/connection').length;
  el('sttd-refresh').click();
  await settle();
  sdk.changeUser('uid-c');
  await settle();
  sdk.calls.tokenGate.release();
  sdk.calls.tokenGate = null;
  await settle();
  assert.equal(ui.web('/v1/web/connection').length, web, 'the token fetched for the previous owner is not sent');
  assert.equal(ui.stepState(1), 'current');
  // ログアウト → 1へ。
  el('sttd-login').click();
  await settle();
  assert.equal(ui.stepState(2), 'current');
  sdk.changeUser(null);
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2)], ['current', 'locked']);
  assert.equal(el('sttd-account-text').textContent, EN('common.loginRefresh'));
  // 401 → 1へ戻し、古い進捗を残さない。
  el('sttd-login').click();
  await settle();
  el('sttd-refresh').click();
  await settle();
  assert.equal(ui.stepState(3), 'current');
  state.mode = 'web401';
  ui.clickPanel(2);
  el('sttd-refresh').click();
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.stepState(3)], ['current', 'locked', 'locked']);
  // 401はaccountの変化を確かめていないので、変化したとは断定せず再ログインを案内する。
  assert.equal(el('sttd-wizard-note').textContent, EN('wizard.signInAgain'));
  state.mode = 'deliver';
  for (const written of ui.writes) assert.equal(/uid-[abc]|synthetic-id-token/.test(written), false, 'no uid or token in the page text');
  assert.equal(clipboard.writes.length, 1);
  results.W8 = { listeners: sdk.calls.listeners.length, fetches: ui.fetches.length };
});

test('W9 stale copy results: a clipboard write that completes after a reset (sign-in again or a failed re-check) does not satisfy the new step 3, and the copy status is not restored', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { state, onFetch } = helper();
  const held = gate();
  navigator.clipboard.writeText = (value) => {
    clipboard.writes.push(value);
    return clipboard.mode === 'hold' ? held.promise : Promise.resolve();
  };
  const ui = await runConsole({ html: html('ja'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  clipboard.mode = 'hold';
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.equal(el('sttd-copy-test').disabled, true, 'pending');
  // pending中に再ログイン（別account）→ 2以降reset。
  assert.equal(ui.clickPanel(1), true);
  el('sttd-switch').click();
  await settle();
  held.release();
  await settle();
  assert.deepEqual([ui.stepState(1), ui.stepState(2)], ['done', 'current']);
  el('sttd-refresh').click();
  await settle();
  assert.equal(ui.stepState(3), 'current');
  assert.equal(el('sttd-done-test').disabled, true, 'the stale success does not count for the new step 3');
  assert.equal(el('sttd-copy-result-test').textContent, '', 'no stale copied status');
  el('sttd-done-test').onclick();
  assert.equal(el('sttd-copy-result-test').textContent, JA('wizard.copyRequired'));
  // 新しいコピーは有効。pending中の再確認失敗でも同じく捨てる。
  clipboard.mode = 'ok';
  el('sttd-copy-test').click();
  await settle();
  assert.equal(el('sttd-done-test').disabled, false);
  const held2 = gate();
  clipboard.mode = 'hold';
  navigator.clipboard.writeText = (value) => {
    clipboard.writes.push(value);
    return clipboard.mode === 'hold' ? held2.promise : Promise.resolve();
  };
  el('sttd-done-test').click();
  await settle();
  assert.equal(ui.stepState(4), 'current');
  ui.clickPanel(3);
  el('sttd-copy-test').click();
  await settle();
  state.mode = 'webFail';
  ui.clickPanel(2);
  el('sttd-refresh').click();
  await settle();
  assert.equal(ui.stepState(3), 'locked');
  held2.release();
  await settle();
  state.mode = 'deliver';
  el('sttd-refresh').click();
  await settle();
  assert.equal(el('sttd-done-test').disabled, true, 'copy completed after the reset does not count');
  results.W9 = { clipboardWrites: clipboard.writes.length };
});

test('W10 click propagation: a completion click inside the active panel moves to the next step and the bubbling click does not re-select the old panel; the first click into an inactive panel (even on a control or summary) only re-selects it and runs no control; locked panels ignore clicks and keys and their details stay closed; Enter/Space re-selects a done panel', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { clipboard, navigator } = clipboardStub();
  const { onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk, navigator });
  const { el } = ui;
  // 未解放panel内のsummary/ボタンへのclick・keyは再選択も操作も起こさず、detailsも開かない。
  assert.equal(el('sttd-guide-operation-summary').click(), true, 'the event is dispatched (pointer target is the summary in this synthetic check)');
  assert.equal(el('sttd-guide-operation').open, false, 'locked details stay closed');
  el('sttd-guide-operation-summary').keydown('Enter');
  assert.equal(el('sttd-guide-operation').open, false);
  assert.deepEqual([ui.panelState(6), clipboard.writes.length, ui.fetches.length], ['locked', 0, 0]);
  await reachStep3(ui, sdk);
  // activeなpanel3内の「貼り付けて次へ」: 同じclickが親panelへ伝播しても手順4がcurrentのまま。
  el('sttd-copy-test').click();
  await settle();
  assert.equal(el('sttd-done-test').parent.id, 'sttd-panel-3', 'the fixture models the panel as the ancestor of its controls');
  assert.equal(el('sttd-done-test').click(), true);
  await settle();
  assert.deepEqual([ui.panelState(3), ui.panelState(4)], ['done', 'current'], 'the completion click is not followed by a re-selection of step 3');
  // 非active（done）のpanel3内のcontrolへの最初のclickは再選択だけ（コピーは実行されない）。
  const writesBefore = clipboard.writes.length;
  el('sttd-copy-test').disabled = false; // pointer-events:none相当のCSSは合成DOMに無いので、controlがtargetになった最悪形を再現する。
  assert.equal(el('sttd-copy-test').click(), true);
  await settle();
  assert.deepEqual([ui.panelState(3), ui.panelState(4), clipboard.writes.length], ['current', 'ready', writesBefore], 're-selection only; the control did not run');
  // 次のclickは通常どおり動く（activeになったので）。
  el('sttd-copy-test').click();
  await settle();
  assert.equal(clipboard.writes.length, writesBefore + 1);
  // 4へ戻り受信確認→5で送信→一致確認のclickも伝播で戻らない。
  assert.equal(ui.clickPanel(4), true);
  assert.equal(el('sttd-receive-check').click(), true);
  await settle();
  assert.deepEqual([ui.panelState(4), ui.panelState(5)], ['done', 'current'], 'the receiving check click does not fall back to step 4');
  el('sttd-text').value = 'propagation check';
  el('sttd-send').click();
  await settle();
  assert.equal(el('sttd-verify-send').click(), true);
  await settle();
  assert.deepEqual([ui.panelState(5), ui.panelState(6)], ['done', 'current'], 'the verification click does not fall back to step 5');
  // done panelの余白へのEnter/Spaceで再選択（preventDefaultされる）。activeなpanelへのEnterは何もしない。
  assert.equal(ui.keyPanel(5, ' '), true);
  assert.equal(ui.panelState(5), 'current');
  assert.equal(ui.keyPanel(5, 'Enter'), false, 'already active: no default prevented, nothing changes');
  assert.equal(ui.panelState(5), 'current');
  // 非active（ready）panel6のsummaryをclick → 再選択だけでdetailsは開かない。次のclickで開く。
  assert.equal(el('sttd-guide-operation-summary').click(), true);
  assert.deepEqual([ui.panelState(6), el('sttd-guide-operation').open], ['current', false]);
  el('sttd-guide-operation-summary').click();
  assert.equal(el('sttd-guide-operation').open, true, 'the summary works once its panel is active');
  assert.equal(ui.api().filter((entry) => entry.method === 'POST' && entry.url === '/v2/commands').length, 1, 'no extra send from any of the clicks');
  results.W10 = { clipboardWrites: clipboard.writes.length };
});

test('W7 disconnect from step 2: confirm first, one POST, steps 2+ reset and the state re-checked; nothing sent on cancel', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { navigator } = clipboardStub();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('ja'), onFetch, sdk, navigator });
  const { el } = ui;
  await reachStep3(ui, sdk);
  el('sttd-copy-test').click();
  await settle();
  el('sttd-done-test').click();
  await settle();
  assert.equal(ui.clickPanel(2), true);
  assert.equal(el('sttd-disconnect').hidden, false);
  el('sttd-disconnect').click();
  await settle();
  assert.equal(el('sttd-disconnect-confirm').hidden, false);
  el('sttd-disconnect-no').click();
  await settle();
  assert.deepEqual([state.disconnects, ui.stepState(3), ui.stepState(4)], [0, 'done', 'ready']);
  el('sttd-disconnect').click();
  await settle();
  assert.equal(el('sttd-disconnect-yes').click(), true);
  await settle();
  assert.equal(state.disconnects, 1);
  assert.equal(el('sttd-disconnect-result').textContent, JA('common.disconnectDone'));
  assert.deepEqual([ui.stepState(2), ui.stepState(3), ui.stepState(4)], ['current', 'locked', 'locked']);
  assert.equal(el('sttd-state-guide').textContent, JA('wizard.next.unlinked'), 're-checked after the disconnect');
  assert.equal(el('sttd-wizard-note').textContent, JA('wizard.stateReset'));
  results.W7 = { disconnects: state.disconnects };
});

/** 手順5（送信）まで進める（コピー＋「貼り付けて次へ」＋受信状態の確認）。 */
async function reachStep5(ui, sdk) {
  await reachStep3(ui, sdk);
  ui.el('sttd-copy-test').click();
  await settle();
  // clipboardの無い合成browserでは手動コピーの確認で代える。
  if (!ui.el('sttd-manual-test').hidden) ui.el('sttd-manual-test').click();
  ui.el('sttd-done-test').click();
  await settle();
  assert.equal(ui.stepState(4), 'current');
  await receive(ui);
}

test('W11 access: allowed unlocks; denied / unavailable / an old service without the field keep steps 3+ locked with distinct guidance; a later stop keeps status/cancel but blocks new sends; 403 access_denied is distinct from 403 connection_revoked', { timeout: 20_000 }, async () => {
  for (const [access, key] of [['denied', 'wizard.access.denied'], ['unavailable', 'wizard.access.unavailable'], [undefined, 'wizard.access.outdated'], ['something-else', 'wizard.access.unavailable']]) {
    const sdk = syntheticSdk();
    const { state, onFetch } = helper();
    state.access = access;
    const ui = await runConsole({ html: html('ja'), onFetch, sdk });
    ui.el('sttd-login').click();
    await settle();
    ui.el('sttd-refresh').click();
    await settle();
    assert.deepEqual([ui.stepState(2), ui.stepState(3)], ['current', 'locked'], `${access}: not unlocked`);
    assert.equal(ui.el('sttd-state-guide').textContent, JA(key));
    // 本人の接続解除は残す。
    assert.equal(ui.el('sttd-disconnect').hidden, false, `${access}: disconnect stays available`);
    assert.equal(ui.api().length, 0);
  }
  // 許可→手順5で送信（不明）→停止を確認: 新しい送信は不可、前の送信の照会・取消は残る。
  const sdk = syntheticSdk();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk });
  const { el } = ui;
  await reachStep5(ui, sdk);
  state.mode = 'fail';
  el('sttd-text').value = 'before the stop';
  el('sttd-send').click();
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.unknown'));
  state.mode = 'deliver';
  state.access = 'denied';
  ui.clickPanel(2);
  el('sttd-refresh').click();
  await settle();
  assert.equal(el('sttd-state-guide').textContent, EN('wizard.access.denied'));
  ui.clickPanel(5);
  assert.equal(ui.stepState(5), 'current', 'progress kept');
  assert.equal(el('sttd-check').hidden, false);
  el('sttd-check').click();
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'), 'the owner can still check the earlier send');
  el('sttd-new').click();
  await settle();
  assert.deepEqual([el('sttd-send').disabled, el('sttd-text').disabled], [true, true], 'no new send while not permitted');
  assert.ok(el('sttd-result').textContent.includes(EN('wizard.access.denied')));
  const posts = ui.api().filter((entry) => entry.url === '/v2/commands').length;
  el('sttd-send').onclick();
  await settle();
  assert.equal(ui.api().filter((entry) => entry.url === '/v2/commands').length, posts);

  // 403 access_denied（利用許可）は接続の失効（403）と別の文言。どちらも未送信で確認不可。
  const sdk2 = syntheticSdk();
  const h2 = helper();
  const ui2 = await runConsole({ html: html('ja'), onFetch: h2.onFetch, sdk: sdk2 });
  await reachStep5(ui2, sdk2);
  h2.state.mode = 'accessDenied';
  ui2.el('sttd-text').value = 'refused';
  ui2.el('sttd-send').click();
  await settle();
  assert.equal(ui2.el('sttd-result').textContent, JA('console.error.access_denied'));
  assert.notEqual(JA('console.error.access_denied'), JA('console.error.403'));
  assert.equal(ui2.el('sttd-verify-send').disabled, true);
  // 403 access_denied の後は、手動の接続確認でallowedを得るまで新しい送信を封鎖する（ボタンも直接handlerもPOST 0）。
  h2.state.mode = 'deliver';
  ui2.el('sttd-new').click();
  await settle();
  assert.deepEqual([ui2.el('sttd-send').disabled, ui2.el('sttd-text').disabled], [true, true]);
  assert.ok(ui2.el('sttd-result').textContent.includes(JA('wizard.access.denied')));
  const postsBefore = ui2.api().filter((entry) => entry.url === '/v2/commands').length;
  ui2.el('sttd-text').value = 'must not be sent';
  ui2.el('sttd-send').onclick();
  await settle();
  assert.equal(ui2.api().filter((entry) => entry.url === '/v2/commands').length, postsBefore, 'no POST until access is re-checked');
  // 手動の再確認でallowedなら再開できる。
  ui2.clickPanel(2);
  ui2.el('sttd-refresh').click();
  await settle();
  assert.equal(ui2.el('sttd-state-guide').textContent, JA('wizard.next.subscribed'));
  ui2.clickPanel(5);
  assert.equal(ui2.el('sttd-send').disabled, false);
  ui2.el('sttd-text').value = 'after re-check';
  ui2.el('sttd-send').click();
  await settle();
  assert.equal(ui2.api().filter((entry) => entry.url === '/v2/commands').length, postsBefore + 1);
  assert.equal(ui2.el('sttd-result').textContent, JA('console.state.delivered'));
  results.W11 = { fetches: ui.fetches.length };
});

test('W12 helper refusals: a stale-nonce refusal before upstream is "not sent" with reload guidance and cannot be confirmed; 404/405/413 from the helper are not sent; the same code from upstream without the helper header is not treated as local; an upstream/network unknown stays unknown', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk });
  const { el } = ui;
  await reachStep5(ui, sdk);
  for (const [status, code] of [[403, 'local_reload_required'], [404, 'not_found'], [405, 'method_not_allowed'], [413, 'payload_too_large'], [401, 'authentication_required']]) {
    const upstream = state.upstream;
    state.local = { status, code };
    el('sttd-text').value = `local ${status}`;
    el('sttd-send').click();
    await settle();
    assert.equal(state.upstream, upstream, `${status}: nothing reached upstream`);
    assert.equal(el('sttd-result').textContent, EN('console.localRefused'), `${status}: not sent, reload guidance`);
    assert.equal(el('sttd-verify-send').disabled, true, `${status}: cannot be confirmed`);
    assert.equal(el('sttd-check').hidden, true, `${status}: settled as not sent`);
    assert.equal(ui.stepState(1), 'done', `${status}: a helper 401 is not a sign-in loss`);
    el('sttd-new').click();
    await settle();
    assert.equal(el('sttd-wizard-note').textContent, '', 'no duplicate warning for a send that never left');
  }
  // 上流が同じcodeを返しただけ（helperのheaderなし）: 未送信にしない（403の既存文言）。
  state.mode = 'spoof';
  el('sttd-text').value = 'spoof';
  el('sttd-send').click();
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.error.403'));
  el('sttd-new').click();
  await settle();
  // helperの502（上流不明）とnetwork失敗は結果不明のまま（確認・照会できる）。
  for (const mode of ['unknown', 'fail']) {
    state.mode = mode;
    el('sttd-text').value = mode;
    el('sttd-send').click();
    await settle();
    assert.equal(el('sttd-result').textContent, EN('console.unknown'), mode);
    assert.equal(el('sttd-verify-send').disabled, false, `${mode}: the user may confirm`);
    assert.equal(el('sttd-check').hidden, false);
    state.mode = 'deliver';
    el('sttd-new').click();
    await settle();
  }
  // 接続確認のhelper拒否も未送信として再読込みを案内する（ログインは失わない）。
  ui.clickPanel(2);
  state.local = { status: 403, code: 'local_reload_required' };
  el('sttd-refresh').click();
  await settle();
  assert.deepEqual([el('sttd-state-guide').textContent, ui.stepState(1)], [EN('console.localRefused'), 'done']);
  results.W12 = { upstream: state.upstream };
});

test('W13 duplicate warning survives resets that drop an unsettled send: sign-in change during a pending POST, 401, re-applying the test after an unknown result; not overwritten by the reset note; a fresh send clears it', { timeout: 20_000 }, async () => {
  // POST保留中に別accountへ切替 → 1へ戻すが、重複注意を残す（自動の照会・取消・再送なし）。
  {
    const sdk = syntheticSdk();
    const { state, onFetch } = helper();
    const ui = await runConsole({ html: html('ja'), onFetch, sdk });
    await reachStep5(ui, sdk);
    state.mode = 'hold';
    ui.el('sttd-text').value = 'pending';
    ui.el('sttd-send').click();
    await settle();
    const before = ui.fetches.length;
    sdk.changeUser('uid-b');
    await settle();
    assert.equal(ui.stepState(1), 'current');
    assert.equal(ui.el('sttd-wizard-note').textContent, `${JA('wizard.authChanged')} ${JA('console.duplicateWarning')}`);
    state.holds.shift().hold.release({ status: 200, json: { state: 'delivered' } });
    await settle();
    assert.equal(ui.fetches.length, before, 'no automatic check/cancel/resend');
    assert.ok(ui.el('sttd-wizard-note').textContent.includes(JA('console.duplicateWarning')));
  }
  // 結果不明の後の401 → 再ログイン案内（変化と断定しない）＋重複注意。
  {
    const sdk = syntheticSdk();
    const { state, onFetch } = helper();
    const ui = await runConsole({ html: html('en'), onFetch, sdk });
    await reachStep5(ui, sdk);
    state.mode = 'fail';
    ui.el('sttd-text').value = 'unknown then 401';
    ui.el('sttd-send').click();
    await settle();
    state.mode = 'web401';
    ui.clickPanel(2);
    ui.el('sttd-refresh').click();
    await settle();
    assert.equal(ui.el('sttd-wizard-note').textContent, `${EN('wizard.signInAgain')} ${EN('console.duplicateWarning')}`);
  }
  // 結果不明の後にテスト指示を再適用 → 4〜6を戻すが重複注意を残し、受信の再確認後、次の送信の開始で消す。確定した送信は注意しない。
  {
    const sdk = syntheticSdk();
    const { clipboard, navigator } = clipboardStub();
    const { state, onFetch } = helper();
    const ui = await runConsole({ html: html('en'), onFetch, sdk, navigator });
    await reachStep5(ui, sdk);
    state.mode = 'fail';
    ui.el('sttd-text').value = 'unknown then re-apply';
    ui.el('sttd-send').click();
    await settle();
    ui.clickPanel(3);
    ui.el('sttd-copy-test').click();
    await settle();
    ui.el('sttd-done-test').click();
    await settle();
    assert.equal(ui.el('sttd-wizard-note').textContent, `${EN('wizard.testReapplied')} ${EN('console.duplicateWarning')}`);
    assert.equal(ui.el('sttd-result').textContent, EN('console.duplicateWarning'));
    state.mode = 'deliver';
    await receive(ui);
    assert.equal(ui.el('sttd-wizard-note').textContent, EN('console.duplicateWarning'), 'the warning stays after the receiving check');
    ui.el('sttd-text').value = 'fresh';
    ui.el('sttd-send').click();
    await settle();
    assert.equal(ui.el('sttd-wizard-note').textContent, '', 'cleared by the next send');
    ui.clickPanel(3);
    ui.el('sttd-done-test').click();
    await settle();
    assert.equal(ui.el('sttd-wizard-note').textContent, EN('wizard.testReapplied'), 'a settled delivery is not uncertain');
    assert.equal(clipboard.writes.length, 2, 'copied in step 3 twice');
  }
  results.W13 = true;
});

test('W14 cancel / check / new message also require the active step 5: direct handler calls while another step is active send nothing and change nothing; after re-selecting step 5 they work', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { state, onFetch } = helper();
  const ui = await runConsole({ html: html('en'), onFetch, sdk });
  const { el } = ui;
  await reachStep5(ui, sdk);
  state.mode = 'fail';
  el('sttd-text').value = 'unknown result';
  el('sttd-send').click();
  await settle();
  state.mode = 'deliver';
  ui.clickPanel(3);
  assert.equal(ui.stepState(3), 'current');
  const fetches = ui.fetches.length;
  const result = el('sttd-result').textContent;
  el('sttd-cancel').onclick();
  el('sttd-check').onclick();
  el('sttd-new').onclick();
  await settle();
  assert.deepEqual([ui.fetches.length, el('sttd-result').textContent, el('sttd-check').hidden], [fetches, result, false], 'no request and no state change');
  ui.clickPanel(5);
  el('sttd-check').click();
  await settle();
  assert.equal(el('sttd-result').textContent, EN('console.state.delivered'));
  assert.equal(ui.fetches.length, fetches + 1);
  results.W14 = { fetches: ui.fetches.length };
});

test('W15 step 2 plugin guide: a short intro is visible from the start; the expandable steps show this deployment\'s <mcpOrigin>/mcp (escaped, following the helper origin) or, without an origin, no invented URL; opening, links and language switches send nothing; a locked or inactive step 2 keeps the guide closed; an existing connection can still read it', { timeout: 20_000 }, async () => {
  const MCP = 'https://mcp-guide.example.org';
  const page = (language, mcpOrigin) => consoleAsset('/console', WEB, { language, nonce: NONCE, secure: false, ...(mcpOrigin === undefined ? {} : { mcpOrigin }) }).body;
  // 登録先URLはhelperの検証済みoriginへ追従し、HTMLへescapeして埋め込む。localhost・API・query・不正な形は受けない。
  for (const origin of [MCP, 'https://other-mcp.example.net', 'https://a.1-2']) {
    const body = page('en', origin);
    assert.ok(body.includes(`<code id="sttd-plugin-url" class="sttd-plugin-url">${origin}/mcp</code>`), origin);
    assert.equal(body.includes('sttd-plugin-url-missing'), false);
  }
  for (const bad of ['http://mcp-guide.example.org', 'https://localhost', 'https://a.localhost', 'https://1.2.3.4', 'https://mcp-guide.example.org/mcp', 'https://mcp-guide.example.org?x=1', 'https://a"><script>x</script>.example.org', 'javascript:alert(1)', '']) {
    assert.throws(() => page('en', bad), (error) => error.name === 'ConsoleConfigError', bad);
  }
  // rendererは配置設定・helperと同じ既存の判定（http/origin.js）をそのまま使う（判定が食い違わない）。
  const { isDevelopmentPublicOrigin } = await import('../dist/http/origin.js');
  const accepted = (origin) => {
    try {
      page('en', origin);
      return true;
    } catch {
      return false;
    }
  };
  for (const origin of [MCP, 'https://a.1-2', 'https://a.localhost', 'https://localhost', 'https://1.2.3.4', 'https://x.example.org:8443', 'https://X.example.org']) {
    assert.equal(accepted(origin), isDevelopmentPublicOrigin(origin), origin);
  }
  const missing = page('ja', undefined);
  assert.equal(missing.includes('id="sttd-plugin-url"'), false, 'no URL is invented without an origin');
  assert.ok(missing.includes(JA('plugin.urlMissing')));

  const sdk = syntheticSdk();
  const { state, onFetch } = helper('unlinked');
  const ui = await runConsole({ html: page('en', MCP), onFetch, sdk });
  const { el } = ui;
  // 初期表示: 導入文と閉じたガイドが手順2の中にあり、通信0。手順2は未解放なのでsummaryをclickしても開かない。
  assert.equal(el('sttd-plugin-intro').textContent, EN('plugin.intro'));
  assert.equal(el('sttd-plugin-guide').parent.id, 'sttd-panel-2');
  assert.equal(el('sttd-plugin-guide').open, false);
  el('sttd-plugin-summary').click();
  assert.equal(el('sttd-plugin-doc-connect').click(), true, 'a link in a locked panel does not navigate');
  assert.equal(el('sttd-plugin-guide').open, false, 'a locked step keeps the guide closed');
  assert.equal(el('sttd-plugin-url').textContent, `${MCP}/mcp`);
  assert.equal(el('sttd-plugin-url-note').textContent, EN('plugin.urlNote'));
  for (const n of [1, 2, 3, 4, 5]) assert.equal(el(`sttd-plugin-step-${n}`).textContent, EN(`plugin.step${n}`));
  assert.deepEqual([el('sttd-plugin-doc-connect').getAttribute('href'), el('sttd-plugin-doc-custom').getAttribute('href')], [PLUGIN_GUIDE_LINKS.connect, PLUGIN_GUIDE_LINKS.customMcp]);
  assert.deepEqual([el('sttd-plugin-doc-connect').getAttribute('target'), el('sttd-plugin-doc-connect').getAttribute('rel')], ['_blank', 'noopener noreferrer']);
  // ログインで手順2が有効になると、展開して読める。展開・公式リンク・言語切替は通信も認証も起こさない。
  el('sttd-login').click();
  await settle();
  assert.equal(ui.stepState(2), 'current');
  const fetches = ui.fetches.length;
  const tokens = sdk.calls.tokens;
  el('sttd-plugin-summary').click();
  assert.equal(el('sttd-plugin-guide').open, true);
  assert.equal(el('sttd-plugin-doc-custom').click(), false, 'an ordinary link (opened by the user, not prevented)');
  el('sttd-lang-ja').click();
  await settle();
  assert.deepEqual([el('sttd-plugin-summary').textContent, el('sttd-plugin-step-4').textContent, el('sttd-plugin-labels').textContent], [JA('plugin.title'), JA('plugin.step4'), JA('plugin.labels')]);
  assert.equal(el('sttd-plugin-url').textContent, `${MCP}/mcp`, 'the URL is not translated');
  assert.equal(el('sttd-plugin-guide').open, true, 'switching the language keeps the guide open');
  assert.deepEqual([ui.fetches.length, sdk.calls.tokens], [fetches, tokens], 'no request and no token for the guide');
  // 接続済み（受信中）で手順3へ進んだ後も、手順2を選び直せばガイドを見直せる（再登録は求めない）。
  state.connection = 'subscribed';
  el('sttd-refresh').click();
  await settle();
  assert.equal(ui.stepState(3), 'current');
  assert.equal(ui.clickPanel(2), true);
  assert.equal(ui.stepState(2), 'current');
  assert.equal(el('sttd-plugin-guide').open, true);
  assert.equal(ui.web('/v1/web/connection').length, 1, 'only the explicit check reached the helper');
  results.W15 = { fetches: ui.fetches.length };
});

test('W16 receiving check in step 4: only an explicit click sends one GET; linked keeps step 4 with the start-receiving guidance; an error or an access that is not allowed never opens step 5; losing receiving later resets steps 4 to 6; leaving the connection resets to step 2; a result that arrives after the sign-in changed is ignored', { timeout: 20_000 }, async () => {
  const sdk = syntheticSdk();
  const { state, onFetch } = helper('linked');
  const ui = await runConsole({ html: html('en'), onFetch, sdk });
  const { el } = ui;
  await reachStep3(ui, sdk);
  el('sttd-copy-test').click();
  await settle();
  el('sttd-manual-test').click();
  el('sttd-done-test').click();
  await settle();
  assert.deepEqual([4, 5, 6].map(ui.stepState), ['current', 'locked', 'locked']);
  const gets = ui.web('/v1/web/connection').length;
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['current', 'locked', EN('wizard.receive.linked')]);
  state.mode = 'webFail';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['current', 'locked', EN('wizard.next.unavailable')], 'an error is not success');
  state.mode = 'deliver';
  state.connection = 'subscribed';
  state.access = 'denied';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['current', 'locked', EN('wizard.access.denied')]);
  state.access = 'allowed';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([ui.stepState(4), ui.stepState(5), el('sttd-receive-text').textContent], ['done', 'current', EN('wizard.receive.ok')]);
  assert.deepEqual([ui.web('/v1/web/connection').length, ui.api().length], [gets + 4, 0], 'one GET per click; nothing polled or sent automatically');
  // 受信の喪失（linkedへ戻る）→ 4以降を戻し、手順2/3は残す。
  ui.clickPanel(4);
  state.connection = 'linked';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([2, 3, 4, 5, 6].map(ui.stepState), ['done', 'done', 'current', 'locked', 'locked']);
  assert.equal(el('sttd-wizard-note').textContent, EN('wizard.receiveReset'));
  // 接続許可の外（期限切れ）→ 手順2へ戻す。
  state.connection = 'expired';
  el('sttd-receive-check').click();
  await settle();
  assert.deepEqual([2, 3, 4].map(ui.stepState), ['current', 'locked', 'locked']);
  assert.equal(el('sttd-state-guide').textContent, EN('wizard.next.expired'));

  // 確認中にログインが変わる → 遅れて届いたsubscribedで5を開かない。
  const held = gate();
  let hold = false;
  const h2 = helper('linked');
  const slow = async (entry) => {
    if (hold && entry.url === '/v1/web/connection') {
      hold = false;
      await held.promise;
    }
    return h2.onFetch(entry);
  };
  const sdk2 = syntheticSdk();
  const ui2 = await runConsole({ html: html('en'), onFetch: slow, sdk: sdk2 });
  await reachStep3(ui2, sdk2);
  ui2.el('sttd-copy-test').click();
  await settle();
  ui2.el('sttd-manual-test').click();
  ui2.el('sttd-done-test').click();
  await settle();
  const moved = [];
  ui2.el('sttd-panel-5').scrollIntoView = () => moved.push(5);
  h2.state.connection = 'subscribed';
  hold = true;
  ui2.el('sttd-receive-check').click();
  await settle();
  assert.equal(ui2.el('sttd-receive-text').textContent, EN('wizard.receiveChecking'));
  sdk2.changeUser('uid-b');
  await settle();
  held.release();
  await settle();
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui2.stepState), ['current', 'locked', 'locked', 'locked', 'locked', 'locked'], 'the stale result unlocks nothing');
  assert.deepEqual(moved, [], 'the stale result does not move the view');
  results.W16 = { gets: ui.web('/v1/web/connection').length };
});