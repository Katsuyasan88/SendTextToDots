// 開発者向けコード（T-065）の画面・operator helperの合成検証。
//   - O: operator設定のexact schema、限定4操作（Origin必須/nonce/認証header拒否/小本文/JSON/未知route/method）、二重クリックの直列化、
//        照会による発行結果の再表示（再発行しない）、再発行失敗で現在のコードを維持、active時だけcustom token、取消。
//        CLIは同projectの署名SAだけをFirebase Adminの`serviceAccountId`へ渡し、不正なら資格・SDK・Secretの前に止まる（合成のSDK生成口）。
//   - U: ステップ1の方式選択（operator off=未設定の案内）、日英、秘密/コードをHTMLへ入れない、自動poll無し、プラグイン接続画面のコード入力
//        （feature offでは出さない）、固定の失敗案内、送信元consoleのpanel 1への統合。
// 合成のstore/auth・127.0.0.1のlocal serverだけ。実SDK・Cloud・資格・外部network 0。

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { test } from 'node:test';

import { OPERATOR_TEXT, operatorScript, parseOperatorConfig, renderOperatorCodePanel, renderOperatorSection } from '../dist/console/operator-config.js';
import { createOperatorRoutes, parseOperatorArgs, startOperatorConsole } from '../dist/console/operator-server.js';
import { CODE_TEXT, INTERACTION_SCRIPT, renderInteractionLogin } from '../dist/connect/pages.js';
import { renderConsolePage } from '../dist/connect/console.js';
import { DeveloperLoginError } from '../dist/identity/developer-login.js';

const WEB = { apiKey: 'AIzaSyntheticPublicKey000000000000000', authDomain: 'sttd-synthetic.firebaseapp.com', projectId: 'sttd-synthetic' };
const NONCE = randomBytes(32).toString('hex');

function fakeStore() {
  const calls = { issue: [], claim: 0, cancel: 0 };
  let n = 0;
  const store = {
    calls,
    state: 'pending',
    issueDelay: 0,
    failIssue: null,
    async issue(input) {
      calls.issue.push(input);
      if (store.issueDelay > 0) await new Promise((resolve) => setTimeout(resolve, store.issueDelay));
      if (store.failIssue) throw new DeveloperLoginError(store.failIssue);
      n += 1;
      return { kind: 'issued', code: String(n).padStart(6, '0'), operationId: randomBytes(32).toString('base64url'), issuedAt: Date.now(), authExpiresAt: Date.now() + 600_000, candidates: 1 };
    },
    async claim() {
      calls.claim += 1;
      return store.state === 'active' ? { kind: 'active', uid: `sttdc_${'a'.repeat(32)}`, familyId: globalThis.crypto.randomUUID() } : { kind: store.state };
    },
    async cancel() {
      calls.cancel += 1;
      return 'revoked';
    },
  };
  return store;
}

async function withHelper(store, fn) {
  const routes = createOperatorRoutes({ store, auth: { createCustomToken: async () => 'synthetic-custom-token' }, clock: { now: () => Date.now() } });
  let origin = '';
  const server = createServer((req, res) => {
    const url = new URL(req.url, origin);
    routes.handle(req, res, { path: url.pathname, method: req.method, nonce: NONCE, origin }).catch(() => res.destroy());
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://localhost:${server.address().port}`;
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (action, init = {}) =>
    fetch(`${base}/v1/operator/code/${action}`, {
      method: init.method ?? 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin, 'X-Sttd-Local-Nonce': NONCE, ...(init.headers ?? {}) },
      ...(init.method === 'GET' ? {} : { body: init.body ?? '{}' }),
    });
  try {
    await fn({ post, base, origin });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const OPERATOR_CONFIG = Object.freeze({
  version: 1,
  projectId: 'sttd-synthetic',
  databaseId: '(default)',
  namespace: 't256_0b2c9a1e-4d5f-4a6b-8c7d-9e0f1a2b3c4d',
  identifierKeySecretVersion: 'projects/123456789012/secrets/sttd-identifier/versions/1',
  signingServiceAccount: 'sttd-signer@sttd-synthetic.iam.gserviceaccount.com',
});

/** 署名SAの不正値（欠落・空・別project・compute/App Engine既定・URL・大文字・長さ・型）。 */
const BAD_SIGNERS = [
  '',
  'sttd-signer@other-project.iam.gserviceaccount.com',
  'sttd-signer@sttd-synthetic.iam.gserviceaccount.com.evil.example',
  '123456789012-compute@developer.gserviceaccount.com',
  'sttd-synthetic@appspot.gserviceaccount.com',
  'default',
  'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sttd-signer@sttd-synthetic.iam.gserviceaccount.com',
  'projects/-/serviceAccounts/sttd-signer@sttd-synthetic.iam.gserviceaccount.com',
  'Sttd-Signer@sttd-synthetic.iam.gserviceaccount.com',
  'abcde@sttd-synthetic.iam.gserviceaccount.com',
  `s${'a'.repeat(30)}@sttd-synthetic.iam.gserviceaccount.com`,
  'sttd-signer-@sttd-synthetic.iam.gserviceaccount.com',
  'a@b@sttd-synthetic.iam.gserviceaccount.com',
  ' sttd-signer@sttd-synthetic.iam.gserviceaccount.com',
  ['sttd-signer@sttd-synthetic.iam.gserviceaccount.com'],
  null,
];

test('O1 operator config is exact and contains no secret value', () => {
  const good = OPERATOR_CONFIG;
  assert.equal(parseOperatorConfig(good).identifierKeySecretVersion, good.identifierKeySecretVersion);
  assert.equal(parseOperatorConfig(good).signingServiceAccount, good.signingServiceAccount);
  // 境界: SA名6文字・30文字は受ける（配置設定のserviceAccountと同じ規則）。
  for (const name of ['abcdef', `s${'a'.repeat(29)}`]) {
    const value = `${name}@sttd-synthetic.iam.gserviceaccount.com`;
    assert.equal(parseOperatorConfig({ ...good, signingServiceAccount: value }).signingServiceAccount, value);
  }
  const { signingServiceAccount: _omitted, ...withoutSigner } = good;
  for (const bad of [
    { ...good, extra: 1 },
    { ...good, version: 2 },
    { ...good, identifierKeySecretVersion: 'projects/123456789012/secrets/x/versions/latest' },
    { ...good, identifierKeySecretVersion: 'projects/sttd-synthetic/secrets/x/versions/1' },
    { ...good, purpose: 'plugin-connect' },
    { ...good, namespace: 'replace-me' },
    { ...good, dedupeKey: 'inline-secret' },
    withoutSigner,
    { ...withoutSigner, serviceAccountId: good.signingServiceAccount },
    { ...good, privateKey: 'synthetic-key-data' },
    ...BAD_SIGNERS.map((signingServiceAccount) => ({ ...good, signingServiceAccount })),
  ]) assert.throws(() => parseOperatorConfig(bad), (error) => error.name === 'OperatorConfigError' && error.message === 'operator config: invalid');
  assert.deepEqual(parseOperatorArgs(['--config', 'a.json', '--operator', 'b.json']), { configPath: 'a.json', operatorPath: 'b.json', port: undefined });
  assert.throws(() => parseOperatorArgs(['--config', 'a.json']));
  assert.throws(() => parseOperatorArgs(['--config', 'a.json', '--operator', 'b.json', '--url', 'https://x']));
});

/** CLIの資格・SDK生成口の合成（呼出し順を記録する。実SDK・ADC探索・Secret・network 0）。 */
function fakeSdk(operatorConfig) {
  const calls = [];
  const credential = Object.freeze({ synthetic: 'adc' });
  const app = Object.freeze({ name: 'synthetic-app' });
  const sdk = {
    calls,
    readFile(path) {
      calls.push(['readFile', path]);
      return path === 'operator.json' ? JSON.stringify(operatorConfig) : JSON.stringify({ synthetic: 'console' });
    },
    secretManager() {
      calls.push(['secretManager']);
      return { async accessSecretVersion(request) { calls.push(['accessSecretVersion', request.name]); return [{ payload: { data: new Uint8Array(32).fill(7) } }]; } };
    },
    applicationDefault() {
      calls.push(['applicationDefault']);
      return credential;
    },
    initializeApp(options, name) {
      calls.push(['initializeApp', options, name]);
      return app;
    },
    getAuth(received) {
      calls.push(['getAuth', received]);
      return { async createCustomToken() { return 'synthetic-custom-token'; } };
    },
    firestore(settings) {
      calls.push(['firestore', settings]);
      // storeの生成が参照を組むだけの最小chain（DB操作は0）。
      const ref = { collection: () => ref, doc: () => ref };
      return ref;
    },
    async startLocalConsole(input) {
      calls.push(['startLocalConsole', input]);
      return { origin: 'http://localhost:0' };
    },
  };
  return { sdk, calls, credential, app };
}

test('O5 CLI passes only the configured same-project signer to Firebase Admin; invalid signer stops before credentials, SDK or secret I/O', async () => {
  const argv = ['--config', 'console.json', '--operator', 'operator.json'];
  const ok = fakeSdk(OPERATOR_CONFIG);
  assert.deepEqual(await startOperatorConsole(argv, ok.sdk), { origin: 'http://localhost:0' });
  const init = ok.calls.filter(([name]) => name === 'initializeApp');
  assert.equal(init.length, 1);
  const [, options] = init[0];
  // 署名先は設定値そのもの（ADC/metadata/UIDからの推測ではない）。serviceAccountIdがあるとSDKのIAMSignerはmetadata serverへ進まない。
  assert.deepEqual(Object.keys(options).sort(), ['credential', 'projectId', 'serviceAccountId']);
  assert.equal(options.serviceAccountId, OPERATOR_CONFIG.signingServiceAccount);
  assert.equal(options.projectId, OPERATOR_CONFIG.projectId);
  assert.equal(options.credential, ok.credential);
  assert.equal(ok.calls.find(([name]) => name === 'getAuth')[1], ok.app);
  assert.deepEqual(ok.calls.find(([name]) => name === 'firestore')[1], { projectId: OPERATOR_CONFIG.projectId, databaseId: OPERATOR_CONFIG.databaseId });
  assert.equal(typeof ok.calls.find(([name]) => name === 'startLocalConsole')[1].operator.handle, 'function');
  // 署名SAの別名は同じ規則で受け、そのまま渡る（固定値の写しではない）。
  const other = fakeSdk({ ...OPERATOR_CONFIG, signingServiceAccount: 'sttd-mcp-runtime@sttd-synthetic.iam.gserviceaccount.com' });
  await startOperatorConsole(argv, other.sdk);
  assert.equal(other.calls.find(([name]) => name === 'initializeApp')[1].serviceAccountId, 'sttd-mcp-runtime@sttd-synthetic.iam.gserviceaccount.com');

  const { signingServiceAccount: _omitted, ...withoutSigner } = OPERATOR_CONFIG;
  for (const config of [withoutSigner, ...BAD_SIGNERS.map((signingServiceAccount) => ({ ...OPERATOR_CONFIG, signingServiceAccount }))]) {
    const bad = fakeSdk(config);
    await assert.rejects(startOperatorConsole(argv, bad.sdk), (error) => {
      // 固定error。設定値（SA・project・Secret版名）を含まない。
      assert.equal(error.message, 'operator config: invalid');
      assert.ok(!error.message.includes('sttd-'));
      return true;
    });
    // operator設定を読んだだけで止まる（console設定・資格・Secret・SDK・DB・serverは0）。
    assert.deepEqual(bad.calls, [['readFile', 'operator.json']]);
  }
});

test('O2 helper refuses missing Origin, wrong nonce, auth header, wrong method/type/body, unknown action', async () => {
  const store = fakeStore();
  await withHelper(store, async ({ post, base }) => {
    assert.equal((await fetch(`${base}/v1/operator/code/issue`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Sttd-Local-Nonce': NONCE }, body: '{}' })).status, 403);
    assert.equal((await post('issue', { headers: { 'X-Sttd-Local-Nonce': 'x'.repeat(43) } })).status, 403);
    assert.equal((await post('issue', { headers: { Origin: 'http://localhost:1' } })).status, 403);
    assert.equal((await post('issue', { headers: { Authorization: 'Bearer abc' } })).status, 403);
    assert.equal((await post('issue', { method: 'GET' })).status, 405);
    assert.equal((await post('issue', { headers: { 'Content-Type': 'text/plain' } })).status, 415);
    assert.equal((await post('issue', { body: JSON.stringify({ code: '123456', pad: 'x'.repeat(80) }) })).status, 400);
    assert.equal((await post('write')).status, 404);
    assert.equal(store.calls.issue.length, 0);
  });
});

test('O3 issue, double click serialized, status re-shows result, reissue failure keeps current code, active token, cancel', async () => {
  const store = fakeStore();
  await withHelper(store, async ({ post }) => {
    store.issueDelay = 50;
    const [first, second] = await Promise.all([post('issue'), post('issue')]);
    assert.deepEqual([first.status, second.status].sort(), [200, 409]);
    store.issueDelay = 0;
    const issued = await (first.status === 200 ? first : second).json();
    assert.match(issued.code, /^[0-9]{6}$/);
    assert.equal(store.calls.issue.length, 1);
    assert.equal((await post('issue')).status, 409);
    const status = await (await post('status')).json();
    assert.equal(status.state, 'pending');
    assert.equal(status.code, issued.code);
    assert.equal(store.calls.issue.length, 1);
    store.failIssue = 'issue_exhausted';
    const failed = await post('reissue');
    assert.equal(failed.status, 503);
    assert.equal((await failed.json()).error.code, 'issue_exhausted');
    assert.equal((await (await post('status')).json()).code, issued.code);
    store.failIssue = null;
    const reissued = await (await post('reissue')).json();
    assert.notEqual(reissued.code, issued.code);
    assert.equal(typeof store.calls.issue.at(-1).previousOperationId, 'string');
    assert.equal(store.calls.issue.at(-1).claimSecret, store.calls.issue[0].claimSecret);
    store.state = 'active';
    const active = await (await post('status')).json();
    assert.deepEqual(active, { state: 'active', customToken: 'synthetic-custom-token' });
    assert.equal((await (await post('cancel')).json()).state, 'ended');
    assert.equal((await (await post('status')).json()).state, 'ended');
  });
});

test('O4 operator script is served same-origin and has no automatic polling', async () => {
  await withHelper(fakeStore(), async ({ base }) => {
    const response = await fetch(`${base}/console/operator.js`);
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(body.includes('X-Sttd-Local-Nonce'));
    assert.ok(!/setInterval\((call|confirm|issue)/.test(body));
    assert.ok(!body.includes('localStorage'));
  });
  const script = operatorScript('X-Sttd-Local-Nonce');
  assert.equal((script.match(/fetch\(/g) ?? []).length, 1);
});

test('U1 step 1 method choice: off shows not-configured; on has explicit buttons; ja/en; no secret in HTML', () => {
  const off = renderOperatorSection({ language: 'ja', enabled: false, nonce: NONCE, web: WEB });
  assert.ok(off.includes(OPERATOR_TEXT.ja.notConfigured));
  assert.ok(!off.includes('sttd-method-continue'));
  const on = renderOperatorSection({ language: 'en', enabled: true, nonce: NONCE, web: WEB });
  for (const id of ['sttd-method-apple', 'sttd-method-code', 'sttd-method-continue']) assert.ok(on.includes(`id="${id}"`), id);
  // コード操作は手順2の部品（operator modeでないときは空）
  const codePanel = renderOperatorCodePanel({ language: 'en', enabled: true });
  assert.equal(renderOperatorCodePanel({ language: 'en', enabled: false }), '');
  for (const id of ['sttd-code-confirm', 'sttd-code-reissue', 'sttd-code-cancel', 'sttd-code-display', 'sttd-code-guide']) assert.ok(codePanel.includes(`id="${id}"`), id);
  assert.ok(!on.includes('id="sttd-code-panel"'), 'code operations are not in step 1');
  assert.ok(!on.includes('id="sttd-code-issue"'), 'issuing starts from the single Continue button');
  assert.ok(codePanel.includes(OPERATOR_TEXT.en.codeGuide));
  assert.ok(codePanel.includes('id="sttd-code-panel" hidden'));
  // native radio（fieldset/legend/label、初期値は既存のApple方式）と共通の「続ける」1つ。別のApple実行ボタンは置かない
  assert.ok(/<fieldset class="sttd-method-choice"><legend>/.test(on));
  assert.ok(/<label class="sttd-radio"><input type="radio" name="sttd-method" id="sttd-method-apple" value="apple" checked>/.test(on));
  assert.ok(/<input type="radio" name="sttd-method" id="sttd-method-code" value="code">/.test(on));
  assert.equal((on.match(/<button/g) ?? []).filter(Boolean).length, (on.match(/id="sttd-method-continue"|id="sttd-code-(reissue|confirm|cancel)"/g) ?? []).length, 'no other buttons');
  assert.equal(OPERATOR_TEXT.ja.methodApple, 'Appleでログイン（推奨）');
  assert.equal(OPERATOR_TEXT.ja.methodCode, 'コードでログイン');
  assert.equal(OPERATOR_TEXT.ja.continue, '続ける');
  assert.ok(!/[0-9]{6}<\/code>/.test(on));
  assert.ok(OPERATOR_TEXT.ja.switchNotice.includes('ステップ2'));
  assert.deepEqual(Object.keys(OPERATOR_TEXT.ja).sort(), Object.keys(OPERATOR_TEXT.en).sort());
});

test('U2 plugin connection screen: code input only when enabled, fixed failure guidance, custom-token login then existing /login', () => {
  const on = renderInteractionLogin(WEB, 'interactionUid1', 'Client', 'c'.repeat(43), 'ja', true);
  assert.ok(on.includes('id="sttd-code-input"'));
  assert.ok(on.includes('data-sttd-code="on"'));
  assert.ok(on.includes('<section id="sttd-code-section" aria-labelledby="sttd-code-heading">'));
  const off = renderInteractionLogin(WEB, 'interactionUid1', 'Client', 'c'.repeat(43), 'en');
  assert.ok(off.includes('<section id="sttd-code-section" aria-labelledby="sttd-code-heading" hidden>'));
  assert.ok(/id="sttd-code-submit" disabled/.test(off));
  assert.ok(off.includes('data-sttd-code="off"'));
  assert.equal(CODE_TEXT.ja.rejected, 'このコードでは接続できません。コンソールで新しいコードを発行してください。');
  assert.equal(CODE_TEXT.en.rejected, 'This code cannot be used to connect. Generate a new code in the console.');
  assert.ok(INTERACTION_SCRIPT.includes('signInWithCustomToken'));
  assert.ok(INTERACTION_SCRIPT.includes("'/code'"));
  assert.ok(!/setInterval/.test(INTERACTION_SCRIPT));
});

test('U3 console page panel 1 includes the method section', () => {
  const section = renderOperatorSection({ language: 'en', enabled: false, nonce: NONCE, web: WEB });
  const html = renderConsolePage(WEB, { language: 'en', nonce: NONCE, secure: false, operatorSection: section });
  const panel1 = html.slice(html.indexOf('id="sttd-panel-1"'), html.indexOf('id="sttd-panel-2"'));
  assert.ok(panel1.includes('id="sttd-code-not-configured"'));
  // 通常の配信modeは従来どおりApple操作が先（方式選択は無い）
  assert.ok(panel1.indexOf('id="sttd-login"') < panel1.indexOf('id="sttd-code-not-configured"'));
  assert.ok(!panel1.includes('id="sttd-method-apple"'));
});

test('U4 operator mode puts the method choice first in step 1; Apple guidance and sign-in are one group after it', () => {
  const section = renderOperatorSection({ language: 'ja', enabled: true, nonce: NONCE, web: WEB });
  const html = renderConsolePage(WEB, { language: 'ja', nonce: NONCE, secure: false, operatorSection: section, operatorFirst: true });
  const panel1 = html.slice(html.indexOf('id="sttd-panel-1"'), html.indexOf('id="sttd-panel-2"'));
  const at = (id) => panel1.indexOf(`id="${id}"`);
  assert.ok(at('sttd-method') > 0 && at('sttd-method') < at('sttd-apple-panel'), 'method choice first');
  // operator modeでは下のApple操作を最初から出さない（「続ける」1つで始める）
  assert.ok(panel1.includes('<div id="sttd-apple-panel" hidden>'), 'Apple sign-in button group is hidden in operator mode');
  assert.equal((panel1.match(/id="sttd-method-continue"/g) ?? []).length, 1);
  assert.equal((panel1.match(/id="sttd-login"/g) ?? []).length, 1);
  assert.equal((panel1.match(/id="sttd-method-apple"/g) ?? []).length, 1);
});

// ---------- B: 送信画面の本体controllerとoperator部品を同じ合成DOMで実行（既存fixture console-browser.mjs） ----------

import vm from 'node:vm';
import { randomUUID } from 'node:crypto';
import { consoleAsset, CONSOLE_SCRIPT } from '../dist/connect/console.js';
import { domFromHtml, SDK_LOADER_LINE, settle, syntheticSdk } from './fixtures/console-browser.mjs';

/** 保留して後から解放する合成の待ち。 */
const gate = () => {
  let release;
  const promise = new Promise((resolve) => (release = resolve));
  return { promise, release };
};

const CODE_UID = `sttdc_${'A'.repeat(32)}`;

async function runConsoleWithOperator({ onOperator, restoredCode = false, restoredClaims = null, restoredHold = null } = {}) {
  const html = consoleAsset('/console', WEB, {
    nonce: NONCE,
    secure: false,
    operatorSection: renderOperatorSection({ language: 'en', enabled: true, nonce: NONCE, web: WEB }),
    operatorFirst: true,
    operatorCodePanel: renderOperatorCodePanel({ language: 'en', enabled: true }),
  }).body;
  const dom = domFromHtml(html);
  const base = syntheticSdk();
  const codeUser = {
    uid: CODE_UID,
    async getIdToken() {
      return 'synthetic-code-id-token';
    },
    // 保存済みのコードログイン（Firebase persistence）のID token claims。restoredHoldで応答を遅らせる。
    async getIdTokenResult() {
      if (restoredHold) await restoredHold.promise;
      return { claims: restoredClaims ?? {} };
    },
  };
  if (restoredCode) base.auth.currentUser = codeUser;
  const custom = { calls: 0, hold: null, tokens: [] };
  const sdk = {
    ...base,
    load: async () => {
      const [app, mod] = await base.load();
      return [
        app,
        {
          ...mod,
          signInWithCustomToken: async (auth, token) => {
            custom.calls += 1;
            custom.tokens.push(token);
            if (custom.hold) await custom.hold.promise;
            auth.currentUser = codeUser;
            return { user: codeUser };
          },
        },
      ];
    },
  };
  const fetches = [];
  const fetch = async (url, init = {}) => {
    fetches.push({ url, init });
    assert.ok(url.startsWith('/'), 'same-origin only');
    const prefix = '/v1/operator/code/';
    const { status, json } = url.startsWith(prefix) ? await onOperator(url.slice(prefix.length), init) : { status: 503, json: { error: { code: 'unavailable' } } };
    return { ok: status >= 200 && status < 300, status, headers: { get: () => null }, json: async () => json };
  };
  const context = vm.createContext({ document: dom.document, fetch, crypto: { randomUUID }, TextEncoder, setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {}, AbortController, __sdk: sdk });
  vm.runInContext(CONSOLE_SCRIPT.replace(SDK_LOADER_LINE, 'const loadSdkModules = () => __sdk.load();'), context, { filename: 'console-app.js' });
  // ブラウザではmodule scriptごとに独立したscope。vmでは同じglobalなので関数scopeで包んで同じ分離にする。
  vm.runInContext(`(() => {\n${operatorScript('X-Sttd-Local-Nonce')}\n})();`, context, { filename: 'operator.js' });
  await settle();
  const el = (id) => dom.elements.get(id);
  const click = async (id) => {
    el(id).click();
    for (let i = 0; i < 4; i += 1) await settle();
  };
  const stepState = (n) => el(`sttd-panel-${n}`).getAttribute('data-sttd-state');
  return { el, click, stepState, base, custom, fetches };
}

const issuedJson = () => ({ status: 200, json: { code: '012345', authExpiresAt: Date.now() + 600_000 } });
const activeJson = () => ({ status: 200, json: { state: 'active', customToken: 'synthetic-custom-token' } });

test('B1 issue unlocks only step 2 from the controller state; sending stays locked; no SDK or upstream call', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? issuedJson() : { status: 200, json: { state: 'pending' } }) });
  assert.equal(ui.stepState(2), 'locked');
  // 初期はApple方式のradioが選択済みで、その説明だけ。下のApple操作とコード操作は出さない
  assert.equal(ui.el('sttd-method-apple').checked, true);
  assert.equal(ui.el('sttd-method-desc-apple').hidden, false);
  assert.equal(ui.el('sttd-method-desc-code').hidden, true);
  assert.equal(ui.el('sttd-apple-panel').hidden, true);
  assert.equal(ui.el('sttd-code-panel').hidden, true);
  await ui.click('sttd-method-code');
  // 選択だけでは発行・通信しない。空の方式切替では旧pluginの注意を出さない
  assert.equal(ui.fetches.length, 0, 'selecting does not issue');
  assert.equal(ui.el('sttd-switch-notice').hidden, true, 'no reinstall notice for an empty switch');
  assert.equal(ui.el('sttd-method-code').checked, true);
  assert.equal(ui.el('sttd-method-apple').checked, false);
  assert.equal(ui.el('sttd-method-desc-code').hidden, false);
  assert.equal(ui.el('sttd-method-desc-apple').hidden, true);
  assert.equal(ui.el('sttd-code-panel').hidden, false);
  // 選択だけでは10分以内の入力案内を出さない（発行の説明だけ）
  assert.equal(ui.el('sttd-code-guide').hidden, true, 'no input guide before a code is issued');
  await ui.click('sttd-method-continue');
  assert.equal(ui.el('sttd-code-value').textContent, '012345');
  assert.equal(ui.el('sttd-code-guide').hidden, false, 'input guide shown after a successful issue');
  // 発行成功だけで、controllerの正規状態から手順2へ進み、追加方法を開く。コード未認証の間は通常の接続確認を出さない
  assert.equal(ui.stepState(2), 'current');
  assert.equal(ui.el('sttd-plugin-guide').open, true, 'plugin guide expanded');
  assert.equal(ui.el('sttd-refresh').hidden, true, 'normal connection check hidden before the code sign-in');
  assert.equal(ui.el('sttd-code-confirm').hidden, false);
  assert.ok(ui.el('sttd-plugin-step-3').textContent.includes('Connect with a code'), 'plugin guide matches the code method');
  assert.ok(!ui.el('sttd-plugin-step-3').textContent.includes('same Apple account'));
  for (const n of [3, 4, 5, 6]) assert.equal(ui.stepState(n), 'locked', `step ${n}`);
  assert.equal(ui.base.calls.loads, 0, 'no SDK before an explicit sign-in');
  assert.equal(ui.fetches.filter((f) => !f.url.startsWith('/v1/operator/')).length, 0, 'no upstream call');
  assert.equal(ui.el('sttd-apple-panel').hidden, true, 'code mode shows only code operations');
});

test('B2 confirm success signs in with the custom token and advances the console without reload or Apple', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? issuedJson() : activeJson()) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  await ui.click('sttd-code-confirm');
  assert.equal(ui.custom.calls, 1);
  assert.deepEqual(ui.custom.tokens, ['synthetic-custom-token']);
  assert.equal(ui.base.calls.popups, 0, 'no Apple popup');
  assert.equal(ui.stepState(1), 'done');
  assert.equal(ui.stepState(2), 'current');
  assert.equal(ui.el('sttd-login').hidden, true, 'signed in');
  assert.equal(ui.el('sttd-code-message').textContent, OPERATOR_TEXT.en.connected);
});

test('B3 switching method resets to step 1, locks later steps and closes the code session', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? issuedJson() : activeJson()) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  await ui.click('sttd-code-confirm');
  assert.equal(ui.stepState(2), 'current');
  const signOuts = ui.base.calls.signOuts;
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-apple');
  assert.equal(ui.stepState(1), 'current');
  for (const n of [2, 3, 4, 5, 6]) assert.equal(ui.stepState(n), 'locked', `step ${n}`);
  assert.equal(ui.base.auth.currentUser, null, 'the code session is closed');
  assert.ok(ui.base.calls.signOuts > signOuts);
  assert.equal(ui.el('sttd-switch-notice').hidden, false, 'reinstall guidance shown');
  assert.equal(ui.el('sttd-code-panel').hidden, true);
  assert.equal(ui.el('sttd-apple-panel').hidden, true, 'no separate Apple button; Continue starts Apple');
  assert.equal(ui.el('sttd-method-apple').checked, true);
  assert.equal(ui.el('sttd-method-code').checked, false);
  assert.equal(ui.el('sttd-method-desc-apple').hidden, false);
});

test('B7 the code input guide appears only after a successful issue; hidden on failure, cancel and method switch', async () => {
  let fail = true;
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? (fail ? { status: 503, json: { error: { code: 'issue_failed' } } } : issuedJson()) : { status: 200, json: { state: 'cancelled' } }) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  assert.equal(ui.el('sttd-code-guide').hidden, true, 'not shown after a failed issue');
  fail = false;
  await ui.click('sttd-method-continue');
  assert.equal(ui.el('sttd-code-guide').hidden, false);
  await ui.click('sttd-code-cancel');
  assert.equal(ui.el('sttd-code-guide').hidden, true, 'hidden after cancel');
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-continue');
  assert.equal(ui.el('sttd-code-guide').hidden, false);
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-apple');
  assert.equal(ui.el('sttd-code-guide').hidden, true, 'hidden after a method switch');
});

test('B8 after the code sign-in step 2 uses the normal connection check only (reissue and cancel stay); switching after an Apple sign-in shows the reinstall notice', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? issuedJson() : activeJson()) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  await ui.click('sttd-code-confirm');
  assert.equal(ui.el('sttd-refresh').hidden, false, 'normal connection check after the code sign-in');
  assert.equal(ui.el('sttd-code-confirm').hidden, true, 'no second (code) check');
  assert.deepEqual([ui.el('sttd-code-reissue').hidden, ui.el('sttd-code-cancel').hidden], [false, false], 'reissue and cancel stay in step 2');
  const apple = await runConsoleWithOperator({ onOperator: async () => issuedJson() });
  await apple.click('sttd-method-continue');
  assert.equal(apple.base.calls.popups, 1);
  assert.ok(apple.el('sttd-plugin-step-3').textContent.includes('same Apple account'), 'Apple method keeps the Apple guide');
  await apple.click('sttd-panel-1');
  await apple.click('sttd-method-code');
  assert.equal(apple.el('sttd-switch-notice').hidden, false, 'reinstall notice after an Apple sign-in');
});

test('B6 Apple with Continue starts the existing Apple sign-in; selecting alone loads nothing', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async () => issuedJson() });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-apple');
  assert.equal(ui.base.calls.loads, 0, 'selecting does not load the SDK');
  assert.equal(ui.base.calls.popups, 0);
  assert.equal(ui.fetches.length, 0);
  await ui.click('sttd-method-continue');
  assert.equal(ui.base.calls.popups, 1, 'Continue opens the Apple sign-in');
  assert.equal(ui.fetches.filter((f) => f.url.startsWith('/v1/operator/')).length, 0, 'no code issued for Apple');
});

test('B4 late issue/confirm results after a method switch are discarded', async () => {
  const issueHold = gate();
  let statusHold = null;
  let holdIssue = true;
  const ui = await runConsoleWithOperator({
    onOperator: async (action) => {
      if (action === 'issue') {
        if (holdIssue) await issueHold.promise;
        return issuedJson();
      }
      if (statusHold) await statusHold.promise;
      return activeJson();
    },
  });
  await ui.click('sttd-method-code');
  ui.el('sttd-method-continue').click();
  await settle();
  await ui.click('sttd-method-apple');
  issueHold.release();
  await settle();
  await settle();
  assert.equal(ui.stepState(2), 'locked', 'late issue does not unlock');
  assert.equal(ui.el('sttd-code-display').hidden, true);
  holdIssue = false;
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  statusHold = gate();
  ui.el('sttd-code-confirm').click();
  await settle();
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-apple');
  statusHold.release();
  await settle();
  await settle();
  assert.equal(ui.custom.calls, 0, 'no code sign-in after the switch');
  assert.equal(ui.stepState(1), 'current');
  assert.equal(ui.el('sttd-login').hidden, false);
});

test('B5 a slow custom-token SDK result after switching is signed out; a restored code session is not accepted as Apple', async () => {
  const ui = await runConsoleWithOperator({ onOperator: async (action) => (action === 'issue' ? issuedJson() : activeJson()) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  ui.custom.hold = gate();
  ui.el('sttd-code-confirm').click();
  await settle();
  await settle();
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-apple');
  ui.custom.hold.release();
  await settle();
  await settle();
  assert.equal(ui.custom.calls, 1);
  assert.equal(ui.base.auth.currentUser, null, 'late code session closed');
  assert.equal(ui.stepState(2), 'locked');

  const restored = await runConsoleWithOperator({ restoredCode: true, onOperator: async () => issuedJson() });
  await restored.click('sttd-login');
  assert.equal(restored.base.calls.popups, 1, 'Apple sign-in is explicit');
  assert.notEqual(restored.base.auth.currentUser?.uid, CODE_UID);
  assert.equal(restored.stepState(2), 'current');
});

test('B9 after the code sign-in a failed reissue keeps the connection; a successful reissue or cancel ends the old owner and the later steps through the controller', async () => {
  let reissue = 'fail';
  const ui = await runConsoleWithOperator({
    onOperator: async (action) => {
      if (action === 'issue') return issuedJson();
      if (action === 'reissue') return reissue === 'ok' ? issuedJson() : { status: 503, json: { error: { code: 'issue_failed' } } };
      if (action === 'cancel') return { status: 200, json: { state: 'cancelled' } };
      return activeJson();
    },
  });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  await ui.click('sttd-code-confirm');
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.el('sttd-login').hidden], ['done', 'current', true]);
  await ui.click('sttd-code-reissue');
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.el('sttd-login').hidden], ['done', 'current', true], 'a failed reissue keeps the current connection');
  assert.notEqual(ui.base.auth.currentUser, null);
  reissue = 'ok';
  const signOuts = ui.base.calls.signOuts;
  await ui.click('sttd-code-reissue');
  assert.equal(ui.base.auth.currentUser, null, 'the old code owner is signed out');
  assert.ok(ui.base.calls.signOuts > signOuts);
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui.stepState), ['ready', 'current', 'locked', 'locked', 'locked', 'locked'], 'the new code opens only step 2');
  assert.deepEqual([ui.el('sttd-code-confirm').hidden, ui.el('sttd-code-value').textContent], [false, '012345']);
  await ui.click('sttd-code-cancel');
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(ui.stepState), ['current', 'locked', 'locked', 'locked', 'locked', 'locked'], 'cancel locks step 2 and later');
  assert.equal(ui.el('sttd-code-reissue').hidden, true);
  assert.equal(ui.fetches.filter((f) => !f.url.startsWith('/v1/operator/')).length, 0, 'no upstream call');
});

const FAMILY = '12345678-1234-4123-8123-123456789abc';
const codeClaims = (over = {}) => ({ aud: WEB.projectId, iss: `https://securetoken.google.com/${WEB.projectId}`, sub: CODE_UID, firebase: { sign_in_provider: 'custom' }, sttd_dlc: 1, sttd_fam: FAMILY, ...over });

test('B10 skip in step 1 resumes a saved code sign-in only when the token claims match this deployment and the code method; no popup, sign-out, issue or code request; reissue/cancel/confirm stay hidden because the helper does not own that session', async () => {
  const ui = await runConsoleWithOperator({ restoredCode: true, restoredClaims: codeClaims(), onOperator: async () => issuedJson() });
  await ui.click('sttd-method-code');
  assert.equal(ui.fetches.length, 0, 'selecting does not issue');
  await ui.click('sttd-skip-1');
  assert.deepEqual([ui.stepState(1), ui.stepState(2)], ['skipped', 'current']);
  assert.deepEqual([ui.base.calls.popups, ui.base.calls.signOuts, ui.custom.calls, ui.fetches.length], [0, 0, 0, 0], 'no popup, sign-out, custom token or code request');
  assert.equal(ui.base.auth.currentUser.uid, CODE_UID);
  for (const id of ['sttd-code-reissue', 'sttd-code-cancel', 'sttd-code-confirm']) assert.equal(ui.el(id).hidden, true, `${id} hidden`);
  assert.equal(ui.el('sttd-refresh').hidden, false, 'the normal connection check is used');
  assert.deepEqual([ui.el('sttd-skipped-1').hidden, ui.el('sttd-skipped-1').textContent], [false, 'Skipped (unconfirmed)']);
  // 隠すだけでなく、handlerを直接呼んでもhelperが所有しないsessionへの照会・再発行・取消は要求0。
  ui.el('sttd-code-reissue').onclick();
  ui.el('sttd-code-confirm').onclick();
  ui.el('sttd-code-cancel').onclick();
  for (let i = 0; i < 4; i += 1) await settle();
  assert.deepEqual([ui.fetches.length, ui.custom.calls, ui.stepState(2)], [0, 0, 'current'], 'no code request from direct handler calls');
  for (const n of [3, 4, 5, 6, 7]) assert.equal(ui.stepState(n), 'locked', `step ${n}`);
  // UIDの接頭辞だけでは信用しない: marker・family・project・tenant・providerのどれかが違えば手順1に留まり、保存済みログインも消さない。
  for (const [name, claims] of [['marker', codeClaims({ sttd_dlc: undefined })], ['family', codeClaims({ sttd_fam: 'not-a-family' })], ['project', codeClaims({ aud: 'other-project' })], ['tenant', codeClaims({ firebase: { sign_in_provider: 'custom', tenant: 't1' } })], ['provider', codeClaims({ firebase: { sign_in_provider: 'apple.com' } })], ['subject', codeClaims({ sub: 'sttdc_' + 'B'.repeat(32) })]]) {
    const bad = await runConsoleWithOperator({ restoredCode: true, restoredClaims: claims, onOperator: async () => issuedJson() });
    await bad.click('sttd-method-code');
    await bad.click('sttd-skip-1');
    assert.deepEqual([bad.stepState(1), bad.stepState(2), bad.base.calls.signOuts, bad.base.calls.popups, bad.custom.calls, bad.fetches.length], ['current', 'locked', 0, 0, 0, 0], name);
    assert.equal(bad.base.auth.currentUser.uid, CODE_UID, `${name}: the saved sign-in is not signed out`);
  }
  // Apple方式で保存済みのコードログインを復元しようとしても通さない（Appleへの変換・popup・発行なし）。
  const apple = await runConsoleWithOperator({ restoredCode: true, restoredClaims: codeClaims(), onOperator: async () => issuedJson() });
  await apple.click('sttd-skip-1');
  assert.deepEqual([apple.stepState(2), apple.base.calls.popups, apple.base.calls.signOuts, apple.fetches.length], ['locked', 0, 0, 0]);
  // 復元の途中で方式を変えた古い結果は採らない。
  const hold = gate();
  const late = await runConsoleWithOperator({ restoredCode: true, restoredClaims: codeClaims(), restoredHold: hold, onOperator: async () => issuedJson() });
  await late.click('sttd-method-code');
  late.el('sttd-skip-1').click();
  await settle();
  await late.click('sttd-method-apple');
  hold.release();
  for (let i = 0; i < 4; i += 1) await settle();
  assert.deepEqual([late.stepState(1), late.stepState(2), late.fetches.length], ['current', 'locked', 0], 'the stale result unlocks nothing');
});

test('B11 a code issued on this page after a resume keeps its own controls and is not cancelled by the resume path', async () => {
  const ui = await runConsoleWithOperator({ restoredCode: true, restoredClaims: codeClaims(), onOperator: async (action) => (action === 'issue' ? issuedJson() : { status: 200, json: { state: 'pending' } }) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-method-continue');
  assert.equal(ui.stepState(2), 'current');
  const cancels = () => ui.fetches.filter((entry) => entry.url.endsWith('/cancel')).length;
  await ui.click('sttd-panel-1');
  await ui.click('sttd-skip-1');
  assert.deepEqual([ui.stepState(1), ui.stepState(2), cancels()], ['skipped', 'current', 0], 'resuming does not cancel the issued code');
  assert.deepEqual([ui.el('sttd-code-reissue').hidden, ui.el('sttd-code-cancel').hidden], [false, false], 'the code issued on this page keeps its controls');
});

test('B12 after a resume, an explicit Continue issues a new code and its normal exchange replaces the resumed owner: step 1 becomes done (not skipped), the code check is hidden and reissue/cancel work as the page-owned session', async () => {
  const ui = await runConsoleWithOperator({ restoredCode: true, restoredClaims: codeClaims(), onOperator: async (action) => (action === 'issue' || action === 'reissue' ? issuedJson() : activeJson()) });
  await ui.click('sttd-method-code');
  await ui.click('sttd-skip-1');
  assert.deepEqual([ui.stepState(1), ui.fetches.length], ['skipped', 0]);
  await ui.click('sttd-panel-1');
  await ui.click('sttd-method-continue');
  assert.deepEqual([ui.stepState(2), ui.fetches.filter((entry) => entry.url.endsWith('/issue')).length, ui.el('sttd-code-confirm').hidden], ['current', 1, false], 'the explicit Continue issues a page-owned code');
  await ui.click('sttd-code-confirm');
  assert.equal(ui.custom.calls, 1, 'the new code is exchanged once');
  assert.deepEqual([ui.stepState(1), ui.stepState(2), ui.el('sttd-skipped-1').hidden], ['done', 'current', true], 'the resume flag is cleared by the normal code sign-in');
  assert.deepEqual([ui.el('sttd-code-confirm').hidden, ui.el('sttd-code-reissue').hidden, ui.el('sttd-code-cancel').hidden], [true, false, false]);
  const reissues = () => ui.fetches.filter((entry) => entry.url.endsWith('/reissue')).length;
  await ui.click('sttd-code-reissue');
  assert.equal(reissues(), 1, 'reissue works for the page-owned session');
});