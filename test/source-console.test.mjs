// ローカル送信画面helper（src/console/local-server.ts）の登録開発者環境。実helperを127.0.0.1の一時portで起動し、上流は合成fetchだけ。
//   - 設定がある時だけ: POST /v2/commandsと接続承認（GET/POST /v1/source/approvals/{ref}）を固定上流向けに署名する（登録公開鍵で検証可能）。
//   - 照会/取消・接続状態/解除は署名しない（最小回復）。nonce・本文・methodの不備は上流0で拒否。任意宛先・任意headerの署名口は無い。
//   - 設定が無い通常consoleは従来どおり（承認route・scriptは404、署名header 0）。画面・応答に秘密鍵を出さない。
// 鍵は試験内で生成した合成鍵を一時fileへ書くだけ。実Cloud・資格・Dots・配送 0。

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { startLocalConsole } from '../dist/console/local-server.js';
import { parseSourceProof, verifySourceSignature } from '../dist/source/proof.js';

const SOURCE = 'src_abcdefghijklmnopqrstuvwxyz';
const API = 'https://api.example.org';
const MCP = 'https://connect.example.org';
const baseConfig = { apiOrigin: API, mcpOrigin: MCP, firebase: { apiKey: 'synthetic-key', authDomain: 'synthetic.example.org', projectId: 'sendtexttodots-test' } };

function keyFile(type = 'ed25519') {
  const dir = mkdtempSync(join(tmpdir(), 'sttd-source-'));
  const pair = type === 'ed25519' ? generateKeyPairSync('ed25519') : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const path = join(dir, 'key.pem');
  writeFileSync(path, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  return { dir, path, publicKey: pair.publicKey, pem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }) };
}

async function start(config) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, ...init });
    return { status: 200, headers: { get: (name) => (name === 'content-type' ? 'application/json' : null) }, body: null };
  };
  const console = await startLocalConsole({ config, port: 0, fetch });
  const request = (path, { method = 'GET', headers = {}, body } = {}) =>
    globalThis.fetch(`${console.origin}${path}`, { method, headers: { 'X-Sttd-Local-Nonce': console.nonce, Authorization: 'Bearer synthetic.id.token', ...headers }, body });
  return { console, calls, request };
}

function verifyCall(call, publicKey, audience, path, body, idempotencyKey) {
  const proof = parseSourceProof({ 'x-sttd-source': call.headers['x-sttd-source'], 'x-sttd-source-signature': call.headers['x-sttd-source-signature'] });
  assert.equal(proof.kind, 'present');
  const raw = publicKey.export({ format: 'jwk' }).x;
  const request = { audience, method: call.method, path, search: '', sourceId: SOURCE, body: Buffer.from(body), bearer: 'synthetic.id.token', idempotencyKey };
  assert.equal(verifySourceSignature(raw, request, proof.proof.claims, proof.proof.signature), true);
  // 別宛先へは流用できない。
  assert.equal(verifySourceSignature(raw, { ...request, audience: 'https://other.example.org' }, proof.proof.claims, proof.proof.signature), false);
}

test('登録開発者環境: 送信と接続承認だけを固定上流向けに署名し、照会/取消・接続状態は署名しない', async () => {
  const key = keyFile();
  const { console, calls, request } = await start({ ...baseConfig, source: { sourceId: SOURCE, keyFile: key.path } });
  try {
    const id = randomUUID();
    const body = JSON.stringify({ text: 'synthetic' });
    assert.equal((await request('/v2/commands', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': id }, body })).status, 200);
    verifyCall(calls[0], key.publicKey, API, '/v2/commands', body, id);
    assert.equal((await request('/v1/source/approvals/interaction-ref-1')).status, 200);
    assert.equal(calls[1].url, `${MCP}/v1/source/approvals/interaction-ref-1`);
    verifyCall(calls[1], key.publicKey, MCP, '/v1/source/approvals/interaction-ref-1', '', undefined);
    assert.equal((await request('/v1/source/approvals/interaction-ref-1', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"approve":true}' })).status, 200);
    verifyCall(calls[2], key.publicKey, MCP, '/v1/source/approvals/interaction-ref-1', '{"approve":true}', undefined);
    assert.equal((await request(`/v2/commands/${id}`)).status, 200);
    assert.equal((await request('/v1/web/connection')).status, 200);
    for (const call of calls.slice(3)) assert.equal(call.headers['x-sttd-source-signature'], undefined);
    // 本文の不備・nonce不一致・未知methodは上流0で拒否。
    const before = calls.length;
    assert.equal((await request('/v1/source/approvals/interaction-ref-1', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"approve":1234}' })).status, 400);
    assert.equal((await request('/v1/source/approvals/interaction-ref-1', { headers: { 'X-Sttd-Local-Nonce': 'stale' } })).status, 403);
    assert.equal((await request('/v1/source/approvals/interaction-ref-1', { method: 'DELETE' })).status, 405);
    assert.equal((await request('/v1/source/approvals/a/b')).status, 404);
    assert.equal(calls.length, before);
    // 画面は承認欄を持ち、秘密鍵を含まない。
    const page = await (await globalThis.fetch(`${console.origin}/console`)).text();
    assert.ok(page.includes('sttd-source'));
    assert.ok(!page.includes('PRIVATE KEY') && !page.includes(key.pem.split('\n')[1]));
    assert.equal((await globalThis.fetch(`${console.origin}/console/source.js`)).status, 200);
  } finally {
    await console.close();
    rmSync(key.dir, { recursive: true, force: true });
  }
});

test('通常console（登録環境なし）: 承認route・scriptは404、送信は従来どおり署名しない', async () => {
  const { console, calls, request } = await start(baseConfig);
  try {
    assert.equal((await request('/v1/source/approvals/interaction-ref-1')).status, 404);
    assert.equal((await globalThis.fetch(`${console.origin}/console/source.js`)).status, 404);
    const id = randomUUID();
    assert.equal((await request('/v2/commands', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': id }, body: '{"text":"x"}' })).status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].headers['x-sttd-source'], undefined);
    assert.equal(calls[0].headers['x-sttd-source-signature'], undefined);
    const page = await (await globalThis.fetch(`${console.origin}/console`)).text();
    assert.ok(!page.includes('id="sttd-source"'));
  } finally {
    await console.close();
  }
});

test('登録環境の鍵: Ed25519以外・読めないfile・不正な設定は起動しない', async () => {
  const ec = keyFile('ec');
  try {
    await assert.rejects(startLocalConsole({ config: { ...baseConfig, source: { sourceId: SOURCE, keyFile: ec.path } }, port: 0, fetch: async () => ({}) }));
    await assert.rejects(startLocalConsole({ config: { ...baseConfig, source: { sourceId: SOURCE, keyFile: join(ec.dir, 'missing.pem') } }, port: 0, fetch: async () => ({}) }));
    await assert.rejects(startLocalConsole({ config: { ...baseConfig, source: { sourceId: 'laptop', keyFile: ec.path } }, port: 0, fetch: async () => ({}) }));
    await assert.rejects(startLocalConsole({ config: { ...baseConfig, source: { sourceId: SOURCE, keyFile: ec.path, extra: 1 } }, port: 0, fetch: async () => ({}) }));
  } finally {
    rmSync(ec.dir, { recursive: true, force: true });
  }
});

// ---- 配信する実際の承認欄script（/console/source.js）を、合成DOM・合成Firebase SDK・合成fetchで実行する（実browser/実SDKの合格ではない） ----

const LOADER_LINE = 'const loadSdk = (url) => import(url);';

async function servedScript() {
  const key = keyFile();
  const { console } = await start({ ...baseConfig, source: { sourceId: SOURCE, keyFile: key.path } });
  try {
    return await (await globalThis.fetch(`${console.origin}/console/source.js`)).text();
  } finally {
    await console.close();
    rmSync(key.dir, { recursive: true, force: true });
  }
}

function deferred() {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
}

function element(extra = {}) {
  const handlers = {};
  return {
    value: '',
    disabled: false,
    textContent: '',
    dataset: {},
    addEventListener: (type, handler) => (handlers[type] = handler),
    fire: (type) => handlers[type]?.(),
    ...extra,
  };
}

/** 合成環境で配信scriptを実行する。SDKの遅延importの1行だけを合成loaderへ差し替える（他は配信されたbytesのまま）。 */
function runScript(script, { gate = {} } = {}) {
  assert.equal(script.split(LOADER_LINE).length, 2);
  assert.ok(!/^\s*import\s/m.test(script), 'no static import');
  const root = element({
    dataset: { sttdSourceNonce: 'nonce', sttdSourceFailed: 'failed', sttdSourceLogin: 'login', sttdSourceChecked: 'checked {client}', sttdSourceApproved: 'approved' },
  });
  const nodes = { 'sttd-source': root, 'sttd-source-ref': element(), 'sttd-source-check': element(), 'sttd-source-approve': element({ disabled: true }), 'sttd-source-message': element() };
  const user = (uid) => ({ uid, getIdToken: () => (gate.token ? gate.token.promise.then(() => `token-${uid}`) : Promise.resolve(`token-${uid}`)) });
  const users = { a: user('a'), b: user('b') };
  const auth = { currentUser: users.a, listener: null };
  const loads = [];
  const fetches = [];
  const sdk = {
    'firebase-app.js': { getApps: () => [{ name: '[DEFAULT]' }] },
    'firebase-auth.js': { getAuth: () => auth, onAuthStateChanged: (target, listener) => (auth.listener = listener) },
  };
  const load = async (url) => {
    loads.push(url);
    return sdk[url.split('/').pop()];
  };
  const fetch = async (url, init) => {
    fetches.push({ url, method: init.method, authorization: init.headers.Authorization });
    if (init.method === 'GET' && gate.get) await gate.get.promise;
    return { ok: true, json: async () => (init.method === 'GET' ? { client: 'Dots' } : { state: 'approved' }) };
  };
  new Function('document', 'fetch', '__load', script.replace(LOADER_LINE, 'const loadSdk = (url) => __load(url);'))({ getElementById: (id) => nodes[id] }, fetch, load);
  const type = (value) => {
    nodes['sttd-source-ref'].value = value;
    nodes['sttd-source-ref'].fire('input');
  };
  const switchUser = (next) => {
    auth.currentUser = next;
    auth.listener?.(next);
  };
  return { nodes, users, auth, loads, fetches, type, switchUser, check: () => nodes['sttd-source-check'].fire('click'), approve: () => nodes['sttd-source-approve'].fire('click') };
}

test('承認欄script: 初期表示ではSDK import・通信0、確認Aの後に入力Bへ変えると承認できない', async () => {
  const script = await servedScript();
  const env = runScript(script);
  assert.equal(env.loads.length, 0);
  assert.equal(env.fetches.length, 0);
  env.type('ref-a');
  await env.check();
  assert.equal(env.nodes['sttd-source-approve'].disabled, false);
  assert.ok(env.loads.every((url) => url.startsWith('https://www.gstatic.com/firebasejs/')));
  env.type('ref-b');
  assert.equal(env.nodes['sttd-source-approve'].disabled, true);
  await env.approve();
  assert.equal(env.fetches.filter((call) => call.method === 'POST').length, 0);
  // 正規: 確認した参照だけへ1回POSTし、2回目のclickは再確認が要る。
  await env.check();
  await Promise.all([env.approve(), env.approve()]);
  const posts = env.fetches.filter((call) => call.method === 'POST');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, '/v1/source/approvals/ref-b');
  await env.approve();
  assert.equal(env.fetches.filter((call) => call.method === 'POST').length, 1);
  assert.equal(env.nodes['sttd-source-message'].textContent, 'approved');
  assert.ok(!JSON.stringify(env.nodes).includes('token-'));
});

test('承認欄script: GET/token待機中の本人・入力変更と多重clickでは遅い結果を採用しない', async () => {
  const script = await servedScript();
  // GET待機中に本人が変わる。
  const gate = { get: deferred() };
  const env = runScript(script, { gate });
  env.type('ref-a');
  const first = env.check();
  await env.check(); // 確認中の2回目は無視
  await new Promise((resolve) => setImmediate(resolve));
  env.switchUser(env.users.b);
  gate.get.resolve();
  await first;
  assert.equal(env.fetches.filter((call) => call.method === 'GET').length, 1);
  assert.equal(env.nodes['sttd-source-approve'].disabled, true);
  await env.approve();
  assert.equal(env.fetches.filter((call) => call.method === 'POST').length, 0);

  // token待機中に入力が変わる: GETを送らない。
  const tokenGate = { token: deferred() };
  const other = runScript(script, { gate: tokenGate });
  other.type('ref-a');
  const pending = other.check();
  await new Promise((resolve) => setImmediate(resolve));
  other.type('ref-c');
  tokenGate.token.resolve();
  await pending;
  assert.equal(other.fetches.length, 0);
  assert.equal(other.nodes['sttd-source-approve'].disabled, true);
});
