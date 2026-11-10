// gateway-v1の接合: 実gateway（createGatewayRuntime＝entryと同じ組立て・合成IAM port）→ 所有127.0.0.1のbackend（実adapter）→ 既存handler。
//   API: 実createApiBackendServe → 実createIngressOperationDeliveryRequestHandler → 実source gate（開発者署名・SourceStore）→
//        実KmsRequestDeliveryService/Store（送出確定txでsource/Grantを再検査）。元の公開audienceへの署名がgatewayを通っても成立し、
//        source停止・署名不正・backend直行（transport不一致）では送出0。
//   MCP: 実startDevelopmentKmsConnectServer（transportAuthority＝backend）→ 実Provider・cookie・CSRF・PKCE・許可元承認・Grant。
//        元の公開URLでauthorize→login→承認GET/POST→consent→resumeのcode、未承認/停止sourceの拒否、MCP 401のWWW-Authenticate・
//        discoveryの公開resourceを保ち、応答にbackend名が出ないことを確かめる。
// 合成DB・合成KMS・合成本人・合成IAMだけ。実Cloud IAMの効力・実SDK通信・外部network・Dots・配送 0（Cloud IAMはT091相当の実配置で確認）。

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import http from 'node:http';
import { after, before, test } from 'node:test';

import { validateDeploymentConfig } from '../dist/config/validate.js';
import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { applyConsoleCors } from '../dist/deployment/console-cors.js';
import { createApiBackendServe } from '../dist/gateway/backend.js';
import { createGatewayRuntime } from '../dist/gateway/runtime.js';
import { CHATGPT_CIMD_CANDIDATE } from '../dist/oauth/cimd.js';
import { resourceFor } from '../dist/oauth/provider.js';
import { newSourceGeneration, newSourceId } from '../dist/source/admin.js';
import { signSourceRequest } from '../dist/source/proof.js';
import { createAppCheckVerifier } from '../dist/source/app-check.js';
import { closeAll, countListener, iamFetcher, listen, listenerCount, request, topologyConfig, topologyOf } from './fixtures/gateway-runtime.mjs';
import { createDeliveryRuntime, startConnectHttpRuntime } from './fixtures/source-runtime.mjs';

const API_PUBLIC = 'https://api.sttd-http.example.com';
const API_BACKEND = 'https://sendtexttodots-api-backend-123456789012.europe-west1.run.app';
const CONNECT_BACKEND = 'https://sendtexttodots-connect-backend-123456789012.europe-west1.run.app';
const API_BACKEND_HOST = new URL(API_BACKEND).host;
const CONNECT_BACKEND_HOST = new URL(CONNECT_BACKEND).host;
const PID = 'sendtexttodots-test';

/**
 * 検証済みの合成gateway-v1配置に、試験の公開origin（実connect fixtureのissuer・API署名の宛先）だけを重ねる（gatewayが読むのはHost照合だけ）。
 */
function configFor(connectOrigin) {
  const validated = validateDeploymentConfig(topologyConfig({ topology: topologyOf({ api: API_BACKEND, connect: CONNECT_BACKEND }) }));
  return { ...validated, api: { ...validated.api, publicOrigin: API_PUBLIC }, connect: { ...validated.connect, publicOrigin: connectOrigin } };
}

/** 固定CIMD候補clientの合成鍵（private_key_jwt。jwks_uriの合成応答だけに置く）。 */
const CLIENT_KEY = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const CLIENT_JWK = { ...CLIENT_KEY.publicKey.export({ format: 'jwk' }), kid: 'synthetic-client', alg: 'ES256', use: 'sig' };

let rt;
let connectGateway;
/** 通常direct配置（transportAuthorityなし）の同じ実connect server。MCPのhelperはrtをこれへ差し替えた時だけ直接送る。 */
let direct;
const sent = [];

before(async () => {
  rt = await startConnectHttpRuntime({ strict: true, transportAuthority: CONNECT_BACKEND_HOST, clientJwks: [CLIENT_JWK], echoChallenge: true });
  direct = await startConnectHttpRuntime({ strict: true, clientJwks: [CLIENT_JWK], echoChallenge: true });
  countListener();
  const config = configFor(rt.issuer);
  const iam = iamFetcher();
  const handler = createGatewayRuntime({
    role: 'connect',
    config,
    env: { K_SERVICE: config.connect.serviceName, K_REVISION: 'sendtexttodots-connect-00001-abc', K_CONFIGURATION: 'sendtexttodots-connect' },
    clock: { now: () => Date.now() },
    fetcher: iam.fetcher,
    transport: (options, onResponse) => {
      sent.push(options.headers);
      return http.request(options, onResponse);
    },
    connectTo: { host: '127.0.0.1', port: rt.port },
  });
  const { port } = await listen((req, res) => void handler.handle(req, res));
  connectGateway = { port, iam, handler, config };
});

after(async () => {
  await rt?.close();
  await direct?.close();
  await closeAll();
  assert.ok(listenerCount() <= 20);
});

// ---------- API ----------

test('API: 公開audienceへの正規source署名がgateway→実adapter→実handler→実配送storeで一回だけ成立し、停止・不正・直行は送出0', async () => {
  const w = createDeliveryRuntime({ audience: API_PUBLIC });
  const config = configFor('https://connect.sttd-http.example.com');
  const owner = w.enroll();
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const uid = 'uid-gateway-api';
  const source = {
    schemaVersion: 1,
    sourceId: newSourceId(),
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['send', 'keys'],
    publicKey: publicKey.export({ format: 'jwk' }).x,
    identityHash: connectIdentityHash(w.hasher, w.NS, { projectId: PID, uid }),
    expiresAt: w.clock.t + 3_600_000,
    createdAt: w.clock.t,
    updatedAt: w.clock.t,
  };
  assert.equal(await w.sources.create(source), 'created');
  // 購読Grantは接続承認したsource（connect操作）へ結ぶ（同意の最終txと同じ形）。
  const grantSource = { ...source, sourceId: newSourceId(), generation: newSourceGeneration(), operations: ['connect'], publicKey: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, expiresAt: null };
  assert.equal(await w.sources.create(grantSource), 'created');
  w.bindGrant(owner.grantId, grantSource);
  const counts = { identity: 0, handler: 0 };
  const identity = {
    projectId: PID,
    async verifyIdToken(token) {
      counts.identity += 1;
      if (token !== 'token.user.a') throw Object.assign(new Error('invalid'), { code: 'invalid' });
      return { projectId: PID, uid, authTimeSec: 1 };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const backend = createApiBackendServe({ transportAuthority: API_BACKEND_HOST, logicalAuthority: new URL(API_PUBLIC).host, clock: w.clock, cors: applyConsoleCors });
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async () => owner.ownerId,
    service: w.service,
    clock: w.clock,
    lifetime: new AbortController().signal,
    ingress: backend.ingress,
    sources: w.gate,
  });
  const seenAtBackend = [];
  const { port: backendPort } = await listen((req, res) => {
    seenAtBackend.push([...req.rawHeaders]);
    void backend.serve(req, res, (rq, rs) => ((counts.handler += 1), handler(rq, rs)));
  });
  const iam = iamFetcher();
  const gateway = createGatewayRuntime({
    role: 'api',
    config,
    env: { K_SERVICE: 'sendtexttodotsapi', K_REVISION: 'sendtexttodotsapi-00001-abc', K_CONFIGURATION: 'sendtexttodotsapi' },
    clock: { now: () => Date.now() },
    fetcher: iam.fetcher,
    transport: (options, onResponse) => http.request(options, onResponse),
    connectTo: { host: '127.0.0.1', port: backendPort },
  });
  const { port } = await listen((req, res) => void gateway.handle(req, res));

  const command = () => {
    const commandId = randomUUID();
    const iso = (ms) => new Date(ms).toISOString();
    return { commandId, body: JSON.stringify({ schemaVersion: 2, commandId, text: 'synthetic', createdAt: iso(w.clock.t), expiresAt: iso(w.clock.t + 60_000) }) };
  };
  const send = ({ commandId, body }, { tamper = false, signer = privateKey, extra = {} } = {}) => {
    const nowSec = Math.floor(w.clock.t / 1000);
    const signature = signSourceRequest(
      { audience: API_PUBLIC, method: 'POST', path: '/v2/commands', search: '', sourceId: source.sourceId, body: Buffer.from(body), bearer: 'token.user.a', idempotencyKey: commandId },
      { issuedAt: nowSec, expiresAt: nowSec + 60, nonce: randomBytes(16).toString('base64url') },
      signer,
    );
    return request(port, {
      method: 'POST',
      path: '/v2/commands',
      headers: {
        Host: new URL(API_PUBLIC).host,
        Authorization: 'Bearer token.user.a',
        'Content-Type': 'application/json',
        'Idempotency-Key': commandId,
        'X-STTD-Source': source.sourceId,
        'X-STTD-Source-Signature': signature,
        ...extra,
      },
      body: tamper ? body.replace('synthetic', 'tampered!') : body,
    });
  };

  // 正規: gatewayは本文・署名を変えず、外部の内部headerは作り直す。backendの実handlerで送出確定。
  const ok = await send(command(), { extra: { 'X-Serverless-Authorization': 'Bearer forged', 'X-STTD-Gateway-Budget-Ms': '99999', Forwarded: 'host=evil.example' } });
  assert.equal(ok.status, 200, ok.body);
  assert.equal(JSON.parse(ok.body).state, 'delivered');
  assert.equal(w.sent.length, 1);
  const last = seenAtBackend.at(-1).map((value) => value.toLowerCase());
  assert.equal(last.filter((value) => value === 'x-serverless-authorization').length, 1);
  assert.ok(!last.includes('bearer forged') && !last.includes('99999') && !last.includes('forwarded'));
  assert.equal(last[last.indexOf('host') + 1], API_BACKEND_HOST);
  assert.ok(!ok.body.includes(API_BACKEND_HOST));
  assert.equal(iam.calls.count, 1);
  assert.deepEqual(iam.calls.audiences, [API_BACKEND]);

  // 本文改変・別鍵の署名は実gateで403、送出0。
  const tampered = await send(command(), { tamper: true });
  assert.equal(tampered.status, 403);
  const otherKey = await send(command(), { signer: generateKeyPairSync('ed25519').privateKey });
  assert.equal(otherKey.status, 403);
  assert.equal(w.sent.length, 1);

  // 署名なしの要求はgatewayを通っても実gateで403（gatewayの通過・自己申告で許可しない）。
  const unsigned = await request(port, { method: 'POST', path: '/v2/commands', headers: { Authorization: 'Bearer token.user.a', 'Content-Type': 'application/json', 'Idempotency-Key': randomUUID() }, body: command().body });
  assert.equal(unsigned.status, 403);

  // sourceを停止すると、gateway経由の正規署名でも送出0（最終storeの拒否）。
  w.clock.t += 1_000;
  w.docs.set(`sttdConnect/${w.NS}/sources/${source.sourceId}`, { ...source, state: 'disabled', updatedAt: source.updatedAt + 1 });
  const stopped = await send(command());
  assert.notEqual(stopped.status === 200 ? JSON.parse(stopped.body).state : 'refused', 'delivered');
  assert.equal(w.sent.length, 1);

  // backendへの直行（公開Host・残時間なし）はadapterで400、handler・本人確認0。
  const handlerBefore = counts.handler;
  const identityBefore = counts.identity;
  const direct = await request(backendPort, { method: 'POST', path: '/v2/commands', headers: { Host: new URL(API_PUBLIC).host, Authorization: 'Bearer token.user.a' }, body: '{}' });
  assert.equal(direct.status, 400);
  const forgedBudget = await request(backendPort, { method: 'POST', path: '/v2/commands', headers: { Host: API_BACKEND_HOST, 'X-STTD-Gateway-Budget-Ms': '20001' }, body: '{}' });
  assert.equal(forgedBudget.status, 400);
  assert.equal(counts.handler, handlerBefore);
  assert.equal(counts.identity, identityBefore);
  assert.equal(iam.calls.count, 1, 'IAM token is shared in RAM');
});

// ---------- MCP ----------

const paths = (collection) => [...rt.docs.keys()].filter((path) => path.startsWith(`${rt.root}/${collection}/`));
const viaGateway = () => (rt === direct ? rt.browser() : rt.browser({ via: connectGateway.port }));

async function startFlow() {
  const b = viaGateway();
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CHATGPT_CIMD_CANDIDATE.clientId,
    redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri,
    scope: 'sttd:events',
    resource: resourceFor(rt.issuer),
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: randomUUID(),
  });
  const res = await b.request('GET', `/oauth/authorize?${params}`);
  assert.ok([302, 303].includes(res.status), `authorize redirects (${res.status})`);
  assert.ok(!JSON.stringify(res.headers).includes(CONNECT_BACKEND_HOST));
  const location = new URL(res.headers.location, rt.issuer);
  assert.equal(location.origin, rt.issuer, 'Location stays on the public origin');
  const uid = /\/interaction\/([A-Za-z0-9_-]+)$/.exec(location.pathname)?.[1];
  assert.ok(uid);
  assert.ok(Array.isArray(res.headers['set-cookie']) && res.headers['set-cookie'].length >= 2, 'multiple Set-Cookie are kept');
  return { b, uid, verifier };
}

async function login(flow, person) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  assert.equal(page.status, 200);
  assert.ok(!page.body.includes(CONNECT_BACKEND_HOST));
  const csrf = /data-sttd-csrf="([^"]+)"/.exec(page.body)?.[1];
  assert.ok(csrf);
  // 実画面が読むscriptも元の公開URLのgateway経由で200（兄弟pathは404）。
  const src = /<script[^>]*\ssrc="([^"]+)"/.exec(page.body)?.[1];
  assert.ok(src, 'interaction page references its script');
  const script = await flow.b.request('GET', new URL(src, rt.issuer).pathname);
  assert.equal(script.status, 200);
  assert.match(script.headers['content-type'], /javascript/);
  assert.equal((await flow.b.request('GET', '/interaction/app.css')).status, 404);
  const res = await flow.b.request('POST', `/interaction/${flow.uid}/login`, {
    headers: { 'Content-Type': 'application/json', Origin: rt.issuer },
    body: JSON.stringify({ csrf, idToken: person.idToken }),
  });
  assert.equal(res.status, 204, `login (${res.status})`);
}

async function consentPage(flow) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  return {
    status: page.status,
    csrf: /name="csrf" value="([^"]+)"/.exec(page.body)?.[1],
    receiverToken: /name="receiverToken" value="([^"]+)"/.exec(page.body)?.[1] ?? '',
    sourceState: /data-sttd-source-state="([a-z]+)"/.exec(page.body)?.[1] ?? null,
  };
}

function consent(flow, form) {
  return flow.b.request('POST', `/interaction/${flow.uid}/consent`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: rt.issuer },
    body: new URLSearchParams({ csrf: form.csrf ?? '', receiverToken: form.receiverToken ?? '' }).toString(),
  });
}

/** 許可元の承認GET/POST（署名の宛先は公開MCP origin）。gateway経由だけで送る。 */
function approval(method, uid, person, { body } = {}) {
  const path = `/v1/source/approvals/${uid}`;
  const nowSec = Math.floor(rt.clock.now() / 1000);
  const signature = signSourceRequest(
    { audience: rt.issuer, method, path, search: '', sourceId: person.record.sourceId, body: Buffer.from(body ?? ''), bearer: person.idToken, idempotencyKey: undefined },
    { issuedAt: nowSec, expiresAt: nowSec + 30, nonce: randomBytes(16).toString('base64url') },
    person.privateKey,
  );
  return viaGateway().request(method, path, {
    cookies: false,
    headers: { Authorization: `Bearer ${person.idToken}`, 'X-STTD-Source': person.record.sourceId, 'X-STTD-Source-Signature': signature, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body,
  });
}

const APPROVE = '{"approve":true}';

test('T105 C08 API gateway: 取消の429（Retry-After・no-store・body）をそのまま返し、backendへ一回だけ（自動再送0）、外部の期限headerは作り直す', async () => {
  const config = configFor('https://connect.sttd-http.example.com');
  const backend = createApiBackendServe({ transportAuthority: API_BACKEND_HOST, logicalAuthority: new URL(API_PUBLIC).host, clock: { now: () => Date.now() }, cors: applyConsoleCors });
  const seen = [];
  const { port: backendPort } = await listen((req, res) => {
    void backend.serve(req, res, (rq, rs) => {
      seen.push([rq.method, rq.url, rq.headers.host]);
      rs.writeHead(429, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '6' });
      rs.end(JSON.stringify({ error: { code: 'rate_limited', retryable: true } }));
    });
  });
  const iam = iamFetcher();
  const gateway = createGatewayRuntime({
    role: 'api',
    config,
    env: { K_SERVICE: 'sendtexttodotsapi', K_REVISION: 'sendtexttodotsapi-00001-abc', K_CONFIGURATION: 'sendtexttodotsapi' },
    clock: { now: () => Date.now() },
    fetcher: iam.fetcher,
    transport: (options, onResponse) => http.request(options, onResponse),
    connectTo: { host: '127.0.0.1', port: backendPort },
  });
  const { port } = await listen((req, res) => void gateway.handle(req, res));
  const commandId = randomUUID();
  const res = await new Promise((resolve, reject) => {
    const rq = http.request({ host: '127.0.0.1', port, method: 'POST', path: `/v2/commands/${commandId}/cancel`, headers: { Host: new URL(API_PUBLIC).host, Authorization: 'Bearer token.user.a', 'Content-Length': '0', 'X-STTD-Gateway-Deadline': '1' } }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    rq.on('error', reject);
    rq.end();
  });
  assert.equal(res.status, 429, res.body);
  assert.deepEqual([res.headers['retry-after'], res.headers['cache-control'], JSON.parse(res.body).error.code], ['6', 'no-store', 'rate_limited']);
  // 偽の期限header（過去）はgatewayが除去・再作成したので、backendは受け付けて一回だけ処理した。
  assert.deepEqual(seen, [['POST', `/v2/commands/${commandId}/cancel`, new URL(API_PUBLIC).host]]);
  assert.ok(!res.body.includes(API_BACKEND_HOST));
});

test('MCP: 元の公開URLでauthorize→login→承認GET/POST→元cookie/CSRFのconsent→resumeのcode、Grantとsource binding', async () => {
  const person = await rt.enrollPerson('uid-gateway-a');
  const flow = await startFlow();
  await login(flow, person);
  assert.equal((await consentPage(flow)).sourceState, 'waiting');
  const checked = await approval('GET', flow.uid, person);
  assert.equal(checked.status, 200, checked.body);
  assert.equal(JSON.parse(checked.body).resource, resourceFor(rt.issuer));
  const approved = await approval('POST', flow.uid, person, { body: APPROVE });
  assert.equal(approved.status, 200, approved.body);
  const confirmed = await consentPage(flow);
  assert.equal(confirmed.sourceState, 'confirmed');
  const metaBefore = paths('grantMeta').length;
  const done = await consent(flow, confirmed);
  assert.ok([302, 303].includes(done.status), `consent (${done.status})`);
  assert.equal(paths('grantMeta').length, metaBefore + 1);
  assert.ok(paths('sourceGrants').map((path) => rt.docs.get(path).data).some((binding) => binding.sourceId === person.record.sourceId));
  const resumed = await flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
  assert.ok([302, 303].includes(resumed.status), `resume (${resumed.status})`);
  const final = new URL(resumed.headers.location);
  assert.equal(`${final.origin}${final.pathname}`, CHATGPT_CIMD_CANDIDATE.redirectUri);
  assert.ok(final.searchParams.get('code'));
  assert.ok(!resumed.headers.location.includes(CONNECT_BACKEND_HOST));
  // 転送は全て固定backend Host・gatewayのIAM headerだけ（外部入力から選ばない）。
  for (const headers of sent) {
    const lower = headers.map((value) => String(value).toLowerCase());
    assert.equal(lower[lower.indexOf('host') + 1], CONNECT_BACKEND_HOST);
    assert.equal(lower.filter((value) => value === 'x-serverless-authorization').length, 1);
  }
  assert.equal(connectGateway.iam.calls.count, 1);
  assert.deepEqual(connectGateway.iam.calls.audiences, [CONNECT_BACKEND]);
});

test('MCP: 承認なし・停止sourceではGrantを作らない。MCP 401のWWW-Authenticateとdiscoveryの公開resourceを保つ', async () => {
  const person = await rt.enrollPerson('uid-gateway-b');
  const flow = await startFlow();
  await login(flow, person);
  const waiting = await consentPage(flow);
  const metaBefore = paths('grantMeta').length;
  const refused = await consent(flow, waiting);
  assert.ok(![302, 303].includes(refused.status) || paths('grantMeta').length === metaBefore);
  assert.equal(paths('grantMeta').length, metaBefore, 'no Grant without approval');
  // sourceを停止すると、gateway経由の正規署名でも承認できない。
  rt.write(`${rt.root}/sources/${person.record.sourceId}`, { ...person.record, state: 'disabled', updatedAt: person.record.updatedAt + 1 });
  const stopped = await approval('POST', flow.uid, person, { body: APPROVE });
  assert.notEqual(stopped.status, 200);
  assert.equal(paths('grantMeta').length, metaBefore);
  // MCPの未認証要求は既存の401とWWW-Authenticate（公開resource metadata）をそのまま返す。
  const mcp = await viaGateway().request('POST', '/mcp', { cookies: false, headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' });
  assert.equal(mcp.status, 401);
  assert.ok(mcp.headers['www-authenticate'].includes(rt.issuer));
  assert.ok(!mcp.headers['www-authenticate'].includes(CONNECT_BACKEND_HOST));
  const discovery = await viaGateway().request('GET', '/.well-known/oauth-protected-resource/mcp', { cookies: false });
  assert.equal(discovery.status, 200, discovery.body);
  assert.equal(JSON.parse(discovery.body).resource, resourceFor(rt.issuer));
  assert.ok(!discovery.body.includes(CONNECT_BACKEND_HOST));
  const metadata = await viaGateway().request('GET', '/.well-known/oauth-authorization-server', { cookies: false });
  if (metadata.status === 200) {
    assert.equal(JSON.parse(metadata.body).issuer, rt.issuer);
    assert.ok(!metadata.body.includes(CONNECT_BACKEND_HOST));
  }
  // 公開Hostでbackendへ直行するとadapterで固定400（transport authority不一致）。
  const direct = await rt.browser().request('GET', '/.well-known/oauth-protected-resource/mcp', { cookies: false });
  assert.equal(direct.status, 400);
});

// ---------- R1: App Check・code交換・refresh・認証済みMCP ----------

test('API App Check: gateway経由で実backend gateが要求ごとにconsume1回、再利用・停止・障害は送出0、gatewayはconsume0', async () => {
  const PN = '123456789012';
  const APP_ID = `1:${PN}:ios:0123abcd`;
  const consumed = new Set();
  const port0 = { calls: 0, down: false };
  const appCheckPort = {
    async verifyToken(token, options) {
      port0.calls += 1;
      assert.deepEqual(options, { consume: true });
      if (port0.down) throw new Error('synthetic app check down');
      const already = consumed.has(token);
      consumed.add(token);
      return { appId: APP_ID, token: { iss: `https://firebaseappcheck.googleapis.com/${PN}`, aud: [`projects/${PN}`], sub: APP_ID }, alreadyConsumed: already };
    },
  };
  const w = createDeliveryRuntime({ audience: API_PUBLIC, appCheck: createAppCheckVerifier({ appCheck: appCheckPort, projectNumber: PN, projectId: PID }) });
  const owner = w.enroll();
  const uid = 'uid-gateway-appcheck';
  const appSource = { schemaVersion: 1, sourceId: newSourceId(), kind: 'app', state: 'active', generation: newSourceGeneration(), operations: ['send'], appId: APP_ID, createdAt: w.clock.t, updatedAt: w.clock.t };
  assert.equal(await w.sources.create(appSource), 'created');
  // 購読Grantは別の（接続承認した）sourceへ結ぶ。
  const grantSource = {
    schemaVersion: 1,
    sourceId: newSourceId(),
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['connect'],
    publicKey: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x,
    identityHash: connectIdentityHash(w.hasher, w.NS, { projectId: PID, uid }),
    expiresAt: null,
    createdAt: w.clock.t,
    updatedAt: w.clock.t,
  };
  assert.equal(await w.sources.create(grantSource), 'created');
  w.bindGrant(owner.grantId, grantSource);
  const identity = { projectId: PID, verifyIdToken: async () => ({ projectId: PID, uid, authTimeSec: 1 }), accountStatus: async () => 'active' };
  const backend = createApiBackendServe({ transportAuthority: API_BACKEND_HOST, logicalAuthority: new URL(API_PUBLIC).host, clock: w.clock, cors: applyConsoleCors });
  const handler = createIngressOperationDeliveryRequestHandler({ identity, findOwner: async () => owner.ownerId, service: w.service, clock: w.clock, lifetime: new AbortController().signal, ingress: backend.ingress, sources: w.gate });
  const { port: backendPort } = await listen((req, res) => void backend.serve(req, res, (rq, rs) => handler(rq, rs)));
  const gateway = createGatewayRuntime({
    role: 'api',
    config: configFor('https://connect.sttd-http.example.com'),
    env: { K_SERVICE: 'sendtexttodotsapi', K_REVISION: 'sendtexttodotsapi-00001-abc', K_CONFIGURATION: 'sendtexttodotsapi' },
    clock: { now: () => Date.now() },
    fetcher: iamFetcher().fetcher,
    transport: (options, onResponse) => http.request(options, onResponse),
    connectTo: { host: '127.0.0.1', port: backendPort },
  });
  const { port } = await listen((req, res) => void gateway.handle(req, res));
  const send = (token) => {
    const commandId = randomUUID();
    const iso = (ms) => new Date(ms).toISOString();
    const body = JSON.stringify({ schemaVersion: 2, commandId, text: 'synthetic', createdAt: iso(w.clock.t), expiresAt: iso(w.clock.t + 60_000) });
    return request(port, {
      method: 'POST',
      path: '/v2/commands',
      headers: { Authorization: 'Bearer token.user.a', 'Content-Type': 'application/json', 'Idempotency-Key': commandId, 'X-STTD-Source': appSource.sourceId, 'X-Firebase-AppCheck': token },
      body,
    });
  };
  const ok = await send('aaa.bbb.ccc');
  assert.equal(ok.status, 200, ok.body);
  assert.equal(JSON.parse(ok.body).state, 'delivered');
  assert.equal(port0.calls, 1, 'consumed exactly once per request, only in the backend');
  assert.equal(w.sent.length, 1);
  // 同じtokenの再利用は消費済みで403、送出0。
  assert.equal((await send('aaa.bbb.ccc')).status, 403);
  assert.equal(port0.calls, 2);
  // App Checkの障害は503（開発者方式へ降格しない）、送出0。
  port0.down = true;
  assert.equal((await send('ddd.eee.fff')).status, 503);
  port0.down = false;
  // 要求sourceの停止は、正規の新tokenでも送出0。
  w.clock.t += 1_000;
  w.docs.set(`sttdConnect/${w.NS}/sources/${appSource.sourceId}`, { ...appSource, state: 'disabled', updatedAt: appSource.updatedAt + 1 });
  const stopped = await send('ggg.hhh.iii');
  assert.notEqual(stopped.status === 200 ? JSON.parse(stopped.body).state : 'refused', 'delivered');
  assert.equal(w.sent.length, 1);
});

/** 固定CIMD候補clientのprivate_key_jwt（ES256・Node crypto）。 */
function clientAssertion() {
  const part = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const iat = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'ES256', kid: CLIENT_JWK.kid, typ: 'JWT' })}.${part({ iss: CHATGPT_CIMD_CANDIDATE.clientId, sub: CHATGPT_CIMD_CANDIDATE.clientId, aud: `${rt.issuer}/oauth/token`, jti: randomUUID(), iat, exp: iat + 60 })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: CLIENT_KEY.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

function tokenRequest(fields) {
  const body = new URLSearchParams({
    ...fields,
    client_id: CHATGPT_CIMD_CANDIDATE.clientId,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion(),
  }).toString();
  return viaGateway().request('POST', '/oauth/token', { cookies: false, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
}

function mcpCall(accessToken, id, method, params = {}) {
  return viaGateway().request('POST', '/mcp', {
    cookies: false,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': method,
      ...(method === 'tools/call' ? { 'Mcp-Name': params.name } : {}),
    },
    // 2026-07-28版の要求ごとのenvelope（test/mcp-subscribe-audit.test.mjsと同じ最小の値）。
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
  });
}

test('MCP: gateway経由で元の公開URLのcode交換（PKCE・private_key_jwt）→refresh→認証済みMCP、source停止後のrefreshは拒否', async () => {
  const person = await rt.enrollPerson('uid-gateway-token');
  const flow = await startFlow();
  await login(flow, person);
  assert.equal((await approval('POST', flow.uid, person, { body: APPROVE })).status, 200);
  const done = await consent(flow, await consentPage(flow));
  assert.ok([302, 303].includes(done.status));
  const resumed = await flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
  const code = new URL(resumed.headers.location).searchParams.get('code');
  assert.ok(code);
  const exchanged = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: flow.verifier, resource: resourceFor(rt.issuer) });
  assert.equal(exchanged.status, 200, exchanged.body);
  const tokens = JSON.parse(exchanged.body);
  assert.ok(tokens.access_token && tokens.refresh_token);
  assert.ok(!exchanged.body.includes(CONNECT_BACKEND_HOST));
  const refreshed = await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, resource: resourceFor(rt.issuer) });
  assert.equal(refreshed.status, 200, refreshed.body);
  const rotated = JSON.parse(refreshed.body);
  assert.ok(rotated.access_token);
  // 認証済みMCP: serverが支持する版（MCP-Protocol-Version header・旧initialize手順なし）のtools/listが元resourceのBearerで成功する。
  const tools = await mcpCall(rotated.access_token, 2, 'tools/list');
  assert.equal(tools.status, 200, tools.body);
  // gateway-v1のMCP backendは受信状態照会の対象外: 一覧は従来どおり空で、tools/callは未提供（照会0・文書書込み0）。
  assert.deepEqual(JSON.parse(tools.body).result.tools, []);
  const allVersions = () => JSON.stringify([...rt.docs.keys()].sort().map((path) => [path, JSON.stringify(rt.docs.get(path))]));
  const statusCall = async (id, args) => {
    const before = allVersions();
    const response = await mcpCall(rotated.access_token, id, 'tools/call', { name: 'get_receiving_status', ...(args === undefined ? {} : { arguments: args }) });
    assert.equal(allVersions(), before, 'tools/call writes no document');
    return response;
  };
  const notProvided = await statusCall(20);
  assert.equal(JSON.parse(notProvided.body).error?.code, -32601, notProvided.body);
  assert.doesNotMatch(notProvided.body, /linked|subscribed|"state"/);
  // 購読保存: 実registration runtime/storeが合成callback challengeを確認して保存する（実HTTP 0）。
  const subscribe = (token, id) =>
    mcpCall(token, id, 'events/subscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url: `https://hooks.sttd-gateway.example/${randomBytes(6).toString('hex')}`, secret: `whsec_${randomBytes(32).toString('base64')}` } });
  const subscriptions = () => [...rt.docs.keys()].filter((path) => path.startsWith(`sttdAuth/${rt.SUB_NS}/subscriptions/`));
  const challengesBefore = rt.challenges.length;
  const saved = await subscribe(rotated.access_token, 3);
  assert.equal(saved.status, 200, saved.body);
  assert.match(saved.body, /"result"/);
  assert.doesNotMatch(saved.body, /"error"/);
  assert.equal(rt.challenges.length, challengesBefore + 1);
  assert.equal(subscriptions().length, 1, 'subscription saved in the real store');
  const stillNotProvided = await statusCall(21, {});
  assert.equal(JSON.parse(stillNotProvided.body).error?.code, -32601, stillNotProvided.body);
  assert.equal(rt.challenges.length, challengesBefore + 1, 'tools/call sends no challenge');
  const savedState = JSON.stringify(rt.docs.get(subscriptions()[0]).data);
  const refusedMcp = (res) => res.status !== 200 || !/"result"/.test(res.body);
  // Grantのsourceを停止すると、同じrefresh系列・access tokenは使えず、購読保存も拒否される。
  rt.write(`${rt.root}/sources/${person.record.sourceId}`, { ...person.record, state: 'disabled', updatedAt: person.record.updatedAt + 1 });
  const afterStop = await mcpCall(rotated.access_token, 4, 'tools/list');
  assert.ok(refusedMcp(afterStop), `${afterStop.status}`);
  assert.ok(refusedMcp(await subscribe(rotated.access_token, 5)));
  // 再有効化でも世代が違えば旧Grantは使えない。
  rt.write(`${rt.root}/sources/${person.record.sourceId}`, { ...person.record, generation: newSourceGeneration(), updatedAt: person.record.updatedAt + 2 });
  assert.ok(refusedMcp(await mcpCall(rotated.access_token, 6, 'tools/list')));
  assert.ok(refusedMcp(await subscribe(rotated.access_token, 7)));
  assert.equal(JSON.stringify(rt.docs.get(subscriptions()[0]).data), savedState, 'refused subscribe does not change the store');
  const refreshAfterStop = await tokenRequest({ grant_type: 'refresh_token', refresh_token: rotated.refresh_token ?? tokens.refresh_token, resource: resourceFor(rt.issuer) });
  assert.notEqual(refreshAfterStop.status, 200);
  // 同じcodeの再利用は拒否（Providerの単回利用。Providerは再利用で系列も失効させるため最後に確認）。
  assert.notEqual((await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: flow.verifier, resource: resourceFor(rt.issuer) })).status, 200);
});

test('MCP direct: 通常direct配置の実connect server・実Provider・実OAuth（PKCE・private_key_jwt）で、get_receiving_statusを1件発見し、引数省略/{}の実呼出しが実状態portの状態を返す（文書書込み0）', async () => {
  const gatewayRuntime = rt;
  rt = direct;
  try {
    const person = await rt.enrollPerson('uid-direct-status');
    const flow = await startFlow();
    await login(flow, person);
    assert.equal((await approval('POST', flow.uid, person, { body: APPROVE })).status, 200);
    const done = await consent(flow, await consentPage(flow));
    assert.ok([302, 303].includes(done.status));
    const resumed = await flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
    const code = new URL(resumed.headers.location).searchParams.get('code');
    assert.ok(code);
    const exchanged = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: flow.verifier, resource: resourceFor(rt.issuer) });
    assert.equal(exchanged.status, 200, exchanged.body);
    const token = JSON.parse(exchanged.body).access_token;
    assert.ok(token);
    // 発見: 読取り専用のget_receiving_status 1件だけ。
    const listed = await mcpCall(token, 1, 'tools/list');
    assert.equal(listed.status, 200, listed.body);
    const tools = JSON.parse(listed.body).result.tools;
    assert.deepEqual(
      tools.map((tool) => [tool.name, tool.annotations.readOnlyHint, tool.annotations.destructiveHint, tool.annotations.openWorldHint, JSON.stringify(tool.inputSchema)]),
      [['get_receiving_status', true, false, false, JSON.stringify({ type: 'object', properties: {}, additionalProperties: false })]],
    );
    const documents = () => JSON.stringify([...rt.docs.keys()].sort().map((path) => [path, JSON.stringify(rt.docs.get(path))]));
    const status = async (id, args) => {
      const before = documents();
      const challenges = rt.challenges.length;
      const response = await mcpCall(token, id, 'tools/call', { name: 'get_receiving_status', ...(args === undefined ? {} : { arguments: args }) });
      assert.equal(response.status, 200, response.body);
      assert.equal(documents(), before, 'the status query writes no document');
      assert.equal(rt.challenges.length, challenges, 'the status query sends no challenge');
      const { result } = JSON.parse(response.body);
      assert.deepEqual(result.content, [{ type: 'text', text: JSON.stringify(result.structuredContent) }]);
      return result.structuredContent;
    };
    // 実状態port（view.statusFor・strict source・実Grant開封）: 購読前は購読待ち、購読後は受信中。
    assert.deepEqual(await status(2), { state: 'linked' });
    const saved = await mcpCall(token, 3, 'events/subscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url: `https://hooks.sttd-direct.example/${randomBytes(6).toString('hex')}`, secret: `whsec_${randomBytes(32).toString('base64')}` } });
    assert.equal(saved.status, 200, saved.body);
    assert.match(saved.body, /"result"/);
    assert.deepEqual(await status(4, {}), { state: 'subscribed' });
    assert.deepEqual(await status(5), { state: 'subscribed' });
    // sourceの停止後は認証で拒否され、状態は出ない。
    rt.write(`${rt.root}/sources/${person.record.sourceId}`, { ...person.record, state: 'disabled', updatedAt: person.record.updatedAt + 1 });
    const stopped = await mcpCall(token, 6, 'tools/call', { name: 'get_receiving_status' });
    assert.ok(stopped.status !== 200 || !/"result"/.test(stopped.body), `${stopped.status}`);
    assert.doesNotMatch(stopped.body, /subscribed|linked/);
  } finally {
    rt = gatewayRuntime;
  }
});
