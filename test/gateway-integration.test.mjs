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
import { createDeliveryRuntime, createResolverRuntime, startConnectHttpRuntime, syntheticFirebaseToken } from './fixtures/source-runtime.mjs';
import { REVIEWER_GRANT_TTL_MS } from '../dist/access/policy.js';
import { createFirebaseAdminVerifier } from '../dist/identity/firebase.js';

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
/** 審査・テスト専用ログインを有効にした通常direct配置（compatible・実verifier）。 */
let reviewerRt;
const REVIEWER_UID = 'ReviewerSyntheticUid0001';
const SAMPLE_DESTINATION = 'https://hooks.sttd-review.example/sample';
/** T-277の初回固定runtime（合成のオリジンだけ。実受信先の値は使わない）。 */
let firstRt;
let firstWindow;
const FIRST_ORIGIN = 'https://hooks.sttd-first.example';
const FIRST_UIDS = ['FirstReviewerSynthetic01', 'FirstReviewerSynthetic02', 'FirstReviewerSynthetic03', 'FirstReviewerSynthetic04'];
const sent = [];

before(async () => {
  rt = await startConnectHttpRuntime({ strict: true, transportAuthority: CONNECT_BACKEND_HOST, clientJwks: [CLIENT_JWK], echoChallenge: true });
  gatewayRt = rt;
  direct = await startConnectHttpRuntime({ strict: true, clientJwks: [CLIENT_JWK], echoChallenge: true });
  reviewerRt = await startConnectHttpRuntime({ strict: false, clientJwks: [CLIENT_JWK], echoChallenge: true, reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE_DESTINATION] } });
  // T-277: 初回固定（合成オリジン・起動時から10分の絶対時間枠）。
  const opened = Date.now();
  firstWindow = { startsAt: opened - 1_000, endsAt: opened + 10 * 60_000 };
  firstRt = await startConnectHttpRuntime({
    strict: false,
    clientJwks: [CLIENT_JWK],
    echoChallenge: true,
    reviewer: { uids: FIRST_UIDS, firstDestination: { origin: FIRST_ORIGIN, ...firstWindow } },
  });
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
  await reviewerRt?.close();
  await firstRt?.close();
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
/** gateway経由はgateway-v1のruntime（最初のrt）だけ。他（direct・審査・初回固定・試験内の専用runtime）は直接送る。 */
let gatewayRt;
const viaGateway = () => (rt !== gatewayRt ? rt.browser() : rt.browser({ via: connectGateway.port }));

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

// ---------- T-274 審査・テスト専用ログイン（合成の本人・合成DB・合成KMSだけ。実Firebase・実Cloud・実配送0） ----------

/** 審査runtimeでの1つの接続（実Provider・cookie・CSRF・PKCE）。entryはlogin/reviewer。 */
async function reviewerFlowLogin(idToken, entry) {
  const flow = await startFlow();
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  assert.equal(page.status, 200);
  const csrf = /data-sttd-csrf="([^"]+)"/.exec(page.body)?.[1];
  assert.ok(csrf);
  const res = await flow.b.request('POST', `/interaction/${flow.uid}/${entry}`, {
    headers: { 'Content-Type': 'application/json', Origin: rt.issuer },
    body: JSON.stringify({ csrf, idToken }),
  });
  return { flow, page, res };
}

async function reviewerConsentAndExchange(flow) {
  const form = await consentPage(flow);
  assert.match(form.receiverToken, /^[a-f0-9]{64}$/, 'receiver snapshot is bound to this consent');
  const done = await consent(flow, form);
  assert.ok([302, 303].includes(done.status), `consent (${done.status})`);
  const resumed = await flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
  const code = new URL(resumed.headers.location).searchParams.get('code');
  assert.ok(code);
  return tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: flow.verifier, resource: resourceFor(rt.issuer) });
}

const statusOf = async (token, id) => {
  const response = await mcpCall(token, id, 'tools/call', { name: 'get_receiving_status' });
  return response.status === 200 && /"result"/.test(response.body) ? JSON.parse(response.body).result.structuredContent : { refused: response.status, body: response.body };
};
const subscribeTo = (token, id, url) =>
  mcpCall(token, id, 'events/subscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url, secret: `whsec_${randomBytes(32).toString('base64')}` } });
const reviewerToken = (sub, provider, authTimeSec, aud) => syntheticFirebaseToken({ sub, provider, authTimeSec, aud });

test('T-274 R1 審査入口: 明示選択の入口だけで事前登録UID・password・同projectを受け、通常入口・他provider・未登録・別projectは拒否。同意→交換→get_receiving_status、購読はサンプル受信先だけ', async () => {
  const saved = rt;
  rt = reviewerRt;
  try {
    const nowSec = () => Math.floor(rt.clock.now() / 1000);
    rt.allow(REVIEWER_UID);
    const normalUid = 'NormalGoogleSynthetic001';
    rt.allow(normalUid);

    // 入口の表示: 機能onで審査の入口ボタンを置き、入力欄の区画は閉じたまま（scriptが明示選択で開く）。
    const probe = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'google.com', nowSec()), 'login');
    assert.match(probe.page.body, /data-sttd-reviewer="on"/);
    assert.match(probe.page.body, /<section id="sttd-reviewer-section" aria-labelledby="sttd-reviewer-heading" hidden>/);
    // 通常入口: 審査UIDはGoogle（同じUIDの別provider）でもpasswordでも拒否。未登録のpasswordも従来どおり拒否。
    assert.equal(probe.res.status, 401, probe.res.body);
    assert.equal((await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', nowSec()), 'login')).res.status, 401);
    assert.equal((await reviewerFlowLogin(reviewerToken('UnregisteredPassword0001', 'password', nowSec()), 'login')).res.status, 401);
    // 審査入口: Google・Apple・通常利用者・未登録password・別project・customは拒否。
    const refused = [
      [reviewerToken(REVIEWER_UID, 'google.com', nowSec()), 'reviewer uid via google'],
      [reviewerToken(REVIEWER_UID, 'apple.com', nowSec()), 'reviewer uid via apple'],
      [reviewerToken(normalUid, 'google.com', nowSec()), 'normal google user'],
      [reviewerToken('UnregisteredPassword0001', 'password', nowSec()), 'unregistered password uid'],
      [reviewerToken(REVIEWER_UID, 'password', nowSec(), 'other-sttd-project'), 'other project'],
      [reviewerToken(REVIEWER_UID, 'custom', nowSec()), 'custom provider'],
    ];
    for (const [token, label] of refused) assert.equal((await reviewerFlowLogin(token, 'reviewer')).res.status, 401, label);
    // 更新済みのID tokenならauth_timeから24時間を過ぎても通常のログイン規則を使う。
    const stale = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', nowSec() - REVIEWER_GRANT_TTL_MS / 1000 - 1), 'reviewer');
    assert.equal(stale.res.status, 204, stale.res.body);
    assert.equal(paths('grantMeta').length, 0);

    // 正常: 審査入口・password・事前登録UID。
    const authTimeSec = nowSec();
    const ok = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', authTimeSec), 'reviewer');
    assert.equal(ok.res.status, 204, ok.res.body);
    const exchanged = await reviewerConsentAndExchange(ok.flow);
    assert.equal(exchanged.status, 200, exchanged.body);
    const tokens = JSON.parse(exchanged.body);
    const metas = paths('grantMeta').map((path) => rt.docs.get(path).data);
    assert.equal(metas.length, 1);
    assert.equal(metas[0].reviewerExpiresAt, undefined, 'new reviewer grant has standard OAuth lifetime');
    assert.equal(paths('owners').filter((path) => rt.docs.get(path).data.loginKind === 'reviewer').length, 1, 'one dedicated reviewer owner');

    assert.deepEqual(await statusOf(tokens.access_token, 1), { state: 'linked' });
    // 一般の受信先への購読は送出・保存の前に拒否（challenge 0）。サンプル受信先だけ成立する。
    const challenges = rt.challenges.length;
    const general = await subscribeTo(tokens.access_token, 2, 'https://hooks.sttd-review.example/general');
    assert.doesNotMatch(general.body, /"result"/, general.body);
    assert.equal(rt.challenges.length, challenges, 'no challenge to a general destination');
    const sample = await subscribeTo(tokens.access_token, 3, SAMPLE_DESTINATION);
    assert.match(sample.body, /"result"/, sample.body);
    assert.deepEqual(await statusOf(tokens.access_token, 4), { state: 'subscribed' });
    // 解除も一般の受信先は拒否、サンプル受信先は通常の手順で成立し、接続は維持（linked）。
    const unsubscribeGeneral = await mcpCall(tokens.access_token, 5, 'events/unsubscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url: 'https://hooks.sttd-review.example/general' } });
    assert.doesNotMatch(unsubscribeGeneral.body, /"result"/, unsubscribeGeneral.body);
    const unsubscribe = await mcpCall(tokens.access_token, 6, 'events/unsubscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url: SAMPLE_DESTINATION } });
    assert.match(unsubscribe.body, /"result"/, unsubscribe.body);
    assert.deepEqual(await statusOf(tokens.access_token, 7), { state: 'linked' });

    // 通常のGoogle利用者は同じ配置でも従来どおり（審査の制約を受けない・一般の受信先へ購読できる・Grantは期限を持たない）。
    const normal = await reviewerFlowLogin(reviewerToken(normalUid, 'google.com', nowSec()), 'login');
    assert.equal(normal.res.status, 204, normal.res.body);
    const normalTokens = JSON.parse((await reviewerConsentAndExchange(normal.flow)).body);
    const normalSaved = await subscribeTo(normalTokens.access_token, 8, `https://hooks.sttd-review.example/${randomBytes(6).toString('hex')}`);
    assert.match(normalSaved.body, /"result"/, normalSaved.body);
    assert.equal(paths('grantMeta').filter((path) => rt.docs.get(path).data.reviewerExpiresAt === undefined).length, 2);
  } finally {
    rt = saved;
  }
});

test('T-274 R2 移行前の審査Grantの24時間失効は交換・refresh・実行に残り、再ログインで新しい通常期限のGrantを発行する', async () => {
  const saved = rt;
  rt = reviewerRt;
  try {
    const nowSec = () => Math.floor(rt.clock.now() / 1000);
    rt.allow(REVIEWER_UID);
    // auth_timeが期限の60秒前（ID tokenは更新済みの想定）のログイン。
    const authTimeSec = nowSec() - REVIEWER_GRANT_TTL_MS / 1000 + 60;
    const markLegacy = () => {
      for (const path of paths('grantMeta')) {
        const data = rt.docs.get(path).data;
        if (data.authTimeSec === authTimeSec) rt.write(path, { ...data, reviewerExpiresAt: authTimeSec * 1000 + REVIEWER_GRANT_TTL_MS });
      }
    };
    const first = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', authTimeSec), 'reviewer');
    assert.equal(first.res.status, 204, first.res.body);
    const firstTokens = JSON.parse((await reviewerConsentAndExchange(first.flow)).body);
    markLegacy();
    assert.deepEqual(await statusOf(firstTokens.access_token, 1), { state: 'linked' });
    const refreshed = await tokenRequest({ grant_type: 'refresh_token', refresh_token: firstTokens.refresh_token, resource: resourceFor(rt.issuer) });
    assert.equal(refreshed.status, 200, refreshed.body);
    const rotated = JSON.parse(refreshed.body);
    const expiries = () => paths('grantMeta').map((path) => rt.docs.get(path).data.reviewerExpiresAt).filter((value) => value !== undefined);
    const before = expiries();
    assert.ok(before.includes(authTimeSec * 1000 + REVIEWER_GRANT_TTL_MS), 'refresh keeps the original expiry');

    // 期限の前に未交換のcodeを用意する（期限後の交換の拒否を見る）。
    const pending = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', authTimeSec), 'reviewer');
    assert.equal(pending.res.status, 204);
    const done = await consent(pending.flow, await consentPage(pending.flow));
    const resumed = await pending.flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
    const pendingCode = new URL(resumed.headers.location).searchParams.get('code');
    assert.ok(pendingCode);
    markLegacy();

    // 61秒進める（access tokenの寿命内・refresh tokenの窓内でも、Grantの期限で止まる）。
    rt.offset.ms += 61_000;
    const expiredStatus = await statusOf(rotated.access_token, 2);
    assert.ok(expiredStatus.refused !== undefined, JSON.stringify(expiredStatus));
    assert.doesNotMatch(expiredStatus.body, /linked|subscribed/);
    assert.doesNotMatch((await subscribeTo(rotated.access_token, 3, SAMPLE_DESTINATION)).body, /"result"/, 'no subscribe after expiry');
    assert.notEqual((await tokenRequest({ grant_type: 'refresh_token', refresh_token: rotated.refresh_token, resource: resourceFor(rt.issuer) })).status, 200, 'refresh after expiry');
    const late = await tokenRequest({ grant_type: 'authorization_code', code: pendingCode, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: pending.flow.verifier, resource: resourceFor(rt.issuer) });
    assert.notEqual(late.status, 200, 'code exchange after expiry');

    // 新しい接続のGrantには専用期限がなく、既に失効したGrantは戻らない。
    const again = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', nowSec()), 'reviewer');
    assert.equal(again.res.status, 204, again.res.body);
    const againTokens = JSON.parse((await reviewerConsentAndExchange(again.flow)).body);
    assert.deepEqual(await statusOf(againTokens.access_token, 4), { state: 'linked' });
    for (const value of before) assert.ok(expiries().includes(value), 'earlier expiries are unchanged');
    assert.ok((await statusOf(rotated.access_token, 5)).refused !== undefined, 'the old grant stays expired');
  } finally {
    rt = saved;
  }
});

test('T-274 R3 実verifier・接続保存の判定: 標準構成は審査off、審査UIDは通常検証で全provider拒否、配送・購読・照会が使うgrantUseDecisionは期限後denied', async () => {
  const projectId = 'sttd-unit-review';
  const auth = {
    async verifyIdToken(token) {
      const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      return { aud: projectId, iss: `https://securetoken.google.com/${projectId}`, sub: claims.sub, auth_time: claims.authTimeSec, firebase: { sign_in_provider: claims.provider } };
    },
    async getUser() {
      return { disabled: false };
    },
  };
  const t = (sub, provider) => reviewerToken(sub, provider, 1_900_000_000);
  // 標準構成: 審査の口なし・passwordは従来どおり拒否。
  const standard = createFirebaseAdminVerifier({ auth, projectId });
  assert.equal(standard.verifyReviewerIdToken, undefined);
  await assert.rejects(standard.verifyIdToken(t(REVIEWER_UID, 'password')), { code: 'wrong_provider' });
  // 審査UIDを登録した配置: 通常検証（API・送信画面・MCPの通常入口が共有）は同じUIDをApple/Google/passwordで受けない。
  const verifier = createFirebaseAdminVerifier({ auth, projectId, reviewerUids: [REVIEWER_UID] });
  for (const provider of ['apple.com', 'google.com', 'password']) await assert.rejects(verifier.verifyIdToken(t(REVIEWER_UID, provider)), { code: 'wrong_provider' }, provider);
  assert.equal((await verifier.verifyIdToken(t('OrdinaryAppleSynthetic01', 'apple.com'))).uid, 'OrdinaryAppleSynthetic01');
  assert.equal((await verifier.verifyReviewerIdToken(t(REVIEWER_UID, 'password'))).method, 'reviewer');
  await assert.rejects(verifier.verifyReviewerIdToken(t('OrdinaryAppleSynthetic01', 'password')), { code: 'wrong_provider' });
  for (const bad of [[], ['short'], [`sttdc_${'a'.repeat(32)}`], [REVIEWER_UID, REVIEWER_UID]]) assert.throws(() => createFirebaseAdminVerifier({ auth, projectId, reviewerUids: bad }));

  // 配送（KmsRequestDeliveryStore）・購読保存・状態照会の最終txが呼ぶ実ConnectStorage.grantUseDecision。
  const runtime = createResolverRuntime({ strict: false });
  try {
    const ownerId = randomUUID();
    const generation = randomUUID();
    const access = { exists: true, data: { version: 1, state: 'active', generation, updatedAt: 1 } };
    const nowMs = Date.now();
    const authTimeSec = Math.floor(nowMs / 1000) - REVIEWER_GRANT_TTL_MS / 1000 + 30;
    const meta = { ownerId, authTimeSec, createdAt: nowMs, accessGeneration: generation, reviewerExpiresAt: authTimeSec * 1000 + REVIEWER_GRANT_TTL_MS };
    assert.equal(runtime.connect.grantUseDecision(access, { exists: true, data: meta }, ownerId), 'allowed');
    assert.equal(runtime.connect.grantUseDecision(access, { exists: true, data: { ...meta, reviewerExpiresAt: meta.reviewerExpiresAt + 1 } }, ownerId), 'unavailable', 'an extended expiry is malformed');
    const expired = { ...meta, authTimeSec: authTimeSec - 60, reviewerExpiresAt: (authTimeSec - 60) * 1000 + REVIEWER_GRANT_TTL_MS };
    assert.equal(runtime.connect.grantUseDecision(access, { exists: true, data: expired }, ownerId), 'denied');
    const ordinary = { ownerId, authTimeSec, createdAt: nowMs, accessGeneration: generation };
    assert.equal(runtime.connect.grantUseDecision(access, { exists: true, data: ordinary }, ownerId), 'allowed', 'ordinary grants are unchanged');
  } finally {
    runtime.dispose();
  }
});

test('T-274 R4 停止の区別: 製品の権限停止（利用許可disabled）は発行済みaccess tokenの実行・refreshを即時に止め、再許可でも旧Grantは戻らない。Firebase側の停止だけではrefresh・交換は止まるが発行済みaccess tokenの実行は止まらない（実測）', async () => {
  const saved = rt;
  rt = reviewerRt;
  try {
    const nowSec = () => Math.floor(rt.clock.now() / 1000);
    const identityHash = rt.allow(REVIEWER_UID);
    const accessPath = `${rt.root}/access/${identityHash}`;
    const login = async () => {
      const flow = await reviewerFlowLogin(reviewerToken(REVIEWER_UID, 'password', nowSec()), 'reviewer');
      assert.equal(flow.res.status, 204, flow.res.body);
      const exchanged = await reviewerConsentAndExchange(flow.flow);
      assert.equal(exchanged.status, 200, exchanged.body);
      return JSON.parse(exchanged.body);
    };
    // 製品の権限停止（運営者の利用許可をdisabledへ。管理CLIと同じ新世代の遷移）。
    const stopped = await login();
    assert.deepEqual(await statusOf(stopped.access_token, 1), { state: 'linked' });
    const record = rt.docs.get(accessPath).data;
    rt.write(accessPath, { ...record, state: 'disabled', generation: randomUUID(), updatedAt: record.updatedAt + 1 });
    const afterStop = await statusOf(stopped.access_token, 2);
    assert.ok(afterStop.refused !== undefined, JSON.stringify(afterStop));
    assert.doesNotMatch(afterStop.body, /linked|subscribed/);
    assert.notEqual((await tokenRequest({ grant_type: 'refresh_token', refresh_token: stopped.refresh_token, resource: resourceFor(rt.issuer) })).status, 200, 'refresh after the stop');
    // 再許可（新しい世代）でも旧Grantの発行済みtokenは使えない。
    rt.allow(REVIEWER_UID);
    assert.ok((await statusOf(stopped.access_token, 3)).refused !== undefined, 'old grant stays refused after re-allow');

    // Firebase側の停止（アカウントdisabled＝accountStatusの拒否）だけ。
    const firebaseOnly = await login();
    rt.accountStates.set(REVIEWER_UID, 'disabled');
    try {
      assert.notEqual((await tokenRequest({ grant_type: 'refresh_token', refresh_token: firebaseOnly.refresh_token, resource: resourceFor(rt.issuer) })).status, 200, 'refresh refused by the Firebase account state');
      // 実測: 発行済みaccess tokenでの実行は、Firebaseの状態を要求ごとに照会しないため、access tokenの期限まで続く。
      assert.deepEqual(await statusOf(firebaseOnly.access_token, 4), { state: 'linked' });
    } finally {
      rt.accountStates.delete(REVIEWER_UID);
    }
  } finally {
    rt = saved;
  }
});

test('T-274 R5 起動時の構成の不一致: 審査の構成に対し共通verifierに審査口が無い、strictの許可元承認と同時、のどちらも接続serverは起動せず固定の設定error', async () => {
  const destinations = [SAMPLE_DESTINATION];
  await assert.rejects(startConnectHttpRuntime({ strict: false, reviewer: { uids: undefined, destinations } }), { name: 'KmsConnectServerConfigError' }, 'verifier without the reviewer check');
  await assert.rejects(startConnectHttpRuntime({ strict: true, reviewer: { uids: [REVIEWER_UID], destinations } }), { name: 'KmsConnectServerConfigError' }, 'strict source authorization');
  await assert.rejects(startConnectHttpRuntime({ strict: false, reviewer: { uids: [REVIEWER_UID], destinations: ['http://hooks.sttd-review.example/sample'] } }), { name: 'KmsConnectServerConfigError' }, 'non-https destination');
});

test('T-274 R6 一般の入口（送信API・接続状態/解除・許可元承認が使うfindOwner）は、審査ownerを本人確認の方式・構成に関わらず引かない', async () => {
  const runtime = createResolverRuntime({ strict: false });
  try {
    const projectId = 'demo-sttd-source-runtime';
    const generation = randomUUID();
    const hashOf = (uid) => runtime.hasher.hash(`t256:${runtime.NS}:identity`, `${projectId}\0${uid}`);
    for (const uid of [REVIEWER_UID, 'OrdinaryAppleSynthetic01']) {
      runtime.db.docs.set(`sttdConnect/${runtime.NS}/access/${hashOf(uid)}`, { version: 1, state: 'active', generation, updatedAt: 1 });
    }
    const authTimeSec = Math.floor(Date.now() / 1000);
    const reviewer = { projectId, uid: REVIEWER_UID, authTimeSec, method: 'reviewer' };
    const ordinary = { projectId, uid: 'OrdinaryAppleSynthetic01', authTimeSec };
    const admitted = await runtime.ctx.run(runtime.op(), () => runtime.connect.resolveOwner(reviewer));
    assert.equal(admitted.kind, 'admitted');
    assert.equal(await runtime.ctx.run(runtime.op(), () => runtime.connect.isReviewerOwner(admitted.ownerId)), true);
    // 構成の不一致で一般verifierが同じUIDを通してしまった場合（Google・Apple扱い）も、審査方式でも、一般の入口はownerを返さない。
    for (const identity of [{ projectId, uid: REVIEWER_UID, authTimeSec, method: 'google' }, { projectId, uid: REVIEWER_UID, authTimeSec }, reviewer]) {
      assert.equal(await runtime.ctx.run(runtime.op(), () => runtime.connect.findOwner(identity)), undefined, JSON.stringify(identity.method ?? 'apple'));
    }
    // 一般ログインで審査ownerを使えない（種別を付け替えない）。
    assert.equal((await runtime.ctx.run(runtime.op(), () => runtime.connect.resolveOwner({ projectId, uid: REVIEWER_UID, authTimeSec, method: 'google' }))).kind, 'inactive');
    // 通常ownerは従来どおり引ける。
    const normal = await runtime.ctx.run(runtime.op(), () => runtime.connect.resolveOwner(ordinary));
    assert.equal(normal.kind, 'admitted');
    assert.equal(await runtime.ctx.run(runtime.op(), () => runtime.connect.findOwner(ordinary)), normal.ownerId);
  } finally {
    runtime.dispose();
  }
});

// ---------- T-277 審査ownerの初回受信先の固定（合成オリジン・合成DB・合成challengeだけ。実受信先・実OpenAI URL 0） ----------

/** 初回固定runtimeでの審査ログイン→同意→交換（新しいGrant）。 */
async function firstLogin(uid) {
  const flow = await reviewerFlowLogin(reviewerToken(uid, 'password', Math.floor(rt.clock.now() / 1000)), 'reviewer');
  assert.equal(flow.res.status, 204, flow.res.body);
  const exchanged = await reviewerConsentAndExchange(flow.flow);
  assert.equal(exchanged.status, 200, exchanged.body);
  return JSON.parse(exchanged.body);
}
/** そのUIDのownerの購読文書（無ければundefined）。 */
function subscriptionOf(identityHash) {
  const ownerId = rt.docs.get(`${rt.root}/identities/${identityHash}`)?.data.ownerId;
  return ownerId === undefined ? undefined : rt.docs.get(`sttdAuth/${rt.SUB_NS}/subscriptions/${ownerId}`)?.data;
}
const unsubscribeFrom = (token, id, url) => mcpCall(token, id, 'events/unsubscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url } });
const succeeded = (res) => res.status === 200 && /"result"/.test(res.body);

test('T-286 web disconnect removes the receiver and its authorization, and a new connection can register again', async () => {
  const saved = rt;
  rt = direct;
  try {
    const person = await rt.enrollPerson('uid-t286-disconnect');
    async function connect() {
      const flow = await startFlow();
      await login(flow, person);
      assert.equal((await approval('POST', flow.uid, person, { body: APPROVE })).status, 200);
      const exchanged = await reviewerConsentAndExchange(flow);
      assert.equal(exchanged.status, 200, exchanged.body);
      return JSON.parse(exchanged.body);
    }
    const old = await connect();
    const oldUrl = 'https://hooks.sttd-disconnect.example/old';
    assert.ok(succeeded(await subscribeTo(old.access_token, 1, oldUrl)));
    const nextUrl = 'https://hooks.sttd-disconnect.example/new';
    assert.ok(!succeeded(await subscribeTo(old.access_token, 2, nextUrl)));
    assert.ok(subscriptionOf(person.identityHash).pending);
    const ownerId = rt.docs.get(`${rt.root}/identities/${person.identityHash}`).data.ownerId;
    const ownerPath = `${rt.root}/owners/${ownerId}`;
    const grantMeta = () => paths('grantMeta').filter((path) => rt.docs.get(path).data.ownerId === ownerId);
    const [metaPath] = grantMeta();
    assert.ok(metaPath);
    const bindingPath = metaPath.replace('/grantMeta/', '/sourceGrants/');
    assert.ok(rt.docs.has(bindingPath));
    const page = await rt.browser().request('GET', '/disconnect?lang=ja', { cookies: false });
    assert.equal(page.status, 200);
    assert.match(page.body, /<title>接続解除<\/title>/);
    assert.match(page.body, /id="sttd-disconnect-confirm">解除<\/button>/);
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal((await rt.browser().request('GET', '/disconnect/review', { cookies: false })).status, 404);
    const script = await rt.browser().request('GET', '/disconnect/app.js', { cookies: false });
    assert.equal(script.status, 200);
    assert.match(script.headers['content-type'], /javascript/);
    assert.ok(subscriptionOf(person.identityHash).active, 'opening the screen does not touch the receiving settings');
    const disconnect = (idToken) => rt.browser().request('POST', '/v1/web/disconnect', {
      cookies: false,
      headers: idToken === undefined ? {} : { Authorization: `Bearer ${idToken}`, Origin: rt.issuer },
    });
    assert.equal((await disconnect()).status, 401);
    assert.ok(subscriptionOf(person.identityHash).active);
    rt.rejectNextCommit();
    assert.ok((await disconnect(person.idToken)).status >= 500);
    assert.ok(subscriptionOf(person.identityHash).active);
    assert.ok(subscriptionOf(person.identityHash).pending);
    assert.ok(rt.docs.has(metaPath) && rt.docs.has(bindingPath), 'a failed commit leaves both sides intact');
    const response = await disconnect(person.idToken);
    assert.equal(response.status, 200, response.body);
    assert.deepEqual(JSON.parse(response.body), { state: 'unlinked' });
    assert.equal(subscriptionOf(person.identityHash), undefined, 'active, pending and pinned receiver are physically removed');
    assert.deepEqual(grantMeta(), []);
    assert.equal(rt.docs.has(bindingPath), false);
    assert.ok((await statusOf(old.access_token, 3)).refused !== undefined);
    assert.ok(!succeeded(await subscribeTo(old.access_token, 4, oldUrl)));
    assert.notEqual((await tokenRequest({ grant_type: 'refresh_token', refresh_token: old.refresh_token, resource: resourceFor(rt.issuer) })).status, 200);
    const generation = rt.docs.get(ownerPath).data.receiverGeneration;
    assert.equal((await disconnect(person.idToken)).status, 200);
    assert.equal(rt.docs.get(ownerPath).data.receiverGeneration, generation, 'repeating an already completed disconnect is a no-op');

    const fresh = await connect();
    assert.deepEqual(await statusOf(fresh.access_token, 5), { state: 'linked' });
    assert.ok(succeeded(await subscribeTo(fresh.access_token, 6, nextUrl)));
    assert.deepEqual(await statusOf(fresh.access_token, 7), { state: 'subscribed' });
  } finally {
    rt = saved;
  }
});

test('T-277 F1 初回固定: 対象外オリジンはchallenge・pending保存0で拒否、失敗したchallengeは固定しない、成功した1件だけ固定し、別URLの購読・解除は拒否、解除後も固定で期間外の同じ受信先は再購読できる。通常利用者は従来どおり', async () => {
  const saved = rt;
  rt = firstRt;
  const A = `${FIRST_ORIGIN}/task-a`;
  try {
    const hash = rt.allow(FIRST_UIDS[0]);
    const tokens = await firstLogin(FIRST_UIDS[0]);
    assert.deepEqual(await statusOf(tokens.access_token, 1), { state: 'linked' });
    const challenges = () => rt.challenges.length;

    // 対象外オリジン（別host・http・port付き・userinfo付き）: 外部通信（challenge）とpending保存の前に拒否。
    const before = challenges();
    for (const [index, url] of ['https://hooks.sttd-other.example/task-a', 'https://hooks.sttd-first.example:8443/task-a', 'https://user@hooks.sttd-first.example/task-a'].entries()) {
      assert.ok(!succeeded(await subscribeTo(tokens.access_token, 10 + index, url)), url);
    }
    assert.equal(challenges(), before, 'no challenge for an unlisted origin');
    assert.equal(subscriptionOf(hash), undefined, 'no pending or destination saved');

    // challengeの失敗: 外部通信は1回、固定0。
    rt.challengeControl.echo = false;
    try {
      assert.ok(!succeeded(await subscribeTo(tokens.access_token, 20, A)));
    } finally {
      rt.challengeControl.echo = null;
    }
    assert.equal(challenges(), before + 1);
    assert.equal(subscriptionOf(hash)?.knownDestinationId ?? null, null, 'a failed challenge pins nothing');

    // 成功した1件を固定。
    assert.ok(succeeded(await subscribeTo(tokens.access_token, 21, A)));
    assert.deepEqual(await statusOf(tokens.access_token, 22), { state: 'subscribed' });
    const pinned = subscriptionOf(hash).knownDestinationId;
    assert.match(pinned, /^sub_[0-9a-f]{64}$/);

    // 同じオリジンの別URL: challenge・pending保存の前に拒否（change_pendingも作らない）。解除も拒否。
    const afterPin = challenges();
    assert.ok(!succeeded(await subscribeTo(tokens.access_token, 23, `${FIRST_ORIGIN}/task-b`)));
    assert.ok(!succeeded(await unsubscribeFrom(tokens.access_token, 24, `${FIRST_ORIGIN}/task-b`)));
    assert.equal(challenges(), afterPin);
    assert.equal(subscriptionOf(hash).pending, null);
    assert.equal(subscriptionOf(hash).knownDestinationId, pinned);

    // 解除 → linked。固定は残る。
    assert.ok(succeeded(await unsubscribeFrom(tokens.access_token, 25, A)));
    assert.deepEqual(await statusOf(tokens.access_token, 26), { state: 'linked' });
    assert.equal(subscriptionOf(hash).knownDestinationId, pinned, 'pinned after unsubscribe');

    // 時間枠の終了後（終了時刻ちょうど＝枠外）も、固定済みの同じ受信先は再購読できる。別URLは引き続き拒否。
    const shift = firstWindow.endsAt - Date.now();
    rt.offset.ms += shift;
    try {
      assert.ok(succeeded(await subscribeTo(tokens.access_token, 27, A)));
      assert.deepEqual(await statusOf(tokens.access_token, 28), { state: 'subscribed' });
      assert.ok(!succeeded(await subscribeTo(tokens.access_token, 29, `${FIRST_ORIGIN}/task-c`)));
      assert.equal(subscriptionOf(hash).knownDestinationId, pinned);
    } finally {
      rt.offset.ms -= shift;
    }

    // 通常のGoogle利用者は同じ配置でも従来どおり（オリジン・時間枠に関わらず購読でき、別URLは既存のchange_pending）。
    const normalUid = 'NormalGoogleFirst000001';
    rt.allow(normalUid);
    const normal = await reviewerFlowLogin(reviewerToken(normalUid, 'google.com', Math.floor(rt.clock.now() / 1000)), 'login');
    assert.equal(normal.res.status, 204, normal.res.body);
    const normalTokens = JSON.parse((await reviewerConsentAndExchange(normal.flow)).body);
    assert.ok(succeeded(await subscribeTo(normalTokens.access_token, 30, 'https://hooks.sttd-other.example/normal-1')));
    const pending = await subscribeTo(normalTokens.access_token, 31, 'https://hooks.sttd-other.example/normal-2');
    assert.ok(!succeeded(pending));
    assert.match(pending.body, /pending|change/i, pending.body);
  } finally {
    rt = saved;
  }
});

test('T-277 F2 検証中の期限終了・権限停止では固定しない。再接続の承認で固定先を削除する。同時の異なるURLは保存最大1件', async () => {
  const saved = rt;
  rt = firstRt;
  try {
    // (a) 検証中に時間枠が終わる: 要求自体の20秒期限より短い5秒枠の専用runtimeで、challengeの応答前に6秒進める。
    //     challengeは送られるが確定transactionで拒否、固定0。その後（期間外・未固定）はchallengeの前に拒否。
    const shortOpened = Date.now();
    const shortRt = await startConnectHttpRuntime({
      strict: false,
      clientJwks: [CLIENT_JWK],
      echoChallenge: true,
      reviewer: { uids: [FIRST_UIDS[1]], firstDestination: { origin: FIRST_ORIGIN, startsAt: shortOpened - 1_000, endsAt: shortOpened + 5_000 } },
    });
    rt = shortRt;
    try {
      const hashA = rt.allow(FIRST_UIDS[1]);
      const tokensA = await firstLogin(FIRST_UIDS[1]);
      const sentBefore = rt.challenges.length;
      rt.challengeControl.during = async () => {
        rt.offset.ms += 6_000;
      };
      try {
        assert.ok(!succeeded(await subscribeTo(tokensA.access_token, 1, `${FIRST_ORIGIN}/expiring`)));
      } finally {
        rt.challengeControl.during = null;
      }
      assert.equal(rt.challenges.length, sentBefore + 1, 'the challenge itself was sent inside the window');
      assert.equal(subscriptionOf(hashA)?.knownDestinationId ?? null, null, 'expiry during the challenge pins nothing');
      const before = rt.challenges.length;
      assert.ok(!succeeded(await subscribeTo(tokensA.access_token, 2, `${FIRST_ORIGIN}/late`)));
      assert.equal(rt.challenges.length, before, 'no challenge outside the window when nothing is pinned');
      assert.equal(subscriptionOf(hashA)?.knownDestinationId ?? null, null);
    } finally {
      rt = firstRt;
      await shortRt.close();
    }

    // (b) 検証中に権限停止: 固定0。再許可後に固定し、次の再接続の承認で固定先を削除する。
    const hashB = rt.allow(FIRST_UIDS[2]);
    const tokensB = await firstLogin(FIRST_UIDS[2]);
    const accessPath = `${rt.root}/access/${hashB}`;
    rt.challengeControl.during = async () => {
      const record = rt.docs.get(accessPath).data;
      rt.write(accessPath, { ...record, state: 'disabled', generation: randomUUID(), updatedAt: record.updatedAt + 1 });
    };
    try {
      assert.ok(!succeeded(await subscribeTo(tokensB.access_token, 3, `${FIRST_ORIGIN}/stopped`)));
    } finally {
      rt.challengeControl.during = null;
    }
    assert.equal(subscriptionOf(hashB)?.knownDestinationId ?? null, null, 'a stop during the challenge pins nothing');
    rt.allow(FIRST_UIDS[2]);
    assert.ok(!succeeded(await subscribeTo(tokensB.access_token, 4, `${FIRST_ORIGIN}/stopped`)), 'the old grant stays refused after re-allow');
    const renewed = await firstLogin(FIRST_UIDS[2]);
    const B = `${FIRST_ORIGIN}/renewed`;
    assert.ok(succeeded(await subscribeTo(renewed.access_token, 5, B)));
    const pinnedB = subscriptionOf(hashB).knownDestinationId;
    rt.allow(FIRST_UIDS[2]);
    assert.equal(subscriptionOf(hashB).knownDestinationId, pinnedB, 're-allow alone retains the pinned destination');
    const again = await firstLogin(FIRST_UIDS[2]);
    assert.equal(subscriptionOf(hashB).knownDestinationId, null, 'connection approval clears the pinned destination');
    assert.ok(succeeded(await subscribeTo(again.access_token, 6, `${FIRST_ORIGIN}/other-after-reallow`)));
    assert.ok(!succeeded(await subscribeTo(again.access_token, 7, B)));
    assert.notEqual(subscriptionOf(hashB).knownDestinationId, pinnedB);

    // (c) 同時の異なるURL: 保存（固定）は最大1件。
    const hashC = rt.allow(FIRST_UIDS[3]);
    const tokensC = await firstLogin(FIRST_UIDS[3]);
    const results = await Promise.all([subscribeTo(tokensC.access_token, 8, `${FIRST_ORIGIN}/race-1`), subscribeTo(tokensC.access_token, 9, `${FIRST_ORIGIN}/race-2`)]);
    assert.ok(results.filter(succeeded).length <= 1, results.map((res) => res.body).join('\n'));
    const state = subscriptionOf(hashC);
    assert.ok(state === undefined || state.pending === null);
    const activeCount = state?.active === null || state === undefined ? 0 : 1;
    assert.ok(activeCount <= 1);
    assert.equal(results.filter(succeeded).length, activeCount, 'only the saved one reports success');
  } finally {
    rt = saved;
  }
});

test('T-277 F3 規則と構成: 審査owner以外は常に成立、off・完全一致・初回固定の境界（開始を含み終了を含まない）、時間枠15分・正規形オリジン・二者択一の構成検査', async () => {
  const rules = await import('../dist/storage/firestore/kms-subscription-registration-rules.js');
  const reviewer = { loginKind: 'reviewer' };
  const normal = { loginKind: 'normal' };
  const first = { kind: 'first', startsAt: 1_000, endsAt: 2_000 };
  const none = { knownDestinationId: null };
  const pinned = { knownDestinationId: 'sub_a' };
  const allow = (policy, owner, state, id, claim, at, receiverGeneration = 0) =>
    rules.reviewerDestinationAllowed(policy, owner, state, id, claim, at, receiverGeneration);
  for (const policy of [{ kind: 'off' }, { kind: 'exact' }, first]) assert.equal(allow(policy, normal, none, 'sub_x', 'unlisted', 5_000), true, `normal owner ${policy.kind}`);
  assert.equal(allow({ kind: 'off' }, reviewer, none, 'sub_x', 'listed', 1_500), false);
  assert.equal(allow({ kind: 'exact' }, reviewer, none, 'sub_x', 'listed', 9_999), true);
  assert.equal(allow({ kind: 'exact' }, reviewer, none, 'sub_x', 'unlisted', 1_500), false);
  assert.deepEqual([999, 1_000, 1_999, 2_000].map((at) => allow(first, reviewer, none, 'sub_x', 'listed', at)), [false, true, true, false], 'window [start, end)');
  assert.equal(allow(first, reviewer, none, 'sub_x', 'unlisted', 1_500), false, 'other origin');
  assert.equal(allow(first, reviewer, none, 'sub_x', 'listed', 9_999, 1), true, 're-registration after reset outside the initial window');
  assert.equal(allow(first, reviewer, none, 'sub_x', 'unlisted', 9_999, 1), false, 'other origin after reset');
  assert.equal(allow(first, reviewer, pinned, 'sub_a', 'unlisted', 9_999), true, 'pinned id outside the window');
  assert.equal(allow(first, reviewer, pinned, 'sub_b', 'listed', 1_500), false, 'other id inside the window');
  assert.equal(rules.reviewerCancelAllowed(first, reviewer, none, 'sub_a', 'listed'), false);
  assert.equal(rules.reviewerCancelAllowed(first, reviewer, pinned, 'sub_a', 'unlisted'), true);
  assert.equal(rules.reviewerCancelAllowed({ kind: 'off' }, normal, none, 'sub_z', 'unlisted'), true);
  assert.throws(() => rules.copyReviewerPolicy({ kind: 'first', startsAt: 0, endsAt: 15 * 60_000 + 1 }));
  assert.equal(rules.copyReviewerPolicy({ kind: 'first', startsAt: 0, endsAt: 15 * 60_000 }).kind, 'first');

  // 従来の受信先制限を明示した場合の排他・オリジンの正規形・15分。
  const bad = {
    both: { destinations: [SAMPLE_DESTINATION], firstDestination: { origin: FIRST_ORIGIN, startsAt: 1_000, endsAt: 2_000 } },
    trailingSlash: { firstDestination: { origin: `${FIRST_ORIGIN}/`, startsAt: 1_000, endsAt: 2_000 } },
    http: { firstDestination: { origin: 'http://hooks.sttd-first.example', startsAt: 1_000, endsAt: 2_000 } },
    withPath: { firstDestination: { origin: `${FIRST_ORIGIN}/task`, startsAt: 1_000, endsAt: 2_000 } },
    over15min: { firstDestination: { origin: FIRST_ORIGIN, startsAt: 1_000, endsAt: 1_000 + 15 * 60_000 + 1 } },
    reversed: { firstDestination: { origin: FIRST_ORIGIN, startsAt: 2_000, endsAt: 1_000 } },
  };
  for (const [name, raw] of Object.entries(bad)) {
    await assert.rejects(startConnectHttpRuntime({ strict: false, reviewer: { uids: [REVIEWER_UID], raw } }), { name: 'KmsConnectServerConfigError' }, name);
  }
  const ok = await startConnectHttpRuntime({ strict: false, reviewer: { uids: [REVIEWER_UID], raw: { firstDestination: { origin: FIRST_ORIGIN, startsAt: 1_000, endsAt: 1_000 + 15 * 60_000 } } } });
  await ok.close();
});
