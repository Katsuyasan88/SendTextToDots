// gateway-v1の接合: 実gateway（createGatewayRuntime＝entryと同じ組立て・合成IAM port）→ 所有127.0.0.1のbackend（実adapter）→ 既存handler。
//   API: 実createApiBackendServe → 実createIngressOperationDeliveryRequestHandler → 実source gate（開発者署名・SourceStore）→
//        実KmsRequestDeliveryService/Store（送出確定txでsource/Grantを再検査）。元の公開audienceへの署名がgatewayを通っても成立し、
//        source停止・署名不正・backend直行（transport不一致）では送出0。
//   MCP: 実startDevelopmentKmsConnectServer（transportAuthority＝backend）→ 実Provider・cookie・CSRF・PKCE・許可元承認・Grant。
//        元の公開URLでauthorize→login→承認GET/POST→consent→resumeのcode、未承認/停止sourceの拒否、MCP 401のWWW-Authenticate・
//        discoveryの公開resourceを保ち、応答にbackend名が出ないことを確かめる。
// 合成DB・合成KMS・合成本人・合成IAMだけ。実Cloud IAMの効力・実SDK通信・外部network・Dots・配送 0（Cloud IAMはT091相当の実配置で確認）。

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
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

let rt;
let connectGateway;
const sent = [];

before(async () => {
  rt = await startConnectHttpRuntime({ strict: true, transportAuthority: CONNECT_BACKEND_HOST });
  countListener();
  const config = configFor(rt.issuer);
  const iam = iamFetcher();
  const handler = createGatewayRuntime({
    role: 'connect',
    config,
    env: { K_SERVICE: config.connect.serviceName },
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
    env: { K_SERVICE: 'sendtexttodotsapi' },
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
const viaGateway = () => rt.browser({ via: connectGateway.port });

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
  return { b, uid };
}

async function login(flow, person) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  assert.equal(page.status, 200);
  assert.ok(!page.body.includes(CONNECT_BACKEND_HOST));
  const csrf = /data-sttd-csrf="([^"]+)"/.exec(page.body)?.[1];
  assert.ok(csrf);
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
