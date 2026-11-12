// T-282: 許可元strict＋Playground＋審査ログインを同じ通常MCPで有効にした合成runtime（実Provider・cookie・CSRF・PKCE・private_key_jwt・
// 実source gate・実承認記録・Grantでの単回消費）。審査承認は合成Ed25519鍵の専用署名port。実鍵・実登録・外部通信・Cloud 0。
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { after, before, test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { CHATGPT_CIMD_CANDIDATE } from '../dist/oauth/cimd.js';
import { resourceFor } from '../dist/oauth/provider.js';
import { newSourceGeneration, newSourceId } from '../dist/source/admin.js';
import { createSourceGate } from '../dist/source/http.js';
import { signSourceRequest, verifySourceSignature } from '../dist/source/proof.js';
import { createKeyObjectReviewerSigner, issueReviewerApproval, parseReviewerApprovalKey, reviewerApprovalRequest } from '../dist/source/reviewer-approval.js';
import { sourceApprovalId } from '../dist/source/proof.js';
import { validateDeploymentConfig, reviewerApprovalOf } from '../dist/config/validate.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { startConnectHttpRuntime, syntheticFirebaseToken } from './fixtures/source-runtime.mjs';

const CLIENT_KEY = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const CLIENT_JWK = { ...CLIENT_KEY.publicKey.export({ format: 'jwk' }), kid: 'synthetic-client', alg: 'ES256', use: 'sig' };
const REVIEWER_UID = 'StrictReviewerSynthetic01';
const NORMAL_UID = 'StrictNormalSynthetic0001';
const SAMPLE = 'https://hooks.sttd-strict.example/sample';
const APPROVAL_KEY = generateKeyPairSync('ed25519');
const APPROVAL_SOURCE_ID = newSourceId();
const PLAYGROUND_KEY = generateKeyPairSync('ed25519');
const PLAYGROUND = { sourceId: newSourceId(), publicKey: PLAYGROUND_KEY.publicKey.export({ format: 'jwk' }).x };

let rt;
let reviewerSource;
const nowSec = () => Math.floor(rt.clock.now() / 1000);
const tok = (sub, provider, authTimeSec = nowSec()) => syntheticFirebaseToken({ sub, provider, authTimeSec });
const docsIn = (collection) => [...rt.docs.keys()].filter((p) => p.startsWith(`${rt.root}/${collection}/`));

before(async () => {
  rt = await startConnectHttpRuntime({
    strict: true,
    clientJwks: [CLIENT_JWK],
    echoChallenge: true,
    playground: PLAYGROUND,
    reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval: createKeyObjectReviewerSigner(APPROVAL_SOURCE_ID, APPROVAL_KEY.privateKey, REVIEWER_UID) },
  });
  const identityHash = rt.allow(REVIEWER_UID);
  rt.allow(NORMAL_UID);
  const now = rt.clock.now();
  // 運用者が事前登録する審査用のconnect専用source（本人＝審査UID、公開鍵＝専用署名portの鍵）。
  reviewerSource = {
    schemaVersion: 1,
    sourceId: APPROVAL_SOURCE_ID,
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['connect'],
    publicKey: APPROVAL_KEY.publicKey.export({ format: 'jwk' }).x,
    identityHash,
    expiresAt: null,
    createdAt: now,
    updatedAt: now,
  };
  assert.equal(await rt.sources.create(reviewerSource), 'created');
});
after(async () => {
  await rt?.close();
});

async function startFlow() {
  const b = rt.browser();
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
  const uid = /\/interaction\/([A-Za-z0-9_-]+)$/.exec(new URL(res.headers.location, rt.issuer).pathname)?.[1];
  assert.ok(uid);
  return { b, uid, verifier };
}
async function login(flow, entry, idToken) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  const csrf = /data-sttd-csrf="([^"]+)"/.exec(page.body)?.[1];
  return flow.b.request('POST', `/interaction/${flow.uid}/${entry}`, { headers: { 'Content-Type': 'application/json', Origin: rt.issuer }, body: JSON.stringify({ csrf, idToken }) });
}
async function consentForm(flow) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  return { html: page.body, csrf: /name="csrf" value="([^"]+)"/.exec(page.body)?.[1] ?? '', receiverToken: /name="receiverToken" value="([^"]+)"/.exec(page.body)?.[1] ?? '' };
}
const consent = (flow, form) =>
  flow.b.request('POST', `/interaction/${flow.uid}/consent`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: rt.issuer },
    body: new URLSearchParams({ csrf: form.csrf, receiverToken: form.receiverToken }).toString(),
  });
function clientAssertion() {
  const part = (v) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
  const iat = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'ES256', kid: CLIENT_JWK.kid, typ: 'JWT' })}.${part({ iss: CHATGPT_CIMD_CANDIDATE.clientId, sub: CHATGPT_CIMD_CANDIDATE.clientId, aud: `${rt.issuer}/oauth/token`, jti: randomUUID(), iat, exp: iat + 60 })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key: CLIENT_KEY.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
const tokenRequest = (fields) =>
  rt.browser().request('POST', '/oauth/token', {
    cookies: false,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...fields, client_id: CHATGPT_CIMD_CANDIDATE.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: clientAssertion() }).toString(),
  });
async function exchange(flow, done) {
  const resumed = await flow.b.request('GET', new URL(done.headers.location, rt.issuer).pathname);
  const code = new URL(resumed.headers.location).searchParams.get('code');
  assert.ok(code);
  const res = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: CHATGPT_CIMD_CANDIDATE.redirectUri, code_verifier: flow.verifier, resource: resourceFor(rt.issuer) });
  assert.equal(res.status, 200, res.body);
  return JSON.parse(res.body);
}
const status = async (token, id = 1) => {
  const res = await rt.browser().request('POST', '/mcp', {
    cookies: false,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'get_receiving_status' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'get_receiving_status', _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
  });
  return res.status === 200 && /"result"/.test(res.body) ? JSON.parse(res.body).result.structuredContent : { refused: res.status };
};
async function reviewerConsent() {
  const flow = await startFlow();
  const logged = await login(flow, 'reviewer', tok(REVIEWER_UID, 'password'));
  assert.equal(logged.status, 204, logged.body);
  const form = await consentForm(flow);
  assert.doesNotMatch(form.html, /id="sttd-source-reference"|data-sttd-source-state=/, 'review consent does not require a separate approval');
  return { flow, done: await consent(flow, form) };
}
const setSource = (patch) => rt.write(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`, { ...rt.docs.get(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`).data, ...patch });

test('T282-1 同じ通常MCPでstrict・Playground・審査を同時に有効化: 審査ログイン→明示同意→サーバー署名の承認→OAuth交換→get_receiving_status、承認は単回消費でGrantへbinding', async () => {
  const approvalsBefore = docsIn('sourceApprovals').length;
  const { flow, done } = await reviewerConsent();
  assert.ok([302, 303].includes(done.status), `${done.status} ${done.body}`);
  const tokens = await exchange(flow, done);
  assert.deepEqual(await status(tokens.access_token), { state: 'linked' });
  assert.equal(docsIn('sourceApprovals').length, approvalsBefore + 1, 'one approval recorded');
  const grantBindings = docsIn('sourceGrants').map((p) => rt.docs.get(p).data).filter((d) => d.sourceId === APPROVAL_SOURCE_ID);
  assert.equal(grantBindings.length, 1, 'the grant is bound to the reviewer source');
  // 新規の審査Grantは通常のOAuth期限を使う。
  assert.ok(docsIn('grantMeta').every((p) => !Object.hasOwn(rt.docs.get(p).data, 'reviewerExpiresAt')));
});

test('T282-2 通常経路は不変: 通常利用者のstrict同意は承認なしで再表示（審査承認は作らない）、Playground登録は従来どおり、審査UIDは通常ログイン・Playground・接続承認APIで拒否', async () => {
  const before = docsIn('sourceApprovals').length;
  const flow = await startFlow();
  assert.equal((await login(flow, 'login', tok(NORMAL_UID, 'google.com'))).status, 204);
  const res = await consent(flow, await consentForm(flow));
  assert.equal(res.status, 409, 'strict still requires a source approval for ordinary users');
  assert.match(res.body, /id="sttd-source-reference"/, 'ordinary users still get the approval reference');
  assert.equal(docsIn('sourceApprovals').length, before, 'no reviewer approval for an ordinary user');
  // 審査UIDの通常ログインは拒否。
  assert.equal((await login(await startFlow(), 'login', tok(REVIEWER_UID, 'google.com'))).status, 401);
  // Playground登録（通常の署名・Bearer）。
  const register = (bearer, nonce = randomBytes(16).toString('base64url')) => {
    const iat = nowSec();
    const sig = signSourceRequest({ audience: rt.issuer, method: 'POST', path: '/v1/playground/register', search: '', sourceId: PLAYGROUND.sourceId, body: Buffer.from('{}'), bearer, idempotencyKey: undefined }, { issuedAt: iat, expiresAt: iat + 60, nonce }, PLAYGROUND_KEY.privateKey);
    return rt.browser().request('POST', '/v1/playground/register', { cookies: false, headers: { 'x-sttd-source': PLAYGROUND.sourceId, 'x-sttd-source-signature': sig, Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' }, body: '{}' });
  };
  const ok = await register(tok(NORMAL_UID, 'google.com'));
  assert.equal(ok.status, 200, ok.body);
  assert.equal((await register(tok(REVIEWER_UID, 'password'))).status, 401, 'reviewer identity is not an ordinary Playground identity');
  // 通常の接続承認API（Bearer＝本人token）へ審査tokenは通らない。
  const approvalApi = await rt.browser().request('POST', `/v1/source/approvals/${flow.uid}`, { cookies: false, headers: { Authorization: `Bearer ${tok(REVIEWER_UID, 'password')}`, 'x-sttd-source': APPROVAL_SOURCE_ID, 'x-sttd-source-signature': `v1.${nowSec()}.${nowSec() + 30}.${'A'.repeat(22)}.${'A'.repeat(86)}`, 'Content-Type': 'application/json' }, body: '{"approve":true}' });
  assert.ok([401, 403].includes(approvalApi.status), `${approvalApi.status}`);
});

test('T282-3 不成立は承認0・Grant0: 不一致の登録公開鍵（無効署名）・source停止・connect外の操作・利用許可の停止・CSRF違い', async () => {
  const refusedWithoutApproval = async (label, mutate, restore) => {
    const before = docsIn('sourceApprovals').length;
    mutate();
    try {
      const { done } = await reviewerConsent();
      assert.ok(![302, 303].includes(done.status), `${label}: ${done.status}`);
      assert.equal(docsIn('sourceApprovals').length, before, `${label}: no approval`);
    } finally {
      restore();
    }
  };
  const original = structuredClone(rt.docs.get(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`).data);
  const reset = () => rt.write(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`, original);
  await refusedWithoutApproval('wrong public key', () => setSource({ publicKey: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x }), reset);
  await refusedWithoutApproval('source disabled', () => setSource({ state: 'disabled', updatedAt: original.updatedAt + 1 }), reset);
  await refusedWithoutApproval('send-only source', () => setSource({ operations: ['send'] }), reset);
  // 利用許可の停止（ログイン後・同意前）。
  {
    const before = docsIn('sourceApprovals').length;
    const flow = await startFlow();
    assert.equal((await login(flow, 'reviewer', tok(REVIEWER_UID, 'password'))).status, 204);
    const accessPath = `${rt.root}/access/${connectIdentityHash(rt.hasher, rt.NS, { projectId: rt.projectId, uid: REVIEWER_UID })}`;
    const access = structuredClone(rt.docs.get(accessPath).data);
    rt.write(accessPath, { ...access, state: 'disabled', generation: randomUUID(), updatedAt: access.updatedAt + 1 });
    try {
      const done = await consent(flow, await consentForm(flow));
      assert.ok(![302, 303].includes(done.status), `access stopped: ${done.status}`);
      assert.equal(docsIn('sourceApprovals').length, before);
    } finally {
      rt.write(accessPath, { ...access, generation: randomUUID(), updatedAt: access.updatedAt + 2 });
    }
  }
  // CSRF違い（別の値）: 承認を作らない。
  {
    const before = docsIn('sourceApprovals').length;
    const flow = await startFlow();
    assert.equal((await login(flow, 'reviewer', tok(REVIEWER_UID, 'password'))).status, 204);
    const form = await consentForm(flow);
    const done = await consent(flow, { ...form, csrf: 'x'.repeat(43) });
    assert.ok(![302, 303].includes(done.status));
    assert.equal(docsIn('sourceApprovals').length, before);
  }
  // 審査専用の24時間期限を過ぎても、通常のOAuthと同じく有効なログインから同意できる。
  {
    const before = docsIn('sourceApprovals').length;
    const flow = await startFlow();
    assert.equal((await login(flow, 'reviewer', tok(REVIEWER_UID, 'password', nowSec() - 24 * 3600 + 5))).status, 204);
    rt.offset.ms += 10_000;
    try {
      const done = await consent(flow, await consentForm(flow));
      assert.ok([302, 303].includes(done.status), done.body);
      assert.equal(docsIn('sourceApprovals').length, before + 1);
    } finally {
      rt.offset.ms -= 10_000;
    }
  }
});

test('T282-4 発行済みの審査接続: source停止・世代変更・利用許可停止で照会を拒否（再許可しても旧Grantは戻らない）', async () => {
  const run = async (label, mutate, restore) => {
    const { flow, done } = await reviewerConsent();
    assert.ok([302, 303].includes(done.status), `${label} setup ${done.status}`);
    const tokens = await exchange(flow, done);
    assert.deepEqual(await status(tokens.access_token), { state: 'linked' });
    mutate();
    try {
      assert.ok((await status(tokens.access_token, 2)).refused !== undefined, label);
    } finally {
      restore();
    }
    assert.ok((await status(tokens.access_token, 3)).refused !== undefined, `${label}: stays refused`);
  };
  const original = structuredClone(rt.docs.get(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`).data);
  await run('source stopped', () => setSource({ state: 'disabled', updatedAt: original.updatedAt + 1 }), () => setSource({ ...original, generation: newSourceGeneration(), updatedAt: original.updatedAt + 2 }));
  const current = structuredClone(rt.docs.get(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`).data);
  await run('generation changed', () => setSource({ generation: newSourceGeneration(), updatedAt: current.updatedAt + 1 }), () => {});
  const accessPath = `${rt.root}/access/${connectIdentityHash(rt.hasher, rt.NS, { projectId: rt.projectId, uid: REVIEWER_UID })}`;
  const access = structuredClone(rt.docs.get(accessPath).data);
  await run('access stopped', () => rt.write(accessPath, { ...access, state: 'disabled', generation: randomUUID(), updatedAt: access.updatedAt + 1 }), () => rt.write(accessPath, { ...access, generation: randomUUID(), updatedAt: access.updatedAt + 2 }));
});

test('T282-5 同時の同意2件: 承認は最大1件、Grant（302）は最大1件', async () => {
  const flow = await startFlow();
  assert.equal((await login(flow, 'reviewer', tok(REVIEWER_UID, 'password'))).status, 204);
  const form = await consentForm(flow);
  const before = docsIn('sourceApprovals').length;
  const results = await Promise.all([consent(flow, form), consent(flow, form)]);
  assert.equal(results.filter((r) => [302, 303].includes(r.status)).length, 1, results.map((r) => r.status).join(','));
  assert.equal(docsIn('sourceApprovals').length - before, 1);
});

test('T282-8 strictでも審査ownerの購読はサンプル受信先だけ（一般の受信先はchallenge前に拒否）、照会はsubscribedへ', async () => {
  const { flow, done } = await reviewerConsent();
  assert.ok([302, 303].includes(done.status));
  const tokens = await exchange(flow, done);
  const subscribe = (url, id) =>
    rt.browser().request('POST', '/mcp', {
      cookies: false,
      headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'events/subscribe' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method: 'events/subscribe', params: { name: 'text.submitted', delivery: { mode: 'webhook', url, secret: `whsec_${randomBytes(32).toString('base64')}` }, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
    });
  const challenges = rt.challenges.length;
  assert.doesNotMatch((await subscribe('https://hooks.sttd-strict.example/general', 1)).body, /"result"/);
  assert.equal(rt.challenges.length, challenges, 'no challenge to a general destination');
  const saved = await subscribe(SAMPLE, 2);
  assert.match(saved.body, /"result"/, saved.body);
  assert.deepEqual(await status(tokens.access_token, 3), { state: 'subscribed' });
});

test('T282-6 署名の束縛（単体）: 別client・別resource・別interaction・別UIDへの流用不可、期限切れ・リプレイを既存gateが拒否、署名portの失敗は承認を作らない', async () => {
  const signer = createKeyObjectReviewerSigner(APPROVAL_SOURCE_ID, APPROVAL_KEY.privateKey, REVIEWER_UID);
  const pub = APPROVAL_KEY.publicKey.export({ format: 'jwk' }).x;
  const target = { audience: rt.issuer, interactionId: 'interactionA', reviewerUid: REVIEWER_UID, clientId: CHATGPT_CIMD_CANDIDATE.clientId, resource: resourceFor(rt.issuer) };
  const issued = await issueReviewerApproval(signer, target, rt.clock.now());
  assert.ok(verifySourceSignature(pub, issued.request, issued.proof.claims, issued.proof.signature));
  for (const patch of [{ clientId: 'https://other.example/client.json' }, { resource: 'https://other.example/mcp' }, { interactionId: 'interactionB' }, { reviewerUid: 'OtherReviewerSynthetic1' }, { audience: 'https://other.example' }]) {
    assert.equal(verifySourceSignature(pub, reviewerApprovalRequest({ ...target, ...patch }, APPROVAL_SOURCE_ID), issued.proof.claims, issued.proof.signature), false, JSON.stringify(patch));
  }
  const gate = createSourceGate({ policy: { mode: 'strict-v1', methods: ['developer-key-v1'] }, store: rt.sources, hasher: rt.hasher, namespace: rt.NS, audience: rt.issuer, clock: rt.clock });
  const identity = { projectId: rt.projectId, uid: REVIEWER_UID, authTimeSec: 1, method: 'reviewer' };
  const input = (req) => ({ identity, operation: 'connect', method: req.method, path: req.path, search: req.search, body: req.body, bearer: req.bearer, idempotencyKey: undefined });
  assert.equal((await gate.authorize(issued.proof, input(issued.request))).kind, 'allowed');
  assert.equal((await gate.authorize(issued.proof, input(issued.request))).kind, 'denied', 'replay');
  const other = await issueReviewerApproval(signer, target, rt.clock.now());
  assert.equal((await gate.authorize(other.proof, { ...input(other.request), identity: { ...identity, uid: NORMAL_UID } })).kind, 'denied', 'other identity');
  const old = await issueReviewerApproval(signer, target, rt.clock.now() - 10 * 60_000);
  assert.equal((await gate.authorize(old.proof, input(old.request))).kind, 'denied', 'expired');
  await assert.rejects(issueReviewerApproval({ sourceId: APPROVAL_SOURCE_ID, reviewerUid: REVIEWER_UID, sign: () => { throw new Error('port down'); } }, target, rt.clock.now()), { name: 'ReviewerApprovalError' });
  await assert.rejects(issueReviewerApproval({ sourceId: APPROVAL_SOURCE_ID, reviewerUid: REVIEWER_UID, sign: () => new Uint8Array(10) }, target, rt.clock.now()), { name: 'ReviewerApprovalError' });
});

test('T282-7 未設定はfail closed: strict＋審査で署名port無し、compatible＋署名port、gateway＋審査は起動しない', async () => {
  const approval = createKeyObjectReviewerSigner(APPROVAL_SOURCE_ID, APPROVAL_KEY.privateKey, REVIEWER_UID);
  await assert.rejects(startConnectHttpRuntime({ strict: true, reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE] } }), { name: 'KmsConnectServerConfigError' });
  await assert.rejects(startConnectHttpRuntime({ strict: false, reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval } }), { name: 'KmsConnectServerConfigError' });
  await assert.rejects(startConnectHttpRuntime({ strict: true, transportAuthority: 'backend.sttd-strict.example.com', reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval } }), { name: 'KmsConnectServerConfigError' });
  await assert.rejects(startConnectHttpRuntime({ strict: true, reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval: { sourceId: 'bad', reviewerUid: REVIEWER_UID, sign: () => new Uint8Array(64) } } }), { name: 'KmsConnectServerConfigError' });
  await assert.rejects(startConnectHttpRuntime({ strict: true, reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval: { sourceId: APPROVAL_SOURCE_ID, sign: () => new Uint8Array(64) } } }), { name: 'KmsConnectServerConfigError' }, 'reviewerUid missing');
});

// ---------- T-282 起動口の追補 ----------

test('T282-9 設定の審査UIDと保存済みowner UIDの不一致: 署名0・承認0で、同じinteractionに既にある承認も使わない（通常経路へfallbackしない）', async () => {
  // 署名portの審査UIDだけが別（設定変更後のprocessを想定）。verifierは旧UIDを受ける。
  const other = await startConnectHttpRuntime({
    strict: true,
    clientJwks: [CLIENT_JWK],
    reviewer: { uids: [REVIEWER_UID], destinations: [SAMPLE], approval: createKeyObjectReviewerSigner(APPROVAL_SOURCE_ID, APPROVAL_KEY.privateKey, 'ReplacedReviewerUid0001') },
  });
  const saved = rt;
  rt = other;
  try {
    const identityHash = rt.allow(REVIEWER_UID);
    const now = rt.clock.now();
    const source = { ...reviewerSource, identityHash, createdAt: now, updatedAt: now };
    assert.equal(await rt.sources.create(source), 'created');
    const flow = await startFlow();
    assert.equal((await login(flow, 'reviewer', tok(REVIEWER_UID, 'password'))).status, 204);
    // 設定変更の前に記録された承認がこのinteractionに残っている状況を作る。
    const recorded = await rt.sources.recordApproval(
      {
        approvalId: sourceApprovalId(rt.hasher, rt.NS, flow.uid),
        identityHash,
        clientHash: rt.hasher.hash(`t256:${rt.NS}:source-client`, CHATGPT_CIMD_CANDIDATE.clientId),
        resourceHash: rt.hasher.hash(`t256:${rt.NS}:source-resource`, resourceFor(rt.issuer)),
      },
      { sourceId: source.sourceId, generation: source.generation },
      now + 300_000,
    );
    assert.equal(recorded.kind, 'recorded');
    const replays = docsIn('sourceReplay').length;
    const done = await consent(flow, await consentForm(flow));
    assert.equal(done.status, 409, 'refused even with a pending approval');
    assert.match(done.body, /We could not approve this review connection/);
    assert.doesNotMatch(done.body, /id="sttd-source-reference"/);
    assert.equal(docsIn('sourceReplay').length, replays, 'no signature was verified (no nonce consumed)');
    assert.equal(docsIn('grantMeta').length, 0, 'no grant');
  } finally {
    rt = saved;
    await other.close();
  }
});

test('T282-10 connect以外の操作を持つ審査source（connect＋send）は署名の前に拒否（nonce消費0・承認0）', async () => {
  const original = structuredClone(rt.docs.get(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`).data);
  setSource({ operations: ['connect', 'send'] });
  try {
    const approvals = docsIn('sourceApprovals').length;
    const replays = docsIn('sourceReplay').length;
    const { done } = await reviewerConsent();
    assert.equal(done.status, 409);
    assert.equal(docsIn('sourceApprovals').length, approvals);
    assert.equal(docsIn('sourceReplay').length, replays);
  } finally {
    rt.write(`${rt.root}/sources/${APPROVAL_SOURCE_ID}`, original);
  }
});

test('T282-11 配置設定: strict＋審査は developer-key-v1・direct・審査UID 1件・専用sourceがPlayground登録元と別の時だけ。compatibleは追加項目不可。承認の値は鍵を持たない', () => {
  const strict = { mode: 'strict-v1', methods: ['developer-key-v1'] };
  const login = (patch = {}) => ({ mode: 'reviewer-password-v1', uids: [REVIEWER_UID], destinations: [SAMPLE.replace('sttd-strict.example', 'sendtexttodots.example.org')], ...patch });
  const reviewerLogin = { mode: 'reviewer-password-v1', uids: [REVIEWER_UID], approvalSourceId: APPROVAL_SOURCE_ID };
  const ok = validateDeploymentConfig({ ...structuredClone(SYNTHETIC), sourceAuthorization: strict, playgroundRegistrar: PLAYGROUND, reviewerLogin });
  assert.deepEqual(reviewerApprovalOf(ok), { sourceId: APPROVAL_SOURCE_ID, reviewerUid: REVIEWER_UID });
  assert.equal(reviewerApprovalOf(validateDeploymentConfig({ ...structuredClone(SYNTHETIC), reviewerLogin: login() })), undefined, 'compatible has no approval');
  const bad = {
    strictWithoutSource: { sourceAuthorization: strict, reviewerLogin: login() },
    twoUids: { sourceAuthorization: strict, reviewerLogin: login({ uids: [REVIEWER_UID, 'SecondReviewerUid000001'], approvalSourceId: APPROVAL_SOURCE_ID }) },
    appCheckOnly: { sourceAuthorization: { mode: 'strict-v1', methods: ['app-check-v1'] }, reviewerLogin: login({ approvalSourceId: APPROVAL_SOURCE_ID }) },
    sameAsPlayground: { sourceAuthorization: strict, playgroundRegistrar: PLAYGROUND, reviewerLogin: login({ approvalSourceId: PLAYGROUND.sourceId }) },
    badSourceId: { sourceAuthorization: strict, reviewerLogin: login({ approvalSourceId: 'src_x' }) },
    compatibleWithSource: { reviewerLogin: login({ approvalSourceId: APPROVAL_SOURCE_ID }) },
  };
  for (const [name, patch] of Object.entries(bad)) assert.throws(() => validateDeploymentConfig({ ...structuredClone(SYNTHETIC), ...patch }), { code: 'deployment_config_invalid' }, name);
});

test('T282-12 鍵の入力: canonical base64のEd25519 PKCS8だけ。欠落・空・非正規・過大・別種別の鍵は値を含まない固定error', () => {
  const pkcs8 = (key) => key.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  const valid = pkcs8(generateKeyPairSync('ed25519').privateKey);
  const key = parseReviewerApprovalKey(valid);
  assert.equal(key.asymmetricKeyType, 'ed25519');
  const cases = [undefined, '', `${valid}\n`, ` ${valid}`, `${valid}==`, valid.slice(0, -1), 'A'.repeat(300), pkcs8(generateKeyPairSync('x25519').privateKey), pkcs8(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey), Buffer.from('not a key').toString('base64')];
  for (const value of cases) {
    try {
      parseReviewerApprovalKey(value);
      assert.fail('accepted');
    } catch (error) {
      assert.equal(error.name, 'ReviewerApprovalError');
      if (typeof value === 'string' && value.length > 0) assert.equal(String(error.message).includes(value.slice(0, 16)), false, 'no key material in the error');
    }
  }
});

test('T282-13 起動口: 審査承認を設定していない配置では鍵の受け渡しを拒否（SDK・秘密・listenの前の設定error）', async () => {
  const { startOwnedDevelopmentConnectServer } = await import('../dist/google-runtime/connect-development.js');
  const S = structuredClone(SYNTHETIC);
  const options = {
    projectId: S.projectId,
    projectNumber: S.projectNumber,
    databaseId: S.databaseId,
    expectedServiceName: S.connect.serviceName,
    bindPort: 8080,
    publicOrigin: S.connect.publicOrigin,
    connectNamespace: S.connectNamespace,
    kms: S.kms,
    secretVersions: S.secretVersions,
    web: { apiKey: 'synthetic-web-api-key', authDomain: S.web.authDomain, projectId: S.web.projectId },
    clock: { now: () => Date.now() },
    operation: { deadlineAt: Date.now() + 20_000, signal: new AbortController().signal },
    reviewerApprovalKey: generateKeyPairSync('ed25519').privateKey,
  };
  await assert.rejects(startOwnedDevelopmentConnectServer(options), (error) => error?.code === 'owned_development_connect_config_invalid');
});

test('T-289 send_text uses the OAuth account’s subscription and the authorized send source', async () => {
  const original = rt;
  const sent = [];
  const digest = randomBytes(32);
  rt = await startConnectHttpRuntime({
    strict: true,
    clientJwks: [CLIENT_JWK],
    echoChallenge: true,
    reviewer: { uids: [REVIEWER_UID], approval: createKeyObjectReviewerSigner(APPROVAL_SOURCE_ID, APPROVAL_KEY.privateKey, REVIEWER_UID) },
    sendText: {
      namespace: `t270_${randomUUID()}`,
      loadDigestKey: async () => digest,
      egress: { async postCommandCallback(url, post) { sent.push({ url, body: JSON.parse(post.body.toString('utf8')), headers: post.headers }); return { status: 200 }; } },
    },
  });
  try {
    assert.deepEqual(digest, Buffer.alloc(32));
    const identityHash = rt.allow(REVIEWER_UID);
    const record = { ...reviewerSource, identityHash, operations: ['connect', 'send'] };
    assert.equal(await rt.sources.create(record), 'created');
    const { flow, done } = await reviewerConsent();
    const { access_token: token } = await exchange(flow, done);
    const rpc = (id, method, params, bearer = token) => rt.browser().request('POST', '/mcp', {
      cookies: false,
      headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method, ...(params?.name ? { 'Mcp-Name': params.name } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
    });
    const call = (id, args, bearer) => rpc(id, 'tools/call', { name: 'send_text', arguments: args }, bearer);
    const register = (id, url, bearer) => rpc(id, 'events/subscribe', { name: 'text.submitted', delivery: { mode: 'webhook', url, secret: `whsec_${randomBytes(32).toString('base64')}` } }, bearer);
    const tools = JSON.parse((await rpc(1, 'tools/list')).body).result.tools;
    assert.deepEqual(tools.map(({ name }) => name), ['get_receiving_status', 'send_text']);
    assert.equal(tools[1].annotations.readOnlyHint, false);
    const text = 'Hello from Work — テスト';
    assert.deepEqual(JSON.parse((await call(2, { text })).body).result.structuredContent, { status: 'not_delivered' });
    const subscribe = await register(3, SAMPLE);
    assert.match(subscribe.body, /"result"/, subscribe.body);
    assert.ok(JSON.parse((await call(4, { text, url: 'https://other.example/' })).body).error);
    assert.equal(sent.length, 0);
    const delivered = await call(5, { text });
    assert.deepEqual(JSON.parse(delivered.body).result?.structuredContent, { status: 'delivered' }, delivered.body);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].url, SAMPLE);
    assert.ok(sent[0].headers['webhook-signature']);
    assert.ok(JSON.stringify(sent[0].body).includes(text));
    assert.doesNotMatch(delivered.body, /Hello from Work/);
    setSource({ operations: ['connect'] });
    assert.deepEqual(JSON.parse((await call(6, { text })).body).result.structuredContent, { status: 'not_delivered' });
    assert.equal(sent.length, 1);
    setSource({ operations: ['connect', 'send'] });

    const reconnect = await reviewerConsent();
    const { access_token: newToken } = await exchange(reconnect.flow, reconnect.done);
    assert.deepEqual(await status(newToken), { state: 'linked' });
    assert.deepEqual(JSON.parse((await call(7, { text }, newToken)).body).result?.structuredContent, { status: 'not_delivered' });
    assert.equal(sent.length, 1, 'the old receiver is no longer used after approval');
    const nextUrl = 'https://hooks.other-dots.example/new-task';
    assert.doesNotMatch((await register(8, SAMPLE)).body, /"result"/, 'the old grant cannot restore its receiver');
    assert.doesNotMatch((await register(9, 'http://hooks.other-dots.example/new-task', newToken)).body, /"result"/, 'standard HTTPS validation still applies');
    const registered = await register(10, nextUrl, newToken);
    assert.match(registered.body, /"result"/, registered.body);
    assert.deepEqual(await status(newToken), { state: 'subscribed' });
    assert.deepEqual(JSON.parse((await call(11, { text }, newToken)).body).result?.structuredContent, { status: 'delivered' });
    assert.deepEqual(sent.map(({ url }) => url), [SAMPLE, nextUrl]);

    const page = await rt.browser().request('GET', '/disconnect/review?lang=ja', { cookies: false });
    assert.equal(page.status, 200);
    assert.equal(page.headers['x-robots-tag'], 'noindex, nofollow');
    assert.match(page.body, /id="sttd-disconnect-password" type="password"/);
    assert.doesNotMatch(page.body, /id="sttd-google-login"/);
    const normalPage = await rt.browser().request('GET', '/disconnect?lang=ja', { cookies: false });
    assert.doesNotMatch(normalPage.body, /id="sttd-disconnect-password"/);
    const disconnect = (bearer, { path = '/v1/web/disconnect/reviewer', origin = rt.issuer } = {}) =>
      rt.browser().request('POST', path, {
        cookies: false,
        headers: { Origin: origin, ...(bearer === null ? {} : { Authorization: `Bearer ${bearer}` }) },
      });
    const reviewerToken = tok(REVIEWER_UID, 'password');
    assert.equal((await disconnect(null)).status, 401);
    assert.equal((await disconnect(tok(REVIEWER_UID, 'google.com'))).status, 401);
    assert.equal((await disconnect(tok(NORMAL_UID, 'password'))).status, 401);
    assert.equal((await disconnect(reviewerToken, { origin: 'https://unrelated.example' })).status, 403);
    assert.equal((await disconnect(reviewerToken, { path: '/v1/web/disconnect' })).status, 401);
    assert.deepEqual(await status(newToken), { state: 'subscribed' });
    const disconnected = await disconnect(reviewerToken);
    assert.equal(disconnected.status, 200, disconnected.body);
    assert.deepEqual(JSON.parse(disconnected.body), { state: 'unlinked' });
    const ownerId = rt.docs.get(`${rt.root}/identities/${identityHash}`).data.ownerId;
    assert.equal(rt.docs.has(`sttdAuth/${rt.SUB_NS}/subscriptions/${ownerId}`), false);
    assert.ok((await status(newToken)).refused !== undefined);
    assert.equal(sent.length, 2, 'the deletion does not send an event');
  } finally {
    await rt.close();
    rt = original;
  }
});
