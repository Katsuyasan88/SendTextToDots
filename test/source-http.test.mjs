// 許可元strictの実HTTP境界（実connect server: startDevelopmentKmsConnectServerの実handler・実Provider 9.12.2・cookie・KMS封緘・adapter）。
//   PKCE/resource付きGET /oauth/authorize → interactionのLocation/cookie → 元interactionのlogin → 同本人のsource証明でGET/POST
//   /v1/source/approvals/{id} → 元cookie/CSRFのconsent → resume。承認なし/別本人/別interaction/消費済み/停止/期限、cookie/CSRF不正、
//   query/method/body不正、受信先設定の保護、互換配置との差（strict起動配線）を検査する。
// 合成DB・合成AES-GCM KMS・合成本人verifier・固定CIMD文書だけのfake egress、listen境界の局所intercept（127.0.0.1/port 0）だけ。
// 実Cloud・資格・SDK通信・外部DNS/HTTP・Dots・配送 0。redirectは追わず、元issuer内のpathだけを127.0.0.1へ送る。

import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';

import { CHATGPT_CIMD_CANDIDATE } from '../dist/oauth/cimd.js';
import { resourceFor } from '../dist/oauth/provider.js';
import { KMS_CAPSULE_PREFIX } from '../dist/protection/kms-sealing.js';
import { signSourceRequest } from '../dist/source/proof.js';
import { kmsStateDocument, kmsVersionName } from '../dist/storage/firestore/kms-subscription-format.js';
import { startConnectHttpRuntime } from './fixtures/source-runtime.mjs';

let strict;
let compat;

before(async () => {
  strict = await startConnectHttpRuntime({ strict: true });
  compat = await startConnectHttpRuntime({ strict: false });
});

after(async () => {
  await strict?.close();
  await compat?.close();
});

const paths = (rt, collection) => [...rt.docs.keys()].filter((path) => path.startsWith(`${rt.root}/${collection}/`));

/** PKCE/resource付きの認可要求を実handlerへ送り、interactionのuidとcookieを持つbrowserを返す。 */
async function startFlow(rt) {
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
  assert.ok([302, 303].includes(res.status), `authorize redirects to the interaction (${res.status})`);
  const uid = /\/interaction\/([A-Za-z0-9_-]+)$/.exec(new URL(res.headers.location, rt.issuer).pathname)?.[1];
  assert.ok(uid, 'interaction uid from Location');
  assert.ok(b.jar.size > 0, 'interaction cookie set');
  return { b, uid };
}

async function login(rt, flow, person) {
  const page = await flow.b.request('GET', `/interaction/${flow.uid}`);
  assert.equal(page.status, 200);
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
    reference: /<code id="sttd-source-reference">([^<]+)<\/code>/.exec(page.body)?.[1] ?? null,
    confirmBox: page.body.includes('name="receiverReset"'),
    body: page.body,
  };
}

async function consent(rt, flow, form, { cookies = true } = {}) {
  return flow.b.request('POST', `/interaction/${flow.uid}/consent`, {
    cookies,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: rt.issuer },
    body: new URLSearchParams({ csrf: form.csrf ?? '', receiverToken: form.receiverToken ?? '', ...(form.confirm ? { receiverReset: '1' } : {}) }).toString(),
  });
}

/** 許可元（cookieなしの別client）からの承認GET/POST。署名は宛先=MCP origin・method・path・本文・本人tokenへ束縛。 */
async function approval(rt, method, uid, person, { body, query = '', signer = person, unsigned = false, headers = {} } = {}) {
  const path = `/v1/source/approvals/${uid}`;
  const nowSec = Math.floor(rt.clock.now() / 1000);
  const claims = { issuedAt: nowSec, expiresAt: nowSec + 30, nonce: randomBytes(16).toString('base64url') };
  const signature = signSourceRequest(
    { audience: rt.issuer, method, path, search: '', sourceId: signer.record.sourceId, body: Buffer.from(body ?? ''), bearer: person.idToken, idempotencyKey: undefined },
    claims,
    signer.privateKey,
  );
  return rt.browser().request(method, `${path}${query}`, {
    cookies: false,
    headers: {
      Authorization: `Bearer ${person.idToken}`,
      ...(unsigned ? {} : { 'X-STTD-Source': signer.record.sourceId, 'X-STTD-Source-Signature': signature }),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body,
  });
}

const APPROVE = '{"approve":true}';

test('strict正規: authorize→login→承認GET/POST→元cookie/CSRFのconsent→resumeでcode、Grant metadataとsource bindingを作る', async () => {
  const person = await strict.enrollPerson('uid-http-a');
  const flow = await startFlow(strict);
  await login(strict, flow, person);
  const waiting = await consentPage(flow);
  assert.equal(waiting.status, 200);
  assert.equal(waiting.sourceState, 'waiting');
  assert.equal(waiting.reference, flow.uid);
  // 実Providerが保持するparams（client_id/resource/scope）でrouteが通り、内容の最小照会を返す。
  const checked = await approval(strict, 'GET', flow.uid, person);
  assert.equal(checked.status, 200, checked.body);
  const content = JSON.parse(checked.body);
  assert.deepEqual(Object.keys(content).sort(), ['client', 'expiresAt', 'resource', 'scope']);
  assert.equal(content.resource, resourceFor(strict.issuer));
  assert.equal(content.scope, 'sttd:events');
  const approved = await approval(strict, 'POST', flow.uid, person, { body: APPROVE });
  assert.equal(approved.status, 200, approved.body);
  assert.equal(JSON.parse(approved.body).state, 'approved');
  assert.equal((await approval(strict, 'POST', flow.uid, person, { body: APPROVE })).status, 409);
  const confirmed = await consentPage(flow);
  assert.equal(confirmed.sourceState, 'confirmed');
  const metaBefore = paths(strict, 'grantMeta').length;
  const done = await consent(strict, flow, confirmed);
  assert.ok([302, 303].includes(done.status), `consent finishes (${done.status})`);
  assert.equal(paths(strict, 'grantMeta').length, metaBefore + 1);
  const bindings = paths(strict, 'sourceGrants').map((path) => strict.docs.get(path).data);
  assert.ok(bindings.some((binding) => binding.sourceId === person.record.sourceId && binding.generation === person.record.generation));
  // resumeは元cookieで認可codeを発行する（外部redirect先は追わず、Locationだけ確認）。
  const resumed = await flow.b.request('GET', new URL(done.headers.location, strict.issuer).pathname);
  assert.ok([302, 303].includes(resumed.status), `resume (${resumed.status})`);
  const final = new URL(resumed.headers.location);
  assert.equal(`${final.origin}${final.pathname}`, CHATGPT_CIMD_CANDIDATE.redirectUri);
  assert.ok(final.searchParams.get('code'));
  // 消費済みinteractionへの承認・照会は404。
  assert.equal((await approval(strict, 'GET', flow.uid, person)).status, 404);
  // 外部egressは固定CIMD文書だけ。
  assert.ok(strict.egressCalls.every((url) => url === CHATGPT_CIMD_CANDIDATE.clientId || url === CHATGPT_CIMD_CANDIDATE.jwksUri));
});

test('承認route: 証明欠落・query/method/body不正・未ログイン・別本人・別interaction・他人のsource・停止sourceを拒否する', async () => {
  const a = await strict.enrollPerson('uid-http-b');
  const other = await strict.enrollPerson('uid-http-c');
  const flow = await startFlow(strict);
  // 未ログインのinteractionは404。
  assert.equal((await approval(strict, 'GET', flow.uid, a)).status, 404);
  await login(strict, flow, a);
  assert.equal((await approval(strict, 'GET', flow.uid, a, { unsigned: true })).status, 403);
  assert.ok((await approval(strict, 'GET', flow.uid, a, { unsigned: true })).body.includes('source_required'));
  assert.equal((await approval(strict, 'GET', flow.uid, a, { query: '?x=1' })).status, 400);
  assert.equal((await approval(strict, 'PUT', flow.uid, a)).status, 405);
  assert.equal((await approval(strict, 'POST', flow.uid, a, { body: '{"approve":1234}' })).status, 400);
  // 別本人（自分のsourceで正しく署名）は他人のinteractionを扱えない（情報を増やさず404）。
  assert.equal((await approval(strict, 'GET', flow.uid, other)).status, 404);
  assert.equal((await approval(strict, 'POST', flow.uid, other, { body: APPROVE })).status, 404);
  // 存在しない別interaction。
  assert.equal((await approval(strict, 'GET', 'no-such-interaction', a)).status, 404);
  // 他人に登録されたsourceの鍵での署名（本人とsourceの不一致）は403。
  assert.equal((await approval(strict, 'GET', flow.uid, a, { signer: other })).status, 403);
  // 停止したsourceは403で、承認を作らない。
  const sourcePath = `${strict.root}/sources/${a.record.sourceId}`;
  strict.write(sourcePath, { ...a.record, state: 'disabled', updatedAt: a.record.updatedAt + 1 });
  assert.equal((await approval(strict, 'POST', flow.uid, a, { body: APPROVE })).status, 403);
  strict.write(sourcePath, a.record);
  assert.equal((await consentPage(flow)).sourceState, 'waiting');
});

test('consent: 承認なし・cookie/CSRF不正では作らず、interactionを消費しない', async () => {
  const person = await strict.enrollPerson('uid-http-d');
  const flow = await startFlow(strict);
  await login(strict, flow, person);
  const page = await consentPage(flow);
  const metaBefore = paths(strict, 'grantMeta').length;
  const refused = await consent(strict, flow, page);
  assert.equal(refused.status, 409);
  assert.ok(refused.body.includes('data-sttd-source-state="required"'));
  assert.equal(paths(strict, 'grantMeta').length, metaBefore);
  // interactionは消費されていない（同意画面を再び表示できる）。
  const again = await consentPage(flow);
  assert.equal(again.status, 200);
  // 承認後でも、CSRF不正・cookie無しの同意は作らない。
  assert.equal((await approval(strict, 'POST', flow.uid, person, { body: APPROVE })).status, 200);
  const fresh = await consentPage(flow);
  const badCsrf = await consent(strict, flow, { ...fresh, csrf: randomBytes(32).toString('base64url') });
  assert.ok(badCsrf.status >= 400, `bad csrf (${badCsrf.status})`);
  const noCookie = await consent(strict, flow, await consentPage(flow), { cookies: false });
  assert.ok(noCookie.status >= 400, `no cookie (${noCookie.status})`);
  assert.equal(paths(strict, 'grantMeta').length, metaBefore);
  // 正しいcookie/CSRFなら完了する。
  const ok = await consent(strict, flow, await consentPage(flow));
  assert.ok([302, 303].includes(ok.status), `consent (${ok.status})`);
  assert.equal(paths(strict, 'grantMeta').length, metaBefore + 1);
});

test('受信先設定の保護: 承認なし・承認後の停止では確認付きの同意でも旧受信先設定を消さない', async () => {
  const person = await strict.enrollPerson('uid-http-e');
  const flow = await startFlow(strict);
  await login(strict, flow, person);
  const ownerId = strict.docs.get(`${strict.root}/identities/${person.identityHash}`).data.ownerId;
  const b64 = (buffer) => Buffer.from(buffer).toString('base64url');
  const capsule = () => `${KMS_CAPSULE_PREFIX}${b64(Buffer.from(JSON.stringify([kmsVersionName(strict.policy.cryptoKey, 1), b64(randomBytes(48))]), 'utf8'))}`;
  const subscriptionPath = `sttdAuth/${strict.SUB_NS}/subscriptions/${ownerId}`;
  const id = `sub_${'a'.repeat(64)}`;
  strict.write(
    subscriptionPath,
    kmsStateDocument(ownerId, { active: { id, ownerId, grantId: 'grant-old', sealedUrl: capsule(), sealedSecret: capsule(), secretHash: 'c'.repeat(64), previousSecret: null, expiresAt: null }, knownDestinationId: id, pending: null, lastEnded: null }),
  );
  const before = JSON.stringify(strict.docs.get(subscriptionPath).data);
  const page = await consentPage(flow);
  assert.equal(page.confirmBox, true, 'existing receiver settings ask for confirmation');
  const refused = await consent(strict, flow, { ...page, confirm: true });
  assert.equal(refused.status, 409);
  assert.equal(JSON.stringify(strict.docs.get(subscriptionPath).data), before);
  // 承認の後にsourceが停止された同意も、受信先設定を消さない。
  assert.equal((await approval(strict, 'POST', flow.uid, person, { body: APPROVE })).status, 200);
  strict.write(`${strict.root}/sources/${person.record.sourceId}`, { ...person.record, state: 'disabled', updatedAt: person.record.updatedAt + 1 });
  const stopped = await consent(strict, flow, { ...(await consentPage(flow)), confirm: true });
  assert.equal(stopped.status, 409);
  assert.equal(JSON.stringify(strict.docs.get(subscriptionPath).data), before);
});

test('期限: 承認の5分を過ぎた同意はGrantを作らない', async () => {
  const person = await strict.enrollPerson('uid-http-f');
  const flow = await startFlow(strict);
  await login(strict, flow, person);
  assert.equal((await approval(strict, 'POST', flow.uid, person, { body: APPROVE })).status, 200);
  const page = await consentPage(flow);
  const metaBefore = paths(strict, 'grantMeta').length;
  strict.offset.ms = 301_000;
  try {
    const late = await consent(strict, flow, page);
    assert.ok(![302, 303].includes(late.status), `expired (${late.status})`);
  } finally {
    strict.offset.ms = 0;
  }
  assert.equal(paths(strict, 'grantMeta').length, metaBefore);
});

test('互換配置（strict起動設定なし）: 承認routeは404、同意は承認なしで従来どおり完了する', async () => {
  const flow = await startFlow(compat);
  const uid = 'uid-http-compat';
  const { connectIdentityHash } = await import('../dist/connect/firestore.js');
  compat.write(`${compat.root}/access/${connectIdentityHash(compat.hasher, compat.NS, { projectId: 'sttd-http-test', uid })}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: Date.now() });
  await login(compat, flow, { idToken: `id-${uid}` });
  const page = await consentPage(flow);
  assert.equal(page.sourceState, null);
  const route = await compat.browser().request('GET', `/v1/source/approvals/${flow.uid}`, { cookies: false, headers: { Authorization: `Bearer id-${uid}` } });
  assert.equal(route.status, 404);
  const done = await consent(compat, flow, page);
  assert.ok([302, 303].includes(done.status), `compat consent (${done.status})`);
  assert.equal(paths(compat, 'sourceGrants').length, 0);
});
