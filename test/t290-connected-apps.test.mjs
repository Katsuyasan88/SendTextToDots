import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { test } from 'node:test';
import { CHATGPT_CIMD_CANDIDATE as client } from '../dist/oauth/cimd.js';
import { resourceFor } from '../dist/oauth/provider.js';
import { APP_PAIR_CODE, APP_PAIR_TTL_MS, PAIR_APP_PATH } from '../dist/source/connected-apps.js';
import { newSourceGeneration, newSourceId } from '../dist/source/admin.js';
import { signSourceRequest } from '../dist/source/proof.js';
import { createAppCheckVerifier } from '../dist/source/app-check.js';
import { createSourceGate } from '../dist/source/http.js';
import { reviewerApprovalOf, validateDeploymentConfig } from '../dist/config/validate.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { startConnectHttpRuntime, syntheticFirebaseToken } from './fixtures/source-runtime.mjs';

const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'pairing-test', alg: 'ES256', use: 'sig' };
const protocol = '2026-07-28';
const form = 'application/x-www-form-urlencoded';

async function connect(rt, user, loginPath = 'login') {
  const browser = rt.browser();
  const verifier = randomBytes(32).toString('base64url');
  const resource = resourceFor(rt.issuer);
  const params = new URLSearchParams({
    response_type: 'code', client_id: client.clientId, redirect_uri: client.redirectUri, scope: 'sttd:events', resource,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', state: randomUUID(),
  });
  const redirect = await browser.request('GET', '/oauth/authorize?' + params);
  const path = new URL(redirect.headers.location, rt.issuer).pathname;
  const login = await browser.request('GET', path);
  const csrf = /data-sttd-csrf="([^"]+)"/.exec(login.body)?.[1];
  const signedIn = await browser.request('POST', path + '/' + loginPath, {
    headers: { 'Content-Type': 'application/json', Origin: rt.issuer }, body: JSON.stringify({ csrf, idToken: user.idToken }),
  });
  assert.equal(signedIn.status, 204, signedIn.body);
  const consent = await browser.request('GET', path);
  assert.doesNotMatch(consent.body, /id="sttd-source-reference"|data-sttd-source-state=/);
  const agreed = await browser.request('POST', path + '/consent', {
    headers: { 'Content-Type': form, Origin: rt.issuer },
    body: new URLSearchParams({ csrf: /name="csrf" value="([^"]+)"/.exec(consent.body)[1], receiverToken: /name="receiverToken" value="([^"]+)"/.exec(consent.body)[1] }).toString(),
  });
  assert.ok([302, 303].includes(agreed.status), agreed.body);
  const resumed = await browser.request('GET', new URL(agreed.headers.location, rt.issuer).pathname);
  const code = new URL(resumed.headers.location).searchParams.get('code');
  assert.ok(code);
  const iat = Math.floor(Date.now() / 1000);
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const jwt = part({ alg: 'ES256', kid: jwk.kid, typ: 'JWT' }) + '.' + part({ iss: client.clientId, sub: client.clientId, aud: rt.issuer + '/oauth/token', jti: randomUUID(), iat, exp: iat + 60 });
  const assertion = jwt + '.' + sign('sha256', Buffer.from(jwt), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const tokens = await rt.browser().request('POST', '/oauth/token', {
    headers: { 'Content-Type': form },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: client.redirectUri, code_verifier: verifier, resource,
      client_id: client.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }).toString(),
  });
  assert.equal(tokens.status, 200, tokens.body);
  return JSON.parse(tokens.body).access_token;
}

async function mcp(rt, token, name, args, method = name === undefined ? 'tools/list' : 'tools/call') {
  const _meta = { 'io.modelcontextprotocol/protocolVersion': protocol, 'io.modelcontextprotocol/clientCapabilities': {} };
  const response = await rt.browser().request('POST', '/mcp', {
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': protocol, 'Mcp-Method': method, ...(name ? { 'Mcp-Name': name } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...(name ? { name } : {}), ...(method === 'tools/call' ? { arguments: args } : args), _meta } }),
  });
  assert.equal(response.status, 200, response.body);
  const parsed = JSON.parse(response.body);
  assert.ok(parsed.result, response.body);
  return method === 'tools/list' ? parsed.result.tools : method === 'tools/call' ? parsed.result.structuredContent : parsed.result;
}

function appRequest(rt, user, method, path, body) {
  const issuedAt = Math.floor(rt.clock.now() / 1000);
  const sourceId = user.record.sourceId;
  const bearer = user.idToken;
  const signature = signSourceRequest(
    { audience: rt.issuer, method, path, search: '', sourceId, body: Buffer.from(body ?? ''), bearer, idempotencyKey: undefined },
    { issuedAt, expiresAt: issuedAt + 60, nonce: randomBytes(16).toString('base64url') }, user.privateKey,
  );
  return rt.browser().request(method, path, {
    headers: { Authorization: 'Bearer ' + bearer, 'x-sttd-source': sourceId, 'x-sttd-source-signature': signature, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body,
  });
}

test('account OAuth, app pairing, revocation and disconnect work without the old source approval', async (t) => {
  const deliveries = [];
  const rt = await startConnectHttpRuntime({
    clientJwks: [jwk], connectedApps: true, echoChallenge: true,
    sendText: {
      namespace: 't270_' + randomUUID(),
      loadDigestKey: async () => randomBytes(32),
      egress: { async postCommandCallback(url, post) { deliveries.push({ url, body: post.body.toString('utf8') }); return { status: 200 }; } },
    },
  });
  t.after(() => rt.close());
  const alice = await rt.enrollPerson('pair-alice', ['connect', 'send']);
  const bob = await rt.enrollPerson('pair-bob', ['connect', 'send']);
  const token = await connect(rt, alice);
  const otherToken = await connect(rt, bob);
  const tool = (name, args) => mcp(rt, token, name, args);
  const issue = (name = 'Playground') => tool('add_connected_app', { name });
  const use = (user, code) => appRequest(rt, user, 'POST', PAIR_APP_PATH, JSON.stringify({ code }));
  const allowed = async () => JSON.parse((await appRequest(rt, alice, 'GET', PAIR_APP_PATH)).body).allowed;
  const gate = createSourceGate({ policy: { mode: 'strict-v1', methods: ['developer-key-v1'] }, store: rt.sources, hasher: rt.hasher, namespace: rt.NS, audience: rt.issuer, clock: rt.clock });
  const finalDispatch = () => rt.db.runTransaction(gate.dispatchCheck(alice.record, 'send', { projectId: rt.projectId, uid: alice.uid }));
  const advertisedTools = await tool();
  assert.deepEqual(advertisedTools.map((item) => item.name), ['get_receiving_status', 'send_text', 'list_connected_apps', 'add_connected_app', 'remove_connected_app']);
  assert.equal(advertisedTools.find((item) => item.name === 'add_connected_app').annotations.destructiveHint, true);
  assert.deepEqual(await tool('get_receiving_status'), { state: 'linked' });
  assert.deepEqual(await tool('list_connected_apps'), { apps: [] });
  assert.equal(await allowed(), false);
  assert.equal(await finalDispatch(), false);
  assert.equal([...rt.docs.keys()].some((path) => path.includes('/sourceApprovals/')), false);

  const replaced = await issue();
  const first = await issue();
  assert.match(first.code, APP_PAIR_CODE);
  assert.notEqual(first.code, replaced.code);
  assert.ok([...rt.docs.entries()].filter(([path]) => path.includes('/appPairingCodes/')).every(([, doc]) => !JSON.stringify(doc).includes(first.code)));
  assert.equal((await use(alice, replaced.code)).status, 400);
  assert.equal((await use(bob, first.code)).status, 400);
  assert.deepEqual((await Promise.all([use(alice, first.code), use(alice, first.code)])).map((r) => r.status).sort(), [200, 400]);
  assert.deepEqual(await tool('list_connected_apps'), { apps: [{ appId: alice.record.sourceId, name: 'Playground' }] });
  assert.equal(await allowed(), true);
  assert.equal(await finalDispatch(), true);
  assert.deepEqual(await mcp(rt, otherToken, 'remove_connected_app', { appId: alice.record.sourceId }), { removed: false });
  assert.deepEqual(await tool('remove_connected_app', { appId: alice.record.sourceId }), { removed: true });
  assert.deepEqual(await tool('list_connected_apps'), { apps: [] });
  assert.equal(await allowed(), false);
  assert.equal(await finalDispatch(), false);
  assert.deepEqual(await tool('get_receiving_status'), { state: 'linked' });

  const destination = 'https://hooks.pairing.example/dot';
  const subscription = await mcp(rt, token, 'text.submitted', {
    delivery: { mode: 'webhook', url: destination, secret: 'whsec_' + randomBytes(32).toString('base64') },
  }, 'events/subscribe');
  assert.equal(typeof subscription.id, 'string');
  assert.deepEqual(await tool('get_receiving_status'), { state: 'subscribed' });
  const text = 'A synthetic message for the current Dot';
  assert.deepEqual(await tool('send_text', { text }), { status: 'delivered' });
  assert.equal(deliveries[0].url, destination);
  assert.ok(deliveries[0].body.includes(text));

  const expired = await issue();
  rt.offset.ms += APP_PAIR_TTL_MS;
  assert.equal((await use(alice, expired.code)).status, 400);
  const again = await issue();
  assert.equal((await use(alice, again.code)).status, 200);
  const pending = await issue();
  const disconnected = await rt.browser().request('POST', '/v1/web/disconnect', { headers: { Authorization: 'Bearer ' + alice.idToken } });
  assert.equal(disconnected.status, 200, disconnected.body);
  assert.equal((await use(alice, pending.code)).status, 400);
  assert.equal(await allowed(), false);
  assert.equal(await finalDispatch(), false);
  assert.equal(deliveries.length, 1);
});

test('a legacy subscription carries its valid sending app to the first new connection without retaining the old Dot', async (t) => {
  const deliveries = [];
  const rt = await startConnectHttpRuntime({
    clientJwks: [jwk], connectedApps: true, echoChallenge: true,
    sendText: {
      namespace: 't270_' + randomUUID(),
      loadDigestKey: async () => randomBytes(32),
      egress: { async postCommandCallback(url) { deliveries.push(url); return { status: 200 }; } },
    },
  });
  t.after(() => rt.close());
  const user = await rt.enrollPerson('legacy-owner', ['connect', 'send']);
  const previousToken = await connect(rt, user);
  const bound = { sourceId: user.record.sourceId, generation: user.record.generation };
  const accountMarker = rt.root + '/connectedAppOwners/' + user.identityHash;
  const grantPaths = [...rt.docs.keys()].filter((path) => path.startsWith(rt.root + '/sourceGrants/'));
  assert.equal(grantPaths.length, 1);
  // The existing OAuth grant and receiver are real fixture data. Use the old persisted grant binding and omit the migration marker.
  assert.equal(rt.docs.delete(accountMarker), true);
  rt.write(grantPaths[0], bound);
  rt.write(rt.root + '/playgroundBindings/' + user.identityHash, { version: 1, ...bound });
  const alternate = { ...user.record, sourceId: newSourceId(), generation: newSourceGeneration() };
  assert.equal(await rt.sources.create(alternate), 'created');
  const alternateUser = { ...user, record: alternate };
  const allowed = async (sourceUser) => {
    const response = await appRequest(rt, sourceUser, 'GET', PAIR_APP_PATH);
    assert.equal(response.status, 200, response.body);
    return JSON.parse(response.body).allowed;
  };
  const register = (token, url) => mcp(rt, token, 'text.submitted', {
    delivery: { mode: 'webhook', url, secret: 'whsec_' + randomBytes(32).toString('base64') },
  }, 'events/subscribe');
  const message = { text: 'Check the delivery destination' };
  const oldDot = 'https://hooks.pairing.example/old-dot';
  const newDot = 'https://hooks.pairing.example/new-dot';
  assert.equal(typeof (await register(previousToken, oldDot)).id, 'string');
  assert.deepEqual(await mcp(rt, previousToken, 'get_receiving_status'), { state: 'subscribed' });
  assert.equal(await allowed(user), true);
  assert.equal(await allowed(alternateUser), true);
  assert.deepEqual(await mcp(rt, previousToken, 'send_text', message), { status: 'delivered' });

  const token = await connect(rt, user);
  assert.deepEqual(await mcp(rt, token, 'get_receiving_status'), { state: 'linked' });
  assert.deepEqual(await mcp(rt, token, 'list_connected_apps'), {
    apps: [{ appId: bound.sourceId, name: 'SendTextToDots Playground' }],
  });
  assert.equal(await allowed(user), true);
  assert.equal(await allowed(alternateUser), false);
  assert.deepEqual(await mcp(rt, token, 'send_text', message), { status: 'not_delivered' });
  await assert.rejects(register(previousToken, oldDot), 'the old grant cannot restore the previous receiver');
  assert.deepEqual(deliveries, [oldDot]);

  assert.equal(typeof (await register(token, newDot)).id, 'string');
  assert.deepEqual(await mcp(rt, token, 'send_text', message), { status: 'delivered' });
  assert.deepEqual(deliveries, [oldDot, newDot]);
  assert.deepEqual(await mcp(rt, token, 'remove_connected_app', { appId: bound.sourceId }), { removed: true });
  const { code } = await mcp(rt, token, 'add_connected_app', { name: 'Another app' });
  const reconnected = await connect(rt, user);
  assert.deepEqual(await mcp(rt, reconnected, 'list_connected_apps'), { apps: [] });
  assert.equal(await allowed(user), false);
  assert.equal((await appRequest(rt, alternateUser, 'POST', PAIR_APP_PATH, JSON.stringify({ code }))).status, 400);
});

test('account-based reviewer sign-in and Work tools do not need the legacy approval key', async (t) => {
  const uid = 'SyntheticPairReviewer00001';
  const config = {
    ...structuredClone(SYNTHETIC), connectedApps: true,
    sourceAuthorization: { mode: 'strict-v1', methods: ['developer-key-v1'] },
    reviewerLogin: { mode: 'reviewer-password-v1', uids: [uid] },
  };
  assert.equal(reviewerApprovalOf(validateDeploymentConfig(config)), undefined);
  const oldReviewer = { ...config.reviewerLogin, approvalSourceId: newSourceId() };
  assert.equal(reviewerApprovalOf(validateDeploymentConfig({ ...config, reviewerLogin: oldReviewer })), undefined);

  const deliveries = [];
  const rt = await startConnectHttpRuntime({
    clientJwks: [jwk], connectedApps: true, echoChallenge: true, reviewer: { uids: [uid] },
    sendText: {
      namespace: 't270_' + randomUUID(),
      loadDigestKey: async () => randomBytes(32),
      egress: { async postCommandCallback(url) { deliveries.push(url); return { status: 200 }; } },
    },
  });
  t.after(() => rt.close());
  const account = await rt.enrollPerson(uid, ['send']);
  const reviewer = {
    ...account,
    idToken: syntheticFirebaseToken({ sub: uid, provider: 'password', authTimeSec: Math.floor(rt.clock.now() / 1000) }),
  };
  const token = await connect(rt, reviewer, 'reviewer');
  assert.deepEqual(await mcp(rt, token, 'get_receiving_status'), { state: 'linked' });
  assert.deepEqual(await mcp(rt, token, 'list_connected_apps'), { apps: [] });
  const issued = await mcp(rt, token, 'add_connected_app', { name: 'Review demo app' });
  assert.match(issued.code, APP_PAIR_CODE);
  assert.deepEqual(await mcp(rt, token, 'list_connected_apps'), { apps: [] });
  const externalRedemption = await appRequest(rt, reviewer, 'POST', PAIR_APP_PATH, JSON.stringify({ code: issued.code }));
  assert.equal(externalRedemption.status, 401);

  const dot = 'https://hooks.pairing.example/reviewer-dot';
  await mcp(rt, token, 'text.submitted', { delivery: { mode: 'webhook', url: dot, secret: 'whsec_' + randomBytes(32).toString('base64') } }, 'events/subscribe');
  assert.deepEqual(await mcp(rt, token, 'get_receiving_status'), { state: 'subscribed' });
  assert.deepEqual(await mcp(rt, token, 'send_text', { text: 'Hello from SendTextToDots.' }), { status: 'delivered' });
  assert.deepEqual(deliveries, [dot]);
  assert.equal([...rt.docs.keys()].some((path) => path.includes('/sourceApprovals/')), false);
});

test('iPhone pairing uses a fresh App Check proof and unlocks both key fetch and sending', async (t) => {
  const number = '123456789012';
  const appId = '1:' + number + ':ios:abc123';
  const differentApp = '1:' + number + ':ios:def456';
  const consumed = new Set();
  const appCheck = {
    async verifyToken(token, options) {
      assert.deepEqual(options, { consume: true });
      const alreadyConsumed = consumed.has(token);
      consumed.add(token);
      const sub = token.startsWith('other.') ? differentApp : appId;
      return { appId: sub, token: { sub, aud: ['projects/' + number], iss: 'https://firebaseappcheck.googleapis.com/' + number }, alreadyConsumed };
    },
  };
  const rt = await startConnectHttpRuntime({ clientJwks: [jwk], connectedApps: true, appCheck });
  t.after(() => rt.close());
  const uid = 'iphone-pairing';
  rt.allow(uid);
  const user = { uid, idToken: 'id-' + uid };
  const app = {
    schemaVersion: 1, sourceId: newSourceId(), generation: newSourceGeneration(), kind: 'app',
    appId, state: 'active', operations: ['send', 'keys'], createdAt: rt.clock.now(), updatedAt: rt.clock.now(),
  };
  assert.equal(await rt.sources.create(app), 'created');
  const auth = { Authorization: 'Bearer ' + user.idToken, 'x-sttd-source': app.sourceId };
  const proof = (kind = 'iphone') => kind + '.' + randomBytes(12).toString('base64url') + '.synthetic';
  const pair = (method, token, code) => rt.browser().request(method, PAIR_APP_PATH, {
    headers: { ...auth, 'x-firebase-appcheck': token, ...(code ? { 'Content-Type': 'application/json' } : {}) },
    body: code ? JSON.stringify({ code }) : undefined,
  });
  const status = async () => {
    const result = await pair('GET', proof());
    assert.equal(result.status, 200, result.body);
    return JSON.parse(result.body);
  };
  const deliveryGate = createSourceGate({
    policy: { mode: 'strict-v1', methods: ['app-check-v1'] }, store: rt.sources, hasher: rt.hasher,
    namespace: rt.NS, audience: 'https://api.pairing.example', clock: rt.clock,
    appCheck: createAppCheckVerifier({ appCheck, projectId: rt.projectId, projectNumber: number }),
  });
  const allowAtApi = (operation) => deliveryGate.authorize(
    { method: 'app-check-v1', sourceId: app.sourceId, token: proof() },
    {
      identity: { projectId: rt.projectId, uid: user.uid }, operation,
      method: operation === 'keys' ? 'GET' : 'POST',
      path: operation === 'keys' ? '/v2/encryption-key' : '/v2/encrypted-commands',
      search: '', body: Buffer.alloc(0), bearer: user.idToken, idempotencyKey: undefined,
    },
  );

  const token = await connect(rt, user);
  const { code } = await mcp(rt, token, 'add_connected_app', { name: 'DPADAA' });
  assert.deepEqual(await status(), { allowed: false });
  assert.equal((await allowAtApi('keys')).kind, 'denied');
  assert.equal((await allowAtApi('send')).kind, 'denied');
  assert.equal((await pair('POST', proof('other'), code)).status, 403);
  const single = proof();
  const registered = await pair('POST', single, code);
  assert.equal(registered.status, 200, registered.body);
  assert.deepEqual(JSON.parse(registered.body), { linked: true });
  assert.equal((await pair('GET', single)).status, 403, 'proofs cannot be reused across operations');
  assert.deepEqual(await status(), { allowed: true });
  assert.equal((await allowAtApi('keys')).kind, 'allowed');
  assert.equal((await allowAtApi('send')).kind, 'allowed');
  assert.deepEqual(await mcp(rt, token, 'remove_connected_app', { appId: app.sourceId }), { removed: true });
  assert.deepEqual(await status(), { allowed: false });
  assert.equal((await allowAtApi('keys')).kind, 'denied');
  assert.equal((await allowAtApi('send')).kind, 'denied');
});
