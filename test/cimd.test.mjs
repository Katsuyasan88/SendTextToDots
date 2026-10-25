// CIMD（Client ID Metadata Document）のclient方針（dist/oauth/cimd.js）を、合成の送出portと制御した時計で確かめる。
//   - 取得: 許可した2つのURL（文書・JWKS）へのGETだけを安全な送出へ渡し、呼出し元の見出し・signal・本文は渡さない。他のURL・method・
//     本文付きは送出0で拒否。成功・失敗とも60秒の間隔内は同じ結果を再利用し、時計が戻れば取り直す。応答見出しは捨てる。
//   - client: client_idの完全一致だけ取得を許し、取得した文書のredirect・認証方式・JWKS URL・応答/grant typeが許可値と一致する時だけ使う。
//   - assertion: sub＝client_id・jtiの形・整数exp・client_idとjtiの組の単回予約（再使用は拒否）。
// 送出・DNS・TLS・子process 0。

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { errors } from 'oidc-provider';

import {
  CHATGPT_CIMD_CANDIDATE as ALLOWED,
  CIMD_FETCH_MIN_INTERVAL_MS,
  CIMD_FETCH_TIMEOUT_MS,
  CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC,
  createAllowClient,
  createAllowFetch,
  createAssertClientAssertion,
  createCimdClientPolicy,
  createCimdFetch,
} from '../dist/oauth/cimd.js';

const BASE = 1_900_000_000_000;
const clockState = { value: BASE };
const clock = { now: () => clockState.value };

function fakeEgress(responses = {}) {
  const calls = [];
  return {
    calls,
    getJson(url, options) {
      calls.push({ url, options, argc: arguments.length });
      const reply = responses[url] ?? { status: 200, body: '{}' };
      return reply instanceof Error ? Promise.reject(reply) : Promise.resolve(reply);
    },
  };
}
const replay = () => {
  const reserved = new Map();
  return {
    reserved,
    async reserve(key, expiresAt, now) {
      if (reserved.has(key) && reserved.get(key) > now) return false;
      reserved.set(key, expiresAt);
      return true;
    },
  };
};

test('F1 fetch: only GET to the 2 allowed URLs reaches the egress with just {timeoutMs: 2500}; other URLs, methods and bodies are refused with no egress call; caller headers and signal are never passed on; response headers are dropped', async () => {
  const egress = fakeEgress({ [ALLOWED.clientId]: { status: 200, body: '{"client_id":"x"}', headers: { 'set-cookie': 'a=b' } } });
  const outcomes = [];
  const fetchFn = createCimdFetch({ allowed: ALLOWED, egress, assertionReplay: replay(), clock, onFetch: (outcome, target) => outcomes.push(`${outcome}:${target}`) });
  const signal = new AbortController().signal;
  const response = await fetchFn(ALLOWED.clientId, { method: 'GET', headers: { authorization: 'Bearer leak', cookie: 'c=d' }, signal });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"client_id":"x"}');
  assert.equal(response.headers.get('set-cookie'), null);
  assert.deepEqual(egress.calls, [{ url: ALLOWED.clientId, options: { timeoutMs: CIMD_FETCH_TIMEOUT_MS }, argc: 2 }]);
  await fetchFn(new URL(ALLOWED.jwksUri));
  assert.equal(egress.calls.at(-1).url, ALLOWED.jwksUri);
  const refusals = [
    () => fetchFn('https://chatgpt.com/other.json'),
    () => fetchFn(`${ALLOWED.clientId}?x=1`),
    () => fetchFn(ALLOWED.clientId.replace('https:', 'http:')),
    () => fetchFn(ALLOWED.clientId, { method: 'POST' }),
    () => fetchFn(ALLOWED.jwksUri, { method: 'GET', body: 'x' }),
    () => fetchFn({ url: ALLOWED.clientId }),
  ];
  for (const call of refusals) await assert.rejects(call(), (error) => error?.name === 'EgressError' && error.kind === 'destination_forbidden');
  assert.equal(egress.calls.length, 2, 'no egress call for a refused request');
  assert.deepEqual(outcomes, ['fetched:client_metadata', 'fetched:jwks', 'refused:other', 'refused:other', 'refused:other', 'refused:client_metadata', 'refused:jwks', 'refused:other']);
});

test('F2 fetch interval: a success and a failure are reused for 60 s (no new egress call), refetched at the interval, and refetched when the clock goes back; an out-of-range status is a protocol error', async () => {
  clockState.value = BASE;
  const failing = new Error('egress failure');
  const egress = fakeEgress({ [ALLOWED.jwksUri]: failing, [ALLOWED.clientId]: { status: 700, body: '' } });
  const fetchFn = createCimdFetch({ allowed: ALLOWED, egress, assertionReplay: replay(), clock });
  await assert.rejects(fetchFn(ALLOWED.jwksUri));
  clockState.value = BASE + CIMD_FETCH_MIN_INTERVAL_MS - 1;
  await assert.rejects(fetchFn(ALLOWED.jwksUri));
  assert.equal(egress.calls.length, 1, 'failure reused within the interval');
  clockState.value = BASE + CIMD_FETCH_MIN_INTERVAL_MS;
  await assert.rejects(fetchFn(ALLOWED.jwksUri));
  assert.equal(egress.calls.length, 2, 'refetched at the interval');
  clockState.value = BASE;
  await assert.rejects(fetchFn(ALLOWED.jwksUri));
  assert.equal(egress.calls.length, 3, 'refetched after the clock went back');
  await assert.rejects(fetchFn(ALLOWED.clientId), (error) => error?.kind === 'protocol_error');
});

test('C1 client: only the exact client_id may be fetched; a fetched client is used only with the single allowed redirect, private_key_jwt, the allowed JWKS URL, no embedded keys or secret, response type code and authorization_code (+refresh_token) grants', () => {
  const allowFetch = createAllowFetch(ALLOWED);
  assert.equal(allowFetch(undefined, ALLOWED.clientId), true);
  for (const other of [`${ALLOWED.clientId}/`, ALLOWED.clientId.toUpperCase(), 'https://chatgpt.com/oauth/client.json?x', ALLOWED.jwksUri]) assert.equal(allowFetch(undefined, other), false, other);
  const allowClient = createAllowClient(ALLOWED);
  const good = { client_id: ALLOWED.clientId, redirect_uris: [ALLOWED.redirectUri], token_endpoint_auth_method: 'private_key_jwt', jwks_uri: ALLOWED.jwksUri, response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'] };
  const client = (metadata) => ({ metadata: () => metadata });
  assert.equal(allowClient(undefined, client(good)), true);
  const bad = {
    otherId: { ...good, client_id: 'https://evil.example/client.json' },
    twoRedirects: { ...good, redirect_uris: [ALLOWED.redirectUri, 'https://evil.example/cb'] },
    otherRedirect: { ...good, redirect_uris: ['https://evil.example/cb'] },
    secretAuth: { ...good, token_endpoint_auth_method: 'client_secret_basic' },
    otherJwks: { ...good, jwks_uri: 'https://evil.example/jwks.json' },
    embeddedJwks: { ...good, jwks: { keys: [] } },
    secret: { ...good, client_secret: 'x' },
    tokenResponse: { ...good, response_types: ['code', 'token'] },
    implicitGrant: { ...good, grant_types: ['authorization_code', 'implicit'] },
    noCodeGrant: { ...good, grant_types: ['refresh_token'] },
  };
  for (const [name, metadata] of Object.entries(bad)) assert.equal(allowClient(undefined, client(metadata)), false, name);
});

test('A1 assertion: sub must equal client_id, jti must be 1–256 printable characters, exp an integer; the (client_id, jti) pair is reserved once until exp + 15 s and a reuse is refused', async () => {
  clockState.value = BASE;
  const store = replay();
  const assertClaims = createAssertClientAssertion({ assertionReplay: store, clock });
  const client = { clientId: ALLOWED.clientId };
  const exp = Math.floor(BASE / 1000) + 60;
  await assertClaims(undefined, { sub: ALLOWED.clientId, jti: 'jti-1', exp }, {}, client);
  assert.equal(store.reserved.size, 1);
  assert.equal([...store.reserved.values()][0], (exp + CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC) * 1000);
  const refused = [
    { sub: ALLOWED.clientId, jti: 'jti-1', exp },
    { sub: 'https://evil.example/client.json', jti: 'jti-2', exp },
    { sub: ALLOWED.clientId, jti: '', exp },
    { sub: ALLOWED.clientId, jti: 'x'.repeat(257), exp },
    { sub: ALLOWED.clientId, jti: 'has space', exp },
    { sub: ALLOWED.clientId, jti: 'jti-3', exp: exp + 0.5 },
    { sub: ALLOWED.clientId, jti: 'jti-4', exp: String(exp) },
  ];
  for (const claims of refused) await assert.rejects(assertClaims(undefined, claims, {}, client), (error) => error instanceof errors.InvalidClientAuth, JSON.stringify(claims));
  assert.equal(store.reserved.size, 1, 'only the first pair was reserved');
});

test('P1 policy bundle: non-canonical https URLs are refused at construction; the bundle enables the draft feature with the allow checks, the limited fetch and the assertion check, and caps the document at 5 KiB and JWKS at the egress limit', () => {
  for (const allowed of [
    { ...ALLOWED, clientId: 'http://chatgpt.com/oauth/client.json' },
    { ...ALLOWED, redirectUri: 'https://chatgpt.com/cb#x' },
    { ...ALLOWED, jwksUri: 'https://user@chatgpt.com/oauth/jwks.json' },
  ]) {
    assert.throws(() => createCimdClientPolicy({ allowed, egress: fakeEgress(), assertionReplay: replay(), clock }));
  }
  const policy = createCimdClientPolicy({ allowed: ALLOWED, egress: fakeEgress(), assertionReplay: replay(), clock });
  assert.deepEqual([policy.feature.enabled, policy.feature.ack, typeof policy.feature.allowFetch, typeof policy.feature.allowClient, typeof policy.fetch, typeof policy.assertJwtClientAuthClaimsAndHeader], [true, 'draft-02', 'function', 'function', 'function', 'function']);
  assert.deepEqual(policy.fetchResponseBodyLimits, { 'client_id metadata document': 5 * 1024, jwks_uri: 8192 });
});
