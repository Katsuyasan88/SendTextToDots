// MCP Eventsのcallback検証の送出（dist/egress/verification-sender.js）を、安全な送出（dist/egress/safe-egress.js）の実TLS経路と
// loopbackの受信機（試験専用CA・試験用connector）で確かめる。成功は受信機がchallengeを返した応答だけで、失敗は固定の4分類
// （connection_refused・timeout・tls_error・challenge_failed）だけを運ぶ。製品の宛先ポリシー（dist/egress/product.js）はloopbackへ
// 1本も接続しない。URL・IP・secret・本文・元例外は失敗に入らない。外部network・実callback 0。

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createProductEgress } from '../dist/egress/product.js';
import { createSafeEgress } from '../dist/egress/safe-egress.js';
import { createEgressVerificationSender } from '../dist/egress/verification-sender.js';
import { VerificationSendError } from '../dist/events/subscriptions.js';
import { CALLBACK_HOST, closedPort, createTlsFixture, fixtureConnector, OTHER_HOST, startReceiver } from './egress-helpers.mjs';

const tls = createTlsFixture();
const SECRET = 'whsec_fixture-secret-value-0123456789';
const request = (url, challenge = 'challenge-fixture-value') => ({
  url,
  headers: { 'content-type': 'application/json', 'webhook-id': 'msg_fixture', 'webhook-signature': `v1,${SECRET}` },
  body: JSON.stringify({ type: 'sttd.verification', challenge }),
});
const senderFor = (receiverPort, options = {}) => createEgressVerificationSender(createSafeEgress(fixtureConnector({ dns: { [CALLBACK_HOST]: ['127.0.0.1'], [OTHER_HOST]: ['127.0.0.1'] }, port: receiverPort, ca: tls.ca, ...options })));
async function failure(promise) {
  const error = await promise.then(
    () => assert.fail('must not succeed'),
    (thrown) => thrown,
  );
  assert.ok(error instanceof VerificationSendError);
  assert.deepEqual(Object.keys(error).sort(), ['name', 'reason']);
  for (const leak of [SECRET, CALLBACK_HOST, '127.0.0.1', 'challenge-fixture-value']) assert.equal(`${error.message}\n${error.stack}`.includes(leak), false, leak);
  return error.reason;
}

test('V1 a verification POST travels over the real TLS path once: the receiver gets the fixed headers and body only (no cookie, authorization or caller header) and the echoed challenge comes back as the response', async (t) => {
  const receiver = await startReceiver(t, tls.good);
  const response = await senderFor(receiver.port)(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal);
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), { challenge: 'challenge-fixture-value' });
  assert.equal(receiver.requests.length, 1);
  const [record] = receiver.requests;
  assert.deepEqual([record.method, record.url, record.servername], ['POST', '/hook', CALLBACK_HOST]);
  assert.equal(record.headers.cookie, undefined);
  assert.equal(record.headers.authorization, undefined);
  assert.equal(record.headers['webhook-id'], 'msg_fixture');
  assert.equal(JSON.parse(record.body).challenge, 'challenge-fixture-value');
});

test('V2 failures carry only the fixed reason: an unknown name and a closed port are connection_refused, an untrusted or expired certificate and a name outside the SAN are tls_error, a redirect and an oversized reply are challenge_failed', async (t) => {
  const port = await closedPort();
  assert.equal(await failure(senderFor(port, { dns: {} })(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal)), 'connection_refused');
  assert.equal(await failure(senderFor(port)(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal)), 'connection_refused');
  for (const credentials of [tls.untrusted, tls.expired]) {
    const receiver = await startReceiver(t, credentials);
    assert.equal(await failure(senderFor(receiver.port)(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal)), 'tls_error');
    assert.equal(receiver.requests.length, 0, 'no request on a failed handshake');
  }
  const good = await startReceiver(t, tls.good);
  assert.equal(await failure(senderFor(good.port)(request(`https://${OTHER_HOST}/hook`), new AbortController().signal)), 'tls_error');
  good.handle = (_req, res) => {
    res.writeHead(302, { location: `https://${CALLBACK_HOST}/elsewhere`, 'content-length': '0' });
    res.end();
  };
  assert.equal(await failure(senderFor(good.port)(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal)), 'challenge_failed');
  good.handle = (_req, res) => {
    const big = 'x'.repeat(64 * 1024);
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(big.length) });
    res.end(big);
  };
  assert.equal(await failure(senderFor(good.port)(request(`https://${CALLBACK_HOST}/hook`), new AbortController().signal)), 'challenge_failed');
  assert.equal(good.requests.length, 2, 'one request each, no retry');
});

test('V3 an aborted signal sends nothing new; the product destination policy refuses a loopback callback as challenge_failed without one connection to the receiver', async (t) => {
  const receiver = await startReceiver(t, tls.ip);
  const aborted = new AbortController();
  aborted.abort();
  assert.equal(await failure(senderFor(receiver.port)(request(`https://${CALLBACK_HOST}/hook`), aborted.signal)), 'challenge_failed');
  const before = receiver.connections;
  const product = createEgressVerificationSender(createProductEgress());
  assert.equal(await failure(product(request(`https://127.0.0.1:${receiver.port}/hook`), new AbortController().signal)), 'challenge_failed');
  assert.equal(receiver.connections, before, 'no connection from the product policy');
  assert.equal(receiver.requests.length, 0);
});

test('V4 fixture cleanup: the temporary certificate directory is gone', () => {
  assert.equal(tls.tempDirGone(), true);
});
