// 許可元の証明（source/proof.ts）とApp Check verifier（source/app-check.ts）。
//   - Ed25519要求署名: 宛先・method・path・query・本文・本人token・Idempotency-Key・source ID・時刻・nonceの流用を全て拒否。
//   - header: 欠落と不正（重複・両方式の併記・形違い）を区別。期限は最大60秒・時計許容30秒。
//   - App Check: verifyTokenを毎回consume:trueで呼び、消費済み・消費結果不明・別project・SDK障害を通さない。
//   - 実firebase-admin 14.5.0のgetAppCheck/verifyTokenの存在だけをlocalで確かめる（SDKの外向き通信・実token 0。consumeの実挙動はT091の配置確認）。
// 鍵は試験内で生成する合成鍵だけ。

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { test } from 'node:test';

import { createAppCheckVerifier } from '../dist/source/app-check.js';
import {
  normalizeSourcePublicKey,
  parseSourceProof,
  signatureTimeVerdict,
  signSourceRequest,
  verifySourceSignature,
} from '../dist/source/proof.js';

const SOURCE = 'src_abcdefghijklmnopqrstuvwxyz';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const RAW = publicKey.export({ format: 'jwk' }).x;
const request = {
  audience: 'https://api-a.example.org',
  method: 'POST',
  path: '/v2/commands',
  search: '',
  sourceId: SOURCE,
  body: Buffer.from('{"text":"synthetic"}'),
  bearer: 'synthetic.id.token',
  idempotencyKey: 'key-1',
};
const claims = { issuedAt: 1_700_000_000, expiresAt: 1_700_000_060, nonce: randomBytes(16).toString('base64url') };

function parsedSignature(header) {
  const parsed = parseSourceProof({ 'x-sttd-source': SOURCE, 'x-sttd-source-signature': header });
  assert.equal(parsed.kind, 'present');
  return parsed.proof;
}

test('署名: 同じ要求だけ通り、要素を1つでも変えると拒否する', () => {
  const proof = parsedSignature(signSourceRequest(request, claims, privateKey));
  assert.equal(verifySourceSignature(RAW, request, proof.claims, proof.signature), true);
  const variants = [
    { audience: 'https://api-b.example.org' },
    { method: 'GET' },
    { path: '/v2/encrypted-commands' },
    { search: '?x=1' },
    { sourceId: 'src_bbbbbbbbbbbbbbbbbbbbbbbbbb' },
    { body: Buffer.from('{"text":"other"}') },
    { bearer: 'other.id.token' },
    { idempotencyKey: 'key-2' },
    { idempotencyKey: undefined },
  ];
  for (const change of variants) assert.equal(verifySourceSignature(RAW, { ...request, ...change }, proof.claims, proof.signature), false);
  assert.equal(verifySourceSignature(RAW, request, { ...proof.claims, nonce: 'A'.repeat(22) }, proof.signature), false);
  assert.equal(verifySourceSignature(RAW, request, { ...proof.claims, expiresAt: claims.expiresAt - 1 }, proof.signature), false);
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;
  assert.equal(verifySourceSignature(other, request, proof.claims, proof.signature), false);
});

test('header: 欠落と不正（重複・併記・形違い）を区別する', () => {
  const header = signSourceRequest(request, claims, privateKey);
  assert.deepEqual(parseSourceProof({}), { kind: 'missing' });
  const malformed = [
    { 'x-sttd-source': SOURCE },
    { 'x-sttd-source-signature': header },
    { 'x-sttd-source': 'my-laptop', 'x-sttd-source-signature': header },
    { 'x-sttd-source': SOURCE, 'x-sttd-source-signature': `${header}, ${header}` },
    { 'x-sttd-source': [SOURCE, SOURCE], 'x-sttd-source-signature': header },
    { 'x-sttd-source': SOURCE, 'x-sttd-source-signature': header, 'x-firebase-appcheck': 'a.b.c' },
    { 'x-sttd-source': SOURCE, 'x-sttd-source-signature': header.replace('v1.', 'v2.') },
    { 'x-sttd-source': SOURCE, 'x-firebase-appcheck': 'not-a-jwt' },
    { 'x-firebase-appcheck': 'a.b.c' },
  ];
  for (const headers of malformed) assert.deepEqual(parseSourceProof(headers), { kind: 'malformed' });
  assert.equal(parseSourceProof({ 'x-sttd-source': SOURCE, 'x-firebase-appcheck': 'aaa.bbb.ccc' }).proof.method, 'app-check-v1');
});

test('時刻: 最大60秒の有効期間・時計許容30秒、期限は即時に判定する', () => {
  const at = (sec) => sec * 1000;
  assert.equal(signatureTimeVerdict(claims, at(claims.issuedAt)), 'ok');
  assert.equal(signatureTimeVerdict({ ...claims, expiresAt: claims.issuedAt + 61 }, at(claims.issuedAt)), 'invalid');
  assert.equal(signatureTimeVerdict({ ...claims, expiresAt: claims.issuedAt }, at(claims.issuedAt)), 'invalid');
  assert.equal(signatureTimeVerdict(claims, at(claims.issuedAt - 30)), 'ok');
  assert.equal(signatureTimeVerdict(claims, at(claims.issuedAt - 31)), 'not_yet_valid');
  assert.equal(signatureTimeVerdict(claims, at(claims.expiresAt + 30)), 'ok');
  assert.equal(signatureTimeVerdict(claims, at(claims.expiresAt + 31)), 'expired');
});

test('公開鍵: Ed25519のPEM/raw だけを登録形へ、他の鍵種は拒否する', () => {
  assert.equal(normalizeSourcePublicKey(RAW), RAW);
  assert.equal(normalizeSourcePublicKey(publicKey.export({ format: 'pem', type: 'spki' })), RAW);
  assert.equal(normalizeSourcePublicKey(generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'pem', type: 'spki' })), null);
  assert.equal(normalizeSourcePublicKey(privateKey.export({ format: 'pem', type: 'pkcs8' })), null);
  assert.equal(normalizeSourcePublicKey('not a key'), null);
});

const PROJECT_NUMBER = '123456789012';
const APP_ID = `1:${PROJECT_NUMBER}:ios:0123abcd`;
function appCheckPort(behaviour) {
  const calls = [];
  return {
    calls,
    port: {
      async verifyToken(token, options) {
        calls.push({ token, options });
        return behaviour(token, options);
      },
    },
  };
}
const decoded = (overrides = {}) => ({ iss: `https://firebaseappcheck.googleapis.com/${PROJECT_NUMBER}`, aud: [`projects/${PROJECT_NUMBER}`, 'projects/sendtexttodots-test'], sub: APP_ID, ...overrides });

test('App Check: 毎回consume:trueで呼び、消費済み・結果不明・別project・障害を通さない', async () => {
  const cases = [
    [() => ({ appId: APP_ID, token: decoded(), alreadyConsumed: false }), { kind: 'verified', appId: APP_ID }],
    [() => ({ appId: APP_ID, token: decoded(), alreadyConsumed: true }), { kind: 'rejected', reason: 'consumed' }],
    [() => ({ appId: APP_ID, token: decoded() }), { kind: 'unavailable' }],
    [() => ({ appId: APP_ID, token: decoded({ aud: ['projects/999999999999'] }), alreadyConsumed: false }), { kind: 'rejected', reason: 'wrong_project' }],
    [() => ({ appId: APP_ID, token: decoded({ iss: 'https://firebaseappcheck.googleapis.com/999999999999' }), alreadyConsumed: false }), { kind: 'rejected', reason: 'wrong_project' }],
    [() => ({ appId: APP_ID, token: decoded({ sub: '1:123456789012:ios:ffff' }), alreadyConsumed: false }), { kind: 'rejected', reason: 'invalid' }],
    [() => { throw Object.assign(new Error('x'), { code: 'app-check/invalid-argument' }); }, { kind: 'rejected', reason: 'invalid' }],
    [() => { throw Object.assign(new Error('x'), { code: 'app-check/permission-denied' }); }, { kind: 'unavailable' }],
    [() => { throw new Error('network'); }, { kind: 'unavailable' }],
  ];
  for (const [behaviour, expected] of cases) {
    const { port, calls } = appCheckPort(behaviour);
    const verifier = createAppCheckVerifier({ appCheck: port, projectNumber: PROJECT_NUMBER, projectId: 'sendtexttodots-test' });
    assert.deepEqual(await verifier.consume('aaa.bbb.ccc'), expected);
    assert.deepEqual(calls, [{ token: 'aaa.bbb.ccc', options: { consume: true } }]);
  }
});

test('App Check: runtimeが結ぶ実firebase-adminのAPI（getAppCheck・verifyToken）が固定版に存在する', () => {
  const requireCjs = createRequire(import.meta.url);
  const module = requireCjs('firebase-admin/app-check');
  assert.equal(typeof module.getAppCheck, 'function');
  assert.equal(typeof module.AppCheck.prototype.verifyToken, 'function');
});
