// 公開名称（sttd）の整合: OAuth scope・保存root・KMS capsule prefix/format/AAD domain・config marker・接続/操作画面のdatasetが
// 同じ識別子で揃い、実codec（合成AES-GCM transport）でseal/openが成功し、別domain・未知prefix/formatを拒否することを確かめる。
// 実Cloud・資格・外部network 0。

import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { test } from 'node:test';

import { CONNECT_STORAGE_ROOT } from '../dist/connect/firestore.js';
import { consoleAsset, CONSOLE_SCRIPT } from '../dist/connect/console.js';
import { INTERACTION_SCRIPT, renderInteractionConsent, renderInteractionLogin } from '../dist/connect/pages.js';
import { loadDeploymentConfig } from '../dist/config/validate.js';
import { DELIVERY_STORAGE_ROOT } from '../dist/delivery/kms-store.js';
import { STTD_SCOPE } from '../dist/oauth/provider.js';
import { createKmsSealingCodec, crc32c, KMS_CAPSULE_PREFIX, KmsSealingError } from '../dist/protection/kms-sealing.js';
import {
  AUTH_STORAGE_ROOT,
  createKmsSubscriptionPolicy,
  isKmsCapsule,
  KMS_SUBSCRIPTION_FORMAT,
  kmsMarkerDocument,
  requireKmsMarker,
} from '../dist/storage/firestore/kms-subscription-format.js';

const PROJECT = 'demo-sttd-naming';
const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/naming`;
const NS = 't268_3f6c2a1e-8b4d-4c7a-9e21-5d0b7f3a9c64';
const BINDING = Object.freeze({ purpose: 'oidc', model: 'Session', recordId: 'naming-record', ownerBinding: null, secretHash: null });
const clock = { now: () => Date.now() };
const operation = () => ({ deadlineAt: Date.now() + 5000 });

function aesKms(key) {
  const stats = { encrypt: 0, decrypt: 0, aads: [] };
  const transport = {
    async encrypt(request) {
      stats.encrypt += 1;
      stats.aads.push(Buffer.from(request.additionalAuthenticatedData).toString('utf8'));
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(request.additionalAuthenticatedData);
      const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
      const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
      return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
    },
    async decrypt(request) {
      stats.decrypt += 1;
      const raw = request.ciphertext;
      const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
      decipher.setAAD(request.additionalAuthenticatedData);
      decipher.setAuthTag(raw.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
      return { plaintext, plaintextCrc32c: crc32c(plaintext), protectionLevel: 'SOFTWARE' };
    },
  };
  return { stats, transport };
}

const codecOf = (transport, namespace = NS) =>
  createKmsSealingCodec({ environment: 'local-test', projectId: PROJECT, databaseId: '(default)', namespace, cryptoKey: KEY, writeVersion: 1, readVersions: [1], transport, clock });
const policy = createKmsSubscriptionPolicy({ namespace: NS, environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: KEY, writeVersion: 1, readVersions: [1] });

/** capsuleの本体（[keyVersion, ciphertext]）を保ったまま、prefixだけ差し替える。 */
const withPrefix = (capsule, prefix) => prefix + capsule.slice(KMS_CAPSULE_PREFIX.length);

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => error instanceof KmsSealingError && error.code === code);
}

test('scope・保存root・capsule prefix/format・markerがsttdで揃う', () => {
  assert.equal(STTD_SCOPE, 'sttd:events');
  assert.equal(AUTH_STORAGE_ROOT, 'sttdAuth');
  assert.equal(CONNECT_STORAGE_ROOT, 'sttdConnect');
  assert.equal(DELIVERY_STORAGE_ROOT, 'sttdDelivery');
  assert.equal(KMS_SUBSCRIPTION_FORMAT, 'sttdkms1');
  assert.equal(KMS_CAPSULE_PREFIX, `${KMS_SUBSCRIPTION_FORMAT}.`);
  assert.equal(policy.format, 'sttdkms1');

  const marker = kmsMarkerDocument(policy);
  assert.equal(marker.format, 'sttdkms1');
  requireKmsMarker(marker, policy);
  // 別のformat名のmarkerは、他のfieldが一致していても受けない（読み替え・継承なし）。
  for (const format of ['sttdkms2', 'otherkms1', 'STTDKMS1', '']) assert.throws(() => requireKmsMarker({ ...marker, format }, policy));
});

test('実codec: sttdkms1でseal/openが成功し、AADのdomainがsttdkms1', async () => {
  const kms = aesKms(randomBytes(32));
  const codec = codecOf(kms.transport);
  const plaintext = Buffer.from('naming synthetic payload', 'utf8');
  const capsule = await codec.seal(BINDING, plaintext, operation());
  assert.ok(capsule.startsWith('sttdkms1.'));
  assert.equal(isKmsCapsule(capsule, policy), true);
  assert.equal(JSON.parse(kms.stats.aads[0])[0], 'sttdkms1');
  assert.deepEqual(await codec.open(BINDING, capsule, operation()), plaintext);
});

test('実codec: 未知prefix/formatのcapsuleは通信前に拒否する', async () => {
  const kms = aesKms(randomBytes(32));
  const codec = codecOf(kms.transport);
  const capsule = await codec.seal(BINDING, Buffer.from('x'), operation());
  for (const prefix of ['sttdkms2.', 'otherkms1.', 'STTDKMS1.', 'sttdkms1', '']) {
    const forged = withPrefix(capsule, prefix);
    assert.equal(isKmsCapsule(forged, policy), false, prefix);
    await rejects(codec.open(BINDING, forged, operation()), 'invalid_input');
  }
  assert.equal(kms.stats.decrypt, 0);
});

test('実codec: 別domain（AAD tag）や別namespaceで封緘した暗号文は開けない', async () => {
  const key = randomBytes(32);
  const kms = aesKms(key);
  const codec = codecOf(kms.transport);
  const sealed = await codec.seal(BINDING, Buffer.from('domain bound'), operation());
  const [keyVersion] = JSON.parse(Buffer.from(sealed.slice(KMS_CAPSULE_PREFIX.length), 'base64url').toString('utf8'));

  // 同じ鍵・同じ文脈で、AADの先頭（domain tag）だけ別の値にして暗号化し、正規のsttdkms1 capsuleへ包む。
  const aad = JSON.parse(kms.stats.aads[0]);
  const foreign = Buffer.from(JSON.stringify(['otherkms1', ...aad.slice(1)]), 'utf8');
  const response = await kms.transport.encrypt({ name: keyVersion, plaintext: Buffer.from('domain bound'), additionalAuthenticatedData: foreign });
  const forged = KMS_CAPSULE_PREFIX + Buffer.from(JSON.stringify([keyVersion, response.ciphertext.toString('base64url')]), 'utf8').toString('base64url');
  assert.equal(isKmsCapsule(forged, policy), true);
  await rejects(codec.open(BINDING, forged, operation()), 'unavailable');

  // 同じ鍵でも、namespaceが違うcodecでは正規のcapsuleを開けない。
  await rejects(codecOf(kms.transport, 't268_0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d').open(BINDING, sealed, operation()), 'unavailable');
});

test('OAuth interaction/送信画面: id/dataはsttd-、scriptのdatasetはsttdCamelCaseで対応する', () => {
  const deployment = loadDeploymentConfig();
  const web = { apiKey: 'synthetic-web-api-key', authDomain: deployment.web.authDomain, projectId: deployment.web.projectId };
  const interactionHtml = [renderInteractionLogin(web, 'uid-1', 'client', 'csrf-1'), renderInteractionConsent(web, 'uid-1', 'client', 'csrf-1')].join('\n');
  const consoleHtml = consoleAsset('/console', web, deployment.api.publicOrigin).body;
  const camel = (name) => name.replace(/-([a-z])/g, (_, char) => char.toUpperCase());

  for (const [html, script] of [[interactionHtml, INTERACTION_SCRIPT], [consoleHtml, CONSOLE_SCRIPT]]) {
    const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
    const data = [...html.matchAll(/\sdata-([a-z0-9-]+)=/g)].map((match) => match[1]);
    assert.ok(ids.length > 0 && data.length > 0);
    for (const name of [...ids, ...data]) assert.match(name, /^sttd-/);
    const datasetKeys = new Set(data.map(camel));
    const reads = [...script.matchAll(/\.dataset\.([A-Za-z0-9]+)/g)].map((match) => match[1]);
    assert.ok(reads.length > 0);
    for (const key of reads) {
      assert.match(key, /^sttd[A-Z]/);
      assert.ok(datasetKeys.has(key), key);
    }
    const elementIds = [...script.matchAll(/\bel\('([^']+)'\)/g)].map((match) => match[1]);
    assert.ok(elementIds.length > 0);
    for (const id of elementIds) assert.ok(ids.includes(id), id);
  }
});
