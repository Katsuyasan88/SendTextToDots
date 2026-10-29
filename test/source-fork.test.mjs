// 異なる二配置（Fork）・二sourceの分離。合成の二namespace・二HMAC鍵・二project・二送信API origin。実Cloud・資格・network 0。
//   - 配置Aのsource/署名/承認/bindingは配置Bで使えない（同じ公開鍵を両方へ登録しても、宛先・source IDの違いで拒否）。
//   - App Check: 配置Aのprojectのtokenは配置Bのverifierで別projectとして拒否。登録は同配置projectのApp IDだけ。
//   - 管理入力: 期限は明示（無期限も"never"の明示時だけ）、未知field・別projectのApp ID・不正な公開鍵・argvの不備を拒否。

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createHmacHasher } from '../dist/secrets.js';
import { newSourceGeneration, newSourceId, parseRegistrationInput, parseSourceAdminArgs } from '../dist/source/admin.js';
import { createAppCheckVerifier } from '../dist/source/app-check.js';
import { SourceStore } from '../dist/source/firestore.js';
import { createSourceGate } from '../dist/source/http.js';
import { parseSourceProof, signSourceRequest } from '../dist/source/proof.js';

function fakeDb() {
  const docs = new Map();
  let lock = Promise.resolve();
  const snap = (path) => {
    const data = docs.get(path);
    return { id: path.split('/').pop(), exists: data !== undefined, data: () => (data === undefined ? undefined : structuredClone(data)) };
  };
  const ref = (path) => ({ id: path.split('/').pop(), path, collection: (name) => ({ doc: (id) => ref(`${path}/${name}/${id}`) }), get: async () => snap(path) });
  return {
    docs,
    collection: (name) => ({ doc: (id) => ref(`${name}/${id}`) }),
    runTransaction(fn) {
      const run = lock.then(async () => {
        const writes = [];
        const tx = {
          get: async (r) => snap(r.path),
          create: (r, data) => (writes.push(() => {
            if (docs.has(r.path)) throw new Error('exists');
            docs.set(r.path, structuredClone(data));
          }), tx),
          set: (r, data) => (writes.push(() => docs.set(r.path, structuredClone(data))), tx),
          update: (r, data) => (writes.push(() => docs.set(r.path, { ...docs.get(r.path), ...structuredClone(data) })), tx),
        };
        const result = await fn(tx);
        for (const write of writes) write();
        return result;
      });
      lock = run.catch(() => {});
      return run;
    },
  };
}

const NOW = 1_700_000_000_000;
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const RAW = publicKey.export({ format: 'jwk' }).x;

function deployment(name, projectNumber) {
  const NS = `t256_${randomUUID()}`;
  const hasher = createHmacHasher(randomBytes(32));
  const db = fakeDb();
  const clock = { now: () => NOW };
  const store = new SourceStore({ db, namespace: NS, clock });
  const projectId = `sttd-fork-${name}`;
  const audience = `https://api-${name}.example.org`;
  const appCheck = createAppCheckVerifier({
    projectNumber,
    projectId,
    appCheck: {
      // 合成port: 受け取ったtokenの中身（合成JSON）をそのまま「検証済み」として返す（SDK外向き通信の代替）。
      async verifyToken(token) {
        const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
        return { appId: claims.sub, token: claims, alreadyConsumed: false };
      },
    },
  });
  const gate = createSourceGate({ policy: { mode: 'strict-v1', methods: ['developer-key-v1', 'app-check-v1'] }, store, hasher, namespace: NS, audience, clock, appCheck });
  const identity = { projectId, uid: 'uid-same', authTimeSec: 1 };
  const developer = {
    schemaVersion: 1,
    sourceId: newSourceId(),
    kind: 'developer',
    state: 'active',
    generation: newSourceGeneration(),
    operations: ['send', 'connect'],
    publicKey: RAW,
    identityHash: connectIdentityHash(hasher, NS, identity),
    expiresAt: null,
    createdAt: 1,
    updatedAt: 1,
  };
  return { NS, hasher, db, store, gate, identity, audience, projectNumber, developer };
}

function sign(target, sourceId, nonce = randomBytes(16).toString('base64url')) {
  const body = Buffer.from('{"text":"synthetic"}');
  const header = signSourceRequest(
    { audience: target.audience, method: 'POST', path: '/v2/commands', search: '', sourceId, body, bearer: 'token', idempotencyKey: 'k' },
    { issuedAt: NOW / 1000, expiresAt: NOW / 1000 + 30, nonce },
    privateKey,
  );
  return { proof: parseSourceProof({ 'x-sttd-source': sourceId, 'x-sttd-source-signature': header }).proof, body };
}

const input = (target, body) => ({ identity: target.identity, operation: 'send', method: 'POST', path: '/v2/commands', search: '', body, bearer: 'token', idempotencyKey: 'k' });

test('二配置: 同じ公開鍵でも、配置Aの署名・source IDは配置Bで使えない', async () => {
  const a = deployment('a', '111111111111');
  const b = deployment('b', '222222222222');
  await a.store.create(a.developer);
  await b.store.create(b.developer);
  const forA = sign(a, a.developer.sourceId);
  assert.equal((await a.gate.authorize(forA.proof, input(a, forA.body))).kind, 'allowed');
  // Aのsource IDはBに無い。
  const replayedAtB = sign(a, a.developer.sourceId);
  assert.deepEqual(await b.gate.authorize(replayedAtB.proof, input(b, replayedAtB.body)), { kind: 'denied', code: 'source_rejected', reason: 'missing' });
  // BのIDでもAの宛先へ署名したものはBで拒否（宛先origin・本人hashが配置ごとに違う）。
  const wrongAudience = sign(a, b.developer.sourceId);
  assert.deepEqual(await b.gate.authorize(wrongAudience.proof, input(b, wrongAudience.body)), { kind: 'denied', code: 'source_rejected', reason: 'proof' });
  const forB = sign(b, b.developer.sourceId);
  assert.equal((await b.gate.authorize(forB.proof, input(b, forB.body))).kind, 'allowed');
});

test('二配置: Aの承認・bindingはBで使えず、App CheckはAのprojectのtokenをBで拒否する', async () => {
  const a = deployment('a', '111111111111');
  const b = deployment('b', '222222222222');
  await a.store.create(a.developer);
  const binding = { sourceId: a.developer.sourceId, generation: a.developer.generation };
  assert.equal((await a.store.bindingUsable(binding)).kind, 'usable');
  assert.deepEqual(await b.store.bindingUsable(binding), { kind: 'rejected', reason: 'missing' });

  const appA = { schemaVersion: 1, sourceId: newSourceId(), kind: 'app', state: 'active', generation: newSourceGeneration(), operations: ['send'], appId: '1:111111111111:ios:aa', createdAt: 1, updatedAt: 1 };
  await a.store.create(appA);
  await b.store.create({ ...appA, sourceId: newSourceId() });
  const tokenOf = (projectNumber, appId) =>
    `e30.${Buffer.from(JSON.stringify({ iss: `https://firebaseappcheck.googleapis.com/${projectNumber}`, aud: [`projects/${projectNumber}`], sub: appId })).toString('base64url')}.c2ln`;
  const proof = (sourceId, token) => parseSourceProof({ 'x-sttd-source': sourceId, 'x-firebase-appcheck': token }).proof;
  assert.equal((await a.gate.authorize(proof(appA.sourceId, tokenOf('111111111111', appA.appId)), input(a, Buffer.alloc(1)))).kind, 'allowed');
  const bSource = [...b.db.docs.values()].find((doc) => doc.kind === 'app').sourceId;
  assert.deepEqual(await b.gate.authorize(proof(bSource, tokenOf('111111111111', appA.appId)), input(b, Buffer.alloc(1))), { kind: 'denied', code: 'source_rejected', reason: 'wrong_project' });
  // 同じprojectでも登録と違うApp IDは拒否。
  assert.deepEqual(await a.gate.authorize(proof(appA.sourceId, tokenOf('111111111111', '1:111111111111:android:bb')), input(a, Buffer.alloc(1))), { kind: 'denied', code: 'source_rejected', reason: 'proof' });
});

test('管理入力: 期限・App ID・公開鍵・argvの不備を拒否する', () => {
  const ok = (value, command = 'register-developer') => parseRegistrationInput(command, Buffer.from(JSON.stringify(value)), '111111111111', NOW);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'], expiresAt: 'never' }).expiresAt, null);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'], expiresAt: '2030-01-01T00:00:00Z' }).expiresAt, Date.parse('2030-01-01T00:00:00Z'));
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'] }), null);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'], expiresAt: null }), null);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'], expiresAt: '2000-01-01T00:00:00Z' }), null);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: ['send'], expiresAt: 'never', privateKey: 'x' }), null);
  assert.equal(ok({ uid: 'uid-1', publicKey: 'not-a-key', operations: ['send'], expiresAt: 'never' }), null);
  assert.equal(ok({ uid: 'uid-1', publicKey: RAW, operations: [], expiresAt: 'never' }), null);
  assert.equal(ok({ appId: '1:111111111111:ios:aa', operations: ['send'] }, 'register-app').appId, '1:111111111111:ios:aa');
  assert.equal(ok({ appId: '1:222222222222:ios:aa', operations: ['send'] }, 'register-app'), null);

  const base = ['--project', 'p', '--database', 'd', '--namespace', 'n'];
  assert.equal(parseSourceAdminArgs(['register-app', ...base]).command, 'register-app');
  assert.equal(parseSourceAdminArgs(['disable', ...base, '--source', newSourceId()]), null);
  assert.equal(parseSourceAdminArgs(['disable', ...base, '--source', newSourceId(), '--expect', '12']).command, 'disable');
  assert.equal(parseSourceAdminArgs(['register-app', ...base, '--source', newSourceId()]), null);
  assert.equal(parseSourceAdminArgs(['register-app', ...base, '--key', 'secret']), null);
  assert.equal(parseSourceAdminArgs(['status', ...base, '--source', 'laptop']), null);
});
