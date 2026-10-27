// 本文暗号化の本人鍵の保存基盤（src/encryption/*。HTTP入口は別）。全て合成値・in-memoryのFirestore代替・合成Secret source。
//   - K01: 同じUIDの2 clientは同じring/kidを再利用する（2回目は鍵生成0・Secret読取り0）。
//   - K02: 別のUID（新しいコード接続のUIDを含む）は別scope・別kidのringになる。
//   - K03: 同じUIDの並行初期化は1つのringへ収束し、負けた候補は保存されない。
//   - K04: commit応答不明（書込みは成功）は同じscopeを1回読んで採用結果を返す。
//   - K05: 鍵生成の失敗はunavailableでring作成0。
//   - K06: 保護鍵の取得・形式不正（wrap不能）はunavailableでring作成0。
//   - K07: DB commitの失敗（書込みなし）はunavailableで、自動の再生成0。
//   - K08: 保存した秘密鍵の保護は本人・環境・kid・公開鍵・Secret版の5改ざんで開封不能（正しい束縛では開封できる）。
//   - K09: 旧版で包んだringは取得時に同じkid/秘密鍵のまま新版へrewrapされる（版ごとの読取り1回）。
//   - K10: 旧版が読めない/新版の取得に失敗したrewrapは旧ringをそのまま残しunavailable。
//   - K11: owner失効・許可disabled・90日無活動の3拒否（owner未作成は作成0でconnection_required）。
//   - K12: 暗号化off（欠落を含む）はfactory呼出し0（Secret読取り0・鍵作成0）、平文の配置設定検証は従来どおり通る。
//   - K13: 不正な保存schema（ring/controls）は修復せずunavailable、Secret読取り0。
//   - K14: 初期化rate（分3/UTC日10）。429は非消費でRetry-After秒は残り待ちのceil。
//   - D01: beginの完了後に中止された取得の結果を採用しない。D02: beginの遅い読取りの後は書込み0。
//   - D03: 初期化CASの直前の中止でring0。D04: rewrapのCAS中に期限を過ぎると旧ringが不変。
//   - D05: commit応答不明の間に許可がdisabledになれば、採用readで拒否する。D06: tag失敗でも未認証平文のBufferを0埋めする。
//   - D07: 時計の巻戻しでrate枠を取り直さない。D08: ownerの非有限時刻を許可へ読み替えない。
//   - D09: 専用Secretの合成SDK adapter（固定版/CRC/name/後着cleanupの4入力。許可外の版は呼出し0）。
//   - D10: offの配置は既存4用途のreaderだけで足り、追加秘密0。さらにoffの合成配置でfactory呼出し0のまま、既存の平文HTTP handler
//     （createIngressOperationDeliveryRequestHandler）と共通配送service（KmsRequestDeliveryService）へ合成identity/owner/store/codec/send
//     ・loopbackで送った最小の要求が成功する（模擬sendの成功で、実署名・TLS・DBの成功ではない）。前後で配置設定/distのbytesが不変。
//   - D11: 保存のpublicJwkだけ・publicKeySpkiだけを別鍵へ変えたringは、固定障害で書換え0・Secret読取り0。
// node:testのtest数とscenario数は一致しない（K02/K08/K11とD01〜D05などは1つのtestに複数入力）。実Cloud・資格・Secret・network 0。

import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import net from 'node:net';
import { test } from 'node:test';

import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { KmsRequestDeliveryService } from '../dist/delivery/kms-service.js';

import { validateDeploymentConfig } from '../dist/config/validate.js';
import { connectIdentityHash } from '../dist/connect/firestore.js';
import { consumeRate, parseRingRecord } from '../dist/encryption/contract.js';
import { KeyProtectionError, unwrapPrivateKey } from '../dist/encryption/crypto.js';
import { createEncryptionSecretProvider } from '../dist/encryption/secret-provider.js';
import { createEncryptionKeyServiceFor, EncryptionKeyService } from '../dist/encryption/service.js';
import { EncryptionKeyStore } from '../dist/encryption/store.js';
import { createGoogleEncryptionSecretSource } from '../dist/encryption/secret-provider.js';
import { createGoogleSecretReader } from '../dist/keys/google-secret-reader.js';
import { crc32c } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';

const DAY = 86_400_000;
const T0 = Date.UTC(2026, 9, 28, 0, 0, 30);

// ---- in-memory Firestore代替（version付きの楽観transaction。commit失敗の注入つき） ----

class Snapshot {
  constructor(id, data) {
    this.id = id;
    this.exists = data !== undefined;
    this._data = data;
  }
  data() {
    return this._data === undefined ? undefined : structuredClone(this._data);
  }
}

class Ref {
  constructor(db, path) {
    this.db = db;
    this.path = path;
    this.id = path.split('/').pop();
  }
  collection(name) {
    return { doc: (id) => new Ref(this.db, `${this.path}/${name}/${id}`) };
  }
  async get() {
    await null;
    return new Snapshot(this.id, this.db.docs.get(this.path));
  }
}

class FakeDb {
  docs = new Map();
  versions = new Map();
  /** null | 'fail'（書込みなしで例外）| 'lost'（書込み後に例外）。1回だけ。 */
  commitFault = null;
  transactions = 0;
  /** 試験用の注入点（読取りの直前・commit適用の直後）。 */
  onGet = null;
  afterCommit = null;
  collection(name) {
    return { doc: (id) => new Ref(this, `${name}/${id}`) };
  }
  async runTransaction(fn, options) {
    for (let attempt = 0; attempt < options.maxAttempts; attempt += 1) {
      this.transactions += 1;
      const reads = new Map();
      const writes = [];
      const tx = {
        get: async (ref) => {
          await null;
          this.onGet?.(ref.path);
          reads.set(ref.path, this.versions.get(ref.path) ?? 0);
          return new Snapshot(ref.id, this.docs.get(ref.path));
        },
        set: (ref, data) => writes.push(['set', ref.path, structuredClone(data)]),
        create: (ref, data) => writes.push(['create', ref.path, structuredClone(data)]),
        update: (ref, data) => writes.push(['update', ref.path, structuredClone(data)]),
      };
      const result = await fn(tx);
      await null;
      const stale = [...reads].some(([path, version]) => (this.versions.get(path) ?? 0) !== version);
      const clash = writes.some(([kind, path]) => kind === 'create' && this.docs.has(path));
      if (stale || clash) continue;
      const fault = this.commitFault;
      this.commitFault = null;
      if (fault === 'fail') throw new Error('synthetic commit failure');
      for (const [kind, path, data] of writes) {
        if (kind === 'update') {
          if (!this.docs.has(path)) throw new Error('synthetic missing document');
          this.docs.set(path, { ...this.docs.get(path), ...data });
        } else this.docs.set(path, data);
        this.versions.set(path, (this.versions.get(path) ?? 0) + 1);
      }
      this.afterCommit?.();
      if (fault === 'lost') throw new Error('synthetic lost commit response');
      return result;
    }
    throw new Error('synthetic transaction aborted');
  }
}

// ---- 合成の配置・本人・Secret ----

const ENV = Object.freeze({
  projectId: 'synthetic-project',
  projectNumber: '123456',
  databaseId: '(default)',
  connectNamespace: `t256_${randomUUID()}`,
  deliveryNamespace: `t270_${randomUUID()}`,
  encryptionNamespace: `t280_${randomUUID()}`,
});
const SECRET = 'projects/123456/secrets/synthetic-payload-protection';
const hasher = createHmacHasher(randomBytes(32));
/** 試験用のRSA3072鍵（このprocessで生成する合成鍵。保存しない）。生成器は順番に返す。 */
const POOL = Array.from({ length: 4 }, () => generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 }));

function world() {
  const db = new FakeDb();
  const clock = { t: T0, now() { return this.t; } };
  const secretValues = new Map();
  const secretReads = [];
  const secretFaults = new Set();
  const source = {
    async read(name) {
      secretReads.push(name);
      await null;
      if (secretFaults.has(name)) throw new Error('synthetic secret failure');
      const value = secretValues.get(name);
      if (value === undefined) throw new Error('synthetic missing version');
      return Buffer.from(value, 'latin1');
    },
  };
  const addVersion = (version, value = randomBytes(32).toString('base64url')) => secretValues.set(`${SECRET}/versions/${version}`, value);
  const gen = { calls: 0, fail: false, together: null };
  const generate = async () => {
    gen.calls += 1;
    // 並行試験では2つの候補が揃うまで待たせ、両方の要求が初期化へ進んだ状態でCASを競わせる。
    if (gen.together !== null) {
      if (gen.calls === 2) gen.together.release();
      await gen.together.ready;
    }
    await null;
    if (gen.fail) throw new Error('synthetic generation failure');
    return POOL[gen.calls % POOL.length];
  };
  const service = (write = 1, read = [write]) => {
    const store = new EncryptionKeyStore({ db, connectNamespace: ENV.connectNamespace, encryptionNamespace: ENV.encryptionNamespace, writeSecretVersion: write, clock });
    const secrets = createEncryptionSecretProvider(source, { secret: SECRET, writeSecretVersion: write, readSecretVersions: read });
    return new EncryptionKeyService({ environment: ENV, store, secrets, hasher, clock, generate });
  };
  const connect = `sttdConnect/${ENV.connectNamespace}`;
  const enroll = (uid, { access = 'active', lastActiveAt = T0, revokedAt = null, owner = true } = {}) => {
    const identityHash = connectIdentityHash(hasher, ENV.connectNamespace, { projectId: ENV.projectId, uid });
    db.docs.set(`${connect}/access/${identityHash}`, { version: 1, state: access, generation: randomUUID(), updatedAt: T0 });
    if (owner) {
      const ownerId = randomUUID();
      db.docs.set(`${connect}/identities/${identityHash}`, { ownerId, createdAt: T0 });
      db.docs.set(`${connect}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: T0, lastActiveAt, revokedAt });
    }
    return { projectId: ENV.projectId, uid };
  };
  const rings = () => [...db.docs].filter(([path]) => path.includes('/rings/'));
  const operation = () => ({ deadlineAt: clock.t + 20_000, signal: new AbortController().signal });
  addVersion(1);
  return { db, clock, service, enroll, rings, operation, gen, secretReads, secretFaults, secretValues, addVersion };
}

const bindingOf = (w, ring, key, overrides = {}) => ({
  projectNumber: ENV.projectNumber,
  databaseId: ENV.databaseId,
  connectNamespace: ENV.connectNamespace,
  deliveryNamespace: ENV.deliveryNamespace,
  encryptionNamespace: ENV.encryptionNamespace,
  identityHash: ring.identityHash,
  ownerId: ring.ownerId,
  scope: ring.scope,
  kid: key.kid,
  secretVersion: key.secretVersion,
  publicKeySpki: key.publicKeySpki,
  ...overrides,
});
const protectionKey = (w, version) => Buffer.from(w.secretValues.get(`${SECRET}/versions/${version}`), 'base64url');
const onlyRing = (w) => {
  const all = w.rings();
  assert.equal(all.length, 1);
  return all[0][1];
};
const PUBLIC_KEYS = ['version', 'kid', 'alg', 'enc', 'scope', 'publicJwk', 'publicKeySpki', 'createdAt'];

test('K01/K02: 同UIDの2 clientは再利用、別UID・新コードUIDは別ring', async () => {
  const w = world();
  const a = w.enroll('synthetic-apple-uid-a');
  const first = await w.service().getOrInitialize(a, w.operation());
  assert.equal(first.kind, 'ok');
  assert.deepEqual(Object.keys(first.key).sort(), [...PUBLIC_KEYS].sort());
  assert.deepEqual(Object.keys(first.key.publicJwk).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
  assert.match(first.key.scope, /^[A-Za-z0-9_-]{43}$/);
  const json = JSON.stringify(first);
  assert.ok(!json.includes('synthetic-apple-uid-a') && !json.includes(onlyRing(w).ownerId) && !json.includes(SECRET));
  const gens = w.gen.calls;
  const reads = w.secretReads.length;
  const second = await w.service().getOrInitialize(a, w.operation());
  assert.deepEqual(second, first);
  assert.equal(w.gen.calls, gens);
  assert.equal(w.secretReads.length, reads);

  // K02: 別UIDと新しいコード接続のUID（同じ人物でも別UID）は別scope・別kid。
  const b = w.enroll('synthetic-apple-uid-b');
  const code = w.enroll('synthetic-code-uid-c');
  const kb = await w.service().getOrInitialize(b, w.operation());
  const kc = await w.service().getOrInitialize(code, w.operation());
  const kids = new Set([first.key.kid, kb.key.kid, kc.key.kid]);
  const scopes = new Set([first.key.scope, kb.key.scope, kc.key.scope]);
  assert.equal(kids.size, 3);
  assert.equal(scopes.size, 3);
  assert.equal(w.rings().length, 3);
});

test('K03: 同UIDの並行初期化は1つのringへ収束する', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-concurrent');
  let release;
  w.gen.together = { ready: new Promise((resolve) => (release = resolve)), release: () => release() };
  const [x, y] = await Promise.all([w.service().getOrInitialize(a, w.operation()), w.service().getOrInitialize(a, w.operation())]);
  assert.equal(x.kind, 'ok');
  assert.deepEqual(y, x);
  const ring = onlyRing(w);
  assert.equal(ring.keys.length, 1);
  assert.equal(ring.activeKid, x.key.kid);
  assert.equal(w.gen.calls, 2);
});

test('K04: commit応答不明は同じscopeを読み採用結果を返す', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-lost');
  // beginのtransactionではなく2つ目（初期化CAS）のcommitへ注入する。
  const service = w.service();
  const original = w.db.runTransaction.bind(w.db);
  let count = 0;
  w.db.runTransaction = async (fn, options) => {
    count += 1;
    if (count === 2) w.db.commitFault = 'lost';
    return original(fn, options);
  };
  const got = await service.getOrInitialize(a, w.operation());
  assert.equal(got.kind, 'ok');
  assert.equal(onlyRing(w).activeKid, got.key.kid);
  assert.equal(w.gen.calls, 1);
});

test('K05/K06/K07: 生成失敗・保護鍵不正・commit失敗はunavailableで保存0、再生成0', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-faults');
  w.gen.fail = true;
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.equal(w.rings().length, 0);
  assert.equal(w.secretReads.length, 0);
  w.gen.fail = false;

  // K06: 書込み版の値が43文字のcanonical base64urlでない（wrap不能）。取得失敗も同じ。
  w.secretValues.set(`${SECRET}/versions/1`, 'not-a-protection-key');
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  w.addVersion(1);
  w.secretFaults.add(`${SECRET}/versions/1`);
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  w.secretFaults.clear();
  assert.equal(w.rings().length, 0);

  // K07: 初期化CASのcommitが書込みなしで失敗。1回readして不在ならunavailable、候補を作り直さない（分rateを避けて次の分へ）。
  w.clock.t += 60_000;
  const gens = w.gen.calls;
  const original = w.db.runTransaction.bind(w.db);
  let count = 0;
  w.db.runTransaction = async (fn, options) => {
    count += 1;
    if (count === 2) w.db.commitFault = 'fail';
    return original(fn, options);
  };
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.equal(w.gen.calls, gens + 1);
  assert.equal(w.rings().length, 0);
});

test('K08: 本人・環境・kid・公開鍵・Secret版の5改ざんで開封不能', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-tamper');
  const b = w.enroll('synthetic-uid-other');
  await w.service().getOrInitialize(a, w.operation());
  await w.service().getOrInitialize(b, w.operation());
  const [ringA, ringB] = w.rings().map(([, ring]) => ring);
  const key = ringA.keys[0];
  const pk = protectionKey(w, 1);
  const ok = unwrapPrivateKey(key.wrappedPrivateKey, pk, bindingOf(w, ringA, key));
  assert.ok(ok.length > 1000);
  ok.fill(0);
  const tampers = {
    identity: { identityHash: ringB.identityHash, ownerId: ringB.ownerId, scope: ringB.scope },
    environment: { deliveryNamespace: `t270_${randomUUID()}` },
    kid: { kid: randomUUID() },
    publicKey: { publicKeySpki: ringB.keys[0].publicKeySpki },
    secretVersion: { secretVersion: 2 },
  };
  for (const [name, overrides] of Object.entries(tampers)) {
    assert.throws(() => unwrapPrivateKey(key.wrappedPrivateKey, pk, bindingOf(w, ringA, key, overrides)), KeyProtectionError, name);
  }
  // DB recordを別本人のscopeへ写しても束縛の検査で採用しない。
  assert.throws(() => parseRingRecord(ringA, { scope: ringB.scope, identityHash: ringB.identityHash, ownerId: ringB.ownerId }));
  // DB・応答に生の秘密鍵/保護鍵/UIDが無い。
  const dump = JSON.stringify([...w.db.docs]);
  assert.ok(!dump.includes(w.secretValues.get(`${SECRET}/versions/1`)));
  assert.ok(!dump.includes('synthetic-uid-tamper'));
  for (const pair of POOL) assert.ok(!dump.includes(pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url').slice(64, 160)));
});

test('K09/K10: 旧新版の混在rewrapと、失敗時の旧ring保存', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-rotate');
  const first = await w.service(1, [1]).getOrInitialize(a, w.operation());
  const before = structuredClone(onlyRing(w));
  w.addVersion(2);
  w.secretReads.length = 0;
  const rotated = await w.service(2, [1, 2]).getOrInitialize(a, w.operation());
  assert.deepEqual(rotated, first);
  const after = onlyRing(w);
  assert.equal(after.generation, before.generation + 1);
  assert.equal(after.keys[0].kid, before.keys[0].kid);
  assert.equal(after.keys[0].secretVersion, 2);
  assert.notEqual(after.keys[0].wrappedPrivateKey, before.keys[0].wrappedPrivateKey);
  assert.deepEqual([...w.secretReads].sort(), [`${SECRET}/versions/1`, `${SECRET}/versions/2`]);
  const opened = unwrapPrivateKey(after.keys[0].wrappedPrivateKey, protectionKey(w, 2), bindingOf(w, after, after.keys[0]));
  opened.fill(0);
  assert.throws(() => unwrapPrivateKey(after.keys[0].wrappedPrivateKey, protectionKey(w, 1), bindingOf(w, after, after.keys[0], { secretVersion: 1 })), KeyProtectionError);

  // K10: 旧版2を読めない配置（read=[3]）と、新版3の取得失敗。どちらもringは不変でunavailable。
  const kept = structuredClone(onlyRing(w));
  w.addVersion(3);
  assert.deepEqual(await w.service(3, [3]).getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.deepEqual(onlyRing(w), kept);
  w.secretFaults.add(`${SECRET}/versions/3`);
  assert.deepEqual(await w.service(3, [2, 3]).getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.deepEqual(onlyRing(w), kept);
});

test('K11: owner失効・許可disabled・90日無活動の3拒否、owner未作成は作成0', async () => {
  const w = world();
  const revoked = w.enroll('synthetic-uid-revoked', { revokedAt: T0 });
  const disabled = w.enroll('synthetic-uid-disabled', { access: 'disabled' });
  const idle = w.enroll('synthetic-uid-idle', { lastActiveAt: T0 - 90 * DAY });
  const missing = w.enroll('synthetic-uid-no-owner', { owner: false });
  const docs = w.db.docs.size;
  assert.deepEqual(await w.service().getOrInitialize(revoked, w.operation()), { kind: 'connection_required' });
  assert.deepEqual(await w.service().getOrInitialize(disabled, w.operation()), { kind: 'access_denied' });
  assert.deepEqual(await w.service().getOrInitialize(idle, w.operation()), { kind: 'connection_required' });
  assert.deepEqual(await w.service().getOrInitialize(missing, w.operation()), { kind: 'connection_required' });
  assert.equal(w.db.docs.size, docs);
  assert.equal(w.gen.calls, 0);
  assert.equal(w.secretReads.length, 0);
});

test('K12: off（欠落を含む）はfactory 0、平文の設定検証は従来どおり', () => {
  let factoryCalls = 0;
  const factory = () => {
    factoryCalls += 1;
    throw new Error('must not be called');
  };
  const legacy = validateDeploymentConfig(structuredClone(SYNTHETIC));
  assert.equal(legacy.payloadEncryption, 'off');
  assert.equal(createEncryptionKeyServiceFor(legacy, factory), null);
  assert.equal(createEncryptionKeyServiceFor(validateDeploymentConfig({ ...structuredClone(SYNTHETIC), payloadEncryption: 'off' }), factory), null);
  assert.equal(factoryCalls, 0);
  const projectNumber = SYNTHETIC.projectNumber;
  const enabled = {
    mode: 'jwe-rsa-oaep-256-a256gcm-v1',
    namespace: `t280_${randomUUID()}`,
    secret: `projects/${projectNumber}/secrets/synthetic-payload-protection`,
    writeSecretVersion: 2,
    readSecretVersions: [1, 2],
  };
  assert.deepEqual(validateDeploymentConfig({ ...structuredClone(SYNTHETIC), payloadEncryption: enabled }).payloadEncryption, enabled);
  const reuse = SYNTHETIC.secretVersions.identifierKey.split('/versions/')[0];
  for (const bad of [{ ...enabled, secret: reuse }, { ...enabled, readSecretVersions: [1] }, { ...enabled, readSecretVersions: [1, 2, 3, 4] }, { ...enabled, extra: 1 }, 'on']) {
    assert.throws(() => validateDeploymentConfig({ ...structuredClone(SYNTHETIC), payloadEncryption: bad }));
  }
});

test('K13: 不正な保存schemaは修復せずunavailable', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-schema');
  await w.service().getOrInitialize(a, w.operation());
  const [path, ring] = w.rings()[0];
  w.db.docs.set(path, { ...ring, extra: true });
  const reads = w.secretReads.length;
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.deepEqual(w.db.docs.get(path), { ...ring, extra: true });
  w.db.docs.set(path, ring);
  const controls = path.replace('/rings/', '/controls/');
  w.db.docs.set(controls, { ...w.db.docs.get(controls), windows: { init: {} } });
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'unavailable' });
  assert.equal(w.secretReads.length, reads);
});

test('K14: 初期化rateは分3/UTC日10、429は非消費', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-rate');
  w.gen.fail = true;
  const run = () => w.service().getOrInitialize(a, w.operation());
  for (let i = 0; i < 3; i += 1) assert.deepEqual(await run(), { kind: 'unavailable' });
  const controlsPath = () => [...w.db.docs.keys()].find((path) => path.includes('/controls/'));
  const snapshot = structuredClone(w.db.docs.get(controlsPath()));
  const limited = await run();
  assert.equal(limited.kind, 'rate_limited');
  assert.equal(limited.retryAfterSec, 30);
  assert.deepEqual(w.db.docs.get(controlsPath()), snapshot);
  assert.equal(w.gen.calls, 3);
  for (let minute = 1; minute <= 3; minute += 1) {
    w.clock.t = T0 + minute * 60_000;
    for (let i = 0; i < (minute === 3 ? 1 : 3); i += 1) assert.deepEqual(await run(), { kind: 'unavailable' });
  }
  assert.equal(w.gen.calls, 10);
  w.clock.t = T0 + 4 * 60_000;
  const daily = await run();
  assert.equal(daily.kind, 'rate_limited');
  assert.equal(daily.retryAfterSec, Math.ceil((Date.UTC(2026, 9, 29) - w.clock.t) / 1000));
  w.clock.t = Date.UTC(2026, 9, 29, 0, 0, 1);
  w.gen.fail = false;
  assert.equal((await run()).kind, 'ok');
});

const UNAVAILABLE = { kind: 'unavailable' };
const hashOf = (identity) => connectIdentityHash(hasher, ENV.connectNamespace, identity);

test('D01〜D05: 元operationの期限・中止と、commit応答不明の再認可', async () => {
  // D01: beginのcommit後に中止 → 結果を採用しない。
  {
    const w = world();
    const a = w.enroll('synthetic-uid-d01');
    assert.equal((await w.service().getOrInitialize(a, w.operation())).kind, 'ok');
    const abort = new AbortController();
    w.db.afterCommit = () => {
      abort.abort();
      w.db.afterCommit = null;
    };
    assert.deepEqual(await w.service().getOrInitialize(a, { deadlineAt: w.clock.t + 20_000, signal: abort.signal }), UNAVAILABLE);
  }
  // D02: beginのring読取りが遅く期限を過ぎる → 書込み0・生成0・Secret0。
  {
    const w = world();
    const a = w.enroll('synthetic-uid-d02');
    const versions = new Map(w.db.versions);
    const docs = w.db.docs.size;
    w.db.onGet = (path) => {
      if (path.includes('/rings/')) w.clock.t += 25_000;
    };
    assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), UNAVAILABLE);
    assert.deepEqual(w.db.versions, versions);
    assert.equal(w.db.docs.size, docs);
    assert.equal(w.gen.calls + w.secretReads.length, 0);
  }
  // D03: 初期化CASの読取り中に中止 → ring0。
  {
    const w = world();
    const a = w.enroll('synthetic-uid-d03');
    const abort = new AbortController();
    w.db.onGet = () => {
      if (w.db.transactions === 2) abort.abort();
    };
    assert.deepEqual(await w.service().getOrInitialize(a, { deadlineAt: w.clock.t + 20_000, signal: abort.signal }), UNAVAILABLE);
    assert.equal(w.rings().length, 0);
    assert.equal(w.gen.calls, 1);
  }
  // D04: rewrapのCAS中に期限を過ぎる → 旧ring不変。
  {
    const w = world();
    const a = w.enroll('synthetic-uid-d04');
    await w.service(1, [1]).getOrInitialize(a, w.operation());
    const kept = structuredClone(onlyRing(w));
    w.addVersion(2);
    const base = w.db.transactions;
    w.db.onGet = () => {
      if (w.db.transactions === base + 2) w.clock.t += 25_000;
    };
    assert.deepEqual(await w.service(2, [1, 2]).getOrInitialize(a, w.operation()), UNAVAILABLE);
    assert.deepEqual(onlyRing(w), kept);
  }
  // D05: 初期化のcommit応答不明の間に許可がdisabled → 採用readで拒否（成功にしない）。
  {
    const w = world();
    const a = w.enroll('synthetic-uid-d05');
    const accessPath = `sttdConnect/${ENV.connectNamespace}/access/${hashOf(a)}`;
    const original = w.db.runTransaction.bind(w.db);
    let count = 0;
    w.db.runTransaction = async (fn, options) => {
      count += 1;
      if (count === 2) {
        w.db.commitFault = 'lost';
        w.db.afterCommit = () => {
          w.db.docs.set(accessPath, { ...w.db.docs.get(accessPath), state: 'disabled' });
          w.db.afterCommit = null;
        };
      }
      return original(fn, options);
    };
    assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), { kind: 'access_denied' });
  }
});

test('D06: unwrapのtag失敗でも未認証平文のBufferを0埋めする', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-d06');
  await w.service().getOrInitialize(a, w.operation());
  const ring = onlyRing(w);
  const key = ring.keys[0];
  const sealed = Buffer.from(key.wrappedPrivateKey, 'base64url');
  sealed[sealed.length - 1] ^= 1;
  const tampered = sealed.toString('base64url');
  const bodyLength = sealed.length - 12 - 16;
  const fill = Buffer.prototype.fill;
  const filled = [];
  Buffer.prototype.fill = function (...args) {
    filled.push(this);
    return fill.apply(this, args);
  };
  try {
    assert.throws(() => unwrapPrivateKey(tampered, protectionKey(w, 1), bindingOf(w, ring, key)), KeyProtectionError);
  } finally {
    Buffer.prototype.fill = fill;
  }
  const bodies = filled.filter((buffer) => buffer.length === bodyLength);
  assert.ok(bodies.length >= 1);
  assert.ok(bodies.every((buffer) => buffer.every((byte) => byte === 0)));
});

test('D07/D08: 時計の巻戻しとownerの非有限時刻は固定障害', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-d07');
  w.clock.t = T0 + 120_000;
  assert.equal((await w.service().getOrInitialize(a, w.operation())).kind, 'ok');
  const controls = [...w.db.docs].find(([path]) => path.includes('/controls/'));
  const kept = structuredClone(controls[1]);
  w.clock.t = T0 + 60_000;
  assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), UNAVAILABLE);
  assert.deepEqual(w.db.docs.get(controls[0]), kept);
  // 窓の判定そのもの: 保存窓より前の時刻・不正な時刻は枠の取り直しにしない。
  assert.throws(() => consumeRate(kept.windows.fetch, 'fetch', T0 + 60_000));
  assert.throws(() => consumeRate(kept.windows.fetch, 'fetch', Number.NaN));
  assert.ok('next' in consumeRate(kept.windows.fetch, 'fetch', T0 + 120_000));

  const nan = w.enroll('synthetic-uid-d08', { lastActiveAt: Number.NaN });
  const docs = w.db.docs.size;
  assert.deepEqual(await w.service().getOrInitialize(nan, w.operation()), UNAVAILABLE);
  assert.equal(w.db.docs.size, docs);
});

function gaxPromise(produce) {
  const promise = produce();
  Object.defineProperty(promise, 'cancel', { value: () => {}, writable: true, configurable: true, enumerable: false });
  return promise;
}

test('D09/D10: 専用Secretの合成SDK adapterと、offの既存reader', async () => {
  const value = Buffer.from(randomBytes(32).toString('base64url'), 'latin1');
  const calls = [];
  let mode = 'ok';
  let late = null;
  const seen = [];
  const client = {
    innerApiCalls: {
      accessSecretVersion: (request, options) => {
        calls.push({ name: request.name, retry: options.retry });
        const data = Uint8Array.from(value);
        seen.push(data);
        const response = {
          name: mode === 'name' ? `${SECRET}/versions/9` : request.name,
          payload: { data, dataCrc32c: mode === 'crc' ? (crc32c(data) + 1) % 0x100000000 : crc32c(data) },
        };
        if (mode === 'late') return gaxPromise(() => new Promise((resolve) => (late = () => resolve([response]))));
        return gaxPromise(() => Promise.resolve([response]));
      },
    },
  };
  const source = createGoogleEncryptionSecretSource({ client, policy: { secret: SECRET, writeSecretVersion: 2, readSecretVersions: [1, 2] }, clock: { now: () => Date.now() } });
  const op = (ms = 20_000) => ({ deadlineAt: Date.now() + ms, signal: new AbortController().signal });
  const name = `${SECRET}/versions/2`;
  // 固定版の成功: 要求名・retry null、所有copyを返しSDKのbytesは0埋め。
  const got = await source.read(name, op());
  assert.deepEqual(got, value);
  assert.deepEqual(calls.at(-1), { name, retry: null });
  assert.ok(seen.at(-1).every((byte) => byte === 0));
  // CRC不一致・応答名不一致は失敗でbytesは0埋め。
  for (const bad of ['crc', 'name']) {
    mode = bad;
    await assert.rejects(source.read(name, op()));
    assert.ok(seen.at(-1).every((byte) => byte === 0), bad);
  }
  // 後着: 期限で失敗し、後から届いたbytesも0埋め。
  mode = 'late';
  await assert.rejects(source.read(name, op(30)));
  late();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(seen.at(-1).every((byte) => byte === 0));
  // 許可外の版・latestは呼出し0。
  const before = calls.length;
  for (const other of [`${SECRET}/versions/3`, `${SECRET}/versions/latest`]) await assert.rejects(source.read(other, op()));
  assert.equal(calls.length, before);
  source.dispose();

  // D10: offの配置は既存4用途のreaderだけ（追加の必須秘密0）で、識別子用途の読取りが従来どおり成功する。
  const config = validateDeploymentConfig(structuredClone(SYNTHETIC));
  assert.equal(config.payloadEncryption, 'off');
  const legacyCalls = [];
  const legacyClient = {
    innerApiCalls: {
      accessSecretVersion: (request) => {
        legacyCalls.push(request.name);
        const data = Uint8Array.from(randomBytes(32));
        return gaxPromise(() => Promise.resolve([{ name: request.name, payload: { data, dataCrc32c: crc32c(data) } }]));
      },
    },
  };
  const reader = createGoogleSecretReader({ client: legacyClient, projectNumber: config.projectNumber, versions: { ...config.secretVersions }, clock: { now: () => Date.now() } });
  const key = await reader.read('identifierKey', op());
  assert.equal(key.length, 32);
  key.fill(0);
  reader.dispose();
  assert.deepEqual(legacyCalls, [config.secretVersions.identifierKey]);
  assert.ok(!legacyCalls.some((entry) => entry.includes('synthetic-payload-protection')));
});

test('D10: offの合成配置で既存の平文handler＋共通配送serviceの最小要求が成功する', { timeout: 20_000 }, async () => {
  const root = new URL('..', import.meta.url);
  const guarded = ['src/config/deployment.ts', 'dist/config/deployment.js', 'dist/config/validate.js'];
  const digest = () => guarded.map((name) => createHash('sha256').update(readFileSync(new URL(name, root))).digest('hex')).join(',');
  const before = digest();
  const config = validateDeploymentConfig(structuredClone(SYNTHETIC));
  let factoryCalls = 0;
  assert.equal(
    createEncryptionKeyServiceFor(config, () => {
      factoryCalls += 1;
      throw new Error('must not be called');
    }),
    null,
  );

  const BASE = 1_900_000_000_000;
  const clock = { now: () => BASE };
  const hashKey = randomBytes(32);
  const hash = (purpose, value) => createHmac('sha256', hashKey).update(purpose).update('\0').update(value).digest('hex');
  const OWNER = `owner-${randomUUID()}`;
  const TOKEN = `tok.${randomBytes(12).toString('base64url')}.sig`;
  const used = { prepare: 0, dispatch: 0, finish: 0, open: 0, send: 0 };
  const docFor = (ownerId, attemptId, receivedAt) => ({
    version: 1,
    ownerId,
    tombstone: false,
    digest: 'd'.repeat(64),
    state: 'prepared',
    reason: null,
    attemptId,
    destination: { subscriptionId: 'sub_plain', grantId: 'grant_plain', secretHash: 'h'.repeat(64) },
    receivedAt,
    expiresAt: receivedAt + 60_000,
    deadlineAt: receivedAt + 20_000,
    updatedAt: receivedAt,
    acknowledgedAt: null,
    purgeAt: receivedAt + 86_400_000,
  });
  const store = {
    commandKey: (ownerId, commandId) => hash('command', `${ownerId}\0${commandId}`),
    async prepare(input) {
      used.prepare += 1;
      return { kind: 'prepared', doc: docFor(input.ownerId, input.attemptId, input.receivedAt), sealedUrl: 'capsule-url', sealedSecret: 'capsule-secret', previous: null };
    },
    async dispatch(ownerId, commandKey, attemptId) {
      used.dispatch += 1;
      return { kind: 'granted', doc: { ...docFor(ownerId, attemptId, BASE), state: 'dispatching' }, previousValid: false };
    },
    async finish(ownerId, commandKey, attemptId, state, reason) {
      used.finish += 1;
      return { ...docFor(ownerId, attemptId, BASE), state, reason, acknowledgedAt: state === 'delivered' ? BASE : null };
    },
    async abandon(ownerId, commandKey, attemptId, reason) {
      return { ...docFor(ownerId, attemptId, BASE), state: 'failed', reason };
    },
    async read(ownerId) {
      return { ...docFor(ownerId, 'a', BASE), state: 'delivered', acknowledgedAt: BASE };
    },
    async cancel(ownerId) {
      return { kind: 'observed', doc: { ...docFor(ownerId, 'a', BASE), state: 'delivered', acknowledgedAt: BASE } };
    },
  };
  const codec = {
    async open(binding) {
      used.open += 1;
      return Buffer.from(binding.purpose === 'callback-url' ? 'https://receiver.example/hook' : `whsec_${randomBytes(32).toString('base64')}`, 'utf8');
    },
  };
  const lifetime = new AbortController();
  const logs = [];
  const log = (entry) => logs.push(entry);
  const service = new KmsRequestDeliveryService({
    store,
    codec,
    hash,
    digestKey: randomBytes(32),
    send: async () => ((used.send += 1), { kind: 'delivered', reason: 'acknowledged', stopSubscription: false }),
    clock,
    newAttemptId: () => `attempt-${used.prepare + 1}`,
    log,
    budgetMs: 20_000,
    lifetime: lifetime.signal,
    hooks: {},
  });
  const identity = {
    projectId: 'demo-sttd-plain',
    async verifyIdToken(token) {
      if (token !== TOKEN) throw new Error('bad token');
      return { projectId: 'demo-sttd-plain', uid: 'synthetic-uid-plain', authTimeSec: Math.floor(BASE / 1000) };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async () => OWNER,
    service,
    clock,
    log,
    lifetime: lifetime.signal,
    ingress: () => ({ receivedAt: BASE, deadlineAt: BASE + 20_000, signal: new AbortController().signal }),
  });
  const server = createServer((req, res) => void handler(req, res));
  await new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  try {
    const commandId = randomUUID();
    const body = JSON.stringify({ schemaVersion: 2, commandId, text: 'synthetic plain text', createdAt: new Date(BASE).toISOString(), expiresAt: new Date(BASE + 60_000).toISOString() });
    const head = [
      'POST /v2/commands HTTP/1.1',
      'Host: 127.0.0.1',
      `Authorization: Bearer ${TOKEN}`,
      'Content-Type: application/json',
      `Idempotency-Key: ${commandId}`,
      `Content-Length: ${Buffer.byteLength(body)}`,
      'Connection: close',
    ];
    const raw = await new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port: server.address().port });
      const chunks = [];
      const timer = setTimeout(() => socket.destroy(), 10_000);
      socket.on('data', (chunk) => chunks.push(chunk));
      socket.on('error', reject);
      socket.on('close', () => {
        clearTimeout(timer);
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
      socket.write(`${head.join('\r\n')}\r\n\r\n${body}`);
    });
    const split = raw.indexOf('\r\n\r\n');
    assert.equal(Number(raw.split('\r\n')[0].split(' ')[1]), 200);
    assert.equal(JSON.parse(raw.slice(split + 4)).state, 'delivered');
    assert.deepEqual({ ...used, open: used.open >= 1 }, { prepare: 1, dispatch: 1, finish: 1, open: true, send: 1 });
  } finally {
    lifetime.abort();
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
  assert.equal(factoryCalls, 0);
  assert.ok(!logs.some((entry) => JSON.stringify(entry).includes('synthetic plain text')));
  assert.equal(digest(), before);
});

test('D11: 保存のpublicJwkだけ・SPKIだけを別鍵へ変えたringは固定障害で書換え0', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-d11a');
  const b = w.enroll('synthetic-uid-d11b');
  await w.service().getOrInitialize(a, w.operation());
  await w.service().getOrInitialize(b, w.operation());
  const [[pathA, ringA], [, ringB]] = w.rings();
  const other = ringB.keys[0];
  assert.notEqual(other.publicJwk.n, ringA.keys[0].publicJwk.n);
  const reads = w.secretReads.length;
  const mutations = {
    jwkOnly: (key) => ({ ...key, publicJwk: { ...key.publicJwk, n: other.publicJwk.n } }),
    spkiOnly: (key) => ({ ...key, publicKeySpki: other.publicKeySpki }),
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const tampered = { ...ringA, keys: [mutate(ringA.keys[0])] };
    w.db.docs.set(pathA, structuredClone(tampered));
    assert.deepEqual(await w.service().getOrInitialize(a, w.operation()), UNAVAILABLE, name);
    assert.deepEqual(w.db.docs.get(pathA), tampered, name);
  }
  assert.equal(w.secretReads.length, reads);
});
