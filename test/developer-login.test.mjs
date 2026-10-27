// 開発者向け6桁ログインコード（運営者が発行し、プラグイン接続に使う）の状態・保存・認証・接続flowの合成検証。
//   - S: 6桁/先頭0/一様乱数port、10分境界、予約24時間、HMAC予約ID、schema。
//   - D: 共有DBの条件付き作成（衝突→別候補、同時同番号は成功1件、20候補失敗、DB障害は衝突扱いしない、期限）、TTL削除遅延中の重複回避、
//        鍵指紋変更は時間に関係なく拒否、試行制限（interaction/送信元/全体、並行）、取消/再発行の原子性、同番号再利用後の旧operation。
//   - A: 交換の段階分離（作成/署名失敗・応答消失・期限超過で消費を戻さない、遅延確定の失効）、共通verifierのmarker/family/state、
//        Apple回帰、feature off、rollback（code UIDをApple相当で通さない）。
//   - F: 発行→交換→新identity1件→ConnectStorage.resolveOwner（許可世代）→ID token2回検証（1回目で消費しない）→再発行でそのfamilyだけ失効。
// 合成のin-memory Firestore・HMAC・時計・乱数だけ。実SDK・Cloud・資格・network 0。コード・UID・tokenを出力しない。

import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { Timestamp } from '@google-cloud/firestore';

import {
  CODE_AUTH_TTL_MS,
  DEVELOPER_LOGIN_LIMITS,
  DeveloperLoginError,
  RESERVATION_HOLD_MS,
  developerLoginKeys,
  drawCode,
  isCodeUid,
  newReservation,
  parseCodeInput,
  parseReservation,
  reservationExpired,
  reservationUsable,
  transitionReservation,
} from '../dist/identity/developer-login.js';
import { DeveloperLoginStore } from '../dist/identity/developer-login-store.js';
import { createCodeIdentityLookup, createDeveloperCodeExchange, createLateCodeIdentityCheck, consoleToken } from '../dist/identity/developer-code-identity.js';
import { DEVELOPER_LOGIN_MODE, validateDeploymentConfig } from '../dist/config/validate.js';
import { createFirebaseAdminVerifier, IdentityError } from '../dist/identity/firebase.js';
import { ConnectStorage, connectIdentityHash } from '../dist/connect/firestore.js';
import * as runtimeModule from '../dist/events/kms-subscription-runtime.js';
import { createConnectKmsSealingPort } from '../dist/connect/kms-port.js';
import { crc32c } from '../dist/protection/kms-sealing.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument } from '../dist/storage/firestore/kms-subscription-format.js';

// ---------- 合成Firestore（楽観的transaction・読取りは書込みより前・create/update検査・障害注入） ----------

class Snapshot {
  constructor(ref, entry) {
    this.ref = ref;
    this.id = ref.id;
    this.exists = entry !== undefined;
    this._data = entry?.data;
    this.updateTime = entry === undefined ? undefined : Timestamp.fromMillis(1_900_000_000_000 + entry.version);
  }
  data() {
    return this._data === undefined ? undefined : { ...this._data };
  }
}

class Ref {
  constructor(db, path) {
    this.db = db;
    this.path = path;
    this.id = path.slice(path.lastIndexOf('/') + 1);
  }
  /** 製品の借用db同一性の検査（ref.firestore === db）に合わせ、生成元の同じ合成dbを返す。 */
  get firestore() {
    return this.db;
  }
  collection(name) {
    return new Coll(this.db, `${this.path}/${name}`);
  }
  async get() {
    await this.db.gate();
    return new Snapshot(this, this.db.docs.get(this.path));
  }
  // transaction外の書込み（oidc adapter等）。
  async set(data) {
    await this.db.gate();
    this.db.put(this.path, { ...data });
  }
  async update(data) {
    await this.db.gate();
    const existing = this.db.docs.get(this.path);
    if (existing === undefined) throw new Error('fake: not found');
    this.db.put(this.path, { ...existing.data, ...data });
  }
  async delete() {
    await this.db.gate();
    this.db.docs.delete(this.path);
  }
}

class Coll {
  constructor(db, path) {
    this.db = db;
    this.path = path;
  }
  doc(id) {
    return new Ref(this.db, `${this.path}/${id}`);
  }
}

class Tx {
  constructor(db) {
    this.db = db;
    this.reads = new Map();
    this.writes = [];
  }
  async get(ref) {
    if (this.writes.length > 0) throw new Error('fake: read after write in transaction');
    await this.db.gate();
    const entry = this.db.docs.get(ref.path);
    this.reads.set(ref.path, entry?.version ?? 0);
    return new Snapshot(ref, entry);
  }
  create(ref, data) {
    this.writes.push({ kind: 'create', path: ref.path, data });
  }
  set(ref, data) {
    this.writes.push({ kind: 'set', path: ref.path, data });
  }
  update(ref, data) {
    this.writes.push({ kind: 'update', path: ref.path, data });
  }
  delete(ref) {
    this.writes.push({ kind: 'delete', path: ref.path });
  }
  async getAll(...refs) {
    const snapshots = [];
    for (const ref of refs) snapshots.push(await this.get(ref));
    return snapshots;
  }
}

class FakeDb {
  constructor() {
    this.docs = new Map();
    this.clockVersion = 1;
    this.failures = 0;
    this.hang = false;
    this.commits = 0;
  }
  collection(name) {
    return new Coll(this, name);
  }
  doc(path) {
    return new Ref(this, path);
  }
  put(path, data) {
    this.clockVersion += 1;
    this.docs.set(path, { data, version: this.clockVersion });
  }
  async gate() {
    await new Promise((resolve) => setImmediate(resolve));
    if (this.hang) await new Promise(() => undefined);
    if (this.failures > 0) {
      this.failures -= 1;
      throw Object.assign(new Error('synthetic sdk failure'), { code: 14 });
    }
  }
  async runTransaction(fn, options = {}) {
    // 文書lockの近似として1件ずつ実行する（並行要求は待って最新を読む）。
    const previous = this.lock ?? Promise.resolve();
    let release;
    this.lock = new Promise((resolve) => (release = resolve));
    await previous;
    try {
      return await this.runLocked(fn, options);
    } finally {
      release();
    }
  }
  async runLocked(fn, options) {
    const max = options.maxAttempts ?? 5;
    for (let attempt = 1; attempt <= max; attempt += 1) {
      const tx = new Tx(this);
      const result = await fn(tx);
      await this.gate();
      const stale = [...tx.reads].some(([path, version]) => (this.docs.get(path)?.version ?? 0) !== version);
      if (stale) continue;
      for (const write of tx.writes) {
        if (write.kind === 'delete') {
          this.docs.delete(write.path);
          continue;
        }
        const existing = this.docs.get(write.path);
        if (write.kind === 'create' && existing !== undefined) throw new Error('fake: already exists');
        if (write.kind === 'update' && existing === undefined) throw new Error('fake: not found');
        const data = write.kind === 'update' ? { ...existing.data, ...write.data } : { ...write.data };
        this.clockVersion += 1;
        this.docs.set(write.path, { data, version: this.clockVersion });
      }
      this.commits += 1;
      return result;
    }
    throw Object.assign(new Error('fake: contention'), { code: 10 });
  }
  /** TTLの物理削除（遅延も含め、試験が明示した時だけ）。 */
  delete(pathSuffix) {
    for (const path of [...this.docs.keys()]) if (path.endsWith(pathSuffix)) this.docs.delete(path);
  }
  count(collection) {
    return [...this.docs.keys()].filter((path) => path.includes(`/${collection}/`)).length;
  }
}

// ---------- 合成の時計・乱数・鍵 ----------

const T0 = Date.UTC(2026, 9, 27, 0, 0, 0);
function clockAt(start = T0) {
  const clock = { t: start, now: () => clock.t };
  return clock;
}

/** 指定した数字列を順に返し、尽きたら暗号学的乱数へ戻る乱数port。 */
function scriptedRandom(values = []) {
  const queue = [...values];
  return {
    int: (max) => (queue.length > 0 ? queue.shift() : Math.floor(randomBytes(4).readUInt32BE() / 2 ** 32 * max)),
    bytes: (n) => randomBytes(n),
    uuid: () => globalThis.crypto.randomUUID(),
  };
}

const NAMESPACE = 't256_0b2c9a1e-4d5f-4a6b-8c7d-9e0f1a2b3c4d';
const PROJECT = 'sttd-synthetic';
const SCOPE = { projectId: PROJECT, databaseId: '(default)', namespace: NAMESPACE, purpose: 'plugin-connect' };

function makeStore(options = {}) {
  const db = options.db ?? new FakeDb();
  const clock = options.clock ?? clockAt();
  const keys = developerLoginKeys(options.secret ?? randomBytes(32));
  const store = new DeveloperLoginStore({
    db,
    scope: SCOPE,
    hasher: keys.hasher,
    sealer: keys.sealer,
    clock,
    random: options.random ?? scriptedRandom(options.codes),
    ...(options.limits ? { limits: options.limits } : {}),
  });
  return { db, clock, store, keys };
}

const claim = () => randomBytes(32).toString('base64url');
const WIDE = { ...DEVELOPER_LOGIN_LIMITS, namespaceActiveMax: 100, consoleActiveMax: 100, consoleIssuesPerHour: 100, namespaceIssuesPerHour: 100 };

// 接続保存のidentity HMAC（試験用の固定形。実配置はSecret Managerの鍵）。
const CONNECT_KEY = randomBytes(32);
const connectHasher = { hash: (purpose, value) => createHmac('sha256', CONNECT_KEY).update(`${purpose}\0${value}`).digest('hex') };

function fakeAuth(options = {}) {
  const users = new Set();
  const calls = { createUser: 0, sign: 0 };
  return {
    users,
    calls,
    async createUser({ uid }) {
      calls.createUser += 1;
      if (options.createFails) throw Object.assign(new Error('x'), { code: 'auth/internal-error' });
      if (users.has(uid)) throw Object.assign(new Error('x'), { code: 'auth/uid-already-exists' });
      users.add(uid);
      if (options.loseCreateResponse) throw Object.assign(new Error('x'), { code: 'app/network-timeout' });
      return { uid };
    },
    async createCustomToken(uid, claims) {
      calls.sign += 1;
      if (options.signFails) throw new Error('sign');
      if (options.signHangs) return new Promise(() => undefined);
      return `ct.${Buffer.from(JSON.stringify({ uid, claims })).toString('base64url')}`;
    },
  };
}

/** custom tokenでSDKログインした後のID tokenを模すadmin verify（合成）。 */
function fakeAdminVerify(tokens) {
  return {
    async verifyIdToken(idToken) {
      const decoded = tokens.get(idToken);
      if (decoded === undefined) throw Object.assign(new Error('x'), { code: 'auth/invalid-id-token' });
      return decoded;
    },
    async getUser() {
      return { disabled: false };
    },
  };
}

function idTokenFor(customToken, tokens, overrides = {}) {
  const { uid, claims } = JSON.parse(Buffer.from(customToken.slice(3), 'base64url').toString('utf8'));
  const id = `id.${randomBytes(8).toString('hex')}`;
  tokens.set(id, {
    aud: PROJECT,
    iss: `https://securetoken.google.com/${PROJECT}`,
    sub: uid,
    auth_time: Math.floor(T0 / 1000),
    firebase: { sign_in_provider: 'custom' },
    ...claims,
    ...overrides,
  });
  return { id, uid };
}

// ================= S: 純粋状態 =================

test('S1 code is 6 digits with leading zeros kept and uniform port range enforced', () => {
  assert.equal(drawCode(scriptedRandom([7])), '000007');
  assert.equal(drawCode(scriptedRandom([0])), '000000');
  assert.equal(drawCode(scriptedRandom([999_999])), '999999');
  assert.throws(() => drawCode(scriptedRandom([1_000_000])), DeveloperLoginError);
  assert.throws(() => drawCode(scriptedRandom([-1])), DeveloperLoginError);
  assert.equal(parseCodeInput(' 012345 '), '012345');
  for (const bad of ['12345', '1234567', '12 345', '１２３４５６', 12345, null, '0x1234']) assert.equal(parseCodeInput(bad), null);
});

test('S2 10 minute boundary, 24h hold not shortened by consume/revoke', () => {
  const record = newReservation({ issuanceId: globalThis.crypto.randomUUID(), consoleHash: 'c', consoleGeneration: 1, purpose: 'plugin-connect', issuedAt: T0 });
  assert.equal(record.authExpiresAt, T0 + CODE_AUTH_TTL_MS);
  assert.equal(record.deleteAfter, T0 + RESERVATION_HOLD_MS);
  assert.equal(reservationUsable(record, T0 + CODE_AUTH_TTL_MS - 1), true);
  assert.equal(reservationUsable(record, T0 + CODE_AUTH_TTL_MS), false);
  assert.equal(reservationExpired(record, T0 + CODE_AUTH_TTL_MS), true);
  const consumed = transitionReservation(record, 'provisioning', 'i');
  assert.equal(consumed.deleteAfter, record.deleteAfter);
  assert.equal(transitionReservation(consumed, 'revoked').deleteAfter, record.deleteAfter);
  assert.throws(() => transitionReservation(consumed, 'issued'), DeveloperLoginError);
  assert.equal(reservationUsable(consumed, T0 + 1), false);
});

test('S3 reservation schema is exact (unknown version/extra key/short deleteAfter rejected)', () => {
  const record = newReservation({ issuanceId: globalThis.crypto.randomUUID(), consoleHash: 'c', consoleGeneration: 1, purpose: 'plugin-connect', issuedAt: T0 });
  const ms = (value) => (typeof value === 'number' ? value : null);
  assert.equal(parseReservation({ ...record }, ms).state, 'issued');
  assert.throws(() => parseReservation({ ...record, version: 2 }, ms));
  assert.throws(() => parseReservation({ ...record, extra: 1 }, ms));
  assert.throws(() => parseReservation({ ...record, deleteAfter: T0 + 1000 }, ms));
  assert.throws(() => parseReservation({ ...record, state: 'active', boundInteractionHash: null }, ms));
});

test('S4 HMAC reservation id depends on key and scope, not plain hash; sealer binds purpose', () => {
  const a = makeStore();
  const b = makeStore();
  assert.notEqual(a.store.reservationIdOf('012345'), b.store.reservationIdOf('012345'));
  assert.equal(a.store.reservationIdOf('012345'), a.store.reservationIdOf('012345'));
  assert.ok(!a.store.reservationIdOf('012345').includes('012345'));
  const sealed = a.keys.sealer.seal('p1', 'secret-uid');
  assert.equal(a.keys.sealer.open('p1', sealed), 'secret-uid');
  assert.throws(() => a.keys.sealer.open('p2', sealed));
  assert.throws(() => b.keys.sealer.open('p1', sealed));
  assert.throws(() => developerLoginKeys(Buffer.alloc(16)));
});

// ================= D: 発行・重複防止・試行制限 =================

test('D1 collision once then regenerate; stored doc has no plaintext code', async () => {
  const { db, store, clock } = makeStore({ codes: [42, 42, 43], limits: WIDE });
  const first = await store.issue({ claimSecret: claim() });
  assert.equal(first.code, '000042');
  clock.t += 1000;
  const second = await store.issue({ claimSecret: claim() });
  assert.equal(second.code, '000043');
  assert.equal(second.candidates, 2);
  for (const [, entry] of db.docs) assert.ok(!JSON.stringify(entry.data).includes('000042'));
});

test('D2 concurrent same-number issuance: exactly one gets the number', async () => {
  const { store } = makeStore({ codes: [5, 5, 6, 7], limits: WIDE });
  const results = await Promise.all([store.issue({ claimSecret: claim() }), store.issue({ claimSecret: claim() })]);
  const codes = results.map((r) => r.code).sort();
  assert.equal(codes.filter((c) => c === '000005').length, 1);
  assert.equal(new Set(codes).size, 2);
});

test('D3 20 candidates exhausted -> issue_exhausted, existing reservations untouched', async () => {
  const { db, store, clock } = makeStore({ codes: [9, ...Array(20).fill(9)], limits: WIDE });
  await store.issue({ claimSecret: claim() });
  const before = db.count('developerLoginCodeReservations');
  clock.t += 1;
  await assert.rejects(store.issue({ claimSecret: claim() }), (e) => e instanceof DeveloperLoginError && e.code === 'issue_exhausted');
  assert.equal(db.count('developerLoginCodeReservations'), before);
});

test('D4 DB failure is unavailable (not treated as collision, no extra candidates)', async () => {
  const { db, store } = makeStore({ codes: [1, 2, 3] });
  db.failures = 1;
  await assert.rejects(store.issue({ claimSecret: claim() }), (e) => e.code === 'unavailable');
  assert.equal(db.count('developerLoginCodeReservations'), 0);
});

test('D5 hung DB returns unavailable within the 15s budget (no infinite wait)', async () => {
  const clock = clockAt();
  const { db, store } = makeStore({ clock });
  db.hang = true;
  const pending = store.issue({ claimSecret: claim() });
  // 元期限を合成時計で過ぎさせる（実時間は待たない）: guardのtimerは残り時間で張るため、時計を進めてから短いtimerを確認する。
  clock.t += 15_001;
  await assert.rejects(Promise.race([pending, new Promise((_, r) => setTimeout(() => r(new Error('waited too long')), 16_000).unref())]), (e) => e.code === 'unavailable');
});

test('D6 reuse refused before +24h and while TTL deletion is delayed; allowed only after physical deletion', async () => {
  const { db, store, clock } = makeStore({ codes: [77, 77, 78, 77], limits: WIDE });
  const first = await store.issue({ claimSecret: claim() });
  assert.equal(first.code, '000077');
  clock.t += RESERVATION_HOLD_MS + 60 * 60_000; // 24h後でも削除前
  const second = await store.issue({ claimSecret: claim() });
  assert.equal(second.code, '000078');
  db.delete(store.reservationIdOf('000077'));
  clock.t += 1;
  const third = await store.issue({ claimSecret: claim() });
  assert.equal(third.code, '000077');
});

test('D7 dedupe key change is refused regardless of time (TTL-delayed old docs could collide)', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const a = makeStore({ db, clock, codes: [11] });
  await a.store.issue({ claimSecret: claim() });
  clock.t += RESERVATION_HOLD_MS * 3; // deleteAfter後、旧予約は削除遅延で残存
  const b = makeStore({ db, clock, codes: [11] });
  await assert.rejects(b.store.issue({ claimSecret: claim() }), (e) => e.code === 'key_rotation_blocked');
  assert.equal(db.count('developerLoginCodeReservations'), 1);
});

test('D8 issuance limits: console active 1, console 3/h, namespace 20/h and active 5', async () => {
  const { store, clock } = makeStore();
  const secret = claim();
  await store.issue({ claimSecret: secret });
  await assert.rejects(store.issue({ claimSecret: secret }), (e) => e.code === 'rate_limited');
  for (let i = 0; i < 4; i += 1) await store.issue({ claimSecret: claim() });
  await assert.rejects(store.issue({ claimSecret: claim() }), (e) => e.code === 'rate_limited'); // active 5
  clock.t += CODE_AUTH_TTL_MS;
  const other = claim();
  await store.issue({ claimSecret: other });
  clock.t += CODE_AUTH_TTL_MS;
  await store.issue({ claimSecret: other });
  clock.t += CODE_AUTH_TTL_MS;
  await store.issue({ claimSecret: other });
  clock.t += CODE_AUTH_TTL_MS;
  await assert.rejects(store.issue({ claimSecret: other }), (e) => e.code === 'rate_limited'); // console 3/h
});

test('D9 attempt limits cannot be bypassed by changing interaction/source or by parallel attempts', async () => {
  const { store } = makeStore({ codes: [100] });
  await store.issue({ claimSecret: claim() });
  const tries = [];
  for (let i = 0; i < 8; i += 1) tries.push(store.consume({ code: String(200 + i).padStart(6, '0'), interactionKey: `i${i}`, sourceKey: `s${i}` }));
  const results = await Promise.all(tries);
  assert.equal(results.filter((r) => r.kind === 'rejected').length, 5);
  assert.equal(results.filter((r) => r.kind === 'rate_limited').length, 3);
  // 全体の失敗上限中は正しいコードでも通さない。
  assert.equal((await store.consume({ code: '000100', interactionKey: 'new', sourceKey: 'new' })).kind, 'rate_limited');
});

test('D10 per-interaction limit and bucket failure refuses', async () => {
  const { db, store } = makeStore({ codes: [100] });
  await store.issue({ claimSecret: claim() });
  const results = [];
  for (let i = 0; i < 6; i += 1) results.push((await store.consume({ code: '000100', interactionKey: 'same', sourceKey: `s${i}` })).kind);
  assert.deepEqual(results.slice(0, 2), ['consumed', 'rejected']);
  db.failures = 1;
  await assert.rejects(store.consume({ code: '000101', interactionKey: 'x', sourceKey: 'y' }), (e) => e.code === 'unavailable');
});

test('D11 expired, consumed, revoked and unknown codes are the same rejection; replay/double exchange creates nothing', async () => {
  const { store, clock } = makeStore({ codes: [300], limits: { ...WIDE, namespaceFailures: 100, attemptsPerSource: 100, attemptsPerInteraction: 100 } });
  const issued = await store.issue({ claimSecret: claim() });
  const [a, b] = await Promise.all([
    store.consume({ code: issued.code, interactionKey: 'i1', sourceKey: 's' }),
    store.consume({ code: issued.code, interactionKey: 'i2', sourceKey: 's' }),
  ]);
  assert.deepEqual([a.kind, b.kind].sort(), ['consumed', 'rejected']);
  assert.equal((await store.consume({ code: issued.code, interactionKey: 'i1', sourceKey: 's' })).kind, 'rejected');
  assert.equal((await store.consume({ code: '999998', interactionKey: 'i3', sourceKey: 's' })).kind, 'rejected');
  const s2 = makeStore({ codes: [301], limits: WIDE });
  const late = await s2.store.issue({ claimSecret: claim() });
  s2.clock.t += CODE_AUTH_TTL_MS; // ちょうど10分
  assert.equal((await s2.store.consume({ code: late.code, interactionKey: 'i', sourceKey: 's' })).kind, 'rejected');
  const s3 = makeStore({ codes: [302], limits: WIDE });
  const secret = claim();
  const cancelled = await s3.store.issue({ claimSecret: secret });
  assert.equal(await s3.store.cancel({ claimSecret: secret, operationId: cancelled.operationId }), 'revoked');
  assert.equal((await s3.store.consume({ code: cancelled.code, interactionKey: 'i', sourceKey: 's' })).kind, 'rejected');
  void clock;
});

test('D12 other console cannot claim/cancel/reissue with the 6 digits or its own secret', async () => {
  const { store } = makeStore({ codes: [400, 401] });
  const owner = claim();
  const issued = await store.issue({ claimSecret: owner });
  const stranger = claim();
  await assert.rejects(store.claim({ claimSecret: stranger, operationId: issued.operationId }), (e) => e.code === 'not_owner');
  await assert.rejects(store.cancel({ claimSecret: stranger, operationId: issued.operationId }), (e) => e.code === 'not_owner');
  await assert.rejects(store.issue({ claimSecret: stranger, previousOperationId: issued.operationId }), (e) => e.code === 'not_owner');
  await assert.rejects(store.claim({ claimSecret: stranger, operationId: issued.code }), (e) => e.code === 'invalid_request');
});

// ================= A: 交換・認証 =================

function exchangeFor(store, auth, clock) {
  return createDeveloperCodeExchange({
    store,
    auth,
    clock,
    accessIdentityHash: (uid) => connectIdentityHash(connectHasher, NAMESPACE, { projectId: PROJECT, uid }),
  });
}

test('A1 SDK create/sign failure or lost response never returns the code to unused and grants nothing', async () => {
  for (const option of ['createFails', 'loseCreateResponse', 'signFails']) {
    const { store, clock, db } = makeStore({ codes: [500] });
    const issued = await store.issue({ claimSecret: claim() });
    const auth = fakeAuth({ [option]: true });
    const outcome = await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
    assert.equal(outcome.kind, 'failed', option);
    assert.equal(db.count('developerCodeIdentities'), 0, option);
    assert.equal(db.count('/access/'.slice(1, -1)), 0, option);
    assert.equal((await store.consume({ code: issued.code, interactionKey: 'i2', sourceKey: 's2' })).kind, 'rejected', option);
  }
});

test('A2 existing UID error is not adopted', async () => {
  const { store, clock } = makeStore({ codes: [501] });
  const issued = await store.issue({ claimSecret: claim() });
  const auth = fakeAuth();
  const original = auth.createUser;
  auth.createUser = async () => {
    throw Object.assign(new Error('x'), { code: 'auth/uid-already-exists' });
  };
  assert.equal((await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'i', sourceKey: 's' })).kind, 'failed');
  void original;
});

test('A3 signing that never returns ends at the deadline; a late activation cannot be committed', async () => {
  const clock = clockAt();
  const { store, db } = makeStore({ codes: [502], clock });
  const issued = await store.issue({ claimSecret: claim() });
  const auth = fakeAuth({ signHangs: true });
  // 製品のtimerはunref（serverを止めない）なので、試験の待ちの間だけ参照付きtimerでevent loopを保つ。
  const keepAlive = setTimeout(() => undefined, 20_000);
  const started = Date.now();
  const outcome = await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  clearTimeout(keepAlive);
  assert.equal(outcome.kind, 'failed');
  assert.ok(Date.now() - started < 16_000);
  assert.equal(db.count('developerCodeIdentities'), 0);
});

test('A4 verifier: marker/family/UID/state checks, custom refused when feature off, Apple regression, rollback', async () => {
  const { store, clock } = makeStore({ codes: [600] });
  const issued = await store.issue({ claimSecret: claim() });
  const auth = fakeAuth();
  const outcome = await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  assert.equal(outcome.kind, 'token');
  const tokens = new Map();
  const admin = fakeAdminVerify(tokens);
  const verifier = createFirebaseAdminVerifier({ auth: admin, projectId: PROJECT, codeIdentities: createCodeIdentityLookup(store) });
  const good = idTokenFor(outcome.customToken, tokens);
  const verified = await verifier.verifyIdToken(good.id);
  assert.equal(verified.method, 'developer_code');
  assert.ok(isCodeUid(verified.uid));
  const reject = async (id, code) => assert.rejects(verifier.verifyIdToken(id), (e) => e instanceof IdentityError && e.code === code);
  await reject(idTokenFor(outcome.customToken, tokens, { sttd_dlc: undefined }).id, 'wrong_provider');
  await reject(idTokenFor(outcome.customToken, tokens, { sttd_dlc: 2 }).id, 'wrong_provider');
  await reject(idTokenFor(outcome.customToken, tokens, { sttd_fam: globalThis.crypto.randomUUID() }).id, 'revoked');
  await reject(idTokenFor(outcome.customToken, tokens, { sub: `sttdc_${randomBytes(24).toString('base64url')}` }).id, 'deleted');
  await reject(idTokenFor(outcome.customToken, tokens, { sub: 'arbitrary-existing-uid' }).id, 'wrong_provider');
  await reject(idTokenFor(outcome.customToken, tokens, { aud: 'other-project' }).id, 'wrong_project');
  await reject(idTokenFor(outcome.customToken, tokens, { firebase: { sign_in_provider: 'custom', tenant: 't1' } }).id, 'wrong_project');
  // feature off（lookupなし）ではcustomを受けず、code UIDのaccountStatusも有効にしない。
  const off = createFirebaseAdminVerifier({ auth: admin, projectId: PROJECT });
  await assert.rejects(off.verifyIdToken(good.id), (e) => e.code === 'wrong_provider');
  assert.equal(await off.accountStatus(good.uid, 0), 'revoked');
  // rollback: code UIDをapple.comとして名乗っても受けない。Appleの通常UIDは従来どおり。
  const appleSpoof = `id.${randomBytes(4).toString('hex')}`;
  tokens.set(appleSpoof, { aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, sub: good.uid, auth_time: 1, firebase: { sign_in_provider: 'apple.com' } });
  await reject(appleSpoof, 'wrong_provider');
  const apple = `id.${randomBytes(4).toString('hex')}`;
  tokens.set(apple, { aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, sub: 'AppleUid0123456789abcdef', auth_time: 1, firebase: { sign_in_provider: 'apple.com' } });
  const appleVerified = await verifier.verifyIdToken(apple);
  assert.equal(appleVerified.method, undefined);
  assert.equal(appleVerified.uid, 'AppleUid0123456789abcdef');
  assert.equal(await verifier.accountStatus(good.uid, 0), 'active');
});

test('A5 lookup outage is unavailable (not accepted)', async () => {
  const tokens = new Map();
  const verifier = createFirebaseAdminVerifier({
    auth: fakeAdminVerify(tokens),
    projectId: PROJECT,
    codeIdentities: { status: async () => { throw new Error('db'); } },
  });
  const uid = `sttdc_${randomBytes(24).toString('base64url')}`;
  tokens.set('t', { aud: PROJECT, iss: `https://securetoken.google.com/${PROJECT}`, sub: uid, auth_time: 1, firebase: { sign_in_provider: 'custom' }, sttd_dlc: 1, sttd_fam: globalThis.crypto.randomUUID() });
  await assert.rejects(verifier.verifyIdToken('t'), (e) => e.code === 'unavailable');
});

// ================= F: 接続flow・再発行 =================

function connectStorage(db, clock) {
  return new ConnectStorage({
    db,
    namespace: NAMESPACE,
    hasher: connectHasher,
    box: { seal: async (purpose, plaintext) => `sealed:${Buffer.from(plaintext).toString('base64url')}`, open: async (purpose, sealed) => Buffer.from(sealed.slice(7), 'base64url').toString() },
    clock,
    ownerInactivityMs: 90 * 24 * 60 * 60_000,
    interactionTtlMs: 10 * 60_000,
    grantInactivityMs: 90 * 24 * 60 * 60_000,
  });
}

test('F1 issue -> exchange -> one new identity -> owner admitted with access generation -> two verifications; reissue revokes only that family', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const { store } = makeStore({ db, clock, codes: [12, 34, 56], limits: WIDE });
  const auth = fakeAuth();
  const exchange = exchangeFor(store, auth, clock);
  const tokens = new Map();
  const verifier = createFirebaseAdminVerifier({ auth: fakeAdminVerify(tokens), projectId: PROJECT, codeIdentities: createCodeIdentityLookup(store) });
  const storage = connectStorage(db, clock);

  const consoleA = claim();
  const a = await store.issue({ claimSecret: consoleA });
  assert.equal((await store.claim({ claimSecret: consoleA, operationId: a.operationId })).kind, 'pending');
  const outA = await exchange.exchange({ code: a.code, interactionKey: 'interaction-a', sourceKey: 'src' });
  assert.equal(outA.kind, 'token');
  assert.equal(auth.users.size, 1);
  const idA = idTokenFor(outA.customToken, tokens);
  const verifiedA = await verifier.verifyIdToken(idA.id);
  const admission = await storage.resolveOwner(verifiedA);
  assert.equal(admission.kind, 'admitted');
  // 2回の送信相当（ID token検証）で認証権を消費しない。
  assert.equal((await verifier.verifyIdToken(idA.id)).uid, idA.uid);
  assert.equal((await verifier.verifyIdToken(idA.id)).uid, idA.uid);
  assert.equal(await storage.findOwner(verifiedA), admission.ownerId);

  // 発行元コンソールは照会secretの証明でだけ同じUIDのtokenを得る。
  const consoleTok = await consoleToken(store, auth, { claimSecret: consoleA, operationId: a.operationId }, clock);
  assert.equal(consoleTok.kind, 'active');
  assert.equal(JSON.parse(Buffer.from(consoleTok.customToken.slice(3), 'base64url').toString()).uid, idA.uid);

  // 別コンソールBの接続（新identity。Aとは別）。
  const consoleB = claim();
  const b = await store.issue({ claimSecret: consoleB });
  const outB = await exchange.exchange({ code: b.code, interactionKey: 'interaction-b', sourceKey: 'src2' });
  const idB = idTokenFor(outB.customToken, tokens);
  const verifiedB = await verifier.verifyIdToken(idB.id);
  assert.notEqual(verifiedB.uid, verifiedA.uid);
  assert.equal((await storage.resolveOwner(verifiedB)).kind, 'admitted');

  // 予約の物理削除（24時間後）は接続に影響しない。
  clock.t += RESERVATION_HOLD_MS + 1;
  db.delete(store.reservationIdOf(a.code));
  assert.equal((await verifier.verifyIdToken(idA.id)).uid, idA.uid);

  // Aの再発行: 新予約と旧family/許可の失効を同時に確定。Bは影響なし。
  const a2 = await store.issue({ claimSecret: consoleA, previousOperationId: a.operationId });
  assert.equal(a2.code.length, 6);
  await assert.rejects(verifier.verifyIdToken(idA.id), (e) => e.code === 'revoked');
  assert.equal(await verifier.accountStatus(idA.uid, 0), 'revoked');
  assert.equal((await storage.resolveOwner(verifiedA)).kind, 'denied');
  assert.equal((await verifier.verifyIdToken(idB.id)).uid, idB.uid);
  assert.equal((await storage.resolveOwner(verifiedB)).kind, 'admitted');
  assert.equal((await store.claim({ claimSecret: consoleA, operationId: a.operationId })).kind, 'ended');
});

test('F2 reissue whose candidate cannot be secured keeps the old connection', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const { store } = makeStore({ db, clock, codes: [70, 71, ...Array(20).fill(71)], limits: WIDE });
  const auth = fakeAuth();
  const tokens = new Map();
  const verifier = createFirebaseAdminVerifier({ auth: fakeAdminVerify(tokens), projectId: PROJECT, codeIdentities: createCodeIdentityLookup(store) });
  const consoleA = claim();
  const a = await store.issue({ claimSecret: consoleA });
  const out = await exchangeFor(store, auth, clock).exchange({ code: a.code, interactionKey: 'i', sourceKey: 's' });
  const id = idTokenFor(out.customToken, tokens);
  await store.issue({ claimSecret: claim() }); // 71を占有
  await assert.rejects(store.issue({ claimSecret: consoleA, previousOperationId: a.operationId }), (e) => e.code === 'issue_exhausted');
  assert.equal((await verifier.verifyIdToken(id.id)).uid, id.uid);
  db.failures = 1;
  await assert.rejects(store.issue({ claimSecret: consoleA, previousOperationId: a.operationId }), (e) => e.code === 'unavailable');
  assert.equal((await verifier.verifyIdToken(id.id)).uid, id.uid);
});

test('F3 cancel racing activation: activation after cancel grants nothing', async () => {
  const { store, clock, db } = makeStore({ codes: [80] });
  const secret = claim();
  const issued = await store.issue({ claimSecret: secret });
  const consumed = await store.consume({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  assert.equal(consumed.kind, 'consumed');
  assert.equal(await store.cancel({ claimSecret: secret, operationId: issued.operationId }), 'revoked');
  const activated = await store.activate({
    operationIdHash: consumed.operationIdHash,
    issuanceId: consumed.issuanceId,
    uid: consumed.uid,
    accessIdentityHash: connectIdentityHash(connectHasher, NAMESPACE, { projectId: PROJECT, uid: consumed.uid }),
  });
  assert.equal(activated.kind, 'revoked');
  assert.equal(db.count('developerCodeIdentities'), 0);
  void clock;
});

test('F4 same number reused after 24h: old operation/secret cannot touch the new owner', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const { store } = makeStore({ db, clock, codes: [90, 90], limits: WIDE });
  const oldSecret = claim();
  const old = await store.issue({ claimSecret: oldSecret });
  clock.t += RESERVATION_HOLD_MS + 1;
  db.delete(store.reservationIdOf(old.code));
  const fresh = await store.issue({ claimSecret: claim() });
  assert.equal(fresh.code, old.code);
  assert.equal(await store.cancel({ claimSecret: oldSecret, operationId: old.operationId }), 'revoked');
  // 新しい予約は旧operationの取消で変わらず、正しく交換できる。
  assert.equal((await store.consume({ code: fresh.code, interactionKey: 'i', sourceKey: 's' })).kind, 'consumed');
});

test('F6 code identity -> access generation -> owner -> interaction bind -> consent -> Grant metadata -> Grant generation check; reissue refuses the old generation and old Grant', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const { store } = makeStore({ db, clock, codes: [810, 811], limits: WIDE });
  const auth = fakeAuth();
  const tokens = new Map();
  const verifier = createFirebaseAdminVerifier({ auth: fakeAdminVerify(tokens), projectId: PROJECT, codeIdentities: createCodeIdentityLookup(store) });
  // 実ConnectStorage（login/同意/Grant metadataの保存と、Grant世代の判定）。
  const storage = connectStorage(db, clock);
  const consoleA = claim();
  const issued = await store.issue({ claimSecret: consoleA });
  const outcome = await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'interaction-consent', sourceKey: 's' });
  assert.equal(outcome.kind, 'token');
  const id = idTokenFor(outcome.customToken, tokens);
  const verified = await verifier.verifyIdToken(id.id);

  // login: 利用許可（code確定で作った予定UID1件の世代）でownerを解決し、interactionへ同じ世代で束縛する。
  const admission = await storage.resolveOwner(verified);
  assert.equal(admission.kind, 'admitted');
  const opened = await storage.openInteraction('interaction-consent');
  assert.equal(opened.ownerId, null);
  assert.equal(await storage.interactionAccepts('interaction-consent', opened.csrf), true);
  assert.equal(await storage.bindInteraction('interaction-consent', opened.csrf, admission.ownerId, verified.authTimeSec, admission.accessGeneration), 'ok');
  // 同意: 単回消費→Grant metadataを同じ世代で作る→Grant世代の判定が成立。
  const consent = await storage.consumeInteraction('interaction-consent', opened.csrf);
  assert.equal(typeof consent, 'object');
  assert.equal(consent.ownerId, admission.ownerId);
  assert.equal(consent.accessGeneration, admission.accessGeneration);
  assert.equal(await storage.consumeInteraction('interaction-consent', opened.csrf), undefined, 'consent is single-use');
  assert.equal(await storage.putGrantMeta('grant-code-1', consent), 'created');
  assert.equal(await storage.grantUsable(admission.ownerId, 'grant-code-1'), true);
  assert.deepEqual(await storage.grantMeta('grant-code-1'), { ownerId: admission.ownerId, authTimeSec: verified.authTimeSec });

  // 再発行前に開いた別interaction（旧世代で束縛済み・未同意）。
  const pendingOpen = await storage.openInteraction('interaction-old');
  assert.equal(await storage.bindInteraction('interaction-old', pendingOpen.csrf, admission.ownerId, verified.authTimeSec, admission.accessGeneration), 'ok');

  // 同じ発行元の再発行: 利用許可の世代が変わり（disabled）、旧Grant・旧世代の同意・旧identityを拒否する。
  await store.issue({ claimSecret: consoleA, previousOperationId: issued.operationId });
  assert.equal(await storage.grantUsable(admission.ownerId, 'grant-code-1'), false, 'old Grant refused');
  assert.equal(await storage.consumeInteraction('interaction-old', pendingOpen.csrf), 'denied', 'old-generation consent refused');
  assert.equal(await storage.putGrantMeta('grant-code-late', consent), 'denied', 'no Grant metadata from the old generation');
  assert.equal((await storage.resolveOwner(verified)).kind, 'denied');
  await assert.rejects(verifier.verifyIdToken(id.id), (e) => e.code === 'revoked');
  const fresh = await storage.openInteraction('interaction-after');
  assert.equal(await storage.bindInteraction('interaction-after', fresh.csrf, admission.ownerId, verified.authTimeSec, admission.accessGeneration), 'denied');
});

test('F7 code identity -> consent Grant -> real subscription registration runtime registers for the code owner; reissue refuses the old Grant for new registration', { timeout: 20_000 }, async () => {
  const db = new FakeDb();
  db.projectId = PROJECT;
  const clock = clockAt();
  const { store } = makeStore({ db, clock, codes: [820, 821], limits: WIDE });
  const auth = fakeAuth();
  const tokens = new Map();
  const verifier = createFirebaseAdminVerifier({ auth: fakeAdminVerify(tokens), projectId: PROJECT, codeIdentities: createCodeIdentityLookup(store) });
  // 接続保存の封緘は既存の購読runtime試験と同じ実KMS port（合成AES-GCM transport、接続namespace）。
  const kmsTransport = { current: null };
  const kmsKey = randomBytes(32);
  const transport = {
    async encrypt(request) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', kmsKey, iv);
      cipher.setAAD(request.additionalAuthenticatedData);
      const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
      const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
      return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
    },
    async decrypt(request) {
      const raw = request.ciphertext;
      const decipher = createDecipheriv('aes-256-gcm', kmsKey, raw.subarray(0, 12));
      decipher.setAAD(request.additionalAuthenticatedData);
      decipher.setAuthTag(raw.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
      return { plaintext, plaintextCrc32c: crc32c(plaintext), protectionLevel: 'SOFTWARE' };
    },
    close() {},
  };
  kmsTransport.current = transport;
  const box = createConnectKmsSealingPort({
    kms: { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`, writeVersion: 1, readVersions: [1], namespace: NAMESPACE, transport: { encrypt: (r) => kmsTransport.current.encrypt(r), decrypt: (r) => kmsTransport.current.decrypt(r), close() {} }, clock },
    operation: () => ({ deadlineAt: clock.now() + 60_000 }),
  });
  const storage = new ConnectStorage({ db, namespace: NAMESPACE, hasher: connectHasher, box, clock, ownerInactivityMs: 90 * 24 * 60 * 60_000, interactionTtlMs: 10 * 60_000, grantInactivityMs: 90 * 24 * 60 * 60_000 });
  const consoleA = claim();
  const issued = await store.issue({ claimSecret: consoleA });
  const outcome = await exchangeFor(store, auth, clock).exchange({ code: issued.code, interactionKey: 'interaction-sub', sourceKey: 's' });
  assert.equal(outcome.kind, 'token');
  const verified = await verifier.verifyIdToken(idTokenFor(outcome.customToken, tokens).id);
  const admission = await storage.resolveOwner(verified);
  assert.equal(admission.kind, 'admitted');
  const opened = await storage.openInteraction('interaction-sub');
  assert.equal(await storage.bindInteraction('interaction-sub', opened.csrf, admission.ownerId, verified.authTimeSec, admission.accessGeneration), 'ok');
  const consent = await storage.consumeInteraction('interaction-sub', opened.csrf);
  assert.equal(consent.ownerId, admission.ownerId);

  // 同意後のGrant: providerがgrant.save()で書く位置（実ConnectStorageのoidc adapter）と、同意記録の世代付きmetadata（実putGrantMeta）。
  const RESOURCE = 'https://mcp.sttd-code.invalid/mcp';
  const grantId = `grant-${randomBytes(9).toString('base64url')}`;
  const nowSec = Math.floor(clock.now() / 1000);
  await storage.adapterFactory('Grant').upsert(
    grantId,
    { iat: nowSec, exp: nowSec + 3600, accountId: admission.ownerId, clientId: 'https://client.sttd-code.invalid/meta.json', kind: 'Grant', jti: grantId, resources: { [RESOURCE]: 'sttd:events' } },
    3600,
  );
  assert.equal(await storage.putGrantMeta(grantId, consent), 'created');

  // 購読登録runtime（実物）。KMS・verification送出・Firestoreは合成（既存の購読runtime試験と同じ組立て）。
  const SUB_NS = `t268_${randomUUID()}`;
  const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
  const baseKms = { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: KEY, writeVersion: 1, readVersions: [1] };
  const policy = createKmsSubscriptionPolicy({ ...baseKms, namespace: SUB_NS });
  db.put(`sttdAuth/${SUB_NS}/config/kms-subscription`, kmsMarkerDocument(policy));
  const sent = [];
  const verificationSender = (request) => {
    sent.push(request);
    return Promise.resolve({ status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) });
  };
  const runtime = runtimeModule.createKmsSubscriptionRegistrationRuntime({
    db,
    connect: storage,
    connectNamespace: NAMESPACE,
    resource: RESOURCE,
    kms: { ...baseKms, namespace: SUB_NS, transport },
    hasher: connectHasher,
    clock: { now: () => clock.now() },
    verificationSender,
  });
  const op = () => ({ deadlineAt: clock.now() + 3_600_000, signal: new AbortController().signal });
  const url = `https://hooks.sttd-code.example/${randomBytes(6).toString('hex')}`;
  const secret = `whsec_${randomBytes(32).toString('base64')}`;
  const registered = await runtime.service.subscribe({ ownerId: admission.ownerId, grantId }, { name: 'text.submitted', url, secret, ttlMs: 60_000 }, op());
  assert.match(registered.id, /^sub_/);
  assert.equal(sent.length, 1, 'one signed verification challenge');
  const subscription = db.docs.get(`sttdAuth/${SUB_NS}/subscriptions/${admission.ownerId}`)?.data;
  assert.ok(subscription, 'subscription stored for the code owner');
  assert.equal(subscription.active.id, registered.id);
  assert.equal(subscription.active.grantId, grantId, 'bound to the consented Grant');
  assert.equal(JSON.stringify(subscription).includes(url), false, 'callback URL is sealed');

  // 別ownerのGrantを名乗る登録は拒否（ownerとGrantの束縛は実判定）。
  await assert.rejects(runtime.service.subscribe({ ownerId: randomUUID(), grantId }, { name: 'text.submitted', url, secret, ttlMs: 60_000 }, op()));

  // 同じ発行元の再発行: 利用許可の世代が変わり、旧Grantで新規登録・更新はできない（送出なし）。
  await store.issue({ claimSecret: consoleA, previousOperationId: issued.operationId });
  assert.equal(await storage.grantUsable(admission.ownerId, grantId), false);
  const url2 = `https://hooks.sttd-code.example/${randomBytes(6).toString('hex')}`;
  await assert.rejects(runtime.service.subscribe({ ownerId: admission.ownerId, grantId }, { name: 'text.submitted', url: url2, secret, ttlMs: 60_000 }, op()));
  assert.equal(sent.length, 1, 'no challenge for the old Grant');
  await runtime.close?.();
});

test('W1 deployment config: developerLogin absent/off is off, operator-code-v1 enables, unknown values are config errors', async () => {
  const fixture = await import('./fixtures/synthetic-deployment.mjs');
  const base = Object.values(fixture).find((value) => value !== null && typeof value === 'object' && value.configured === true);
  assert.ok(base, 'synthetic configured deployment');
  const { developerLogin: _ignored, ...withoutFlag } = base;
  assert.equal(validateDeploymentConfig(withoutFlag).developerLogin, 'off');
  assert.equal(validateDeploymentConfig({ ...withoutFlag, developerLogin: 'off' }).developerLogin, 'off');
  assert.equal(validateDeploymentConfig({ ...withoutFlag, developerLogin: DEVELOPER_LOGIN_MODE }).developerLogin, 'operator-code-v1');
  for (const bad of ['on', true, 1, null, { mode: 'on' }]) assert.throws(() => validateDeploymentConfig({ ...withoutFlag, developerLogin: bad }));
});

test('W2 late-bound lookup: unbound = off (custom refused), bound once to the deployment store, no rebinding', async () => {
  const { store, clock } = makeStore({ codes: [650] });
  const issued = await store.issue({ claimSecret: claim() });
  const outcome = await exchangeFor(store, fakeAuth(), clock).exchange({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  const tokens = new Map();
  const late = createLateCodeIdentityCheck();
  const verifier = createFirebaseAdminVerifier({ auth: fakeAdminVerify(tokens), projectId: PROJECT, codeIdentities: late });
  const id = idTokenFor(outcome.customToken, tokens);
  await assert.rejects(verifier.verifyIdToken(id.id), (e) => e.code === 'wrong_provider');
  assert.equal(await verifier.accountStatus(id.uid, 0), 'revoked');
  late.bind(createCodeIdentityLookup(store));
  assert.equal((await verifier.verifyIdToken(id.id)).method, 'developer_code');
  assert.throws(() => late.bind(createCodeIdentityLookup(makeStore().store)));
});

test('W3 two namespaces sharing one Firestore client do not see each other\'s codes or identities', async () => {
  const db = new FakeDb();
  const clock = clockAt();
  const secret = randomBytes(32);
  const keys = developerLoginKeys(secret);
  const storeFor = (namespace) =>
    new DeveloperLoginStore({ db, scope: { ...SCOPE, namespace }, hasher: keys.hasher, sealer: keys.sealer, clock, random: scriptedRandom([700, 700]) });
  const a = storeFor(NAMESPACE);
  const b = storeFor('t256_1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f');
  const issued = await a.issue({ claimSecret: claim() });
  // 同じ番号でも別namespaceでは別の予約（重複にならない）、相手のコードでは交換できない。
  const other = await b.issue({ claimSecret: claim() });
  assert.equal(other.code, issued.code);
  await a.consume({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  assert.equal((await b.consume({ code: '000701', interactionKey: 'i', sourceKey: 's' })).kind, 'rejected');
  assert.equal((await b.consume({ code: other.code, interactionKey: 'j', sourceKey: 't' })).kind, 'consumed');
});

test('F5 late committed activation after the exchange deadline is revoked by fail()', async () => {
  const { store, db } = makeStore({ codes: [95] });
  const issued = await store.issue({ claimSecret: claim() });
  const consumed = await store.consume({ code: issued.code, interactionKey: 'i', sourceKey: 's' });
  const accessIdentityHash = connectIdentityHash(connectHasher, NAMESPACE, { projectId: PROJECT, uid: consumed.uid });
  assert.equal((await store.activate({ operationIdHash: consumed.operationIdHash, issuanceId: consumed.issuanceId, uid: consumed.uid, accessIdentityHash })).kind, 'active');
  await store.fail({ operationIdHash: consumed.operationIdHash, issuanceId: consumed.issuanceId });
  const state = await store.identityState(store.identityHashOf(consumed.uid));
  assert.equal(state.state, 'revoked');
  const access = [...db.docs].find(([path]) => path.endsWith(`/${accessIdentityHash}`));
  assert.equal(access[1].data.state, 'disabled');
});
