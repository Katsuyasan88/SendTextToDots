// 利用許可（明示登録した利用者だけ）の判定と、接続保存（ConnectStorage）のlogin・同意・Grant metadata・code/refresh・接続表示の境界。
//   - P1: 許可recordのexact schema・判定（欠落/disabled=拒否、不正/未知版=一時障害、active=世代）、Grant同意記録の世代、遷移。
//   - P2: 配置設定の必須accessPolicy（欠落・未知値は設定error、配布placeholderは従来どおりunconfigured）。
//   - P3: login（resolveOwner）: 未許可はowner・identityを作らない、不正recordは一時障害で無書込み、許可は世代を返す。
//   - P4: login→同意の間の停止・再登録・metadata保存前の停止は同意/Grant metadataを作らない。旧版interactionは使えない。
//   - P5: code交換・refresh（grantUsable）: 同世代だけ可、旧形式/別世代/停止/別ownerは不成立、不正・DB障害は一時障害（区別する）。
//   - P6: 接続表示（accessDisplay）はallowed/denied/unavailableで、読めなくても例外を出さない。
// 合成のin-memory Firestore・HMAC・封緘portだけ。実SDK・Cloud・資格・network 0。UIDは合成値で出力しない。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import {
  ACCESS_RECORD_VERSION,
  accessVerdictOf,
  grantGenerationOf,
  grantUseVerdict,
  nextAccessRecord,
  parseAccessRecord,
} from '../dist/access/policy.js';
import { AccessUnavailableError, ConnectStorage } from '../dist/connect/firestore.js';
import { DeploymentConfigError, validateDeploymentConfig } from '../dist/config/validate.js';
import { createHmacHasher } from '../dist/secrets.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { DEPLOYMENT_CONFIG as UNCONFIGURED } from './fixtures/unconfigured-deployment.mjs';

const NS = `t256_${randomUUID()}`;
const PROJECT = 'sendtexttodots-test';
const DAY = 86_400_000;
const BASE = 1_900_000_000_000;

/** 合成Firestore（参照・snapshot・transaction・updateTime）。failで読取りの障害を合成する。 */
function fakeDb() {
  const docs = new Map();
  let tick = 0;
  const control = { failReads: false, writes: 0 };
  const stamp = () => {
    tick += 1;
    const time = { seconds: 1_900_000_000 + tick, nanoseconds: tick };
    return { ...time, isEqual: (other) => other.seconds === time.seconds && other.nanoseconds === time.nanoseconds };
  };
  const snapshot = (path) => {
    if (control.failReads) throw new Error('synthetic read failure');
    const entry = docs.get(path);
    return { ref: refOf(path), exists: entry !== undefined, updateTime: entry?.updateTime, data: () => (entry === undefined ? undefined : structuredClone(entry.data)), get: (field) => entry?.data[field] };
  };
  const write = (path, data) => {
    control.writes += 1;
    docs.set(path, { data: structuredClone(data), updateTime: stamp() });
  };
  const collectionOf = (path) => ({ doc: (id) => refOf(`${path}/${id}`) });
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      get: async () => snapshot(path),
      set: async (data) => write(path, data),
      create: async (data) => {
        if (docs.has(path)) throw new Error('ALREADY_EXISTS');
        write(path, data);
      },
      update: async (partial) => {
        if (!docs.has(path)) throw new Error('NOT_FOUND');
        write(path, { ...docs.get(path).data, ...partial });
      },
      delete: async () => void docs.delete(path),
    };
  }
  const db = {
    docs,
    control,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    async runTransaction(fn) {
      const pending = [];
      const tx = {
        get: async (ref) => snapshot(ref.path),
        getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
        set: (ref, data) => void pending.push(() => write(ref.path, data)),
        create: (ref, data) =>
          void pending.push(() => {
            if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
            write(ref.path, data);
          }),
        update: (ref, partial) =>
          void pending.push(() => {
            if (!docs.has(ref.path)) throw new Error('NOT_FOUND');
            write(ref.path, { ...docs.get(ref.path).data, ...partial });
          }),
      };
      const result = await fn(tx);
      for (const apply of pending) apply();
      return result;
    },
  };
  return db;
}

function fixture() {
  const db = fakeDb();
  const hasher = createHmacHasher(randomBytes(32));
  const box = { seal: (purpose, plaintext) => `sealed:${Buffer.from(plaintext).toString('base64url')}`, open: (purpose, sealed) => Buffer.from(sealed.slice(7), 'base64url').toString() };
  const clock = { now: () => BASE };
  const storage = new ConnectStorage({ db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
  const identityHash = (uid) => hasher.hash(`t256:${NS}:identity`, `${PROJECT}\0${uid}`);
  const accessPath = (uid) => `sttdConnect/${NS}/access/${identityHash(uid)}`;
  const setAccess = (uid, state, generation = randomUUID()) => {
    db.docs.set(accessPath(uid), { data: { version: 1, state, generation, updatedAt: BASE }, updateTime: { seconds: 1, nanoseconds: 1 } });
    return generation;
  };
  const metaPath = (grantId) => `sttdConnect/${NS}/grantMeta/${hasher.hash(`t256:${NS}:grant`, grantId)}`;
  const identity = (uid) => ({ projectId: PROJECT, uid, authTimeSec: Math.floor(BASE / 1000) });
  const paths = (prefix) => [...db.docs.keys()].filter((path) => path.startsWith(`sttdConnect/${NS}/${prefix}/`));
  return { db, storage, setAccess, accessPath, metaPath, identity, paths };
}

/** 合成interactionを開いてCSRFを返す。 */
async function openInteraction(fx, uid) {
  const opened = await fx.storage.openInteraction(uid);
  return opened.csrf;
}

test('P1 access record schema and verdicts, Grant consent generation, transitions', () => {
  const generation = randomUUID();
  const good = { version: ACCESS_RECORD_VERSION, state: 'active', generation, updatedAt: BASE };
  assert.deepEqual(parseAccessRecord(good), good);
  assert.deepEqual(accessVerdictOf(true, good), { kind: 'allowed', generation });
  assert.deepEqual(accessVerdictOf(true, { ...good, state: 'disabled' }), { kind: 'denied' });
  assert.deepEqual(accessVerdictOf(false, undefined), { kind: 'denied' });
  const invalid = [
    { ...good, version: 2 },
    { ...good, state: 'paused' },
    { ...good, generation: generation.toUpperCase() },
    { ...good, generation: 'not-a-uuid' },
    { ...good, updatedAt: -1 },
    { ...good, updatedAt: 1.5 },
    { ...good, extra: true },
    { version: 1, state: 'active', generation },
    null,
    [],
    'active',
  ];
  for (const value of invalid) assert.deepEqual(accessVerdictOf(true, value), { kind: 'unavailable' }, JSON.stringify(value));
  const withGetter = Object.defineProperty({ ...good }, 'state', { get: () => 'active', enumerable: true });
  assert.deepEqual(accessVerdictOf(true, withGetter), { kind: 'unavailable' }, 'accessor is not read');

  const owner = randomUUID();
  const meta = { ownerId: owner, authTimeSec: 1, createdAt: BASE, accessGeneration: generation };
  assert.deepEqual(grantGenerationOf(true, meta), { kind: 'bound', ownerId: owner, generation });
  assert.deepEqual(grantGenerationOf(false, undefined), { kind: 'missing' });
  assert.deepEqual(grantGenerationOf(true, { ownerId: owner, authTimeSec: 1, createdAt: BASE }), { kind: 'legacy' });
  assert.deepEqual(grantGenerationOf(true, { ...meta, accessGeneration: 7 }), { kind: 'invalid' });
  assert.deepEqual(grantGenerationOf(true, { ...meta, ownerId: 5 }), { kind: 'invalid' });

  const allowed = accessVerdictOf(true, good);
  const verdict = (access, grant, ownerId = owner) => grantUseVerdict(access, grant, ownerId).kind;
  assert.equal(verdict(allowed, grantGenerationOf(true, meta)), 'allowed');
  assert.equal(verdict(allowed, grantGenerationOf(true, { ...meta, accessGeneration: randomUUID() })), 'denied', 'old generation');
  assert.equal(verdict(allowed, grantGenerationOf(true, meta), randomUUID()), 'denied', 'other owner');
  assert.equal(verdict(allowed, { kind: 'legacy' }), 'denied', 'pre-migration Grant');
  assert.equal(verdict(allowed, { kind: 'missing' }), 'denied', 'no metadata');
  assert.equal(verdict(allowed, { kind: 'invalid' }), 'unavailable');
  assert.equal(verdict({ kind: 'denied' }, grantGenerationOf(true, meta)), 'denied');
  assert.equal(verdict({ kind: 'unavailable' }, grantGenerationOf(true, meta)), 'unavailable');

  // 遷移: 不存在→active（新世代）、同じ状態は書込みなし、active→disabled→activeは毎回新世代、不存在の停止は書込みなし。
  const g1 = randomUUID();
  const first = nextAccessRecord(null, 'active', BASE, g1);
  assert.deepEqual(first, { version: 1, state: 'active', generation: g1, updatedAt: BASE });
  assert.equal(nextAccessRecord(first, 'active', BASE + 1, randomUUID()), null);
  const stopped = nextAccessRecord(first, 'disabled', BASE + 1, randomUUID());
  assert.notEqual(stopped.generation, g1);
  const again = nextAccessRecord(stopped, 'active', BASE + 2, randomUUID());
  assert.ok(again.generation !== g1 && again.generation !== stopped.generation);
  assert.equal(nextAccessRecord(null, 'disabled', BASE, randomUUID()), null);
  assert.throws(() => nextAccessRecord(first, 'disabled', BASE, g1), 'the same generation is never reused');
});

test('P2 accessPolicy is required and fixed; the distributed placeholder stays unconfigured', () => {
  const code = (value) => {
    try {
      validateDeploymentConfig(value);
      return 'ok';
    } catch (error) {
      return error instanceof DeploymentConfigError ? error.code : 'unexpected';
    }
  };
  assert.equal(code(structuredClone(SYNTHETIC)), 'ok');
  assert.equal(validateDeploymentConfig(structuredClone(SYNTHETIC)).accessPolicy, 'explicit-allow-v1');
  const missing = structuredClone(SYNTHETIC);
  delete missing.accessPolicy;
  for (const value of [missing, { ...structuredClone(SYNTHETIC), accessPolicy: 'allow-all' }, { ...structuredClone(SYNTHETIC), accessPolicy: 'EXPLICIT-ALLOW-V1' }, { ...structuredClone(SYNTHETIC), accessPolicy: null }]) {
    assert.equal(code(value), 'deployment_config_invalid');
  }
  assert.equal(code(structuredClone(UNCONFIGURED)), 'deployment_config_unconfigured');
  assert.equal(code({ ...structuredClone(UNCONFIGURED), accessPolicy: 'explicit-allow-v1' }), 'deployment_config_unconfigured');
});

test('P3 login: a missing/disabled record creates no owner or identity; an invalid record or DB failure is temporary with no writes; an active record returns its generation', async () => {
  const fx = fixture();
  assert.deepEqual(await fx.storage.resolveOwner(fx.identity('uid-missing')), { kind: 'denied' });
  fx.setAccess('uid-off', 'disabled');
  assert.deepEqual(await fx.storage.resolveOwner(fx.identity('uid-off')), { kind: 'denied' });
  assert.deepEqual([fx.paths('owners').length, fx.paths('identities').length], [0, 0], 'no owner/identity for a refused login');

  fx.db.docs.set(fx.accessPath('uid-bad'), { data: { version: 9, state: 'active', generation: randomUUID(), updatedAt: BASE }, updateTime: { seconds: 1, nanoseconds: 1 } });
  const writes = fx.db.control.writes;
  await assert.rejects(fx.storage.resolveOwner(fx.identity('uid-bad')), (error) => error instanceof AccessUnavailableError);
  fx.db.control.failReads = true;
  await assert.rejects(fx.storage.resolveOwner(fx.identity('uid-bad')));
  fx.db.control.failReads = false;
  assert.equal(fx.db.control.writes, writes, 'no write on a temporary failure');

  const generation = fx.setAccess('uid-a', 'active');
  const admitted = await fx.storage.resolveOwner(fx.identity('uid-a'));
  assert.equal(admitted.kind, 'admitted');
  assert.equal(admitted.accessGeneration, generation);
  assert.deepEqual(await fx.storage.resolveOwner(fx.identity('uid-a')), admitted, 'same owner on the next login');
  // 既存ownerでも停止後のloginは拒否（owner自体は失効させない）。
  fx.setAccess('uid-a', 'disabled');
  assert.deepEqual(await fx.storage.resolveOwner(fx.identity('uid-a')), { kind: 'denied' });
  assert.equal(await fx.storage.isOwnerActive(admitted.ownerId), true, 'the stop is independent from owner revocation');
});

test('P4 consent: a stop between login and bind/consent or before the Grant metadata creates nothing usable; a re-enable is a new generation; an old-format interaction is not usable', async () => {
  const fx = fixture();
  const g1 = fx.setAccess('uid-c', 'active');
  const { ownerId } = await fx.storage.resolveOwner(fx.identity('uid-c'));
  const auth = Math.floor(BASE / 1000);

  // 正常: bind（世代を束縛）→ consume → metadata（同じ世代）。
  let csrf = await openInteraction(fx, 'i-ok');
  assert.equal(await fx.storage.bindInteraction('i-ok', csrf, ownerId, auth, g1), 'ok');
  const consent = await fx.storage.consumeInteraction('i-ok', csrf);
  assert.deepEqual(consent, { ownerId, authTimeSec: auth, accessGeneration: g1 });
  assert.equal(await fx.storage.putGrantMeta('grant-ok', consent), 'created');
  assert.equal(fx.db.docs.get(fx.metaPath('grant-ok')).data.accessGeneration, g1);

  // loginの後・bindの前に停止 → denied（世代を束縛しない）。
  fx.setAccess('uid-c', 'disabled');
  csrf = await openInteraction(fx, 'i-stop');
  assert.equal(await fx.storage.bindInteraction('i-stop', csrf, ownerId, auth, g1), 'denied');
  // 再有効化（新世代）でも、旧世代のloginは束縛できない。
  const g2 = fx.setAccess('uid-c', 'active');
  assert.equal(await fx.storage.bindInteraction('i-stop', csrf, ownerId, auth, g1), 'denied');

  // bindの後・同意の前に停止→再登録 → 同意はinteractionを閉じてdenied（Grantを作る前）。
  csrf = await openInteraction(fx, 'i-mid');
  assert.equal(await fx.storage.bindInteraction('i-mid', csrf, ownerId, auth, g2), 'ok');
  fx.setAccess('uid-c', 'disabled');
  fx.setAccess('uid-c', 'active');
  assert.equal(await fx.storage.consumeInteraction('i-mid', csrf), 'denied');
  assert.equal(await fx.storage.consumeInteraction('i-mid', csrf), undefined, 'closed: no second attempt');

  // 同意の後・metadataの保存前に停止 → metadataを作らない。
  const g3 = fx.setAccess('uid-c', 'active');
  csrf = await openInteraction(fx, 'i-late');
  assert.equal(await fx.storage.bindInteraction('i-late', csrf, ownerId, auth, g3), 'ok');
  const late = await fx.storage.consumeInteraction('i-late', csrf);
  fx.setAccess('uid-c', 'disabled');
  assert.equal(await fx.storage.putGrantMeta('grant-late', late), 'denied');
  assert.equal(fx.db.docs.has(fx.metaPath('grant-late')), false);

  // 不正な許可recordは一時障害（同意記録・metadataを作らない）。
  fx.db.docs.set(fx.accessPath('uid-c'), { data: { broken: true }, updateTime: { seconds: 2, nanoseconds: 2 } });
  await assert.rejects(fx.storage.putGrantMeta('grant-bad', late), (error) => error instanceof AccessUnavailableError);
  assert.equal(fx.db.docs.has(fx.metaPath('grant-bad')), false);

  // この版より前に束縛した（世代を持たない）interactionは同意に使えない。
  const g4 = fx.setAccess('uid-c', 'active');
  csrf = await openInteraction(fx, 'i-old');
  assert.equal(await fx.storage.bindInteraction('i-old', csrf, ownerId, auth, g4), 'ok');
  const path = [...fx.db.docs.keys()].find((key) => key.includes('/interactions/') && fx.db.docs.get(key).data.state === 'authenticated');
  const { accessGeneration, ...old } = fx.db.docs.get(path).data;
  assert.equal(accessGeneration, g4);
  fx.db.docs.set(path, { data: old, updateTime: { seconds: 3, nanoseconds: 3 } });
  assert.equal(await fx.storage.consumeInteraction('i-old', csrf), undefined);
});

test('P5 code exchange / refresh eligibility: same generation only; legacy, other generation, stop and other owner are refusals; invalid record or DB failure is a distinct temporary error', async () => {
  const fx = fixture();
  const g1 = fx.setAccess('uid-r', 'active');
  const { ownerId } = await fx.storage.resolveOwner(fx.identity('uid-r'));
  const meta = (grantId, extra = {}) => fx.db.docs.set(fx.metaPath(grantId), { data: { ownerId, authTimeSec: 1, createdAt: BASE, accessGeneration: g1, ...extra }, updateTime: { seconds: 4, nanoseconds: 4 } });
  meta('grant-1');
  assert.equal(await fx.storage.grantUsable(ownerId, 'grant-1'), true);
  meta('grant-legacy', { accessGeneration: undefined });
  const legacy = fx.db.docs.get(fx.metaPath('grant-legacy'));
  delete legacy.data.accessGeneration;
  assert.equal(await fx.storage.grantUsable(ownerId, 'grant-legacy'), false, 'pre-migration Grant');
  assert.equal(await fx.storage.grantUsable(ownerId, 'grant-none'), false, 'no metadata');
  // 別の許可済みownerが同じGrantを使うことはできない（同意記録のownerが違う）。
  fx.setAccess('uid-other', 'active');
  const other = await fx.storage.resolveOwner(fx.identity('uid-other'));
  assert.equal(await fx.storage.grantUsable(other.ownerId, 'grant-1'), false, 'other owner');
  // ownerの文書自体が無い（identityHashへ辿れない）ものは許可にしない（一時障害。呼出し元はowner有効性を先に確かめる）。
  await assert.rejects(fx.storage.grantUsable(randomUUID(), 'grant-1'), (error) => error instanceof AccessUnavailableError);
  fx.setAccess('uid-r', 'disabled');
  assert.equal(await fx.storage.grantUsable(ownerId, 'grant-1'), false, 'stopped');
  fx.setAccess('uid-r', 'active');
  assert.equal(await fx.storage.grantUsable(ownerId, 'grant-1'), false, 're-enabled: the old refresh does not come back');
  fx.db.docs.set(fx.accessPath('uid-r'), { data: { version: 1, state: 'active' }, updateTime: { seconds: 5, nanoseconds: 5 } });
  await assert.rejects(fx.storage.grantUsable(ownerId, 'grant-1'), (error) => error instanceof AccessUnavailableError);
  meta('grant-bad', { accessGeneration: 'x' });
  fx.setAccess('uid-r', 'active');
  await assert.rejects(fx.storage.grantUsable(ownerId, 'grant-bad'), (error) => error instanceof AccessUnavailableError);
  fx.db.control.failReads = true;
  await assert.rejects(fx.storage.grantUsable(ownerId, 'grant-1'));
  fx.db.control.failReads = false;
});

test('P6 connection display: allowed / denied / unavailable, never throws and never returns identifiers', async () => {
  const fx = fixture();
  assert.equal(await fx.storage.accessDisplay(fx.identity('uid-none')), 'denied');
  fx.setAccess('uid-d', 'active');
  assert.equal(await fx.storage.accessDisplay(fx.identity('uid-d')), 'allowed');
  fx.setAccess('uid-d', 'disabled');
  assert.equal(await fx.storage.accessDisplay(fx.identity('uid-d')), 'denied');
  fx.db.docs.set(fx.accessPath('uid-d'), { data: { version: 1 }, updateTime: { seconds: 6, nanoseconds: 6 } });
  assert.equal(await fx.storage.accessDisplay(fx.identity('uid-d')), 'unavailable');
  fx.db.control.failReads = true;
  assert.equal(await fx.storage.accessDisplay(fx.identity('uid-d')), 'unavailable');
  fx.db.control.failReads = false;
});
