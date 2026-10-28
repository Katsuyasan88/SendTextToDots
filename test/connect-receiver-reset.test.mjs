// 受信先設定一式のreset（プラグイン接続のApple login後に、本人が明示確認した時だけ）の保存層の回帰。
//   - R1: grantMetaの受信reset世代の形とhelperの純関数（parseKmsStateによる受信先設定の検査、版の精密検査）。
//   - R2: 同意画面の表示（Appleは常に隠しsnapshot、設定がある時だけ初期未選択・必須の確認欄と削除を含む許可の文言）と固定案内（日英）。
//   - R3: Apple・設定あり・確認あり → 1つのtransaction（maxAttempts 1）で消費・取消世代+1・受信reset世代+1・購読文書を空に。
//         account/identity/許可は不変。新しい同意の世代でgrantMeta。二重submitで2回目の削除0。
//   - R4: 削除0の境界（コード・login方法なし・設定なし・none→あり・未確認・表示後の変化・改変token・別のresetを跨いだ古い画面・期限切れ・CSRF・
//         許可の停止・ownerの失効/無活動・不正な世代・別ownerや未知の形の購読文書）。
//   - R5: 古い同意（resetの前に消費）のgrantMetaは、resetの後には作らない（現在の値で救済しない）。
// 合成のin-memory Firestore・HMAC・封緘portだけ。実SDK・Cloud・資格・network 0。UID・URL・secretは合成値で出力しない。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { grantGenerationOf, grantReceiverGenerationOf } from '../dist/access/policy.js';
import { AccessUnavailableError, ConnectStorage } from '../dist/connect/firestore.js';
import { renderInteractionConsent, renderReceiverResetOutcome } from '../dist/connect/pages.js';
import { createHmacHasher } from '../dist/secrets.js';
import { emptyKmsState, kmsStateDocument } from '../dist/storage/firestore/kms-subscription-format.js';
import { ownerReceiverGeneration, ReceiverResetUnavailableError, receiverResetWrites, receiverSettingsPresent } from '../dist/storage/firestore/receiver-reset.js';

const NS = `t256_${randomUUID()}`;
const AUTH_NS = `t268_${randomUUID()}`;
const PROJECT = 'sendtexttodots-test';
const DAY = 86_400_000;
const BASE = 1_900_000_000_000;
const WEB = { apiKey: 'synthetic-web-key', authDomain: 'synthetic.example.invalid', projectId: PROJECT };
// 受信先設定の検査は、activeが無い状態ではpolicyのcapsuleの照合を使わない（合成のpolicy）。
const POLICY = Object.freeze({});
const subId = (c) => `sub_${c.repeat(64)}`;

/** 合成Firestore（参照・snapshot・transaction・updateTime、transactionのoptionsを記録）。 */
function fakeDb() {
  const docs = new Map();
  let tick = 0;
  const control = { txOptions: [] };
  const stamp = () => {
    tick += 1;
    return { seconds: 1_900_000_000 + tick, nanoseconds: tick };
  };
  const snapshot = (path) => {
    const entry = docs.get(path);
    return { ref: refOf(path), exists: entry !== undefined, updateTime: entry?.updateTime, data: () => (entry === undefined ? undefined : structuredClone(entry.data)) };
  };
  const write = (path, data) => docs.set(path, { data: structuredClone(data), updateTime: stamp() });
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
    write,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    async runTransaction(fn, options) {
      control.txOptions.push(options);
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
  let now = BASE;
  const clock = { now: () => now };
  const subPath = (ownerId) => `sttdAuth/${AUTH_NS}/subscriptions/${ownerId}`;
  const storage = new ConnectStorage({
    db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY,
    receiverSubscriptions: { refFor: (ownerId) => db.doc(subPath(ownerId)), policy: POLICY },
  });
  const identityHash = (uid) => hasher.hash(`t256:${NS}:identity`, `${PROJECT}\0${uid}`);
  const accessPath = (uid) => `sttdConnect/${NS}/access/${identityHash(uid)}`;
  const setAccess = (uid, state, generation = randomUUID()) => {
    db.write(accessPath(uid), { version: 1, state, generation, updatedAt: BASE });
    return generation;
  };
  const metaPath = (grantId) => `sttdConnect/${NS}/grantMeta/${hasher.hash(`t256:${NS}:grant`, grantId)}`;
  const ownerPath = (ownerId) => `sttdConnect/${NS}/owners/${ownerId}`;
  const identity = (uid) => ({ projectId: PROJECT, uid, authTimeSec: Math.floor(BASE / 1000) });
  const data = (path) => (db.docs.has(path) ? structuredClone(db.docs.get(path).data) : undefined);
  // 受信先設定あり（既知の送信先だけ。parseKmsStateで正しい形）。
  const putSettings = (ownerId, known = subId('a')) => db.write(subPath(ownerId), kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: known }));
  /** 許可active・owner作成・interactionを開いてlogin済みにする（login方法を指定）。 */
  async function loggedIn(uid, method) {
    const interaction = `i-${randomUUID()}`;
    // 同じ本人の2回目のloginは、既存の許可の世代のまま（停止・再登録を跨がない）。
    const existing = data(accessPath(uid));
    const generation = existing?.state === 'active' ? existing.generation : setAccess(uid, 'active');
    const admission = await storage.resolveOwner(identity(uid));
    assert.equal(admission.kind, 'admitted');
    const opened = await storage.openInteraction(interaction);
    assert.equal(await storage.bindInteraction(interaction, opened.csrf, admission.ownerId, identity(uid).authTimeSec, generation, method), 'ok');
    return { interaction, csrf: opened.csrf, ownerId: admission.ownerId, generation, uid };
  }
  return { db, storage, setAccess, accessPath, metaPath, ownerPath, subPath, identity, data, putSettings, loggedIn, advance: (ms) => (now += ms) };
}

test('R1 grantMeta receiver generation shape and the pure helpers (canonical receiver-settings check)', () => {
  const ownerId = randomUUID();
  const meta = { ownerId, authTimeSec: 1, createdAt: BASE, accessGeneration: randomUUID() };
  assert.equal(grantGenerationOf(true, meta).kind, 'bound');
  assert.equal(grantGenerationOf(true, { ...meta, receiverGeneration: 1 }).kind, 'bound');
  for (const bad of [0, -1, 1.5, '1', null]) assert.equal(grantGenerationOf(true, { ...meta, receiverGeneration: bad }).kind, 'invalid', `receiverGeneration ${String(bad)}`);
  assert.equal(grantGenerationOf(true, { ownerId, authTimeSec: 1, createdAt: BASE, receiverGeneration: 1 }).kind, 'invalid', 'legacy shape cannot carry a receiver generation');
  assert.equal(grantReceiverGenerationOf(meta), 0);
  assert.equal(grantReceiverGenerationOf({ ...meta, receiverGeneration: 3 }), 3);
  assert.equal(grantReceiverGenerationOf({ ...meta, receiverGeneration: 0 }), null);
  assert.equal(ownerReceiverGeneration({}), 0);
  assert.equal(ownerReceiverGeneration({ receiverGeneration: 2 }), 2);
  for (const bad of [{ receiverGeneration: -1 }, { receiverGeneration: 1.5 }, { receiverGeneration: '1' }, null]) assert.throws(() => ownerReceiverGeneration(bad), ReceiverResetUnavailableError);
  const snap = (doc) => ({ exists: true, data: () => doc });
  assert.equal(receiverSettingsPresent({ exists: false, data: () => undefined }, ownerId, POLICY), false);
  assert.equal(receiverSettingsPresent(snap(kmsStateDocument(ownerId, emptyKmsState())), ownerId, POLICY), false);
  assert.equal(receiverSettingsPresent(snap(kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: subId('b') })), ownerId, POLICY), true);
  // 別owner・未知field・不正なid・版の違い・pendingの不整合は、一時障害（消さない）。
  const bad = [
    kmsStateDocument(randomUUID(), { ...emptyKmsState(), knownDestinationId: subId('b') }),
    { ...kmsStateDocument(ownerId, emptyKmsState()), extra: 1 },
    kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: 'sub_not_hex' }),
    { ...kmsStateDocument(ownerId, emptyKmsState()), version: 999 },
    kmsStateDocument(ownerId, { ...emptyKmsState(), pending: { id: subId('c'), grantId: 'g', requestedAt: BASE } }),
  ];
  for (const doc of bad) assert.throws(() => receiverSettingsPresent(snap(doc), ownerId, POLICY), ReceiverResetUnavailableError);
  const writes = receiverResetWrites(ownerId, { subscriptionGeneration: 4, receiverGeneration: 1 });
  assert.deepEqual(writes.ownerUpdate, { subscriptionGeneration: 5, receiverGeneration: 2 });
  assert.equal(writes.receiverGeneration, 2);
  assert.deepEqual(writes.subscriptionDoc, kmsStateDocument(ownerId, emptyKmsState()));
});

test('R2 consent page: hidden snapshot always for Apple; checkbox and deletion wording only when settings exist; fixed outcome pages (en/ja)', () => {
  const plain = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'en');
  assert.ok(!plain.includes('receiver') && plain.includes('Allow the connection to this Dots'));
  const none = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'en', { token: 'opaque-none', confirm: false });
  assert.ok(none.includes('name="receiverToken" value="opaque-none"') && !none.includes('type="checkbox"') && none.includes('Allow the connection to this Dots'));
  const offered = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'en', { token: 'opaque-token', confirm: true });
  assert.match(offered, /<input type="checkbox" id="sttd-receiver-reset" name="receiverReset" value="1" required>/);
  assert.ok(!/checked/.test(offered.match(/<input type="checkbox"[^>]*>/)[0]), 'initially unchecked');
  assert.ok(offered.includes('Delete the previous receiver settings and allow the connection') && !offered.includes('Allow the connection to this Dots'));
  assert.ok(offered.includes('deliveries already started are not cancelled'));
  const ja = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'ja', { token: 't', confirm: true, required: true });
  assert.ok(ja.includes('以前の受信先設定を削除して接続を許可') && ja.includes('何も削除していません'));
  assert.ok(renderReceiverResetOutcome(WEB, 'i-1', 'incomplete', 'en').includes('were deleted, but the connection was not completed'));
  assert.ok(renderReceiverResetOutcome(WEB, 'i-1', 'unknown', 'ja').includes('接続が完了したかを確認できませんでした'));
  assert.ok(renderReceiverResetOutcome(WEB, 'i-1', 'reset_unknown', 'en').includes('could not be confirmed whether the previous receiver settings were deleted'));
});

test('R3 Apple + settings + confirmation: one transaction (maxAttempts 1) consumes, raises both generations, empties only the receiver settings; grantMeta binds the new generation; second submit deletes nothing', async () => {
  const fx = fixture();
  const s = await fx.loggedIn(`apple-${randomUUID()}`, 'apple');
  fx.putSettings(s.ownerId);
  const keep = () => ({
    identity: [...fx.db.docs.keys()].filter((p) => p.includes('/identities/')).map((p) => JSON.stringify(fx.data(p))),
    access: JSON.stringify(fx.data(fx.accessPath(s.uid))),
    ownerUid: fx.data(fx.ownerPath(s.ownerId)).sealedUid,
  });
  const before = keep();
  const snapshot = await fx.storage.receiverSnapshot(s.interaction);
  assert.equal(snapshot.present, true);
  const consent = await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, snapshot.token, true);
  assert.equal(fx.db.control.txOptions.at(-1)?.maxAttempts, 1, 'no automatic retry of the destructive transaction');
  assert.equal(consent.receiverReset, true);
  assert.equal(consent.receiverGeneration, 1);
  assert.deepEqual(fx.data(fx.subPath(s.ownerId)), kmsStateDocument(s.ownerId, emptyKmsState()));
  const owner = fx.data(fx.ownerPath(s.ownerId));
  assert.deepEqual([owner.receiverGeneration, owner.subscriptionGeneration], [1, 1]);
  assert.deepEqual(keep(), before, 'account/identity/permit kept');
  assert.equal(await fx.storage.putGrantMeta('grant-new', consent), 'created');
  assert.equal(fx.data(fx.metaPath('grant-new')).receiverGeneration, 1);
  const version = fx.db.docs.get(fx.subPath(s.ownerId)).updateTime;
  assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, snapshot.token, true), undefined, 'second submit');
  assert.equal(fx.db.docs.get(fx.subPath(s.ownerId)).updateTime, version);
  assert.equal(fx.data(fx.ownerPath(s.ownerId)).receiverGeneration, 1);
  const again = await fx.loggedIn(s.uid, 'apple');
  assert.equal((await fx.storage.receiverSnapshot(again.interaction)).present, false, 'nothing left to delete');
});

test('R4 nothing is deleted at any boundary (and nothing is consumed where a new confirmation is needed)', async () => {
  const fx = fixture();
  const same = (ownerId, snap) => assert.deepEqual(fx.data(fx.subPath(ownerId)), snap);
  const open = (s) => fx.storage.interactionAccepts(s.interaction, s.csrf);
  // コード・login方法なし: snapshotなし。偽造の確認でも通常の同意だけ（削除0）。
  for (const method of ['developer_code', undefined]) {
    const s = await fx.loggedIn(`m-${randomUUID()}`, method);
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    assert.equal(await fx.storage.receiverSnapshot(s.interaction), null);
    const consent = await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, 'forged', true);
    assert.equal(consent.receiverReset, undefined);
    same(s.ownerId, snap);
  }
  // 設定なし→表示の後に設定ができた（none→あり）: 確認の有無に関わらず'changed'、消費・削除0。
  {
    const s = await fx.loggedIn(`none-${randomUUID()}`, 'apple');
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    assert.equal(shown.present, false);
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, false), 'changed');
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, true), 'changed');
    same(s.ownerId, snap);
    assert.ok(await open(s), 'not consumed');
  }
  // 設定あり・未確認: 'confirm_required'、消費・削除0。改変token・空token: 'changed'。
  {
    const s = await fx.loggedIn(`unc-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, false), 'confirm_required');
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, `${shown.token}x`, true), 'changed');
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, '', true), 'changed');
    same(s.ownerId, snap);
    assert.ok(await open(s));
  }
  // 別のresetを跨いだ古い画面: 同じownerの別のinteractionでresetが確定した後、古い画面の確認は'changed'（2回目の削除0）。
  {
    const uid = `two-${randomUUID()}`;
    const a = await fx.loggedIn(uid, 'apple');
    fx.putSettings(a.ownerId);
    const shownA = await fx.storage.receiverSnapshot(a.interaction);
    const b = await fx.loggedIn(uid, 'apple');
    const shownB = await fx.storage.receiverSnapshot(b.interaction);
    assert.equal((await fx.storage.consumeInteractionChecked(b.interaction, b.csrf, shownB.token, true)).receiverReset, true);
    fx.putSettings(a.ownerId, subId('d'));
    const snap = fx.data(fx.subPath(a.ownerId));
    assert.equal(await fx.storage.consumeInteractionChecked(a.interaction, a.csrf, shownA.token, true), 'changed');
    same(a.ownerId, snap);
    assert.equal(fx.data(fx.ownerPath(a.ownerId)).receiverGeneration, 1);
  }
  // CSRFの不一致・期限切れ（表示の後）: undefined、削除0。
  {
    const s = await fx.loggedIn(`exp-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, 'wrong-csrf', shown.token, true), undefined);
    fx.advance(300_001);
    assert.equal(await fx.storage.receiverSnapshot(s.interaction), null);
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, true), undefined);
    same(s.ownerId, snap);
  }
  // 許可の停止（表示の後）: 'denied'、削除0。ownerの失効・無活動（表示の後）: undefined、削除0・世代の変化0。
  {
    const s = await fx.loggedIn(`stop-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    fx.setAccess(s.uid, 'disabled');
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, true), 'denied');
    same(s.ownerId, snap);
  }
  for (const change of [(owner) => ({ ...owner, revokedAt: BASE }), (owner) => ({ ...owner, lastActiveAt: BASE - 91 * DAY })]) {
    const s = await fx.loggedIn(`own-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    fx.db.write(fx.ownerPath(s.ownerId), change(fx.data(fx.ownerPath(s.ownerId))));
    assert.equal(await fx.storage.consumeInteractionChecked(s.interaction, s.csrf, shown.token, true), undefined);
    assert.equal(await fx.storage.receiverSnapshot(s.interaction), null);
    same(s.ownerId, snap);
    assert.equal(fx.data(fx.ownerPath(s.ownerId)).receiverGeneration, undefined);
  }
  // 不正な受信reset世代・別ownerの購読文書: 一時障害（推測で消さない）。
  {
    const s = await fx.loggedIn(`bad-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    fx.db.write(fx.ownerPath(s.ownerId), { ...fx.data(fx.ownerPath(s.ownerId)), receiverGeneration: -1 });
    await assert.rejects(fx.storage.receiverSnapshot(s.interaction), (error) => error instanceof AccessUnavailableError);
    const t = await fx.loggedIn(`other-${randomUUID()}`, 'apple');
    fx.db.write(fx.subPath(t.ownerId), kmsStateDocument(randomUUID(), { ...emptyKmsState(), knownDestinationId: subId('e') }));
    const snap = fx.data(fx.subPath(t.ownerId));
    await assert.rejects(fx.storage.receiverSnapshot(t.interaction), (error) => error instanceof AccessUnavailableError);
    await assert.rejects(fx.storage.consumeInteractionChecked(t.interaction, t.csrf, 'x', true), (error) => error instanceof AccessUnavailableError);
    same(t.ownerId, snap);
  }
});

test('R5 an older consent is not upgraded: consumed before another reset, its grantMeta is refused after it', async () => {
  const fx = fixture();
  const uid = `late-${randomUUID()}`;
  const first = await fx.loggedIn(uid, 'apple');
  const shown = await fx.storage.receiverSnapshot(first.interaction);
  const late = await fx.storage.consumeInteractionChecked(first.interaction, first.csrf, shown.token, false);
  assert.equal(late.receiverGeneration ?? 0, 0, 'generation 0 is the absent field (unchanged consent shape)');
  fx.putSettings(first.ownerId);
  const second = await fx.loggedIn(uid, 'apple');
  const shown2 = await fx.storage.receiverSnapshot(second.interaction);
  const fresh = await fx.storage.consumeInteractionChecked(second.interaction, second.csrf, shown2.token, true);
  assert.equal(fresh.receiverGeneration, 1);
  assert.equal(await fx.storage.putGrantMeta('grant-late', late), 'denied');
  assert.equal(fx.data(fx.metaPath('grant-late')), undefined);
  assert.equal(await fx.storage.putGrantMeta('grant-fresh', fresh), 'created');
  assert.equal(await fx.storage.putGrantMeta('grant-old-shape', { ownerId: late.ownerId, authTimeSec: late.authTimeSec, accessGeneration: late.accessGeneration }), 'denied');
});
