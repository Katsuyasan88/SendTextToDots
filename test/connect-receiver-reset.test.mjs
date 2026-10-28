// 受信先設定一式のreset（プラグイン接続のApple login後に、本人が明示確認した時だけ）の回帰。
//   - R1: grantMetaの受信reset世代の形（欠落=0、1以上の整数だけ、不正は形の不正）とhelperの純関数。
//   - R2: 同意画面の表示（確認欄は初期未選択・必須、許可の文言に削除を含む）と、削除後の失敗の固定案内（日英）。
//   - R3: Apple・設定あり・確認あり → 1つのtransactionで消費・取消世代+1・受信reset世代+1・購読文書を空に。account/identity/許可は不変。
//         新しい同意の世代でgrantMetaを作る。二重submitで2回目の削除0。
//   - R4: 削除0の境界（コード・login方法なし・設定なし・none→あり・表示後の変化・改変token・期限切れ・CSRF・許可の停止・不正な世代）。
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

/** 合成Firestore（access-policy.test.mjsと同じ形: 参照・snapshot・transaction・updateTime）。 */
function fakeDb() {
  const docs = new Map();
  let tick = 0;
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
    write,
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
  let now = BASE;
  const clock = { now: () => now };
  const subPath = (ownerId) => `sttdAuth/${AUTH_NS}/subscriptions/${ownerId}`;
  const storage = new ConnectStorage({
    db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY,
    receiverSubscriptions: (ownerId) => db.doc(subPath(ownerId)),
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
  // 受信先設定あり（既知の送信先だけ。中身は合成）。
  const putSettings = (ownerId, known = `sub_${'a'.repeat(43)}`) => db.write(subPath(ownerId), kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: known }));
  /** 許可active・owner作成・interactionを開いてlogin済みにする（login方法を指定）。 */
  async function loggedIn(uid, method, interaction = `i-${randomUUID()}`) {
    const generation = setAccess(uid, 'active');
    const admission = await storage.resolveOwner(identity(uid));
    assert.equal(admission.kind, 'admitted');
    const opened = await storage.openInteraction(interaction);
    assert.equal(await storage.bindInteraction(interaction, opened.csrf, admission.ownerId, identity(uid).authTimeSec, generation, method), 'ok');
    return { interaction, csrf: opened.csrf, ownerId: admission.ownerId, generation };
  }
  return { db, storage, setAccess, accessPath, metaPath, ownerPath, subPath, identity, data, putSettings, loggedIn, advance: (ms) => (now += ms), hasher };
}

test('R1 grantMeta receiver generation shape and the pure helpers', () => {
  const ownerId = randomUUID();
  const meta = { ownerId, authTimeSec: 1, createdAt: BASE, accessGeneration: randomUUID() };
  assert.equal(grantGenerationOf(true, meta).kind, 'bound');
  assert.equal(grantGenerationOf(true, { ...meta, receiverGeneration: 1 }).kind, 'bound');
  for (const bad of [0, -1, 1.5, '1', null]) assert.equal(grantGenerationOf(true, { ...meta, receiverGeneration: bad }).kind, 'invalid', `receiverGeneration ${String(bad)}`);
  const legacy = { ownerId, authTimeSec: 1, createdAt: BASE };
  assert.equal(grantGenerationOf(true, { ...legacy, receiverGeneration: 1 }).kind, 'invalid', 'legacy shape cannot carry a receiver generation');
  assert.equal(grantReceiverGenerationOf(meta), 0);
  assert.equal(grantReceiverGenerationOf({ ...meta, receiverGeneration: 3 }), 3);
  assert.equal(grantReceiverGenerationOf({ ...meta, receiverGeneration: 0 }), null);
  assert.equal(ownerReceiverGeneration({}), 0);
  assert.equal(ownerReceiverGeneration({ receiverGeneration: 2 }), 2);
  for (const bad of [{ receiverGeneration: -1 }, { receiverGeneration: 1.5 }, { receiverGeneration: '1' }, null]) assert.throws(() => ownerReceiverGeneration(bad), ReceiverResetUnavailableError);
  const empty = { exists: true, data: () => kmsStateDocument(ownerId, emptyKmsState()) };
  assert.equal(receiverSettingsPresent({ exists: false, data: () => undefined }, ownerId), false);
  assert.equal(receiverSettingsPresent(empty, ownerId), false);
  assert.equal(receiverSettingsPresent({ exists: true, data: () => kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: `sub_${'b'.repeat(43)}` }) }, ownerId), true);
  assert.throws(() => receiverSettingsPresent({ exists: true, data: () => ({ version: 999 }) }, ownerId), ReceiverResetUnavailableError);
  const writes = receiverResetWrites(ownerId, { subscriptionGeneration: 4, receiverGeneration: 1 });
  assert.deepEqual(writes.ownerUpdate, { subscriptionGeneration: 5, receiverGeneration: 2 });
  assert.equal(writes.receiverGeneration, 2);
  assert.deepEqual(writes.subscriptionDoc, kmsStateDocument(ownerId, emptyKmsState()));
});

test('R2 consent page: unchecked required checkbox and deletion stated on the allow button only when offered; fixed outcome pages (en/ja)', () => {
  const plain = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'en');
  assert.ok(!plain.includes('receiverReset') && plain.includes('Allow the connection to this Dots'));
  const offered = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'en', { token: 'opaque-token' });
  assert.match(offered, /<input type="checkbox" id="sttd-receiver-reset" name="receiverReset" value="1" required>/);
  assert.ok(!/checked/.test(offered.match(/<input type="checkbox"[^>]*>/)[0]), 'initially unchecked');
  assert.ok(offered.includes('name="receiverToken" value="opaque-token"'));
  assert.ok(offered.includes('Delete the previous receiver settings and allow the connection'));
  assert.ok(!offered.includes('Allow the connection to this Dots'));
  const ja = renderInteractionConsent(WEB, 'i-1', 'Client', 'csrf-1', 'ja', { token: 't', required: true });
  assert.ok(ja.includes('以前の受信先設定を削除して接続を許可') && ja.includes('何も削除していません'));
  assert.ok(renderReceiverResetOutcome(WEB, 'i-1', 'incomplete', 'en').includes('were deleted, but the connection was not completed'));
  assert.ok(renderReceiverResetOutcome(WEB, 'i-1', 'unknown', 'ja').includes('接続が完了したかを確認できませんでした'));
});

test('R3 Apple + settings + confirmation: one transaction consumes, raises both generations and empties the receiver settings only; grantMeta binds the new generation; second submit deletes nothing', async () => {
  const fx = fixture();
  const uid = `apple-${randomUUID()}`;
  const s = await fx.loggedIn(uid, 'apple');
  fx.putSettings(s.ownerId);
  const before = { identity: [...fx.db.docs.keys()].filter((p) => p.includes('/identities/')).map((p) => JSON.stringify(fx.data(p))), access: JSON.stringify(fx.data(fx.accessPath(uid))), ownerUid: fx.data(fx.ownerPath(s.ownerId)).sealedUid };
  const offer = await fx.storage.receiverResetOffer(s.interaction);
  assert.ok(offer !== null && typeof offer.token === 'string' && offer.token.length > 0);
  const consent = await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, offer.token);
  assert.equal(consent.receiverReset, true);
  assert.equal(consent.receiverGeneration, 1);
  assert.deepEqual(fx.data(fx.subPath(s.ownerId)), kmsStateDocument(s.ownerId, emptyKmsState()), 'receiver settings emptied');
  const owner = fx.data(fx.ownerPath(s.ownerId));
  assert.equal(owner.receiverGeneration, 1);
  assert.equal(owner.subscriptionGeneration, 1);
  assert.equal(owner.sealedUid, before.ownerUid, 'owner/account kept');
  assert.equal(JSON.stringify(fx.data(fx.accessPath(uid))), before.access, 'permit kept');
  assert.deepEqual([...fx.db.docs.keys()].filter((p) => p.includes('/identities/')).map((p) => JSON.stringify(fx.data(p))), before.identity, 'identity kept');
  assert.equal(await fx.storage.putGrantMeta('grant-new', consent), 'created');
  const meta = fx.data(fx.metaPath('grant-new'));
  assert.equal(meta.receiverGeneration, 1);
  assert.equal(grantGenerationOf(true, meta).kind, 'bound');
  // 二重submit: 消費済みなので2回目は何もしない（削除・世代の変化0）。
  const versionBefore = fx.db.docs.get(fx.subPath(s.ownerId)).updateTime;
  assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, offer.token), undefined);
  assert.equal(fx.db.docs.get(fx.subPath(s.ownerId)).updateTime, versionBefore);
  assert.equal(fx.data(fx.ownerPath(s.ownerId)).receiverGeneration, 1);
  // 再接続では削除対象が無いので、確認は出ない。
  const again = await fx.loggedIn(uid, 'apple');
  assert.equal(await fx.storage.receiverResetOffer(again.interaction), null);
});

test('R4 nothing is deleted: code login, no method, no settings, none->settings, changed after display, tampered token, expired, wrong CSRF, stopped permit, malformed generation', async () => {
  const fx = fixture();
  const unchanged = (ownerId, snapshot) => assert.deepEqual(fx.data(fx.subPath(ownerId)), snapshot);
  // コード（検証済みのmethod）: 確認0・削除0。確認欄を偽造しても通常の同意だけ。
  {
    const s = await fx.loggedIn(`code-${randomUUID()}`, 'developer_code');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    assert.equal(await fx.storage.receiverResetOffer(s.interaction), null);
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, 'forged'), 'not_applicable');
    unchanged(s.ownerId, snap);
    assert.ok(await fx.storage.interactionAccepts(s.interaction, s.csrf), 'not consumed');
  }
  // login方法が無い（旧版のbind）: 確認0・削除0。
  {
    const s = await fx.loggedIn(`old-${randomUUID()}`, undefined);
    fx.putSettings(s.ownerId);
    assert.equal(await fx.storage.receiverResetOffer(s.interaction), null);
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, 'x'), 'not_applicable');
  }
  // 設定なし（新規owner）: 確認0。表示の後に設定ができた（none→あり）: 消費・削除0で'changed'。
  {
    const s = await fx.loggedIn(`new-${randomUUID()}`, 'apple');
    assert.equal(await fx.storage.receiverResetOffer(s.interaction), null);
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, ''), 'changed');
    unchanged(s.ownerId, snap);
    assert.ok(await fx.storage.interactionAccepts(s.interaction, s.csrf), 'not consumed');
  }
  // 表示の後に設定が変わった・改変token: 'changed'、消費・削除0。
  {
    const s = await fx.loggedIn(`chg-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const offer = await fx.storage.receiverResetOffer(s.interaction);
    fx.putSettings(s.ownerId, `sub_${'c'.repeat(43)}`);
    const snap = fx.data(fx.subPath(s.ownerId));
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, offer.token), 'changed');
    const fresh = await fx.storage.receiverResetOffer(s.interaction);
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, `${fresh.token}x`), 'changed');
    unchanged(s.ownerId, snap);
    assert.equal(fx.data(fx.ownerPath(s.ownerId)).receiverGeneration, undefined);
  }
  // CSRFの不一致・期限切れ: undefined、削除0。
  {
    const s = await fx.loggedIn(`exp-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const offer = await fx.storage.receiverResetOffer(s.interaction);
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, 'wrong-csrf', offer.token), undefined);
    fx.advance(300_001);
    assert.equal(await fx.storage.receiverResetOffer(s.interaction), null);
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, offer.token), undefined);
    unchanged(s.ownerId, snap);
  }
  // 許可の停止（表示の後）: 'denied'、interactionは閉じるが削除0。
  {
    const uid = `stop-${randomUUID()}`;
    const s = await fx.loggedIn(uid, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    const offer = await fx.storage.receiverResetOffer(s.interaction);
    fx.setAccess(uid, 'disabled');
    assert.equal(await fx.storage.consumeInteractionWithReceiverReset(s.interaction, s.csrf, offer.token), 'denied');
    unchanged(s.ownerId, snap);
    assert.equal(fx.data(fx.ownerPath(s.ownerId)).receiverGeneration, undefined);
  }
  // owner文書の受信reset世代が不正: 一時障害（推測で消さない）。
  {
    const s = await fx.loggedIn(`bad-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const snap = fx.data(fx.subPath(s.ownerId));
    fx.db.write(fx.ownerPath(s.ownerId), { ...fx.data(fx.ownerPath(s.ownerId)), receiverGeneration: -1 });
    await assert.rejects(fx.storage.receiverResetOffer(s.interaction), (error) => error instanceof AccessUnavailableError);
    unchanged(s.ownerId, snap);
  }
});

test('R5 an older consent is not upgraded: consumed before another reset, its grantMeta is refused after it', async () => {
  const fx = fixture();
  const uid = `late-${randomUUID()}`;
  // 1つ目: 設定なしで通常の同意（世代0を捕捉）。metadataの保存は遅れる。
  const first = await fx.loggedIn(uid, 'apple');
  const late = await fx.storage.consumeInteraction(first.interaction, first.csrf);
  assert.equal(late.receiverGeneration ?? 0, 0, 'generation 0 is the absent field (unchanged consent shape)');
  // 2つ目: 設定ができ、本人がresetを確認（世代1）。
  fx.putSettings(first.ownerId);
  const second = await fx.loggedIn(uid, 'apple');
  const offer = await fx.storage.receiverResetOffer(second.interaction);
  const fresh = await fx.storage.consumeInteractionWithReceiverReset(second.interaction, second.csrf, offer.token);
  assert.equal(fresh.receiverGeneration, 1);
  // 遅れた古い同意は、現在の世代で救済されない。新しい同意は作れる。
  assert.equal(await fx.storage.putGrantMeta('grant-late', late), 'denied');
  assert.equal(fx.data(fx.metaPath('grant-late')), undefined);
  assert.equal(await fx.storage.putGrantMeta('grant-fresh', fresh), 'created');
  // 世代の欠落した同意（旧版の呼出し）も0として扱い、救済しない。
  assert.equal(await fx.storage.putGrantMeta('grant-old-shape', { ownerId: late.ownerId, authTimeSec: late.authTimeSec, accessGeneration: late.accessGeneration }), 'denied');
});
