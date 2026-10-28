// 同意（POST）の手順（runConsent）を、実際の保存層（ConnectStorage・合成のin-memory Firestore）と合成のGrant・redirect portで通す回帰。
//   - 新規（設定なし）・Appleの設定あり・確認あり・未確認・改変token・コードと偽造の確認・none→ありの競合・別のresetを跨いだ古い画面。
//   - ownerの失効・期限切れ・CSRF不一致は削除0。
//   - 削除の後の失敗は段階で固定の結果（Grant保存/grantMeta→incomplete、redirect（応答前）→unknown、応答の後→none）。確認付きの消費の例外→reset_unknown。
//   - 削除は購読文書1件だけ（identity・許可・暗号化の鍵・履歴の番兵は不変）。固定のログeventだけ。
// 合成値だけ。実SDK・Cloud・資格・network 0。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';

import { ConnectStorage } from '../dist/connect/firestore.js';
import { runConsent } from '../dist/connect/interaction-consent.js';
import { createHmacHasher } from '../dist/secrets.js';
import { emptyKmsState, kmsStateDocument } from '../dist/storage/firestore/kms-subscription-format.js';

const NS = `t256_${randomUUID()}`;
const AUTH_NS = `t268_${randomUUID()}`;
const PROJECT = 'sendtexttodots-test';
const DAY = 86_400_000;
const BASE = 1_900_000_000_000;

/** 合成Firestore。transactionのoptionsと、削除・置換（購読文書の書込み）の回数を記録し、transactionの失敗を注入できる。 */
function fakeDb() {
  const docs = new Map();
  let tick = 0;
  const control = { txOptions: [], failNextTx: false, writes: [] };
  const write = (path, data) => {
    tick += 1;
    docs.set(path, { data: structuredClone(data), updateTime: { seconds: 1_900_000_000 + tick, nanoseconds: tick } });
  };
  const snapshot = (path) => {
    const entry = docs.get(path);
    return { ref: refOf(path), exists: entry !== undefined, updateTime: entry?.updateTime, data: () => (entry === undefined ? undefined : structuredClone(entry.data)) };
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
    write,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    async runTransaction(fn, options) {
      control.txOptions.push(options);
      const pending = [];
      const tx = {
        get: async (ref) => snapshot(ref.path),
        getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
        set: (ref, data) => void pending.push(() => (control.writes.push(ref.path), write(ref.path, data))),
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
      if (control.failNextTx) {
        // commitの結果が不明（書込みは反映しない）。
        control.failNextTx = false;
        throw new Error('synthetic commit failure');
      }
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
  const subPath = (ownerId) => `sttdAuth/${AUTH_NS}/subscriptions/${ownerId}`;
  const storage = new ConnectStorage({
    db, namespace: NS, hasher, box, clock: { now: () => now }, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY,
    receiverSubscriptions: { refFor: (ownerId) => db.doc(subPath(ownerId)), policy: Object.freeze({}) },
  });
  const identityHash = (uid) => hasher.hash(`t256:${NS}:identity`, `${PROJECT}\0${uid}`);
  const accessPath = (uid) => `sttdConnect/${NS}/access/${identityHash(uid)}`;
  const ownerPath = (ownerId) => `sttdConnect/${NS}/owners/${ownerId}`;
  const data = (path) => (db.docs.has(path) ? structuredClone(db.docs.get(path).data) : undefined);
  const putSettings = (ownerId, c = 'a') => db.write(subPath(ownerId), kmsStateDocument(ownerId, { ...emptyKmsState(), knownDestinationId: `sub_${c.repeat(64)}` }));
  // 無関係な番兵（暗号化の鍵・配送履歴・別ownerの購読文書）。削除・変更されないことを見る。
  const sentinels = [`sttdAuth/${AUTH_NS}/encryptionKeys/sentinel`, `sttdAuth/${AUTH_NS}/deliveries/sentinel`, subPath('other-owner')];
  for (const path of sentinels) db.write(path, { sentinel: path.length });
  async function loggedIn(uid, method) {
    const interaction = `i-${randomUUID()}`;
    const existing = data(accessPath(uid));
    const generation = existing?.state === 'active' ? existing.generation : randomUUID();
    if (existing?.state !== 'active') db.write(accessPath(uid), { version: 1, state: 'active', generation, updatedAt: BASE });
    const identity = { projectId: PROJECT, uid, authTimeSec: Math.floor(BASE / 1000) };
    const admission = await storage.resolveOwner(identity);
    assert.equal(admission.kind, 'admitted');
    const opened = await storage.openInteraction(interaction);
    assert.equal(await storage.bindInteraction(interaction, opened.csrf, admission.ownerId, identity.authTimeSec, generation, method), 'ok');
    return { interaction, csrf: opened.csrf, ownerId: admission.ownerId, uid };
  }
  /** 実際の保存層と合成のGrant・redirect portでrunConsentを行う。 */
  async function submit(s, { csrf = s.csrf, token, confirm, saveGrant, putGrantMeta, finish, headersSent = () => false } = {}) {
    const logs = [];
    const grants = [];
    const result = await runConsent(
      {
        consume: (input) => storage.consumeInteractionChecked(s.interaction, input.csrf, input.token, input.confirm),
        isOwnerActive: (ownerId) => storage.isOwnerActive(ownerId),
        saveGrant: saveGrant ?? (async (ownerId) => (grants.push(ownerId), `grant-${randomUUID()}`)),
        putGrantMeta: putGrantMeta ?? ((grantId, consent) => storage.putGrantMeta(grantId, consent)),
        finish: finish ?? (async () => {}),
        headersSent,
        log: (entry) => logs.push({ ...entry }),
      },
      { csrf, token: token ?? '', confirm: confirm ?? false },
    );
    return { result, logs, grants };
  }
  const snapshotOf = (ownerId) => ({ sub: data(subPath(ownerId)), owner: data(ownerPath(ownerId)), sentinels: sentinels.map(data), access: [...db.docs.keys()].filter((p) => p.includes('/access/')).map(data) });
  const subWrites = (ownerId) => db.control.writes.filter((p) => p === subPath(ownerId)).length;
  return { db, storage, data, subPath, ownerPath, putSettings, loggedIn, submit, snapshotOf, subWrites, advance: (ms) => (now += ms) };
}

const events = (logs) => logs.map((l) => (l.category === undefined ? l.event : `${l.event}:${l.category}`));

test('Apple + settings + confirmation: one delete, finished, only the receiver settings change; fixed events', async () => {
  const fx = fixture();
  const s = await fx.loggedIn(`a-${randomUUID()}`, 'apple');
  fx.putSettings(s.ownerId);
  const before = fx.snapshotOf(s.ownerId);
  const shown = await fx.storage.receiverSnapshot(s.interaction);
  const { result, logs } = await fx.submit(s, { token: shown.token, confirm: true });
  assert.deepEqual(result, { kind: 'finished' });
  assert.deepEqual(events(logs), ['interaction.receiver_reset', 'interaction.consented']);
  assert.equal(fx.subWrites(s.ownerId), 1);
  assert.equal(fx.db.control.txOptions.filter((o) => o?.maxAttempts === 1).length, 1);
  const after = fx.snapshotOf(s.ownerId);
  assert.deepEqual(after.sub, kmsStateDocument(s.ownerId, emptyKmsState()));
  assert.deepEqual([after.sentinels, after.access], [before.sentinels, before.access], 'unrelated keys, history and permit unchanged');
  // 二重submit: 削除0（リンク無効）。
  assert.deepEqual((await fx.submit(s, { token: shown.token, confirm: true })).result, { kind: 'link_unavailable' });
  assert.equal(fx.subWrites(s.ownerId), 1);
});

test('new owner without settings: hidden snapshot, normal consent, nothing deleted; none→present after display reshows', async () => {
  const fx = fixture();
  const s = await fx.loggedIn(`n-${randomUUID()}`, 'apple');
  const shown = await fx.storage.receiverSnapshot(s.interaction);
  assert.equal(shown.present, false);
  const ok = await fx.submit(s, { token: shown.token });
  assert.deepEqual([ok.result, events(ok.logs)], [{ kind: 'finished' }, ['interaction.consented']]);
  assert.equal(fx.subWrites(s.ownerId), 0);
  const t = await fx.loggedIn(`r-${randomUUID()}`, 'apple');
  const shownT = await fx.storage.receiverSnapshot(t.interaction);
  fx.putSettings(t.ownerId);
  for (const confirm of [false, true]) assert.deepEqual((await fx.submit(t, { token: shownT.token, confirm })).result, { kind: 'reshow' });
  assert.equal(fx.subWrites(t.ownerId), 0);
  assert.ok(await fx.storage.interactionAccepts(t.interaction, t.csrf), 'not consumed');
});

test('unchecked, forged token, code login with forged confirmation, stale page across another reset: no extra delete', async () => {
  const fx = fixture();
  const s = await fx.loggedIn(`u-${randomUUID()}`, 'apple');
  fx.putSettings(s.ownerId);
  const shown = await fx.storage.receiverSnapshot(s.interaction);
  assert.deepEqual((await fx.submit(s, { token: shown.token, confirm: false })).result, { kind: 'reshow' });
  assert.deepEqual((await fx.submit(s, { token: 'forged', confirm: true })).result, { kind: 'reshow' });
  assert.equal(fx.subWrites(s.ownerId), 0);
  const c = await fx.loggedIn(`c-${randomUUID()}`, 'developer_code');
  fx.putSettings(c.ownerId);
  const before = fx.snapshotOf(c.ownerId);
  const code = await fx.submit(c, { token: 'forged', confirm: true });
  assert.deepEqual([code.result, events(code.logs)], [{ kind: 'finished' }, ['interaction.consented']]);
  assert.deepEqual(fx.snapshotOf(c.ownerId).sub, before.sub);
  // 同じ本人の2つの画面: 片方でresetした後、古い画面の確認は再表示（2回目の削除0）。
  const b = await fx.loggedIn(s.uid, 'apple');
  const shownB = await fx.storage.receiverSnapshot(b.interaction);
  assert.deepEqual((await fx.submit(b, { token: shownB.token, confirm: true })).result, { kind: 'finished' });
  fx.putSettings(s.ownerId, 'b');
  assert.deepEqual((await fx.submit(s, { token: shown.token, confirm: true })).result, { kind: 'reshow' });
  assert.equal(fx.subWrites(s.ownerId), 1);
});

test('owner revoked, expiry and wrong CSRF after display: link unavailable, nothing deleted', async () => {
  const fx = fixture();
  const cases = [
    (s) => fx.db.write(fx.ownerPath(s.ownerId), { ...fx.data(fx.ownerPath(s.ownerId)), revokedAt: BASE }),
    () => fx.advance(300_001),
    () => {},
  ];
  for (const [index, change] of cases.entries()) {
    const s = await fx.loggedIn(`x-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    const shown = await fx.storage.receiverSnapshot(s.interaction);
    change(s);
    const before = fx.snapshotOf(s.ownerId);
    const { result, logs } = await fx.submit(s, { token: shown.token, confirm: true, csrf: index === 2 ? 'wrong-csrf' : s.csrf });
    assert.deepEqual([result, logs], [{ kind: 'link_unavailable' }, []]);
    assert.deepEqual(fx.snapshotOf(s.ownerId), before);
    assert.equal(fx.subWrites(s.ownerId), 0);
  }
});

test('failures after the reset are reported by stage; a failed confirmed consume is not declared either way', async () => {
  const fx = fixture();
  const ready = async () => {
    const s = await fx.loggedIn(`f-${randomUUID()}`, 'apple');
    fx.putSettings(s.ownerId);
    return { s, token: (await fx.storage.receiverSnapshot(s.interaction)).token };
  };
  const boom = async () => {
    throw new Error('synthetic failure');
  };
  const outcome = (kind) => ({ kind: 'receiver_reset', outcome: kind });
  {
    const { s, token } = await ready();
    const r = await fx.submit(s, { token, confirm: true, saveGrant: boom });
    assert.deepEqual([r.result, events(r.logs)], [outcome('incomplete'), ['interaction.receiver_reset', 'interaction.receiver_reset_incomplete:incomplete']]);
    assert.equal(fx.subWrites(s.ownerId), 1);
  }
  {
    const { s, token } = await ready();
    const r = await fx.submit(s, { token, confirm: true, putGrantMeta: async () => 'denied' });
    assert.deepEqual(r.result, outcome('incomplete'));
  }
  {
    const { s, token } = await ready();
    const r = await fx.submit(s, { token, confirm: true, finish: boom });
    assert.deepEqual([r.result, events(r.logs).at(-1)], [outcome('unknown'), 'interaction.receiver_reset_incomplete:unknown']);
  }
  {
    const { s, token } = await ready();
    const r = await fx.submit(s, { token, confirm: true, finish: boom, headersSent: () => true });
    assert.deepEqual(r.result, { kind: 'none' }, 'no second response');
  }
  {
    const { s, token } = await ready();
    fx.db.control.failNextTx = true;
    const r = await fx.submit(s, { token, confirm: true });
    assert.deepEqual([r.result, events(r.logs)], [outcome('reset_unknown'), ['interaction.receiver_reset_incomplete:reset_unknown']]);
    assert.equal(fx.subWrites(s.ownerId), 0, 'the failed commit wrote nothing');
    assert.ok(await fx.storage.interactionAccepts(s.interaction, s.csrf));
  }
  // 確認の無い同意の失敗は従来どおり（例外はそのまま）。
  {
    const s = await fx.loggedIn(`p-${randomUUID()}`, 'apple');
    const token = (await fx.storage.receiverSnapshot(s.interaction)).token;
    await assert.rejects(fx.submit(s, { token, saveGrant: boom }), /synthetic failure/);
  }
});
