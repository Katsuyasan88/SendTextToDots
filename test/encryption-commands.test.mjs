// 暗号文の送信（POST /v2/encrypted-commands）。送信APIの実HTTP入口→実の暗号文endpoint（encryption/commands.js）→実の鍵store/service
// （in-memoryのFirestore代替・合成Secret source）→実のKMS配送service（KmsRequestDeliveryService.postValidated）→既存の純粋な判定
// （delivery/contract.jsのdecidePrepare/decideDispatch/decideFinish/decideAbandon/decideCancel）をRAMのMapに載せた合成配送store・合成codec・合成send。
// 合成配送storeのdispatchは、実storeと同じく渡されたkeyCheckを同じ「transaction」（鍵側のin-memory DBの読取り）で呼んでから判定する。
// これはFirestoreのtransaction・実KMS・実署名送出・実Dotsの確認ではない（実storeのtransaction内の配線は型と静的確認、実環境はT075/T076）。
// 試験clientの暗号化はNode組込みcryptoで、server helperの再利用ではないが、独立vectorの確認はT075。
//   E01 6入力（日本語・絵文字・改行/空白・4096byte・制御文字最大・混在）/E02 9改ざん/E03 他UID・他環境の2/E04 期限/E05 wire内の形の上限/
//   E06 header重複・未知・base64url不正の3/E07 復号rate/E08 Secret障害と平文成功/E09 plain→encrypted/E10 encrypted→plain/E11 再暗号化/
//   E12 内容差/E13 取消tombstone/E14 結果不明/E15 dispatch直前失効/E16 非保存・固定ログ・buffer清掃/E17 元20秒/E18 wire超過の消費0。計34。
// PM是正の追加（4 scenario/8入力）:
//   S01 実のKmsRequestDeliveryStore（合成DB/txへ接続）で、送出権のtransactionが同じtxで鍵ringを読む（valid／鍵の読取り中に猶予が切れる）。
//   S02 Secretの待機中に猶予が切れると、本文を開く前に409（準備0）。
//   S03 ringの最終利用は今回の配送成功だけで更新（成功／tag不正／送出失敗の3入力。重複の既存結果でも延ばさない）。
//   S04 CEK・PKCS8・本文/未認証本文のBufferの0埋め（成功／tag失敗の2入力。Buffer.prototype.fillを観測し、欠ければ失敗）。
//   S05 署名eventの送出上限（MAX_SIGNED_EVENT_BYTES）: 実のbuildEventBytesで制御文字4096byteのeventを作り（envelope 512以内）、実の
//       createCommandDeliveryAttempt→createSafeEgressから試験用CA・所有loopback TLS受信機へ1回送り、本文とStandard Webhooks署名が一致する／
//       上限+1は送出前に拒否（attemptとsafe-egressの両方、受信0）。合成CA・127.0.0.1だけで、実Dots・外部callbackは0。
// node:testのtest数とscenario数は一致しない。

import assert from 'node:assert/strict';
import { constants, createCipheriv, createHmac, createPublicKey, publicEncrypt, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import {
  commandDocData,
  decideAbandon,
  decideCancel,
  decideDispatch,
  decideFinish,
  decidePrepare,
  ownerControlData,
  parseCommandDoc,
  parseOwnerControl,
  usable,
} from '../dist/delivery/contract.js';
import { KmsRequestDeliveryService } from '../dist/delivery/kms-service.js';
import { Webhook } from 'standardwebhooks';

import { createCommandDeliveryAttempt } from '../dist/commands/delivery-attempt.js';
import { buildEventBytes, eventIdFor } from '../dist/delivery/event.js';
import { KmsRequestDeliveryStore } from '../dist/delivery/kms-store.js';
import { createSafeEgress } from '../dist/egress/safe-egress.js';
import { MAX_SIGNED_EVENT_BYTES } from '../dist/policy.js';
import { CALLBACK_HOST, createTlsFixture, fixtureConnector, startReceiver } from './egress-helpers.mjs';
import { createEncryptedCommandEndpoint } from '../dist/encryption/commands.js';
import { unwrapPrivateKey } from '../dist/encryption/crypto.js';
import { KMS_CAPSULE_PREFIX } from '../dist/protection/kms-sealing.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument, kmsStateDocument, kmsVersionName } from '../dist/storage/firestore/kms-subscription-format.js';
import { createEncryptionSecretProvider } from '../dist/encryption/secret-provider.js';
import { EncryptionKeyService } from '../dist/encryption/service.js';
import { EncryptionKeyStore } from '../dist/encryption/store.js';
import { createHmacHasher } from '../dist/secrets.js';

const BASE = 1_900_000_000_000;
const iso = (ms) => new Date(ms).toISOString();

// ---- 鍵側のin-memory Firestore代替 ----
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
    return new Snapshot(this.id, this.db.docs.get(this.path));
  }
}
class FakeDb {
  docs = new Map();
  transactions = 0;
  collection(name) {
    return { doc: (id) => new Ref(this, `${name}/${id}`) };
  }
  async runTransaction(fn) {
    this.transactions += 1;
    const writes = [];
    const tx = {
      get: async (ref) => new Snapshot(ref.id, this.docs.get(ref.path)),
      set: (ref, data) => writes.push(['set', ref.path, structuredClone(data)]),
      create: (ref, data) => writes.push(['create', ref.path, structuredClone(data)]),
      update: (ref, data) => writes.push(['update', ref.path, structuredClone(data)]),
    };
    const result = await fn(tx);
    for (const [kind, path, data] of writes) this.docs.set(path, kind === 'update' ? { ...this.docs.get(path), ...data } : data);
    return result;
  }
}

const servers = [];
after(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

function world() {
  const clock = { t: BASE, now() { return this.t; } };
  const db = new FakeDb();
  const hashKey = randomBytes(32);
  const hasher = createHmacHasher(randomBytes(32));
  const hash = (purpose, value) => createHmac('sha256', hashKey).update(purpose).update('\0').update(value).digest('hex');
  const environment = {
    projectId: 'synthetic-project',
    projectNumber: '123456',
    databaseId: '(default)',
    connectNamespace: `t256_${randomUUID()}`,
    deliveryNamespace: `t270_${randomUUID()}`,
    encryptionNamespace: `t280_${randomUUID()}`,
  };
  const secretValue = randomBytes(32).toString('base64url');
  const secret = { reads: 0, fail: false };
  const SECRET = 'projects/123456/secrets/synthetic-payload-protection';
  const source = {
    async read() {
      secret.reads += 1;
      if (secret.fail) throw new Error('synthetic secret failure SECRET-DETAIL');
      return Buffer.from(secretValue, 'latin1');
    },
  };
  const policy = { secret: SECRET, writeSecretVersion: 1, readSecretVersions: [1] };
  const secrets = createEncryptionSecretProvider(source, policy);
  const keyStore = new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: 1, clock });
  const keys = new EncryptionKeyService({ environment, store: keyStore, secrets, hasher, clock });

  // ---- 合成の配送store（既存の純粋な判定） ----
  const docs = new Map();
  const controls = new Map();
  const owners = new Map();
  const calls = { prepare: 0, dispatch: 0, keyChecks: 0, sent: [], owned: [], logs: [] };
  const control = { afterOpen: null, sendResult: null };
  const viewOf = (ownerId) => {
    const owner = owners.get(ownerId);
    if (owner === undefined) return { ownerActive: false, subscription: undefined, grantLive: false, access: 'denied' };
    const active = { id: `sub_${hash('subscription', ownerId)}`, ownerId, grantId: `grant-${ownerId}`, sealedUrl: 'capsule-url', sealedSecret: 'capsule-secret', secretHash: 'c'.repeat(64), previousSecret: null, expiresAt: null };
    return { ownerActive: true, grantLive: true, access: 'allowed', subscription: { active, knownDestinationId: active.id, pending: null, lastEnded: null } };
  };
  const load = (ownerId, commandKey) => parseCommandDoc(docs.has(commandKey) ? structuredClone(docs.get(commandKey)) : undefined, ownerId);
  const save = (commandKey, doc) => docs.set(commandKey, structuredClone(commandDocData(doc)));
  const release = (ownerId, commandKey) => {
    const current = parseOwnerControl(controls.get(ownerId), ownerId);
    if (current.current?.commandKey === commandKey) controls.set(ownerId, structuredClone(ownerControlData(ownerId, current.rate, null)));
  };
  const store = {
    commandKey: (ownerId, commandId) => hash('command', `${ownerId}\0${commandId}`),
    async prepare(request) {
      calls.prepare += 1;
      const now = clock.now();
      const decision = decidePrepare(usable(load(request.ownerId, request.commandKey), now), parseOwnerControl(controls.get(request.ownerId), request.ownerId), viewOf(request.ownerId), request, now);
      if (decision.kind !== 'prepared') return decision;
      save(request.commandKey, decision.doc);
      controls.set(request.ownerId, structuredClone(decision.control));
      return { kind: 'prepared', doc: decision.doc, sealedUrl: decision.sealedUrl, sealedSecret: decision.sealedSecret, previous: null };
    },
    async dispatch(ownerId, commandKey, attemptId, evidence, operation, keyCheck) {
      calls.dispatch += 1;
      const now = clock.now();
      let view = viewOf(ownerId);
      if (keyCheck !== undefined) {
        calls.keyChecks += 1;
        // 実storeと同じ順序: 同じ「transaction」の読取りで鍵の最新状態を見てから判定する。
        if (!(await keyCheck({ get: (ref) => ref.get() }, now))) view = { ...view, access: 'denied' };
      }
      const decision = decideDispatch(load(ownerId, commandKey), view, attemptId, null, now);
      if (decision.kind !== 'unchanged') save(commandKey, decision.doc);
      if (decision.kind === 'refused') release(ownerId, commandKey);
      if (decision.kind !== 'granted') return decision;
      return { kind: 'granted', doc: decision.doc, previousValid: false };
    },
    async finish(ownerId, commandKey, attemptId, state, reason) {
      const next = decideFinish(load(ownerId, commandKey), attemptId, state, reason, clock.now());
      if (next === undefined) return load(ownerId, commandKey);
      save(commandKey, next);
      release(ownerId, commandKey);
      return next;
    },
    async abandon(ownerId, commandKey, attemptId, reason) {
      const next = decideAbandon(load(ownerId, commandKey), attemptId, reason, clock.now());
      if (next === undefined) return load(ownerId, commandKey);
      save(commandKey, next);
      release(ownerId, commandKey);
      return next;
    },
    async read(ownerId, commandKey) {
      return usable(load(ownerId, commandKey), clock.now());
    },
    async cancel(ownerId, commandKey) {
      const now = clock.now();
      const decision = decideCancel(usable(load(ownerId, commandKey), now), ownerId, now);
      if (decision.kind === 'observed') return decision;
      save(commandKey, decision.doc);
      if (decision.kind === 'cancelled') release(ownerId, commandKey);
      return decision;
    },
  };
  const codec = {
    async open(binding) {
      return Buffer.from(binding.purpose === 'callback-url' ? 'https://receiver.example/hook' : `whsec_${randomBytes(32).toString('base64')}`, 'utf8');
    },
  };
  let attempts = 0;
  const lifetime = new AbortController();
  const log = (entry) => calls.logs.push(entry);
  const service = new KmsRequestDeliveryService({
    store,
    codec,
    hash,
    digestKey: randomBytes(32),
    send: async (request) => {
      calls.sent.push({ eventBytes: Buffer.from(request.eventBytes) });
      if (control.sendResult === 'throw') throw new Error('socket reset');
      return { kind: 'delivered', reason: 'acknowledged', stopSubscription: false };
    },
    clock,
    newAttemptId: () => `attempt-${(attempts += 1)}`,
    log,
    budgetMs: 20_000,
    lifetime: lifetime.signal,
    hooks: {
      afterOpen: async () => {
        const run = control.afterOpen;
        control.afterOpen = null;
        if (run) await run();
      },
      onOwned: (buffer) => calls.owned.push(buffer),
    },
  });
  const endpoint = createEncryptedCommandEndpoint({ environment, store: keyStore, secrets, hasher, clock, delivery: service });

  // ---- 本人（接続保存の対応・owner・許可）とHTTP ----
  const tokens = new Map();
  const ownerOfUid = new Map();
  const identity = {
    projectId: environment.projectId,
    calls: 0,
    async verifyIdToken(token) {
      identity.calls += 1;
      const uid = tokens.get(token);
      if (uid === undefined) throw new Error('bad token');
      return { projectId: environment.projectId, uid, authTimeSec: Math.floor(BASE / 1000) };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const connect = `sttdConnect/${environment.connectNamespace}`;
  const enroll = (uid) => {
    const identityHash = connectIdentityHash(hasher, environment.connectNamespace, { projectId: environment.projectId, uid });
    const ownerId = randomUUID();
    db.docs.set(`${connect}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: BASE });
    db.docs.set(`${connect}/identities/${identityHash}`, { ownerId, createdAt: BASE });
    db.docs.set(`${connect}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: BASE, lastActiveAt: BASE, revokedAt: null });
    owners.set(ownerId, {});
    ownerOfUid.set(uid, ownerId);
    const token = `tok.${randomBytes(12).toString('base64url')}.sig`;
    tokens.set(token, uid);
    return { uid, token, ownerId };
  };
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async (verified) => ownerOfUid.get(verified.uid),
    service,
    clock,
    log,
    lifetime: lifetime.signal,
    ingress: () => ({ receivedAt: clock.t, deadlineAt: clock.t + 20_000, signal: new AbortController().signal }),
    encryptedCommands: endpoint,
  });
  const publicKeyOf = async (user) => {
    const got = await keys.getOrInitialize({ projectId: environment.projectId, uid: user.uid }, { deadlineAt: clock.t + 20_000, signal: new AbortController().signal });
    assert.equal(got.kind, 'ok');
    return got.key;
  };
  const ringPath = () => [...db.docs.keys()].find((path) => path.includes('/rings/'));
  const controlsPaths = () => [...db.docs.keys()].filter((path) => path.includes('/controls/'));
  return { clock, db, environment, secret, secretValue, calls, control, docs, handler, enroll, publicKeyOf, ringPath, controlsPaths, identity, store, endpoint };
}

async function serve(handler) {
  const server = createServer((req, res) => void handler(req, res));
  servers.push(server);
  await new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  return server.address().port;
}
function request(port, method, path, { token, headers = [], body = '' } = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const lines = [`${method} ${path} HTTP/1.1`, 'Host: 127.0.0.1', ...(token ? [`Authorization: Bearer ${token}`] : []), ...headers.map(([k, v]) => `${k}: ${v}`), 'Connection: close'];
  if (payload.length > 0 || method === 'POST') lines.push(`Content-Length: ${payload.length}`);
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => {
      const all = Buffer.concat(chunks).toString('utf8');
      const split = all.indexOf('\r\n\r\n');
      let json = null;
      try {
        json = JSON.parse(all.slice(split + 4));
      } catch {
        json = null;
      }
      const head = all.slice(0, split).split('\r\n');
      const headers = Object.fromEntries(head.slice(1).map((line) => [line.slice(0, line.indexOf(':')).toLowerCase(), line.slice(line.indexOf(':') + 1).trim()]));
      resolve({ status: Number(head[0]?.split(' ')[1]), json, headers, raw: all });
    });
    socket.write(Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), payload]));
  });
}

const b64 = (buffer) => Buffer.from(buffer).toString('base64url');
/** 試験clientのJWE compact（RSA-OAEP-256/A256GCM）。headerOverridesで保護header、rawHeaderで生のheader文字列を使う。 */
function seal(key, fields, { headerOverrides = {}, rawHeader = null, cek = randomBytes(32) } = {}) {
  const header = { alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'sttd-command+jwe', kid: key.kid, sttdVersion: 1, scope: key.scope, commandId: fields.commandId, createdAt: fields.createdAt, expiresAt: fields.expiresAt, ...headerOverrides };
  const protectedPart = b64(Buffer.from(rawHeader ?? JSON.stringify(header), 'utf8'));
  const iv = randomBytes(12);
  const publicKey = createPublicKey({ key: { kty: 'RSA', n: key.publicJwk.n, e: key.publicJwk.e }, format: 'jwk' });
  const encryptedKey = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek);
  const cipher = createCipheriv('aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.from(protectedPart, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(fields.text, 'utf8'), cipher.final()]);
  return [protectedPart, b64(encryptedKey), b64(iv), b64(ciphertext), b64(cipher.getAuthTag())];
}
const join = (parts) => parts.join('.');
const fieldsAt = (clock, text, commandId = randomUUID()) => ({ commandId, text, createdAt: iso(clock.t), expiresAt: iso(clock.t + 60_000) });
const postEncrypted = (port, user, wire, commandId) =>
  request(port, 'POST', '/v2/encrypted-commands', { token: user.token, headers: [['Content-Type', 'application/jose'], ['Idempotency-Key', commandId]], body: wire });
const postPlain = (port, user, fields) =>
  request(port, 'POST', '/v2/commands', {
    token: user.token,
    headers: [['Content-Type', 'application/json'], ['Idempotency-Key', fields.commandId]],
    body: JSON.stringify({ schemaVersion: 2, commandId: fields.commandId, text: fields.text, createdAt: fields.createdAt, expiresAt: fields.expiresAt }),
  });
const sentText = (sent) => JSON.parse(sent.eventBytes.toString('utf8')).data.text;
const decryptCount = (w) => w.controlsPaths().reduce((sum, path) => sum + w.db.docs.get(path).windows.decrypt.dayCount, 0);

test('E01: 日本語・絵文字・改行/空白・4096byte・制御文字最大・混在の6入力が元のまま1回だけ届く', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const key = await w.publicKeyOf(a);
  const texts = ['こんにちは、世界', '絵文字 😀👍🏽 と 🇯🇵', '  前後の空白\n改行\r\nタブ\t ', 'a'.repeat(4096), '\u0001'.repeat(4096), `${'x'.repeat(4000)}\u0007😀\n`];
  for (const text of texts) {
    // 既存の配送件数の枠（owner別）に当たらないよう、送信ごとに時計を進める。
    w.clock.t += 70_000;
    const fields = fieldsAt(w.clock, text);
    const response = await postEncrypted(port, a, join(seal(key, fields)), fields.commandId);
    assert.equal(response.status, 200, `status for ${Buffer.byteLength(text)} bytes`);
    assert.equal(response.json.state, 'delivered');
    assert.equal(sentText(w.calls.sent.at(-1)), text);
  }
  assert.equal(w.calls.sent.length, 6);
  assert.equal(w.calls.keyChecks, 6);
});

test('E02/E03/E05/E06: 9改ざん・他UID/他環境・wire内の形の上限・header不正は400で送出0', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const b = w.enroll('synthetic-uid-b');
  const key = await w.publicKeyOf(a);
  const keyB = await w.publicKeyOf(b);
  const fields = fieldsAt(w.clock, 'synthetic tamper text');
  const good = seal(key, fields);
  const flip = (part, at = 0) => {
    const bytes = Buffer.from(part, 'base64url');
    bytes[at] ^= 1;
    return b64(bytes);
  };
  const withHeader = (overrides) => {
    const resealed = seal(key, fields, { headerOverrides: overrides });
    // 改ざん: headerだけ差し替え、元の暗号文・tagはそのまま（AADが違うのでtagが合わない）。
    return [resealed[0], ...good.slice(1)];
  };
  const cases = {
    cipher: [good[0], good[1], good[2], flip(good[3]), good[4]],
    tag: [good[0], good[1], good[2], good[3], flip(good[4])],
    nonce: [good[0], good[1], flip(good[2]), good[3], good[4]],
    header: withHeader({ typ: 'sttd-command+jwe' }).map((part, index) => (index === 0 ? b64(Buffer.from(JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'sttd-command+jwe', kid: key.kid, sttdVersion: 1, scope: key.scope, commandId: fields.commandId, createdAt: fields.createdAt, expiresAt: fields.expiresAt }, null, 1))) : part)),
    kid: withHeader({ kid: keyB.kid }),
    scope: withHeader({ scope: keyB.scope }),
    commandId: withHeader({ commandId: randomUUID() }),
    createdAt: withHeader({ createdAt: iso(w.clock.t + 1000), expiresAt: iso(w.clock.t + 61_000) }),
    expiresAt: withHeader({ expiresAt: iso(w.clock.t + 59_000) }),
    // E03: 他UIDの鍵で暗号化した要求を本人として送る / 他の環境のscope。
    otherUid: seal(keyB, fields),
    otherEnvironment: seal({ ...key, scope: b64(randomBytes(32)) }, fields),
    // E05: wire内だが形の上限を超える（ciphertext 4097byte）。
    ciphertextLimit: seal(key, { ...fields, text: 'b'.repeat(4097) }),
    // E06: header重複・未知key・base64url不正（非canonical）。
    duplicate: seal(key, fields, { rawHeader: `{"alg":"RSA-OAEP-256","alg":"RSA-OAEP-256","enc":"A256GCM","typ":"sttd-command+jwe","kid":"${key.kid}","sttdVersion":1,"scope":"${key.scope}","commandId":"${fields.commandId}","createdAt":"${fields.createdAt}","expiresAt":"${fields.expiresAt}"}` }),
    unknown: seal(key, fields, { headerOverrides: { zip: 'DEF' } }),
    base64url: [`${good[0]}=`, ...good.slice(1)],
  };
  const before = decryptCount(w);
  for (const [name, parts] of Object.entries(cases)) {
    // commandIdの改ざんは送る側のIdempotency-Keyも新しい値に揃える（headerの元表記と一致させる）。
    const id = name === 'commandId' ? JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')).commandId : fields.commandId;
    const response = await postEncrypted(port, a, join(parts), id);
    assert.equal(response.status, 400, name);
    assert.equal(response.json.error.code, 'invalid_encrypted_request', name);
  }
  assert.equal(w.calls.sent.length, 0);
  assert.equal(w.calls.prepare, 0);
  // wire内の不正は全て、認証・owner確認の後の復号試行として数える。
  assert.equal(decryptCount(w) - before, Object.keys(cases).length);
  // 正しい要求は通る（改ざんの比較対象）。
  assert.equal((await postEncrypted(port, a, join(good), fields.commandId)).status, 200);
});

test('E04/E07/E08/E18: 期限・復号rate・Secret障害と平文の成功・wire超過の消費0', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const key = await w.publicKeyOf(a);
  // E04: 期限切れのcommand（既存の時間判定へ通る）。
  const old = { commandId: randomUUID(), text: 'late', createdAt: iso(w.clock.t - 55_000), expiresAt: iso(w.clock.t + 5_000) };
  const late = await postEncrypted(port, a, join(seal(key, old)), old.commandId);
  assert.equal(late.status, 422);
  assert.equal(late.json.error.code, 'command_expired');

  // E18: 12288byte超は認証・DB・復号試行の前に400（identity 0・DB transaction 0・rate消費0）。
  const verifies = w.identity.calls;
  const transactions = w.db.transactions;
  const counted = decryptCount(w);
  const huge = await postEncrypted(port, a, 'A'.repeat(12_289), randomUUID());
  assert.equal(huge.status, 400);
  assert.equal(huge.json.error.code, 'invalid_encrypted_request');
  assert.equal(w.identity.calls, verifies);
  assert.equal(w.db.transactions, transactions);
  assert.equal(decryptCount(w), counted);

  // E08: 専用Secretの障害は503（配送0）、同じ入口の平文は成功。
  w.secret.fail = true;
  const fields = fieldsAt(w.clock, 'synthetic secret outage');
  const failed = await postEncrypted(port, a, join(seal(key, fields)), fields.commandId);
  assert.equal(failed.status, 503);
  assert.ok(!failed.raw.includes('SECRET-DETAIL'));
  const plain = fieldsAt(w.clock, 'plain during outage');
  const ok = await postPlain(port, a, plain);
  assert.equal(ok.status, 200);
  assert.equal(ok.json.state, 'delivered');
  assert.equal(w.calls.sent.length, 1);
  w.secret.fail = false;

  // E07: 復号試行の分枠（30）の上限で429＋Retry-After、復号0。
  const path = w.controlsPaths()[0];
  const controls = w.db.docs.get(path);
  w.db.docs.set(path, { ...controls, windows: { ...controls.windows, decrypt: { ...controls.windows.decrypt, minuteCount: 30 } } });
  const next = fieldsAt(w.clock, 'rate limited');
  const limited = await postEncrypted(port, a, join(seal(key, next)), next.commandId);
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers['retry-after']) >= 1);
  assert.equal(w.calls.sent.length, 1);
});

test('E09〜E14: 平文/暗号文の重複収束・再暗号化・内容差・取消tombstone・結果不明', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const key = await w.publicKeyOf(a);
  // E09: plain→encrypted（同じ論理5項目）。
  const f9 = fieldsAt(w.clock, 'same logical command');
  assert.equal((await postPlain(port, a, f9)).json.state, 'delivered');
  const e9 = await postEncrypted(port, a, join(seal(key, f9)), f9.commandId);
  assert.equal(e9.status, 200);
  assert.equal(e9.json.state, 'delivered');
  assert.equal(w.calls.sent.length, 1);
  // E10: encrypted→plain。
  const f10 = fieldsAt(w.clock, 'encrypted first');
  assert.equal((await postEncrypted(port, a, join(seal(key, f10)), f10.commandId)).json.state, 'delivered');
  assert.equal((await postPlain(port, a, f10)).json.state, 'delivered');
  assert.equal(w.calls.sent.length, 2);
  // E11: 同じIDの再暗号化（新しいCEK/IV）。
  assert.equal((await postEncrypted(port, a, join(seal(key, f10)), f10.commandId)).json.state, 'delivered');
  assert.equal(w.calls.sent.length, 2);
  // E12: 同じIDで内容差は409。
  const conflict = await postEncrypted(port, a, join(seal(key, { ...f10, text: 'different text' })), f10.commandId);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.json.error.code, 'idempotency_conflict');
  // E13: 先に取消したID（tombstone）は暗号文でも送出0。
  const f13 = fieldsAt(w.clock, 'cancelled before');
  assert.equal((await request(port, 'POST', `/v2/commands/${f13.commandId}/cancel`, { token: a.token })).status, 200);
  const e13 = await postEncrypted(port, a, join(seal(key, f13)), f13.commandId);
  assert.equal(e13.json.state, 'cancelled');
  assert.equal(w.calls.sent.length, 2);
  // E14: 送出の結果不明（delivery_unknown）は同じIDの再送で再送出しない。GETで状態を照会できる。
  w.control.sendResult = 'throw';
  const f14 = fieldsAt(w.clock, 'ambiguous');
  assert.equal((await postEncrypted(port, a, join(seal(key, f14)), f14.commandId)).json.state, 'delivery_unknown');
  w.control.sendResult = null;
  const again = await postEncrypted(port, a, join(seal(key, f14)), f14.commandId);
  assert.equal(again.json.state, 'delivery_unknown');
  assert.equal(w.calls.sent.length, 3);
  assert.equal((await request(port, 'GET', `/v2/commands/${f14.commandId}`, { token: a.token })).json.state, 'delivery_unknown');
});

test('E15/E16/E17: dispatch直前の失効で送出0、非保存・固定ログ・buffer清掃、元の20秒', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const key = await w.publicKeyOf(a);
  const path = w.ringPath();
  // 失効後のringもactiveの鍵ちょうど1つの不変条件を保つため、別の有効な公開鍵の形を新しいkidで置く（合成。T074の再発行の代わり）。
  const c = w.enroll('synthetic-uid-c');
  await w.publicKeyOf(c);
  const donor = [...w.db.docs].find(([other]) => other.includes('/rings/') && other !== path)[1].keys[0];
  const replacementKid = randomUUID();
  // E15: 開封の後・送出権の前に鍵を失効させる（別transactionの確認ではなく送出権のtransactionで判定される）。
  w.control.afterOpen = async () => {
    const ring = w.db.docs.get(path);
    const revokedKeys = ring.keys.map((entry) => ({ ...entry, state: 'revoked', decryptUntil: w.clock.t, retireAfter: w.clock.t + 86_400_000 }));
    const replacement = { ...donor, kid: replacementKid, publicJwk: { ...donor.publicJwk, kid: replacementKid } };
    w.db.docs.set(path, { ...ring, activeKid: replacementKid, keys: [replacement, ...revokedKeys] });
  };
  const f15 = fieldsAt(w.clock, 'revoked just before dispatch');
  const revoked = await postEncrypted(port, a, join(seal(key, f15)), f15.commandId);
  assert.equal(revoked.status, 200);
  assert.notEqual(revoked.json.state, 'delivered');
  assert.equal(w.calls.sent.length, 0);
  assert.equal(w.calls.keyChecks, 1);
  // 失効後の再送は開封せず固定の409（状態はGETで照会）。
  const resend = await postEncrypted(port, a, join(seal(key, f15)), f15.commandId);
  assert.equal(resend.status, 409);
  assert.equal(resend.json.error.code, 'encryption_key_unavailable');
  assert.equal((await request(port, 'GET', `/v2/commands/${f15.commandId}`, { token: a.token })).status, 200);

  // E16/E17は別の本人（有効な鍵）で確かめる。
  const b = w.enroll('synthetic-uid-b');
  const keyB = await w.publicKeyOf(b);
  const secretText = 'synthetic secret body 本文';
  const f16 = fieldsAt(w.clock, secretText);
  const wire = join(seal(keyB, f16));
  assert.equal((await postEncrypted(port, b, wire, f16.commandId)).json.state, 'delivered');
  const stored = JSON.stringify([...w.docs.values(), ...w.db.docs.values()]);
  assert.ok(!stored.includes(secretText) && !stored.includes(wire.split('.')[3]));
  assert.ok(!JSON.stringify(w.calls.logs).includes(secretText));
  assert.ok(w.calls.owned.length > 0 && w.calls.owned.every((buffer) => buffer.every((byte) => byte === 0)));

  // E17: 受信時刻は元のingressのまま（開封の間に時計が進んでも取り直さない）、20秒を過ぎれば送出0。
  w.clock.t += 1000;
  const receivedAt = w.clock.t;
  const f17 = fieldsAt(w.clock, 'deadline');
  w.control.afterOpen = async () => {
    w.clock.t += 21_000;
  };
  const sent = w.calls.sent.length;
  const stopped = await postEncrypted(port, b, join(seal(keyB, f17)), f17.commandId);
  assert.equal(stopped.status, 503);
  assert.equal(w.calls.sent.length, sent);
  // 準備の文書は元のingressの受信時刻のまま（復号・開封の後に取り直していない）で、送出していない。
  const doc = [...w.docs.values()].find((entry) => entry.receivedAt === receivedAt);
  assert.ok(doc !== undefined);
  assert.notEqual(doc.state, 'delivered');
});

// ---- S01/S02: 実のKmsRequestDeliveryStore（同じ合成DB。txごとの読取り・書込みを記録） ----

function realWorld() {
  const clock = { t: BASE, now() { return this.t; } };
  const docs = new Map();
  const log = [];
  let seq = 0;
  /** grantUntil: 合成connectのGrantの有効期限（nullは無期限）。時刻の判定は実storeが渡すnowで行う。 */
  const hooks = { onGet: null, onSecret: null, grantUntil: null };
  const db = {
    collection: (name) => collectionOf(name),
    async runTransaction(fn) {
      const id = (seq += 1);
      const writes = [];
      const read = (ref) => {
        log.push({ tx: id, kind: 'read', path: ref.path });
        hooks.onGet?.(ref.path, id);
        return snapshotOf(ref.path);
      };
      const tx = {
        get: async (ref) => read(ref),
        getAll: async (...refs) => refs.map(read),
        set: (ref, data) => writes.push(['set', ref.path, structuredClone(data)]),
        create: (ref, data) => writes.push(['create', ref.path, structuredClone(data)]),
        update: (ref, data) => writes.push(['update', ref.path, structuredClone(data)]),
        delete: (ref) => writes.push(['delete', ref.path]),
      };
      const result = await fn(tx);
      for (const [kind, path, data] of writes) {
        log.push({ tx: id, kind: 'write', path });
        if (kind === 'delete') docs.delete(path);
        else docs.set(path, kind === 'update' ? { ...docs.get(path), ...data } : data);
      }
      return result;
    },
  };
  function snapshotOf(path) {
    const data = docs.get(path);
    return { id: path.split('/').pop(), ref: refOf(path), exists: data !== undefined, data: () => (data === undefined ? undefined : structuredClone(data)) };
  }
  function refOf(path) {
    return { firestore: db, path, id: path.split('/').pop(), collection: (name) => collectionOf(`${path}/${name}`), get: async () => snapshotOf(path) };
  }
  function collectionOf(path) {
    return { doc: (id) => refOf(`${path}/${id}`) };
  }
  const hashKey = randomBytes(32);
  const hasher = createHmacHasher(randomBytes(32));
  const hash = (purpose, value) => createHmac('sha256', hashKey).update(purpose).update('\0').update(value).digest('hex');
  const environment = {
    projectId: 'synthetic-project',
    projectNumber: '123456',
    databaseId: '(default)',
    connectNamespace: `t256_${randomUUID()}`,
    deliveryNamespace: `t270_${randomUUID()}`,
    encryptionNamespace: `t280_${randomUUID()}`,
  };
  const secretValue = randomBytes(32).toString('base64url');
  const source = {
    async read() {
      hooks.onSecret?.();
      return Buffer.from(secretValue, 'latin1');
    },
  };
  const secrets = createEncryptionSecretProvider(source, { secret: 'projects/123456/secrets/synthetic-payload-protection', writeSecretVersion: 1, readSecretVersions: [1] });
  const keyStore = new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: 1, clock });
  const keys = new EncryptionKeyService({ environment, store: keyStore, secrets, hasher, clock });
  const policy = createKmsSubscriptionPolicy({
    environment: 'development',
    projectId: environment.projectId,
    databaseId: environment.databaseId,
    namespace: `t268_${randomUUID()}`,
    cryptoKey: 'projects/synthetic-project/locations/us-central1/keyRings/synthetic-ring/cryptoKeys/synthetic-key',
    writeVersion: 1,
    readVersions: [1],
  });
  const connectRoot = `sttdConnect/${environment.connectNamespace}`;
  const connect = {
    ownerDocRef: (ownerId) => refOf(`${connectRoot}/owners/${ownerId}`),
    grantDocRef: (grantId) => refOf(`${connectRoot}/grants/${grantId}`),
    ownerDocActive: (data) => data !== undefined && data.revokedAt === null,
    grantDocLive: (data, ownerId, grantId, now) => hooks.grantUntil === null || now < hooks.grantUntil,
    accessDocRefForOwner: (data) => (typeof data?.identityHash === 'string' ? refOf(`${connectRoot}/access/${data.identityHash}`) : null),
    grantMetaDocRef: (grantId) => refOf(`${connectRoot}/grantMeta/${grantId}`),
    accessUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
    grantUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
  };
  const deliveryStore = new KmsRequestDeliveryStore({ db, namespace: environment.deliveryNamespace, connect, hash, clock, policy });
  docs.set(`sttdAuth/${policy.namespace}/config/kms-subscription`, kmsMarkerDocument(policy));
  const capsule = () => `${KMS_CAPSULE_PREFIX}${b64(Buffer.from(JSON.stringify([kmsVersionName(policy.cryptoKey, 1), b64(randomBytes(48))]), 'utf8'))}`;
  const sent = [];
  let attempts = 0;
  const service = new KmsRequestDeliveryService({
    store: deliveryStore,
    codec: { open: async (binding) => Buffer.from(binding.purpose === 'callback-url' ? 'https://receiver.example/hook' : `whsec_${randomBytes(32).toString('base64')}`, 'utf8') },
    hash,
    digestKey: randomBytes(32),
    send: async (request) => (sent.push(Buffer.from(request.eventBytes)), { kind: 'delivered', reason: 'acknowledged', stopSubscription: false }),
    clock,
    newAttemptId: () => `attempt-${(attempts += 1)}`,
    log: () => {},
    budgetMs: 20_000,
    lifetime: new AbortController().signal,
    hooks: {},
  });
  const endpoint = createEncryptedCommandEndpoint({ environment, store: keyStore, secrets, hasher, clock, delivery: service });
  const enroll = (uid) => {
    const identityHash = connectIdentityHash(hasher, environment.connectNamespace, { projectId: environment.projectId, uid });
    const ownerId = randomUUID();
    docs.set(`${connectRoot}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: BASE });
    docs.set(`${connectRoot}/identities/${identityHash}`, { ownerId, createdAt: BASE });
    docs.set(`${connectRoot}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: BASE, lastActiveAt: BASE, revokedAt: null });
    const subscriptionId = `sub_${hash('subscription', ownerId)}`;
    docs.set(
      `sttdAuth/${policy.namespace}/subscriptions/${ownerId}`,
      kmsStateDocument(ownerId, {
        active: { id: subscriptionId, ownerId, grantId: `grant-${ownerId}`, sealedUrl: capsule(), sealedSecret: capsule(), secretHash: 'c'.repeat(64), previousSecret: null, expiresAt: null },
        knownDestinationId: subscriptionId,
        pending: null,
        lastEnded: null,
      }),
    );
    return { uid, ownerId };
  };
  const keyOf = async (user) => {
    const got = await keys.getOrInitialize({ projectId: environment.projectId, uid: user.uid }, { deadlineAt: clock.t + 20_000, signal: new AbortController().signal });
    assert.equal(got.kind, 'ok');
    return got.key;
  };
  const ringPathOf = (scope) => `sttdEncryption/${environment.encryptionNamespace}/rings/${scope}`;
  /** 鍵を猶予（decryptUntil=until）へ回し、別の有効な公開鍵の形を新しいkidのactiveに置く（T074の再発行の代わりの合成）。 */
  const toGrace = (scope, donorScope, until) => {
    const ring = docs.get(ringPathOf(scope));
    const donor = docs.get(ringPathOf(donorScope)).keys[0];
    const kid = randomUUID();
    const grace = ring.keys.map((entry) => ({ ...entry, state: 'grace', decryptUntil: until, retireAfter: until + 86_400_000 }));
    docs.set(ringPathOf(scope), { ...ring, activeKid: kid, keys: [{ ...donor, kid, publicJwk: { ...donor.publicJwk, kid } }, ...grace] });
  };
  const post = (user, wire, commandId) =>
    endpoint.post({ projectId: environment.projectId, uid: user.uid, authTimeSec: Math.floor(BASE / 1000) }, commandId, Buffer.from(wire, 'latin1'), clock.t, Object.freeze({ deadlineAt: clock.t + 20_000, signal: new AbortController().signal }));
  return { clock, docs, log, hooks, sent, enroll, keyOf, toGrace, ringPathOf, post };
}

test('S01/S02: 実storeの送出権transactionが同じtxで鍵を読む（valid／読取り中の猶予切れ）、Secret待機中の猶予切れは開封前に409', async () => {
  const r = realWorld();
  const a = r.enroll('synthetic-uid-real-a');
  const b = r.enroll('synthetic-uid-real-b');
  const key = await r.keyOf(a);
  const keyB = await r.keyOf(b);
  // S01 valid: 配送され、ringの読取りと同じtxでCommandの読取り・書込み（送出権の確定）が起きている。
  const f1 = fieldsAt(r.clock, 'real store valid');
  const ok = await r.post(a, join(seal(key, f1)), f1.commandId);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.state, 'delivered');
  assert.equal(r.sent.length, 1);
  const ringPath = r.ringPathOf(key.scope);
  const ringTxs = new Set(r.log.filter((entry) => entry.kind === 'read' && entry.path === ringPath).map((entry) => entry.tx));
  const dispatchTx = r.log.find((entry) => entry.kind === 'write' && entry.path.includes('/commands/') && ringTxs.has(entry.tx) && r.log.some((other) => other.tx === entry.tx && other.kind === 'read' && other.path === entry.path));
  assert.ok(dispatchTx !== undefined, 'ring read, command read and command write share one transaction');

  // S01 鍵の読取り中に猶予が切れる: 送出権のtx（Commandを読んだtx）で鍵を読んでいる間に時計がdecryptUntilを越えると、送出権0・送出0。
  r.clock.t += 70_000;
  r.toGrace(key.scope, keyB.scope, r.clock.t + 1_000);
  r.hooks.onGet = (path, tx) => {
    if (path === ringPath && r.log.some((entry) => entry.tx === tx && entry.path.includes('/commands/'))) {
      r.clock.t += 2_000;
      r.hooks.onGet = null;
    }
  };
  const f2 = fieldsAt(r.clock, 'grace expires during dispatch');
  const refused = await r.post(a, join(seal(key, f2)), f2.commandId);
  assert.equal(refused.status, 200);
  assert.notEqual(refused.body.state, 'delivered');
  assert.equal(r.sent.length, 1);
  assert.equal(r.hooks.onGet, null, 'the dispatch transaction read the key ring');

  // S02: Secretの待機中に猶予が切れる → 本文を開く前に409、準備（Commandの書込み）0。
  r.clock.t += 70_000;
  r.toGrace(key.scope, keyB.scope, r.clock.t + 1_000);
  r.hooks.onSecret = () => {
    r.clock.t += 2_000;
    r.hooks.onSecret = null;
  };
  const writesBefore = r.log.filter((entry) => entry.kind === 'write' && entry.path.includes('/commands/')).length;
  const f3 = fieldsAt(r.clock, 'grace expires while waiting for the secret');
  const late = await r.post(a, join(seal(key, f3)), f3.commandId);
  assert.equal(late.status, 409);
  assert.equal(late.body.error.code, 'encryption_key_unavailable');
  assert.equal(r.log.filter((entry) => entry.kind === 'write' && entry.path.includes('/commands/')).length, writesBefore);
  assert.equal(r.sent.length, 1);
});

test('S06: 鍵は有効なまま、送出権txの鍵読取り中にGrantの期限だけが切れると送出権0・送出0（最新時刻でview全体を再評価）', async () => {
  const r = realWorld();
  const a = r.enroll('synthetic-uid-grant');
  const key = await r.keyOf(a);
  const ringPath = r.ringPathOf(key.scope);
  // Grantは準備の時点では有効。送出権のtx（Commandを読んだtx）で鍵ringを読んでいる間に、元の20秒内で期限だけを越える。
  r.hooks.grantUntil = r.clock.t + 1_000;
  r.hooks.onGet = (path, tx) => {
    if (path === ringPath && r.log.some((entry) => entry.tx === tx && entry.path.includes('/commands/'))) {
      r.clock.t += 2_000;
      r.hooks.onGet = null;
    }
  };
  const f = fieldsAt(r.clock, 'grant expires during key read');
  const response = await r.post(a, join(seal(key, f)), f.commandId);
  assert.equal(r.hooks.onGet, null, 'the dispatch transaction read the key ring');
  assert.equal(response.status, 200);
  assert.notEqual(response.body.state, 'delivered');
  assert.equal(r.sent.length, 0);
  // 鍵そのものは有効なまま（拒否の原因はGrantの期限）。
  const ring = r.docs.get(ringPath);
  assert.equal(ring.keys.find((entry) => entry.kid === key.kid).state, 'active');
});

test('S03: ringの最終利用は今回の配送成功だけで更新（成功／tag不正／送出失敗、重複でも延ばさない）', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-touch');
  const key = await w.publicKeyOf(a);
  const lastUsed = () => w.db.docs.get(w.ringPath()).lastUsedAt;
  // 成功: 配送の後の時刻で更新。
  w.clock.t += 70_000;
  const f1 = fieldsAt(w.clock, 'touch on success');
  const before = lastUsed();
  const ok = await w.endpoint.post({ projectId: w.environment.projectId, uid: a.uid }, f1.commandId, Buffer.from(join(seal(key, f1))), w.clock.t, Object.freeze({ deadlineAt: w.clock.t + 20_000, signal: new AbortController().signal }));
  assert.equal(ok.body.state, 'delivered');
  assert.ok(lastUsed() > before);
  const afterSuccess = lastUsed();
  const send = (parts, fields) => w.endpoint.post({ projectId: w.environment.projectId, uid: a.uid }, fields.commandId, Buffer.from(join(parts)), w.clock.t, Object.freeze({ deadlineAt: w.clock.t + 20_000, signal: new AbortController().signal }));
  // 重複（既存の結果）では延ばさない。
  w.clock.t += 70_000;
  assert.equal((await send(seal(key, f1), f1)).body.state, 'delivered');
  assert.equal(lastUsed(), afterSuccess);
  // tag不正では延ばさない。
  const f2 = fieldsAt(w.clock, 'tag failure');
  const bad = seal(key, f2);
  const tag = Buffer.from(bad[4], 'base64url');
  tag[0] ^= 1;
  assert.equal((await send([...bad.slice(0, 4), b64(tag)], f2)).status, 400);
  assert.equal(lastUsed(), afterSuccess);
  // 送出失敗（結果不明）では延ばさない。
  w.control.sendResult = 'throw';
  const f3 = fieldsAt(w.clock, 'send failure');
  assert.equal((await send(seal(key, f3), f3)).body.state, 'delivery_unknown');
  w.control.sendResult = null;
  assert.equal(lastUsed(), afterSuccess);
});

test('S04: CEK・PKCS8・本文（成功）／未認証本文（tag失敗）のBufferを0埋めする', async () => {
  const w = world();
  const a = w.enroll('synthetic-uid-wipe');
  const key = await w.publicKeyOf(a);
  const ring = w.db.docs.get(w.ringPath());
  const stored = ring.keys[0];
  const pkcs8 = unwrapPrivateKey(stored.wrappedPrivateKey, Buffer.from(w.secretValue, 'base64url'), {
    ...w.environment,
    identityHash: ring.identityHash,
    ownerId: ring.ownerId,
    scope: ring.scope,
    kid: stored.kid,
    secretVersion: stored.secretVersion,
    publicKeySpki: stored.publicKeySpki,
  });
  const fill = Buffer.prototype.fill;
  const observe = async (parts, fields, targets) => {
    const counts = Object.fromEntries(Object.keys(targets).map((name) => [name, 0]));
    Buffer.prototype.fill = function (...args) {
      for (const [name, target] of Object.entries(targets)) if (this.length === target.length && target.equals(this)) counts[name] += 1;
      return fill.apply(this, args);
    };
    try {
      return { response: await w.endpoint.post({ projectId: w.environment.projectId, uid: a.uid }, fields.commandId, Buffer.from(join(parts)), w.clock.t, Object.freeze({ deadlineAt: w.clock.t + 20_000, signal: new AbortController().signal })), counts };
    } finally {
      Buffer.prototype.fill = fill;
    }
  };
  // 成功: CEK（commands.ts）、PKCS8（unwrap内の本体とcommands.tsが受け取った写しの2つ）、本文（decipherの出力とtext bytesの2つ）。
  w.clock.t += 70_000;
  const text = 'synthetic wipe body 本文';
  const cek = randomBytes(32);
  const f1 = fieldsAt(w.clock, text);
  const success = await observe(seal(key, f1, { cek }), f1, { cek, pkcs8, text: Buffer.from(text, 'utf8') });
  assert.equal(success.response.body.state, 'delivered');
  assert.ok(success.counts.cek >= 1, 'CEK wiped');
  assert.ok(success.counts.pkcs8 >= 2, 'both PKCS8 buffers wiped');
  assert.ok(success.counts.text >= 2, 'decrypted body buffers wiped');
  // tag失敗: CEK・PKCS8と、decipher.updateが返した未認証の本文を0埋めする。
  w.clock.t += 70_000;
  const cek2 = randomBytes(32);
  const f2 = fieldsAt(w.clock, text);
  const parts = seal(key, f2, { cek: cek2 });
  const tag = Buffer.from(parts[4], 'base64url');
  tag[0] ^= 1;
  const failure = await observe([...parts.slice(0, 4), b64(tag)], f2, { cek: cek2, pkcs8, text: Buffer.from(text, 'utf8') });
  assert.equal(failure.response.status, 400);
  assert.ok(failure.counts.cek >= 1, 'CEK wiped on tag failure');
  assert.ok(failure.counts.pkcs8 >= 2, 'PKCS8 wiped on tag failure');
  assert.ok(failure.counts.text >= 1, 'unauthenticated body wiped on tag failure');
  pkcs8.fill(0);
});

test('S05: 制御文字4096byteの署名eventは実の送出部品で1回届き本文・署名が一致、上限+1は送出前に拒否', { timeout: 30_000 }, async (t) => {
  assert.equal(MAX_SIGNED_EVENT_BYTES, 25_088);
  const now = Date.now();
  const text = '\u0001'.repeat(4096);
  const fields = { schemaVersion: 2, commandId: randomUUID(), text, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString() };
  const eventId = eventIdFor({ hash: createHmacHasher(randomBytes(32)).hash }, randomUUID(), fields.commandId);
  const eventBytes = buildEventBytes(fields, eventId, now, now + 60_000);
  // 実のbuildEventBytes: 本文の展開（6×4096）を除いた部分が固定envelope 512以内で、上限に収まる。
  assert.ok(eventBytes.length <= MAX_SIGNED_EVENT_BYTES);
  assert.ok(eventBytes.length - 6 * 4096 <= 512);
  assert.ok(eventBytes.length > 8704, 'the event exceeds the old 8704 limit');

  const tls = createTlsFixture();
  const receiver = await startReceiver(t, tls.good);
  const egress = createSafeEgress(fixtureConnector({ dns: { [CALLBACK_HOST]: ['127.0.0.1'] }, port: receiver.port, ca: tls.ca }));
  const attempt = createCommandDeliveryAttempt({ egress, clock: { now: () => Date.now() } });
  t.after(() => attempt.dispose());
  const secret = randomBytes(32);
  const request = (bytes) => ({
    eventBytes: bytes,
    eventId,
    subscriptionId: `sub_${'a'.repeat(64)}`,
    url: `https://${CALLBACK_HOST}/hook`,
    secrets: [secret],
    expiresAt: now + 60_000,
    leaseUntil: now + 20_000,
    signal: null,
  });
  const result = await attempt.send(request(eventBytes));
  assert.equal(result.kind, 'delivered');
  assert.equal(receiver.requests.length, 1);
  const received = receiver.requests[0];
  assert.equal(JSON.parse(received.body).data.text, text);
  const verified = new Webhook(`whsec_${secret.toString('base64')}`).verify(received.body, received.headers);
  assert.equal(verified.data.text, text);

  // 上限+1: attempt・safe-egressのどちらでも送出前に拒否し、受信0。
  const oversize = Buffer.alloc(MAX_SIGNED_EVENT_BYTES + 1, 0x61);
  await assert.rejects(attempt.send(request(oversize)), (error) => error?.code === 'invalid_input');
  await assert.rejects(egress.postCommandCallback(`https://${CALLBACK_HOST}/hook`, { headers: {}, body: oversize }));
  assert.equal(receiver.requests.length, 1);
});
