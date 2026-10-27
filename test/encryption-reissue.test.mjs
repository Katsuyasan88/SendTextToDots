// 本人の鍵の再発行（POST /v2/encryption-key/reissue）。送信APIの実HTTP入口→実の公開鍵endpoint・鍵service/store（予約→候補→CAS）→
// 合成DB（txごとの読取り/書込み、commit失敗/応答不明の注入）。暗号文の送信は実の暗号文endpoint→実のKMS配送service→実の
// KmsRequestDeliveryStore（同じ合成DB、connectは合成）→合成codec・合成send。実Cloud・資格・Secret・SDK通信・Dots 0。
// 試験のRSA3072鍵はこのprocessで生成した合成鍵の使い回し（kidは毎回新規）。node:testのtest数とscenario数は一致しない。
//   R01 通常再発行の旧鍵: 猶予内は配送、猶予外は409（2入力）/R02 漏えい時の即時全失効/R03 同ID二重は元の結果/R04 同IDのmode差409/
//   R05 並行の別ID/R06 応答消失/R07 生成・保護（Secret）・DBの失敗（3入力）/R08 停止・他UID（2入力）/R09 回数（24hに4件・60秒間隔）/
//   R10 切替とdispatchの両順序（2入力）/R11 新旧鍵での同じcommandの重複/R12 複数clientの追従/R13 過去鍵・操作の上限と24h回収（計18）。
//   Q01 pending中の同IDは202・追加生成0、別IDは409（2入力）/Q02 期限切れpendingは失敗・旧鍵維持・再生成0/
//   Q03 応答不明から同IDのcompleted読取りとmode差の拒否/Q04 GETと再発行のHTTP共有枠・同IDで再発行枠の追加0（計4scenario/5入力）。
//   PM是正: B01 60秒間隔の429と複数制約の429は非消費・最長の待ち（2入力）/B02 期限済み過去鍵をpruneしてからrewrap判定（旧版のread許可を
//   外してもGET成功・旧版read0）/B03 pending中に保護鍵rewrapがgenerationを進めると再発行CASは失敗し、旧activeと最新wrapを維持・再生成0。

import assert from 'node:assert/strict';
import { constants, createCipheriv, createHmac, createPublicKey, generateKeyPairSync, publicEncrypt, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { connectIdentityHash } from '../dist/connect/firestore.js';
import { createIngressOperationDeliveryRequestHandler } from '../dist/delivery/api.js';
import { KmsRequestDeliveryService } from '../dist/delivery/kms-service.js';
import { KmsRequestDeliveryStore } from '../dist/delivery/kms-store.js';
import { createEncryptionKeyEndpoint } from '../dist/encryption/api.js';
import { createEncryptedCommandEndpoint } from '../dist/encryption/commands.js';
import { createEncryptionSecretProvider } from '../dist/encryption/secret-provider.js';
import { EncryptionKeyService } from '../dist/encryption/service.js';
import { EncryptionKeyStore } from '../dist/encryption/store.js';
import { KMS_CAPSULE_PREFIX } from '../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../dist/secrets.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument, kmsStateDocument, kmsVersionName } from '../dist/storage/firestore/kms-subscription-format.js';

const BASE = 1_900_000_000_000;
const DAY = 86_400_000;
const POOL = Array.from({ length: 6 }, () => generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 }));
const b64 = (buffer) => Buffer.from(buffer).toString('base64url');
const iso = (ms) => new Date(ms).toISOString();

const servers = [];
after(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

function world() {
  const clock = { t: BASE, now() { return this.t; } };
  const docs = new Map();
  const log = [];
  let seq = 0;
  /** commitFault(writes)が'fail'（書込みなし）/'lost'（書込み後）を返すと、そのtxへ1回だけ注入する。 */
  const hooks = { commitFault: null, afterOpen: null, beforeFinish: null };
  const db = {
    collection: (name) => collectionOf(name),
    async runTransaction(fn) {
      const id = (seq += 1);
      const writes = [];
      const read = (ref) => {
        log.push({ tx: id, kind: 'read', path: ref.path });
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
      const fault = hooks.commitFault?.(writes) ?? null;
      if (fault !== null) hooks.commitFault = null;
      if (fault === 'fail') throw new Error('synthetic commit failure');
      for (const [kind, path, data] of writes) {
        log.push({ tx: id, kind: 'write', path });
        if (kind === 'delete') docs.delete(path);
        else docs.set(path, kind === 'update' ? { ...docs.get(path), ...data } : data);
      }
      if (fault === 'lost') throw new Error('synthetic lost commit response');
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
  /** 保護鍵の合成版（1と2）。読取りは版名で記録する（値は出力しない）。 */
  const secretValues = new Map([1, 2].map((version) => [version, randomBytes(32).toString('base64url')]));
  const secret = { fail: false, reads: [] };
  const source = {
    async read(name) {
      secret.reads.push(name);
      if (secret.fail) throw new Error('synthetic secret failure');
      const value = secretValues.get(Number(name.split('/').pop()));
      if (value === undefined) throw new Error('synthetic missing version');
      return Buffer.from(value, 'latin1');
    },
  };
  const SECRET_NAME = 'projects/123456/secrets/synthetic-payload-protection';
  const secrets = createEncryptionSecretProvider(source, { secret: SECRET_NAME, writeSecretVersion: 1, readSecretVersions: [1] });
  const keyStore = new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: 1, clock });
  // 生成器: holdがあれば解放まで待つ（並行・期限切れの試験）。failで失敗。
  const gen = { calls: 0, fail: false, hold: null };
  const generate = async () => {
    gen.calls += 1;
    if (gen.hold !== null) {
      const hold = gen.hold;
      gen.hold = null;
      hold.reached();
      await hold.promise;
    }
    if (gen.fail) throw new Error('synthetic generation failure');
    return POOL[gen.calls % POOL.length];
  };
  const keys = new EncryptionKeyService({ environment, store: keyStore, secrets, hasher, clock, generate });
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
    grantDocLive: () => true,
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
    hooks: {
      afterOpen: async () => {
        const run = hooks.afterOpen;
        hooks.afterOpen = null;
        if (run) await run();
      },
      beforeFinish: async () => {
        const run = hooks.beforeFinish;
        hooks.beforeFinish = null;
        if (run) await run();
      },
    },
  });
  const encryptedCommands = createEncryptedCommandEndpoint({ environment, store: keyStore, secrets, hasher, clock, delivery: service });
  const tokens = new Map();
  const ownerOfUid = new Map();
  const identity = {
    projectId: environment.projectId,
    async verifyIdToken(token) {
      const uid = tokens.get(token);
      if (uid === undefined) throw new Error('bad token');
      return { projectId: environment.projectId, uid, authTimeSec: Math.floor(BASE / 1000) };
    },
    async accountStatus() {
      return 'active';
    },
  };
  const handler = createIngressOperationDeliveryRequestHandler({
    identity,
    findOwner: async (verified) => ownerOfUid.get(verified.uid),
    service,
    clock,
    log: () => {},
    lifetime: new AbortController().signal,
    ingress: () => ({ receivedAt: clock.t, deadlineAt: clock.t + 20_000, signal: new AbortController().signal }),
    encryptionKeys: createEncryptionKeyEndpoint(keys),
    encryptedCommands,
  });
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
    ownerOfUid.set(uid, ownerId);
    const token = `tok.${randomBytes(12).toString('base64url')}.sig`;
    tokens.set(token, uid);
    return { uid, ownerId, token, identityHash, accessPath: `${connectRoot}/access/${identityHash}` };
  };
  const ringOf = (scope) => docs.get(`sttdEncryption/${environment.encryptionNamespace}/rings/${scope}`);
  const controlsOf = (scope) => docs.get(`sttdEncryption/${environment.encryptionNamespace}/controls/${scope}`);
  /** 同じDB・hasher・生成器で、保護鍵の書込み版/読取り版だけが違う鍵service（保護鍵の版の更新＝rewrapの合成）。 */
  const keysWith = (write, read) =>
    new EncryptionKeyService({
      environment,
      store: new EncryptionKeyStore({ db, connectNamespace: environment.connectNamespace, encryptionNamespace: environment.encryptionNamespace, writeSecretVersion: write, clock }),
      secrets: createEncryptionSecretProvider(source, { secret: SECRET_NAME, writeSecretVersion: write, readSecretVersions: read }),
      hasher,
      clock,
      generate,
    });
  const operation = () => Object.freeze({ deadlineAt: clock.t + 20_000, signal: new AbortController().signal });
  return { clock, docs, hooks, gen, secret, sent, enroll, handler, ringOf, controlsOf, keysWith, operation, projectId: environment.projectId, SECRET_NAME };
}

async function serve(handler) {
  const server = createServer((req, res) => void handler(req, res));
  servers.push(server);
  await new Promise((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  return server.address().port;
}
function request(port, method, path, { token, headers = [], body = '' } = {}) {
  const payload = Buffer.from(body, 'utf8');
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
      const head = all.slice(0, split).split('\r\n');
      const headers = Object.fromEntries(head.slice(1).map((line) => [line.slice(0, line.indexOf(':')).toLowerCase(), line.slice(line.indexOf(':') + 1).trim()]));
      let json = null;
      try {
        json = JSON.parse(all.slice(split + 4));
      } catch {
        json = null;
      }
      resolve({ status: Number(head[0]?.split(' ')[1]), headers, json, raw: all });
    });
    socket.write(Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), payload]));
  });
}
const getKey = (port, user) => request(port, 'GET', '/v2/encryption-key', { token: user.token });
const reissue = (port, user, requestId, mode = 'normal', extra = {}) =>
  request(port, 'POST', '/v2/encryption-key/reissue', {
    token: user.token,
    headers: [['Content-Type', 'application/json'], ['Idempotency-Key', requestId]],
    body: JSON.stringify({ requestId, mode, ...extra }),
  });
function seal(key, fields) {
  const header = { alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'sttd-command+jwe', kid: key.kid, sttdVersion: 1, scope: key.scope, commandId: fields.commandId, createdAt: fields.createdAt, expiresAt: fields.expiresAt };
  const protectedPart = b64(Buffer.from(JSON.stringify(header), 'utf8'));
  const cek = randomBytes(32);
  const iv = randomBytes(12);
  const publicKey = createPublicKey({ key: { kty: 'RSA', n: key.publicJwk.n, e: key.publicJwk.e }, format: 'jwk' });
  const encryptedKey = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek);
  const cipher = createCipheriv('aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.from(protectedPart, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(fields.text, 'utf8'), cipher.final()]);
  return [protectedPart, b64(encryptedKey), b64(iv), b64(ciphertext), b64(cipher.getAuthTag())].join('.');
}
const fieldsAt = (clock, text, commandId = randomUUID()) => ({ commandId, text, createdAt: iso(clock.t), expiresAt: iso(clock.t + 60_000) });
const sendEncrypted = (port, user, key, fields) =>
  request(port, 'POST', '/v2/encrypted-commands', { token: user.token, headers: [['Content-Type', 'application/jose'], ['Idempotency-Key', fields.commandId]], body: seal(key, fields) });
function gate() {
  let release;
  let reached;
  const whenReached = new Promise((resolve) => (reached = resolve));
  const promise = new Promise((resolve) => (release = resolve));
  return { promise, whenReached, reached: () => reached(), release: () => release() };
}

test('R03/R04/R06/R12/Q03: 同IDは元の結果、mode差409、応答消失は同IDの記録を読み直す、複数clientの追従', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const first = (await getKey(port, a)).json;
  const id1 = randomUUID();
  const done = await reissue(port, a, id1);
  assert.equal(done.status, 200);
  assert.notEqual(done.json.kid, first.kid);
  assert.ok(!done.raw.includes('wrappedPrivateKey') && !done.raw.includes('pkcs8'));
  assert.deepEqual(Object.keys(done.json).sort(), Object.keys(first).sort());
  const generation = w.ringOf(first.scope).generation;
  // R03: 同ID・同modeの再試行は元の公開結果（生成0・generation不変）。
  const calls = w.gen.calls;
  assert.deepEqual((await reissue(port, a, id1)).json, done.json);
  assert.equal(w.gen.calls, calls);
  assert.equal(w.ringOf(first.scope).generation, generation);
  // R04: 同IDのmode差は409。
  const conflict = await reissue(port, a, id1, 'compromised');
  assert.equal(conflict.status, 409);
  assert.equal(conflict.json.error.code, 'idempotency_conflict');
  // R12: 別のclientのGETは新しい鍵へ追従する。
  assert.equal((await getKey(port, a)).json.kid, done.json.kid);

  // R06/Q03: 確定のcommit応答が消える（書込みは成功）→同じ操作の記録を読み直して元の結果を返す。新ID・再生成0。
  w.clock.t += 61_000;
  const id2 = randomUUID();
  w.hooks.commitFault = (writes) => (writes.some(([, path]) => path.includes('/owners/')) && writes.some(([, path]) => path.includes('/rings/')) ? 'lost' : null);
  const before = w.gen.calls;
  const lost = await reissue(port, a, id2);
  assert.equal(lost.status, 200);
  assert.equal(w.gen.calls, before + 1);
  assert.equal(w.ringOf(first.scope).activeKid, lost.json.kid);
  assert.deepEqual((await reissue(port, a, id2)).json, lost.json);
  assert.equal((await reissue(port, a, id2, 'compromised')).status, 409);
});

test('R01/R02/R11: 通常再発行の旧鍵は猶予内だけ使え、漏えい時は即時失効、新旧鍵の同じcommandは重複送出0', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const oldKey = (await getKey(port, a)).json;
  const fx = fieldsAt(w.clock, 'same command across keys');
  assert.equal((await sendEncrypted(port, a, oldKey, fx)).json.state, 'delivered');
  const newKey = (await reissue(port, a, randomUUID())).json;
  // R01: 猶予（120秒）内は旧鍵で配送される。
  w.clock.t += 60_000;
  const inGrace = fieldsAt(w.clock, 'old key within grace');
  assert.equal((await sendEncrypted(port, a, oldKey, inGrace)).json.state, 'delivered');
  // R11: 同じcommandを新しい鍵で送り直しても、既存の結果へ収束して送出は増えない。
  const sent = w.sent.length;
  assert.equal((await sendEncrypted(port, a, newKey, fx)).json.state, 'delivered');
  assert.equal(w.sent.length, sent);
  // R01: 猶予の後は旧鍵を開かない。
  w.clock.t += 61_000;
  const outGrace = await sendEncrypted(port, a, oldKey, fieldsAt(w.clock, 'old key after grace'));
  assert.equal(outGrace.status, 409);
  assert.equal(outGrace.json.error.code, 'encryption_key_unavailable');
  // R02: 漏えい時の再発行は、直前のactive（newKey）を即時に失効させる。
  const latest = (await reissue(port, a, randomUUID(), 'compromised')).json;
  const revoked = await sendEncrypted(port, a, newKey, fieldsAt(w.clock, 'compromised key'));
  assert.equal(revoked.status, 409);
  assert.equal((await sendEncrypted(port, a, latest, fieldsAt(w.clock, 'latest key'))).json.state, 'delivered');
});

test('R05/Q01/Q02: pending中の同IDは202・生成追加0、別IDは409、期限切れpendingは失敗で旧鍵維持・再生成0', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const first = (await getKey(port, a)).json;
  const hold = gate();
  w.gen.hold = hold;
  const id1 = randomUUID();
  const running = reissue(port, a, id1);
  await hold.whenReached;
  const calls = w.gen.calls;
  // Q01: 同IDのpendingは202 in_flight・Retry-After 1、生成の追加0。
  const pending = await reissue(port, a, id1);
  assert.equal(pending.status, 202);
  assert.equal(pending.json.state, 'in_flight');
  assert.equal(pending.headers['retry-after'], '1');
  assert.equal(w.gen.calls, calls);
  // Q01/R05: 別IDの並行操作は409 key_reissue_in_progress。
  const other = await reissue(port, a, randomUUID());
  assert.equal(other.status, 409);
  assert.equal(other.json.error.code, 'key_reissue_in_progress');
  hold.release();
  assert.equal((await running).status, 200);

  // Q02: 生成の間に元の期限（20秒）を過ぎる → 失敗（503）、旧鍵（現在のactive）は維持。同IDの再試行は409 key_reissue_failedで再生成0。
  w.clock.t += 61_000;
  const active = w.ringOf(first.scope).activeKid;
  const hold2 = gate();
  w.gen.hold = hold2;
  const id3 = randomUUID();
  const slow = reissue(port, a, id3);
  await hold2.whenReached;
  w.clock.t += 21_000;
  hold2.release();
  assert.equal((await slow).status, 503);
  assert.equal(w.ringOf(first.scope).activeKid, active);
  const generated = w.gen.calls;
  const failed = await reissue(port, a, id3);
  assert.equal(failed.status, 409);
  assert.equal(failed.json.error.code, 'key_reissue_failed');
  assert.equal(w.gen.calls, generated);
});

test('R07: 生成・保護（Secret）・DBの失敗は503で旧鍵を変えず、記録した失敗は同IDで409', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const first = (await getKey(port, a)).json;
  const active = () => w.ringOf(first.scope).activeKid;
  // 生成の失敗。
  w.gen.fail = true;
  const id1 = randomUUID();
  assert.equal((await reissue(port, a, id1)).status, 503);
  w.gen.fail = false;
  assert.equal(active(), first.kid);
  assert.equal((await reissue(port, a, id1)).json.error.code, 'key_reissue_failed');
  // 保護鍵（Secret）の失敗。
  w.clock.t += 61_000;
  w.secret.fail = true;
  assert.equal((await reissue(port, a, randomUUID())).status, 503);
  w.secret.fail = false;
  assert.equal(active(), first.kid);
  // 確定のDB commitの失敗（書込みなし）。
  w.clock.t += 61_000;
  w.hooks.commitFault = (writes) => (writes.some(([, path]) => path.includes('/owners/')) && writes.some(([, path]) => path.includes('/rings/')) ? 'fail' : null);
  assert.equal((await reissue(port, a, randomUUID())).status, 503);
  assert.equal(active(), first.kid);
  // 失敗の後も旧鍵で送れる。
  assert.equal((await sendEncrypted(port, a, first, fieldsAt(w.clock, 'old key still usable'))).json.state, 'delivered');
});

test('R08/R09/R13/Q04: 停止・他UID・本文の自己申告、回数制限、過去鍵/操作の上限と24h回収、HTTP共有枠', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const b = w.enroll('synthetic-uid-b');
  const first = (await getKey(port, a)).json;
  const firstB = (await getKey(port, b)).json;
  // R08: 本文で他UIDを申告しても400、未知のmodeも400、他UIDの再発行は本人のringを変えない。
  assert.equal((await reissue(port, a, randomUUID(), 'normal', { uid: 'synthetic-uid-b' })).status, 400);
  assert.equal((await reissue(port, a, randomUUID(), 'rotate')).status, 400);
  assert.equal((await reissue(port, b, randomUUID())).status, 200);
  assert.equal(w.ringOf(first.scope).activeKid, first.kid);
  assert.notEqual(w.ringOf(firstB.scope).activeKid, firstB.kid);

  // R09: 60秒間隔と24hに4件（pending/失敗を含む）。
  const ids = [];
  for (let i = 0; i < 4; i += 1) {
    if (i > 0) w.clock.t += 61_000;
    const id = randomUUID();
    ids.push(id);
    const done = await reissue(port, a, id, 'normal');
    assert.equal(done.status, 200, `reissue ${i}`);
    if (i === 0) {
      const tooSoon = await reissue(port, a, randomUUID());
      assert.equal(tooSoon.status, 429);
      assert.ok(Number(tooSoon.headers['retry-after']) >= 1);
    }
  }
  w.clock.t += 61_000;
  const limited = await reissue(port, a, randomUUID());
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers['retry-after']) > 60);
  // R13: activeは1つ、過去鍵は4以下、操作記録は4以下。
  const ring = w.ringOf(first.scope);
  assert.equal(ring.keys.filter((key) => key.state === 'active').length, 1);
  assert.ok(ring.keys.length <= 5);
  assert.equal(ring.reissues.length, 4);

  // Q04: 同IDの再試行は再発行の試行枠を消費しない。GETと再発行はHTTPの取得枠（分60）を共用する。
  const attemptBefore = structuredClone(w.controlsOf(first.scope).windows.reissueAttempt);
  assert.equal((await reissue(port, a, ids[3])).status, 200);
  assert.deepEqual(w.controlsOf(first.scope).windows.reissueAttempt, attemptBefore);
  const controlsPath = `sttdEncryption/${[...w.docs.keys()].find((path) => path.includes('/controls/') && path.endsWith(first.scope)).split('sttdEncryption/')[1]}`;
  const controls = w.docs.get(controlsPath);
  w.docs.set(controlsPath, { ...controls, windows: { ...controls.windows, fetch: { ...controls.windows.fetch, minuteCount: 59 } } });
  assert.equal((await reissue(port, a, ids[3])).status, 200);
  assert.equal((await getKey(port, a)).status, 429);

  // R13: 24h後の正常な取得で、期限済みの過去鍵と24hを過ぎた操作記録を回収する（activeは残る）。
  w.clock.t += DAY + 120_000;
  for (const path of [...w.docs.keys()].filter((entry) => entry.includes('/owners/'))) w.docs.set(path, { ...w.docs.get(path), lastActiveAt: w.clock.t });
  assert.equal((await getKey(port, a)).status, 200);
  const pruned = w.ringOf(first.scope);
  assert.equal(pruned.keys.length, 1);
  assert.equal(pruned.reissues.length, 0);

  // R08: 停止（許可disabled）は403。
  w.docs.set(a.accessPath, { ...w.docs.get(a.accessPath), state: 'disabled' });
  assert.equal((await reissue(port, a, randomUUID())).status, 403);
});

test('R10: 切替とdispatchの両順序（切替が先なら送出0、送出権が先なら配送済み）', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const key = (await getKey(port, a)).json;
  // 漏えい時の切替が、開封の後・送出権のtransactionの前に確定 → 送出0。
  w.hooks.afterOpen = async () => {
    assert.equal((await reissue(port, a, randomUUID(), 'compromised')).status, 200);
  };
  const before = await sendEncrypted(port, a, key, fieldsAt(w.clock, 'switch before dispatch'));
  assert.notEqual(before.json.state, 'delivered');
  assert.equal(w.sent.length, 0);
  // 送出権の確定の後に切替 → その送出は撤回されず配送済み。
  w.clock.t += 61_000;
  const current = (await getKey(port, a)).json;
  w.hooks.beforeFinish = async () => {
    assert.equal((await reissue(port, a, randomUUID(), 'compromised')).status, 200);
  };
  const afterDispatch = await sendEncrypted(port, a, current, fieldsAt(w.clock, 'switch after dispatch'));
  assert.equal(afterDispatch.json.state, 'delivered');
  assert.equal(w.sent.length, 1);
});

test('B01: 60秒間隔の429と複数制約の429は、fetch・試行枠・予約数を消費せず、最長の待ちを返す', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const scope = (await getKey(port, a)).json.scope;
  assert.equal((await reissue(port, a, randomUUID())).status, 200);
  const snapshot = () => structuredClone({ controls: w.controlsOf(scope), reissues: w.ringOf(scope).reissues });
  // 60秒間隔だけ: 429、消費0。
  const before = snapshot();
  const spacing = await reissue(port, a, randomUUID());
  assert.equal(spacing.status, 429);
  assert.ok(Number(spacing.headers['retry-after']) >= 1 && Number(spacing.headers['retry-after']) <= 60);
  assert.deepEqual(snapshot(), before);
  // 24hに4件＋試行枠の分上限が同時: 短い分の待ちではなく、24hの最長の待ち。消費0。
  for (let i = 0; i < 3; i += 1) {
    w.clock.t += 61_000;
    assert.equal((await reissue(port, a, randomUUID())).status, 200);
  }
  w.clock.t += 61_000;
  const controlsPath = [...w.docs.keys()].find((path) => path.includes('/controls/') && path.endsWith(scope));
  const controls = w.docs.get(controlsPath);
  const minuteStart = Math.floor(w.clock.t / 60_000) * 60_000;
  w.docs.set(controlsPath, { ...controls, windows: { ...controls.windows, reissueAttempt: { ...controls.windows.reissueAttempt, minuteStart, minuteCount: 3 } } });
  const both = snapshot();
  const limited = await reissue(port, a, randomUUID());
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers['retry-after']) > 3600, 'the longest wait (rolling 24h) wins');
  assert.deepEqual(snapshot(), both);
});

test('B02/B03: 期限済み過去鍵をpruneしてからrewrap判定、pending中のrewrapで再発行CASは失敗し旧activeと最新wrapを維持', async () => {
  const w = world();
  const port = await serve(w.handler);
  const a = w.enroll('synthetic-uid-a');
  const scope = (await getKey(port, a)).json.scope;
  const identity = { projectId: w.projectId, uid: a.uid };
  // B02: 保護鍵の書込み版2（読取り1,2）で再発行 → active=v2、旧鍵=v1（grace）。24h後、読取り版を2だけにしてもGETは成功し、v1の読取り0。
  const keys2 = w.keysWith(2, [1, 2]);
  const done = await keys2.reissue(identity, { requestId: randomUUID(), mode: 'normal' }, w.operation());
  assert.equal(done.kind, 'ok');
  assert.deepEqual(w.ringOf(scope).keys.map((key) => key.secretVersion).sort(), [1, 2]);
  w.clock.t += DAY + 1_000;
  const reads = w.secret.reads.length;
  const after = await w.keysWith(2, [2]).getOrInitialize(identity, w.operation());
  assert.equal(after.kind, 'ok');
  assert.equal(after.key.kid, done.key.kid);
  assert.equal(w.secret.reads.length, reads);
  assert.deepEqual(w.ringOf(scope).keys.map((key) => key.secretVersion), [2]);

  // B03: 再発行のpending中（候補の生成を保留）に、保護鍵の版3への更新（rewrap）がgenerationを進める → 再発行の確定は失敗（409）、
  // activeは旧active（rewrap後の版を維持）、再生成0。
  const b = w.enroll('synthetic-uid-b');
  const scopeB = (await getKey(port, b)).json.scope;
  const activeB = w.ringOf(scopeB).activeKid;
  const hold = gate();
  w.gen.hold = hold;
  const running = reissue(port, b, randomUUID());
  await hold.whenReached;
  const rewrapped = await w.keysWith(2, [1, 2]).getOrInitialize({ projectId: w.projectId, uid: b.uid }, w.operation());
  assert.equal(rewrapped.kind, 'ok');
  const generation = w.ringOf(scopeB).generation;
  const calls = w.gen.calls;
  hold.release();
  const result = await running;
  assert.equal(result.status, 409);
  assert.equal(result.json.error.code, 'key_reissue_failed');
  const ringB = w.ringOf(scopeB);
  assert.equal(ringB.activeKid, activeB);
  assert.equal(ringB.generation, generation);
  assert.ok(ringB.keys.every((key) => key.secretVersion === 2));
  assert.equal(w.gen.calls, calls);
});
