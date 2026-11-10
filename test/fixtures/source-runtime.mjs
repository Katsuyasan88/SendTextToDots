// 許可元strictの接合試験だけが使う合成runtime部品（製品からの依存0）。実秘密・資格・実配置・SDK通信0。
//   createResolverRuntime: test/mcp-auth-bearer.test.mjsと同じ組立て（本物の固定oidc-provider・ConnectStorage・要求context・KMS sealing
//   port＋合成AES-GCM transport・限定fake Firestore）。strictではresolver生成の前にConnectStorageへSourceStoreを結ぶ（製品の起動順と同じ）。
// 鍵・IDは全て試験内の乱数。外部egressは常に失敗（CIMD等の取得0）。

import { createCipheriv, createDecipheriv, createHmac, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

import { KmsRequestDeliveryService } from '../../dist/delivery/kms-service.js';
import { KmsRequestDeliveryStore } from '../../dist/delivery/kms-store.js';
import { KMS_CAPSULE_PREFIX } from '../../dist/protection/kms-sealing.js';
import { createSourceGate } from '../../dist/source/http.js';
import { createKmsSubscriptionPolicy, kmsMarkerDocument, kmsStateDocument, kmsVersionName } from '../../dist/storage/firestore/kms-subscription-format.js';

import { ConnectStorage } from '../../dist/connect/firestore.js';
import { createConnectKmsSealingPort } from '../../dist/connect/kms-port.js';
import { createOAuthProvider, resourceFor } from '../../dist/oauth/provider.js';
import { createRequestAuthContext, createRequestScopedOAuthOwnerResolver } from '../../dist/oauth/request-auth-runtime.js';
import { PRODUCT_POLICY } from '../../dist/policy.js';
import { crc32c } from '../../dist/protection/kms-sealing.js';
import { createHmacHasher } from '../../dist/secrets.js';
import { SourceStore } from '../../dist/source/firestore.js';
import { newSourceGeneration, newSourceId } from '../../dist/source/admin.js';

const DAY = 86_400_000;

/** 合成AES-GCMのKMS transport（KMS APIのencrypt/decryptと同じ形。外部通信0）。 */
export function syntheticKmsTransport() {
  const key = randomBytes(32);
  return {
    async encrypt(request) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(request.additionalAuthenticatedData);
      const body = Buffer.concat([cipher.update(request.plaintext), cipher.final()]);
      const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), body]);
      return { name: request.name, ciphertext, ciphertextCrc32c: crc32c(ciphertext), verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true, protectionLevel: 'SOFTWARE' };
    },
    async decrypt(request) {
      const raw = request.ciphertext;
      const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
      decipher.setAAD(request.additionalAuthenticatedData);
      decipher.setAuthTag(raw.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
      return { plaintext, plaintextCrc32c: crc32c(plaintext), protectionLevel: 'SOFTWARE' };
    },
  };
}

/** get/set/update/deleteと直列のrunTransactionだけの合成Firestore（refはfirestoreを持つ）。 */
export function syntheticFirestore() {
  const docs = new Map();
  const snapshot = (path) => {
    const data = docs.get(path);
    return { id: path.split('/').pop(), ref: refOf(path), exists: data !== undefined, updateTime: undefined, get: (field) => data?.[field], data: () => (data === undefined ? undefined : structuredClone(data)) };
  };
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => ({ doc: (id) => refOf(`${path}/${name}/${id}`) }),
      set: async (data) => void docs.set(path, structuredClone(data)),
      update: async (partial) => void docs.set(path, { ...docs.get(path), ...structuredClone(partial) }),
      delete: async () => void docs.delete(path),
      get: async () => snapshot(path),
    };
  }
  let lock = Promise.resolve();
  const db = {
    docs,
    collection: (name) => ({ doc: (id) => refOf(`${name}/${id}`) }),
    doc: (path) => refOf(path),
    runTransaction(fn) {
      const run = lock.then(async () => {
        const pending = [];
        const tx = {
          get: async (ref) => snapshot(ref.path),
          getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
          set: (ref, data) => (pending.push(() => docs.set(ref.path, structuredClone(data))), tx),
          create: (ref, data) =>
            (pending.push(() => {
              if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
              docs.set(ref.path, structuredClone(data));
            }),
            tx),
          update: (ref, partial) => (pending.push(() => docs.set(ref.path, { ...docs.get(ref.path), ...structuredClone(partial) })), tx),
          delete: (ref) => (pending.push(() => docs.delete(ref.path)), tx),
        };
        const result = await fn(tx);
        for (const apply of pending) apply();
        return result;
      });
      lock = run.catch(() => {});
      return run;
    },
    terminate() {},
  };
  return db;
}

/**
 * 実resolverの組立て。strict=trueなら、resolver生成の前にConnectStorageへSourceStoreを結ぶ。
 * 返り値: {db, NS, hasher, connect, sources, provider, ctx, resolver, issue(ownerId), bind(grantId, binding), putSource(record), dispose}
 */
export function createResolverRuntime({ strict = true } = {}) {
  const project = 'demo-sttd-source-runtime';
  const issuer = 'https://connect.sttd-source.invalid';
  const resource = resourceFor(issuer);
  const clientId = 'https://client.sttd-source.invalid/client.json';
  const NS = `t256_${randomUUID()}`;
  const clock = { now: () => Date.now() };
  const db = syntheticFirestore();
  const hasher = createHmacHasher(randomBytes(32));
  const ctx = createRequestAuthContext({ clock });
  const box = createConnectKmsSealingPort({
    kms: { environment: 'local-test', projectId: project, databaseId: '(default)', namespace: NS, cryptoKey: `projects/${project}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`, writeVersion: 1, readVersions: [1], transport: syntheticKmsTransport(), clock },
    operation: ctx.current,
  });
  const connect = new ConnectStorage({ db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
  const sources = new SourceStore({ db, namespace: NS, clock });
  if (strict) connect.useSources(sources);
  const signingKey = { ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', kid: randomUUID() };
  const provider = createOAuthProvider({
    profile: {
      kind: 'connect-kms-development',
      issuer,
      adapter: connect.adapterFactory,
      jwks: { keys: [signingKey] },
      cookieKeys: [randomBytes(32)],
      client: { clientId, redirectUri: 'https://client.sttd-source.invalid/callback', jwksUri: 'https://client.sttd-source.invalid/jwks.json' },
      egress: {
        getJson: async () => {
          throw new Error('source-runtime: no egress');
        },
      },
      assertionReplay: connect.assertionReplay,
      clock,
    },
    policy: PRODUCT_POLICY,
    isOwnerActive: async () => true,
  });
  const resolver = createRequestScopedOAuthOwnerResolver({ provider, connect, context: ctx, resource });
  const op = () => ({ deadlineAt: Date.now() + 20_000, signal: new AbortController().signal });
  const root = `sttdConnect/${NS}`;
  return {
    db,
    NS,
    hasher,
    connect,
    sources,
    provider,
    ctx,
    resource,
    clientId,
    op,
    resolve: (token) => resolver(token, op()),
    addOwner() {
      const ownerId = randomUUID();
      // T232: 現行buildが作る通常login ownerの形（明示kind）。期限もkindも無い旧ownerは封緘UIDで判別される。
      db.docs.set(`${root}/owners/${ownerId}`, { identityHash: 'f'.repeat(64), sealedUid: 'sealed', createdAt: Date.now(), lastActiveAt: Date.now(), revokedAt: null, loginKind: 'normal' });
      return ownerId;
    },
    /** 公開SDK APIでslotの中からGrantとopaque access tokenを保存する。 */
    issue(ownerId) {
      return ctx.run(op(), async () => {
        const grant = new provider.Grant({ accountId: ownerId, clientId });
        grant.addResourceScope(resource, 'sttd:events');
        const grantId = await grant.save();
        const token = new provider.AccessToken({ accountId: ownerId, clientId, grantId, scope: 'sttd:events', aud: resource, gty: 'authorization_code' });
        return { value: await token.save(), grantId };
      });
    },
    /** 同意の最終txが作るのと同じbinding記録を置く（Grantの鍵付きhash）。 */
    bind(grantId, binding) {
      db.docs.set(`${root}/sourceGrants/${hasher.hash(`t256:${NS}:grant`, grantId)}`, { sourceId: binding.sourceId, generation: binding.generation });
    },
    dispose: () => ctx.dispose(),
  };
}

/**
 * 実connect server（startDevelopmentKmsConnectServer: 実Provider 9.12.2・JWKS・cookie・KMS封緘・ConnectStorage adapter・route handler）を、
 * 合成DB（where/limit/batch・updateTime）・合成AES-GCM KMS・合成本人verifier・固定CIMD文書だけを返すfake egressで起動する。
 * 本番のlisten境界（0.0.0.0/明示port）だけを試験内で局所interceptして127.0.0.1/port 0へ結び、起動後すぐrestoreする（製品codeは不変）。
 * 要求はNode HTTP clientで、元のhttps Host（設定のauthority）・Origin・cookieを付けて127.0.0.1へ送る。redirectは追わない。
 */
export async function startConnectHttpRuntime({ strict = true, transportAuthority, clientJwks = [], echoChallenge = false } = {}) {
  const net = await import('node:net');
  const http = await import('node:http');
  const { startDevelopmentKmsConnectServer } = await import('../../dist/connect/kms-server.js');
  const { CHATGPT_CIMD_CANDIDATE } = await import('../../dist/oauth/cimd.js');
  const { connectIdentityHash } = await import('../../dist/connect/firestore.js');
  const projectId = 'sttd-http-test';
  const issuer = 'https://connect.sttd-http.example.com';
  const authority = new URL(issuer).host;
  const NS = `t256_${randomUUID()}`;
  const SUB_NS = `t268_${randomUUID()}`;
  const docs = new Map();
  let tick = 0;
  const stamp = () => {
    tick += 1;
    const time = { seconds: 1_900_000_000 + tick, nanoseconds: tick };
    return { ...time, isEqual: (other) => other?.seconds === time.seconds && other?.nanoseconds === time.nanoseconds, toMillis: () => time.seconds * 1000 };
  };
  const write = (path, data) => docs.set(path, { data: structuredClone(data), updateTime: stamp() });
  const snapshot = (path) => {
    const entry = docs.get(path);
    return {
      id: path.split('/').pop(),
      ref: refOf(path),
      exists: entry !== undefined,
      updateTime: entry?.updateTime,
      get: (field) => entry?.data[field],
      data: () => (entry === undefined ? undefined : structuredClone(entry.data)),
    };
  };
  /** collection pathの直下の文書だけを、等値のwhere・limitで絞るquery。 */
  const queryOf = (collectionPath, filters = [], max = Infinity) => ({
    where: (field, op, value) => {
      if (op !== '==') throw new Error('synthetic query: only ==');
      return queryOf(collectionPath, [...filters, [field, value]], max);
    },
    limit: (n) => queryOf(collectionPath, filters, n),
    get: async () => {
      const matched = [...docs.keys()]
        .filter((path) => path.startsWith(`${collectionPath}/`) && !path.slice(collectionPath.length + 1).includes('/'))
        .filter((path) => filters.every(([field, value]) => docs.get(path).data[field] === value))
        .slice(0, max)
        .map(snapshot);
      return { docs: matched, empty: matched.length === 0, size: matched.length };
    },
  });
  const collectionOf = (path) => ({ doc: (id) => refOf(`${path}/${id}`), ...queryOf(path) });
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      set: async (data) => write(path, data),
      create: async (data) => {
        if (docs.has(path)) throw new Error('ALREADY_EXISTS');
        write(path, data);
      },
      update: async (partial) => {
        if (!docs.has(path)) throw new Error('NOT_FOUND');
        write(path, { ...docs.get(path).data, ...structuredClone(partial) });
      },
      delete: async () => void docs.delete(path),
      get: async () => snapshot(path),
    };
  }
  let lock = Promise.resolve();
  const db = {
    projectId,
    docs,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    batch() {
      const ops = [];
      const batch = {
        set: (ref, data) => (ops.push(() => write(ref.path, data)), batch),
        update: (ref, partial) => (ops.push(() => write(ref.path, { ...docs.get(ref.path)?.data, ...structuredClone(partial) })), batch),
        delete: (ref) => (ops.push(() => docs.delete(ref.path)), batch),
        commit: async () => {
          for (const op of ops) op();
          return [];
        },
      };
      return batch;
    },
    runTransaction(fn) {
      const run = lock.then(async () => {
        const pending = [];
        const tx = {
          get: async (ref) => snapshot(ref.path),
          getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
          set: (ref, data) => (pending.push(() => write(ref.path, data)), tx),
          create: (ref, data) =>
            (pending.push(() => {
              if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
              write(ref.path, data);
            }),
            tx),
          update: (ref, partial) =>
            (pending.push(() => {
              if (!docs.has(ref.path)) throw new Error('NOT_FOUND');
              write(ref.path, { ...docs.get(ref.path).data, ...structuredClone(partial) });
            }),
            tx),
          delete: (ref) => (pending.push(() => docs.delete(ref.path)), tx),
        };
        const result = await fn(tx);
        for (const apply of pending) apply();
        return result;
      });
      lock = run.catch(() => {});
      return run;
    },
  };
  const offset = { ms: 0 };
  const clock = { now: () => Date.now() + offset.ms };
  const cryptoKey = `projects/${projectId}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
  const kms = { environment: 'development', projectId, databaseId: '(default)', namespace: SUB_NS, cryptoKey, writeVersion: 1, readVersions: [1] };
  const policy = createKmsSubscriptionPolicy(kms);
  write(`sttdAuth/${SUB_NS}/config/kms-subscription`, kmsMarkerDocument(policy));
  const identifierKey = randomBytes(32);
  const hasher = createHmacHasher(identifierKey);
  const es = { ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig', kid: randomUUID() };
  const rs = { ...generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig', kid: randomUUID() };
  // 固定CIMD候補のclient metadata（cimd.tsのcreateAllowClientが要求する形）。jwksは要求されたら空集合。
  const cimdDocument = {
    client_id: CHATGPT_CIMD_CANDIDATE.clientId,
    client_name: 'ChatGPT',
    redirect_uris: [CHATGPT_CIMD_CANDIDATE.redirectUri],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks_uri: CHATGPT_CIMD_CANDIDATE.jwksUri,
  };
  const egressCalls = [];
  const challenges = [];
  const clientEgress = {
    getJson: async (url) => {
      egressCalls.push(url);
      if (url === CHATGPT_CIMD_CANDIDATE.clientId) return { status: 200, headers: {}, body: JSON.stringify(cimdDocument) };
      if (url === CHATGPT_CIMD_CANDIDATE.jwksUri) return { status: 200, headers: {}, body: JSON.stringify({ keys: clientJwks }) };
      throw new Error('synthetic egress: forbidden');
    },
  };
  // 合成本人verifier: `id-<uid>`の形のtokenを、このprojectのAppleの本人として検証済みにする（外部通信0）。
  const identity = {
    projectId,
    async verifyIdToken(token) {
      const match = /^id-([a-z0-9-]{1,40})$/.exec(token);
      if (!match) throw Object.assign(new Error('invalid'), { code: 'invalid' });
      return Object.freeze({ projectId, uid: match[1], authTimeSec: Math.floor(clock.now() / 1000) });
    },
    async accountStatus() {
      return 'active';
    },
  };
  // listen境界だけの局所intercept（0.0.0.0/明示port → 127.0.0.1/port 0）。起動後すぐrestoreする。
  const originalListen = net.Server.prototype.listen;
  let listened = null;
  net.Server.prototype.listen = function intercepted(port, host, callback) {
    listened = this;
    return originalListen.call(this, 0, '127.0.0.1', typeof host === 'function' ? host : callback);
  };
  let server;
  try {
    server = await startDevelopmentKmsConnectServer({
      bindPort: 18_080,
      db,
      namespace: NS,
      kms: { ...kms, transport: syntheticKmsTransport() },
      secrets: { load: async () => ({ jwks: { keys: [es, rs] }, cookieKeys: [randomBytes(32)], identifierKey: Buffer.from(identifierKey) }) },
      identity,
      web: { apiKey: 'synthetic-web-key', authDomain: `${projectId}.firebaseapp.com`, projectId },
      clientEgress,
      // 合成のcallback challenge（echoChallengeの時だけ受信先の正しい応答を返す。実HTTP 0）。
      verificationSender: async (request) => {
        challenges.push(request.url);
        return echoChallenge ? { status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) } : { status: 500, body: '' };
      },
      clock,
      publicOrigin: issuer,
      ...(transportAuthority !== undefined ? { transportAuthority } : {}),
      ...(strict ? { sourceAuthorization: { policy: { mode: 'strict-v1', methods: ['developer-key-v1'] }, projectNumber: '123456789012' } } : {}),
    });
  } finally {
    net.Server.prototype.listen = originalListen;
  }
  const port = listened.address().port;
  const sources = new SourceStore({ db, namespace: NS, clock });
  const root = `sttdConnect/${NS}`;

  /** 1つのbrowser（cookie jar）。元issuerのpathだけを127.0.0.1へ送る。 */
  const browser = ({ via = port } = {}) => {
    const jar = new Map();
    const store = (setCookie) => {
      for (const line of setCookie ?? []) {
        const [pair, ...attributes] = line.split(';').map((part) => part.trim());
        const index = pair.indexOf('=');
        const name = pair.slice(0, index);
        const value = pair.slice(index + 1);
        const path = attributes.find((attribute) => attribute.toLowerCase().startsWith('path='))?.slice(5) ?? '/';
        const expired = attributes.some((attribute) => /^expires=/i.test(attribute) && Date.parse(attribute.slice(8)) < Date.now()) || value === '';
        const key = `${name};${path}`;
        if (expired) jar.delete(key);
        else jar.set(key, { name, value, path });
      }
    };
    const cookieFor = (path) =>
      [...jar.values()]
        .filter((cookie) => path === cookie.path || path.startsWith(cookie.path.endsWith('/') ? cookie.path : `${cookie.path}/`))
        .map((cookie) => `${cookie.name}=${cookie.value}`)
        .join('; ');
    return {
      jar,
      request: (method, target, { headers = {}, body, cookies = true } = {}) =>
        new Promise((resolve, reject) => {
          const url = new URL(target, issuer);
          if (url.origin !== issuer) throw new Error('synthetic browser: only the original issuer is mapped to localhost');
          const path = `${url.pathname}${url.search}`;
          const cookie = cookies ? cookieFor(url.pathname) : '';
          const req = http.request(
            { host: '127.0.0.1', port: via, method, path, headers: { Host: authority, ...(cookie ? { Cookie: cookie } : {}), ...headers, ...(body !== undefined ? { 'Content-Length': Buffer.byteLength(body) } : {}) } },
            (res) => {
              const chunks = [];
              res.on('data', (chunk) => chunks.push(chunk));
              res.on('end', () => {
                if (cookies) store(res.headers['set-cookie']);
                resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
              });
            },
          );
          req.on('error', reject);
          if (body !== undefined) req.write(body);
          req.end();
        }),
    };
  };

  /** 利用許可と、その本人へ結んだ登録開発者source（connect操作）と鍵。 */
  const enrollPerson = async (uid) => {
    const identityHash = connectIdentityHash(hasher, NS, { projectId, uid });
    write(`${root}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: clock.now() });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const now = clock.now();
    const record = {
      schemaVersion: 1,
      sourceId: newSourceId(),
      kind: 'developer',
      state: 'active',
      generation: newSourceGeneration(),
      operations: ['connect'],
      publicKey: publicKey.export({ format: 'jwk' }).x,
      identityHash,
      expiresAt: null,
      createdAt: now,
      updatedAt: now,
    };
    if ((await sources.create(record)) !== 'created') throw new Error('synthetic source create failed');
    return { uid, idToken: `id-${uid}`, identityHash, record, privateKey };
  };

  return {
    issuer,
    authority,
    port,
    NS,
    SUB_NS,
    db,
    docs,
    write,
    offset,
    clock,
    hasher,
    sources,
    policy,
    egressCalls,
    challenges,
    root,
    browser,
    enrollPerson,
    close: () => server.close(),
  };
}

/**
 * 実購読保存（createKmsSubscriptionRegistrationRuntime → 実registration storeの最終tx）へ、sourceを結んだ実ConnectStorageを接合する
 * （test/mcp-subscriptions-runtime.test.mjsと同じ合成DB（updateTime付き・全読取り後の書込み）・合成AES-GCM・challengeをechoする合成sender）。
 * Grantは実ConnectStorageのGrant adapterで保存し、grantMetaとbindingは同意の最終txが作るのと同じ形で置く。callbackの実HTTP 0。
 */
export async function createSubscriptionRuntime() {
  const { createKmsSubscriptionRegistrationRuntime } = await import('../../dist/events/kms-subscription-runtime.js');
  const PROJECT = 'demo-sttd-source-subscriptions';
  const KEY = `projects/${PROJECT}/locations/asia-northeast1/keyRings/sttd/cryptoKeys/connect`;
  const RESOURCE = 'https://mcp.sttd-source.invalid/mcp';
  const NS = `t256_${randomUUID()}`;
  const SUB_NS = `t268_${randomUUID()}`;
  const docs = new Map();
  let tick = 0;
  const write = (path, data) => docs.set(path, { data: structuredClone(data), updateTime: { seconds: 1_900_000_000 + (tick += 1), nanoseconds: 1 + tick } });
  const snapshot = (path) => {
    const entry = docs.get(path);
    return { ref: refOf(path), id: path.split('/').pop(), exists: entry !== undefined, updateTime: entry === undefined ? undefined : { ...entry.updateTime }, data: () => (entry === undefined ? undefined : structuredClone(entry.data)) };
  };
  const collectionOf = (path) => ({ doc: (id) => refOf(`${path}/${id}`) });
  function refOf(path) {
    return {
      firestore: db,
      path,
      id: path.split('/').pop(),
      collection: (name) => collectionOf(`${path}/${name}`),
      set: async (data) => write(path, data),
      update: async (partial) => write(path, { ...docs.get(path)?.data, ...structuredClone(partial) }),
      delete: async () => void docs.delete(path),
      get: async () => snapshot(path),
    };
  }
  const db = {
    projectId: PROJECT,
    docs,
    collection: (name) => collectionOf(name),
    doc: (path) => refOf(path),
    async runTransaction(fn) {
      const writes = [];
      const tx = {
        get: async (ref) => snapshot(ref.path),
        getAll: async (...refs) => refs.map((ref) => snapshot(ref.path)),
        set: (ref, data) => (writes.push(['set', ref.path, structuredClone(data)]), tx),
        update: (ref, partial) => (writes.push(['update', ref.path, structuredClone(partial)]), tx),
        create: (ref, data) => (writes.push(['create', ref.path, structuredClone(data)]), tx),
        delete: (ref) => (writes.push(['delete', ref.path]), tx),
      };
      const result = await fn(tx);
      for (const [kind, path, data] of writes) {
        if (kind === 'update') write(path, { ...docs.get(path)?.data, ...data });
        else if (kind === 'delete') docs.delete(path);
        else write(path, data);
      }
      return result;
    },
    terminate() {},
  };
  const clock = { now: () => Date.now() };
  const transport = syntheticKmsTransport();
  const baseKms = { environment: 'local-test', projectId: PROJECT, databaseId: '(default)', cryptoKey: KEY, writeVersion: 1, readVersions: [1] };
  const box = createConnectKmsSealingPort({ kms: { ...baseKms, namespace: NS, transport, clock }, operation: () => ({ deadlineAt: Date.now() + 60_000 }) });
  const hasher = createHmacHasher(randomBytes(32));
  const connect = new ConnectStorage({ db, namespace: NS, hasher, box, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
  const sources = new SourceStore({ db, namespace: NS, clock });
  connect.useSources(sources);
  const policy = createKmsSubscriptionPolicy({ ...baseKms, namespace: SUB_NS });
  write(`sttdAuth/${SUB_NS}/config/kms-subscription`, kmsMarkerDocument(policy));
  const sent = [];
  const verificationSender = (request) => {
    sent.push(request.url);
    return Promise.resolve({ status: 200, body: JSON.stringify({ challenge: JSON.parse(request.body).challenge }) });
  };
  const runtime = createKmsSubscriptionRegistrationRuntime({ db, connect, connectNamespace: NS, resource: RESOURCE, kms: { ...baseKms, namespace: SUB_NS, transport }, hasher, clock, verificationSender });
  const grants = connect.adapterFactory('Grant');
  const root = `sttdConnect/${NS}`;
  /** owner・利用許可・実Grant（adapter保存）・grantMetaを置く。bindingは置かない（bindで置く）。 */
  const enroll = async () => {
    const ownerId = randomUUID();
    const identityHash = randomBytes(32).toString('hex');
    const generation = randomUUID();
    const now = Date.now();
    write(`${root}/owners/${ownerId}`, { identityHash, sealedUid: 'sealed-uid-synthetic', createdAt: now, lastActiveAt: now, revokedAt: null });
    write(`${root}/access/${identityHash}`, { version: 1, state: 'active', generation, updatedAt: now });
    const grantId = `grant-${randomBytes(9).toString('base64url')}`;
    const nowSec = Math.floor(now / 1000);
    await grants.upsert(grantId, { iat: nowSec, exp: nowSec + 3600, accountId: ownerId, clientId: 'https://client.sttd-source.invalid/meta.json', kind: 'Grant', jti: grantId, resources: { [RESOURCE]: 'sttd:events' } }, 3600);
    write(`${root}/grantMeta/${hasher.hash(`t256:${NS}:grant`, grantId)}`, { ownerId, authTimeSec: nowSec, createdAt: now, accessGeneration: generation });
    return { ownerId, grantId };
  };
  const bind = (grantId, binding) => write(`${root}/sourceGrants/${hasher.hash(`t256:${NS}:grant`, grantId)}`, { sourceId: binding.sourceId, generation: binding.generation });
  const op = () => ({ deadlineAt: Date.now() + 20_000, signal: new AbortController().signal });
  const subscribe = async (auth) => {
    try {
      return { ok: true, value: await runtime.service.subscribe(auth, { name: 'text.submitted', url: `https://hooks.sttd-source.example/${randomBytes(6).toString('hex')}`, secret: `whsec_${randomBytes(32).toString('base64')}` }, op()) };
    } catch (error) {
      return { ok: false, kind: error?.failure?.kind ?? error?.code ?? error?.name };
    }
  };
  const subscriptionOf = (ownerId) => docs.get(`sttdAuth/${SUB_NS}/subscriptions/${ownerId}`)?.data;
  // 通常MCPの受信状態照会（statusFor）を、同じ実ConnectStorage（sourceを結んだstrict）・同じ合成DBで組み立てる。
  const { createKmsConnectionSubscriptionView } = await import('../../dist/events/kms-subscription-view.js');
  const view = createKmsConnectionSubscriptionView({ db, connect, connectNamespace: NS, resource: RESOURCE, kms: { ...baseKms, namespace: SUB_NS, transport }, clock });
  const status = async (auth) => {
    try {
      return { ok: true, value: await view.statusFor(auth, op()) };
    } catch (error) {
      return { ok: false, kind: error?.code ?? error?.name };
    }
  };
  /** 全文書の版（照会の書込み0の確認）。 */
  const versions = () => JSON.stringify([...docs].map(([path, entry]) => [path, entry.updateTime]));
  return { db, docs, NS, sources, connect, sent, enroll, bind, subscribe, subscriptionOf, status, versions, close: () => (view.dispose(), runtime.close?.()) };
}

/**
 * 実KmsRequestDeliveryStore＋実KmsRequestDeliveryServiceの送出確定（test/encryption-commands.test.mjsのS01と同じ合成DB/txの組立て）へ、
 * strictのsource照合を接合する。owner/Grant/利用許可の判定はS01と同じ合成（常に有効）で、Grantのsource面だけは実ConnectStorage
 * （SourceStoreを結んだもの）のgrantSourceDocRef/grantSourceRecordRef/grantSourceDecisionを使う。API要求のsourceは実SourceGateの
 * dispatchCheckを実serviceのpostへ渡す。callbackの送出は合成sendへ記録するだけ（実egress・Dots 0）。txごとの読取り・書込みを記録する。
 */
export function createDeliveryRuntime({ audience = 'https://api.sttd-source.invalid', appCheck } = {}) {
  const BASE = Date.now();
  const clock = { t: BASE, now() { return this.t; } };
  const docs = new Map();
  const log = [];
  let seq = 0;
  const db = {
    docs,
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
        set: (ref, data) => (writes.push(['set', ref.path, structuredClone(data)]), tx),
        create: (ref, data) => (writes.push(['create', ref.path, structuredClone(data)]), tx),
        update: (ref, data) => (writes.push(['update', ref.path, structuredClone(data)]), tx),
        delete: (ref) => (writes.push(['delete', ref.path]), tx),
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
  const NS = `t256_${randomUUID()}`;
  const hasher = createHmacHasher(randomBytes(32));
  const hashKey = randomBytes(32);
  const hash = (purpose, value) => createHmac('sha256', hashKey).update(purpose).update('\0').update(value).digest('hex');
  const policy = createKmsSubscriptionPolicy({
    environment: 'development',
    projectId: 'synthetic-project',
    databaseId: '(default)',
    namespace: `t268_${randomUUID()}`,
    cryptoKey: 'projects/synthetic-project/locations/us-central1/keyRings/synthetic-ring/cryptoKeys/synthetic-key',
    writeVersion: 1,
    readVersions: [1],
  });
  const sources = new SourceStore({ db, namespace: NS, clock });
  const storage = new ConnectStorage({ db, namespace: NS, hasher, box: { seal: async () => 'x', open: async () => 'x' }, clock, ownerInactivityMs: 90 * DAY, interactionTtlMs: 300_000, grantInactivityMs: 90 * DAY });
  storage.useSources(sources);
  const root = `sttdConnect/${NS}`;
  const connect = {
    ownerDocRef: (ownerId) => refOf(`${root}/owners/${ownerId}`),
    grantDocRef: (grantId) => refOf(`${root}/grants/${grantId}`),
    ownerDocActive: (data) => data !== undefined && data.revokedAt === null,
    grantDocLive: () => true,
    accessDocRefForOwner: (data) => (typeof data?.identityHash === 'string' ? refOf(`${root}/access/${data.identityHash}`) : null),
    grantMetaDocRef: (grantId) => refOf(`${root}/grantMeta/${grantId}`),
    accessUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
    grantUseDecision: (access) => (access.exists && access.data.state === 'active' ? 'allowed' : 'denied'),
    // 実ConnectStorage（strict）のsource面。
    grantSourceDocRef: (grantId) => storage.grantSourceDocRef(grantId),
    grantSourceRecordRef: (binding) => storage.grantSourceRecordRef(binding),
    grantSourceDecision: (binding, source, now) => storage.grantSourceDecision(binding, source, now),
  };
  const store = new KmsRequestDeliveryStore({ db, namespace: `t270_${randomUUID()}`, connect, hash, clock, policy });
  docs.set(`sttdAuth/${policy.namespace}/config/kms-subscription`, kmsMarkerDocument(policy));
  const b64 = (buffer) => Buffer.from(buffer).toString('base64url');
  const capsule = () => `${KMS_CAPSULE_PREFIX}${b64(Buffer.from(JSON.stringify([kmsVersionName(policy.cryptoKey, 1), b64(randomBytes(48))]), 'utf8'))}`;
  const sent = [];
  let attempts = 0;
  const service = new KmsRequestDeliveryService({
    store,
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
  const gate = createSourceGate({
    policy: { mode: 'strict-v1', methods: appCheck === undefined ? ['developer-key-v1'] : ['developer-key-v1', 'app-check-v1'] },
    store: sources,
    hasher,
    namespace: NS,
    audience,
    clock,
    ...(appCheck !== undefined ? { appCheck } : {}),
  });
  /** 有効な購読のある本人（購読はgrantIdのGrantに束縛）。 */
  const enroll = () => {
    const ownerId = randomUUID();
    const identityHash = randomBytes(32).toString('hex');
    const grantId = `grant-${ownerId}`;
    docs.set(`${root}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: BASE });
    docs.set(`${root}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: BASE, lastActiveAt: BASE, revokedAt: null });
    const subscriptionId = `sub_${hash('subscription', ownerId)}`;
    docs.set(
      `sttdAuth/${policy.namespace}/subscriptions/${ownerId}`,
      kmsStateDocument(ownerId, {
        active: { id: subscriptionId, ownerId, grantId, sealedUrl: capsule(), sealedSecret: capsule(), secretHash: 'c'.repeat(64), previousSecret: null, expiresAt: null },
        knownDestinationId: subscriptionId,
        pending: null,
        lastEnded: null,
      }),
    );
    return { ownerId, grantId };
  };
  /** 同意の最終txが作るのと同じGrantのbinding記録。 */
  const bindGrant = (grantId, binding) => docs.set(`${root}/sourceGrants/${hasher.hash(`t256:${NS}:grant`, grantId)}`, { sourceId: binding.sourceId, generation: binding.generation });
  const iso = (ms) => new Date(ms).toISOString();
  /** 平文の送信（実serviceのpost）。requestBindingがあれば実gateのdispatchCheckを送出確定txへ渡す。 */
  const post = (owner, requestBinding) => {
    const commandId = randomUUID();
    const body = Buffer.from(JSON.stringify({ schemaVersion: 2, commandId, text: 'synthetic', createdAt: iso(clock.t), expiresAt: iso(clock.t + 60_000) }));
    const operation = Object.freeze({ deadlineAt: clock.t + 20_000, signal: new AbortController().signal });
    return requestBinding === undefined
      ? service.post(owner.ownerId, commandId, body, clock.t, operation)
      : service.post(owner.ownerId, commandId, body, clock.t, operation, gate.dispatchCheck(requestBinding, 'send'));
  };
  return { db, docs, log, clock, NS, hasher, sources, storage, gate, service, sent, enroll, bindGrant, post };
}
