// 送信API entry（dist/deployment/functions.js）→ bootstrap（dist/google-runtime/delivery-development.js）→ SDK factory
// （dist/google-runtime/development.js。外部SDK portだけrequire cacheの代替）の通常経路のunit。
//   - SDK env gate（bounded memory hint・拒否名・identity）、標準起動・未認証401、固定503とdiagnostic mask、共有startと失敗latch、要求中断・
//     close・元期限、secret・markerの失敗後清掃とsecret bufferの消去、timer・signal listener・envの復元を確かめる。
//   - process.envはその呼出しの間だけ合成Proxyへ置き換え、finallyで必ず元へ戻す（製品のenv変更0・子process 0）。
//   - 実socket・DNS・HTTP(S)・HTTP/2・TLS・fetch・listen・metadata・実SDK RPC・資格readは0（拒否して数え、0であることをassert）。
//   - L01/L02（末尾）: 本文暗号化を有効にした合成配置の隔離copyで、同じSDK代替を通して起動時の専用secret読取り0・最初のGETでの遅延読取りと
//     ring初期化・close後の503を確かめる（SDK代替のin-memory transaction・合成token・専用secretはこの群のplanだけで有効）。

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import dns from 'node:dns';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import Module, { createRequire } from 'node:module';
import net, { Server } from 'node:net';
import { after, test } from 'node:test';
import tls from 'node:tls';

const DEV_URL = new URL('../dist/google-runtime/development.js', import.meta.url);
const requireFromDev = createRequire(DEV_URL);
const LIMITS = Object.freeze({ groups: 9, port: 5000, fixtureBytes: 2 * 1024 * 1024 });
const used = { groups: 0, port: 0, fixtureBytes: 0, sdkSets: 0, computes: 0 };
const results = {};
function take(kind, amount = 1) {
  if (used[kind] + amount > LIMITS[kind]) throw new Error(`api-entry ${kind} budget`);
  used[kind] += amount;
}
const group = (name, fn) => test(name, { timeout: 60_000 }, async () => (take('groups'), fn()));
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, label, ms = 15_000) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > ms) throw new Error(`wait limit: ${label}`);
    await sleep(5);
  }
}

// ---------- 通信の拒否（全て0であること）・listenの拒否 ----------
const net0 = { refused: 0 };
const refuse = () => {
  net0.refused += 1;
  throw new Error('api-entry: network refused');
};
const originals = {
  connect: net.Socket.prototype.connect,
  lookup: dns.lookup,
  promisesLookup: dns.promises.lookup,
  httpRequest: http.request,
  httpGet: http.get,
  httpsRequest: https.request,
  httpsGet: https.get,
  tlsConnect: tls.connect,
  http2Connect: http2.connect,
  fetch: globalThis.fetch,
  listen: Server.prototype.listen,
};
net.Socket.prototype.connect = refuse;
dns.lookup = refuse;
dns.promises.lookup = async () => refuse();
http.request = refuse;
http.get = refuse;
https.request = refuse;
https.get = refuse;
tls.connect = refuse;
http2.connect = refuse;
globalThis.fetch = async () => refuse();
Server.prototype.listen = refuse;
function restoreNetwork() {
  net.Socket.prototype.connect = originals.connect;
  dns.lookup = originals.lookup;
  dns.promises.lookup = originals.promisesLookup;
  Object.assign(http, { request: originals.httpRequest, get: originals.httpGet });
  Object.assign(https, { request: originals.httpsRequest, get: originals.httpsGet });
  tls.connect = originals.tlsConnect;
  http2.connect = originals.http2Connect;
  globalThis.fetch = originals.fetch;
  Server.prototype.listen = originals.listen;
}
const baselineSignals = { SIGTERM: process.listeners('SIGTERM'), SIGINT: process.listeners('SIGINT') };
const addedSignalListeners = (name) => process.listeners(name).filter((listener) => !baselineSignals[name].includes(listener));

// ---------- 実moduleを先に読み込む（実firebase-admin・実Firestoreへ束縛）。その後でSDK代替をrequire cacheへ置く ----------
for (const path of [
  '../dist/connect/firestore.js',
  '../dist/connect/kms-port.js',
  '../dist/connect/kms-server.js',
  '../dist/connect/google-kms-server.js',
  '../dist/delivery/kms-functions.js',
  '../dist/delivery/kms-store.js',
  '../dist/egress/product.js',
  '../dist/keys/google-secret-reader.js',
  '../dist/oauth/request-auth-runtime.js',
  '../dist/protection/google-kms-transport.js',
  '../dist/identity/firebase.js',
]) {
  await import(path);
}
const { crc32c } = await import('../dist/protection/kms-sealing.js');
const { createKmsSubscriptionPolicy, kmsMarkerDocument } = await import('../dist/storage/firestore/kms-subscription-format.js');
// 配置設定はscripts/run-tests.mjsが一時copyへ置いた合成の設定済み値（validateDeploymentConfigを通ったもの）。
const { loadDeploymentConfig } = await import('../dist/config/validate.js');
const M = loadDeploymentConfig();

let plan = {};
const docs = new Map();
const events = [];
const rpc = { access: [], returned: [], pending: 0, transactions: 0, crypto: 0, markerReads: 0 };
const clone = (value) => (value === undefined ? undefined : structuredClone(value));

class FakeCompute {
  constructor(opts) {
    take('port');
    used.computes += 1;
    this.opts = opts;
    this.credentials = {};
  }
  async getAccessToken() {
    take('port');
    throw new Error('no token in this unit');
  }
}
class FakeGoogleAuth {
  constructor(opts) {
    take('port');
    this.opts = opts;
  }
}
class Snapshot {
  constructor(ref, entry) {
    this.ref = ref;
    this.id = ref.id;
    this.exists = entry !== undefined;
    this._data = entry === undefined ? undefined : clone(entry);
  }
  data() {
    return clone(this._data);
  }
}
class DocRef {
  constructor(db, path) {
    this.firestore = db;
    this.path = path;
    this.id = path.slice(path.lastIndexOf('/') + 1);
  }
  collection(name) {
    return new CollRef(this.firestore, `${this.path}/${name}`);
  }
  async get() {
    take('port');
    rpc.markerReads += 1;
    // 共有startの途中で要求の中断を確かめるための試験内だけの遅延（既定0）。
    if (plan.markerDelayMs) await sleep(plan.markerDelayMs);
    if (plan.marker === 'reject') throw new Error('api-entry marker read failure FIXTURE-SECRET-MSG');
    if (plan.marker === 'missing') return new Snapshot(this, undefined);
    if (plan.marker === 'wrong') return new Snapshot(this, { unexpected: true });
    return new Snapshot(this, docs.get(this.path));
  }
}
class CollRef {
  constructor(db, path) {
    this.firestore = db;
    this.path = path;
  }
  doc(id) {
    return new DocRef(this.firestore, `${this.path}/${id}`);
  }
}
class FakeFirestore {
  constructor(settings) {
    take('port');
    used.sdkSets += 1;
    this.settings = settings;
  }
  collection(name) {
    return new CollRef(this, name);
  }
  /** 既存kms-runtimeが組立て前に存在だけを要求する（methodOf）。この試験では呼ばれない（呼ばれたら数えて投げる）。 */
  runTransaction(fn) {
    take('port');
    rpc.transactions += 1;
    // 本文暗号化の有効構成（L01/L02）だけ: docsの上のin-memory transaction。それ以外の群では従来どおり使わない（投げる）。
    if (plan.memoryTx !== true) throw new Error('api-entry: transactions are not used in this unit');
    const writes = [];
    const tx = {
      get: async (ref) => new Snapshot(ref, docs.get(ref.path)),
      getAll: async (...refs) => refs.map((ref) => new Snapshot(ref, docs.get(ref.path))),
      set: (ref, data) => (writes.push([ref.path, clone(data), false]), tx),
      create: (ref, data) => (writes.push([ref.path, clone(data), false]), tx),
      update: (ref, data) => (writes.push([ref.path, clone(data), true]), tx),
    };
    return Promise.resolve(fn(tx)).then((result) => {
      for (const [path, data, merge] of writes) docs.set(path, merge ? { ...docs.get(path), ...data } : data);
      return result;
    });
  }
  terminate() {
    take('port');
    events.push('sdk.terminate');
    if (plan.terminateReject) return Promise.reject(new Error('terminate failure'));
    return Promise.resolve();
  }
}
function gaxPromise(produce) {
  const promise = produce();
  Object.defineProperty(promise, 'cancel', { value: () => {}, writable: true, configurable: true, enumerable: false });
  return promise;
}
const PAYLOADS = { identifierKey: randomBytes(32), commandDigestKey: randomBytes(32) };
take('fixtureBytes', 64);
const SECRET_HEX = Object.values(PAYLOADS).map((buffer) => buffer.toString('hex'));
const purposeOf = (name) => Object.keys(M.secretVersions).find((purpose) => M.secretVersions[purpose] === name);
function gapic(kind, subs, innerApiCalls) {
  return class {
    constructor(opts) {
      take('port');
      const client = { opts };
      for (const [property, stubProperty] of subs) client[property] = { [stubProperty]: undefined };
      client.initialize = () => {
        take('port');
        if (plan[`${kind}Init`] === 'reject') return Promise.reject(new Error(`${kind} initialize failure FIXTURE-SECRET-MSG`));
        client.innerApiCalls = innerApiCalls();
        return Promise.resolve({ close: () => {} });
      };
      client.close = () => {
        take('port');
        events.push(`sdk.${kind}.close`);
        return Promise.resolve();
      };
      return client;
    }
  };
}
const FakeKms = gapic(
  'kms',
  [
    ['iamClient', 'iamPolicyStub'],
    ['locationsClient', 'locationsStub'],
    ['operationsClient', 'operationsStub'],
  ],
  () => ({
    encrypt: () => ((rpc.crypto += 1), gaxPromise(() => Promise.reject(new Error('unused')))),
    decrypt: () => ((rpc.crypto += 1), gaxPromise(() => Promise.reject(new Error('unused')))),
  }),
);
const FakeSecrets = gapic('secrets', [['locationsClient', 'locationsStub']], () => ({
  accessSecretVersion: (request) => {
    take('port');
    // 本文暗号化の有効構成（L01/L02）の専用secretの固定版だけ。読取りを数え、43文字の合成payloadを返す。
    if (plan.encryptionSecret !== undefined && request.name === plan.encryptionSecret.name) {
      plan.encryptionSecret.reads += 1;
      const data = Buffer.from(plan.encryptionSecret.value, 'latin1');
      return gaxPromise(() => Promise.resolve([{ name: request.name, payload: { data, dataCrc32c: crc32c(data) } }, undefined, undefined]));
    }
    const purpose = purposeOf(request.name);
    rpc.access.push(purpose);
    const mode = plan.secret?.[purpose];
    if (mode === 'reject') return gaxPromise(() => Promise.reject(new Error('api-entry secret read failure FIXTURE-SECRET-MSG')));
    if (mode === 'hang') {
      rpc.pending += 1;
      return gaxPromise(() => new Promise(() => {}));
    }
    const source = mode === 'same' ? PAYLOADS.identifierKey : PAYLOADS[purpose];
    const data = Buffer.from(source);
    rpc.returned.push(data);
    return gaxPromise(() => Promise.resolve([{ name: request.name, payload: { data, dataCrc32c: crc32c(data) } }, undefined, undefined]));
  },
}));
const fakeAuth = {
  async verifyIdToken(token) {
    take('port');
    // 本文暗号化の有効構成（L01/L02）だけ: 合成の検証済みtoken。それ以外は従来どおり拒否。
    if (typeof plan.idToken === 'function') return plan.idToken(token);
    throw Object.assign(new Error('invalid'), { code: 'auth/invalid-id-token' });
  },
  async getUser() {
    throw new Error('getUser is not used in this unit');
  },
};
const admin = { apps: [], deleted: [] };
const fakeAdminApp = {
  initializeApp(options, name) {
    take('port');
    const app = { name, options };
    admin.apps.push(app);
    return app;
  },
  deleteApp(app) {
    take('port');
    events.push('sdk.deleteApp');
    admin.deleted.push(app);
    return Promise.resolve();
  },
};
const fakeAdminAuth = {
  getAuth() {
    take('port');
    return fakeAuth;
  },
};
/** SDK代替を置く前のrequire cache。 */
const cacheBefore = new Map();
const install = (name, exports) => {
  const filename = requireFromDev.resolve(name);
  cacheBefore.set(filename, Module._cache[filename]);
  const fake = new Module(filename);
  fake.filename = filename;
  fake.loaded = true;
  fake.exports = exports;
  Module._cache[filename] = fake;
};
install('google-gax', { googleAuthLibrary: { Compute: FakeCompute }, GoogleAuth: FakeGoogleAuth });
install('@google-cloud/firestore', { Firestore: FakeFirestore });
install('@google-cloud/kms', { KeyManagementServiceClient: FakeKms });
install('@google-cloud/secret-manager', { SecretManagerServiceClient: FakeSecrets });
install('firebase-admin/app', fakeAdminApp);
install('firebase-admin/auth', fakeAdminAuth);

const bootstrap = await import('../dist/google-runtime/delivery-development.js');
const MARKER_PATH = `sttdAuth/${M.kms.namespace}/config/kms-subscription`;
docs.set(MARKER_PATH, kmsMarkerDocument(createKmsSubscriptionPolicy({ ...M.kms, readVersions: [...M.kms.readVersions] })));
const docsBefore = JSON.stringify([...docs.entries()]);
process.env.K_SERVICE = M.api.serviceName;
process.env.K_REVISION = `${M.api.serviceName}-00001-api-entry`;
process.env.K_CONFIGURATION = M.api.serviceName;

// ---------- 合成HTTP（実socket 0。entryのhandlerへ直接渡す） ----------
function exchange(method = 'GET', url = '/v1/api-entry-unknown') {
  take('port');
  const req = new EventEmitter();
  Object.assign(req, { method, url, headers: { host: 'api.invalid' }, rawHeaders: ['Host', 'api.invalid'], aborted: false, destroyed: false, complete: true });
  const res = new EventEmitter();
  Object.assign(res, {
    statusCode: 200,
    destroyed: false,
    writableEnded: false,
    headersSent: false,
    writableFinished: false,
    head: {},
    body: null,
    setHeader(name, value) {
      this.head[String(name).toLowerCase()] = value;
    },
    getHeader(name) {
      return this.head[String(name).toLowerCase()];
    },
    writeHead(status, headers = {}) {
      this.statusCode = status;
      this.headersSent = true;
      for (const [name, value] of Object.entries(headers)) this.head[name.toLowerCase()] = value;
      return this;
    },
    end(body) {
      this.body = body === undefined ? Buffer.alloc(0) : Buffer.from(body);
      this.writableEnded = true;
      this.writableFinished = true;
      this.emit('finish');
      this.emit('close');
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    send(body) {
      return this.end(String(body));
    },
  });
  return { req, res };
}
const UNAVAILABLE = { error: { code: 'temporarily_unavailable', retryable: true } };
const UNAVAILABLE_BYTES = JSON.stringify(UNAVAILABLE);
const AUTH = JSON.stringify({ error: { code: 'authentication_required', retryable: false } });
/** stderrへの書込みを記録する（throwOnWriteなら記録した後に同期で例外）。console.error/warnもstderrへ来る。 */
function captureStderr(throwOnWrite = false) {
  const lines = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk) => {
    lines.push(String(chunk));
    if (throwOnWrite) throw new Error('api-entry stderr sink failure');
    return true;
  };
  return { lines, restore: () => (process.stderr.write = original) };
}
const START_LINE = (stage, code) => `{"event":"sttd_api.start_failed","stage":"${stage}","code":"${code}"}\n`;
const MASK_LINE = (mask) => `{"event":"sttd_api.start_failed","stage":"sdk","code":"environment_rejected","environmentGateMask":${mask}}\n`;
const startLines = (lines) => lines.filter((line) => line.includes('sttd_api.start_failed'));
const FORBIDDEN = [
  'FIXTURE-SECRET-MSG',
  'FIXTURE-VALUE',
  'Error',
  'stack',
  'cause',
  M.kms.namespace,
  M.connectNamespace,
  M.deliveryNamespace,
  M.api.serviceName,
  M.connect.serviceName,
  M.projectNumber,
  'secrets/',
  'NODE_OPTIONS',
  'max-old-space-size',
  'GRPC_TRACE',
  'Bad_Revision',
  'Bad_Configuration',
  'other-project',
  'otherservice',
  ...SECRET_HEX,
];
/** 固定start_failed行だけに追加で禁じる印（環境名の断片・flag語）。 */
const START_FORBIDDEN = ['inspect', 'PROXY', 'K_SERVICE', 'K_REVISION', 'K_CONFIGURATION', 'PROJECT'];
const leaks = (lines) => [...FORBIDDEN.filter((mark) => lines.some((line) => line.includes(mark))), ...START_FORBIDDEN.filter((mark) => startLines(lines).some((line) => line.includes(mark)))];
const CLOSE_NAMES = ['sdk.terminate', 'sdk.deleteApp', 'sdk.kms.close', 'sdk.secrets.close'];
const closeCounts = (slice) => CLOSE_NAMES.map((name) => slice.filter((event) => event === name).length);
/** このinstanceが足したSIGTERM listenerを1回だけ呼び、解除までを待つ（closeの記録もcaptureする）。 */
async function closeInstance(known) {
  const term = addedSignalListeners('SIGTERM').filter((listener) => !known.includes(listener));
  for (const listener of term) listener('SIGTERM');
  await until(() => addedSignalListeners('SIGTERM').every((listener) => known.includes(listener)), 'listeners released');
  await sleep(10);
}
const optionsFor = (overrides = {}) => ({
  projectId: M.projectId,
  projectNumber: M.projectNumber,
  databaseId: M.databaseId,
  expectedServiceName: M.api.serviceName,
  connectNamespace: M.connectNamespace,
  deliveryNamespace: M.deliveryNamespace,
  kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
  secretVersions: { ...M.secretVersions },
  clock: { now: () => Date.now() },
  operation: { deadlineAt: Date.now() + 20_000, signal: new AbortController().signal },
  ingress: () => {
    throw new Error('not called at startup');
  },
  ...overrides,
});
const exitCodeAtStart = process.exitCode;

after(async () => {
  for (const name of ['K_SERVICE', 'K_REVISION', 'K_CONFIGURATION']) delete process.env[name];
  restoreNetwork();
  await sleep(30);
  process.stdout.write(`# API_ENTRY_COUNTS ${JSON.stringify({ limits: LIMITS, used, results, refused: net0.refused, access: rpc.access.length, apps: admin.apps.length, deleted: admin.deleted.length, addedSIGTERM: addedSignalListeners('SIGTERM').length, addedSIGINT: addedSignalListeners('SIGINT').length, envSwaps, unhandled })}\n`);
  assert.equal(net0.refused, 0, 'no socket/DNS/HTTP/TLS/HTTP2/fetch/listen attempt');
  assert.equal(JSON.stringify([...docs.entries()]), docsBefore, 'no document written (marker untouched)');
  assert.equal(admin.apps.length, admin.deleted.length, 'every owned admin app deleted');
  assert.deepEqual([addedSignalListeners('SIGTERM').length, addedSignalListeners('SIGINT').length], [0, 0], 'every signal listener released');
  assert.equal(unhandled, 0);
  assert.equal(process.exitCode, exitCodeAtStart);
});

// ---------- 直接factory・直接bootstrap・実entryで使う合成env（Proxy・値読取り/列挙/getterの記録） ----------
const dev = await import('../dist/google-runtime/development.js');
const API = M.api.serviceName;
const MCP = M.connect.serviceName;
const STRICT = '--max-old-space-size=960';
const SDK_MESSAGE = 'development google sdk: environment_rejected';
/** 存在拒否名のうちNODE_OPTIONS以外の33（製品の固定listをtextで写した。値を読まないことをProxy・getterで確かめる）。 */
const OTHER_REFUSED = Object.freeze([
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_OAUTH_ACCESS_TOKEN',
  'CLOUDSDK_AUTH_ACCESS_TOKEN',
  'FIREBASE_TOKEN',
  'GOOGLE_API_KEY',
  'GOOGLE_CLOUD_QUOTA_PROJECT',
  'GOOGLE_CLOUD_UNIVERSE_DOMAIN',
  'GOOGLE_API_USE_MTLS_ENDPOINT',
  'GOOGLE_API_USE_CLIENT_CERTIFICATE',
  'GOOGLE_SDK_NODE_LOGGING',
  'FIRESTORE_EMULATOR_HOST',
  'FIREBASE_AUTH_EMULATOR_HOST',
  'FIREBASE_DATABASE_EMULATOR_HOST',
  'STORAGE_EMULATOR_HOST',
  'FIRESTORE_PREFER_REST',
  'FIRESTORE_ENABLE_TRACING',
  'GCE_METADATA_HOST',
  'GCE_METADATA_IP',
  'METADATA_SERVER_DETECTION',
  'DETECT_GCP_RETRIES',
  'GRPC_TRACE',
  'GRPC_VERBOSITY',
  'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
  'NODE_DEBUG',
  'NODE_EXTRA_CA_CERTS',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'OPENSSL_CONF',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'GRPC_PROXY_EXP',
]);
/** 大小文字違いの拒否名（7。合計40）。 */
const CASE_REFUSED = Object.freeze(['grpc_trace', 'http_proxy', 'Https_Proxy', 'all_proxy', 'node_debug', 'ssl_cert_file', 'Gce_Metadata_Host']);
const IDENTITY = Object.freeze(['K_SERVICE', 'K_REVISION', 'K_CONFIGURATION', 'GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']);
/** gateが値を読んでよい名前（正規名NODE_OPTIONSと固定identity 5）。他の拒否名はreads.includesで個別に未読を確かめる。 */
const GATE_NAMES = new Set(['NODE_OPTIONS', ...IDENTITY]);
const identityEnv = (service) => ({ K_SERVICE: service, K_REVISION: `${service}-00001-api-entry`, K_CONFIGURATION: service });
let envSwaps = 0;
/**
 * 合成env（base＋extra。extraのundefinedはkeyを消す）。accessorsはgetterで定義し呼出しを数える。throwOnはそのnameのgetで例外、throwKeysは列挙で例外。
 * readsはProxyのgetで読まれた名前（値を読んだ印）、keysはownKeysの回数（gate評価の回数）。
 */
function makeEnv(base, extra = {}, { accessors = {}, throwOn = null, throwKeys = false } = {}) {
  const target = { ...base };
  for (const [name, value] of Object.entries(extra)) {
    if (value === undefined) delete target[name];
    else target[name] = value;
  }
  const probe = { reads: [], keys: 0, getters: 0 };
  for (const [name, value] of Object.entries(accessors)) {
    Object.defineProperty(target, name, {
      get() {
        probe.getters += 1;
        return value;
      },
      enumerable: true,
      configurable: true,
    });
  }
  const proxy = new Proxy(target, {
    get(object, property, receiver) {
      if (typeof property === 'string') {
        probe.reads.push(property);
        if (property === throwOn) throw new Error('api-entry env read failure FIXTURE-SECRET-MSG');
      }
      return Reflect.get(object, property, receiver);
    },
    ownKeys(object) {
      probe.keys += 1;
      if (throwKeys) throw new Error('api-entry env keys failure FIXTURE-SECRET-MSG');
      return Reflect.ownKeys(object);
    },
  });
  return { proxy, probe };
}
/** process.envをfnの間だけ合成Proxyへ置き換える（finallyで必ず元へ戻す）。 */
async function withEnv(env, fn) {
  const real = process.env;
  envSwaps += 1;
  process.env = env.proxy;
  try {
    return await fn();
  } finally {
    process.env = real;
    assert.equal(process.env, real, 'process.env restored');
  }
}
const ownMask = (holder) => {
  const descriptor = holder === null || holder === undefined ? undefined : Object.getOwnPropertyDescriptor(holder, 'environmentGateMask');
  return descriptor === undefined ? undefined : descriptor.value;
};
/** 合成envだけで実factoryを1回開く（成功ならenvを戻してから1回close）。 */
async function openWith(service, extra = {}, envOptions = {}) {
  const env = makeEnv(identityEnv(service), extra, envOptions);
  const real = process.env;
  const sets = used.sdkSets;
  const computes = used.computes;
  const before = events.length;
  let outcome;
  let error = null;
  envSwaps += 1;
  process.env = env.proxy;
  try {
    const sdk = await dev.openDevelopmentGoogleSdk({ projectId: M.projectId, databaseId: M.databaseId, expectedServiceName: service, clock: { now: () => Date.now() }, operation: { deadlineAt: Date.now() + 20_000, signal: new AbortController().signal } });
    process.env = real;
    await sdk.close();
    outcome = 'ok';
  } catch (caught) {
    error = caught;
    outcome = caught instanceof dev.DevelopmentGoogleSdkError ? caught.code : 'unexpected';
  } finally {
    process.env = real;
  }
  assert.equal(process.env, real, 'process.env restored');
  return {
    outcome,
    error,
    mask: ownMask(error),
    hasMask: error !== null && Object.hasOwn(error, 'environmentGateMask'),
    message: error?.message ?? null,
    sets: used.sdkSets - sets,
    computes: used.computes - computes,
    closes: closeCounts(events.slice(before)),
    reads: env.probe.reads,
    gateReads: env.probe.reads.filter((name) => GATE_NAMES.has(name)),
    getters: env.probe.getters,
    keys: env.probe.keys,
  };
}
/** errorが外へ出し得る文字列（message・stack・JSON・own値）。 */
const errorText = (error) => [String(error?.message), String(error?.stack), JSON.stringify(error), ...Object.getOwnPropertyNames(error ?? {}).map((name) => String(error[name]))];
const realEnvKeysBefore = JSON.stringify(Object.keys(process.env).sort());
const baseEnv = () => Object.fromEntries(Object.entries(process.env));
const bodySha = (body) => createHash('sha256').update(body ?? Buffer.alloc(0)).digest('hex');

/** 未認証のPOST /v2/commands（JSON本文あり・Authorizationなし・Originなし＝native要求）。 */
function postExchange() {
  const pair = exchange('POST', '/v2/commands');
  pair.req.headers['content-type'] = 'application/json';
  pair.req.rawHeaders.push('Content-Type', 'application/json');
  pair.req.rawBody = Buffer.from('{}', 'utf8');
  return pair;
}
/**
 * fresh entry instance（moduleのstateは各importで別）を合成envの間だけ通す: 同時要求→SIGTERMでclose。stderrを記録する。
 * revisionReadsはK_REVISIONのget回数（firebase-functionsはこの名前を読まないので、SDK gateの評価回数＝共有初期化の回数）。
 */
async function entryCase(name, extra, { requests = 3, post = false, throwOnWrite = false, setup = {}, envOptions = {}, entry = ENTRY } = {}) {
  const env = makeEnv(baseEnv(), extra, envOptions);
  const known = addedSignalListeners('SIGTERM');
  const before = events.length;
  const sets = used.sdkSets;
  const computes = used.computes;
  const stderr = captureStderr(throwOnWrite);
  let replies;
  let closes;
  const started = Date.now();
  let elapsedMs;
  plan = setup;
  try {
    await withEnv(env, async () => {
      const instance = await import(`${entry}?api-entry=${name}`);
      const pairs = Array.from({ length: requests }, () => (post ? postExchange() : exchange('GET')));
      await Promise.all(pairs.map(({ req, res }) => instance.sendtexttodotsapi(req, res)));
      elapsedMs = Date.now() - started;
      replies = pairs.map(({ res }) => ({ status: res.statusCode, text: res.body === null ? null : res.body.toString('utf8'), sha: bodySha(res.body), head: JSON.stringify(res.head), cache: res.head['cache-control'] }));
      const since = events.length;
      await closeInstance(known);
      closes = closeCounts(events.slice(since));
    });
  } finally {
    stderr.restore();
    plan = {};
  }
  return {
    replies,
    elapsedMs,
    starts: startLines(stderr.lines),
    lines: stderr.lines,
    sets: used.sdkSets - sets,
    computes: used.computes - computes,
    closes,
    startupCloses: closeCounts(events.slice(before)),
    revisionReads: env.probe.reads.filter((read) => read === 'K_REVISION').length,
    keys: env.probe.keys,
    getters: env.probe.getters,
  };
}
const unavailableAll = (item) => item.replies.every((reply) => reply.status === 503 && reply.text === UNAVAILABLE_BYTES && reply.cache === 'no-store');
const noMaskInHttp = (item) => item.replies.every((reply) => !reply.head.includes('environmentGateMask') && !String(reply.text).includes('environmentGateMask'));

const ENTRY = '../dist/deployment/functions.js';
const flag = (n) => `--max-old-space-size=${n}`;
const noIngress = (options) => {
  const { ingress: _ingress, ...rest } = options;
  return rest;
};
/** 合成envの間だけbootstrapを直接呼ぶ（成功ならcloseまで）。戻り値は固定形の配列だけ（error本体は返さない）。 */
async function boot(options, extra = {}) {
  const env = makeEnv(baseEnv(), extra);
  const sets = used.sdkSets;
  const before = events.length;
  const access = rpc.access.length;
  const markers = rpc.markerReads;
  return withEnv(env, async () => {
    try {
      const ready = await bootstrap.startOwnedIngressDevelopmentDeliveryFunction(options);
      const closed = events.length;
      await ready.close();
      return ['ok', null, used.sdkSets - sets, closeCounts(events.slice(closed)), rpc.access.length - access, rpc.markerReads - markers];
    } catch (error) {
      const diagnostic = error?.diagnostic === undefined ? null : { ...error.diagnostic };
      return [error?.name ?? 'unknown', diagnostic, used.sdkSets - sets, closeCounts(events.slice(before)), rpc.access.length - access, rpc.markerReads - markers];
    }
  });
}
const diag = (stage, code, mask) => (mask === undefined ? { stage, code } : { stage, code, environmentGateMask: mask });

group('A1 bootstrap → real SDK factory: bounded memory hints (512, 128, 960, empty) open and close every SDK once, 961 and --inspect are {sdk, environment_rejected, mask 1}; another service, a missing ingress, an extra field and a getter field are {config, config_invalid} before any SDK, secret, marker or clock call', async () => {
  const ok = ['ok', null, 1, [1, 1, 1, 1], 2, 1];
  const refused = ['OwnedDevelopmentDeliveryConfigError', diag('sdk', 'environment_rejected', 1), 0, [0, 0, 0, 0], 0, 0];
  const rows = {};
  for (const [name, value] of Object.entries({ f512: flag(512), f128: flag(128), f960: STRICT, empty: '' })) rows[name] = await boot(optionsFor(), { NODE_OPTIONS: value });
  for (const [name, value] of Object.entries({ f961: flag(961), f127: flag(127), inspect: '--inspect' })) rows[name] = await boot(optionsFor(), { NODE_OPTIONS: value });
  rows.none = await boot(optionsFor(), {});
  assert.deepEqual(rows, { f512: ok, f128: ok, f960: ok, empty: ok, f961: refused, f127: refused, inspect: refused, none: ok });
  let clockCalls = 0;
  const countingClock = { now: () => ((clockCalls += 1), Date.now()) };
  const getterOptions = () => {
    const o = optionsFor();
    delete o.clock;
    Object.defineProperty(o, 'clock', { get: () => countingClock, enumerable: true, configurable: true });
    return o;
  };
  const config = ['OwnedDevelopmentDeliveryConfigError', diag('config', 'config_invalid'), 0, [0, 0, 0, 0], 0, 0];
  const refusals = {
    connectService: await boot(optionsFor({ expectedServiceName: MCP, clock: countingClock }), {}),
    otherService: await boot(optionsFor({ expectedServiceName: 'otherservice', clock: countingClock }), {}),
    noIngress: await boot(noIngress(optionsFor({ clock: countingClock })), {}),
    extraPolicy: await boot(optionsFor({ apiNodeOptionsPolicy: 'bounded-memory-hint-v1', clock: countingClock }), {}),
    getter: await boot(getterOptions(), {}),
  };
  assert.deepEqual(refusals, Object.fromEntries(Object.keys(refusals).map((key) => [key, config])));
  assert.equal(clockCalls, 0, 'no clock call before the config refusal');
  const direct = await openWith(MCP, { NODE_OPTIONS: flag(512) });
  assert.deepEqual([direct.outcome, direct.hasMask, direct.sets], ['environment_rejected', false, 0], 'the MCP service refuses NODE_OPTIONS by name without a mask');
  results.A1 = { accepted: 5, refused: 3 + Object.keys(refusals).length };
});

group('A2 entry import / discovery: importing creates no SDK, secret, DB, HTTP or signal listener, and the module exports only the sendtexttodotsapi function', async () => {
  const before = { sets: used.sdkSets, access: rpc.access.length, markers: rpc.markerReads, refused: net0.refused, sigterm: process.listeners('SIGTERM').length, sigint: process.listeners('SIGINT').length };
  const mod = await import(`${ENTRY}?api-entry=import-only`);
  const after = { sets: used.sdkSets, access: rpc.access.length, markers: rpc.markerReads, refused: net0.refused, sigterm: process.listeners('SIGTERM').length, sigint: process.listeners('SIGINT').length };
  assert.deepEqual(after, before);
  assert.deepEqual([Object.keys(mod).sort().join(','), typeof mod.sendtexttodotsapi], ['sendtexttodotsapi', 'function']);
  results.A2 = { exports: Object.keys(mod) };
});

group('A3 standard start: with a bounded hint and without NODE_OPTIONS the API starts once, unauthenticated POSTs get the fixed 401 bytes, both secrets are read in order, the marker once, no start_failed line, and every SDK closes once on close', async () => {
  const out = {};
  for (const [name, extra] of Object.entries({ hint512: { NODE_OPTIONS: flag(512) }, hint960: { NODE_OPTIONS: `${'        '}${STRICT}` }, none: {} })) {
    const access = rpc.access.length;
    const markers = rpc.markerReads;
    const item = await entryCase(`ok-${name}`, extra, { requests: 2, post: true });
    out[name] = [item.replies.map((reply) => [reply.status, reply.text]), item.starts, item.sets, item.closes, rpc.access.slice(access), rpc.markerReads - markers, item.revisionReads, leaks(item.lines)];
  }
  const expected = [[[401, AUTH], [401, AUTH]], [], 1, [1, 1, 1, 1], ['identifierKey', 'commandDigestKey'], 1, 1, []];
  assert.deepEqual(out, { hint512: expected, hint960: expected, none: expected });
  assert.deepEqual([rpc.transactions, rpc.crypto], [0, 0]);
  results.A3 = { cases: Object.keys(out).length };
});

group('A4 failures keep the fixed 503 and one diagnostic line: an invalid hint gives mask 1, with another refused name mask 3, a valid hint with another K_SERVICE mask 4; no value, name or flag appears in any line or HTTP field', async () => {
  const cases = { 1: { NODE_OPTIONS: flag(961) }, 3: { NODE_OPTIONS: `"${flag(512)}"`, GRPC_TRACE: 'FIXTURE-VALUE' }, 4: { NODE_OPTIONS: flag(512), K_SERVICE: 'otherservice' } };
  const out = {};
  for (const [mask, extra] of Object.entries(cases)) {
    const item = await entryCase(`mask-${mask}`, extra, { requests: 3 });
    out[mask] = [unavailableAll(item), noMaskInHttp(item), item.starts, item.sets, item.revisionReads, leaks(item.lines)];
  }
  assert.deepEqual(out, Object.fromEntries(Object.keys(cases).map((mask) => [mask, [true, true, [MASK_LINE(Number(mask))], 0, 1, []]])));
  results.A4 = { masks: Object.keys(out).map(Number) };
});

group('A5 shared start: concurrent requests share one start (one SDK, one gate evaluation); a failed start is latched — later requests get the same 503 without a new start or a second line', async () => {
  const shared = await entryCase('shared', { NODE_OPTIONS: flag(512) }, { requests: 3, post: true });
  assert.deepEqual([shared.replies.map((reply) => reply.status), shared.sets, shared.revisionReads, shared.starts], [[401, 401, 401], 1, 1, []]);
  const env = makeEnv(baseEnv(), { NODE_OPTIONS: flag(961) });
  const known = addedSignalListeners('SIGTERM');
  const stderr = captureStderr();
  let statuses;
  try {
    await withEnv(env, async () => {
      const instance = await import(`${ENTRY}?api-entry=latch`);
      const first = Array.from({ length: 3 }, () => exchange('GET'));
      await Promise.all(first.map(({ req, res }) => instance.sendtexttodotsapi(req, res)));
      const later = [];
      for (let index = 0; index < 2; index += 1) {
        const pair = exchange('GET');
        await instance.sendtexttodotsapi(pair.req, pair.res);
        later.push(pair);
      }
      statuses = [...first, ...later].map(({ res }) => res.statusCode);
      await closeInstance(known);
    });
  } finally {
    stderr.restore();
  }
  assert.deepEqual([statuses, startLines(stderr.lines), env.probe.reads.filter((name) => name === 'K_REVISION').length], [[503, 503, 503, 503, 503], [MASK_LINE(1)], 1]);
  results.A5 = { shared: shared.sets, latched: statuses.length };
});

group('A6 receive deadline / abort / close ownership: an aborted request does not stop the shared start (the other request still gets 401); a close during a hanging secret read stops the start as {identifier_secret, aborted} and cleans every SDK once; a hanging read alone stops at the original 5 s limit as {identifier_secret, timed_out}', async () => {
  const env = makeEnv(baseEnv(), { NODE_OPTIONS: flag(512) });
  const known = addedSignalListeners('SIGTERM');
  const stderr = captureStderr();
  let abortResult;
  try {
    await withEnv(env, async () => {
      plan = { markerDelayMs: 50 };
      const instance = await import(`${ENTRY}?api-entry=abort`);
      const a = postExchange();
      const b = postExchange();
      const pa = instance.sendtexttodotsapi(a.req, a.res);
      await until(() => a.req.listenerCount('aborted') > 0, 'abort listener');
      a.req.emit('aborted');
      const pb = instance.sendtexttodotsapi(b.req, b.res);
      await Promise.all([pa, pb]);
      abortResult = [a.res.statusCode, b.res.statusCode];
      await closeInstance(known);
    });
  } finally {
    stderr.restore();
    plan = {};
  }
  assert.deepEqual([abortResult, startLines(stderr.lines)], [[503, 401], []]);
  plan = { secret: { identifierKey: 'hang' } };
  const env2 = makeEnv(baseEnv(), { NODE_OPTIONS: flag(512) });
  const known2 = addedSignalListeners('SIGTERM');
  const stderr2 = captureStderr();
  const before = events.length;
  const pending = rpc.pending;
  let closedStatus;
  try {
    await withEnv(env2, async () => {
      const instance = await import(`${ENTRY}?api-entry=close-hang`);
      const pair = exchange('GET');
      const p = instance.sendtexttodotsapi(pair.req, pair.res);
      await until(() => rpc.pending > pending, 'hang started');
      await closeInstance(known2);
      await p;
      closedStatus = pair.res.statusCode;
    });
  } finally {
    stderr2.restore();
    plan = {};
  }
  assert.deepEqual([closedStatus, startLines(stderr2.lines), closeCounts(events.slice(before))], [503, [START_LINE('identifier_secret', 'aborted')], [1, 1, 1, 1]]);
  const hang = await entryCase('deadline-hang', { NODE_OPTIONS: flag(512) }, { requests: 1, setup: { secret: { identifierKey: 'hang' } } });
  assert.deepEqual([unavailableAll(hang), hang.starts, hang.startupCloses], [true, [START_LINE('identifier_secret', 'timed_out')], [1, 1, 1, 1]]);
  assert.ok(hang.elapsedMs >= 4_500 && hang.elapsedMs < 20_000, String(hang.elapsedMs));
  results.A6 = { abort: abortResult, closedStatus, hangMs: hang.elapsedMs };
});

group('A7 secret / marker failure cleanup: an identifier read failure, equal keys and a missing marker each give the fixed stage/code line and 503, every owned SDK is cleaned once, and every returned secret buffer is wiped', async () => {
  const cases = {
    identifier: [{ secret: { identifierKey: 'reject' } }, START_LINE('identifier_secret', 'read_failed')],
    equalKeys: [{ secret: { commandDigestKey: 'same' } }, START_LINE('digest_secret', 'format_mismatch')],
    marker: [{ marker: 'missing' }, START_LINE('marker', 'format_mismatch')],
  };
  const out = {};
  for (const [name, [setup, line]] of Object.entries(cases)) {
    const item = await entryCase(`fail-${name}`, { NODE_OPTIONS: flag(512) }, { requests: 2, setup });
    out[name] = [unavailableAll(item), JSON.stringify(item.starts) === JSON.stringify([line]), item.startupCloses, leaks(item.lines)];
  }
  assert.deepEqual(out, Object.fromEntries(Object.keys(cases).map((name) => [name, [true, true, [1, 1, 1, 1], []]])));
  assert.ok(rpc.returned.length > 0 && rpc.returned.every((buffer) => buffer.every((byte) => byte === 0)), 'every returned secret buffer is wiped');
  results.A7 = { cases: Object.keys(out).length, buffers: rpc.returned.length };
});

group('A8 timers / signals / env: a failing and a ready entry leave no timer and no added SIGTERM/SIGINT listener after close; process.env keys and NODE_OPTIONS are unchanged; no real network attempt and no unhandled rejection', async () => {
  const timers = () => process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
  const before = timers();
  await entryCase('timers-fail', { NODE_OPTIONS: flag(961) }, { requests: 2 });
  await entryCase('timers-ready', { NODE_OPTIONS: flag(512) }, { requests: 1, post: true });
  await sleep(20);
  const afterCount = timers();
  assert.deepEqual([afterCount - before, addedSignalListeners('SIGTERM').length, addedSignalListeners('SIGINT').length, JSON.stringify(Object.keys(process.env).sort()) === realEnvKeysBefore, Object.hasOwn(process.env, 'NODE_OPTIONS'), net0.refused, unhandled], [0, 0, 0, true, false, 0, 0]);
  results.A8 = { timersBefore: before, timersAfter: afterCount, envSwaps };
});

// ---------- 本文暗号化の有効構成（T075 L01/L02） ----------
// 有効な配置設定（合成）を隔離copy（候補rootの.tmp/test-encryption-bootstrap-<UUID>、終了時に削除）のdistへ置き、そのcopyの実
// startOwnedIngressDevelopmentDeliveryFunctionを、上と同じ外部SDKの代替（require cache）・合成env・合成HTTPで通す。製品へ試験専用の口は足さない。
//   L01 起動時の専用secretの読取り0、認証済みGETで専用secretの固定版を1回読み、実ringを初期化して公開鍵を返す。
//   L02 close（清掃1回）の後のGETは固定503で、専用secretの追加読取り0。
// 元のsrc/distの配置設定のbytesは前後で同じ（run-testsの検査に加えてここでも確かめる）。
group('L01/L02 payload encryption on: the owned bootstrap reads the dedicated secret only on the first authenticated GET, initializes a real ring, and after close answers 503 with no further secret read', async () => {
  const { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } = await import('node:fs');
  const { basename, dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { randomUUID } = await import('node:crypto');
  const { connectIdentityHash } = await import('../dist/connect/firestore.js');
  const { createHmacHasher } = await import('../dist/secrets.js');
  const { DEPLOYMENT_CONFIG: SYNTHETIC } = await import('./fixtures/synthetic-deployment.mjs');
  const work = fileURLToPath(new URL('..', import.meta.url));
  const root = basename(dirname(work.replace(/[\\/]$/, ''))) === '.tmp' ? dirname(dirname(work.replace(/[\\/]$/, ''))) : work;
  const guarded = [join(work, 'dist', 'config', 'deployment.js'), join(root, 'src', 'config', 'deployment.ts')];
  const digest = () => guarded.map((file) => createHash('sha256').update(readFileSync(file)).digest('hex')).join(',');
  const before = digest();
  const copy = join(root, '.tmp', `test-encryption-bootstrap-${randomUUID()}`);
  const secretName = `projects/${M.projectNumber}/secrets/synthetic-payload-protection/versions/1`;
  const enabled = {
    ...structuredClone(SYNTHETIC),
    payloadEncryption: {
      mode: 'jwe-rsa-oaep-256-a256gcm-v1',
      namespace: `t280_${randomUUID()}`,
      secret: `projects/${M.projectNumber}/secrets/synthetic-payload-protection`,
      writeSecretVersion: 1,
      readSecretVersions: [1],
    },
  };
  const docsAtStart = new Map(docs);
  try {
    mkdirSync(copy, { recursive: true });
    cpSync(join(work, 'dist'), join(copy, 'dist'), { recursive: true });
    cpSync(join(work, 'package.json'), join(copy, 'package.json'));
    writeFileSync(join(copy, 'dist', 'config', 'deployment.js'), `export const DEPLOYMENT_CONFIG = ${JSON.stringify(enabled)};\n`);
    // copyの実moduleを、元のdistと同じ順序で実SDKへ束縛してから読み込み（require cacheを一時的に元へ戻す）、SDKの代替を置き直す。
    const fakes = new Map([...cacheBefore.keys()].map((filename) => [filename, Module._cache[filename]]));
    for (const [filename, original] of cacheBefore) {
      if (original === undefined) delete Module._cache[filename];
      else Module._cache[filename] = original;
    }
    const copyUrl = (path) => new URL(`file:///${join(copy, 'dist', path).replace(/\\/g, '/')}`).href;
    try {
      for (const path of ['connect/firestore.js', 'connect/kms-port.js', 'connect/kms-server.js', 'connect/google-kms-server.js', 'delivery/kms-functions.js', 'delivery/kms-store.js', 'egress/product.js', 'keys/google-secret-reader.js', 'oauth/request-auth-runtime.js', 'protection/google-kms-transport.js', 'identity/firebase.js']) {
        await import(copyUrl(path));
      }
    } finally {
      for (const [filename, fake] of fakes) Module._cache[filename] = fake;
    }
    const enabledBootstrap = await import(copyUrl('google-runtime/delivery-development.js'));

    // 合成の本人（既存owner・明示許可）。identityHashは同じidentifierKeyのHMAC。
    const uid = 'synthetic-apple-uid-encryption';
    const identityHash = connectIdentityHash(createHmacHasher(PAYLOADS.identifierKey), M.connectNamespace, { projectId: M.projectId, uid });
    const ownerId = randomUUID();
    const now = Date.now();
    const connectRoot = `sttdConnect/${M.connectNamespace}`;
    docs.set(`${connectRoot}/access/${identityHash}`, { version: 1, state: 'active', generation: randomUUID(), updatedAt: now });
    docs.set(`${connectRoot}/identities/${identityHash}`, { ownerId, createdAt: now });
    docs.set(`${connectRoot}/owners/${ownerId}`, { identityHash, sealedUid: 'synthetic-sealed', createdAt: now, lastActiveAt: now, revokedAt: null });
    const encryptionSecret = { name: secretName, value: randomBytes(32).toString('base64url'), reads: 0 };
    plan = {
      memoryTx: true,
      encryptionSecret,
      idToken: (token) => {
        if (token !== 'tok.synthetic-encryption.sig') throw Object.assign(new Error('invalid'), { code: 'auth/invalid-id-token' });
        return { aud: M.projectId, iss: `https://securetoken.google.com/${M.projectId}`, sub: uid, uid, auth_time: Math.floor(Date.now() / 1000), firebase: { sign_in_provider: 'apple.com' } };
      },
    };
    const options = optionsFor({
      ingress: () => {
        const at = Date.now();
        return { receivedAt: at, deadlineAt: at + 20_000, signal: new AbortController().signal };
      },
    });
    const get = async (ready) => {
      const { req, res } = exchange('GET', '/v2/encryption-key');
      req.headers.authorization = 'Bearer tok.synthetic-encryption.sig';
      req.rawHeaders.push('Authorization', 'Bearer tok.synthetic-encryption.sig');
      req.rawBody = Buffer.alloc(0);
      await ready.handler(req, res);
      return { status: res.statusCode, json: res.body === null ? null : JSON.parse(res.body.toString('utf8')) };
    };
    const env = makeEnv(baseEnv(), {});
    const outcome = await withEnv(env, async () => {
      const ready = await enabledBootstrap.startOwnedIngressDevelopmentDeliveryFunction(options);
      const atStartup = encryptionSecret.reads;
      const first = await get(ready);
      const afterFirst = encryptionSecret.reads;
      const ring = [...docs.keys()].filter((path) => path.startsWith(`sttdEncryption/${enabled.payloadEncryption.namespace}/rings/`));
      const closedFrom = events.length;
      await ready.close();
      const closes = closeCounts(events.slice(closedFrom));
      const second = await get(ready);
      return { atStartup, first, afterFirst, ring: ring.length, closes, second, afterClose: encryptionSecret.reads };
    });
    // L01: 起動時0、最初のGETで固定版を1回読み、ringを1つ作って公開鍵を返す。
    assert.equal(outcome.atStartup, 0);
    assert.equal(outcome.first.status, 200);
    assert.equal(outcome.first.json.alg, 'RSA-OAEP-256');
    assert.equal(outcome.afterFirst, 1);
    assert.equal(outcome.ring, 1);
    // L02: closeで所有SDKを各1回清掃し、その後のGETは固定503で追加読取り0。
    assert.deepEqual(outcome.closes, [1, 1, 1, 1]);
    assert.equal(outcome.second.status, 503);
    assert.deepEqual(outcome.second.json, UNAVAILABLE);
    assert.equal(outcome.afterClose, 1);
    results.L01 = { startupReads: outcome.atStartup, firstGetReads: outcome.afterFirst };
  } finally {
    plan = {};
    docs.clear();
    for (const [path, value] of docsAtStart) docs.set(path, value);
    rmSync(copy, { recursive: true, force: true, maxRetries: 3 });
  }
  assert.equal(digest(), before, 'the original deployment config bytes are unchanged');
});