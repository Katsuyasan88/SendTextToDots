// gateway-v1配置の試験だけが使う合成部品（製品からの依存0）。実Cloud・IAM・資格・SDK通信・外部DNS/HTTP 0。
//   - topologyConfig: test/fixtures/synthetic-deployment.mjsの合成配置にgateway-v1を足した値（実在のproject・URL・主体ではない）。
//   - syntheticIdToken / iamFetcher: 形だけのJWT（署名なしの合成bytes）と、取得回数を数える合成IAM port。
//   - listen: 所有の127.0.0.1/ephemeral listenerだけ（各runの上限LISTENER_LIMIT。closeAllで必ず閉じる）。
//   - isolatedDist: build済みdistの.jsだけを所有の一時directoryへ写し、配置設定moduleだけを合成のgateway-v1配置へ置き換える。

import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import Module from 'node:module';
import net from 'node:net';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { DEPLOYMENT_CONFIG as SYNTHETIC } from './synthetic-deployment.mjs';

export const LISTENER_LIMIT = 20;
const listeners = { opened: 0, servers: new Set() };

/** 所有の127.0.0.1/ephemeral listener（上限つき）。 */
export async function listen(handler) {
  if (listeners.opened >= LISTENER_LIMIT) throw new Error('gateway fixture: listener budget');
  listeners.opened += 1;
  const server = http.createServer(handler);
  listeners.servers.add(server);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

/** 所有listenerを全て閉じる（finally用）。 */
export async function closeAll() {
  for (const server of listeners.servers) {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(() => resolve()));
  }
  listeners.servers.clear();
}

export const listenerCount = () => listeners.opened;

/** 既存の127.0.0.1 listenerへ数える（start系fixtureが自分でlistenした分）。 */
export function countListener() {
  if (listeners.opened >= LISTENER_LIMIT) throw new Error('gateway fixture: listener budget');
  listeners.opened += 1;
}

export const BACKEND = Object.freeze({
  api: 'https://sendtexttodots-api-backend-123456789012.europe-west1.run.app',
  connect: 'https://sendtexttodots-connect-backend-123456789012.europe-west1.run.app',
});

/** 合成のgateway-v1 topology（上限は小さい合成値）。 */
export function topologyOf({ api = BACKEND.api, connect = BACKEND.connect, limits = {} } = {}) {
  return {
    mode: 'gateway-v1',
    api: { backendServiceName: 'sendtexttodots-api-backend', backendOrigin: api, gatewayServiceAccount: 'api-gateway@sendtexttodots-test.iam.gserviceaccount.com' },
    connect: { backendServiceName: 'sendtexttodots-connect-backend', backendOrigin: connect, gatewayServiceAccount: 'connect-gateway@sendtexttodots-test.iam.gserviceaccount.com' },
    limits: { maxBodyBytes: 65_536, maxConcurrent: 8, ratePerSecond: 100, burst: 100, ...limits },
  };
}

/** 合成配置（gateway-v1つき）。overridesはtop-levelの浅い上書き。 */
export function topologyConfig(overrides = {}) {
  return { ...structuredClone(SYNTHETIC), topology: topologyOf(), ...overrides };
}

/** 形だけの合成ID token（aud・exp。署名部は乱数の合成bytes）。 */
export function syntheticIdToken(audience, expSec) {
  const part = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  return `${part({ alg: 'RS256', typ: 'JWT' })}.${part({ aud: audience, exp: expSec, iss: 'https://accounts.google.invalid' })}.${Buffer.from(randomUUID()).toString('base64url')}`;
}

/** 合成IAM port（呼出し回数と最後のaudienceを数える）。behaviourは (audience) => Promise<string>。 */
export function iamFetcher(behaviour) {
  const calls = { count: 0, audiences: [] };
  const fetcher = async (audience) => {
    calls.count += 1;
    calls.audiences.push(audience);
    return behaviour === undefined ? syntheticIdToken(audience, Math.floor(Date.now() / 1000) + 3600) : behaviour(audience);
  };
  return { fetcher, calls };
}

/** 合成echo backend（受けたmethod/url/rawHeaders/本文を記録し、respondで応答する）。 */
export async function echoBackend(respond) {
  const seen = [];
  const { server, port } = await listen((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, rawHeaders: [...req.rawHeaders], body: Buffer.concat(chunks) };
      seen.push(entry);
      if (respond !== undefined) respond(req, res, entry);
      else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      }
    });
  });
  return { server, port, seen };
}

/** 生のHTTP/1.1要求を書いて応答の先頭行と全文を返す（重複header・曖昧なframingの試験用）。 */
export function rawRequest(port, text, { timeoutMs = 5_000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    const chunks = [];
    const timer = setTimeout(() => {
      socket.destroy();
      const textOut = Buffer.concat(chunks).toString('latin1');
      resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(textOut)?.[1] ?? 0), text: textOut });
    }, timeoutMs);
    const done = () => {
      clearTimeout(timer);
      const textOut = Buffer.concat(chunks).toString('latin1');
      socket.destroy();
      resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(textOut)?.[1] ?? 0), text: textOut });
    };
    // 半closeすると応答前に切断として扱われるため、書いた後は応答（Content-Lengthまで）かcloseを待つ。
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      const end = all.indexOf('\r\n\r\n');
      if (end === -1) return;
      const length = /\r\ncontent-length: *(\d+)/i.exec(all.subarray(0, end).toString('latin1'))?.[1];
      if (length !== undefined && all.length - end - 4 >= Number(length)) done();
    });
    socket.on('error', () => undefined);
    socket.on('close', done);
    socket.on('connect', () => socket.write(text));
    socket.once('error', reject);
  });
}

/** node:http requestの結果（本文・全header・rawHeaders）。 */
export function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: { ...headers, ...(body !== undefined ? { 'Content-Length': Buffer.byteLength(body) } : {}) }, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/**
 * build済みdistの.jsだけを所有の一時directory（cwd直下の.tmp。gitignore対象）へ写し、配置設定moduleを合成configへ置き換える。
 * 戻り値のurl(name)はその写しのmodule URL。cleanupで必ず消す。
 */
export function isolatedDist(config) {
  const root = join(process.cwd(), '.tmp', `gateway-dist-${randomUUID()}`);
  mkdirSync(root, { recursive: true });
  cpSync(join(process.cwd(), 'dist'), join(root, 'dist'), { recursive: true, filter: (source) => !/\.(?:d\.ts|map)$/.test(source) });
  writeFileSync(join(root, 'dist', 'config', 'deployment.js'), `export const DEPLOYMENT_CONFIG = ${JSON.stringify(config)};\n`);
  return {
    root,
    url: (name, query = '') => `${pathToFileURL(join(root, 'dist', ...name.split('/'))).href}${query}`,
    cleanup: () => rmSync(root, { recursive: true, force: true, maxRetries: 3 }),
  };
}

/**
 * 実Google SDK factory（google-runtime/development.js）の公開SDK境界だけを合成に置き換える（test/api-entry.test.mjsのSDK代替と同じ
 * 形: google-gax Compute・Firestore・KMS・Secret Manager・firebase-admin/app・auth）。実moduleを先に読み込んだ後に呼ぶこと。
 * developmentのcreateRequireが読むrequire cacheだけを差し替え、restoreで必ず戻す。通信・資格・実SDK呼出し0。
 */
export function installGoogleSdkSubstitutes({ resolveFrom, secretVersions, docs }) {
  const { createRequire } = Module;
  const requireFrom = createRequire(resolveFrom);
  const events = [];
  const clone = (value) => (value === undefined ? undefined : structuredClone(value));
  const gaxPromise = (produce) => {
    const promise = produce();
    Object.defineProperty(promise, 'cancel', { value: () => {}, writable: true, configurable: true, enumerable: false });
    return promise;
  };
  class FakeCompute {
    constructor() {
      this.credentials = {};
    }
    async getAccessToken() {
      throw new Error('no token in this unit');
    }
  }
  class FakeGoogleAuth {}
  const snapshotOf = (ref, entry) => ({ ref, id: ref.id, exists: entry !== undefined, data: () => clone(entry) });
  const docRef = (db, path) => ({ firestore: db, path, id: path.slice(path.lastIndexOf('/') + 1), collection: (name) => collRef(db, `${path}/${name}`), get: async () => snapshotOf(docRef(db, path), docs.get(path)) });
  const collRef = (db, path) => ({ firestore: db, path, doc: (id) => docRef(db, `${path}/${id}`) });
  class FakeFirestore {
    constructor(settings) {
      this.settings = settings;
      events.push('sdk.firestore');
    }
    collection(name) {
      return collRef(this, name);
    }
    runTransaction() {
      throw new Error('transactions are not used in this unit');
    }
    /** 接続serverが起動時に存在だけを要求する公開method（この試験の起動・discoveryでは呼ばれない）。 */
    batch() {
      throw new Error('batches are not used in this unit');
    }
    terminate() {
      events.push('sdk.terminate');
      return Promise.resolve();
    }
  }
  const gapic = (kind, subs, innerApiCalls) =>
    class {
      constructor(opts) {
        const client = { opts };
        for (const [property, stubProperty] of subs) client[property] = { [stubProperty]: undefined };
        client.initialize = () => {
          client.innerApiCalls = innerApiCalls();
          return Promise.resolve({ close: () => {} });
        };
        client.close = () => {
          events.push(`sdk.${kind}.close`);
          return Promise.resolve();
        };
        return client;
      }
    };
  // 用途ごとの合成secret（keys/google-connect-secrets.tsの形式）: identifier/command digestはraw 32byte、cookieKeysは32byte鍵の連結、
  // jwksは秘密ES256/RS256の2鍵のJSON（MCPのOAuth署名鍵束。APIの32byte鍵を流用しない）。
  const privateJwk = (type, options, alg) => ({ ...generateKeyPairSync(type, options).privateKey.export({ format: 'jwk' }), alg, use: 'sig', kid: randomUUID() });
  const payloads = {
    identifierKey: randomBytes(32),
    commandDigestKey: randomBytes(32),
    cookieKeys: randomBytes(64),
    jwks: Buffer.from(JSON.stringify({ keys: [privateJwk('ec', { namedCurve: 'P-256' }, 'ES256'), privateJwk('rsa', { modulusLength: 2048 }, 'RS256')] }), 'utf8'),
  };
  const purposeOf = (name) => Object.keys(secretVersions).find((purpose) => secretVersions[purpose] === name);
  const FakeKms = gapic('kms', [['iamClient', 'iamPolicyStub'], ['locationsClient', 'locationsStub'], ['operationsClient', 'operationsStub']], () => ({
    encrypt: () => gaxPromise(() => Promise.reject(new Error('unused'))),
    decrypt: () => gaxPromise(() => Promise.reject(new Error('unused'))),
  }));
  const reads = [];
  const FakeSecrets = gapic('secrets', [['locationsClient', 'locationsStub']], () => ({
    accessSecretVersion: (request) => {
      const purpose = purposeOf(request.name);
      reads.push(purpose);
      const data = Buffer.from(payloads[purpose] ?? Buffer.alloc(0));
      return gaxPromise(() => Promise.resolve([{ name: request.name, payload: { data, dataCrc32c: crc32cOf(data) } }, undefined, undefined]));
    },
  }));
  const fakeAuth = {
    async verifyIdToken() {
      throw Object.assign(new Error('invalid'), { code: 'auth/invalid-id-token' });
    },
    async getUser() {
      throw new Error('getUser is not used in this unit');
    },
  };
  const fakeAdminApp = {
    initializeApp: (options, name) => (events.push('sdk.initializeApp'), { name, options }),
    deleteApp: () => (events.push('sdk.deleteApp'), Promise.resolve()),
  };
  const before = new Map();
  const install = (name, exports) => {
    const filename = requireFrom.resolve(name);
    before.set(filename, Module._cache[filename]);
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
  install('firebase-admin/auth', { getAuth: () => fakeAuth });
  return {
    events,
    reads,
    restore: () => {
      for (const [filename, previous] of before) {
        if (previous === undefined) delete Module._cache[filename];
        else Module._cache[filename] = previous;
      }
    },
  };
}

/** CRC32C（Secret Managerの応答検査用。protection/kms-sealing.jsと同じ多項式）。 */
let crc32cOf = () => 0;
export function useCrc32c(fn) {
  crc32cOf = fn;
}
