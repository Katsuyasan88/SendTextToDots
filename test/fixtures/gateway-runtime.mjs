// gateway-v1配置の試験だけが使う合成部品（製品からの依存0）。実Cloud・IAM・資格・SDK通信・外部DNS/HTTP 0。
//   - topologyConfig: test/fixtures/synthetic-deployment.mjsの合成配置にgateway-v1を足した値（実在のproject・URL・主体ではない）。
//   - syntheticIdToken / iamFetcher: 形だけのJWT（署名なしの合成bytes）と、取得回数を数える合成IAM port。
//   - listen: 所有の127.0.0.1/ephemeral listenerだけ（各runの上限LISTENER_LIMIT。closeAllで必ず閉じる）。
//   - isolatedDist: build済みdistの.jsだけを所有の一時directoryへ写し、配置設定moduleだけを合成のgateway-v1配置へ置き換える。

import { randomUUID } from 'node:crypto';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
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
