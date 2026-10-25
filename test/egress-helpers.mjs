// 安全な送出の試験用fixture。loopbackのTLS受信機、試験専用のCA、試験用のconnector（DNS・宛先・port・CAの差し替え）。
// 証明書と秘密鍵は実行ごとにOpenSSLで一時ディレクトリへ生成し、メモリーへ読んだ直後にディレクトリごと削除する。
// repo・通常ログ・試験出力へは書かない。ここにあるものは製品の設定ではなく、src/からは参照されない。

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** 予約済みの.test。どこにも解決されず、fixtureのDNSだけが答える。 */
export const CALLBACK_HOST = 'callback.sttd-fixture.test';
/** 証明書のSANにないhostname。 */
export const OTHER_HOST = 'other.sttd-fixture.test';

const GIT_OPENSSL = 'C:/Program Files/Git/usr/bin/openssl.exe';

function findOpenssl() {
  for (const candidate of ['openssl', GIT_OPENSSL]) {
    try {
      execFileSync(candidate, ['version'], { stdio: 'ignore' });
      return candidate;
    } catch {
      // 次の候補へ。
    }
  }
  throw new Error('OpenSSL was not found (PATH or Git for Windows)');
}

/**
 * 試験専用のCAとサーバー証明書を作る。戻り値はPEM文字列だけで、ファイルは残さない。
 * tempDirGoneは、生成に使った一時ディレクトリが削除済みであることの確認用。
 * extraは、追加で発行するサーバー証明書（名前→SAN）。試験専用のCAが発行し、試験用のconnectorだけが信頼する。
 */
export function createTlsFixture({ extra = {} } = {}) {
  const openssl = findOpenssl();
  const dir = mkdtempSync(join(tmpdir(), 'sttd-egress-fixture-'));
  const file = (name) => join(dir, name);
  const run = (...args) => execFileSync(openssl, args, { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] });
  const keyOptions = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  try {
    const makeCa = (name) =>
      run('req', '-x509', ...keyOptions, '-keyout', `${name}.key`, '-out', `${name}.pem`, '-days', '2',
        '-subj', `/CN=STTD test fixture ${name}`,
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
    const issue = (name, ca, san, validity = ['-days', '2']) => {
      run('req', '-new', ...keyOptions, '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`);
      writeFileSync(file(`${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\n`);
      run('x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-CAcreateserial',
        '-out', `${name}.pem`, '-extfile', `${name}.ext`, ...validity);
      return { key: readFileSync(file(`${name}.key`), 'utf8'), cert: readFileSync(file(`${name}.pem`), 'utf8') };
    };
    makeCa('ca');
    makeCa('other-ca');
    return {
      ca: readFileSync(file('ca.pem'), 'utf8'),
      /** SANがCALLBACK_HOSTだけ（IPのSANなし）。 */
      good: issue('good', 'ca', `DNS:${CALLBACK_HOST}`),
      /** SANが127.0.0.1だけ。IP literalの正の確認用。 */
      ip: issue('ip', 'ca', 'IP:127.0.0.1'),
      /** hostnameは正しいが、信頼していないCAが発行した。 */
      untrusted: issue('untrusted', 'other-ca', `DNS:${CALLBACK_HOST}`),
      /** hostnameとCAは正しいが、期限が切れている。 */
      expired: issue('expired', 'ca', `DNS:${CALLBACK_HOST}`, ['-not_before', '20200101000000Z', '-not_after', '20200102000000Z']),
      extra: Object.fromEntries(Object.entries(extra).map(([name, san]) => [name, issue(name, 'ca', san)])),
      tempDirGone: () => !existsSync(dir),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

/**
 * loopbackのTLS受信機。受けた要求（見出し・本文・SNI・接続先）を記録する。応答はhandleで差し替える。
 * 既定は、検証challengeをそのまま返す。
 */
export async function startReceiver(t, credentials, { host = '127.0.0.1', port = 0, tlsOptions = {} } = {}) {
  const receiver = {
    host,
    port: 0,
    requests: [],
    /** TCP接続の数（TLSに失敗した接続も数える）。 */
    connections: 0,
    /** 接続が閉じられた数。 */
    closed: 0,
    handle: null,
  };
  // tlsOptionsは、handshakeを遅らせる等の受信機側の追加設定（送出側の設定ではない）。
  const server = createHttpsServer({ ...tlsOptions, key: credentials.key, cert: credentials.cert }, (req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const record = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        rawHeaders: req.rawHeaders,
        body,
        servername: req.socket.servername,
        localAddress: req.socket.localAddress,
      };
      receiver.requests.push(record);
      if (receiver.handle) return void receiver.handle(req, res, record);
      let challenge;
      try {
        ({ challenge } = JSON.parse(body));
      } catch {
        challenge = undefined;
      }
      const payload = JSON.stringify({ challenge });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
      res.end(payload);
    });
  });
  const sockets = new Set();
  server.on('connection', (socket) => {
    receiver.connections += 1;
    sockets.add(socket);
    socket.on('close', () => {
      receiver.closed += 1;
      sockets.delete(socket);
    });
  });
  // TLSに失敗した接続のエラーで試験を落とさない。
  server.on('tlsClientError', () => {});
  await listen(server, host, port);
  receiver.port = server.address().port;
  receiver.close = () =>
    new Promise((resolve) => {
      server.close(() => resolve());
      // TLSが成立しなかった接続も含めて、残さず閉じる。
      for (const socket of sockets) socket.destroy();
    });
  t.after(() => receiver.close());
  return receiver;
}

/** TLSを話さないloopbackの受信機（平文で1行返して閉じる）。 */
export async function startPlainReceiver(t, { host = '127.0.0.1' } = {}) {
  const receiver = { host, port: 0, connections: 0 };
  const sockets = new Set();
  const server = createTcpServer((socket) => {
    receiver.connections += 1;
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    socket.end('HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok');
  });
  await listen(server, host, 0);
  receiver.port = server.address().port;
  t.after(
    () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        for (const socket of sockets) socket.destroy();
      }),
  );
  return receiver;
}

/** 誰もlistenしていないloopbackのport。 */
export async function closedPort() {
  const server = createTcpServer();
  await listen(server, '127.0.0.1', 0);
  const { port } = server.address();
  await new Promise((resolve) => server.close(() => resolve()));
  return port;
}

/**
 * 試験用のconnector。dnsはhostname→回答の表、または関数。allowedに列挙したIPだけを接続可とする
 * （それ以外は公開IPも含めて拒否）。resolveの呼び出しはcallsへ記録する。
 */
export function fixtureConnector({ dns = {}, allowed = ['127.0.0.1'], port, ca }) {
  const allow = new Set(allowed);
  const connector = {
    calls: [],
    async resolve(hostname) {
      connector.calls.push(hostname);
      const answers = typeof dns === 'function' ? await dns(hostname, connector.calls.length) : dns[hostname];
      if (answers === undefined) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' });
      return answers.map((answer) =>
        typeof answer === 'string' ? { address: answer, family: answer.includes(':') ? 6 : 4 } : answer,
      );
    },
    isAllowedAddress: (address) => allow.has(address),
    port,
    ca,
  };
  return connector;
}

export const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** 固定分類のEgressErrorで失敗し、分類名以外を運ばないこと。 */
export async function assertEgressFailure(promise, kind, label = kind) {
  const error = await promise.then(
    () => assert.fail(`${label}: 成功してはいけない`),
    (thrown) => thrown,
  );
  assert.equal(error?.name, 'EgressError', label);
  assert.equal(error.kind, kind, label);
  assert.equal(error.message, kind, label);
  assert.equal(error.cause, undefined, label);
  assert.deepEqual(Object.keys(error).sort(), ['kind', 'name'], label);
  return error;
}
