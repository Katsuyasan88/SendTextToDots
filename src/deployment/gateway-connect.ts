// gateway-v1配置のMCP入口（既存MCP Cloud Run service名・公開origin/issuer/resourceのまま）。要求を設定の固定MCP backendへ一回だけ
// 中継する（src/gateway/http.ts）。OAuth署名鍵・cookie鍵・DB・KMS・App Checkの消費・同意/Grantの発行はしない。
// zero-argumentのrunGatewayConnectは、検証済みの配置設定（topologyが必須）・PORT（正規の十進1024〜65535）・実行環境のgateを副作用の前に
// 確かめ、不成立は固定error（listen・token取得・転送0）。importだけではlisten・signal登録0。direct mainの時だけ起動し、失敗は固定log・
// 終了code 1。closeは共有Promiseで1回（新規要求を拒否→進行中の転送を中止→待受を閉じる）。

import { createServer, type Server } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadDeploymentConfig } from '../config/validate.js';
import type { GatewayHandler } from '../gateway/http.js';
import { createGatewayRuntime } from '../gateway/runtime.js';
import { systemClock } from '../policy.js';

const PORT_PATTERN = /^[1-9][0-9]{3,4}$/;

export type GatewayConnectEntryErrorCode = 'gateway_connect_config_invalid' | 'gateway_connect_startup_failed' | 'gateway_connect_close_failed';

export class GatewayConnectEntryError extends Error {
  override readonly name = 'GatewayConnectEntryError';
  readonly code: GatewayConnectEntryErrorCode;
  constructor(code: GatewayConnectEntryErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface GatewayConnectHandle {
  close(): Promise<void>;
}

let runPromise: Promise<GatewayConnectHandle> | undefined;
let closePromise: Promise<void> | undefined;
let gateway: GatewayHandler | undefined;
let server: Server | undefined;
let directMain = false;

const onSignal = (): void => {
  void close().catch(() => undefined);
};

function close(): Promise<void> {
  if (closePromise !== undefined) return closePromise;
  closePromise = new Promise<void>((resolvePromise, reject) => {
    gateway?.close();
    process.off('SIGTERM', onSignal);
    process.off('SIGINT', onSignal);
    const owned = server;
    if (owned === undefined || !owned.listening) return resolvePromise();
    owned.close((error) => (error === undefined ? resolvePromise() : reject(new GatewayConnectEntryError('gateway_connect_close_failed'))));
    owned.closeAllConnections();
  });
  if (directMain) closePromise.catch(() => (process.exitCode = 1));
  return closePromise;
}

const handle: GatewayConnectHandle = Object.freeze({ close });

/** MCP gatewayを起動する（1processに1回・二重runは同じPromise）。 */
export function runGatewayConnect(): Promise<GatewayConnectHandle> {
  runPromise ??= start();
  return runPromise;
}

async function start(): Promise<GatewayConnectHandle> {
  let handler: GatewayHandler;
  let port: number;
  try {
    const config = loadDeploymentConfig();
    const portText = process.env['PORT'];
    if (typeof portText !== 'string' || !PORT_PATTERN.test(portText)) throw new Error('port');
    port = Number(portText);
    if (port < 1024 || port > 65535) throw new Error('port');
    handler = createGatewayRuntime({ role: 'connect', config, env: process.env, clock: systemClock });
  } catch {
    throw new GatewayConnectEntryError('gateway_connect_config_invalid');
  }
  gateway = handler;
  const owned = createServer({ requestTimeout: 20_000, headersTimeout: 10_000, maxHeaderSize: 16_384 }, (req, res) => {
    void handler.handle(req, res).catch(() => {
      if (!res.writableEnded) res.destroy();
    });
  });
  server = owned;
  owned.on('error', () => undefined);
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
  try {
    await new Promise<void>((resolvePromise, reject) => {
      owned.once('error', reject);
      owned.listen(port, '0.0.0.0', () => {
        owned.off('error', reject);
        resolvePromise();
      });
    });
  } catch {
    await close().catch(() => undefined);
    throw new GatewayConnectEntryError('gateway_connect_startup_failed');
  }
  return handle;
}

function isDirectMain(): boolean {
  const entry = process.argv[1];
  if (typeof entry !== 'string' || entry === '') return false;
  try {
    return pathToFileURL(resolve(entry)).href === import.meta.url;
  } catch {
    return false;
  }
}

if (isDirectMain()) {
  directMain = true;
  runGatewayConnect().then(
    () => undefined,
    () => {
      process.exitCode = 1;
      try {
        process.stderr.write('{"event":"sttd_connect_gateway.start_failed"}\n');
      } catch {
        // 記録の失敗は終了codeを変えない。
      }
    },
  );
}
