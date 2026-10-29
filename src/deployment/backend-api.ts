// gateway-v1配置の送信API業務backend（Invoker IAM必須の別Cloud Run service）。既存の送信API bootstrap
// （startOwnedIngressDevelopmentDeliveryFunction: 本人/source/App Check・鍵・最終transaction・配送）を、topology.api.backendServiceNameの
// K_SERVICE gateで1回だけ起動し、node:httpの待受へ結ぶ。各要求はadapter（src/gateway/backend.ts）でtransport authorityを検査して公開
// authorityと残時間へ結んでから、既存のconsole CORS→所有handlerへ渡す。
// zero-argumentのrunBackendApiは、配置設定（topology必須）・PORTを副作用の前に確かめ、不成立は固定のconfig error（SDK・資格・DB・
// listen 0）。SDKの起動失敗は所有清掃の後にstartup error（清掃未完はclose error）。importだけではSDK・listen・signal登録0。
// direct mainの時だけ起動し、失敗は固定log・終了code 1。closeは共有Promiseで1回（要求を中止→待受→所有API.close）。

import { createServer, type Server } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadDeploymentConfig } from '../config/validate.js';
import { authorityOf } from '../gateway/contract.js';
import { createApiBackendServe, type ApiBackendServe } from '../gateway/backend.js';
import { requireGatewayTopology } from '../gateway/runtime.js';
import {
  OwnedDevelopmentDeliveryCloseError,
  startOwnedIngressDevelopmentDeliveryFunction,
  type OwnedDevelopmentDeliveryFunction,
} from '../google-runtime/delivery-development.js';
import { systemClock } from '../policy.js';
import { applyConsoleCors } from './console-cors.js';

const START_BUDGET_MS = 20_000;
const PORT_PATTERN = /^[1-9][0-9]{3,4}$/;

export type BackendApiEntryErrorCode = 'backend_api_config_invalid' | 'backend_api_startup_failed' | 'backend_api_close_failed';

export class BackendApiEntryError extends Error {
  override readonly name = 'BackendApiEntryError';
  readonly code: BackendApiEntryErrorCode;
  constructor(code: BackendApiEntryErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface BackendApiHandle {
  close(): Promise<void>;
}

let runPromise: Promise<BackendApiHandle> | undefined;
let closePromise: Promise<void> | undefined;
let closing = false;
let startup: AbortController | undefined;
let app: OwnedDevelopmentDeliveryFunction | undefined;
let backend: ApiBackendServe | undefined;
let server: Server | undefined;
let directMain = false;

const onSignal = (): void => {
  void close().catch(() => undefined);
};

function close(): Promise<void> {
  if (closePromise !== undefined) return closePromise;
  closing = true;
  startup?.abort();
  backend?.close();
  closePromise = (async () => {
    let ok = true;
    if (runPromise !== undefined) await runPromise.catch(() => undefined);
    const owned = server;
    if (owned?.listening === true) {
      await new Promise<void>((resolvePromise) => {
        owned.close(() => resolvePromise());
        owned.closeAllConnections();
      });
    }
    if (app !== undefined) {
      try {
        await app.close();
      } catch {
        ok = false;
      }
    }
    process.off('SIGTERM', onSignal);
    process.off('SIGINT', onSignal);
    if (!ok) throw new BackendApiEntryError('backend_api_close_failed');
  })();
  if (directMain) closePromise.catch(() => (process.exitCode = 1));
  return closePromise;
}

const handle: BackendApiHandle = Object.freeze({ close });

/** API backendを起動する（1processに1回・二重runは同じPromise）。 */
export function runBackendApi(): Promise<BackendApiHandle> {
  runPromise ??= start();
  return runPromise;
}

async function start(): Promise<BackendApiHandle> {
  if (closing) throw new BackendApiEntryError('backend_api_startup_failed');
  let port: number;
  let serve: ApiBackendServe;
  let M: ReturnType<typeof loadDeploymentConfig>;
  let backendServiceName: string;
  try {
    M = loadDeploymentConfig();
    const T = requireGatewayTopology(M);
    backendServiceName = T.api.backendServiceName;
    const portText = process.env['PORT'];
    if (typeof portText !== 'string' || !PORT_PATTERN.test(portText)) throw new Error('port');
    port = Number(portText);
    if (port < 1024 || port > 65535) throw new Error('port');
    serve = createApiBackendServe({
      transportAuthority: authorityOf(T.api.backendOrigin),
      logicalAuthority: authorityOf(M.api.publicOrigin),
      clock: systemClock,
      cors: applyConsoleCors,
    });
  } catch {
    throw new BackendApiEntryError('backend_api_config_invalid');
  }
  backend = serve;
  const controller = new AbortController();
  startup = controller;
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
  const startedAt = systemClock.now();
  let owned: OwnedDevelopmentDeliveryFunction;
  try {
    owned = await startOwnedIngressDevelopmentDeliveryFunction({
      projectId: M.projectId,
      projectNumber: M.projectNumber,
      databaseId: M.databaseId,
      expectedServiceName: backendServiceName,
      connectNamespace: M.connectNamespace,
      deliveryNamespace: M.deliveryNamespace,
      kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
      secretVersions: { ...M.secretVersions },
      clock: systemClock,
      operation: { deadlineAt: startedAt + START_BUDGET_MS, signal: controller.signal },
      ingress: serve.ingress,
    });
  } catch (error) {
    if (!closing) {
      process.off('SIGTERM', onSignal);
      process.off('SIGINT', onSignal);
    }
    throw new BackendApiEntryError(error instanceof OwnedDevelopmentDeliveryCloseError ? 'backend_api_close_failed' : 'backend_api_startup_failed');
  }
  app = owned;
  const listener = createServer({ requestTimeout: 20_000, headersTimeout: 10_000, maxHeaderSize: 16_384 }, (req, res) => {
    void serve.serve(req, res, async (request, response) => {
      await owned.handler(request as never, response as never);
    }).catch(() => {
      if (!res.writableEnded) res.destroy();
    });
  });
  server = listener;
  listener.on('error', () => undefined);
  try {
    await new Promise<void>((resolvePromise, reject) => {
      listener.once('error', reject);
      listener.listen(port, '0.0.0.0', () => {
        listener.off('error', reject);
        resolvePromise();
      });
    });
  } catch {
    throw new BackendApiEntryError('backend_api_startup_failed');
  }
  if (closing) throw new BackendApiEntryError('backend_api_startup_failed');
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
  runBackendApi().then(
    () => undefined,
    () => {
      process.exitCode = 1;
      try {
        process.stderr.write('{"event":"sttd_api_backend.start_failed"}\n');
      } catch {
        // 記録の失敗は終了codeを変えない。
      }
    },
  );
}
