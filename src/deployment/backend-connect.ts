// gateway-v1配置のMCP業務backend（Invoker IAM必須の別Cloud Run service）。既存のMCP接続bootstrap（startOwnedDevelopmentConnectServer:
// Provider・本人/source承認・Grant・MCP・購読・取消）を、topology.connect.backendServiceNameのK_SERVICE gateと、backend originのhostを
// transport authorityとする入口adapterで1回だけ起動する。issuer/resource/cookie/CSRF/PKCEは公開originのまま（物理Hostだけが別）。
// zero-argumentのrunBackendConnectは、配置設定（topology必須）・PORT・設定のweb.apiKeyEnvを副作用の前に1回だけ捕捉し、不正は固定の
// config error（SDK・資格・DB・listen 0）。起動失敗は所有清掃の後にstartup error（清掃未完はclose error）。importだけではSDK・listen・
// signal登録0。direct mainの時だけ起動し、失敗は固定log・終了code 1。closeは共有Promiseで1回（所有connect.close）。

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadDeploymentConfig } from '../config/validate.js';
import { authorityOf } from '../gateway/contract.js';
import { requireGatewayTopology } from '../gateway/runtime.js';
import {
  OwnedDevelopmentConnectCloseError,
  OwnedDevelopmentConnectConfigError,
  startOwnedDevelopmentConnectServer,
  type OwnedDevelopmentConnectServer,
} from '../google-runtime/connect-development.js';
import { systemClock } from '../policy.js';

const START_BUDGET_MS = 20_000;
const PORT_PATTERN = /^[1-9][0-9]{3,4}$/;

export type BackendConnectEntryErrorCode = 'backend_connect_config_invalid' | 'backend_connect_startup_failed' | 'backend_connect_close_failed';

export class BackendConnectEntryError extends Error {
  override readonly name = 'BackendConnectEntryError';
  readonly code: BackendConnectEntryErrorCode;
  constructor(code: BackendConnectEntryErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface BackendConnectHandle {
  close(): Promise<void>;
}

let runPromise: Promise<BackendConnectHandle> | undefined;
let closePromise: Promise<void> | undefined;
let closing = false;
let startup: AbortController | undefined;
let server: OwnedDevelopmentConnectServer | undefined;
let directMain = false;

const onSignal = (): void => {
  void close().catch(() => undefined);
};

function close(): Promise<void> {
  if (closePromise !== undefined) return closePromise;
  closing = true;
  startup?.abort();
  closePromise = (async () => {
    let ok = true;
    if (runPromise !== undefined) await runPromise.catch(() => undefined);
    if (server !== undefined) {
      try {
        await server.close();
      } catch {
        ok = false;
      }
    }
    process.off('SIGTERM', onSignal);
    process.off('SIGINT', onSignal);
    if (!ok) throw new BackendConnectEntryError('backend_connect_close_failed');
  })();
  if (directMain) closePromise.catch(() => (process.exitCode = 1));
  return closePromise;
}

const handle: BackendConnectHandle = Object.freeze({ close });

/** MCP backendを起動する（1processに1回・二重runは同じPromise）。 */
export function runBackendConnect(): Promise<BackendConnectHandle> {
  runPromise ??= start();
  return runPromise;
}

async function start(): Promise<BackendConnectHandle> {
  if (closing) throw new BackendConnectEntryError('backend_connect_startup_failed');
  let M: ReturnType<typeof loadDeploymentConfig>;
  let backendServiceName: string;
  let transportAuthority: string;
  let bindPort: number;
  let apiKey: string;
  try {
    M = loadDeploymentConfig();
    const T = requireGatewayTopology(M);
    backendServiceName = T.connect.backendServiceName;
    transportAuthority = authorityOf(T.connect.backendOrigin);
    const portText = process.env['PORT'];
    const key = process.env[M.web.apiKeyEnv];
    if (typeof portText !== 'string' || !PORT_PATTERN.test(portText)) throw new Error('port');
    bindPort = Number(portText);
    if (bindPort < 1024 || bindPort > 65535) throw new Error('port');
    if (typeof key !== 'string' || key === '') throw new Error('key');
    apiKey = key;
  } catch {
    throw new BackendConnectEntryError('backend_connect_config_invalid');
  }
  const controller = new AbortController();
  startup = controller;
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
  const startedAt = systemClock.now();
  try {
    server = await startOwnedDevelopmentConnectServer({
      projectId: M.projectId,
      projectNumber: M.projectNumber,
      databaseId: M.databaseId,
      expectedServiceName: backendServiceName,
      bindPort,
      publicOrigin: M.connect.publicOrigin,
      transportAuthority,
      connectNamespace: M.connectNamespace,
      kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
      secretVersions: { ...M.secretVersions },
      web: { apiKey, authDomain: M.web.authDomain, projectId: M.web.projectId },
      clock: systemClock,
      operation: { deadlineAt: startedAt + START_BUDGET_MS, signal: controller.signal },
    });
  } catch (error) {
    if (!closing) {
      process.off('SIGTERM', onSignal);
      process.off('SIGINT', onSignal);
    }
    if (error instanceof OwnedDevelopmentConnectCloseError) throw new BackendConnectEntryError('backend_connect_close_failed');
    throw new BackendConnectEntryError(error instanceof OwnedDevelopmentConnectConfigError ? 'backend_connect_config_invalid' : 'backend_connect_startup_failed');
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
  runBackendConnect().then(
    () => undefined,
    () => {
      process.exitCode = 1;
      try {
        process.stderr.write('{"event":"sttd_connect_backend.start_failed"}\n');
      } catch {
        // 記録の失敗は終了codeを変えない。
      }
    },
  );
}
