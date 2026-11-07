// 送信APIのdirect Cloud Run entry（体験用など、配置設定のapi.runtimeがcloud-run-v1でgateway-v1でない時だけ）。通常の送信APIは
// 既存のFunctions entry（functions.ts）のままで、このentryで置き換えない。既存の送信API bootstrap
// （startOwnedIngressDevelopmentDeliveryFunction: 本人/source/App Check・鍵・最終transaction・配送）をapi.serviceNameのK_SERVICE gateで
// 1回だけ起動し、node:httpの待受へ結ぶ。gateway専用のbackend adapterは使わない（公開Hostだけを受ける）。
// zero-argumentのrunApiは、配置設定（runtime=cloud-run-v1・direct）・PORT・K_SERVICEを副作用の前に確かめ、不成立は固定のconfig error
// （SDK・資格・DB・listen・signal登録0）。importだけでは何もしない。
// 各要求は受信時刻と元20秒期限・AbortControllerを最初のawaitの前に1回だけ作り、要求固有のAsyncLocalStorageで所有handlerへ渡す
// （以後時間を取り直さない・他要求と共有しない）。期限・切断・closeはその要求のsignalだけを中止する。本文は所有handlerの既存Node
// stream parserが読み、認可も既存のまま。
// closeは副作用の前に共有Promiseへラッチし（abort listenerからの同期再入も同じPromise）、要求を中止→起動待ち→待受→所有API.closeを
// 1回だけ行う。direct mainの時だけ起動し、失敗は固定log・終了code 1。

import { AsyncLocalStorage } from 'node:async_hooks';
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';
import type { DeliveryHttpIngress } from '../delivery/api.js';
import { types } from 'node:util';

import {
  OwnedDevelopmentDeliveryCloseError,
  OwnedDevelopmentDeliveryConfigError,
  OwnedDevelopmentDeliveryStartupError,
  startOwnedIngressDevelopmentDeliveryFunction,
  type OwnedDevelopmentDeliveryFunction,
  type OwnedDevelopmentDeliveryOptions,
} from '../google-runtime/delivery-development.js';
import { systemClock } from '../policy.js';
import { applyConsoleCors } from './console-cors.js';

const START_BUDGET_MS = 20_000;
export const API_REQUEST_BUDGET_MS = 20_000;
const PORT_PATTERN = /^[1-9][0-9]{0,4}$/;
const UNAVAILABLE_BODY = Buffer.from(JSON.stringify({ error: { code: 'temporarily_unavailable', retryable: true } }), 'utf8');
const BAD_HOST_BODY = Buffer.from(JSON.stringify({ error: { code: 'invalid_request' } }), 'utf8');

export type ApiEntryErrorCode = 'api_config_invalid' | 'api_startup_failed' | 'api_close_failed';

/** 起動失敗の固定診断（許可表のstage/codeと、sdk/environment_rejectedの時だけ整数1〜63のmask）。元の例外・値は持たない。 */
export interface ApiStartDiagnostic {
  readonly stage: string;
  readonly code: string;
  readonly environmentGateMask?: number;
}

export class ApiEntryError extends Error {
  override readonly name = 'ApiEntryError';
  readonly code: ApiEntryErrorCode;
  readonly diagnostic: ApiStartDiagnostic | undefined;
  constructor(code: ApiEntryErrorCode, diagnostic?: ApiStartDiagnostic) {
    super(code);
    this.code = code;
    this.diagnostic = diagnostic === undefined ? undefined : Object.freeze({ ...diagnostic });
  }
}

/** Functions entry（functions.ts）と同じ許可表。 */
const START_STAGES: ReadonlySet<string> = new Set(['config', 'sdk', 'identifier_secret', 'digest_secret', 'marker', 'assembly']);
const START_CODES: ReadonlySet<string> = new Set(['config_invalid', 'environment_rejected', 'aborted', 'timed_out', 'read_failed', 'format_mismatch', 'cleanup_failed', 'unclassified']);
const UNCLASSIFIED: ApiStartDiagnostic = Object.freeze({ stage: 'entry', code: 'unclassified' });
const CONFIG_INVALID: ApiStartDiagnostic = Object.freeze({ stage: 'config', code: 'config_invalid' });

/** own data propertyの値だけ（getter・Proxy・読取りの例外はundefined）。 */
function ownDataValue(holder: unknown, key: string): unknown {
  try {
    if (typeof holder !== 'object' || holder === null || types.isProxy(holder)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(holder, key);
    return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 所有bootstrapの既知errorが持つ固定diagnosticから、許可表のstage/codeとsdk/environment_rejectedの整数1〜63のmaskだけを取り出す。
 * それ以外（任意のerror・不正な診断・getter・Proxy）はentry/unclassified。読取りの例外は元の失敗・清掃へ影響させない。
 */
export function startDiagnosticOf(error: unknown): ApiStartDiagnostic {
  try {
    if (!(error instanceof OwnedDevelopmentDeliveryStartupError || error instanceof OwnedDevelopmentDeliveryConfigError || error instanceof OwnedDevelopmentDeliveryCloseError)) return UNCLASSIFIED;
    const diagnostic = ownDataValue(error, 'diagnostic');
    const stage = ownDataValue(diagnostic, 'stage');
    const code = ownDataValue(diagnostic, 'code');
    if (typeof stage !== 'string' || typeof code !== 'string' || !START_STAGES.has(stage) || !START_CODES.has(code)) return UNCLASSIFIED;
    const mask = ownDataValue(diagnostic, 'environmentGateMask');
    const maskOk = stage === 'sdk' && code === 'environment_rejected' && typeof mask === 'number' && Number.isInteger(mask) && mask >= 1 && mask <= 63;
    return Object.freeze(maskOk ? { stage, code, environmentGateMask: mask } : { stage, code });
  } catch {
    return UNCLASSIFIED;
  }
}

/** mainの起動失敗の固定1行（ApiEntryErrorの診断だけ。それ以外はentry/unclassified）。 */
export function startFailureLine(error: unknown): string {
  const d = error instanceof ApiEntryError ? (ownDataValue(error, 'diagnostic') as ApiStartDiagnostic | undefined) : undefined;
  const stage = typeof d?.stage === 'string' && (START_STAGES.has(d.stage) || d.stage === 'entry') ? d.stage : 'entry';
  const code = typeof d?.code === 'string' && START_CODES.has(d.code) ? d.code : 'unclassified';
  const mask = stage === 'sdk' && code === 'environment_rejected' && Number.isInteger(d?.environmentGateMask) && (d?.environmentGateMask as number) >= 1 && (d?.environmentGateMask as number) <= 63 ? `,"environmentGateMask":${d?.environmentGateMask as number}` : '';
  return `{"event":"sttd_api.start_failed","stage":"${stage}","code":"${code}"${mask}}\n`;
}

export interface ApiHandle {
  /** listen完了後の実port（Cloud RunではPORTと同じ）。 */
  readonly port: number;
  close(): Promise<void>;
}

/** 所有bootstrapの最小形（試験は合成を渡す。製品は既存のstartOwnedIngressDevelopmentDeliveryFunction）。 */
export interface ApiOwnedApp {
  readonly handler: (req: IncomingMessage, res: ServerResponse) => unknown;
  close(): Promise<void>;
}

/** entryの依存（製品は既定値。試験だけが合成clock/timer/bootstrap/待受を渡す）。 */
export interface ApiEntryDeps {
  readonly loadConfig: () => DeploymentConfig;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly clock: { now(): number };
  readonly bootstrap: (options: OwnedDevelopmentDeliveryOptions) => Promise<ApiOwnedApp>;
  readonly createServer: (listener: (req: IncomingMessage, res: ServerResponse) => void) => Server;
  readonly setTimer: (fn: () => void, ms: number) => unknown;
  readonly clearTimer: (timer: unknown) => void;
  readonly signals: { on(fn: () => void): void; off(fn: () => void): void };
  readonly cors: (req: IncomingMessage, res: ServerResponse) => boolean;
  /** signal経由のcloseが清掃未完で終わった時に1回だけ呼ぶ（direct mainの終了code・固定eventだけ。値・例外を渡さない）。 */
  readonly onSignalCloseFailed?: () => void;
}

export interface ApiEntry {
  run(): Promise<ApiHandle>;
  close(): Promise<void>;
}

/** 書込める時だけ固定のJSON応答（no-store）。 */
function reply(res: ServerResponse, status: number, body: Buffer): void {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  res.writeHead(status, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(body.length) });
  res.end(body);
}

/** Hostは1個で公開originのauthorityと完全一致（重複・欠落・別名は拒否）。 */
function hostMatches(req: IncomingMessage, authority: string): boolean {
  let count = 0;
  const raw = req.rawHeaders;
  for (let index = 0; index < raw.length; index += 2) if (String(raw[index]).toLowerCase() === 'host') count += 1;
  return count === 1 && typeof req.headers.host === 'string' && req.headers.host.toLowerCase() === authority;
}

/** direct Cloud Run entryを組み立てる（1 entryにつきrun・closeとも共有Promiseで1回）。 */
export function createApiEntry(deps: ApiEntryDeps): ApiEntry {
  const requestStore = new AsyncLocalStorage<{ readonly ingress: DeliveryHttpIngress }>();
  const ingressSource = (): DeliveryHttpIngress => {
    const store = requestStore.getStore();
    if (store === undefined) throw new Error('api ingress: no request slot');
    return store.ingress;
  };
  let runPromise: Promise<ApiHandle> | undefined;
  let closePromise: Promise<void> | undefined;
  let closing = false;
  let startup: AbortController | undefined;
  let app: ApiOwnedApp | undefined;
  let server: Server | undefined;
  let signalsOn = false;
  let signalFailureReported = false;
  const active = new Set<AbortController>();

  // signalは同じ共有closeを呼ぶだけ。清掃未完は（多重signal・再入でも）1回だけ通知する。
  const onSignal = (): void => {
    void close().catch(() => {
      if (signalFailureReported) return;
      signalFailureReported = true;
      try {
        deps.onSignalCloseFailed?.();
      } catch {
        // 通知の失敗は清掃結果を変えない。
      }
    });
  };
  const signalsOff = (): void => {
    if (!signalsOn) return;
    signalsOn = false;
    deps.signals.off(onSignal);
  };

  function close(): Promise<void> {
    if (closePromise !== undefined) return closePromise;
    // 副作用（abort）の前にラッチする: abort listenerからの同期再入は同じPromiseを受け取る。
    let settle!: (ok: boolean) => void;
    closePromise = new Promise<void>((resolvePromise, reject) => {
      settle = (ok) => (ok ? resolvePromise() : reject(new ApiEntryError('api_close_failed')));
    });
    closing = true;
    startup?.abort();
    for (const controller of [...active]) controller.abort();
    void (async () => {
      let ok = true;
      // 起動側の清掃未完（後着の所有API・bootstrap・listen失敗の回収失敗）はcloseでも成功へ落とさない。
      if (runPromise !== undefined) {
        await runPromise.catch((error: unknown) => {
          if (error instanceof ApiEntryError && error.code === 'api_close_failed') ok = false;
        });
      }
      const owned = server;
      if (owned?.listening === true) {
        await new Promise<void>((resolvePromise) => {
          owned.close(() => resolvePromise());
          owned.closeAllConnections();
        });
      }
      const ownedApp = app;
      app = undefined;
      if (ownedApp !== undefined) {
        try {
          await ownedApp.close();
        } catch {
          ok = false;
        }
      }
      signalsOff();
      settle(ok);
    })();
    return closePromise;
  }

  async function start(): Promise<ApiHandle> {
    if (closing) throw new ApiEntryError('api_startup_failed');
    let port: number;
    let M: DeploymentConfig;
    let authority: string;
    try {
      M = deps.loadConfig();
      // 体験用direct Runだけ: cloud-run-v1の明示とdirect（gateway-v1でない）が必要。
      if (M.api.runtime !== 'cloud-run-v1' || M.topology !== undefined) throw new Error('runtime');
      const portText = deps.env['PORT'];
      if (typeof portText !== 'string' || !PORT_PATTERN.test(portText)) throw new Error('port');
      port = Number(portText);
      if (port < 1 || port > 65535) throw new Error('port');
      if (deps.env['K_SERVICE'] !== M.api.serviceName) throw new Error('service');
      authority = new URL(M.api.publicOrigin).host.toLowerCase();
    } catch {
      throw new ApiEntryError('api_config_invalid', CONFIG_INVALID);
    }
    const controller = new AbortController();
    startup = controller;
    signalsOn = true;
    deps.signals.on(onSignal);
    const startedAt = deps.clock.now();
    let owned: ApiOwnedApp;
    try {
      owned = await deps.bootstrap({
        projectId: M.projectId,
        projectNumber: M.projectNumber,
        databaseId: M.databaseId,
        expectedServiceName: M.api.serviceName,
        connectNamespace: M.connectNamespace,
        deliveryNamespace: M.deliveryNamespace,
        kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
        secretVersions: { ...M.secretVersions },
        clock: deps.clock,
        operation: { deadlineAt: startedAt + START_BUDGET_MS, signal: controller.signal },
        ingress: ingressSource,
      });
    } catch (error) {
      if (!closing) signalsOff();
      // 所有bootstrapの固定diagnosticだけを許可表で保持（元の例外・message・causeは写さない）
      throw new ApiEntryError(error instanceof OwnedDevelopmentDeliveryCloseError ? 'api_close_failed' : 'api_startup_failed', startDiagnosticOf(error));
    }
    if (closing) {
      // 起動中にcloseされた: 後着の所有APIはここで1回だけ閉じ、待受は作らない。回収失敗は清掃未完（run・closeとも）。
      try {
        await owned.close();
      } catch {
        throw new ApiEntryError('api_close_failed');
      }
      throw new ApiEntryError('api_startup_failed');
    }
    app = owned;
    const serve = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      // 受信時刻は最初のawaitの前に1回だけ。元期限は受信+20秒で、以後取り直さない。
      const receivedAt = deps.clock.now();
      const deadlineAt = receivedAt + API_REQUEST_BUDGET_MS;
      const request = new AbortController();
      const ingress: DeliveryHttpIngress = Object.freeze({ receivedAt, deadlineAt, signal: request.signal });
      const abort = (): void => request.abort();
      const onResponseClose = (): void => {
        if (!res.writableFinished) request.abort();
      };
      active.add(request);
      req.once('aborted', abort);
      res.once('close', onResponseClose);
      const timer = deps.setTimer(abort, Math.max(0, deadlineAt - deps.clock.now()));
      try {
        const target = req.url ?? '';
        if (!hostMatches(req, authority) || !target.startsWith('/') || target.startsWith('//')) {
          reply(res, 400, BAD_HOST_BODY);
          return;
        }
        // 既存の固定MCP originのCORS（preflight・拒否はここで終える）。
        if (deps.cors(req, res)) return;
        const current = app;
        if (current === undefined || closing || request.signal.aborted || !(deps.clock.now() < deadlineAt)) {
          reply(res, 503, UNAVAILABLE_BODY);
          return;
        }
        await requestStore.run({ ingress }, () => current.handler(req, res));
      } catch {
        reply(res, 503, UNAVAILABLE_BODY);
      } finally {
        deps.clearTimer(timer);
        req.off('aborted', abort);
        res.off('close', onResponseClose);
        active.delete(request);
        request.abort();
      }
    };
    const listener = deps.createServer((req, res) => {
      void serve(req, res).catch(() => {
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
      // listen失敗: 所有APIを1回だけ回収してから固定の起動失敗（清掃未完はclose error）。
      const ownedApp = app;
      app = undefined;
      let cleaned = true;
      try {
        await ownedApp?.close();
      } catch {
        cleaned = false;
      }
      if (!closing) signalsOff();
      throw new ApiEntryError(cleaned ? 'api_startup_failed' : 'api_close_failed');
    }
    if (closing) throw new ApiEntryError('api_startup_failed');
    const address = listener.address();
    return Object.freeze({ port: typeof address === 'object' && address !== null ? address.port : port, close });
  }

  return Object.freeze({
    run(): Promise<ApiHandle> {
      runPromise ??= start();
      return runPromise;
    },
    close,
  });
}

const defaultEntry = createApiEntry({
  loadConfig: loadDeploymentConfig,
  env: process.env,
  clock: systemClock,
  bootstrap: (options) => startOwnedIngressDevelopmentDeliveryFunction(options) as Promise<OwnedDevelopmentDeliveryFunction & ApiOwnedApp>,
  createServer: (listener) => createHttpServer({ requestTimeout: API_REQUEST_BUDGET_MS, headersTimeout: 10_000, maxHeaderSize: 16_384 }, listener),
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
  signals: {
    on: (fn) => {
      process.on('SIGTERM', fn);
      process.on('SIGINT', fn);
    },
    off: (fn) => {
      process.off('SIGTERM', fn);
      process.off('SIGINT', fn);
    },
  },
  cors: (req, res) => applyConsoleCors(req as never, res as never),
  // direct mainの時だけ: signal経由の清掃未完を終了code 1と固定event 1行で残す（importだけでは何もしない）。
  onSignalCloseFailed: () => {
    if (!directMain) return;
    process.exitCode = 1;
    try {
      process.stderr.write('{"event":"sttd_api.close_failed"}\n');
    } catch {
      // 記録の失敗は終了codeを変えない。
    }
  },
});
let directMain = false;

/** 送信APIをdirect Cloud Runで起動する（1processに1回・二重runは同じPromise・失敗後も取り直さない）。 */
export function runApi(): Promise<ApiHandle> {
  return defaultEntry.run();
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
  runApi().then(
    () => {
      try {
        process.stdout.write('{"event":"sttd_api.ready"}\n');
      } catch {
        // 記録の失敗は起動結果を変えない。
      }
    },
    (error: unknown) => {
      process.exitCode = 1;
      try {
        process.stderr.write(startFailureLine(error)); // 固定1行（許可表のstage/codeと検証済みmaskだけ）
      } catch {
        // 記録の失敗は終了codeを変えない。
      }
    },
  );
}
