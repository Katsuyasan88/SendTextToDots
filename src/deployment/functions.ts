// 送信APIのCloud Functions（2nd gen）entry。named export sendtexttodotsapi（実onRequest）だけを公開する（他のfunction・
// admin/debug/health/診断routeは無い）。declared optionsはAPI_FUNCTION_OPTIONS＋配置設定のlocation（region）・API runtime SA＋invoker:'private'。
// 配置設定（src/config/deployment.ts）はimportの最初に1回だけ検証し、未設定・不整合なら固定のDeploymentConfigErrorでimport（discovery）を止める
// （SDK・資格・DB・HTTP・signal登録の前）。export名は設定のapi.functionNameと一致する値だけを検証が受け付ける。
// discovery・importはmetadataの作成だけで、SDK instance・token・秘密・DB・HTTP・signal登録0。
//   - 各HTTPは最初のawaitの前に正しい時計（systemClock）から受信時刻を1回観測し、元期限=受信+20秒と要求固有のcontrollerを作る（req abort・
//     未完のres close・元期限・entryのcloseへ結ぶ）。header・query・body・偽の時計から期限を読まない。所有handlerへは、同じ値を
//     要求固有のAsyncLocalStorageからだけ返す（slot外は固定throw→所有handlerが固定503。他要求・直前の値を共有変数へ保存しない）。
//   - SDK/APIの初期化は、副作用の前にラッチする共有Promiseで、このentry moduleにつき1回だけ（startOwnedIngressDevelopmentDeliveryFunction・
//     配置設定・同じ時計・内部source）。SDKの開始operationは専有のcontroller・開始+20秒で、HTTP個々のingressとは別に所有する（あるHTTPの
//     中断・期限で他要求・共有初期化を止めない）。失敗したPromiseも保持し、要求ごとに取り直さない。
//   - 各HTTPのhandler Promiseは、共有初期化がsettleするまでawaitする（切断・期限で先に返して初期化を背景へ残さない）。初期化の後、元ingressが
//     有効な要求だけALSの中で所有handlerをawaitする。期限・中断・閉鎖・初期化失敗は、書込める時だけ固定503（新しい20秒を取り直さない）。
//   - 初回の実起動の時だけSIGTERM/SIGINTを登録する。close状態と共有closeを副作用の前にラッチ→全HTTPのcontrollerをabort・新要求503→
//     初期化中なら専有startupをabortしてその清掃をawait→readyなら所有API.closeを1回。起動の清掃未完（close_failed）・API.closeの失敗は
//     固定のclose failure。固定event sttd_api.close_failedは共有closeの作成時に結んだ1つの消化処理だけが書く（論理closeごと最大1行）。
//     process全体をexitさせない。
//   - 共有起動が失敗した時だけ、固定event sttd_api.start_failedと固定列挙のstage/codeを最大1行（entry moduleにつき1回）書く。値は所有
//     bootstrapの固定diagnostic（許可表と一致する時だけ）か、それ以外はentry/unclassified。stage sdk/code environment_rejectedで検証済みの
//     整数1〜63をown dataで持つ時だけenvironmentGateMaskを足す。元error・message・stack・cause・環境名/値・URL・UID・秘密・本文は書かない。
//     書込みの例外は消化し、共有起動の結果（固定503）・清掃・close・期限・認証を変えない。maskはHTTP応答・route・外部schemaへ出さない。
// ログは固定eventだけ（利用者データ・token・query・鍵・元error 0）。Cloudのcold start・queue・端末25秒/504の扱いを成功へ変えない。

import { AsyncLocalStorage } from 'node:async_hooks';

import { onRequest, type HttpsFunction } from 'firebase-functions/https';

import type { DeliveryHttpIngress } from '../delivery/api.js';
import { API_FUNCTION_OPTIONS } from '../delivery/functions.js';
import {
  OwnedDevelopmentDeliveryCloseError,
  OwnedDevelopmentDeliveryConfigError,
  OwnedDevelopmentDeliveryStartupError,
  startOwnedIngressDevelopmentDeliveryFunction,
  type OwnedDevelopmentDeliveryFunction,
} from '../google-runtime/delivery-development.js';
import { systemClock } from '../policy.js';
import { applyConsoleCors } from './console-cors.js';
import { loadDeploymentConfig } from '../config/validate.js';

/** 検証済みの配置設定（不正ならここで固定errorを投げ、以後のmetadata作成もしない）。 */
const M = loadDeploymentConfig();

const REQUEST_BUDGET_MS = 20_000;
const START_BUDGET_MS = 20_000;
const UNAVAILABLE_BODY = Buffer.from(JSON.stringify({ error: { code: 'temporarily_unavailable', retryable: true } }), 'utf8');

type Request = Parameters<HttpsFunction>[0];
type Response = Parameters<HttpsFunction>[1];

/** 要求固有のstore（そのHTTPの元ingressだけ）。 */
const requestStore = new AsyncLocalStorage<{ readonly ingress: DeliveryHttpIngress }>();
/** 所有handlerへ渡す内部source。slot外は固定throw（所有handlerが固定503にする）。 */
const ingressSource = (): DeliveryHttpIngress => {
  const store = requestStore.getStore();
  if (store === undefined) throw new Error('api ingress: no request slot');
  return store.ingress;
};

/** 共有初期化の結果（rejectしない）。appが無ければ起動失敗で、cleanupFailedは所有bootstrapの清掃未完（close_failed）。 */
interface SharedStart {
  readonly app: OwnedDevelopmentDeliveryFunction | undefined;
  readonly cleanupFailed: boolean;
}

/** entry closeの固定失敗（清掃未完。元の例外・cause・値を持たない）。 */
class DevelopmentApiCloseError extends Error {
  override readonly name = 'DevelopmentApiCloseError';
  constructor() {
    super('development_api_close_failed');
  }
}

/** 起動失敗の記録に使う固定列挙（これ以外の値は書かない）。 */
const START_STAGES: ReadonlySet<string> = new Set(['config', 'sdk', 'identifier_secret', 'digest_secret', 'marker', 'assembly']);
const START_CODES: ReadonlySet<string> = new Set(['config_invalid', 'environment_rejected', 'aborted', 'timed_out', 'read_failed', 'format_mismatch', 'cleanup_failed', 'unclassified']);
let startFailureRecorded = false;

/** diagnosticのown dataのmask（整数1〜63）だけ。getter・prototype・不正値・読取りの例外はundefined。 */
function environmentGateMaskOf(diagnostic: object): number | undefined {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(diagnostic, 'environmentGateMask');
    if (descriptor === undefined || !('value' in descriptor)) return undefined;
    const value: unknown = descriptor.value;
    return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 63 ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 共有起動の失敗を固定1行だけ記録する（最大1回。副作用の前にラッチ）。所有bootstrapの固定diagnosticが許可表と一致する時だけ
 * そのstage/code、それ以外（entry内の同期失敗・他の例外）はentry/unclassified。書込み・読取りの例外は消化して結果を変えない。
 */
function recordStartFailure(error: unknown): void {
  if (startFailureRecorded) return;
  startFailureRecorded = true;
  try {
    let stage = 'entry';
    let code = 'unclassified';
    let mask: number | undefined;
    if (error instanceof OwnedDevelopmentDeliveryStartupError || error instanceof OwnedDevelopmentDeliveryConfigError || error instanceof OwnedDevelopmentDeliveryCloseError) {
      const diagnostic = error.diagnostic;
      if (diagnostic !== undefined && START_STAGES.has(diagnostic.stage) && START_CODES.has(diagnostic.code)) {
        stage = diagnostic.stage;
        code = diagnostic.code;
        if (stage === 'sdk' && code === 'environment_rejected') mask = environmentGateMaskOf(diagnostic);
      }
    }
    const extra = mask === undefined ? '' : `,"environmentGateMask":${mask}`;
    process.stderr.write(`{"event":"sttd_api.start_failed","stage":"${stage}","code":"${code}"${extra}}\n`);
  } catch {
    // 記録の失敗は共有起動の結果・清掃・closeへ影響させない。
  }
}

/** 進行中のHTTPのcontroller（closeで全てabortする）。 */
const active = new Set<AbortController>();
let closing = false;
let closePromise: Promise<void> | undefined;
let initPromise: Promise<SharedStart> | undefined;
let startup: AbortController | undefined;
let signalsRegistered = false;

/** signalは同じ共有closeを呼ぶだけ（失敗の記録は共有closeの作成時に1つだけ結ぶ）。 */
const onSignal = (): void => {
  void closeEntry();
};

function registerSignals(): void {
  if (signalsRegistered) return;
  signalsRegistered = true;
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
}

function unregisterSignals(): void {
  process.off('SIGTERM', onSignal);
  process.off('SIGINT', onSignal);
}

/**
 * 共有の初期化（1回だけ）。共有Promiseを先に変数へ置いてから（同期の再入も同じPromise）signal登録・起動を始める。失敗も保持し、取り直さない。
 * 起動失敗のうち所有bootstrapの清掃未完（close_failed）は、通常の起動失敗と分けてcleanupFailedに残す。
 */
function startShared(): Promise<SharedStart> {
  if (initPromise !== undefined) return initPromise;
  let settle!: (value: SharedStart) => void;
  initPromise = new Promise<SharedStart>((resolve) => {
    settle = resolve;
  });
  const controller = new AbortController();
  startup = controller;
  try {
    registerSignals();
    // signal登録の同期再入でcloseが始まった時はSDKを起動しない。
    if (closing) {
      settle({ app: undefined, cleanupFailed: false });
      return initPromise;
    }
    begin(controller).then(
      (app) => settle({ app, cleanupFailed: false }),
      (error: unknown) => {
        settle({ app: undefined, cleanupFailed: error instanceof OwnedDevelopmentDeliveryCloseError });
        // 結果を確定した後に固定1行だけ（記録の成否で結果を変えない）。
        recordStartFailure(error);
      },
    );
  } catch {
    settle({ app: undefined, cleanupFailed: false });
    recordStartFailure(undefined);
  }
  return initPromise;
}

function begin(controller: AbortController): Promise<OwnedDevelopmentDeliveryFunction> {
  const startedAt = systemClock.now();
  return startOwnedIngressDevelopmentDeliveryFunction({
    projectId: M.projectId,
    projectNumber: M.projectNumber,
    databaseId: M.databaseId,
    expectedServiceName: M.api.serviceName,
    connectNamespace: M.connectNamespace,
    deliveryNamespace: M.deliveryNamespace,
    kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
    secretVersions: { ...M.secretVersions },
    clock: systemClock,
    operation: { deadlineAt: startedAt + START_BUDGET_MS, signal: controller.signal },
    ingress: ingressSource,
  });
}

/** 書込める時だけ、既存と同じ固定503（no-store・JSON）。 */
function refuse(res: Response): void {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  res.writeHead(503, {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(UNAVAILABLE_BODY.length),
  });
  res.end(UNAVAILABLE_BODY);
}

/**
 * 共有closeを副作用の前にラッチし、HTTP→初期化→所有APIの順に1回だけ閉じる。起動の清掃未完・所有API.closeの失敗は固定のclose failure
 * （reject）。所有API.closeの上限は所有bootstrapの元の10秒のまま（延長しない）。process全体はexitさせない。
 */
function closeEntry(): Promise<void> {
  if (closePromise !== undefined) return closePromise;
  let settle!: (ok: boolean) => void;
  closePromise = new Promise<void>((resolve, reject) => {
    settle = (ok) => (ok ? resolve() : reject(new DevelopmentApiCloseError()));
  });
  // 論理closeごとに固定failure eventを最大1回（signal・再呼出の回数によらない）。closePromise自体はrejectのまま。
  // 記録の書込み例外も消化し、清掃・固定失敗を変えない。
  closePromise.catch(() => {
    try {
      process.stderr.write('{"event":"sttd_api.close_failed"}\n');
    } catch {
      // 記録の失敗は清掃・closeの結果へ影響させない。
    }
  });
  closing = true;
  for (const controller of active) controller.abort();
  startup?.abort();
  void (async () => {
    let ok = true;
    const started = initPromise === undefined ? undefined : await initPromise;
    if (started?.cleanupFailed === true) ok = false;
    if (started?.app !== undefined) {
      try {
        await started.app.close();
      } catch {
        ok = false;
      }
    }
    unregisterSignals();
    settle(ok);
  })();
  return closePromise;
}

async function serve(req: Request, res: Response): Promise<void> {
  // 固定MCP originのCORS。preflight（204）・拒否（403）はSDK・DB・秘密の初期化より前にここで終える。
  // Originなしのnative要求はそのまま、許可された実要求も下のBearer認証を必ず通る。
  if (applyConsoleCors(req, res)) return;
  // 受信時刻は最初のawaitの前に1回だけ（正しい時計）。元期限は受信+20秒で、以後取り直さない。
  const receivedAt = systemClock.now();
  const deadlineAt = receivedAt + REQUEST_BUDGET_MS;
  const controller = new AbortController();
  const ingress: DeliveryHttpIngress = Object.freeze({ receivedAt, deadlineAt, signal: controller.signal });
  const abort = (): void => controller.abort();
  const onResponseClose = (): void => {
    if (!res.writableFinished) controller.abort();
  };
  active.add(controller);
  req.once('aborted', abort);
  res.once('close', onResponseClose);
  const timer = setTimeout(abort, Math.max(0, deadlineAt - systemClock.now()));
  try {
    if (closing) {
      refuse(res);
      return;
    }
    // 共有初期化がsettleするまで待つ（この要求の切断・期限で先に返さない）。
    const { app } = await startShared();
    if (app === undefined || closing || controller.signal.aborted || !(systemClock.now() < deadlineAt)) {
      refuse(res);
      return;
    }
    await requestStore.run({ ingress }, () => app.handler(req, res));
  } catch {
    refuse(res);
  } finally {
    clearTimeout(timer);
    req.off('aborted', abort);
    res.off('close', onResponseClose);
    active.delete(controller);
    controller.abort();
  }
}

/** export名はAPI_FUNCTION_EXPORT（設定のapi.functionNameと同じ。検証が一致を保証する）。 */
export const sendtexttodotsapi = onRequest(
  { ...API_FUNCTION_OPTIONS, region: M.location, serviceAccount: M.api.serviceAccount, invoker: M.api.invoker },
  (req, res) => serve(req, res),
);
