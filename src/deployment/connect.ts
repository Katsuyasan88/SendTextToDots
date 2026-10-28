// MCP接続（Cloud Run process）entry。zero-argumentのrunDevelopmentConnectは、検証済みの配置設定（src/config/deployment.ts）・正しい時計
// （systemClock）・専有のstartup operationで実startOwnedDevelopmentConnectServerを1回だけ起動する。PORTと設定のweb.apiKeyEnvが指す環境変数
// を1回だけ捕捉する（PORTは正規の十進1024〜65535、web keyは非空string。値はlog・Gitへ出さない）。別host・origin・project・SA・key・
// namespace・資格をenv・argvで上書きする口は無い（実SDKのCloud環境・資格・proxy等のgateはまま）。
// 例外として、期限付きの診断ログの終了時刻（STTD_CONNECT_DIAGNOSTICS_UNTIL、既定off・最長30分）だけを読む。
//   - importされた時はSDK・listen・signal登録0。Nodeからこのfileをdirect mainとして起動した時だけrunDevelopmentConnectを呼ぶ（argvの解決と
//     import.meta.urlの比較。query付きのimportはauto-start 0）。
//   - 同じprocessの二重runは同じ起動Promise・close所有へまとめ、失敗後の再初期化は0。ready後の戻り値はfrozen {close}だけ。
//   - 初回runでだけSIGTERM/SIGINTを登録し、signalで先に新しい起動を中止→所有connect.closeを1回（接続server→SDK）・全listener解除。closeは
//     副作用の前に共有Promiseをラッチし、元の最大10秒を延長しない。
//   - direct mainの起動失敗は、所有清掃がsettleした後に固定log・終了code 1。libraryとしてimport・callしただけでは、hostのprocessをexitさせない。
//   - closeの失敗記録（direct mainだけ固定event・終了code 1）は、共有closeの作成時に1つだけ結ぶ（論理closeごと最大1行）。
// 外部へ送った処理の撤回、Cloud Runの10秒SIGTERM内の物理終了は保証しない。

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  OwnedDevelopmentConnectCloseError,
  OwnedDevelopmentConnectConfigError,
  startOwnedDevelopmentConnectServer,
  type OwnedDevelopmentConnectServer,
} from '../google-runtime/connect-development.js';
import { CONNECT_DIAGNOSTICS_ENV, createDiagnosticLogSink } from '../http/log.js';
import { systemClock } from '../policy.js';
import { loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';

const START_BUDGET_MS = 20_000;
/** 正規の十進（符号・空白・末尾文字・先頭0なし）。範囲は別に1024〜65535を確かめる。 */
const PORT_PATTERN = /^[1-9][0-9]{3,4}$/;

export type DevelopmentConnectEntryErrorCode =
  | 'development_connect_config_invalid'
  | 'development_connect_startup_failed'
  | 'development_connect_close_failed';

/** 固定codeと固定messageだけの失敗（元の例外・cause・環境の値を持たない）。 */
export class DevelopmentConnectEntryError extends Error {
  override readonly name = 'DevelopmentConnectEntryError';
  readonly code: DevelopmentConnectEntryErrorCode;
  constructor(code: DevelopmentConnectEntryErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface DevelopmentConnectHandle {
  /** 共有Promise・一度だけ（接続server→SDK）。非成功・未完は固定のclose failure。 */
  close(): Promise<void>;
}

let runPromise: Promise<DevelopmentConnectHandle> | undefined;
let closePromise: Promise<void> | undefined;
let closing = false;
let startup: AbortController | undefined;
let server: OwnedDevelopmentConnectServer | undefined;
/** 起動の失敗が清掃未完（close failure）だったか。 */
let startCleanupFailed = false;
let directMain = false;
let signalsRegistered = false;

/** signalは同じ共有closeを呼ぶだけ（失敗の記録は共有closeの作成時に1つだけ結ぶ）。 */
const onSignal = (): void => {
  void close();
};

/** direct mainの時だけ、固定eventを1行・終了code 1（書込み例外も消化し、終了codeを先に決める）。libraryでは何もしない。 */
function reportDirectMainFailure(event: string): void {
  if (!directMain) return;
  process.exitCode = 1;
  try {
    process.stderr.write(event);
  } catch {
    // 記録の失敗は清掃・失敗の分類へ影響させない。
  }
}

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

/** 副作用の前に共有Promiseをラッチし、起動を中止→所有connect.closeを1回→listener解除。 */
function close(): Promise<void> {
  if (closePromise !== undefined) return closePromise;
  let settle!: (ok: boolean) => void;
  closePromise = new Promise<void>((resolvePromise, reject) => {
    settle = (ok) => (ok ? resolvePromise() : reject(new DevelopmentConnectEntryError('development_connect_close_failed')));
  });
  // 論理closeごとに固定failure記録を最大1回（signal・handle.closeの回数によらない）。closePromise自体はrejectのまま。
  closePromise.catch(() => reportDirectMainFailure('{"event":"sttd_connect.close_failed"}\n'));
  closing = true;
  startup?.abort();
  void (async () => {
    let ok = true;
    if (runPromise !== undefined) {
      try {
        await runPromise;
      } catch {
        // 起動の失敗（所有起動口が清掃済み）。清掃未完ならclose failure。
        if (startCleanupFailed) ok = false;
      }
    }
    const owned = server;
    if (owned !== undefined) {
      try {
        await owned.close();
      } catch {
        ok = false;
      }
    }
    unregisterSignals();
    settle(ok);
  })();
  return closePromise;
}

const handle: DevelopmentConnectHandle = Object.freeze({ close });

/**
 * development MCP接続を起動する（zero-argument・1processに1回）。不正なenvは副作用の前にdevelopment_connect_config_invalid、起動の失敗は
 * 所有清掃の後にdevelopment_connect_startup_failed（清掃未完はdevelopment_connect_close_failed）。二重runは同じPromise。
 */
export function runDevelopmentConnect(): Promise<DevelopmentConnectHandle> {
  if (runPromise !== undefined) return runPromise;
  // 共有Promiseを先に変数へ置いてから（同期の再入も同じPromise）env捕捉・signal登録・起動を始める。
  let resolveRun!: (value: DevelopmentConnectHandle) => void;
  let rejectRun!: (error: unknown) => void;
  runPromise = new Promise<DevelopmentConnectHandle>((resolvePromise, reject) => {
    resolveRun = resolvePromise;
    rejectRun = reject;
  });
  runPromise.catch(() => undefined);
  start().then(resolveRun, rejectRun);
  return runPromise;
}

async function start(): Promise<DevelopmentConnectHandle> {
  // close後の新しい起動は0。
  if (closing) throw new DevelopmentConnectEntryError('development_connect_startup_failed');
  // 配置設定（未設定・不整合）はenv捕捉・signal登録・SDKの前に設定エラー。
  let M: DeploymentConfig;
  try {
    M = loadDeploymentConfig();
  } catch {
    throw new DevelopmentConnectEntryError('development_connect_config_invalid');
  }
  // envは1回だけ捕捉する（値は外へ出さない）。
  const portText = process.env['PORT'];
  const apiKey = process.env[M.web.apiKeyEnv];
  if (typeof portText !== 'string' || !PORT_PATTERN.test(portText)) throw new DevelopmentConnectEntryError('development_connect_config_invalid');
  const bindPort = Number(portText);
  if (bindPort < 1024 || bindPort > 65535) throw new DevelopmentConnectEntryError('development_connect_config_invalid');
  if (typeof apiKey !== 'string' || apiKey === '') throw new DevelopmentConnectEntryError('development_connect_config_invalid');
  // 期限付きの診断ログ（既定off。未設定・不正・過去・30分超は無効で、起動・認証には影響しない）。
  const log = createDiagnosticLogSink({
    until: process.env[CONNECT_DIAGNOSTICS_ENV],
    now: () => systemClock.now(),
    write: (line) => {
      process.stdout.write(`${line}\n`);
    },
  });
  const controller = new AbortController();
  startup = controller;
  registerSignals();
  // signal登録の同期再入でcloseが始まった時はSDKを起動しない。
  if (closing) throw new DevelopmentConnectEntryError('development_connect_startup_failed');
  const startedAt = systemClock.now();
  try {
    server = await startOwnedDevelopmentConnectServer({
      projectId: M.projectId,
      projectNumber: M.projectNumber,
      databaseId: M.databaseId,
      expectedServiceName: M.connect.serviceName,
      bindPort,
      publicOrigin: M.connect.publicOrigin,
      connectNamespace: M.connectNamespace,
      kms: { ...M.kms, readVersions: [...M.kms.readVersions] },
      secretVersions: { ...M.secretVersions },
      web: { apiKey, authDomain: M.web.authDomain, projectId: M.web.projectId },
      clock: systemClock,
      operation: { deadlineAt: startedAt + START_BUDGET_MS, signal: controller.signal },
      ...(log !== undefined ? { log } : {}),
    });
  } catch (error) {
    if (!closing) unregisterSignals();
    if (error instanceof OwnedDevelopmentConnectCloseError) {
      startCleanupFailed = true;
      throw new DevelopmentConnectEntryError('development_connect_close_failed');
    }
    throw new DevelopmentConnectEntryError(
      error instanceof OwnedDevelopmentConnectConfigError ? 'development_connect_config_invalid' : 'development_connect_startup_failed',
    );
  }
  return handle;
}

/** このfileがNodeのdirect mainか（argvの解決とimport.meta.urlの比較。I/O 0）。 */
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
  runDevelopmentConnect().then(
    () => undefined,
    () => reportDirectMainFailure('{"event":"sttd_connect.start_failed"}\n'),
  );
}
