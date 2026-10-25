// 送信API（Functions sendtexttodotsapi）のSDK所有起動口。openDevelopmentGoogleSdk→Google Secret reader・Google KMS transport・ConnectStorage
// （KMS sealing port＋RequestAuthContext）→createIngressKmsRequestDeliveryFunctionを、同じ元起動operationと同じ捕捉clockで逐次に構成する。
// SDK・db・client・identity・hasher・鍵・egress・reader・factory・hooks・budgetの注入口は無く、別資格へのfallbackもしない。egressは内部の
// createProductEgressだけ。SDKの環境gateは固定API serviceのbounded-memory-hint-v1（development.ts）で、ここから切り替える入力は無い。
//   - configは配置設定（src/config/deployment.ts）の検証済みproject・number・database・API serviceと一致するものだけ（kms・4用途secretVersionsはMCP起動口と同じ型・
//     検査）。他serviceはSDK・秘密・時計の実呼出し前に{config, config_invalid}。exact own dataを1回捕捉して写し、callerの後続改変を読まない。
//     borrowed config・clock・signalは凍結・書換え・abortしない。namespace・鍵・版を生成・選択・推測しない。
//   - 元期限はmin(親deadlineAt, 開始+20秒)を1回だけ作り、専有controller・親listener・物理watchdogを全段階で共有する。SDKの前後・各Secret
//     readの前後・markerの前後・組立ての前後・readyの採用時にsignal→clock→signalで検査し、awaitの間も親の中断・期限で止める。
//   - 秘密はidentifierKey→commandDigestKeyの2件だけを各1回（jwks・cookie 0）。2件全体の上限は読込み開始+5秒と元期限の短い方（各readで
//     5秒を取り直さない）。各32バイト・値の異なる2鍵だけ。失敗・中断・後着でも所有Bufferを0埋めし、SDKのbytesは元readerが後着も消す。
//     identifierKeyの所有Bufferは実createHmacHasherへ渡してhandleの終了まで保持し、digestはFunctions runtimeが写しを取った直後に0埋めする。
//     readerは読込みの後にdisposeする（以後の秘密read 0）。
//   - markerは既存で正しいものだけ（sttdAuth/{kms.namespace}/config/kms-subscriptionを1回読み、requireKmsMarkerで照合）。作成・修復0。
//   - ingressは必須で、entryの要求固有storeから元HTTP ingressを返すtrustedな内部source。起動時には呼ばずに捕捉してFunctions factoryへ渡す。
//   - API handlerは新しいALS起動slotに包まない。AS/UIDのboxはcreateConnectKmsSealingPortとRequestAuthContext.currentで、slotが無ければ
//     fail closed（配送APIの経路はAS/UIDの暗号を呼ばない）。
//   - 戻り値はfrozen {handler, close}だけ。closeは副作用の前に共有Promiseをラッチし、専有controllerのabort→app.close（5秒）→context・
//     reader・transportのdisposeと所有Bufferの0埋め→成否とも所有SDKのclose（5秒）を各1回試みる（合計10秒以内）。部分失敗でも同じ清掃を行い、
//     清掃未完は固定のclose failure（SDKのclose_failedを起動失敗へ丸めない）。errorは固定のconfig/startup/closeの3種だけ。
//   - 起動失敗の固定errorは、固定列挙の非秘密diagnostic {stage, code}だけを持つ（stageはconfig/sdk/identifier_secret/digest_secret/marker/
//     assembly、codeは設定不正・環境拒否・中断・期限・取得失敗・形式不一致・清掃失敗・未分類）。所有SDKのenvironment_rejectedが持つ検証済み
//     own data mask（整数1〜63）だけをstage sdk/code environment_rejectedのdiagnosticへenvironmentGateMaskとして写す。元の例外・message・
//     cause・値は持たない・写さない（記録はentryが最大1件だけ行う）。
// 既に始めたSDK・HTTPの物理取消、RAMの物理消去、Cloudのcold startの所要時間は保証しない。

import { timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';

import { cryptoKeyLocation, loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';
import { ConnectStorage, isConnectNamespace } from '../connect/firestore.js';
import { createConnectKmsSealingPort } from '../connect/kms-port.js';
import type { DeliveryHttpIngress } from '../delivery/api.js';
import { createIngressKmsRequestDeliveryFunction, type KmsRequestDeliveryFunction } from '../delivery/kms-functions.js';
import { isKmsDeliveryNamespace } from '../delivery/kms-store.js';
import { createProductEgress } from '../egress/product.js';
import type { LogSink } from '../http/log.js';
import { createGoogleSecretReader, type GoogleSecretReader, type GoogleSecretVersions } from '../keys/google-secret-reader.js';
import { createRequestAuthContext, type RequestAuthContext } from '../oauth/request-auth-runtime.js';
import { PRODUCT_POLICY } from '../policy.js';
import { createGoogleKmsTransport, type GoogleKmsTransport } from '../protection/google-kms-transport.js';
import { arrayItems, dataFields, GoogleSdkPortError, isEpochMs, isRealSignal, methodOf } from '../protection/google-sdk-call.js';
import { createHmacHasher } from '../secrets.js';
import { createKmsSubscriptionPolicy, requireKmsMarker, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { AUTH_STORAGE_ROOT, KMS_SUBSCRIPTION_CONFIG_DOC } from '../storage/firestore/kms-subscription-format.js';
import type { GoogleKmsConnectKmsOptions } from '../connect/google-kms-server.js';
import { DevelopmentGoogleSdkError, isDevelopmentEnvironmentGateMask, openDevelopmentGoogleSdk, type DevelopmentGoogleSdk } from './development.js';

const START_BUDGET_MS = 20_000;
const SECRET_LOAD_MS = 5_000;
const CLOSE_STEP_MS = 5_000;
const KEY_BYTES = 32;
const CLOUD_RUN_NAME = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
/** 既存Google secret readerと同じ規則（global resourceの固定数値版、別projectなし）。 */
const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
const VERSION_NUMBER = /^[1-9][0-9]{0,15}$/;
const SECRET_PURPOSES = ['jwks', 'cookieKeys', 'identifierKey', 'commandDigestKey'] as const;
const OPTION_KEYS = [
  'projectId',
  'projectNumber',
  'databaseId',
  'expectedServiceName',
  'connectNamespace',
  'deliveryNamespace',
  'kms',
  'secretVersions',
  'clock',
  'operation',
  'ingress',
] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions'] as const;

export type OwnedDevelopmentDeliveryErrorCode =
  | 'owned_development_delivery_config_invalid'
  | 'owned_development_delivery_startup_failed'
  | 'owned_development_delivery_close_failed';

/** 起動失敗の段階（固定列挙）。 */
export type OwnedDevelopmentDeliveryStartStage = 'config' | 'sdk' | 'identifier_secret' | 'digest_secret' | 'marker' | 'assembly';
/** 起動失敗の分類（固定列挙）。 */
export type OwnedDevelopmentDeliveryStartCode =
  | 'config_invalid'
  | 'environment_rejected'
  | 'aborted'
  | 'timed_out'
  | 'read_failed'
  | 'format_mismatch'
  | 'cleanup_failed'
  | 'unclassified';
/** 固定列挙のstage/codeだけ（元の例外・値・URL・本人値を持たない）。 */
export interface OwnedDevelopmentDeliveryStartDiagnostic {
  readonly stage: OwnedDevelopmentDeliveryStartStage;
  readonly code: OwnedDevelopmentDeliveryStartCode;
  /** stage sdk/code environment_rejectedで検証済みの整数1〜63の時だけ（それ以外はfield自体が無い）。 */
  readonly environmentGateMask?: number;
}

/** own dataのenvironmentGateMask（整数1〜63）だけ。getter・prototype・Proxy・不正値・読取りの例外はundefined。 */
function ownEnvironmentGateMask(holder: object): number | undefined {
  try {
    if (types.isProxy(holder)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(holder, 'environmentGateMask');
    if (descriptor === undefined || !('value' in descriptor)) return undefined;
    const value: unknown = descriptor.value;
    return isDevelopmentEnvironmentGateMask(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** stage/codeを写し、sdk/environment_rejectedで検証済みのmaskだけを足す（それ以外のmaskは省略）。 */
function freezeDiagnostic(diagnostic: OwnedDevelopmentDeliveryStartDiagnostic): OwnedDevelopmentDeliveryStartDiagnostic {
  const { stage, code } = diagnostic;
  const mask = stage === 'sdk' && code === 'environment_rejected' ? ownEnvironmentGateMask(diagnostic) : undefined;
  return mask === undefined ? Object.freeze({ stage, code }) : Object.freeze({ stage, code, environmentGateMask: mask });
}

/** 固定codeと固定messageだけの失敗（元の例外・cause・値・URL・本人値を持たない）。起動の失敗だけ固定diagnosticを持てる。 */
class OwnedDevelopmentDeliveryError extends Error {
  readonly code: OwnedDevelopmentDeliveryErrorCode;
  readonly diagnostic: OwnedDevelopmentDeliveryStartDiagnostic | undefined;
  constructor(code: OwnedDevelopmentDeliveryErrorCode, diagnostic?: OwnedDevelopmentDeliveryStartDiagnostic) {
    super(code);
    this.code = code;
    this.diagnostic = diagnostic === undefined ? undefined : freezeDiagnostic(diagnostic);
  }
}

/** 設定の不正（SDK生成・秘密・DB・組立ての前）。 */
export class OwnedDevelopmentDeliveryConfigError extends OwnedDevelopmentDeliveryError {
  override readonly name = 'OwnedDevelopmentDeliveryConfigError';
  constructor(diagnostic?: OwnedDevelopmentDeliveryStartDiagnostic) {
    super('owned_development_delivery_config_invalid', diagnostic);
  }
}

/** 起動の失敗（所有したSDK・port・Bufferは清掃済み）。 */
export class OwnedDevelopmentDeliveryStartupError extends OwnedDevelopmentDeliveryError {
  override readonly name = 'OwnedDevelopmentDeliveryStartupError';
  constructor(diagnostic?: OwnedDevelopmentDeliveryStartDiagnostic) {
    super('owned_development_delivery_startup_failed', diagnostic);
  }
}

/** 清掃・closeが完了しなかった・失敗した（成功と偽らない）。 */
export class OwnedDevelopmentDeliveryCloseError extends OwnedDevelopmentDeliveryError {
  override readonly name = 'OwnedDevelopmentDeliveryCloseError';
  constructor(diagnostic?: OwnedDevelopmentDeliveryStartDiagnostic) {
    super('owned_development_delivery_close_failed', diagnostic);
  }
}

export interface OwnedDevelopmentDeliveryOptions {
  /** 配置設定のprojectId（一致だけを受け付ける）。 */
  readonly projectId: string;
  /** 配置設定のprojectNumber。 */
  readonly projectNumber: string;
  /** 配置設定のdatabaseId。 */
  readonly databaseId: string;
  /** 配置先Cloud Runの正規service名（配置設定のapi.serviceNameだけ。SDKのK_SERVICE gate）。 */
  readonly expectedServiceName: string;
  /** 接続保存の`t256_<小文字UUID>`。 */
  readonly connectNamespace: string;
  /** 配送の`t270_<小文字UUID>`。 */
  readonly deliveryNamespace: string;
  readonly kms: GoogleKmsConnectKmsOptions;
  /** 4用途の固定数値版（このstartはidentifierKey・commandDigestKeyだけを読む）。 */
  readonly secretVersions: GoogleSecretVersions;
  readonly clock: { now(): number };
  /** 呼出し元全体の起動期限と中断（延長しない）。 */
  readonly operation: { readonly deadlineAt: number; readonly signal: AbortSignal };
  /**
   * entryがALS等の要求固有storeから、そのHTTP要求の元ingressを返すtrustedな内部source（1要求の値を共有変数へ保存して他要求へ使わない）。
   * 起動時には呼ばない。
   */
  readonly ingress: () => DeliveryHttpIngress;
  readonly log?: ((entry: Record<string, unknown>) => void) | undefined;
}

export interface OwnedDevelopmentDeliveryFunction {
  /** Functions factoryが返す実HttpsFunction（API_FUNCTION_OPTIONS）。 */
  readonly handler: KmsRequestDeliveryFunction['handler'];
  /** 共有Promise・一度だけ。app→port/Buffer→所有SDKの順に各1回試み、非成功・未完は固定のclose failure。 */
  close(): Promise<void>;
}

const configInvalid = () => new OwnedDevelopmentDeliveryConfigError();

interface Captured {
  readonly deployment: DeploymentConfig;
  readonly expectedServiceName: string;
  readonly connectNamespace: string;
  readonly deliveryNamespace: string;
  readonly policy: KmsSubscriptionPolicy;
  readonly secretVersions: GoogleSecretVersions;
  readonly now: () => unknown;
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
  readonly log: ((entry: Record<string, unknown>) => void) | undefined;
  /** 捕捉したingress source（起動時には呼ばない）。 */
  readonly ingress: () => DeliveryHttpIngress;
}

/** 4用途の固定数値版の完全名（既存readerと同じ規則・用途ごとに別ID）。不正は設定エラー。 */
function captureSecretVersions(value: unknown, projectNumber: string): GoogleSecretVersions {
  const fields = dataFields(value, SECRET_PURPOSES);
  const ids = new Set<string>();
  const out: Record<string, string> = {};
  for (const purpose of SECRET_PURPOSES) {
    const name = fields.get(purpose);
    if (typeof name !== 'string' || name.length > 1024) throw configInvalid();
    const parts = name.split('/');
    if (parts.length !== 6) throw configInvalid();
    const [p, project, s, secretId, v, version] = parts as [string, string, string, string, string, string];
    if (p !== 'projects' || project !== projectNumber || s !== 'secrets' || v !== 'versions') throw configInvalid();
    if (!SECRET_ID.test(secretId) || !VERSION_NUMBER.test(version) || !Number.isSafeInteger(Number(version))) throw configInvalid();
    ids.add(secretId);
    out[purpose] = name;
  }
  if (ids.size !== SECRET_PURPOSES.length) throw configInvalid();
  return Object.freeze(out) as unknown as GoogleSecretVersions;
}

/** 副作用の前に全てを1回だけ捕捉・検査する（以後は入力objectを読み直さない）。 */
function capture(options: unknown): Captured {
  try {
    // 配置設定（未設定・不整合）は設定エラー（SDK・秘密・時計の実呼出しより前）。
    const deployment: DeploymentConfig = loadDeploymentConfig();
    const PROJECT_ID = deployment.projectId;
    const PROJECT_NUMBER = deployment.projectNumber;
    const DATABASE_ID = deployment.databaseId;
    const API_SERVICE_NAME = deployment.api.serviceName;
    const fields = dataFields(options, OPTION_KEYS, ['log']);
    // ingress sourceは関数（Proxyでない）だけを捕捉する（起動時に呼ばない）。
    const given = fields.get('ingress');
    if (typeof given !== 'function' || types.isProxy(given)) throw configInvalid();
    const ingressFn = given as Function;
    const ingress = (): DeliveryHttpIngress => Reflect.apply(ingressFn, undefined, []) as DeliveryHttpIngress;
    if (fields.get('projectId') !== PROJECT_ID || fields.get('projectNumber') !== PROJECT_NUMBER || fields.get('databaseId') !== DATABASE_ID) {
      throw configInvalid();
    }
    const expectedServiceName = fields.get('expectedServiceName');
    if (typeof expectedServiceName !== 'string' || !CLOUD_RUN_NAME.test(expectedServiceName) || expectedServiceName !== API_SERVICE_NAME) throw configInvalid();
    const connectNamespace = fields.get('connectNamespace');
    if (!isConnectNamespace(connectNamespace)) throw configInvalid();
    const deliveryNamespace = fields.get('deliveryNamespace');
    if (!isKmsDeliveryNamespace(deliveryNamespace)) throw configInvalid();
    // KMS: environment=development・同じproject/database・設定locationの鍵だけ。数値版・t268 namespaceは既存のpure policyで検査・正規化する。
    const kmsFields = dataFields(fields.get('kms'), KMS_KEYS);
    if (kmsFields.get('environment') !== 'development' || kmsFields.get('projectId') !== PROJECT_ID || kmsFields.get('databaseId') !== DATABASE_ID) {
      throw configInvalid();
    }
    const policy = createKmsSubscriptionPolicy({
      namespace: kmsFields.get('namespace'),
      environment: kmsFields.get('environment'),
      projectId: kmsFields.get('projectId'),
      databaseId: kmsFields.get('databaseId'),
      cryptoKey: kmsFields.get('cryptoKey'),
      writeVersion: kmsFields.get('writeVersion'),
      readVersions: [...arrayItems(kmsFields.get('readVersions'))],
    });
    if (cryptoKeyLocation(policy.cryptoKey) !== deployment.location) throw configInvalid();
    const secretVersions = captureSecretVersions(fields.get('secretVersions'), PROJECT_NUMBER);
    const now = methodOf(fields.get('clock'), 'now');
    const operation = dataFields(fields.get('operation'), ['deadlineAt', 'signal']);
    const deadlineAt = operation.get('deadlineAt');
    const signal = operation.get('signal');
    if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) throw configInvalid();
    let log: Captured['log'];
    const logValue = fields.get('log');
    if (logValue !== undefined) {
      if (typeof logValue !== 'function' || types.isProxy(logValue)) throw configInvalid();
      const logFn = logValue as Function;
      log = (entry) => {
        Reflect.apply(logFn, undefined, [entry]);
      };
    }
    return Object.freeze({ deployment, expectedServiceName, connectNamespace, deliveryNamespace, policy, secretVersions, now, deadlineAt, signal, log, ingress });
  } catch {
    throw new OwnedDevelopmentDeliveryConfigError({ stage: 'config', code: 'config_invalid' });
  }
}

/** promiseをsignalの中止までで待つ（後着の成功・失敗は処理済みにする）。中止は固定の起動失敗。 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  promise.catch(() => undefined);
  if (signal.aborted) return Promise.reject(new OwnedDevelopmentDeliveryStartupError());
  return new Promise<T>((resolve, reject) => {
    let done = false;
    const finish = (outcome: () => void): void => {
      if (done) return;
      done = true;
      signal.removeEventListener('abort', onAbort);
      outcome();
    };
    const onAbort = (): void => finish(() => reject(new OwnedDevelopmentDeliveryStartupError()));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => finish(() => resolve(value)),
      () => finish(() => reject(new OwnedDevelopmentDeliveryStartupError())),
    );
  });
}

/** 外部の同期・非同期の呼出しをmsまで待つ（timerは必ず解除。遅いsettle・rejectは処理済み）。成功はtrue。 */
function settledWithin(start: () => unknown, ms: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false;
    const finish = (ok: boolean): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => finish(false), ms);
    try {
      Promise.resolve(start()).then(
        () => finish(true),
        () => finish(false),
      );
    } catch {
      finish(false);
    }
  });
}

/** 所有物（作った順。清掃は逆順でapp→port/Buffer→SDK）。 */
interface Owned {
  sdk: DevelopmentGoogleSdk | undefined;
  reader: GoogleSecretReader | undefined;
  transport: GoogleKmsTransport | undefined;
  context: RequestAuthContext | undefined;
  app: KmsRequestDeliveryFunction | undefined;
  readonly buffers: Buffer[];
}

/**
 * app→port/Buffer→SDKの順に各1回清掃する（app・SDKは各上限5秒）。全てが完了すればtrue。例外を投げない。
 * appのcloseはFunctions runtimeの同期のdisposeで、この時点で新しいHTTP要求は既存の固定503になる。
 */
async function cleanup(owned: Owned): Promise<boolean> {
  let ok = true;
  const app = owned.app;
  if (app !== undefined) ok = (await settledWithin(() => app.close(), CLOSE_STEP_MS)) && ok;
  for (const dispose of [() => owned.context?.dispose(), () => owned.reader?.dispose(), () => owned.transport?.dispose()]) {
    try {
      dispose();
    } catch {
      ok = false;
    }
  }
  for (const buffer of owned.buffers) buffer.fill(0);
  const sdk = owned.sdk;
  if (sdk !== undefined) ok = (await settledWithin(() => sdk.close(), CLOSE_STEP_MS)) && ok;
  return ok;
}

/**
 * 送信APIのFunctions配送を起動する。設定の不正はOwnedDevelopmentDeliveryConfigError（副作用の前）、起動の失敗は
 * OwnedDevelopmentDeliveryStartupError（所有物を清掃済み）、清掃が完了しない・失敗した時はOwnedDevelopmentDeliveryCloseError。
 */
export async function startOwnedIngressDevelopmentDeliveryFunction(options: OwnedDevelopmentDeliveryOptions): Promise<OwnedDevelopmentDeliveryFunction> {
  return startWith(capture(options));
}

/** SDKの固定codeから起動失敗の固定分類へ（中断・closedは元期限のwatchdogなら期限）。 */
function sdkStartCode(code: DevelopmentGoogleSdkError['code'], stoppedCode: () => OwnedDevelopmentDeliveryStartCode): OwnedDevelopmentDeliveryStartCode {
  switch (code) {
    case 'invalid_config':
      return 'config_invalid';
    case 'environment_rejected':
      return 'environment_rejected';
    case 'aborted':
    case 'closed':
      return stoppedCode();
    case 'timed_out':
      return 'timed_out';
    case 'unavailable':
      return 'read_failed';
    case 'close_failed':
      return 'cleanup_failed';
    default:
      return 'unclassified';
  }
}

/**
 * 所有SDK errorのenvironment_rejectedが持つown dataのmask（整数1〜63）だけ。getter・prototype・Proxy・他code・
 * 不正値・読取りの例外はundefined（errorの他のfieldは読まない・写さない）。
 */
function sdkEnvironmentGateMask(error: unknown): number | undefined {
  try {
    if (!(error instanceof DevelopmentGoogleSdkError) || types.isProxy(error) || error.code !== 'environment_rejected') return undefined;
    return ownEnvironmentGateMask(error);
  } catch {
    return undefined;
  }
}

/** Secret reader（GoogleSdkPortError）の固定codeから起動失敗の固定分類へ。それ以外は未分類。 */
function portStartCode(error: unknown, stoppedCode: () => OwnedDevelopmentDeliveryStartCode): OwnedDevelopmentDeliveryStartCode {
  if (!(error instanceof GoogleSdkPortError)) return 'unclassified';
  switch (error.code) {
    case 'aborted':
    case 'closed':
      return stoppedCode();
    case 'timed_out':
      return 'timed_out';
    case 'unavailable':
      return 'read_failed';
    case 'integrity_failed':
    case 'invalid_input':
      return 'format_mismatch';
    default:
      return 'unclassified';
  }
}

async function startWith(config: Captured): Promise<OwnedDevelopmentDeliveryFunction> {
  const { policy } = config;
  const readClock = (): number | null => {
    try {
      const value = config.now();
      return isEpochMs(value) ? value : null;
    } catch {
      return null;
    }
  };
  /** SDK・reader・transport・port・storage・Functions factoryへ渡す同じ捕捉clock。 */
  const clock = Object.freeze({ now: () => config.now() as number });

  // 元期限は1回だけ: min(親deadlineAt, 開始+20秒)。既中断・期限切れ・不正な時計はSDK生成の前に起動失敗。
  // 起動失敗のerrorには固定列挙のstage/codeだけを付ける。
  if (config.signal.aborted) throw new OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'aborted' });
  const startedAt = readClock();
  if (config.signal.aborted) throw new OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'aborted' });
  if (startedAt === null) throw new OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'unclassified' });
  if (!(startedAt < config.deadlineAt)) throw new OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'timed_out' });
  const deadlineAt = Math.min(config.deadlineAt, startedAt + START_BUDGET_MS);
  const startup = new AbortController();
  const operation = Object.freeze({ deadlineAt, signal: startup.signal });
  const onParentAbort = (): void => startup.abort();
  config.signal.addEventListener('abort', onParentAbort, { once: true });
  if (config.signal.aborted) startup.abort();
  /** 失敗時の固定stage/code（最初に分かった分類だけを残す）と、元期限のwatchdogが止めたか。 */
  let stage: OwnedDevelopmentDeliveryStartStage = 'sdk';
  let code: OwnedDevelopmentDeliveryStartCode | undefined;
  let timedOut = false;
  /** 所有SDKのenvironment_rejectedが持つ検証済みmask（無ければundefined）。 */
  let environmentGateMask: number | undefined;
  const stoppedCode = (): OwnedDevelopmentDeliveryStartCode => (timedOut ? 'timed_out' : 'aborted');
  // 同じ元残り時間の物理watchdog（finallyで必ず解除）。
  const watchdog = setTimeout(() => {
    timedOut = true;
    startup.abort();
  }, deadlineAt - startedAt);

  /** signal→clock→signalで、limit（既定は元期限）まで続けてよいか。不成立なら起動を止めて固定の起動失敗。 */
  const live = (limit: number = deadlineAt): void => {
    if (startup.signal.aborted) {
      code ??= stoppedCode();
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    const at = readClock();
    if (startup.signal.aborted) {
      code ??= stoppedCode();
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    if (at === null || !(at < deadlineAt)) {
      startup.abort();
      code ??= at === null ? 'unclassified' : 'timed_out';
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    if (!(at < limit)) {
      code ??= 'timed_out';
      throw new OwnedDevelopmentDeliveryStartupError();
    }
  };

  const owned: Owned = { sdk: undefined, reader: undefined, transport: undefined, context: undefined, app: undefined, buffers: [] };
  /** 起動途中の失敗の分類（清掃が完了しなければclose failureへ上書きする）。 */
  let failure = 'startup' as 'config' | 'startup' | 'close';
  try {
    live();
    try {
      owned.sdk = await openDevelopmentGoogleSdk({
        projectId: config.deployment.projectId,
        databaseId: config.deployment.databaseId,
        expectedServiceName: config.expectedServiceName,
        clock,
        operation,
      });
    } catch (error) {
      // SDK factoryの失敗はfactoryが内部で清掃済み。close_failedは清掃未完として伝える。
      const sdkCode = error instanceof DevelopmentGoogleSdkError ? error.code : 'unavailable';
      failure = sdkCode === 'close_failed' ? 'close' : sdkCode === 'invalid_config' || sdkCode === 'environment_rejected' ? 'config' : 'startup';
      code ??= error instanceof DevelopmentGoogleSdkError ? sdkStartCode(sdkCode, stoppedCode) : 'unclassified';
      environmentGateMask = sdkEnvironmentGateMask(error);
      throw error;
    }
    const sdk = owned.sdk;
    live();

    // 2秘密（identifierKey→commandDigestKey）だけ。全体の上限は読込み開始+5秒と元期限の短い方（各readで取り直さない）。
    stage = 'identifier_secret';
    const reader = createGoogleSecretReader({ client: sdk.secretClient, projectNumber: config.deployment.projectNumber, versions: config.secretVersions, clock });
    owned.reader = reader;
    const loadStartedAt = readClock();
    if (loadStartedAt === null) {
      code ??= 'unclassified';
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    const loadDeadline = Math.min(deadlineAt, loadStartedAt + SECRET_LOAD_MS);
    const readOperation = Object.freeze({ deadlineAt: loadDeadline, signal: startup.signal });
    const keys: Buffer[] = [];
    for (const purpose of ['identifierKey', 'commandDigestKey'] as const) {
      stage = purpose === 'identifierKey' ? 'identifier_secret' : 'digest_secret';
      live(loadDeadline);
      let value: Buffer;
      try {
        value = await reader.read(purpose, readOperation);
      } catch (error) {
        code ??= portStartCode(error, stoppedCode);
        throw error;
      }
      owned.buffers.push(value);
      keys.push(value);
      live(loadDeadline);
    }
    const [identifierKey, digestKey] = keys as [Buffer, Buffer];
    if (identifierKey.length !== KEY_BYTES || digestKey.length !== KEY_BYTES || timingSafeEqual(identifierKey, digestKey)) {
      stage = identifierKey.length !== KEY_BYTES ? 'identifier_secret' : 'digest_secret';
      code ??= 'format_mismatch';
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    // 以後の秘密read 0。
    reader.dispose();
    live();

    // markerは既存の正しいものだけを1回読む（作らない・直さない）。awaitの間も中断・期限で止める。
    stage = 'marker';
    const markerRef = sdk.db.collection(AUTH_STORAGE_ROOT).doc(policy.namespace).collection('config').doc(KMS_SUBSCRIPTION_CONFIG_DOC);
    let marker: Awaited<ReturnType<typeof markerRef.get>>;
    try {
      marker = await untilAborted(Promise.resolve(markerRef.get()), startup.signal);
    } catch (error) {
      code ??= startup.signal.aborted ? stoppedCode() : 'read_failed';
      throw error;
    }
    live();
    if (!marker.exists) {
      code ??= 'format_mismatch';
      throw new OwnedDevelopmentDeliveryStartupError();
    }
    try {
      requireKmsMarker(marker.data(), policy);
    } catch (error) {
      code ??= 'format_mismatch';
      throw error;
    }
    stage = 'assembly';

    // 組立て（同期・I/Oなし）: hasher（所有identifier Bufferを参照）・transport・context・box・ConnectStorage・Functions app。
    const hasher = createHmacHasher(identifierKey);
    const transport = createGoogleKmsTransport({
      client: sdk.kmsClient,
      projectId: policy.projectId,
      cryptoKey: policy.cryptoKey,
      writeVersion: policy.writeVersion,
      readVersions: [...policy.readVersions],
      clock,
    });
    owned.transport = transport;
    const context = createRequestAuthContext({ clock });
    owned.context = context;
    const kmsConfig = {
      environment: policy.environment,
      projectId: policy.projectId,
      databaseId: policy.databaseId,
      cryptoKey: policy.cryptoKey,
      writeVersion: policy.writeVersion,
      readVersions: [...policy.readVersions],
      transport,
    };
    // AS/UIDの封緘（接続t256）。要求slotが無ければcontext.currentが固定の失敗を投げる（配送APIの経路はslotを作らない＝fail closed）。
    const box = createConnectKmsSealingPort({ kms: { ...kmsConfig, namespace: config.connectNamespace, clock }, operation: context.current });
    const connect = new ConnectStorage({
      db: sdk.db,
      namespace: config.connectNamespace,
      hasher,
      box,
      clock,
      ownerInactivityMs: PRODUCT_POLICY.ownerInactivityMs,
      interactionTtlMs: PRODUCT_POLICY.interactionTtlMs,
      grantInactivityMs: PRODUCT_POLICY.refreshFamilyMaxSec * 1000,
    });
    live();
    try {
      const appOptions = {
        db: sdk.db,
        connect,
        hasher,
        digestKey,
        kms: { ...kmsConfig, namespace: policy.namespace },
        identity: sdk.identity,
        egress: createProductEgress(),
        clock,
        namespace: config.deliveryNamespace,
        ...(config.log !== undefined ? { log: config.log } : {}),
      };
      owned.app = createIngressKmsRequestDeliveryFunction({ ...appOptions, ingress: config.ingress });
    } finally {
      // Functions runtimeが写しを作った（または失敗した）直後に、元のdigest Bufferを0埋めする。
      digestKey.fill(0);
    }
    // readyの採用の直前にも同じ元期限・中断を見る（遅い成功を採用しない）。
    live();
  } catch (error) {
    if (error instanceof OwnedDevelopmentDeliveryConfigError) failure = 'config';
    // 未公開のまま、app→port/Buffer→SDKの順で所有物を清掃する。清掃が完了しなければclose failure。
    startup.abort();
    const cleaned = await cleanup(owned);
    // 固定stage/codeだけを付ける。清掃未完はcleanup_failed。
    const classified: OwnedDevelopmentDeliveryStartCode = code ?? (failure === 'config' ? 'config_invalid' : 'unclassified');
    if (!cleaned || failure === 'close') throw new OwnedDevelopmentDeliveryCloseError({ stage, code: 'cleanup_failed' });
    // maskはsdk/environment_rejectedの時だけ（他はfreezeDiagnosticも省略する）。
    const diagnostic: OwnedDevelopmentDeliveryStartDiagnostic =
      stage === 'sdk' && classified === 'environment_rejected' && environmentGateMask !== undefined ? { stage, code: classified, environmentGateMask } : { stage, code: classified };
    throw failure === 'config' ? new OwnedDevelopmentDeliveryConfigError(diagnostic) : new OwnedDevelopmentDeliveryStartupError(diagnostic);
  } finally {
    clearTimeout(watchdog);
    config.signal.removeEventListener('abort', onParentAbort);
  }

  const app = owned.app;
  // 上のtryを正常に抜けた時はappが成立している（型の明示だけ。到達しない）。
  if (app === undefined) throw new OwnedDevelopmentDeliveryStartupError();
  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    let settle!: (ok: boolean) => void;
    // 副作用の前に共有Promiseをラッチする（app・port・SDKのclose中からの再入も同じPromise）。
    closePromise = new Promise<void>((resolve, reject) => {
      settle = (ok) => (ok ? resolve() : reject(new OwnedDevelopmentDeliveryCloseError()));
    });
    closePromise.catch(() => undefined);
    startup.abort();
    void cleanup(owned).then(settle, () => settle(false));
    return closePromise;
  };
  return Object.freeze({ handler: app.handler, close });
}
