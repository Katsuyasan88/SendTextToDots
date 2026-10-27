// MCP/OAuth/接続WebのSDK所有起動口（deployment/connect.tsから使う）。openDevelopmentGoogleSdk（明示Compute・4種SDKの所有）→
// startDevelopmentGoogleKmsConnectServer（Google bridge・親起動operation）を、同じ元operationと同じ捕捉clockで逐次につなぐ。
// SDK・client・db・identity・egress・reader・factory・hooks・budgetの
// 注入口は無く、別資格へのfallbackもしない。clientEgressとverificationSenderは内部の製品構成（createProductEgress・
// createEgressVerificationSender）だけで、宛先ポリシー・port・TLSをcaller・環境で緩めない。
//   - configは配置設定（src/config/deployment.ts）の検証済みproject・number・databaseと一致するものだけ。exact own dataを1回捕捉して写し（nested object/arrayも各data property）、
//     callerの後続改変を読まない。borrowed config・clock・signalは凍結・書換え・abortしない。秘密の版・namespace・鍵・公開originを生成・
//     選択・推測しない（配置設定で別に固定する）。markerは既存の正しいものだけを要求し、作らない・直さない。
//   - 元期限はmin(親deadlineAt, 開始+20秒)を1回だけ作り、親signalを専有controllerへ結び、同じ残り時間のwatchdogを置く。同じfrozen
//     operationをSDKとbridgeの両方へ渡し、各await前後とreadyの採用時にsignal→clock→signalで検査する（SDK・bridgeが20秒を取り直して
//     全体を延長する組立てにしない）。成功・失敗とも親listener・watchdogを解除し、ready後の親の中断・期限は通常要求を止めない。
//   - 戻り値はfrozen {issuer, resource, close}だけ。closeは副作用の前に共有Promiseをラッチし、専有controllerのabort→接続server.close
//     （上限5秒）→成功・失敗とも所有SDKのclose（上限5秒）を各1回試みる。完了しない・失敗した清掃は固定のclose failureで、成功と偽らない。
//   - 部分生成・起動失敗・親の中断・期限でも同じ所有清掃を行い、readyを公開しない。清掃が完了しなければ（SDK factoryのclose_failedを
//     含む）、起動失敗ではなく固定のclose failureで返す。errorは固定のconfig/startup/closeの3種だけ（元error・cause・値を転記しない）。
// 既に始めたSDK・HTTPの物理取消、Cloudのcold startの所要時間、RAMの物理消去は保証しない。

import { DEVELOPER_LOGIN_MODE } from '../config/validate.js';
import type { CodeIdentityLookup } from '../identity/developer-code-identity.js';
import { types } from 'node:util';

import { cryptoKeyLocation, loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';
import { isConnectNamespace } from '../connect/firestore.js';
import {
  GoogleKmsConnectCloseError,
  GoogleKmsConnectConfigError,
  startDevelopmentGoogleKmsConnectServer,
  type GoogleKmsConnectKmsOptions,
  type GoogleKmsConnectServer,
} from '../connect/google-kms-server.js';
import type { FirebaseWebConfig } from '../connect/pages.js';
import { createProductEgress } from '../egress/product.js';
import { createEgressVerificationSender } from '../egress/verification-sender.js';
import type { LogSink } from '../http/log.js';
import type { GoogleSecretVersions } from '../keys/google-secret-reader.js';
import { arrayItems, dataFields, isEpochMs, isRealSignal, methodOf } from '../protection/google-sdk-call.js';
import { createKmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { DevelopmentGoogleSdkError, openDevelopmentGoogleSdk, type DevelopmentGoogleSdk } from './development.js';

const START_BUDGET_MS = 20_000;
const CLOSE_STEP_MS = 5_000;
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
  'bindPort',
  'publicOrigin',
  'connectNamespace',
  'kms',
  'secretVersions',
  'web',
  'clock',
  'operation',
] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions'] as const;
const WEB_KEYS = ['apiKey', 'authDomain', 'projectId'] as const;

export type OwnedDevelopmentConnectErrorCode =
  | 'owned_development_connect_config_invalid'
  | 'owned_development_connect_startup_failed'
  | 'owned_development_connect_close_failed';

/** 固定codeと固定messageだけの失敗（元の例外・cause・値・URLを持たない）。 */
class OwnedDevelopmentConnectError extends Error {
  readonly code: OwnedDevelopmentConnectErrorCode;
  constructor(code: OwnedDevelopmentConnectErrorCode) {
    super(code);
    this.code = code;
  }
}

/** 設定の不正（SDK生成・秘密・DB・listenの前）。 */
export class OwnedDevelopmentConnectConfigError extends OwnedDevelopmentConnectError {
  override readonly name = 'OwnedDevelopmentConnectConfigError';
  constructor() {
    super('owned_development_connect_config_invalid');
  }
}

/** 起動の失敗（所有したSDK・接続serverは清掃済み）。 */
export class OwnedDevelopmentConnectStartupError extends OwnedDevelopmentConnectError {
  override readonly name = 'OwnedDevelopmentConnectStartupError';
  constructor() {
    super('owned_development_connect_startup_failed');
  }
}

/** 清掃・closeが完了しなかった・失敗した（成功と偽らない）。 */
export class OwnedDevelopmentConnectCloseError extends OwnedDevelopmentConnectError {
  override readonly name = 'OwnedDevelopmentConnectCloseError';
  constructor() {
    super('owned_development_connect_close_failed');
  }
}

export interface OwnedDevelopmentConnectOptions {
  /** 配置設定のprojectId（一致だけを受け付ける）。 */
  readonly projectId: string;
  /** 配置設定のprojectNumber。 */
  readonly projectNumber: string;
  /** 配置設定のdatabaseId。 */
  readonly databaseId: string;
  /** 配置先Cloud Runの正規service名（K_SERVICE gate）。 */
  readonly expectedServiceName: string;
  readonly bindPort: number;
  /** 正規形の`https://<小文字DNS-host>`（issuer）。 */
  readonly publicOrigin: string;
  /** 接続保存の`t256_<小文字UUID>`。 */
  readonly connectNamespace: string;
  readonly kms: GoogleKmsConnectKmsOptions;
  /** 4用途の固定数値版（`projects/<projectNumber>/secrets/{ID}/versions/{N}`、用途ごとに別ID）。 */
  readonly secretVersions: GoogleSecretVersions;
  readonly web: FirebaseWebConfig;
  readonly clock: { now(): number };
  /** 呼出し元全体の起動期限と中断（延長しない）。 */
  readonly operation: { readonly deadlineAt: number; readonly signal: AbortSignal };
  readonly log?: LogSink | undefined;
}

export interface OwnedDevelopmentConnectServer {
  readonly issuer: string;
  readonly resource: string;
  /** 共有Promise・一度だけ。接続server→所有SDKの順に各1回試み、非成功・未完は固定のclose failure。 */
  close(): Promise<void>;
}

const configInvalid = () => new OwnedDevelopmentConnectConfigError();

interface Captured {
  readonly deployment: DeploymentConfig;
  readonly bindPort: number;
  readonly publicOrigin: string;
  readonly connectNamespace: string;
  readonly expectedServiceName: string;
  readonly kms: Readonly<Record<(typeof KMS_KEYS)[number], unknown>>;
  readonly secretVersions: GoogleSecretVersions;
  readonly web: FirebaseWebConfig;
  readonly now: () => unknown;
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
  readonly log: LogSink | undefined;
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
  // 配置設定（未設定・不整合）は設定エラー（SDK・秘密・DB・listenの前）。
  let deployment: DeploymentConfig;
  try {
    deployment = loadDeploymentConfig();
  } catch {
    throw configInvalid();
  }
  const PROJECT_ID = deployment.projectId;
  const PROJECT_NUMBER = deployment.projectNumber;
  const DATABASE_ID = deployment.databaseId;
  let fields: Map<string, unknown>;
  try {
    fields = dataFields(options, OPTION_KEYS, ['log']);
  } catch {
    throw configInvalid();
  }
  if (fields.get('projectId') !== PROJECT_ID || fields.get('projectNumber') !== PROJECT_NUMBER || fields.get('databaseId') !== DATABASE_ID) {
    throw configInvalid();
  }
  const expectedServiceName = fields.get('expectedServiceName');
  if (typeof expectedServiceName !== 'string' || !CLOUD_RUN_NAME.test(expectedServiceName)) throw configInvalid();
  const bindPort = fields.get('bindPort');
  if (typeof bindPort !== 'number' || !Number.isSafeInteger(bindPort) || bindPort < 1024 || bindPort > 65535) throw configInvalid();
  const publicOrigin = fields.get('publicOrigin');
  if (!isDevelopmentPublicOrigin(publicOrigin)) throw configInvalid();
  const connectNamespace = fields.get('connectNamespace');
  if (!isConnectNamespace(connectNamespace)) throw configInvalid();
  try {
    // KMS: environment=development・同じproject/database・設定locationの鍵だけ。数値版・t268 namespaceの検査は既存のpure policyで行う。
    const kmsFields = dataFields(fields.get('kms'), KMS_KEYS);
    const readVersions = Object.freeze(arrayItems(kmsFields.get('readVersions')));
    const kms = Object.freeze({
      environment: kmsFields.get('environment'),
      projectId: kmsFields.get('projectId'),
      databaseId: kmsFields.get('databaseId'),
      namespace: kmsFields.get('namespace'),
      cryptoKey: kmsFields.get('cryptoKey'),
      writeVersion: kmsFields.get('writeVersion'),
      readVersions,
    });
    if (kms.environment !== 'development' || kms.projectId !== PROJECT_ID || kms.databaseId !== DATABASE_ID) throw configInvalid();
    if (cryptoKeyLocation(kms.cryptoKey) !== deployment.location) throw configInvalid();
    createKmsSubscriptionPolicy({ ...kms, readVersions: [...readVersions] });
    const secretVersions = captureSecretVersions(fields.get('secretVersions'), PROJECT_NUMBER);
    const webFields = dataFields(fields.get('web'), WEB_KEYS);
    const web = Object.freeze({ apiKey: webFields.get('apiKey'), authDomain: webFields.get('authDomain'), projectId: webFields.get('projectId') });
    if (typeof web.apiKey !== 'string' || web.apiKey === '' || web.authDomain !== deployment.web.authDomain || web.projectId !== PROJECT_ID) throw configInvalid();
    const now = methodOf(fields.get('clock'), 'now');
    const operation = dataFields(fields.get('operation'), ['deadlineAt', 'signal']);
    const deadlineAt = operation.get('deadlineAt');
    const signal = operation.get('signal');
    if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) throw configInvalid();
    let log: LogSink | undefined;
    const logValue = fields.get('log');
    if (logValue !== undefined) {
      if (typeof logValue !== 'function' || types.isProxy(logValue)) throw configInvalid();
      const logFn = logValue as Function;
      log = ((entry: Parameters<LogSink>[0]) => {
        Reflect.apply(logFn, undefined, [entry]);
      }) as LogSink;
    }
    return Object.freeze({
      deployment,
      bindPort,
      publicOrigin,
      connectNamespace,
      expectedServiceName,
      kms,
      secretVersions,
      web: web as unknown as FirebaseWebConfig,
      now,
      deadlineAt,
      signal,
      log,
    });
  } catch {
    throw configInvalid();
  }
}

/** promiseをmsまで待つ（timerは必ず解除。遅いsettle・rejectは処理済みにする）。成功はtrue、失敗・期限はfalse。 */
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

/**
 * SDKを所有するdevelopment MCP接続を起動する。設定の不正はOwnedDevelopmentConnectConfigError（副作用の前）、起動の失敗は
 * OwnedDevelopmentConnectStartupError（所有SDK・接続serverを清掃済み）、清掃が完了しない・失敗した時はOwnedDevelopmentConnectCloseError。
 */
export async function startOwnedDevelopmentConnectServer(options: OwnedDevelopmentConnectOptions): Promise<OwnedDevelopmentConnectServer> {
  const config = capture(options);
  const readClock = (): number | null => {
    try {
      const value = config.now();
      return isEpochMs(value) ? value : null;
    } catch {
      return null;
    }
  };
  /** SDK・bridge・serverへ渡す同じ捕捉clock。 */
  const clock = Object.freeze({ now: () => config.now() as number });

  // 元期限は1回だけ: min(親deadlineAt, 開始+20秒)。既中断・期限切れ・不正な時計はSDK生成の前に起動失敗。
  if (config.signal.aborted) throw new OwnedDevelopmentConnectStartupError();
  const startedAt = readClock();
  if (config.signal.aborted || startedAt === null || !(startedAt < config.deadlineAt)) throw new OwnedDevelopmentConnectStartupError();
  const deadlineAt = Math.min(config.deadlineAt, startedAt + START_BUDGET_MS);
  const startup = new AbortController();
  const operation = Object.freeze({ deadlineAt, signal: startup.signal });
  const onParentAbort = (): void => startup.abort();
  config.signal.addEventListener('abort', onParentAbort, { once: true });
  if (config.signal.aborted) startup.abort();
  // 同じ元残り時間の物理watchdog（finallyで必ず解除）。
  const watchdog = setTimeout(() => startup.abort(), deadlineAt - startedAt);

  /** signal→clock→signalで、元期限まで続けてよいか。 */
  const live = (): boolean => {
    if (startup.signal.aborted) return false;
    const at = readClock();
    if (startup.signal.aborted) return false;
    if (at === null || !(at < deadlineAt)) {
      startup.abort();
      return false;
    }
    return true;
  };

  let sdk: DevelopmentGoogleSdk | undefined;
  let server: GoogleKmsConnectServer | undefined;
  /** 起動途中の失敗の分類（清掃が完了しなければclose failureへ上書きする）。 */
  let failure = 'startup' as 'config' | 'startup' | 'close';
  try {
    if (!live()) throw new OwnedDevelopmentConnectStartupError();
    try {
      sdk = await openDevelopmentGoogleSdk({
        projectId: config.deployment.projectId,
        databaseId: config.deployment.databaseId,
        expectedServiceName: config.expectedServiceName,
        clock,
        operation,
      });
    } catch (error) {
      // SDK factoryの失敗はfactoryが内部で清掃済み。close_failedは清掃未完として伝える。
      const code = error instanceof DevelopmentGoogleSdkError ? error.code : 'unavailable';
      failure = code === 'close_failed' ? 'close' : code === 'invalid_config' || code === 'environment_rejected' ? 'config' : 'startup';
      throw error;
    }
    // ここから所有SDKは本factoryのもの。期限・中断の後はbridgeを始めない。
    if (!live()) throw new OwnedDevelopmentConnectStartupError();
    const egress = createProductEgress();
    const ownedSdk = sdk;
    try {
      server = await startDevelopmentGoogleKmsConnectServer({
        server: {
          bindPort: config.bindPort,
          db: ownedSdk.db,
          namespace: config.connectNamespace,
          identity: ownedSdk.identity,
          web: config.web,
          clientEgress: egress,
          verificationSender: createEgressVerificationSender(egress),
          clock,
          publicOrigin: config.publicOrigin,
          ...(config.log !== undefined ? { log: config.log } : {}),
          // 開発者向けコード（配置設定でonの時だけ）。保存層は接続serverが読んだidentifierKeyから作り、同じSDKの共通verifierへ結ぶ。
          ...(config.deployment.developerLogin === DEVELOPER_LOGIN_MODE
            ? {
                developerCode: {
                  auth: ownedSdk.developerCode.auth,
                  databaseId: config.deployment.databaseId,
                  bindLookup: (lookup: CodeIdentityLookup) => ownedSdk.developerCode.lookup.bind(lookup),
                },
              }
            : {}),
          startupOperation: operation,
        },
        kms: {
          environment: 'development',
          projectId: config.kms.projectId as string,
          databaseId: config.kms.databaseId as string,
          namespace: config.kms.namespace as string,
          cryptoKey: config.kms.cryptoKey as string,
          writeVersion: config.kms.writeVersion as number,
          readVersions: [...(config.kms.readVersions as readonly number[])],
        },
        google: {
          kmsClient: ownedSdk.kmsClient,
          secretClient: ownedSdk.secretClient,
          projectNumber: config.deployment.projectNumber,
          secretVersions: { ...config.secretVersions },
        },
      });
    } catch (error) {
      failure = error instanceof GoogleKmsConnectConfigError ? 'config' : error instanceof GoogleKmsConnectCloseError ? 'close' : 'startup';
      throw error;
    }
    // readyの採用の直前にも同じ元期限・中断を見る（遅い成功を採用しない）。
    if (!live()) throw new OwnedDevelopmentConnectStartupError();
  } catch {
    // 未公開のまま、作った順の逆（接続server→SDK）で所有物を清掃する。清掃が完了しなければclose failure。
    startup.abort();
    let cleaned = true;
    const ownedServer = server;
    const ownedSdk = sdk;
    if (ownedServer !== undefined) cleaned = (await settledWithin(() => ownedServer.close(), CLOSE_STEP_MS)) && cleaned;
    if (ownedSdk !== undefined) cleaned = (await settledWithin(() => ownedSdk.close(), CLOSE_STEP_MS)) && cleaned;
    if (!cleaned || failure === 'close') throw new OwnedDevelopmentConnectCloseError();
    throw failure === 'config' ? new OwnedDevelopmentConnectConfigError() : new OwnedDevelopmentConnectStartupError();
  } finally {
    clearTimeout(watchdog);
    config.signal.removeEventListener('abort', onParentAbort);
  }

  const ownedServer = server;
  const ownedSdk = sdk;
  // 上のtryを正常に抜けた時は両方が成立している（型の明示だけ。到達しない）。
  if (ownedServer === undefined || ownedSdk === undefined) throw new OwnedDevelopmentConnectStartupError();
  let closePromise: Promise<void> | undefined;
  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    let settle!: (ok: boolean) => void;
    // 副作用の前に共有Promiseをラッチする（接続server・SDKのclose中からの再入も同じPromise）。
    closePromise = new Promise<void>((resolve, reject) => {
      settle = (ok) => (ok ? resolve() : reject(new OwnedDevelopmentConnectCloseError()));
    });
    closePromise.catch(() => undefined);
    startup.abort();
    void (async () => {
      // 接続serverを先に止め、成功・失敗とも所有SDKを閉じる（各上限5秒、全体10秒）。
      const serverClosed = await settledWithin(() => ownedServer.close(), CLOSE_STEP_MS);
      const sdkClosed = await settledWithin(() => ownedSdk.close(), CLOSE_STEP_MS);
      settle(serverClosed && sdkClosed);
    })();
    return closePromise;
  };
  return Object.freeze({ issuer: ownedServer.issuer, resource: ownedServer.resource, close });
}
