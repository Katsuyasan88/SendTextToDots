// 配置設定（src/config/deployment.ts）のproject・databaseの通常SDKを、配置先Cloud Run/Functionsに付与された専用SAのmetadata credential
// （明示のCompute）だけで所有して初期化・終了する起動口。本人CLI資格・試験SA・ADC/資格fileの探索・自動project推定は使わない。
//   - Cloud実行環境の事故防止gate（K_SERVICE/K_REVISION/K_CONFIGURATION・project環境値の一致）と、資格・宛先・TLS・ログを別経路へ
//     変え得る環境名の存在拒否（値は読まない・環境は書き換えない）を、SDK生成の前に行う。環境値はCloud/SA本人の暗号学的な証明ではない。
//   - 設定のAPI service（expectedServiceName＝設定のapi.serviceName）だけ、正規名`NODE_OPTIONS`をbounded-memory-hint-v1の文法で照合する:
//     文字列（40文字以下）がASCII spaceだけ0〜8個、又は前後各0〜8個のASCII spaceと単一の`--max-old-space-size=N`（先頭ゼロなし128〜960）の時
//     だけ存在拒否を外す（環境書換え・trim・parser・ログ出力0）。その名前の値だけをRAMで比較し、他の拒否名の値は読まない。
//   - 固定API serviceの拒否条件はSDK生成の前に全て評価し、見つかった全カテゴリを固定6bitの整数environmentGateMask（1〜63）へORして
//     environment_rejectedに持たせる。1=NODE_OPTIONS（大小文字違い・文法外）、2=その他の拒否名の存在、4=K_SERVICE不一致、8=K_REVISION
//     欠落/形不正、16=K_CONFIGURATION欠落/形不正、32=project環境値の不一致。環境名・値・文字列・件数はmaskにしない。
//   - MCP（設定のconnect.serviceName）・他serviceはNODE_OPTIONSを含む全拒否名を最初の1件で値を読まずに止め、maskを持たない。
//     NODE_OPTIONSの扱いを呼出し元・env・HTTPから切り替える入力は無い。
//   - 固定google-gax 6.5.0の公開googleAuthLibrary.Compute（default SA・cloud-platform・googleapis.com）1件と、それを明示した公開
//     GoogleAuth 1件を作り、Firestore 8.3.0（constructorだけ）・KMS 6.3.0・Secret Manager 7.2.0（initialize各1回）・Firebase Admin
//     14.5.0の専有named App/Authへ同じ認証を渡す。AdminのCredentialは同じCompute.getAccessTokenと公開credentials.expiry_dateから
//     expires_inを算出する（推測の値を返さない）。本人確認は既存createFirebaseAdminVerifier（Apple-only契約）のまま。
//   - 初期化の上限はmin(親operation.deadlineAt, 開始+20秒)、清掃は最大5秒（合計25秒以内）。各段階・await後・ready採用時に同じ元期限と
//     signalを見て、遅い成功を採用しない。失敗・中断・期限切れは、その時点までに生成した所有SDKを全て清掃して固定errorだけを返す。
//   - closeは副作用の前に共有Promiseをラッチし、同じhandleのSDKを各1回だけ試みる（上位の失敗でも残りを試す）。補助client（KMSの
//     iam/locations/operations・SMのlocations）は、所有instanceのcloseだけを冪等化し、生成済みの公開stubだけを閉じる。
// SDK/Auth/Gaxiosのprivate field・shared prototypeは変更しない。token・元例外・URL・本人情報をログ/返却値へ出さない。試験の注入口は無い。
// SDK・metadata処理の物理取消の完了、token文字列・SDK/OS内RAMの物理消去は保証しない。callerはHTTP/アプリruntimeを先に止めてから閉じる。

import { createLateCodeIdentityCheck, type CodeAuthAdmin, type LateCodeIdentityCheck } from '../identity/developer-code-identity.js';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { types } from 'node:util';

import type { Firestore } from '@google-cloud/firestore';
import type { KeyManagementServiceClient } from '@google-cloud/kms';
import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import type { App, Credential } from 'firebase-admin/app';

import { loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';
import { createFirebaseAdminVerifier, type AdminAuthLike, type IdentityVerifier } from '../identity/firebase.js';
import { captureClock, dataFields, isEpochMs, isRealSignal, methodOf, ownValue } from '../protection/google-sdk-call.js';

// 固定版のCJS配布物をそのまま読む（gaxのgoogleAuthLibrary再exportと、各SDK）。
const requireCjs = createRequire(import.meta.url);
const gax = requireCjs('google-gax') as typeof import('google-gax');
const firestoreModule = requireCjs('@google-cloud/firestore') as typeof import('@google-cloud/firestore');
const kmsModule = requireCjs('@google-cloud/kms') as typeof import('@google-cloud/kms');
const secretModule = requireCjs('@google-cloud/secret-manager') as typeof import('@google-cloud/secret-manager');
const adminAppModule = requireCjs('firebase-admin/app') as typeof import('firebase-admin/app');
const adminAuthModule = requireCjs('firebase-admin/auth') as typeof import('firebase-admin/auth');

const UNIVERSE_DOMAIN = 'googleapis.com';
const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const PORT = 443;
const ENDPOINTS = Object.freeze({
  firestore: 'firestore.googleapis.com',
  kms: 'cloudkms.googleapis.com',
  secretManager: 'secretmanager.googleapis.com',
});
const INIT_LIMIT_MS = 20_000;
const CLOSE_LIMIT_MS = 5_000;
const ADMIN_APP_PREFIX = 'sendtexttodots-sdk-';
/** Cloud Runのservice/revision/configuration名（小文字・数字・hyphen、英字始まり、63文字以内）。 */
const CLOUD_RUN_NAME = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;

/** 存在すれば（値を読まず）拒否する環境名（大文字で比較）。NO_PROXY・FIREBASE_CONFIGは含めない。 */
const REFUSED_ENV = new Set([
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_OAUTH_ACCESS_TOKEN',
  'CLOUDSDK_AUTH_ACCESS_TOKEN',
  'FIREBASE_TOKEN',
  'GOOGLE_API_KEY',
  'GOOGLE_CLOUD_QUOTA_PROJECT',
  'GOOGLE_CLOUD_UNIVERSE_DOMAIN',
  'GOOGLE_API_USE_MTLS_ENDPOINT',
  'GOOGLE_API_USE_CLIENT_CERTIFICATE',
  'GOOGLE_SDK_NODE_LOGGING',
  'FIRESTORE_EMULATOR_HOST',
  'FIREBASE_AUTH_EMULATOR_HOST',
  'FIREBASE_DATABASE_EMULATOR_HOST',
  'STORAGE_EMULATOR_HOST',
  'FIRESTORE_PREFER_REST',
  'FIRESTORE_ENABLE_TRACING',
  'GCE_METADATA_HOST',
  'GCE_METADATA_IP',
  'METADATA_SERVER_DETECTION',
  'DETECT_GCP_RETRIES',
  'GRPC_TRACE',
  'GRPC_VERBOSITY',
  'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
  'NODE_OPTIONS',
  'NODE_DEBUG',
  'NODE_EXTRA_CA_CERTS',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'OPENSSL_CONF',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'GRPC_PROXY_EXP',
]);

export type DevelopmentGoogleSdkErrorCode =
  | 'invalid_config'
  | 'environment_rejected'
  | 'aborted'
  | 'timed_out'
  | 'unavailable'
  | 'closed'
  | 'close_failed';

/** 環境gate分類の検証（整数1〜63だけ）。 */
export function isDevelopmentEnvironmentGateMask(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 63;
}

/** 固定codeと固定messageだけの失敗（元の例外・cause・token・値・URL・本人情報を持たない）。 */
export class DevelopmentGoogleSdkError extends Error {
  override readonly name = 'DevelopmentGoogleSdkError';
  readonly code: DevelopmentGoogleSdkErrorCode;
  /** environment_rejectedで検証済みmaskを渡された時だけのown data（それ以外はfield自体が無い）。 */
  declare readonly environmentGateMask?: number;
  constructor(code: DevelopmentGoogleSdkErrorCode, environmentGateMask?: number) {
    super(`development google sdk: ${code}`);
    this.code = code;
    if (code === 'environment_rejected' && isDevelopmentEnvironmentGateMask(environmentGateMask)) {
      Object.defineProperty(this, 'environmentGateMask', { value: environmentGateMask, enumerable: true, writable: false, configurable: false });
    }
  }
}

const fail = (code: DevelopmentGoogleSdkErrorCode, environmentGateMask?: number) => new DevelopmentGoogleSdkError(code, environmentGateMask);

export interface DevelopmentGoogleSdkOptions {
  /** 配置設定のprojectId（一致だけを受け付ける）。 */
  readonly projectId: string;
  /** 配置設定のdatabaseId。 */
  readonly databaseId: string;
  /** 配置先Cloud Runの正規service名（K_SERVICEと一致を要求する）。 */
  readonly expectedServiceName: string;
  readonly clock: { now(): number };
  /** 呼出し元全体の起動期限と中断（延長しない）。ready後は監視しない。 */
  readonly operation: { readonly deadlineAt: number; readonly signal: AbortSignal };
}

/** 開発者向けコードの起動部品（SDKごと。別のSDK・起動とは共有しない）。 */
export interface DevelopmentDeveloperCode {
  readonly lookup: LateCodeIdentityCheck;
  readonly auth: CodeAuthAdmin;
}

export interface DevelopmentGoogleSdk {
  readonly db: Firestore;
  readonly kmsClient: KeyManagementServiceClient;
  readonly secretClient: SecretManagerServiceClient;
  /** 既存createFirebaseAdminVerifier（専有named AppのAuth）。 */
  readonly identity: IdentityVerifier;
  /** 開発者向けコード: 共通verifierへ後から結ぶcode identity照合と、専用UIDの作成・custom token署名（同じ専有App）。 */
  readonly developerCode: DevelopmentDeveloperCode;
  /** 共有Promise・一度だけ。全SDKを各1回試み、最大5秒。非成功・未完はclose_failed。 */
  close(): Promise<void>;
}

/**
 * bounded-memory-hint-v1の文法（正規名NODE_OPTIONSの文字列・40文字以下）。(1) ASCII spaceだけ0〜8個、又は(2) 前後それぞれASCII space 0〜8個＋
 * 単一の`--max-old-space-size=N`（Nは先頭ゼロなし3桁128〜960）。trim・shell parser・coerce・他flagは無い（文字列全体をそのまま照合する）。
 */
const BOUNDED_MEMORY_HINT = /^ {0,8}(?:--max-old-space-size=(?:12[89]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-5][0-9]|960) {0,8})?$/;
const BOUNDED_MEMORY_HINT_MAX_LENGTH = 40;
/** 正規名NODE_OPTIONSの値がbounded-memory-hint-v1の文法を満たすか（値は改変しない）。 */
function apiNodeOptionsAccepted(value: string | undefined): boolean {
  return typeof value === 'string' && value.length <= BOUNDED_MEMORY_HINT_MAX_LENGTH && BOUNDED_MEMORY_HINT.test(value);
}

/** 環境gate分類の固定bit。 */
const GATE_NODE_OPTIONS = 1;
const GATE_REFUSED_NAME = 2;
const GATE_SERVICE = 4;
const GATE_REVISION = 8;
const GATE_CONFIGURATION = 16;
const GATE_PROJECT = 32;

/**
 * 固定API serviceの環境gate。拒否条件を全て評価し、見つかったカテゴリをORする（0なら受入）。
 * 拒否名は値を読まない（正規名NODE_OPTIONSだけ文法の照合に値を読む）。identityは固定5名だけを読む。
 */
function apiEnvironmentGateMask(env: NodeJS.ProcessEnv, deployment: DeploymentConfig): number {
  let mask = 0;
  for (const name of Object.keys(env)) {
    const upper = name.toUpperCase();
    if (!REFUSED_ENV.has(upper)) continue;
    if (upper !== 'NODE_OPTIONS') mask |= GATE_REFUSED_NAME;
    else if (name !== 'NODE_OPTIONS' || !apiNodeOptionsAccepted(env[name])) mask |= GATE_NODE_OPTIONS;
  }
  if (env['K_SERVICE'] !== deployment.api.serviceName) mask |= GATE_SERVICE;
  const revision = env['K_REVISION'];
  if (typeof revision !== 'string' || !CLOUD_RUN_NAME.test(revision)) mask |= GATE_REVISION;
  const configuration = env['K_CONFIGURATION'];
  if (typeof configuration !== 'string' || !CLOUD_RUN_NAME.test(configuration)) mask |= GATE_CONFIGURATION;
  for (const name of ['GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']) {
    const value = env[name];
    if (value !== undefined && value !== deployment.projectId) mask |= GATE_PROJECT;
  }
  return mask;
}

/** Cloud実行環境のgateと危険な上書き環境の拒否（SDK生成の前）。拒否名は値を読まない（固定APIのNODE_OPTIONSだけ文法を照合する）。 */
function checkEnvironment(env: NodeJS.ProcessEnv, expectedServiceName: string, deployment: DeploymentConfig): void {
  // NODE_OPTIONSをbounded-memory-hint-v1の文法で照合する唯一のserviceは、配置設定のAPI service。
  if (expectedServiceName === deployment.api.serviceName) {
    const mask = apiEnvironmentGateMask(env, deployment);
    if (mask !== 0) throw fail('environment_rejected', mask);
    return;
  }
  // MCP・他service: 最初の拒否名で値を読まずに止める。
  for (const name of Object.keys(env)) {
    if (!REFUSED_ENV.has(name.toUpperCase())) continue;
    throw fail('environment_rejected');
  }
  if (env['K_SERVICE'] !== expectedServiceName) throw fail('environment_rejected');
  for (const name of ['K_REVISION', 'K_CONFIGURATION']) {
    const value = env[name];
    if (typeof value !== 'string' || !CLOUD_RUN_NAME.test(value)) throw fail('environment_rejected');
  }
  for (const name of ['GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']) {
    const value = env[name];
    if (value !== undefined && value !== deployment.projectId) throw fail('environment_rejected');
  }
}

/**
 * developmentの通常SDKを所有して開く。設定の不正はinvalid_config、環境の拒否はenvironment_rejected（いずれもSDK生成の前）。
 * 起動の失敗・中断・期限切れは、生成済みの所有SDKを全て清掃してから固定code（清掃自体の非成功・未完はclose_failed）で拒否する。
 */
export async function openDevelopmentGoogleSdk(options: DevelopmentGoogleSdkOptions): Promise<DevelopmentGoogleSdk> {
  // 配置設定（未設定・不整合）はinvalid_config（SDK・資格・env gateより前）。
  let deployment: DeploymentConfig;
  try {
    deployment = loadDeploymentConfig();
  } catch {
    throw fail('invalid_config');
  }
  const PROJECT_ID = deployment.projectId;
  const DATABASE_ID = deployment.databaseId;
  let fields: Map<string, unknown>;
  let operation: Map<string, unknown>;
  let now: () => number | null;
  try {
    fields = dataFields(options, ['projectId', 'databaseId', 'expectedServiceName', 'clock', 'operation']);
    operation = dataFields(fields.get('operation'), ['deadlineAt', 'signal']);
    now = captureClock(fields.get('clock'));
  } catch {
    throw fail('invalid_config');
  }
  if (fields.get('projectId') !== PROJECT_ID || fields.get('databaseId') !== DATABASE_ID) throw fail('invalid_config');
  const expectedServiceName = fields.get('expectedServiceName');
  if (typeof expectedServiceName !== 'string' || !CLOUD_RUN_NAME.test(expectedServiceName)) throw fail('invalid_config');
  const deadlineAt = operation.get('deadlineAt');
  const signalValue = operation.get('signal');
  if (!isEpochMs(deadlineAt) || !isRealSignal(signalValue)) throw fail('invalid_config');
  const signal: AbortSignal = signalValue;

  checkEnvironment(process.env, expectedServiceName, deployment);

  // 既中断・期限切れ・不正な時計はSDK生成の前に拒否する（signal→clock→signal）。
  if (signal.aborted) throw fail('aborted');
  const startedAt = now();
  if (signal.aborted) throw fail('aborted');
  if (startedAt === null) throw fail('unavailable');
  if (!(startedAt < deadlineAt)) throw fail('timed_out');
  // 初期化の上限は親の起動期限を延長しない。
  const initDeadline = Math.min(deadlineAt, startedAt + INIT_LIMIT_MS);

  let db: Firestore | null = null;
  let kms: KeyManagementServiceClient | null = null;
  let secrets: SecretManagerServiceClient | null = null;
  let app: App | null = null;
  const subclientClosers: (() => Promise<boolean>)[] = [];
  let closed = false;
  let closePromise: Promise<void> | null = null;
  let stopWaiting: ((error: DevelopmentGoogleSdkError) => void) | null = null;

  /** closed→signal→clock→closed/signalの順で、元の初期化期限まで続けてよいか。 */
  const liveCode = (): DevelopmentGoogleSdkErrorCode | null => {
    if (closed || signal.aborted) return 'aborted';
    const at = now();
    if (closed || signal.aborted) return 'aborted';
    if (at === null) return 'unavailable';
    return at < initDeadline ? null : 'timed_out';
  };
  const live = (): void => {
    const code = liveCode();
    if (code !== null) throw fail(code);
  };

  function close(): Promise<void> {
    if (closePromise !== null) return closePromise;
    let settle!: (ok: boolean) => void;
    // 副作用の前に共有Promiseをラッチする（abort listener・SDKのclose中からの再入も同じPromise）。
    closePromise = new Promise<void>((resolve, reject) => {
      settle = (ok) => (ok ? resolve() : reject(fail('close_failed')));
    });
    closePromise.catch(() => undefined);
    closed = true;
    signal.removeEventListener('abort', onAbort);
    stopWaiting?.(fail('aborted'));
    const attempts: Promise<boolean>[] = [];
    const attempt = (work: () => unknown): void => {
      attempts.push(
        new Promise<boolean>((resolve) => {
          try {
            Promise.resolve(work()).then(
              () => resolve(true),
              () => resolve(false),
            );
          } catch {
            resolve(false);
          }
        }),
      );
    };
    const ownedDb = db;
    const ownedApp = app;
    const ownedKms = kms;
    const ownedSecrets = secrets;
    // 各SDKを1回ずつ試みる（上位の失敗でも残りを試す）。
    if (ownedDb !== null) attempt(() => ownedDb.terminate());
    if (ownedApp !== null) attempt(() => adminAppModule.deleteApp(ownedApp));
    if (ownedKms !== null) attempt(() => ownedKms.close());
    if (ownedSecrets !== null) attempt(() => ownedSecrets.close());
    // 補助clientも同じinstanceの冪等closeで必ず試みる（上位closeが途中で失敗して呼ばなかった場合を含む）。
    for (const closeOnce of [...subclientClosers]) attempts.push(closeOnce());
    let timer: NodeJS.Timeout | undefined;
    const limit = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => resolve('timeout'), CLOSE_LIMIT_MS);
    });
    void Promise.race([Promise.all(attempts), limit]).then((outcome) => {
      clearTimeout(timer);
      db = null;
      kms = null;
      secrets = null;
      app = null;
      subclientClosers.length = 0;
      settle(outcome !== 'timeout' && outcome.every(Boolean));
    });
    return closePromise;
  }

  function onAbort(): void {
    void close();
  }

  /**
   * SDKが生成した公開補助client（同じ所有instance）のcloseを、このinstanceだけで冪等のcloseへ置き換える。
   * 生成済みの公開stub（Promise）だけを閉じ、未生成ならclose0（closeのためにinitializeして新しいstubを作らない）。結果はrejectせず
   * true/falseで返す（SDK側の未awaitのcatch→throw連鎖・console.errorを起こさない）。
   */
  function adoptSubclient(owner: object, property: string, stubProperty: string): void {
    const sub = ownValue(owner, property);
    if (typeof sub !== 'object' || sub === null || types.isProxy(sub)) throw fail('unavailable');
    let outcome: Promise<boolean> | null = null;
    const closeOnce = (): Promise<boolean> => {
      if (outcome !== null) return outcome;
      outcome = new Promise<boolean>((resolve) => {
        const stub = ownValue(sub, stubProperty);
        if (stub === undefined) return resolve(true);
        if (!types.isPromise(stub)) return resolve(false);
        Reflect.apply(Promise.prototype.then, stub, [
          (created: unknown) => {
            try {
              methodOf(created, 'close')();
              resolve(true);
            } catch {
              resolve(false);
            }
          },
          // stubの生成自体が失敗していれば閉じるchannelは無い。
          () => resolve(true),
        ]);
      });
      return outcome;
    };
    Object.defineProperty(sub, 'close', { value: () => closeOnce().then(() => undefined), writable: false, configurable: false, enumerable: false });
    subclientClosers.push(closeOnce);
  }

  signal.addEventListener('abort', onAbort, { once: true });
  if (signal.aborted) onAbort();

  let initTimer: NodeJS.Timeout | undefined;
  try {
    live();
    // 明示のCompute（default SA・cloud-platform・googleapis.com）と、それを明示した公開GoogleAuth。ADC・資格file・project推定は使わない。
    const { Compute } = gax.googleAuthLibrary;
    const ownCompute = new Compute({ serviceAccountEmail: 'default', scopes: [CLOUD_PLATFORM_SCOPE], universeDomain: UNIVERSE_DOMAIN });
    const auth = new gax.GoogleAuth({ authClient: ownCompute, projectId: PROJECT_ID, universeDomain: UNIVERSE_DOMAIN });
    const getComputeToken = methodOf(ownCompute, 'getAccessToken');

    live();
    // Firestoreはconstructorだけ（DB作成・metadata・query・read/write・watch・BulkWriterを初期化確認に使わない）。
    const ownDb = new firestoreModule.Firestore({
      projectId: PROJECT_ID,
      databaseId: DATABASE_ID,
      servicePath: ENDPOINTS.firestore,
      port: PORT,
      ssl: true,
      preferRest: false,
      auth,
      'grpc.enable_retries': 0,
      'grpc.enable_http_proxy': 0,
    });
    db = ownDb;

    const clientOptions = (servicePath: string) =>
      ({
        auth,
        servicePath,
        port: PORT,
        fallback: false,
        universeDomain: UNIVERSE_DOMAIN,
        'grpc.enable_retries': 0,
        'grpc.enable_http_proxy': 0,
      }) as unknown as ConstructorParameters<typeof kmsModule.KeyManagementServiceClient>[0];
    live();
    const ownKms = new kmsModule.KeyManagementServiceClient(clientOptions(ENDPOINTS.kms));
    kms = ownKms;
    adoptSubclient(ownKms, 'iamClient', 'iamPolicyStub');
    adoptSubclient(ownKms, 'locationsClient', 'locationsStub');
    adoptSubclient(ownKms, 'operationsClient', 'operationsStub');
    live();
    const ownSecrets = new secretModule.SecretManagerServiceClient(
      clientOptions(ENDPOINTS.secretManager) as ConstructorParameters<typeof secretModule.SecretManagerServiceClient>[0],
    );
    secrets = ownSecrets;
    adoptSubclient(ownSecrets, 'locationsClient', 'locationsStub');

    live();
    // Adminの専有named App。credentialは同じCompute.getAccessTokenと公開credentials.expiry_dateからexpires_inを算出する。
    const credential: Credential = {
      getAccessToken: async () => {
        if (closed) throw fail('closed');
        let result: unknown;
        try {
          result = await getComputeToken();
        } catch {
          throw fail('unavailable');
        }
        if (closed) throw fail('closed');
        const token = ownValue(result, 'token');
        const expiry = ownValue(ownValue(ownCompute, 'credentials'), 'expiry_date');
        const at = now();
        if (typeof token !== 'string' || token === '' || !isEpochMs(expiry) || at === null) throw fail('unavailable');
        const expiresIn = Math.floor((expiry - at) / 1000);
        if (!(expiresIn > 0)) throw fail('unavailable');
        return { access_token: token, expires_in: expiresIn };
      },
    };
    const ownApp = adminAppModule.initializeApp({ projectId: PROJECT_ID, credential }, `${ADMIN_APP_PREFIX}${randomUUID()}`);
    app = ownApp;
    const ownAuth = adminAuthModule.getAuth(ownApp) as unknown as AdminAuthLike & CodeAuthAdmin;
    // 開発者向けコードの照合は、起動口が秘密を読んだ後に同じ配置の保存層を結ぶ（未結合＝機能off。customのID tokenを受けない）。
    const codeIdentities = createLateCodeIdentityCheck();
    const identity = createFirebaseAdminVerifier({ auth: ownAuth, projectId: PROJECT_ID, codeIdentities });
    const developerCode: DevelopmentDeveloperCode = Object.freeze({
      lookup: codeIdentities,
      auth: Object.freeze({
        createUser: (properties: Parameters<CodeAuthAdmin['createUser']>[0]) => ownAuth.createUser(properties),
        createCustomToken: (uid: string, claims: Record<string, unknown>) => ownAuth.createCustomToken(uid, claims),
      }),
    });

    // KMS/SMのinitializeを各1回、元の初期化期限内で。遅い成功は採用しない（後着は処理済みにし、生成済みstubはcloseが閉じる）。
    const first = now();
    if (first === null) throw fail('unavailable');
    live();
    const stopped = new Promise<never>((_, reject) => {
      stopWaiting = reject;
      initTimer = setTimeout(() => reject(fail('timed_out')), Math.max(0, initDeadline - first));
    });
    stopped.catch(() => undefined);
    const initializations: Promise<unknown>[] = [];
    for (const client of [ownKms, ownSecrets]) {
      live();
      let pending: Promise<unknown>;
      try {
        pending = Promise.resolve(client.initialize());
      } catch {
        pending = Promise.reject(fail('unavailable'));
      }
      pending.catch(() => undefined);
      initializations.push(pending);
    }
    try {
      await Promise.race([Promise.all(initializations), stopped]);
    } catch (error) {
      throw error instanceof DevelopmentGoogleSdkError ? error : fail('unavailable');
    }
    // 採用の前に同じ元期限・signalを見る（遅い成功を採用しない）。
    live();
    clearTimeout(initTimer);
    stopWaiting = null;
    // ready後は起動operationを監視しない（以後の終了はcallerのclose）。
    signal.removeEventListener('abort', onAbort);
    return Object.freeze({ db: ownDb, kmsClient: ownKms, secretClient: ownSecrets, identity, developerCode, close });
  } catch (error) {
    clearTimeout(initTimer);
    stopWaiting = null;
    const code = error instanceof DevelopmentGoogleSdkError ? error.code : 'unavailable';
    let cleanupFailed = false;
    await close().catch(() => {
      cleanupFailed = true;
    });
    throw fail(cleanupFailed ? 'close_failed' : code);
  }
}
