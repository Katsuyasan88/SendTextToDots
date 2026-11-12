// 配置設定（src/config/deployment.ts）の検証。validateDeploymentConfigは純粋関数（I/O・SDK・資格・DB・HTTP・env読取り0）で、
// exact own dataのkey・型・形式・相互整合を全て確かめ、検証済みのdeep frozenな写しを返す。不正は固定codeだけのDeploymentConfigError
// （値・path・元例外を持たない）。configured: trueは必要条件の1つで、それだけでは他の検査を省略しない。配布placeholderは形式で落ちる。
// loadDeploymentConfigは編集済みmoduleの値を1回だけ検証してmemoする（失敗もmemoし、取り直さない）。設定をHTTP・env・argvから選ぶ口は無い。
// 呼出し側（google-runtime・deployment・connect）はSDK生成・秘密・DB・listen・外部HTTPの前にこれを呼ぶ。

import { isConnectNamespace } from '../policy.js';
import { isKmsDeliveryNamespace } from '../delivery/kms-store.js';
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { KMS_REGION_PATTERN } from '../protection/kms-sealing.js';
import { arrayItems, dataFields } from '../protection/google-sdk-call.js';
import { createKmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { isEncryptionNamespace, PAYLOAD_ENCRYPTION_MODE } from '../encryption/contract.js';
import { ED25519_PUBLIC_KEY, parseSourceAuthorization, SOURCE_ID, type SourceAuthorizationConfig } from '../source/contract.js';
import { parseGatewayTopology, type GatewayTopology } from '../gateway/contract.js';
import { DEPLOYMENT_CONFIG } from './deployment.js';

/** src/deployment/functions.tsのexport名（ESMの静的名）。設定のapi.functionName・api.serviceNameはこれと一致しなければならない。 */
export const API_FUNCTION_EXPORT = 'sendtexttodotsapi';

const TOP_KEYS = [
  'configured',
  'projectId',
  'projectNumber',
  'databaseId',
  'location',
  'api',
  'connect',
  'connectNamespace',
  'deliveryNamespace',
  'kms',
  'secretVersions',
  'web',
] as const;
/** 利用許可の唯一の方式（運営者が明示登録した利用者だけ）。欠落・未知値は設定error（全員許可・旧版へのfallbackなし）。 */
export const ACCESS_POLICY = 'explicit-allow-v1';
/** 開発者向け6桁コードの有効値（省略・'off'は無効）。 */
export const DEVELOPER_LOGIN_MODE = 'operator-code-v1';
const API_KEYS = ['functionName', 'serviceName', 'serviceAccount', 'invoker', 'publicOrigin'] as const;
/** 送信APIの任意の明示runtime。省略・functions-v1は既存のFunctions配置、cloud-run-v1はdirect Cloud Run（src/deployment/api.ts）。 */
export const API_RUNTIMES = ['functions-v1', 'cloud-run-v1'] as const;
export type ApiRuntime = (typeof API_RUNTIMES)[number];
const CONNECT_KEYS = ['serviceName', 'serviceAccount', 'publicOrigin', 'invoker'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions'] as const;
const SECRET_PURPOSES = ['jwks', 'cookieKeys', 'identifierKey', 'commandDigestKey'] as const;
const WEB_KEYS = ['projectId', 'authDomain', 'apiKeyEnv'] as const;

/** Google Cloudのproject ID（英小文字始まり・6〜30文字・英小文字/数字/hyphen・末尾hyphenなし）。 */
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const PROJECT_NUMBER = /^[1-9][0-9]{5,19}$/;
/** Firestoreの名前付きdatabase ID（`(default)`以外）。 */
const DATABASE_ID = /^[a-z][a-z0-9-]{2,61}[a-z0-9]$/;
/** Cloud Runのservice名（既存のK_SERVICE gateと同じ規則）。 */
const CLOUD_RUN_NAME = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const SA_LOCAL = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
const VERSION_NUMBER = /^[1-9][0-9]{0,15}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
/** Web API keyの環境変数名に使えない接頭辞・名前（資格・宛先・TLS・runtimeの既存名と衝突させない）。 */
const RESERVED_ENV_PREFIXES = ['GOOGLE_', 'GCLOUD_', 'GCE_', 'CLOUDSDK_', 'FIREBASE_', 'FIRESTORE_', 'STORAGE_', 'GRPC_', 'NODE_', 'K_', 'SSL_', 'OPENSSL_', 'HTTP', 'METADATA_', 'DETECT_', 'FUNCTION_', 'X_GOOGLE_'];
const RESERVED_ENV_NAMES: ReadonlySet<string> = new Set(['PORT', 'ALL_PROXY', 'NO_PROXY', 'GRPC_PROXY_EXP', 'PATH', 'HOME']);

export type DeploymentConfigErrorCode = 'deployment_config_unconfigured' | 'deployment_config_invalid';

/** 固定codeと固定messageだけの設定エラー（値・path・元例外を持たない）。 */
export class DeploymentConfigError extends Error {
  override readonly name = 'DeploymentConfigError';
  readonly code: DeploymentConfigErrorCode;
  constructor(code: DeploymentConfigErrorCode) {
    super(code);
    this.code = code;
  }
}

export interface DeploymentConfig {
  readonly accessPolicy: typeof ACCESS_POLICY;
  /** 開発者向け6桁コード（既定'off'）。 */
  readonly developerLogin: 'off' | typeof DEVELOPER_LOGIN_MODE;
  readonly projectId: string;
  readonly projectNumber: string;
  readonly databaseId: string;
  readonly location: string;
  readonly api: {
    readonly functionName: string;
    readonly serviceName: string;
    readonly serviceAccount: string;
    readonly invoker: 'private';
    readonly publicOrigin: string;
    /** 明示した時だけ（省略はfunctions-v1と同じ既存配置）。 */
    readonly runtime?: ApiRuntime;
  };
  readonly connect: {
    readonly serviceName: string;
    readonly serviceAccount: string;
    readonly publicOrigin: string;
    readonly invoker: 'private';
  };
  readonly connectNamespace: string;
  readonly deliveryNamespace: string;
  readonly kms: {
    readonly environment: 'development';
    readonly projectId: string;
    readonly databaseId: string;
    readonly namespace: string;
    readonly cryptoKey: string;
    readonly writeVersion: number;
    readonly readVersions: readonly number[];
  };
  readonly secretVersions: {
    readonly jwks: string;
    readonly cookieKeys: string;
    readonly identifierKey: string;
    readonly commandDigestKey: string;
  };
  readonly web: {
    readonly projectId: string;
    readonly authDomain: string;
    readonly apiKeyEnv: string;
  };
  /** 本文暗号化（欠落は'off'）。有効時だけ専用secretの固定数値版を持つ。 */
  readonly payloadEncryption: 'off' | PayloadEncryptionConfig;
  /** 許可元の認可（欠落は'compatible'）。strictは管理者が明示した方式だけ。 */
  readonly sourceAuthorization: SourceAuthorizationConfig;
  /**
   * プレイグラウンドの限定route（/v1/playground/*）の固定BFF登録元（欠落は無効）。許可元strictでdeveloper-key-v1を有効にした配置だけ。
   * sourceIdは`src_`＋base32 26文字、publicKeyはraw Ed25519のbase64url（43文字）。
   */
  readonly playgroundRegistrar?: { readonly sourceId: string; readonly publicKey: string };
  /** 既存URLを保つgateway配置（欠落・'direct'は従来のdirect配置でこのkey自体が無い）。 */
  readonly topology?: GatewayTopology;
  /**
   * 審査・テスト専用のメール・パスワードログイン（欠落・'off'は無効）。有効時は事前登録の審査UIDとサンプル受信先の組。
   * 通常MCPのcompatible・direct配置だけ（strictの許可元承認・gateway-v1との同時指定は設定error）。
   */
  readonly reviewerLogin: 'off' | ReviewerLoginConfig;
  readonly mcpSendText?: true;
  readonly connectedApps?: true;
}

export const REVIEWER_LOGIN_MODE = 'reviewer-password-v1';

/**
 * 審査ログインの構成。受信先設定を省略すると通常の購読規則を使う。
 */
export type ReviewerLoginConfig = ReviewerLoginBody & {
  /**
   * 許可元strictの配置だけで必須（compatibleでは指定不可）: 審査承認の専用connect source ID（運用者が事前登録。Playgroundの登録元とは別）。
   * 秘密鍵はMCPの起動時だけ専用の環境変数から読む（設定には書かない）。
   */
  readonly approvalSourceId?: string;
};

type ReviewerLoginBody = {
  readonly mode: typeof REVIEWER_LOGIN_MODE;
  /** 事前登録の審査・テスト専用Firebase UID（1〜8件・重複なし・開発者コード専用UIDの形は不可）。 */
  readonly uids: readonly string[];
} & (
  | { readonly destinations?: never; readonly firstDestination?: never }
  | {
      /** 審査ownerが購読に使えるサンプル受信先のcallback URL（正規形のhttps・1〜8件・重複なし）。 */
      readonly destinations: readonly string[];
      readonly firstDestination?: never;
    }
  | {
      /**
       * 初回固定: 正規形のhttpsオリジン（`https://<host>`）と、ISO 8601 UTCの絶対開始・終了（`YYYY-MM-DDTHH:MM:SS.sssZ`、開始＜終了、
       * 最大15分）。この枠の間に、オリジンが完全一致するURLで初回の確認に成功した1件を審査ownerの受信先に固定する。
       */
      readonly firstDestination: { readonly origin: string; readonly startsAt: string; readonly endsAt: string };
      readonly destinations?: never;
    }
);

const REVIEWER_LIST_MAX = 8;
const REVIEWER_UID = /^[A-Za-z0-9]{20,128}$/;
const CODE_UID = /^sttdc_/;
/** 初回固定の絶対時間枠の上限（15分）。 */
export const REVIEWER_FIRST_WINDOW_MAX_MS = 15 * 60 * 1000;

/** ISO 8601 UTCの正規形（Date#toISOStringと同じ文字列）だけをepoch msへ。 */
function isoInstant(value: unknown): number {
  requireThat(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value));
  const ms = Date.parse(value as string);
  requireThat(Number.isSafeInteger(ms) && ms >= 0 && new Date(ms).toISOString() === value);
  return ms;
}

/** 'off'または有効時のexact object。従来の受信先制限は明示設定時だけ適用する。 */
function parseReviewerLogin(value: unknown): 'off' | ReviewerLoginConfig {
  if (value === 'off') return 'off';
  const fields = dataFields(value, ['mode', 'uids'], ['destinations', 'firstDestination', 'approvalSourceId']);
  const approvalSourceId = fields.has('approvalSourceId') ? fields.get('approvalSourceId') : undefined;
  requireThat(approvalSourceId === undefined || (typeof approvalSourceId === 'string' && SOURCE_ID_FORM.test(approvalSourceId)));
  const body = parseReviewerLoginBody(fields);
  return approvalSourceId === undefined ? body : { ...body, approvalSourceId: approvalSourceId as string };
}

/** 審査承認のsource ID（source/contract.tsのSOURCE_IDと同じ形）。 */
const SOURCE_ID_FORM = /^src_[a-z2-7]{26}$/;

function parseReviewerLoginBody(fields: Map<string, unknown>): ReviewerLoginBody {
  requireThat(fields.get('mode') === REVIEWER_LOGIN_MODE);
  requireThat(!(fields.has('destinations') && fields.has('firstDestination')));
  const uids = arrayItems(fields.get('uids'));
  requireThat(uids.length >= 1 && uids.length <= REVIEWER_LIST_MAX);
  requireThat(uids.every((uid) => typeof uid === 'string' && REVIEWER_UID.test(uid) && !CODE_UID.test(uid)) && new Set(uids).size === uids.length);
  const account = { mode: REVIEWER_LOGIN_MODE, uids: [...(uids as string[])] } as const;
  if (fields.has('firstDestination')) {
    const first = dataFields(fields.get('firstDestination'), ['origin', 'startsAt', 'endsAt']);
    const origin = str(first, 'origin');
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw invalid();
    }
    requireThat(url.protocol === 'https:' && url.origin === origin && url.port === '' && isDnsHost(url.hostname));
    const startsAt = str(first, 'startsAt');
    const endsAt = str(first, 'endsAt');
    const start = isoInstant(startsAt);
    const end = isoInstant(endsAt);
    requireThat(start < end && end - start <= REVIEWER_FIRST_WINDOW_MAX_MS);
    return { ...account, firstDestination: { origin, startsAt, endsAt } };
  }
  if (!fields.has('destinations')) return account;
  const destinations = arrayItems(fields.get('destinations'));
  requireThat(destinations.length >= 1 && destinations.length <= REVIEWER_LIST_MAX);
  for (const destination of destinations) {
    requireThat(typeof destination === 'string' && destination.length <= 2048);
    let url: URL;
    try {
      url = new URL(destination as string);
    } catch {
      throw invalid();
    }
    requireThat(url.protocol === 'https:' && url.href === destination && url.username === '' && url.password === '' && url.hash === '' && isDnsHost(url.hostname) && url.port === '');
  }
  requireThat(new Set(destinations).size === destinations.length);
  return { ...account, destinations: [...(destinations as string[])] };
}

/** 共通verifier（API・MCPの同じSDK factory）へ渡す審査UID。無効ならundefined（標準構成の検証のまま）。 */
export function reviewerUidsOf(config: Pick<DeploymentConfig, 'reviewerLogin'>): readonly string[] | undefined {
  return config.reviewerLogin === 'off' ? undefined : config.reviewerLogin.uids;
}

/** 従来のstrict審査承認: 専用source IDと唯一の審査UID（新方式・compatible・無効ならundefined）。鍵はここに無い（MCP起動時に専用envから読む）。 */
export function reviewerApprovalOf(config: Pick<DeploymentConfig, 'reviewerLogin' | 'connectedApps'>): { readonly sourceId: string; readonly reviewerUid: string } | undefined {
  const reviewer = config.reviewerLogin;
  if (config.connectedApps === true || reviewer === 'off' || reviewer.approvalSourceId === undefined || reviewer.uids.length !== 1) return undefined;
  return { sourceId: reviewer.approvalSourceId, reviewerUid: reviewer.uids[0]! };
}

/** 通常MCPの接続serverへ渡す審査の構成。無効ならundefined、通常の購読規則なら空のobject。 */
export function reviewerServerOptionOf(
  config: Pick<DeploymentConfig, 'reviewerLogin'>,
):
  | { readonly destinations?: never; readonly firstDestination?: never }
  | { readonly destinations: readonly string[]; readonly firstDestination?: never }
  | { readonly destinations?: never; readonly firstDestination: { readonly origin: string; readonly startsAt: number; readonly endsAt: number } }
  | undefined {
  const reviewer = config.reviewerLogin;
  if (reviewer === 'off') return undefined;
  if (reviewer.destinations !== undefined) return { destinations: reviewer.destinations };
  if (reviewer.firstDestination === undefined) return {};
  const { origin, startsAt, endsAt } = reviewer.firstDestination;
  return { firstDestination: { origin, startsAt: Date.parse(startsAt), endsAt: Date.parse(endsAt) } };
}

export interface PayloadEncryptionConfig {
  readonly mode: typeof PAYLOAD_ENCRYPTION_MODE;
  /** `t280_<lower-case UUID>`。 */
  readonly namespace: string;
  /** 専用secret `projects/<projectNumber>/secrets/<id>`（版を含まない。既存4用途と別のid）。 */
  readonly secret: string;
  readonly writeSecretVersion: number;
  /** 開封に使える数値版（writeSecretVersionを含む重複なし1〜3件）。 */
  readonly readSecretVersions: readonly number[];
}

const PAYLOAD_ENCRYPTION_KEYS = ['mode', 'namespace', 'secret', 'writeSecretVersion', 'readSecretVersions'] as const;
const MAX_READ_SECRET_VERSIONS = 3;

function isSecretVersionNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

/** 'off'または有効時のexact object。専用secretは同じprojectNumberで既存4用途のsecret idと別。 */
function parsePayloadEncryption(value: unknown, projectNumber: string, existingSecretIds: ReadonlySet<string>): 'off' | PayloadEncryptionConfig {
  if (value === 'off') return 'off';
  const fields = dataFields(value, PAYLOAD_ENCRYPTION_KEYS);
  requireThat(fields.get('mode') === PAYLOAD_ENCRYPTION_MODE && isEncryptionNamespace(fields.get('namespace')));
  const secret = str(fields, 'secret');
  const parts = secret.split('/');
  requireThat(secret.length <= 512 && parts.length === 4);
  const [p, project, s, secretId] = parts as [string, string, string, string];
  requireThat(p === 'projects' && project === projectNumber && s === 'secrets' && SECRET_ID.test(secretId) && !existingSecretIds.has(secretId));
  const writeSecretVersion = fields.get('writeSecretVersion');
  const readSecretVersions = arrayItems(fields.get('readSecretVersions'));
  requireThat(isSecretVersionNumber(writeSecretVersion) && readSecretVersions.length >= 1 && readSecretVersions.length <= MAX_READ_SECRET_VERSIONS);
  requireThat(readSecretVersions.every(isSecretVersionNumber) && new Set(readSecretVersions).size === readSecretVersions.length);
  requireThat(readSecretVersions.includes(writeSecretVersion));
  return {
    mode: PAYLOAD_ENCRYPTION_MODE,
    namespace: fields.get('namespace') as string,
    secret,
    writeSecretVersion: writeSecretVersion as number,
    readSecretVersions: [...(readSecretVersions as number[])],
  };
}

const invalid = (): DeploymentConfigError => new DeploymentConfigError('deployment_config_invalid');

function requireThat(condition: boolean): void {
  if (!condition) throw invalid();
}

function str(fields: Map<string, unknown>, key: string): string {
  const value = fields.get(key);
  if (typeof value !== 'string') throw invalid();
  return value;
}

/** `https://<DNS-host>`の公開origin（既存の構成値検査）。`.invalid`等の予約TLDは拒否する。 */
function isPublicOrigin(value: string): boolean {
  if (!isDevelopmentPublicOrigin(value)) return false;
  const host = value.slice('https://'.length);
  const last = host.split('.').pop() ?? '';
  return !['invalid', 'example', 'test', 'local', 'internal'].includes(last) && !host.endsWith('.example.com') && host !== 'example.com';
}

function isServiceAccount(value: string, projectId: string): boolean {
  const suffix = `@${projectId}.iam.gserviceaccount.com`;
  return value.endsWith(suffix) && SA_LOCAL.test(value.slice(0, -suffix.length));
}

function isDnsHost(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2 || !labels.every((label) => DNS_LABEL.test(label))) return false;
  const last = labels[labels.length - 1] ?? '';
  return !/^[0-9]+$/.test(last) && !['localhost', 'invalid', 'example', 'test', 'local', 'internal'].includes(last);
}

function isApiKeyEnvName(value: string): boolean {
  return ENV_NAME.test(value) && !RESERVED_ENV_NAMES.has(value) && !RESERVED_ENV_PREFIXES.some((prefix) => value.startsWith(prefix));
}

/** `projects/<projectId>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>`のlocation（形が違えばnull）。 */
export function cryptoKeyLocation(cryptoKey: unknown): string | null {
  if (typeof cryptoKey !== 'string') return null;
  const parts = cryptoKey.split('/');
  return parts.length === 8 && parts[0] === 'projects' && parts[2] === 'locations' ? (parts[3] ?? null) : null;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze((value as Record<PropertyKey, unknown>)[key]);
    Object.freeze(value);
  }
  return value;
}

/**
 * 配置設定を検証して、検証済みのdeep frozenな写しを返す（純粋関数）。configuredがtrueでなければdeployment_config_unconfigured、
 * それ以外の不正・不整合・未知のkey・accessor・Proxyはdeployment_config_invalid。
 */
export function validateDeploymentConfig(raw: unknown): DeploymentConfig {
  let top: Map<string, unknown>;
  try {
    // accessPolicyは配布placeholder（未設定）の判定を先に保つため存在だけ任意で読み、設定済みの時は下で必須にする。
    top = dataFields(raw, TOP_KEYS, ['accessPolicy', 'developerLogin', 'payloadEncryption', 'sourceAuthorization', 'topology', 'playgroundRegistrar', 'reviewerLogin', 'mcpSendText', 'connectedApps']);
  } catch {
    throw invalid();
  }
  if (top.get('configured') !== true) throw new DeploymentConfigError('deployment_config_unconfigured');
  try {
    requireThat(top.get('accessPolicy') === ACCESS_POLICY);
    // 省略は既定off。'off'か'operator-code-v1'だけ（未知値は設定error）。
    const developerLogin = top.has('developerLogin') ? top.get('developerLogin') : 'off';
    requireThat(developerLogin === 'off' || developerLogin === DEVELOPER_LOGIN_MODE);
    const projectId = str(top, 'projectId');
    const projectNumber = str(top, 'projectNumber');
    const databaseId = str(top, 'databaseId');
    const location = str(top, 'location');
    requireThat(PROJECT_ID.test(projectId) && PROJECT_NUMBER.test(projectNumber) && Number.isSafeInteger(Number(projectNumber)));
    requireThat(databaseId === '(default)' || DATABASE_ID.test(databaseId));
    requireThat(KMS_REGION_PATTERN.test(location));

    const apiFields = dataFields(top.get('api'), API_KEYS, ['runtime']);
    const runtime = apiFields.has('runtime') ? apiFields.get('runtime') : undefined;
    requireThat(runtime === undefined || runtime === 'functions-v1' || runtime === 'cloud-run-v1');
    const api = {
      functionName: str(apiFields, 'functionName'),
      serviceName: str(apiFields, 'serviceName'),
      serviceAccount: str(apiFields, 'serviceAccount'),
      invoker: str(apiFields, 'invoker'),
      publicOrigin: str(apiFields, 'publicOrigin'),
    };
    // functionNameは常に固定。serviceNameは既存配置では固定、cloud-run-v1を明示した時だけ独立した安全なCloud Run名（Functionsの名前と共用しない）。
    requireThat(api.functionName === API_FUNCTION_EXPORT);
    if (runtime === 'cloud-run-v1') requireThat(CLOUD_RUN_NAME.test(api.serviceName) && api.serviceName !== API_FUNCTION_EXPORT);
    else requireThat(api.serviceName === API_FUNCTION_EXPORT);
    requireThat(api.invoker === 'private' && isServiceAccount(api.serviceAccount, projectId) && isPublicOrigin(api.publicOrigin));

    const connectFields = dataFields(top.get('connect'), CONNECT_KEYS);
    const connect = {
      serviceName: str(connectFields, 'serviceName'),
      serviceAccount: str(connectFields, 'serviceAccount'),
      publicOrigin: str(connectFields, 'publicOrigin'),
      invoker: str(connectFields, 'invoker'),
    };
    requireThat(CLOUD_RUN_NAME.test(connect.serviceName) && connect.serviceName !== api.serviceName);
    requireThat(connect.invoker === 'private' && isServiceAccount(connect.serviceAccount, projectId) && connect.serviceAccount !== api.serviceAccount);
    requireThat(isPublicOrigin(connect.publicOrigin) && connect.publicOrigin !== api.publicOrigin);

    const connectNamespace = top.get('connectNamespace');
    const deliveryNamespace = top.get('deliveryNamespace');
    requireThat(isConnectNamespace(connectNamespace) && isKmsDeliveryNamespace(deliveryNamespace));

    const kmsFields = dataFields(top.get('kms'), KMS_KEYS);
    const readVersions = arrayItems(kmsFields.get('readVersions'));
    const kmsInput = {
      environment: kmsFields.get('environment'),
      projectId: kmsFields.get('projectId'),
      databaseId: kmsFields.get('databaseId'),
      namespace: kmsFields.get('namespace'),
      cryptoKey: kmsFields.get('cryptoKey'),
      writeVersion: kmsFields.get('writeVersion'),
      readVersions,
    };
    requireThat(kmsInput.environment === 'development' && kmsInput.projectId === projectId && kmsInput.databaseId === databaseId);
    requireThat(cryptoKeyLocation(kmsInput.cryptoKey) === location);
    // 既存のpure policy（namespace形式・同projectのCryptoKey・数値版・writeを含む重複なしのreadVersions）。
    const policy = createKmsSubscriptionPolicy({ ...kmsInput, readVersions: [...readVersions] });

    const secretFields = dataFields(top.get('secretVersions'), SECRET_PURPOSES);
    const ids = new Set<string>();
    const secretVersions: Record<string, string> = {};
    for (const purpose of SECRET_PURPOSES) {
      const name = str(secretFields, purpose);
      requireThat(name.length <= 1024);
      const parts = name.split('/');
      requireThat(parts.length === 6);
      const [p, project, s, secretId, v, version] = parts as [string, string, string, string, string, string];
      requireThat(p === 'projects' && project === projectNumber && s === 'secrets' && v === 'versions');
      requireThat(SECRET_ID.test(secretId) && VERSION_NUMBER.test(version) && Number.isSafeInteger(Number(version)));
      ids.add(secretId);
      secretVersions[purpose] = name;
    }
    requireThat(ids.size === SECRET_PURPOSES.length);

    const webFields = dataFields(top.get('web'), WEB_KEYS);
    const web = { projectId: str(webFields, 'projectId'), authDomain: str(webFields, 'authDomain'), apiKeyEnv: str(webFields, 'apiKeyEnv') };
    requireThat(web.projectId === projectId && isDnsHost(web.authDomain) && isApiKeyEnvName(web.apiKeyEnv));

    const payloadEncryption = parsePayloadEncryption(top.has('payloadEncryption') ? top.get('payloadEncryption') : 'off', projectNumber, ids);
    // 省略は既存互換。strictは明示objectだけで、空・未知・重複の方式は設定error（互換へ降格しない）。
    const sourceAuthorization = parseSourceAuthorization(top.has('sourceAuthorization') ? top.get('sourceAuthorization') : 'compatible');
    // 省略・'direct'は従来のdirect配置。gateway-v1は全fieldの明示だけで、不正はdirectへ降格しない。
    const topology = parseGatewayTopology(top.get('topology'), {
      apiServiceName: api.serviceName,
      connectServiceName: connect.serviceName,
      apiPublicOrigin: api.publicOrigin,
      connectPublicOrigin: connect.publicOrigin,
      apiServiceAccount: api.serviceAccount,
      connectServiceAccount: connect.serviceAccount,
      isServiceAccount: (value) => isServiceAccount(value, projectId),
    });
    // プレイグラウンドの固定BFF登録元（任意・既定は無効）。strictでdeveloper-key-v1が有効な配置だけで、形の不正は設定error。
    let playgroundRegistrar: { readonly sourceId: string; readonly publicKey: string } | undefined;
    if (top.has('playgroundRegistrar')) {
      const reg = dataFields(top.get('playgroundRegistrar'), ['sourceId', 'publicKey'], []);
      const sourceId = reg.get('sourceId');
      const publicKey = reg.get('publicKey');
      requireThat(typeof sourceId === 'string' && SOURCE_ID.test(sourceId) && typeof publicKey === 'string' && ED25519_PUBLIC_KEY.test(publicKey));
      requireThat(sourceAuthorization !== 'compatible' && sourceAuthorization.methods.includes('developer-key-v1'));
      playgroundRegistrar = { sourceId: sourceId as string, publicKey: publicKey as string };
    }
    // プレイグラウンドの限定routeはdirect配置だけ（gateway-v1のroute allowlistへ新しい入口を広げない）。
    requireThat(!(playgroundRegistrar !== undefined && topology !== undefined));
    // direct Cloud Run APIとgateway-v1（公開API = gateway）は同時に選べない（不整合は設定error）。
    requireThat(!(runtime === 'cloud-run-v1' && topology !== undefined));
    // 審査ログイン（省略は'off'）はdirect配置のみ。旧strictでは専用の許可元承認を必須とする。
    const reviewerLogin = parseReviewerLogin(top.has('reviewerLogin') ? top.get('reviewerLogin') : 'off');
    const connectedApps = top.get('connectedApps');
    requireThat(connectedApps === undefined || (connectedApps === true && topology === undefined && sourceAuthorization !== 'compatible'));
    const mcpSendText = top.get('mcpSendText');
    requireThat(mcpSendText === undefined || (mcpSendText === true && topology === undefined && sourceAuthorization !== 'compatible'));
    if (reviewerLogin !== 'off') {
      requireThat(topology === undefined);
      if (sourceAuthorization === 'compatible') requireThat(reviewerLogin.approvalSourceId === undefined);
      else if (connectedApps !== true) {
        // 旧strict: 既存のdeveloper-key-v1が有効、審査UIDは1件、専用承認sourceがPlaygroundの登録元と別の時だけ。
        requireThat(sourceAuthorization.methods.includes('developer-key-v1') && reviewerLogin.uids.length === 1);
        requireThat(reviewerLogin.approvalSourceId !== undefined && reviewerLogin.approvalSourceId !== playgroundRegistrar?.sourceId);
      }
    }

    return deepFreeze({
      accessPolicy: ACCESS_POLICY,
      developerLogin: developerLogin as 'off' | typeof DEVELOPER_LOGIN_MODE,
      projectId,
      projectNumber,
      databaseId,
      location,
      api: (runtime === undefined ? api : { ...api, runtime }) as DeploymentConfig['api'],
      connect: connect as DeploymentConfig['connect'],
      connectNamespace: connectNamespace as string,
      deliveryNamespace: deliveryNamespace as string,
      kms: {
        environment: 'development' as const,
        projectId: policy.projectId,
        databaseId: policy.databaseId,
        namespace: policy.namespace,
        cryptoKey: policy.cryptoKey,
        writeVersion: policy.writeVersion,
        readVersions: [...policy.readVersions],
      },
      secretVersions: secretVersions as unknown as DeploymentConfig['secretVersions'],
      web,
      payloadEncryption,
      sourceAuthorization: sourceAuthorization === 'compatible' ? sourceAuthorization : { mode: sourceAuthorization.mode, methods: [...sourceAuthorization.methods] },
      ...(topology !== undefined ? { topology } : {}),
      ...(playgroundRegistrar !== undefined ? { playgroundRegistrar } : {}),
      reviewerLogin,
      ...(connectedApps === true ? { connectedApps: true as const } : {}),
      ...(mcpSendText === true ? { mcpSendText: true as const } : {}),
    });
  } catch {
    throw invalid();
  }
}

type LoadedConfig = { readonly config: DeploymentConfig; readonly error: null } | { readonly config: null; readonly error: DeploymentConfigErrorCode };
let loaded: LoadedConfig | undefined;

function loadOnce(): LoadedConfig {
  try {
    return { config: validateDeploymentConfig(DEPLOYMENT_CONFIG as unknown), error: null };
  } catch (error) {
    return { config: null, error: error instanceof DeploymentConfigError ? error.code : 'deployment_config_invalid' };
  }
}

/** 編集済みの配置設定を1回だけ検証して返す（結果・失敗ともmemo）。不正は固定のDeploymentConfigError。 */
export function loadDeploymentConfig(): DeploymentConfig {
  const state: LoadedConfig = loaded ?? (loaded = loadOnce());
  if (state.config === null) throw new DeploymentConfigError(state.error);
  return state.config;
}

/** loadDeploymentConfigと同じ検証で、不正ならnull（任意機能の有無の判定だけに使う）。 */
export function tryLoadDeploymentConfig(): DeploymentConfig | null {
  try {
    return loadDeploymentConfig();
  } catch {
    return null;
  }
}
