// 配置設定（src/config/deployment.ts）の検証。validateDeploymentConfigは純粋関数（I/O・SDK・資格・DB・HTTP・env読取り0）で、
// exact own dataのkey・型・形式・相互整合を全て確かめ、検証済みのdeep frozenな写しを返す。不正は固定codeだけのDeploymentConfigError
// （値・path・元例外を持たない）。configured: trueは必要条件の1つで、それだけでは他の検査を省略しない。配布placeholderは形式で落ちる。
// loadDeploymentConfigは編集済みmoduleの値を1回だけ検証してmemoする（失敗もmemoし、取り直さない）。設定をHTTP・env・argvから選ぶ口は無い。
// 呼出し側（google-runtime・deployment・connect）はSDK生成・秘密・DB・listen・外部HTTPの前にこれを呼ぶ。

import { isConnectNamespace } from '../connect/firestore.js';
import { isKmsDeliveryNamespace } from '../delivery/kms-store.js';
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { KMS_REGION_PATTERN } from '../protection/kms-sealing.js';
import { arrayItems, dataFields } from '../protection/google-sdk-call.js';
import { createKmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
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
const API_KEYS = ['functionName', 'serviceName', 'serviceAccount', 'invoker', 'publicOrigin'] as const;
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
    top = dataFields(raw, TOP_KEYS, ['accessPolicy']);
  } catch {
    throw invalid();
  }
  if (top.get('configured') !== true) throw new DeploymentConfigError('deployment_config_unconfigured');
  try {
    requireThat(top.get('accessPolicy') === ACCESS_POLICY);
    const projectId = str(top, 'projectId');
    const projectNumber = str(top, 'projectNumber');
    const databaseId = str(top, 'databaseId');
    const location = str(top, 'location');
    requireThat(PROJECT_ID.test(projectId) && PROJECT_NUMBER.test(projectNumber) && Number.isSafeInteger(Number(projectNumber)));
    requireThat(databaseId === '(default)' || DATABASE_ID.test(databaseId));
    requireThat(KMS_REGION_PATTERN.test(location));

    const apiFields = dataFields(top.get('api'), API_KEYS);
    const api = {
      functionName: str(apiFields, 'functionName'),
      serviceName: str(apiFields, 'serviceName'),
      serviceAccount: str(apiFields, 'serviceAccount'),
      invoker: str(apiFields, 'invoker'),
      publicOrigin: str(apiFields, 'publicOrigin'),
    };
    requireThat(api.functionName === API_FUNCTION_EXPORT && api.serviceName === API_FUNCTION_EXPORT);
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

    return deepFreeze({
      accessPolicy: ACCESS_POLICY,
      projectId,
      projectNumber,
      databaseId,
      location,
      api: api as DeploymentConfig['api'],
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
