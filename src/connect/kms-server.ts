// MCP/OAuthのKMS接続server。startDevelopmentKmsConnectServerが、接続状態/解除API（/v1/web/*。ローカル送信画面のhelperが中継する）・provider interaction（＋その固定script）
// （login/consent/deny）・/console（固定API originの操作画面）・MCP・protected resource metadata・OAuth/.well-knownを、要求ごとのcontext・
// KMS port・AS resolver・MCP入口・購読登録runtime・購読viewの上で内部に組み立て、固定のhttps publicOrigin（issuer）で0.0.0.0の指定portに
// 待ち受ける。OAuth profileはconnect-kms-development。任意のresolver・store・proof・validatorの注入口は無い。
// db・identity・KMS transport・secret source・clientEgress・verificationSender・clockは借用で、成功・失敗・closeのどれでもterminate/close/dispose0。
// 固定秘密は起動時に1回だけ（最大5秒）読み、生成・ログ・暗号box fallbackをしない。markerは既存の正しいもの（environment=development）だけを
// 要求し、作らない・直さない。
//   - 起動の元期限はmin(任意の起動親deadlineAt, 開始+20秒)を最初の1回だけ決め、中断は親と専有controllerの両方。全体の物理待機（所有watchdog）と
//     全stage・await前後・listen成功の採用直前に同じ期限・安全な時計（安全整数・非負・ISO表現域、throwなし）を検査する。listenはstartupの
//     ALS slotの外で始め、採用しなかった待受は閉じ、後着のerrorは固定listenerで受ける。成功・失敗とも親のlistenerを外す。
//   - 各HTTP要求はroute/Providerの前にHost（値とrawHeadersの件数）・request-target（origin-form）を検査し、クライアント由来のForwarded全系列を
//     固定のX-Forwarded-Proto/Hostへ置換する（不一致・重複は固定400）。TLSは外側（Cloud Run）の終端が前提。受付時に元20秒のoperationを1回だけ
//     作り、切断・未完了の応答close・server closeへ結んで、全routeとSDK callbackをcontext.runで待つ。routeとProviderへ渡す外部port（adapter・
//     assertion予約・CIMD取得）・本人確認・保存の各呼出しは、新しく始める前とawaitの後に同じ要求currentを検査する（既に始めた1つの呼出し内部の
//     物理取消は約束しない）。
// ログは固定のevent・route・category・statusだけで、元例外のname/message/stack・token・URL・UID・CSRF・cookie・秘密を出さない。

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { types } from 'node:util';

import type { Firestore } from '@google-cloud/firestore';
import type Provider from 'oidc-provider';
import type { Adapter, AdapterFactory, JWKS } from 'oidc-provider';
import { z } from 'zod';

import { ApiError, apiErrors } from '../errors.js';
import { createKmsSubscriptionRegistrationRuntime, type KmsSubscriptionRuntime } from '../events/kms-subscription-runtime.js';
import {
  createKmsConnectionSubscriptionView,
  KmsConnectionSubscriptionViewError,
  type KmsConnectionSubscriptionView,
} from '../events/kms-subscription-view.js';
import type { SubscribeInput, SubscriptionAuth, VerificationSender } from '../events/subscriptions.js';
import { assertNoBody, readForm, readJson } from '../http/body.js';
import type { LogSink } from '../http/log.js';
import { IdentityError, type IdentityVerifier, type VerifiedIdentity } from '../identity/firebase.js';
import type { McpEntry, McpRequestOperation, RequestScopedSubscriptionPort } from '../mcp/request-operation.js';
import { createRequestScopedMcpEntry } from '../mcp/request-scoped-entry.js';
import { CHATGPT_CIMD_CANDIDATE } from '../oauth/cimd.js';
import { ConnectionService, type ConnectionState } from '../oauth/owner.js';
import { createOAuthProvider, STTD_SCOPE, resourceFor, type ConnectKmsOAuthProfile } from '../oauth/provider.js';
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import {
  createRequestAuthContext,
  createRequestScopedOAuthOwnerResolver,
  RequestAuthContextError,
  type RequestAuthContext,
} from '../oauth/request-auth-runtime.js';
import { PRODUCT_POLICY, type Clock } from '../policy.js';
import { isEpochMs, isRealSignal } from '../protection/google-sdk-call.js';
import type { KmsDecryptRequest, KmsDecryptResponse, KmsEncryptRequest, KmsEncryptResponse, KmsCallOptions } from '../protection/kms-sealing.js';
import { createHmacHasher, OPAQUE_VALUE_PATTERN } from '../secrets.js';
import { createKmsSubscriptionPolicy, requireKmsMarker, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { AUTH_STORAGE_ROOT, KMS_SUBSCRIPTION_CONFIG_DOC } from '../storage/firestore/kms-subscription-format.js';
import { AccessUnavailableError, ConnectStorage, isConnectNamespace } from './firestore.js';
import { isLanguage, LANGUAGE_QUERY, languageCookie, selectLanguage, type Language } from './i18n.js';
import { createConnectKmsSealingPort } from './kms-port.js';
import {
  INTERACTION_SCRIPT,
  INTERACTION_SCRIPT_PATH,
  pageSecurityHeaders,
  renderInteractionAccessDenied,
  renderInteractionConsent,
  renderInteractionLogin,
  type FirebaseWebConfig,
} from './pages.js';

/** 待受（外側の固定TLS終端の後ろの内部network用）。呼出し側から選ばせない。 */
const BIND_HOST = '0.0.0.0';
/** startの全体（元期限）。延長しない。 */
const START_BUDGET_MS = 20_000;
/** 固定秘密の読込み1回の上限。 */
const SECRET_LOAD_BUDGET_MS = 5_000;
/** 1つのHTTP要求の元期限。延長しない。 */
const REQUEST_BUDGET_MS = 20_000;
/** closeの全体の絶対上限。 */
const CLOSE_BUDGET_MS = 5_000;
const MAX_ISO_TIME_MS = 8_640_000_000_000_000;
const ID_TOKEN_MAX = 3800;
const BEARER_ID_TOKEN = /^Bearer ([A-Za-z0-9._-]{1,4096})$/;
const MCP_PATH = '/mcp';
/** 既知の本人確認の失敗分類（identity/firebase.tsのIdentityFailure）。未知の値はunavailableへ閉じ、記録・応答へ転記しない。 */
const IDENTITY_FAILURES: ReadonlySet<string> = new Set(['invalid', 'expired', 'revoked', 'disabled', 'deleted', 'wrong_project', 'wrong_provider', 'unavailable']);
/** 交換・refreshの再確認で拒否として扱う既知のaccount状態（activeは成功、他の値は一時障害）。 */
const ACCOUNT_REFUSALS: ReadonlySet<string> = new Set(['disabled', 'revoked', 'deleted']);
const CIMD_TARGETS: ReadonlySet<string> = new Set(['client_metadata', 'jwks', 'other']);
const CIMD_OUTCOMES: ReadonlySet<string> = new Set(['fetched', 'reused', 'refused']);

const REQUIRED = ['bindPort', 'db', 'namespace', 'kms', 'secrets', 'identity', 'web', 'clientEgress', 'verificationSender', 'clock', 'publicOrigin'] as const;
const OPTIONAL = ['log', 'startupOperation'] as const;
const STARTUP_OPERATION_KEYS = ['deadlineAt', 'signal'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const WEB_KEYS = ['apiKey', 'authDomain', 'projectId'] as const;
const KEY_KEYS = ['jwks', 'cookieKeys', 'identifierKey'] as const;

/** optionsの不正。固定のcode/messageだけで、渡された値・元の例外を持たない。副作用（読込み・DB・listen）の前に返す。 */
export class KmsConnectServerConfigError extends Error {
  override readonly name = 'KmsConnectServerConfigError';
  readonly code = 'kms_connect_config_invalid';
  constructor() {
    super('kms_connect_config_invalid');
  }
}

/** 起動の失敗（秘密の読込み・形・marker・組立て・listen・期限）。cause・元の例外・秘密を持たない。所有資源は片付け済み。 */
export class KmsConnectServerStartupError extends Error {
  override readonly name = 'KmsConnectServerStartupError';
  readonly code = 'kms_connect_startup_failed';
  constructor() {
    super('kms_connect_startup_failed');
  }
}

/** closeが上限（5秒）内に終わらなかった・閉鎖が失敗した。完了と偽らない。 */
export class KmsConnectServerCloseError extends Error {
  override readonly name = 'KmsConnectServerCloseError';
  readonly code = 'kms_connect_close_failed';
  constructor() {
    super('kms_connect_close_failed');
  }
}

/** Secret Managerの固定秘密（封緘portは含めない。保存の封緘はKMS port）。 */
export interface KmsConnectKeys {
  /** AS署名鍵（private ES256 1つ＋RS256 1つ）。 */
  readonly jwks: JWKS;
  /** cookie署名鍵（各32byte、1つ以上）。 */
  readonly cookieKeys: readonly Buffer[];
  /** 識別子HMAC鍵（32byte）。 */
  readonly identifierKey: Buffer;
}

export interface KmsConnectSecretSource {
  load(): Promise<KmsConnectKeys>;
}

/** KMS codec設定からclockを除いたもの（namespaceはKMS購読のt268、environmentはdevelopmentだけ）。 */
export interface KmsConnectKmsConfig {
  readonly environment: 'development';
  readonly projectId: string;
  readonly databaseId: string;
  readonly namespace: string;
  readonly cryptoKey: string;
  readonly writeVersion: number;
  readonly readVersions: readonly number[];
  readonly transport: {
    encrypt(request: KmsEncryptRequest, options: KmsCallOptions): PromiseLike<KmsEncryptResponse>;
    decrypt(request: KmsDecryptRequest, options: KmsCallOptions): PromiseLike<KmsDecryptResponse>;
  };
}

export interface KmsConnectServerOptions {
  /** 0.0.0.0で待ち受ける明示の整数port（1024〜65535）。待受hostは選ばせない。 */
  readonly bindPort: number;
  /** 借用するFirestore instance（terminateしない）。 */
  readonly db: Firestore;
  /** 接続保存の`t256_<小文字UUID>`。 */
  readonly namespace: string;
  readonly kms: KmsConnectKmsConfig;
  readonly secrets: KmsConnectSecretSource;
  /** 既存のIdentityVerifier（kms・webと同じproject）。 */
  readonly identity: IdentityVerifier;
  readonly web: FirebaseWebConfig;
  /** CIMDのclient文書・JWKSの取得（固定の許可先だけ）。 */
  readonly clientEgress: ConnectKmsOAuthProfile['egress'];
  /** callback検証の送出（借用）。 */
  readonly verificationSender: VerificationSender;
  readonly clock: Clock;
  /** 固定のevent・route・category・statusだけを受け取る。 */
  readonly log?: LogSink | undefined;
  /** 正規形の`https://<小文字DNS-host>`だけ（port・path・query・fragment・userinfo・末尾slash・IP・localhostなし）。issuerになる。 */
  readonly publicOrigin: string;
  /**
   * 任意。呼出し元全体の起動operation（親）。startの元期限はmin(親deadlineAt, 開始+20秒)で、親の中断でも止まる（延長しない）。
   * 省略時は開始+20秒。親の期限・中断は起動の間だけ見て、成功後の要求は要求固有のoperationを使う。callerのsignalはabortしない。
   */
  readonly startupOperation?: KmsConnectStartupOperation | undefined;
}

/** 起動の親operation（正確なown dataの2key・epoch ms・genuine AbortSignal）。 */
export interface KmsConnectStartupOperation {
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

export interface KmsConnectServer {
  /** 設定のpublicOrigin。 */
  readonly issuer: string;
  /** issuer配下の`/mcp`。 */
  readonly resource: string;
  /** 同じPromiseで冪等。上限5秒、失敗はKmsConnectServerCloseError。借用資源・保存は閉じない・消さない。 */
  close(): Promise<void>;
}

function configFail(): never {
  throw new KmsConnectServerConfigError();
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知/欠落の名前を拒否、getterを呼ばない）。 */
function dataFields(value: unknown, required: readonly string[], optional: readonly string[], onInvalid: () => Error): Map<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) throw onInvalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw onInvalid();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || optional.includes(key))) throw onInvalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw onInvalid();
    if (descriptor.value !== undefined || required.includes(key)) taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) throw onInvalid();
  return taken;
}

/** prototypeの連鎖をdescriptorで辿ってmethodを1回取り出し、元のobjectへ束縛する（accessor・Proxyを拒否、getterを呼ばない）。 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) configFail();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) configFail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) configFail();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  return configFail();
}

function plainFunction(value: unknown): (...args: unknown[]) => unknown {
  if (typeof value !== 'function' || types.isProxy(value)) configFail();
  const found = value as Function;
  return (...args: unknown[]) => Reflect.apply(found, undefined, args);
}

/** 本物の配列（Proxy・accessor・穴・余分なpropertyなし）の要素を1回だけ読む。 */
function arrayItems(value: unknown, onInvalid: () => Error): unknown[] {
  if (!isObject(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw onInvalid();
  const length = (Object.getOwnPropertyDescriptor(value, 'length') as PropertyDescriptor).value as number;
  if (Reflect.ownKeys(value).length !== length + 1) throw onInvalid();
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) throw onInvalid();
    out.push(descriptor.value);
  }
  return out;
}

/** own data propertyのstringの値（accessor・継承は読まない）。 */
function ownString(target: object, key: string): string | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor !== undefined && 'value' in descriptor && typeof descriptor.value === 'string' ? descriptor.value : undefined;
}

/** 同期の例外もrejectにして、外部の関数を1回だけ呼ぶ。 */
function invoke<T>(call: () => T | PromiseLike<T>): Promise<T> {
  return new Promise<T>((resolve) => resolve(call()));
}

/** 起動の前に1回だけ捕捉した設定（以後は入力objectを読み直さない）。 */
interface Captured {
  /** 検査済みのpublicOrigin。 */
  readonly publicOrigin: string;
  readonly bindPort: number;
  readonly db: Firestore;
  readonly namespace: string;
  readonly policy: KmsSubscriptionPolicy;
  readonly transport: KmsConnectKmsConfig['transport'];
  readonly load: () => unknown;
  readonly identity: IdentityVerifier;
  readonly web: FirebaseWebConfig;
  readonly clientEgress: ConnectKmsOAuthProfile['egress'];
  readonly verificationSender: VerificationSender;
  readonly now: () => unknown;
  readonly log: (entry: Parameters<LogSink>[0]) => void;
  /** 任意の起動親（捕捉した写し）。省略はnull。 */
  readonly startupParent: KmsConnectStartupOperation | null;
}

/** 起動親の捕捉（正確なown dataの2key、安全整数・非負・ISO表現域のepoch ms、genuine AbortSignal）。不正は設定エラー。 */
function captureStartupParent(value: unknown): KmsConnectStartupOperation {
  const fields = dataFields(value, STARTUP_OPERATION_KEYS, [], () => new KmsConnectServerConfigError());
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) configFail();
  return Object.freeze({ deadlineAt, signal });
}

function capture(options: unknown): Captured {
  const fields = dataFields(options, REQUIRED, OPTIONAL, () => new KmsConnectServerConfigError());
  const startupParent = fields.has('startupOperation') ? captureStartupParent(fields.get('startupOperation')) : null;

  const publicOrigin = fields.get('publicOrigin');
  if (!isDevelopmentPublicOrigin(publicOrigin)) configFail();

  const bindPort = fields.get('bindPort');
  if (typeof bindPort !== 'number' || !Number.isSafeInteger(bindPort) || bindPort < 1024 || bindPort > 65535) configFail();

  // dbは借用。SDKのmethodの存在だけをdescriptorで確かめる（呼ばない・接続しない）。
  const db = fields.get('db');
  methodOf(db, 'collection');
  methodOf(db, 'runTransaction');
  methodOf(db, 'batch');

  const namespace = fields.get('namespace');
  if (!isConnectNamespace(namespace)) configFail();

  // KMS: clockを持たせない。購読のpolicy（t268）は共通の検査・正規化で1回捕捉する。environmentはdevelopmentだけで、markerの
  // environmentもこの値と一致を要求する（requireKmsMarker）。
  const kms = dataFields(fields.get('kms'), KMS_KEYS, [], () => new KmsConnectServerConfigError());
  if (kms.get('environment') !== 'development') configFail();
  let policy: KmsSubscriptionPolicy;
  try {
    policy = createKmsSubscriptionPolicy({
      namespace: kms.get('namespace'),
      environment: kms.get('environment'),
      projectId: kms.get('projectId'),
      databaseId: kms.get('databaseId'),
      cryptoKey: kms.get('cryptoKey'),
      writeVersion: kms.get('writeVersion'),
      readVersions: arrayItems(kms.get('readVersions'), () => new KmsConnectServerConfigError()),
    });
  } catch {
    return configFail();
  }
  const encrypt = methodOf(kms.get('transport'), 'encrypt');
  const decrypt = methodOf(kms.get('transport'), 'decrypt');
  const transport = Object.freeze({
    encrypt: (request: KmsEncryptRequest, callOptions: KmsCallOptions) => encrypt(request, callOptions) as PromiseLike<KmsEncryptResponse>,
    decrypt: (request: KmsDecryptRequest, callOptions: KmsCallOptions) => decrypt(request, callOptions) as PromiseLike<KmsDecryptResponse>,
  });

  const load = methodOf(fields.get('secrets'), 'load');

  const identityTarget = fields.get('identity');
  const verifyIdToken = methodOf(identityTarget, 'verifyIdToken');
  const accountStatus = methodOf(identityTarget, 'accountStatus');
  const identityProject = isObject(identityTarget) ? ownString(identityTarget, 'projectId') : undefined;
  if (identityProject !== policy.projectId) configFail();
  const identity: IdentityVerifier = Object.freeze({
    projectId: identityProject,
    verifyIdToken: (idToken: string) => verifyIdToken(idToken) as Promise<VerifiedIdentity>,
    accountStatus: (uid: string, sinceSec: number) => accountStatus(uid, sinceSec) as ReturnType<IdentityVerifier['accountStatus']>,
  });

  const webFields = dataFields(fields.get('web'), WEB_KEYS, [], () => new KmsConnectServerConfigError());
  const web = Object.fromEntries(WEB_KEYS.map((key) => [key, webFields.get(key)])) as Record<string, unknown>;
  if (!WEB_KEYS.every((key) => typeof web[key] === 'string' && web[key] !== '')) configFail();
  if (web.projectId !== policy.projectId) configFail();

  const getJson = methodOf(fields.get('clientEgress'), 'getJson');
  const clientEgress = Object.freeze({
    getJson: (url: string, egressOptions?: unknown) => getJson(url, egressOptions),
  }) as unknown as ConnectKmsOAuthProfile['egress'];

  const sender = plainFunction(fields.get('verificationSender'));
  const verificationSender: VerificationSender = (request, signal) => sender(request, signal) as ReturnType<VerificationSender>;

  const now = methodOf(fields.get('clock'), 'now');
  const logFn = fields.has('log') ? plainFunction(fields.get('log')) : undefined;
  const log = (entry: Parameters<LogSink>[0]): void => {
    if (logFn === undefined) return;
    try {
      logFn(Object.freeze({ ...entry }));
    } catch {
      // 記録の失敗で要求の扱いを変えない。
    }
  };

  return Object.freeze({
    publicOrigin,
    bindPort,
    db: db as Firestore,
    namespace,
    policy,
    transport,
    load: () => load(),
    identity,
    web: Object.freeze(web) as unknown as FirebaseWebConfig,
    clientEgress,
    verificationSender,
    now,
    log,
    startupParent,
  });
}

/** 秘密の形の検査と、所有の写し（借用の値を後から改変されても影響しない）。不正は起動失敗。 */
interface OwnedKeys {
  readonly jwks: JWKS;
  readonly cookieKeys: Buffer[];
  readonly identifierKey: Buffer;
}

function startupFail(): never {
  throw new KmsConnectServerStartupError();
}

function copyKeys(value: unknown): OwnedKeys {
  const fields = dataFields(value, KEY_KEYS, [], () => new KmsConnectServerStartupError());
  const jwksFields = dataFields(fields.get('jwks'), ['keys'], [], () => new KmsConnectServerStartupError());
  const listed = arrayItems(jwksFields.get('keys'), () => new KmsConnectServerStartupError());
  if (listed.length !== 2) startupFail();
  const keys: Record<string, string>[] = [];
  const algs = new Set<string>();
  for (const entry of listed) {
    if (!isObject(entry) || Array.isArray(entry) || Object.getPrototypeOf(entry) !== Object.prototype) startupFail();
    const copy: Record<string, string> = {};
    for (const key of Reflect.ownKeys(entry)) {
      const descriptor = Object.getOwnPropertyDescriptor(entry, key);
      if (typeof key !== 'string' || descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'string') startupFail();
      copy[key] = descriptor.value;
    }
    // private鍵（dあり）で、ES256はEC P-256、RS256はRSA。
    const alg = copy.alg;
    if (alg !== 'ES256' && alg !== 'RS256') startupFail();
    if (typeof copy.d !== 'string' || copy.d === '') startupFail();
    if (alg === 'ES256' ? copy.kty !== 'EC' || copy.crv !== 'P-256' : copy.kty !== 'RSA') startupFail();
    algs.add(alg);
    keys.push(copy);
  }
  if (algs.size !== 2) startupFail();
  const cookies = arrayItems(fields.get('cookieKeys'), () => new KmsConnectServerStartupError());
  // 各32byte・1つ以上（個数上限は置かない）。
  if (cookies.length < 1) startupFail();
  const cookieKeys = cookies.map((key) => {
    if (!Buffer.isBuffer(key) || types.isProxy(key) || key.length !== 32) startupFail();
    return Buffer.from(key);
  });
  const identifier = fields.get('identifierKey');
  if (!Buffer.isBuffer(identifier) || types.isProxy(identifier) || identifier.length !== 32) startupFail();
  return { jwks: { keys } as unknown as JWKS, cookieKeys, identifierKey: Buffer.from(identifier) };
}

/**
 * promiseを、msかsignalまでで待つ（期限のtimerは必ず解除。遅い値は捨て、rejectは握りつぶす）。既に中止されていれば、timer・listenerを
 * 作らずに失敗する。
 */
function within<T>(promise: Promise<T>, ms: number, signal: AbortSignal): Promise<T> {
  promise.catch(() => {});
  if (signal.aborted) return Promise.reject(new KmsConnectServerStartupError());
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (outcome: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      outcome();
    };
    const onAbort = () => finish(() => reject(new KmsConnectServerStartupError()));
    const timer = setTimeout(() => finish(() => reject(new KmsConnectServerStartupError())), Math.max(1, ms));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    promise.then(
      (value) => finish(() => resolve(value)),
      () => finish(() => reject(new KmsConnectServerStartupError())),
    );
  });
}

/** クライアント由来のForwarded系列（Forwarded・X-Forwarded-*）か（小文字の名前）。 */
const isForwardedName = (name: string): boolean => name === 'forwarded' || name.startsWith('x-forwarded-');

/**
 * origin-formのrequest-targetだけ（'/'で始まり、'//'で始まらず、空白・制御文字・非ASCII・'\'を含まない）。
 * absolute-form・authority-form・asterisk-formは拒否する（WHATWG URLで別hostへ解釈され得る'\'と'//'も入れない）。
 */
const ORIGIN_FORM_TARGET = /^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/;

/**
 * 各要求を、route/Providerより前に検査して整える。Hostはheadersの値が設定authorityと完全一致し、かつ
 * rawHeadersにHostがちょうど1件（その値も一致）であること。request-targetはorigin-formだけ。成立したら、クライアント由来のForwarded・
 * X-Forwarded-*をheaders・rawHeadersの両方から全て除去し、信頼する固定deploymentのX-Forwarded-Proto: httpsとX-Forwarded-Host:
 * <authority>だけを置く（Providerのproxy設定はこれだけを読む。Host・Originはこの値で上書きしない）。不成立はfalse（呼出し側が固定の
 * 400にし、DB・本人確認・egress・KMS・Providerを呼ばない）。
 */
function admitRequest(req: IncomingMessage, authority: string): boolean {
  const target = req.url;
  if (typeof target !== 'string' || !ORIGIN_FORM_TARGET.test(target)) return false;
  const raw = req.rawHeaders;
  let hosts = 0;
  for (let index = 0; index + 1 < raw.length; index += 2) {
    if ((raw[index] ?? '').toLowerCase() !== 'host') continue;
    hosts += 1;
    if (raw[index + 1] !== authority) return false;
  }
  if (hosts !== 1 || req.headers.host !== authority) return false;
  const kept: string[] = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index] ?? '';
    if (!isForwardedName(name.toLowerCase())) kept.push(name, raw[index + 1] ?? '');
  }
  kept.push('X-Forwarded-Proto', 'https', 'X-Forwarded-Host', authority);
  raw.length = 0;
  raw.push(...kept);
  const headers = req.headers;
  for (const name of Object.keys(headers)) if (isForwardedName(name)) delete headers[name];
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-host'] = authority;
  return true;
}

const BASE_HEADERS = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };

const loginBody = z.strictObject({
  csrf: z.string().regex(OPAQUE_VALUE_PATTERN),
  idToken: z.string().min(1).max(ID_TOKEN_MAX),
});

/** route処理の結果（context.runの固定unavailableで元の分類を失わないよう、work内で捕捉して運ぶ）。 */
type RouteOutcome = { readonly ok: true; readonly label: string } | { readonly ok: false; readonly error: unknown };
/** context.run自身が期限・中止・閉鎖で打ち切った印。 */
const STOPPED: unique symbol = Symbol('kms connect request stopped');

/** 組み立てた所有資源（起動途中の失敗・closeで片付ける）。借用資源は含めない。 */
interface Owned {
  context: RequestAuthContext | undefined;
  runtime: KmsSubscriptionRuntime | undefined;
  view: KmsConnectionSubscriptionView | undefined;
  mcp: McpEntry | undefined;
  server: Server | undefined;
  keys: OwnedKeys | undefined;
}

/** 片付け: context・runtime・viewの中止（同期）→MCP入口のclose→serverのclose。上限つき。失敗はfalse（例外は運ばない）。 */
async function shutdown(owned: Owned, budgetMs: number): Promise<boolean> {
  owned.context?.dispose();
  owned.runtime?.dispose();
  owned.view?.dispose();
  const steps: Promise<unknown>[] = [];
  if (owned.mcp !== undefined) steps.push(invoke(() => owned.mcp!.close()));
  const server = owned.server;
  if (server !== undefined) {
    steps.push(
      new Promise<void>((resolve, reject) => {
        if (!server.listening) {
          resolve();
          return;
        }
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
    );
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const settled = await Promise.race([
      Promise.allSettled(steps),
      new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => resolve('timeout'), budgetMs);
      }),
    ]);
    return settled !== 'timeout' && settled.every((entry) => entry.status === 'fulfilled');
  } finally {
    clearTimeout(timer);
  }
}

/**
 * KMS接続serverを起動する。optionsを副作用の前に検査・捕捉し（publicOriginの正規形・environment=development。不正は
 * KmsConnectServerConfigError）、元20秒のstartの中で固定秘密の読込み（1回・最大5秒）・markerの確認（一致が必須・作らない・直さない）・
 * 全組立てを終えてから0.0.0.0の指定portでlistenし、採用の直前にも同じ元期限を検査する。issuerはpublicOrigin、resourceはその`/mcp`、
 * OAuth profileはconnect-kms-development（Secure cookie・Bearer専用・90日無活動更新）。失敗は所有資源だけを片付けてKmsConnectServerStartupError。
 */
export async function startDevelopmentKmsConnectServer(options: KmsConnectServerOptions): Promise<KmsConnectServer> {
  return startCaptured(capture(options));
}

async function startCaptured(config: Captured): Promise<KmsConnectServer> {
  const { db, namespace, policy, identity, web, log } = config;
  /** 設定のauthority（`<DNS-host>`）。 */
  const authority = new URL(config.publicOrigin).host;

  /** 共通の時計（captured now）。全構成へ同じobjectを渡す。 */
  const clock: Clock = Object.freeze({ now: () => config.now() as number });
  /** 起動・要求の受付の時刻の観測（安全整数・非負・ISO表現域で、20秒を足しても表現域内）。throw・不正はnull。 */
  const safeNow = (): number | null => {
    let value: unknown;
    try {
      value = config.now();
    } catch {
      return null;
    }
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_ISO_TIME_MS - START_BUDGET_MS ? value : null;
  };
  const issuer = config.publicOrigin;
  const issuerUrl = new URL(issuer);
  const resource = resourceFor(issuer);
  const kmsConfig = () => ({
    environment: policy.environment,
    projectId: policy.projectId,
    databaseId: policy.databaseId,
    namespace: policy.namespace,
    cryptoKey: policy.cryptoKey,
    writeVersion: policy.writeVersion,
    readVersions: [...policy.readVersions],
    transport: config.transport,
  });

  const owned: Owned = { context: undefined, runtime: undefined, view: undefined, mcp: undefined, server: undefined, keys: undefined };
  const startController = new AbortController();
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  // 任意の起動親。親の中断を専有startControllerへ結ぶ（callerのsignalはabortしない）。finallyで必ず解除する。
  const parent = config.startupParent;
  const onParentAbort = (): void => startController.abort();
  try {
    // 起動の元operationは最初の1回だけ決める。異常な時計のままでは、新しいtimer・listen・読込みを始めない。
    const startedAt = safeNow();
    if (startedAt === null) startupFail();
    // 親が既に中断・期限到達なら、秘密の読込み・DB・listenの前に固定の起動失敗（timer・listenerを作らない）。
    if (parent !== null && (parent.signal.aborted || !(startedAt < parent.deadlineAt))) startupFail();
    // 元期限はmin(親deadlineAt, 開始+20秒)（親を延長しない。省略時は開始+20秒）。
    const deadlineAt = parent === null ? startedAt + START_BUDGET_MS : Math.min(parent.deadlineAt, startedAt + START_BUDGET_MS);
    const startOperation: McpRequestOperation = Object.freeze({ deadlineAt, signal: startController.signal });
    if (parent !== null) {
      parent.signal.addEventListener('abort', onParentAbort, { once: true });
      if (parent.signal.aborted) startController.abort();
    }
    // start全体の物理的な待機も同じ元期限まで（到達で全stageの待機を中止）。finallyで必ず解除する。
    watchdog = setTimeout(() => startController.abort(), deadlineAt - startedAt);
    /** 起動の各stage・await前後・listen採用の直前の検査（signal→時計→signal）。不正な時刻・期限・中止は固定の起動失敗。期限を取り直さない。 */
    const startLive = (): void => {
      if (startController.signal.aborted) startupFail();
      const at = safeNow();
      if (startController.signal.aborted) startupFail();
      if (at === null) startupFail();
      if (!(at < startOperation.deadlineAt)) {
        startController.abort();
        startupFail();
      }
    };

    const context = createRequestAuthContext({ clock });
    owned.context = context;

    const built = await context.run(startOperation, async () => {
      // 固定秘密は1回だけ、最大5秒（startの元期限・中止が先ならそちら）。生成・fallback0。slotのsignalは読込みを始める前に捕捉し、
      // 始めたPromiseへ先にreject handlerを付けてから次の検査をする（期限後の新しいtimer・listener0、遅いrejectも未処理0）。
      const { signal } = context.current();
      const pending = invoke(() => config.load());
      pending.catch(() => {});
      context.current();
      const loaded = await within(pending, SECRET_LOAD_BUDGET_MS, signal);
      context.current();
      const keys = copyKeys(loaded);
      owned.keys = keys;

      // markerは既存の正しいものだけ（無い・違う・別policyは起動失敗。作らない・直さない）。
      const markerRef = db.collection(AUTH_STORAGE_ROOT).doc(policy.namespace).collection('config').doc(KMS_SUBSCRIPTION_CONFIG_DOC);
      context.current();
      const marker = await markerRef.get();
      context.current();
      if (!marker.exists) startupFail();
      requireKmsMarker(marker.data(), policy);

      const hasher = createHmacHasher(keys.identifierKey);
      // AS payload・UIDの封緘は、所有contextのcurrentを要求ごとのoperationにするKMS port（namespaceだけ接続保存のt256）。
      const box = createConnectKmsSealingPort({ kms: { ...kmsConfig(), namespace, clock }, operation: context.current });
      const storage = new ConnectStorage({
        db,
        namespace,
        hasher,
        box,
        clock,
        ownerInactivityMs: PRODUCT_POLICY.ownerInactivityMs,
        interactionTtlMs: PRODUCT_POLICY.interactionTtlMs,
        // providerの接続profileが次のrefresh tokenへ与える無活動窓と同じ値。
        grantInactivityMs: PRODUCT_POLICY.refreshFamilyMaxSec * 1000,
      });
      context.current();
      return { hasher, storage };
    });
    // 以後の組立てとlistenはstartupのALS slotの外（HTTPの資源が終了したstartup slotを継承しない）。同じ元期限で検査を続ける。
    startLive();
    const { hasher, storage } = built;

    /** 新しい公開I/O（保存・本人確認・egress・SDK）を始める前の検査。slot外・終了後・期限・中止・閉鎖は固定のRequestAuthContextError。 */
    const alive = (): void => {
      context.current();
    };
    /** 1つの公開I/Oを、開始の前とawaitの後に同じ要求currentで検査して呼ぶ（既に始めた呼出し内部の物理取消はしない）。 */
    const guarded = async <T>(call: () => T | PromiseLike<T>): Promise<T> => {
      alive();
      const value = await call();
      alive();
      return value;
    };

    // Providerへ渡す保存adapter: 同じConnectStorageのadapterを、各呼出しの開始前・await後に要求currentで検査する（署名・this・戻り値は同じ）。
    const adapterFactory: AdapterFactory = (model) => {
      const inner: Adapter = storage.adapterFactory(model);
      return {
        upsert: (id, payload, expiresIn) => guarded(() => inner.upsert(id, payload, expiresIn)),
        find: (id) => guarded(() => inner.find(id)),
        findByUserCode: (userCode) => guarded(() => inner.findByUserCode(userCode)),
        findByUid: (uid) => guarded(() => inner.findByUid(uid)),
        consume: (id) => guarded(() => inner.consume(id)),
        destroy: (id) => guarded(() => inner.destroy(id)),
        revokeByGrantId: (grantId) => guarded(() => inner.revokeByGrantId(grantId)),
      };
    };
    const assertionReplay = Object.freeze({
      reserve: (key: string, expiresAt: number, now: number) => guarded(() => storage.assertionReplay.reserve(key, expiresAt, now)),
    });
    // CIMDの取得は開始前に同期で検査する（失敗はCIMD側の60秒の共有cacheへ入らない）。共有の取得結果を1つの要求の期限で失敗させて他の要求を
    // 巻き込まないため、await後の検査はProviderの次のadapter/route/口の開始前検査が担う。
    const clientEgress = Object.freeze({
      getJson: (url: string, egressOptions?: Parameters<ConnectKmsOAuthProfile['egress']['getJson']>[1]) => {
        alive();
        return config.clientEgress.getJson(url, egressOptions);
      },
    });

    /**
     * 認可コード交換・refresh（grantIdあり）では、同意した時点のFirebase認証がいまも有効か（disabled・失効・削除でない）を確かめる。
     * 確認できない一時障害・未知の状態は固定の例外（providerは5xx）で、invalid_grantにも成功にもしない。refresh tokenはまだ消費されない。
     */
    const isAccountUsable = async (ownerId: string, grantIdInput?: string): Promise<boolean> => {
      if (!(await guarded(() => storage.isOwnerActive(ownerId)))) return false;
      if (grantIdInput === undefined) return true;
      const grantId: string = grantIdInput;
      const meta = await guarded(() => storage.grantMeta(grantId));
      if (meta === undefined || meta.ownerId !== ownerId) return false;
      // 利用許可: owner→許可recordがactiveで、grantMetaの世代が現在の世代と一致する時だけ新規利用（token消費の前に判定）。
      let usable: boolean;
      try {
        usable = await guarded(() => storage.grantUsable(ownerId, grantId));
      } catch (error) {
        if (!(error instanceof AccessUnavailableError)) throw error;
        log({ event: 'access.unavailable' });
        throw apiErrors.temporarilyUnavailable();
      }
      if (!usable) {
        log({ event: 'access.refused' });
        return false;
      }
      const uid = await guarded(() => storage.uidOf(ownerId));
      if (uid === undefined) return false;
      let status: unknown;
      try {
        status = await guarded(() => identity.accountStatus(uid, meta.authTimeSec));
      } catch (error) {
        if (error instanceof RequestAuthContextError) throw error;
        log({ event: 'identity.status_unavailable' });
        throw apiErrors.temporarilyUnavailable();
      }
      if (status !== 'active') {
        if (typeof status === 'string' && ACCOUNT_REFUSALS.has(status)) {
          log({ event: 'identity.status_refused', category: status });
          return false;
        }
        log({ event: 'identity.status_unavailable' });
        throw apiErrors.temporarilyUnavailable();
      }
      await guarded(() => storage.touchOwner(ownerId));
      return true;
    };

    const provider: Provider = createOAuthProvider({
      profile: {
        kind: 'connect-kms-development',
        issuer,
        adapter: adapterFactory,
        jwks: owned.keys!.jwks,
        cookieKeys: owned.keys!.cookieKeys,
        client: CHATGPT_CIMD_CANDIDATE,
        egress: clientEgress,
        assertionReplay,
        clock,
        onFetch: (outcome, target) =>
          log({ event: 'cimd.fetch', category: CIMD_TARGETS.has(target) && CIMD_OUTCOMES.has(outcome) ? `${target}.${outcome}` : 'other' }),
      },
      policy: PRODUCT_POLICY,
      isOwnerActive: isAccountUsable,
    });
    // 元例外のname・messageは記録しない。Koaの既定のerror出力（stack）も、この固定のlistenerで置き換える。
    provider.on('server_error', () => log({ event: 'oauth.server_error' }));
    // Providerの型はKoa由来の'error'のoverloadを持たないため、EventEmitterとして登録する（listenerがあればKoaは既定の出力を足さない）。
    (provider as unknown as NodeJS.EventEmitter).on('error', () => log({ event: 'oauth.request_error' }));

    const resolver = createRequestScopedOAuthOwnerResolver({ provider, connect: storage, context, resource });
    const runtime = createKmsSubscriptionRegistrationRuntime({
      db,
      connect: storage,
      connectNamespace: namespace,
      resource,
      kms: kmsConfig(),
      hasher,
      clock,
      verificationSender: config.verificationSender,
    });
    owned.runtime = runtime;
    const view = createKmsConnectionSubscriptionView({ db, connect: storage, connectNamespace: namespace, resource, kms: kmsConfig(), clock });
    owned.view = view;

    const service = runtime.service;
    /**
     * MCP入口が作る要求operationを、登録の呼出しでも同じcontext.runで包む（外側HTTPのslotの中なら、その元期限より延ばさない）。
     * runtimeの固定の非成功（既存SubscribeError・固定内部error）はwork内で捕捉してそのまま返し、contextの固定unavailableへ潰さない。
     */
    const scoped = async <T>(operation: McpRequestOperation, call: (current: McpRequestOperation) => Promise<T>): Promise<T> => {
      const result = await context.run(operation, async (): Promise<{ ok: true; value: T } | { ok: false; error: unknown }> => {
        try {
          return { ok: true, value: await call(context.current()) };
        } catch (error) {
          return { ok: false, error };
        }
      });
      if (!result.ok) throw result.error;
      return result.value;
    };
    const subscriptions: RequestScopedSubscriptionPort = Object.freeze({
      subscribe: (auth: SubscriptionAuth, input: SubscribeInput, operation: McpRequestOperation) =>
        scoped(operation, (current) => service.subscribe(auth, input, current)),
      unsubscribe: (auth: SubscriptionAuth, identityInput: { readonly name: string; readonly url: string }, operation: McpRequestOperation) =>
        scoped(operation, (current) => service.unsubscribe(auth, identityInput, current)),
    });

    const mcp = createRequestScopedMcpEntry({
      issuer,
      resource,
      clock,
      resolveOAuthOwner: resolver,
      subscriptions,
      onError: (category) => log({ event: 'mcp.error', category }),
    });
    owned.mcp = mcp;

    const connections = new ConnectionService({
      // 購読の見え方はHTTPの要求slotのcurrentを必ず渡す（slot外・終了後・期限後は固定の非成功）。
      subscriptions: { viewFor: (ownerId) => view.viewFor(ownerId, context.current()) },
      issuedGrantSource: async (ownerId) => {
        if (!(await guarded(() => storage.isOwnerActive(ownerId)))) return false;
        for (const grantId of await guarded(() => storage.issuedGrantIds(ownerId))) {
          const grant = await guarded(() => provider.Grant.find(grantId));
          if (grant && !grant.isExpired && grant.accountId === ownerId && grant.getResourceScope(resource).split(' ').includes(STTD_SCOPE)) {
            return true;
          }
        }
        return false;
      },
    });
    const oauthCallback = provider.callback();

    // ---------- 各route（全て要求slotの中で呼ばれる） ----------

    function send(res: ServerResponse, status: number, type: string, body: string, headers: Record<string, string> = {}): void {
      alive();
      const payload = Buffer.from(body, 'utf8');
      res.writeHead(status, { ...BASE_HEADERS, ...headers, 'Content-Type': type, 'Content-Length': payload.length });
      res.end(payload);
    }

    function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
      send(res, status, 'application/json; charset=utf-8', JSON.stringify(body), headers);
    }

    /** 利用許可の拒否（login）。既存のforbidden（origin違い・owner失効）と区別する固定code。 */
    function accessDenied(): ApiError {
      log({ event: 'interaction.access_denied' });
      return new ApiError(403, 'access_denied');
    }

    function requireSameOrigin(req: IncomingMessage): void {
      if (req.headers.origin !== issuerUrl.origin) throw apiErrors.forbidden();
    }

    /** 本人確認の失敗の既知の分類だけ（未知の例外・値はunavailableへ閉じ、記録・応答へ転記しない）。 */
    function identityCategory(error: unknown): string {
      if (!(error instanceof IdentityError)) return 'unavailable';
      const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
      const code: unknown = descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
      return typeof code === 'string' && IDENTITY_FAILURES.has(code) ? code : 'unavailable';
    }

    async function verifyIdentity(idToken: string): Promise<VerifiedIdentity> {
      alive();
      let verified: VerifiedIdentity;
      try {
        verified = await identity.verifyIdToken(idToken);
      } catch (error) {
        alive();
        const category = identityCategory(error);
        log({ event: 'identity.rejected', category });
        if (category === 'unavailable') throw apiErrors.temporarilyUnavailable();
        throw new ApiError(401, 'identity_rejected');
      }
      alive();
      return verified;
    }

    async function bearerIdentity(req: IncomingMessage): Promise<VerifiedIdentity> {
      const match = BEARER_ID_TOKEN.exec(req.headers.authorization ?? '');
      if (!match) throw apiErrors.authenticationRequired();
      return verifyIdentity(match[1]!);
    }

    /** provider自身のinteraction cookieで元browserを確かめ、URLのuidとresource/scopeの一致も見る。 */
    async function browserInteraction(req: IncomingMessage, res: ServerResponse, uid: string) {
      alive();
      let interaction;
      try {
        interaction = await provider.interactionDetails(req, res);
      } catch {
        alive();
        throw apiErrors.linkUnavailable();
      }
      alive();
      if (interaction.uid !== uid) throw apiErrors.linkUnavailable();
      if (interaction.params.resource !== resource || interaction.params.scope !== STTD_SCOPE) throw apiErrors.linkUnavailable();
      return interaction;
    }

    async function clientLabel(clientId: unknown): Promise<string> {
      const client = await guarded(() => provider.Client.find(String(clientId)));
      if (!client) throw apiErrors.linkUnavailable();
      return client.clientName ?? client.clientId;
    }

    /**
     * 画面の表示言語（en/ja）。`?lang=`の明示選択 → 表示専用cookie `sttd_language` → Accept-Languageの順で、認証・認可・owner・CSRFの判断には
     * 使わない。明示選択があればHTML応答にだけsession cookie（Path=/・SameSite=Lax・Secure。Max-Age/Expiresなし）を付ける。
     */
    function pageLanguage(req: IncomingMessage, url: URL): { readonly language: Language; readonly headers: Record<string, string> } {
      const query = url.searchParams.get(LANGUAGE_QUERY);
      const language = selectLanguage({ query, cookie: req.headers.cookie, acceptLanguage: req.headers['accept-language'] });
      return { language, headers: isLanguage(query) ? { 'Set-Cookie': languageCookie(language, true) } : {} };
    }

    async function showInteraction(req: IncomingMessage, res: ServerResponse, uid: string, url: URL): Promise<void> {
      await guarded(() => assertNoBody(req));
      const interaction = await browserInteraction(req, res, uid);
      const label = await clientLabel(interaction.params.client_id);
      const opened = await guarded(() => storage.openInteraction(uid));
      if (opened === undefined) throw apiErrors.linkUnavailable();
      const { language, headers } = pageLanguage(req, url);
      const html =
        opened.ownerId === null
          ? renderInteractionLogin(web, uid, label, opened.csrf, language)
          : renderInteractionConsent(web, uid, label, opened.csrf, language);
      send(res, 200, 'text/html; charset=utf-8', html, { ...pageSecurityHeaders(web), ...headers });
    }

    async function loginInteraction(req: IncomingMessage, res: ServerResponse, uid: string): Promise<void> {
      requireSameOrigin(req);
      const body = await guarded(() => readJson(req, loginBody));
      await browserInteraction(req, res, uid);
      // CSRFが現行でない要求では、本人確認・owner作成へ進まない。
      if (!(await guarded(() => storage.interactionAccepts(uid, body.csrf)))) throw apiErrors.linkUnavailable();
      const verified = await verifyIdentity(body.idToken);
      // 利用許可（運営者の明示登録）がactiveの本人だけownerを解決・作成する。未許可は専用の403 access_denied（ownerを作らない）。
      const admission = await guarded(() => storage.resolveOwner(verified));
      if (admission.kind === 'denied') throw accessDenied();
      if (admission.kind !== 'admitted') throw apiErrors.forbidden();
      const { ownerId } = admission;
      const bound = await guarded(() => storage.bindInteraction(uid, body.csrf, ownerId, verified.authTimeSec, admission.accessGeneration));
      if (bound === 'other_owner') throw new ApiError(409, 'owner_mismatch');
      if (bound === 'denied') throw accessDenied();
      if (bound !== 'ok') throw apiErrors.linkUnavailable();
      log({ event: 'interaction.login' });
      alive();
      res.writeHead(204, BASE_HEADERS);
      res.end();
    }

    /** 同意の利用許可の拒否: 固定の日英案内（403。owner・UID・Grant・世代を出さない）。 */
    function sendAccessDenied(req: IncomingMessage, res: ServerResponse, uid: string, url: URL): void {
      log({ event: 'interaction.access_denied' });
      const { language, headers } = pageLanguage(req, url);
      send(res, 403, 'text/html; charset=utf-8', renderInteractionAccessDenied(web, uid, language), { ...pageSecurityHeaders(web), ...headers });
    }

    async function consentInteraction(req: IncomingMessage, res: ServerResponse, uid: string, url: URL): Promise<void> {
      requireSameOrigin(req);
      const form = await guarded(() => readForm(req, ['csrf']));
      const interaction = await browserInteraction(req, res, uid);
      const consent = await guarded(() => storage.consumeInteraction(uid, form.get('csrf') ?? ''));
      if (consent === undefined) throw apiErrors.linkUnavailable();
      if (consent === 'denied') return sendAccessDenied(req, res, uid, url);
      if (!(await guarded(() => storage.isOwnerActive(consent.ownerId)))) throw apiErrors.linkUnavailable();
      // 同意は同ownerと元interactionへ単回で束縛し、Grantのresource scopeとgrantMetaを保存する。grantMetaは同じtransactionで
      // 利用許可の世代を再確認し、停止を跨いだら作らない（metadataの無いGrantは新規利用に使えず、成功応答もしない）。
      const grant = new provider.Grant({ accountId: consent.ownerId, clientId: String(interaction.params.client_id) });
      grant.addResourceScope(resource, STTD_SCOPE);
      const grantId = await guarded(() => grant.save());
      if ((await guarded(() => storage.putGrantMeta(grantId, consent))) !== 'created') return sendAccessDenied(req, res, uid, url);
      log({ event: 'interaction.consented' });
      alive();
      await provider.interactionFinished(
        req,
        res,
        { login: { accountId: consent.ownerId, remember: false }, consent: { grantId } },
        { mergeWithLastSubmission: false },
      );
    }

    async function denyInteraction(req: IncomingMessage, res: ServerResponse, uid: string): Promise<void> {
      requireSameOrigin(req);
      const form = await guarded(() => readForm(req, ['csrf']));
      await browserInteraction(req, res, uid);
      if (!(await guarded(() => storage.closeInteraction(uid, form.get('csrf') ?? '')))) throw apiErrors.linkUnavailable();
      log({ event: 'interaction.denied' });
      alive();
      await provider.interactionFinished(req, res, { error: 'access_denied' }, { mergeWithLastSubmission: false });
    }

    async function webState(ownerInput: string | undefined): Promise<ConnectionState> {
      if (ownerInput === undefined) return 'unlinked';
      const ownerId: string = ownerInput;
      return guarded(() => connections.stateFor(ownerId));
    }

    async function route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<string> {
      const path = url.pathname;
      const method = req.method ?? '';
      const only = (allowed: string) => {
        if (method !== allowed) throw apiErrors.methodNotAllowed();
      };

      // 送信画面（/console・/console/app.js・/console/app.css）はローカル配信helper（src/console/local-server.ts）が出す。このserverは配信せず、
      // 旧接続画面（/connect・/connect/app.js）と同様に下の未知pathと同じ固定404へ落ちる（redirect・互換page無し）。HTMLはinteractionだけ。
      switch (path) {
        case INTERACTION_SCRIPT_PATH:
          only('GET');
          await guarded(() => assertNoBody(req));
          send(res, 200, 'text/javascript; charset=utf-8', INTERACTION_SCRIPT);
          return 'interaction.script';
        case '/v1/web/connection': {
          only('GET');
          const verified = await bearerIdentity(req);
          await guarded(() => assertNoBody(req));
          const ownerId = await guarded(() => storage.findOwner(verified));
          const state = await webState(ownerId);
          // 利用許可は購読stateと分けて返す（読めなければunavailable。stateの照会はこれに依存しない）。UID・世代・一覧は返さない。
          const access = await guarded(() => storage.accessDisplay(verified));
          sendJson(res, 200, { state, access });
          return 'web.connection';
        }
        case '/v1/web/disconnect': {
          only('POST');
          if (req.headers.origin !== undefined) requireSameOrigin(req);
          const verified = await bearerIdentity(req);
          await guarded(() => assertNoBody(req));
          const ownerId = await guarded(() => storage.findOwner(verified));
          if (ownerId !== undefined) await guarded(() => storage.revokeOwner(ownerId));
          log({ event: 'web.disconnected' });
          sendJson(res, 200, { state: await webState(ownerId) });
          return 'web.disconnect';
        }
      }

      const interactionMatch = /^\/interaction\/([A-Za-z0-9_-]{1,128})(?:\/(login|consent|deny))?$/.exec(path);
      if (interactionMatch) {
        const uid = interactionMatch[1]!;
        switch (interactionMatch[2]) {
          case undefined:
            only('GET');
            await showInteraction(req, res, uid, url);
            return 'interaction.show';
          case 'login':
            only('POST');
            await loginInteraction(req, res, uid);
            return 'interaction.login';
          case 'consent':
            only('POST');
            await consentInteraction(req, res, uid, url);
            return 'interaction.consent';
          default:
            only('POST');
            await denyInteraction(req, res, uid);
            return 'interaction.deny';
        }
      }

      if (path === MCP_PATH) {
        if (req.headers.origin !== undefined) requireSameOrigin(req);
        alive();
        await mcp.handle(req, res);
        return 'mcp';
      }
      if (path === mcp.metadataPath) {
        only('GET');
        await guarded(() => assertNoBody(req));
        sendJson(res, 200, mcp.protectedResourceMetadata);
        return 'mcp.metadata';
      }
      if (path.startsWith('/oauth/') || path.startsWith('/.well-known/')) {
        alive();
        await oauthCallback(req, res);
        return 'oauth';
      }
      throw apiErrors.notFound();
    }

    // ---------- HTTP（要求ごとの元20秒のoperationとslot） ----------

    const active = new Set<AbortController>();
    let closing = false;

    /** 固定の非成功を書く（既に書き始めていれば接続を終える）。 */
    function refuse(res: ServerResponse, error: ApiError): void {
      if (res.writableEnded) return;
      if (res.headersSent || res.destroyed) {
        res.destroy();
        return;
      }
      const payload = Buffer.from(JSON.stringify({ error: { code: error.code, retryable: error.retryable } }), 'utf8');
      res.writeHead(error.status, { ...BASE_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': payload.length, Connection: 'close' });
      res.end(payload);
    }

    /** 非成功の分類（元の例外の内容は使わない）。期限・中止・閉鎖・購読viewの一時障害は503、未知は固定500。 */
    function failureOf(error: unknown): { readonly error: ApiError; readonly category: string } {
      if (error instanceof ApiError) return { error, category: 'api' };
      if (error instanceof RequestAuthContextError) return { error: apiErrors.temporarilyUnavailable(), category: 'context' };
      if (error instanceof AccessUnavailableError) return { error: apiErrors.temporarilyUnavailable(), category: 'access' };
      if (error instanceof KmsConnectionSubscriptionViewError && error.code !== 'invalid_input') {
        return { error: apiErrors.temporarilyUnavailable(), category: 'subscription_view' };
      }
      return { error: new ApiError(500, 'internal_error'), category: 'unexpected' };
    }

    async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
      if (closing) {
        refuse(res, apiErrors.temporarilyUnavailable());
        log({ event: 'http.request', route: 'closing', status: res.statusCode });
        return;
      }
      const receivedAt = safeNow();
      if (receivedAt === null) {
        refuse(res, apiErrors.temporarilyUnavailable());
        log({ event: 'http.request', route: 'clock', status: res.statusCode });
        return;
      }
      // 元20秒のoperationは受付時に1回だけ作る。切断・未完了の応答close・server closeで中止する（正常に書き終えた後のcloseは中止にしない）。
      const controller = new AbortController();
      const operation: McpRequestOperation = Object.freeze({ deadlineAt: receivedAt + REQUEST_BUDGET_MS, signal: controller.signal });
      active.add(controller);
      const abort = (): void => controller.abort();
      const onResponseClose = (): void => {
        if (!res.writableFinished) controller.abort();
      };
      req.once('aborted', abort);
      res.once('close', onResponseClose);
      let label = 'rejected';
      const seen = { mcpRoute: false };
      try {
        let outcome: RouteOutcome | typeof STOPPED;
        try {
          outcome = await context.run(operation, async (): Promise<RouteOutcome> => {
            try {
              if (req.headers.host !== issuerUrl.host) throw apiErrors.invalidRequest();
              const url = new URL(req.url ?? '/', issuerUrl);
              seen.mcpRoute = url.pathname === MCP_PATH;
              return { ok: true, label: await route(req, res, url) };
            } catch (error) {
              return { ok: false, error };
            }
          });
        } catch {
          outcome = STOPPED;
        }
        if (outcome === STOPPED) {
          // 期限・中止・閉鎖でslotが打ち切られた。正常に書き終えた応答はそのまま、MCPは入口の終了処理に任せて接続だけ終える。
          if (!res.writableEnded) {
            if (seen.mcpRoute) res.destroy();
            else refuse(res, apiErrors.temporarilyUnavailable());
          }
          log({ event: 'http.request', route: 'stopped', status: res.statusCode });
          return;
        }
        if (outcome.ok) {
          label = outcome.label;
        } else {
          const failure = failureOf(outcome.error);
          log({ event: 'http.failure', category: failure.category });
          refuse(res, failure.error);
        }
        log({ event: 'http.request', route: label, status: res.statusCode });
      } finally {
        req.off('aborted', abort);
        res.off('close', onResponseClose);
        active.delete(controller);
      }
    }

    // ---------- listen（全組立ての後、startup slotの外。同じ元期限まで） ----------

    const server = createServer();
    owned.server = server;
    // 待受の失敗・後着のerrorを未処理にしない固定のlistener（serverの寿命の間ずっと持つ。元のerrorは記録しない）。
    server.on('error', () => log({ event: 'http.server_error' }));
    server.on('request', (req: IncomingMessage, res: ServerResponse) => {
      // route/Provider・要求slotより前にHost・request-target・Forwardedを処理する。不成立は固定400で、DB・本人確認・egress・KMS・
      // Providerへの新しい呼出し0。
      let admitted = false;
      try {
        admitted = admitRequest(req, authority);
      } catch {
        admitted = false;
      }
      if (!admitted) {
        refuse(res, apiErrors.invalidRequest());
        log({ event: 'http.request', route: 'rejected', status: res.statusCode });
        return;
      }
      void serve(req, res).catch(() => {
        if (!res.writableEnded) res.destroy();
      });
    });
    startLive();
    await new Promise<void>((resolve, reject) => {
      const signal = startController.signal;
      let done = false;
      const finish = (outcome: () => void): void => {
        if (done) return;
        done = true;
        signal.removeEventListener('abort', onAbort);
        server.off('error', onError);
        outcome();
      };
      const onAbort = (): void => finish(() => reject(new KmsConnectServerStartupError()));
      const onError = (): void => finish(() => reject(new KmsConnectServerStartupError()));
      signal.addEventListener('abort', onAbort, { once: true });
      server.once('error', onError);
      server.listen(config.bindPort, BIND_HOST, () => {
        // 採用しなかった（中止・失敗の後に開いた）待受は、すぐ閉じる。
        if (done) {
          server.close();
          return;
        }
        finish(resolve);
      });
    });
    // listenの成功を採用する直前にも、同じ元期限・時計・中止を検査する（不成立ならcatchで所有serverを閉じる）。
    startLive();
    log({ event: 'kms_connect.started' });

    let closePromise: Promise<void> | undefined;
    const close = (): Promise<void> => {
      if (closePromise !== undefined) return closePromise;
      // 同期に閉鎖を確定して新要求を拒否し、進行中のHTTP・登録・context・viewを中止してから、MCP入口・server・socketを閉じる。
      closing = true;
      for (const controller of active) controller.abort();
      closePromise = shutdown(owned, CLOSE_BUDGET_MS).then((ok) => {
        log({ event: 'kms_connect.closed', category: ok ? 'ok' : 'failed' });
        if (!ok) throw new KmsConnectServerCloseError();
      });
      return closePromise;
    };

    return Object.freeze({ issuer, resource, close });
  } catch {
    // 起動途中の失敗: 所有のcontext・runtime・view・MCP入口・serverだけを片付ける（借用資源は閉じない）。元の例外・causeは運ばない。
    startController.abort();
    await shutdown(owned, CLOSE_BUDGET_MS);
    if (owned.keys !== undefined) {
      for (const key of owned.keys.cookieKeys) key.fill(0);
      owned.keys.identifierKey.fill(0);
    }
    log({ event: 'kms_connect.start_failed' });
    throw new KmsConnectServerStartupError();
  } finally {
    clearTimeout(watchdog);
    // 成功・失敗とも親のlistenerを外す（成功後の要求は要求固有のoperationだけを使い、起動親の期限・中断で止めない）。
    parent?.signal.removeEventListener('abort', onParentAbort);
  }
}
