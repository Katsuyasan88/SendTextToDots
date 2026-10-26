// 要求内MCP入口の購読port（RequestScopedSubscriptionPort）を、署名付きchallenge・callback URL/secretの
// KMS封緘・原子的な最終保存（createKmsSubscriptionRegistrationStore）へ接合するruntime（connect/kms-server.tsが組み立てる）。
// factoryは同期・I/Oなし（通信・DB初期化・KMS呼出し0）。
// 1回だけ捕捉した同じclock・同じKMS購読policy（t268）・同じtransportで、登録storeとcallback codecを内部で作る（任意のstore・
// validator・Grant proofの注入口は持たない）。db・connect・hasher・clock・verificationSender・KMS transportは借用で、close・terminate・
// disposeしない。各要求は元deadlineとservice開始+20000msの短い方を一度だけ決め、親signalとruntime.disposeへ結んだ要求専用の子
// operationをprepare/activate/cancelへ同じobjectで渡す（工程ごとに期限を取り直さない）。challengeは1回だけ（呼出しごとの10秒）、
// URL/secretの封緘は各1回（各5秒）、確認後のactivateは1回。最終保存の失敗・競合で自動の再challenge・prepareの取り直し・再送をしない。
// 各await後・次のI/O前・正常な公開の直前にsignal→時計→signalで検査し、遅い成功・失敗を採用しない。既に始めたSDK commit・HTTP・
// 借用senderの物理的な停止、JS文字列・署名library・OSの全RAMの消去は約束しない。URL・secret・challenge・本文・元例外をDB・log・errorへ出さない。

import { types } from 'node:util';

import type { Firestore } from '@google-cloud/firestore';

import { parseEgressUrl } from '../egress/safe-egress.js';
import type { McpRequestOperation, RequestScopedSubscriptionPort } from '../mcp/request-operation.js';
import type { Clock } from '../policy.js';
import {
  createKmsSealingCodec,
  type KmsCallOptions,
  type KmsDecryptRequest,
  type KmsDecryptResponse,
  type KmsEncryptRequest,
  type KmsEncryptResponse,
  type KmsSealingBinding,
  type KmsSealingCodec,
  type KmsSealingConfig,
} from '../protection/kms-sealing.js';
import { hashesEqual, newOpaqueValue, type SecretHasher } from '../secrets.js';
import { isUuid } from '../storage/firestore/checks.js';
import { createKmsSubscriptionPolicy, isKmsGrantId, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import {
  createKmsSubscriptionRegistrationStore,
  KmsSubscriptionRegistrationError,
  MAX_REGISTRATION_TTL_MS,
  type KmsSubscriptionChallengePlan,
  type KmsSubscriptionRegistrationConnect,
  type KmsSubscriptionRegistrationStore,
} from '../storage/firestore/kms-subscription-registration-store.js';
import { EVENT_NAME, type CallbackEndpointReason } from './contract.js';
import { isValidSecret, signBody } from './signing.js';
import {
  SubscribeError,
  VerificationSendError,
  type SubscribeFailure,
  type SubscribeOutcome,
  type SubscriptionAuth,
  type VerificationFailure,
  type VerificationRequest,
  type VerificationSender,
} from './subscriptions.js';

/** 要求全体の上限（元期限とservice開始+この値の短い方）。延長しない。 */
const SUBSCRIPTION_REQUEST_BUDGET_MS = 20_000;
/** 署名付きchallenge 1回の上限（子期限との短い方）。 */
const SUBSCRIPTION_CHALLENGE_BUDGET_MS = 10_000;
/** callback URL/secretの封緘 各1回の上限（子期限との短い方）。 */
const SUBSCRIPTION_SEAL_BUDGET_MS = 5_000;
/** callback URLのUTF-8の上限（byte）。 */
const SUBSCRIPTION_URL_MAX_BYTES = 2048;
/** challengeの応答本文のUTF-8の上限（byte）。 */
const CHALLENGE_RESPONSE_MAX_BYTES = 8192;
/** ECMAScriptのDateで表せる最大のepochミリ秒（ISO文字列の表現域）。 */
const MAX_ISO_TIME_MS = 8_640_000_000_000_000;

const OPTION_KEYS = ['db', 'connect', 'connectNamespace', 'resource', 'kms', 'hasher', 'clock', 'verificationSender'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const ID_PURPOSE = 'subscription.id';
const SECRET_PURPOSE = 'subscription.secret';
const HASH = /^[0-9a-f]{64}$/;
const SEND_FAILURES: ReadonlySet<string> = new Set<VerificationFailure>(['connection_refused', 'timeout', 'tls_error', 'challenge_failed']);

/** factoryの入力の不正。固定のcode/messageだけで、渡された値・元の例外を持たない。 */
export class KmsSubscriptionRuntimeConfigError extends Error {
  override readonly name = 'KmsSubscriptionRuntimeConfigError';
  readonly code = 'subscription_runtime_config_invalid';
  constructor() {
    super('subscription_runtime_config_invalid');
  }
}

export type KmsSubscriptionRuntimeErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted' | 'closed';

const ERROR_MESSAGES: Readonly<Record<KmsSubscriptionRuntimeErrorCode, string>> = {
  invalid_input: 'kms subscription runtime: invalid input',
  unavailable: 'kms subscription runtime: unavailable',
  timed_out: 'kms subscription runtime: timed out',
  aborted: 'kms subscription runtime: aborted',
  closed: 'kms subscription runtime: closed',
};

/** 既存SubscribeErrorへ写さない内部の非成功（MCP入口は固定InternalErrorにする）。cause・元の値を持たない。 */
export class KmsSubscriptionRuntimeError extends Error {
  override readonly name = 'KmsSubscriptionRuntimeError';
  readonly code: KmsSubscriptionRuntimeErrorCode;
  constructor(code: KmsSubscriptionRuntimeErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

export interface KmsSubscriptionRuntimeOptions {
  /** 借用するFirestore instance（terminateしない）。登録storeへそのまま渡す。 */
  readonly db: Firestore;
  /** 接続保存のうち同期の参照・判定4つ（prototypeのmethodを元instanceへ束縛して1回捕捉する）。 */
  readonly connect: KmsSubscriptionRegistrationConnect;
  /** 接続保存の`t256_<小文字UUID>`。 */
  readonly connectNamespace: string;
  /** 固定MCP audience（Grant.resourcesのkey）。HTTPS URL、local-testだけloopbackのHTTPも可。 */
  readonly resource: string;
  /** codec設定からclockを除いたもの。namespaceはKMS購読の`t268_<小文字UUID>`。transportは封緘（encrypt）とGrantの開封（decrypt）。 */
  readonly kms: Omit<KmsSealingConfig, 'clock'>;
  /** 接続側と同じ識別子HMAC。 */
  readonly hasher: SecretHasher;
  readonly clock: Clock;
  /** 既存のcallback検証の送出境界（借用）。 */
  readonly verificationSender: VerificationSender;
}

export interface KmsSubscriptionRuntime {
  /** RequestScopedSubscriptionPortと同じ形（凍結）。 */
  readonly service: RequestScopedSubscriptionPort;
  /** 同期・冪等。先に閉鎖して進行中の要求を中止し、以後の要求をDB/KMS/challenge 0の固定closedにする。借用資源は閉じない。 */
  dispose(): void;
}

function configFail(): never {
  throw new KmsSubscriptionRuntimeConfigError();
}

function runtimeError(code: KmsSubscriptionRuntimeErrorCode): KmsSubscriptionRuntimeError {
  return new KmsSubscriptionRuntimeError(code);
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/**
 * 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前を拒否、getterを呼ばない）。
 * optionalの名前はundefinedの値も許し、無いものとして扱う。不正はonInvalidの例外。
 */
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

/** 数値の配列をdescriptorで写す（getter・Proxy・穴を拒否）。値の検査はpolicyで行う。 */
function arrayCopy(value: unknown): unknown[] {
  if (!isObject(value) || !Array.isArray(value)) configFail();
  const length = (Object.getOwnPropertyDescriptor(value, 'length') as PropertyDescriptor).value as number;
  if (Reflect.ownKeys(value).length !== length + 1) configFail();
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) configFail();
    out.push(descriptor.value);
  }
  return out;
}

/** 不対surrogateを含まない（正しいUTF-8へ変換できる）文字列か。 */
function isWellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** callback URL: 正しいUTF-8・1〜2048byte・既存parseEgressUrlの純粋な検査に合格（DNS・IP・TLSは送出側）。元の文字列をidentityに使う。 */
function isAcceptableUrl(url: string): boolean {
  if (!isWellFormed(url)) return false;
  const bytes = Buffer.byteLength(url, 'utf8');
  if (bytes < 1 || bytes > SUBSCRIPTION_URL_MAX_BYTES) return false;
  try {
    parseEgressUrl(url);
    return true;
  } catch {
    return false;
  }
}

function invalidRequest(): SubscribeError {
  return new SubscribeError({ kind: 'invalid_request' });
}

interface CapturedInput {
  readonly name: string;
  readonly url: string;
  readonly secret: string;
  readonly ttlMs: number | null;
}

/** subscribeの入力をown dataから1回写す。形・URL・secret・TTLの不正はinvalid_request、未知のeventはunknown_event、非nullのcursorはcursor_unsupported。 */
function copySubscribeInput(value: unknown): CapturedInput {
  const fields = dataFields(value, ['name', 'url', 'secret'], ['ttlMs', 'cursor'], invalidRequest);
  const name = fields.get('name');
  const url = fields.get('url');
  const secret = fields.get('secret');
  const ttlInput = fields.has('ttlMs') ? fields.get('ttlMs') : undefined;
  const cursor = fields.has('cursor') ? fields.get('cursor') : undefined;
  if (typeof name !== 'string' || typeof url !== 'string' || typeof secret !== 'string') throw invalidRequest();
  if (cursor !== undefined && cursor !== null && typeof cursor !== 'string') throw invalidRequest();
  let ttlMs: number | null;
  if (ttlInput === undefined) ttlMs = MAX_REGISTRATION_TTL_MS;
  else if (ttlInput === null) ttlMs = null;
  else if (typeof ttlInput === 'number' && Number.isSafeInteger(ttlInput) && ttlInput > 0) ttlMs = Math.min(ttlInput, MAX_REGISTRATION_TTL_MS);
  else throw invalidRequest();
  if (!isAcceptableUrl(url) || !isValidSecret(secret)) throw invalidRequest();
  if (name !== EVENT_NAME) throw new SubscribeError({ kind: 'unknown_event' });
  if (typeof cursor === 'string') throw new SubscribeError({ kind: 'cursor_unsupported' });
  return Object.freeze({ name, url, secret, ttlMs });
}

/** unsubscribeのidentityはexact {name, url}だけ（secret・ttl・cursorを受け付けない）。 */
function copyIdentity(value: unknown): { readonly name: string; readonly url: string } {
  const fields = dataFields(value, ['name', 'url'], [], invalidRequest);
  const name = fields.get('name');
  const url = fields.get('url');
  if (typeof name !== 'string' || typeof url !== 'string' || !isAcceptableUrl(url)) throw invalidRequest();
  if (name !== EVENT_NAME) throw new SubscribeError({ kind: 'unknown_event' });
  return Object.freeze({ name, url });
}

/** 信頼済みcontextのowner/Grant（登録storeと同じ形式）。不正は内部のinvalid_input。 */
function copyAuth(value: unknown): SubscriptionAuth {
  const fields = dataFields(value, ['ownerId', 'grantId'], [], () => runtimeError('invalid_input'));
  const ownerId = fields.get('ownerId');
  const grantId = fields.get('grantId');
  if (!isUuid(ownerId) || !isKmsGrantId(grantId)) throw runtimeError('invalid_input');
  return Object.freeze({ ownerId, grantId });
}

/** 要求operation: exact {deadlineAt, signal}、signalは必須の本物のAbortSignal。 */
function copyOperation(value: unknown): McpRequestOperation {
  const fields = dataFields(value, ['deadlineAt', 'signal'], [], () => runtimeError('invalid_input'));
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) throw runtimeError('invalid_input');
  if (!isObject(signal) || !(signal instanceof AbortSignal)) throw runtimeError('invalid_input');
  return Object.freeze({ deadlineAt, signal });
}

/** 期限つきの待機（呼出しごとのdeadline）が先に来たことを表す内部の印。外へは出さない。 */
const CALL_EXPIRED: unique symbol = Symbol('call expired');

/** 1つの要求の子operation。要求ごとに作り、他の要求と共有しない。 */
interface RequestScope {
  /** store・codecへ渡す同じfrozen object（{deadlineAt, signal: 子signal}）。 */
  readonly operation: Readonly<{ deadlineAt: number; signal: AbortSignal }>;
  readonly deadlineAt: number;
  readonly parent: AbortSignal;
  readonly controller: AbortController;
  /** owned timer・親listener・runtime listenerを解除し、子をabortする（冪等）。 */
  readonly release: () => void;
}

/**
 * KMS購読の登録runtimeを組み立てる（同期・I/Oなし）。全ての検査・捕捉はここで1回だけ行い、以後は入力objectを読み直さない。
 * 不正はKmsSubscriptionRuntimeConfigError。戻り値は凍結した{service, dispose}。markerは既存の正しいものが前提で、ここでは作らない。
 */
export function createKmsSubscriptionRegistrationRuntime(options: KmsSubscriptionRuntimeOptions): KmsSubscriptionRuntime {
  const fields = dataFields(options, OPTION_KEYS, [], () => new KmsSubscriptionRuntimeConfigError());

  // dbは借用。SDKのmethodの存在だけをdescriptorで確かめる（呼ばない・接続しない）。
  const db = fields.get('db');
  methodOf(db, 'collection');
  methodOf(db, 'runTransaction');

  const connectTarget = fields.get('connect');
  const ownerDocRef = methodOf(connectTarget, 'ownerDocRef');
  const grantDocRef = methodOf(connectTarget, 'grantDocRef');
  const ownerDocActive = methodOf(connectTarget, 'ownerDocActive');
  const grantDocLive = methodOf(connectTarget, 'grantDocLive');
  const accessDocRefForOwner = methodOf(connectTarget, 'accessDocRefForOwner');
  const grantMetaDocRef = methodOf(connectTarget, 'grantMetaDocRef');
  const grantUseDecision = methodOf(connectTarget, 'grantUseDecision');
  const connect = Object.freeze({
    ownerDocRef: (ownerId: string) => ownerDocRef(ownerId),
    grantDocRef: (grantId: string) => grantDocRef(grantId),
    ownerDocActive: (data: Record<string, unknown> | undefined, at: number) => ownerDocActive(data, at) === true,
    grantDocLive: (data: Record<string, unknown> | undefined, ownerId: string, grantId: string, at: number) => grantDocLive(data, ownerId, grantId, at) === true,
    accessDocRefForOwner: (data: Record<string, unknown> | undefined) => accessDocRefForOwner(data),
    grantMetaDocRef: (grantId: string) => grantMetaDocRef(grantId),
    // 利用許可の判定は既知の3値だけを採用し、他は一時障害へ閉じる。
    grantUseDecision: (access: unknown, meta: unknown, ownerId: string) => {
      const value = grantUseDecision(access, meta, ownerId);
      return value === 'allowed' || value === 'denied' ? value : 'unavailable';
    },
  }) as unknown as KmsSubscriptionRegistrationConnect;

  const hashMethod = methodOf(fields.get('hasher'), 'hash');
  const clockNow = methodOf(fields.get('clock'), 'now');
  const senderInput = fields.get('verificationSender');
  if (typeof senderInput !== 'function' || types.isProxy(senderInput)) configFail();
  const senderFn = senderInput as Function;
  const sender = (request: VerificationRequest, signal: AbortSignal): unknown => Reflect.apply(senderFn, undefined, [request, signal]);

  /** 読めない・有限でない時計はNaN（残りのないものとして扱う）。元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  // 共通の時計を一度だけ捕捉し、storeとcodecへ同じobjectを渡す。
  const clock: Clock = Object.freeze({ now });

  // KMS設定: clockを持たせない。購読のpolicy（t268）は共通の検査・正規化で1回捕捉し、storeとcodecへ同じ値を渡す。
  const kms = dataFields(fields.get('kms'), KMS_KEYS, [], () => new KmsSubscriptionRuntimeConfigError());
  let policy: KmsSubscriptionPolicy;
  try {
    policy = createKmsSubscriptionPolicy({
      namespace: kms.get('namespace'),
      environment: kms.get('environment'),
      projectId: kms.get('projectId'),
      databaseId: kms.get('databaseId'),
      cryptoKey: kms.get('cryptoKey'),
      writeVersion: kms.get('writeVersion'),
      readVersions: arrayCopy(kms.get('readVersions')),
    });
  } catch {
    return configFail();
  }
  const transportTarget = kms.get('transport');
  const encrypt = methodOf(transportTarget, 'encrypt');
  const decrypt = methodOf(transportTarget, 'decrypt');
  const transport = Object.freeze({
    encrypt: (request: KmsEncryptRequest, callOptions: KmsCallOptions) => encrypt(request, callOptions) as PromiseLike<KmsEncryptResponse>,
    decrypt: (request: KmsDecryptRequest, callOptions: KmsCallOptions) => decrypt(request, callOptions) as PromiseLike<KmsDecryptResponse>,
  });
  const kmsConfig = () => ({
    environment: policy.environment,
    projectId: policy.projectId,
    databaseId: policy.databaseId,
    namespace: policy.namespace,
    cryptoKey: policy.cryptoKey,
    writeVersion: policy.writeVersion,
    readVersions: [...policy.readVersions],
    transport,
  });

  let store: KmsSubscriptionRegistrationStore;
  let codec: KmsSealingCodec;
  try {
    store = createKmsSubscriptionRegistrationStore({
      db: db as Firestore,
      connect,
      connectNamespace: fields.get('connectNamespace') as string,
      resource: fields.get('resource') as string,
      kms: kmsConfig(),
      clock,
    });
    codec = createKmsSealingCodec({ ...kmsConfig(), clock });
  } catch {
    return configFail();
  }
  const storePrepare = store.prepare;
  const storeActivate = store.activate;
  const storeCancel = store.cancel;
  const seal = codec.seal;

  const lifetime = new AbortController();
  let closed = false;
  /** このruntimeが作ったSubscribeErrorだけをそのまま外へ出す（借用portの例外を素通ししない）。 */
  const ours = new WeakSet<object>();
  const subscribeError = (failure: SubscribeFailure): SubscribeError => {
    const error = new SubscribeError(failure);
    ours.add(error);
    return error;
  };

  /** 識別子HMAC。64桁小文字hex以外・例外は内部unavailable（元の例外を出さない）。 */
  function hashOf(purpose: string, value: string): string {
    let result: unknown;
    try {
      result = hashMethod(purpose, value);
    } catch {
      throw runtimeError('unavailable');
    }
    if (typeof result !== 'string' || !HASH.test(result)) throw runtimeError('unavailable');
    return result;
  }

  function subscriptionId(ownerId: string, name: string, url: string): string {
    return `sub_${hashOf(ID_PURPOSE, JSON.stringify([ownerId, name, '{}', url]))}`;
  }

  /** 中止・閉鎖の分類（時計を読まない）。閉鎖→親の中止→子だけの中止（子期限のtimer）＝timed_outの順。 */
  function stopReason(scope: RequestScope): KmsSubscriptionRuntimeError | null {
    if (closed) return runtimeError('closed');
    if (scope.parent.aborted) return runtimeError('aborted');
    if (scope.controller.signal.aborted) return runtimeError('timed_out');
    return null;
  }

  /** まだ進めてよいかを、signal→時計→signalの順に見て、その時刻を返す。 */
  function live(scope: RequestScope): number {
    const before = stopReason(scope);
    if (before !== null) throw before;
    const at = now();
    const after = stopReason(scope);
    if (after !== null) throw after;
    if (!(at < scope.deadlineAt)) throw runtimeError('timed_out');
    return at;
  }

  /** 子期限・中止の検査に加え、呼出しごとのdeadline（challenge 10秒・seal 5秒）も見る。超過はCALL_EXPIRED。 */
  function liveCall(scope: RequestScope, callDeadline: number): number {
    const at = live(scope);
    if (!(at < callDeadline)) throw CALL_EXPIRED;
    return at;
  }

  /**
   * 新しい要求の子operationを作る（最初のawaitの前）。閉鎖・operation・中止・時計・元期限の順に検査し、元期限とservice開始+20000msの
   * 短い方を一度だけ決める。子controllerを親signal・runtime.disposeへ結び、子期限でもabortするowned timerを置く。
   */
  function begin(operationInput: unknown): RequestScope {
    if (closed) throw runtimeError('closed');
    const operation = copyOperation(operationInput);
    const parent = operation.signal;
    if (parent.aborted) throw runtimeError('aborted');
    const start = now();
    if (closed) throw runtimeError('closed');
    if (parent.aborted) throw runtimeError('aborted');
    if (!Number.isFinite(start)) throw runtimeError('timed_out');
    // 時計は有限の安全整数のepochミリ秒（ISOの表現域内）。そうでなければ保存へ進まない固定の非成功。
    if (!Number.isSafeInteger(start) || start < 0 || start > MAX_ISO_TIME_MS) throw runtimeError('unavailable');
    if (!(start < operation.deadlineAt)) throw runtimeError('timed_out');
    const deadlineAt = Math.min(operation.deadlineAt, start + SUBSCRIPTION_REQUEST_BUDGET_MS);
    const controller = new AbortController();
    const abortChild = () => controller.abort();
    parent.addEventListener('abort', abortChild, { once: true });
    lifetime.signal.addEventListener('abort', abortChild, { once: true });
    const timer = setTimeout(abortChild, Math.max(1, deadlineAt - start));
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      clearTimeout(timer);
      parent.removeEventListener('abort', abortChild);
      lifetime.signal.removeEventListener('abort', abortChild);
      controller.abort();
    };
    return Object.freeze({
      operation: Object.freeze({ deadlineAt, signal: controller.signal }),
      deadlineAt,
      parent,
      controller,
      release,
    });
  }

  /**
   * 1つのawaitを子期限・中止まで（callDeadlineがあればその時刻まで）で打ち切る。打切りの後に来た成功・失敗は採用せず、rejectは握りつぶす。
   * 成功は呼出し側が直後にlive/liveCallで再検査する。callDeadlineの到達はonExpireを呼んでからCALL_EXPIREDで返す。
   */
  function bounded<T>(scope: RequestScope, promise: Promise<T>, callDeadline?: number, onExpire?: () => void): Promise<T> {
    promise.catch(() => {});
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const signal = scope.controller.signal;
      const finish = (outcome: () => void) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        signal.removeEventListener('abort', onAbort);
        outcome();
      };
      const onAbort = () => finish(() => reject(stopReason(scope) ?? runtimeError('timed_out')));
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
        return;
      }
      if (callDeadline !== undefined) {
        const observed = now();
        // signal→時計→signal。時計の観測中に同期の中止・閉鎖で既に終わった待機へは、timerも後続の資源も作らない。
        if (settled) return;
        if (signal.aborted || stopReason(scope) !== null) {
          onAbort();
          return;
        }
        const remaining = callDeadline - observed;
        const expire = () =>
          finish(() => {
            onExpire?.();
            reject(CALL_EXPIRED);
          });
        if (!(remaining > 0)) {
          expire();
          return;
        }
        timer = setTimeout(expire, Math.ceil(remaining));
      }
      promise.then(
        (value) => finish(() => resolve(value)),
        (error: unknown) => finish(() => reject(error)),
      );
    });
  }

  /** 非成功の正規化。期限・中止・閉鎖を最優先にし、storeのgrant_inactive/conflictは既存SubscribeErrorへ、他は固定の内部error。 */
  function normalize(scope: RequestScope | null, error: unknown): Error {
    if (scope !== null) {
      try {
        live(scope);
      } catch (stop) {
        if (stop instanceof KmsSubscriptionRuntimeError) return runtimeError(stop.code);
      }
    }
    if (error instanceof SubscribeError && ours.has(error)) return error;
    if (error instanceof KmsSubscriptionRuntimeError) return runtimeError(error.code);
    if (error instanceof KmsSubscriptionRegistrationError) {
      switch (error.code) {
        case 'grant_inactive':
          return subscribeError({ kind: 'grant_inactive' });
        case 'conflict':
          return subscribeError({ kind: 'conflict' });
        case 'timed_out':
          return runtimeError('timed_out');
        case 'aborted':
          return runtimeError('aborted');
        default:
          return runtimeError('unavailable');
      }
    }
    return runtimeError('unavailable');
  }

  /** 入力の検査で作ったSubscribeErrorを、このruntimeのものとして登録する。 */
  function own<T>(capture: () => T): T {
    try {
      return capture();
    } catch (error) {
      if (error instanceof SubscribeError) ours.add(error);
      throw error;
    }
  }

  /** 保存されたepochミリ秒（またはnull）をrefreshBeforeへ。ISOの表現域外は内部unavailable。 */
  function refreshOf(expiresAt: unknown): string | null {
    if (expiresAt === null) return null;
    if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt < 0 || expiresAt > MAX_ISO_TIME_MS) throw runtimeError('unavailable');
    return new Date(expiresAt).toISOString();
  }

  function callbackFailure(reason: CallbackEndpointReason): SubscribeError {
    return subscribeError({ kind: 'callback_endpoint', reason });
  }

  /** 送出の失敗の分類: VerificationSendErrorの4種だけを許し、他の例外・偽のreasonはchallenge_failed。 */
  function sendFailureOf(error: unknown): CallbackEndpointReason {
    try {
      if (error instanceof VerificationSendError && !types.isProxy(error)) {
        const descriptor = Object.getOwnPropertyDescriptor(error, 'reason');
        if (descriptor !== undefined && 'value' in descriptor && typeof descriptor.value === 'string' && SEND_FAILURES.has(descriptor.value)) {
          return descriptor.value as CallbackEndpointReason;
        }
      }
    } catch {
      // 読めない例外は検証不成立として閉じる
    }
    return 'challenge_failed';
  }

  /** 応答のown dataのstatus（整数100〜599）とbody（string）だけを写す。未知・破損はnull。 */
  function responseOf(value: unknown): { readonly status: number; readonly body: string } | null {
    try {
      if (!isObject(value)) return null;
      const statusDescriptor = Object.getOwnPropertyDescriptor(value, 'status');
      const bodyDescriptor = Object.getOwnPropertyDescriptor(value, 'body');
      if (statusDescriptor === undefined || !('value' in statusDescriptor) || bodyDescriptor === undefined || !('value' in bodyDescriptor)) return null;
      const status: unknown = statusDescriptor.value;
      const body: unknown = bodyDescriptor.value;
      if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599 || typeof body !== 'string') return null;
      return { status, body };
    } catch {
      return null;
    }
  }

  /** 2xxの本文が、8192byte以内の正しいUTF-8のJSON objectで、own dataのchallenge stringが送った値と正確に一致するか。 */
  function echoes(body: string, challenge: string): boolean {
    if (!isWellFormed(body) || Buffer.byteLength(body, 'utf8') > CHALLENGE_RESPONSE_MAX_BYTES) return false;
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return false;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(parsed, 'challenge');
    if (descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'string') return false;
    return hashesEqual(descriptor.value, challenge);
  }

  /**
   * 署名付きchallengeを1回だけ送る。呼出しdeadline=min(子期限, 開始+10000)を一度だけ決め、子へ結んだchallenge signalとtimerで待つ。
   * 子の期限・中止・閉鎖を優先し、challenge自身の10秒到達だけをcallback_endpoint timeoutにする。終了時はchallenge signalをabortし
   * listener・timerを解除する。再送しない。
   */
  async function challengeOnce(scope: RequestScope, id: string, url: string, secret: string): Promise<void> {
    const startedAt = live(scope);
    const callDeadline = Math.min(scope.deadlineAt, startedAt + SUBSCRIPTION_CHALLENGE_BUDGET_MS);
    const challenge = newOpaqueValue();
    const body = JSON.stringify({ type: 'verification', challenge });
    const signed = signBody(`msg_${newOpaqueValue()}`, body, new Date(startedAt), [secret]);
    const headers = Object.freeze({
      'content-type': 'application/json',
      'webhook-id': signed['webhook-id'],
      'webhook-timestamp': signed['webhook-timestamp'],
      'webhook-signature': signed['webhook-signature'],
      'x-mcp-subscription-id': id,
    });
    const request: VerificationRequest = Object.freeze({ url, headers, body });
    const call = new AbortController();
    const stopCall = () => call.abort();
    scope.controller.signal.addEventListener('abort', stopCall, { once: true });
    try {
      if (liveCallOrTimeout(scope, callDeadline)) throw callbackFailure('timeout');
      let sent: Promise<unknown>;
      try {
        sent = Promise.resolve(sender(request, call.signal));
      } catch (error) {
        sent = Promise.reject(error);
      }
      let response: unknown;
      try {
        response = await bounded(scope, sent, callDeadline, stopCall);
      } catch (error) {
        const stop = stopReason(scope);
        if (stop !== null) throw stop;
        if (error === CALL_EXPIRED) {
          // 子の期限（元期限・20秒）が同時に来ていればそちらを優先する。challenge自身の10秒だけならtimeout。
          live(scope);
          throw callbackFailure('timeout');
        }
        throw callbackFailure(sendFailureOf(error));
      }
      if (liveCallOrTimeout(scope, callDeadline)) throw callbackFailure('timeout');
      const captured = responseOf(response);
      if (captured === null) throw callbackFailure('challenge_failed');
      if (captured.status >= 400 && captured.status <= 499) throw callbackFailure('http_4xx');
      if (captured.status >= 500 && captured.status <= 599) throw callbackFailure('http_5xx');
      const ok = captured.status >= 200 && captured.status <= 299 && echoes(captured.body, challenge);
      if (liveCallOrTimeout(scope, callDeadline)) throw callbackFailure('timeout');
      if (!ok) throw callbackFailure('challenge_failed');
    } finally {
      scope.controller.signal.removeEventListener('abort', stopCall);
      call.abort();
    }
  }

  /** liveCallの結果を、呼出しdeadlineの超過だけtrueで返す（子の期限・中止・閉鎖はそのまま投げる）。 */
  function liveCallOrTimeout(scope: RequestScope, callDeadline: number): boolean {
    try {
      liveCall(scope, callDeadline);
      return false;
    } catch (error) {
      if (error === CALL_EXPIRED) return true;
      throw error;
    }
  }

  /**
   * callbackのURLまたはsecretをKMS codecで1回だけ封緘する。呼出しdeadline=min(子期限, 開始+5000)を一度だけ決めてcodecへ渡し、await後・
   * 封緘値の採用直前まで同じdeadlineと子signalを検査する。所有Bufferはfinallyで0にする。遅い成功を使わない。codecの失敗は固定unavailable。
   */
  async function sealOnce(scope: RequestScope, binding: KmsSealingBinding, text: string): Promise<string> {
    const plaintext = Buffer.from(text, 'utf8');
    try {
      const startedAt = live(scope);
      const callDeadline = Math.min(scope.deadlineAt, startedAt + SUBSCRIPTION_SEAL_BUDGET_MS);
      const operation = Object.freeze({ deadlineAt: callDeadline, signal: scope.controller.signal });
      let pending: Promise<string>;
      try {
        pending = Promise.resolve(seal(binding, plaintext, operation));
      } catch {
        pending = Promise.reject(runtimeError('unavailable'));
      }
      let capsule: unknown;
      try {
        capsule = await bounded(scope, pending, callDeadline);
      } catch {
        // 5秒の到達・codecの失敗はどちらも固定unavailable（子の期限・中止・閉鎖が先）。
        throw stopReason(scope) ?? runtimeError('unavailable');
      }
      if (liveCallOrTimeout(scope, callDeadline)) throw runtimeError('unavailable');
      if (typeof capsule !== 'string') throw runtimeError('unavailable');
      return capsule;
    } finally {
      plaintext.fill(0);
    }
  }

  function bindingOf(purpose: 'callback-url' | 'callback-secret', id: string, ownerId: string, secretHash: string | null): KmsSealingBinding {
    return Object.freeze({ purpose, model: 'Subscription', recordId: id, ownerBinding: `id:${ownerId}`, secretHash });
  }

  async function subscribe(authInput: unknown, inputInput: unknown, operationInput: unknown): Promise<SubscribeOutcome> {
    let scope: RequestScope | null = null;
    try {
      // 最初のawaitの前に、閉鎖・中止・時計・期限・入力を捕捉する（後の改変で束縛を変えない）。
      scope = begin(operationInput);
      const auth = copyAuth(authInput);
      const input = own(() => copySubscribeInput(inputInput));
      const startedAt = live(scope);
      if (input.ttlMs !== null && startedAt + input.ttlMs > MAX_ISO_TIME_MS) throw runtimeError('unavailable');
      const id = subscriptionId(auth.ownerId, input.name, input.url);
      const secretHash = hashOf(SECRET_PURPOSE, input.secret);
      live(scope);

      const prepared = await bounded(scope, storePrepare(auth, { id, secretHash, ttlMs: input.ttlMs }, scope.operation));
      live(scope);
      if (prepared.kind === 'extended') {
        const refreshBefore = refreshOf(prepared.expiresAt);
        live(scope);
        return Object.freeze({ id, refreshBefore });
      }
      if (prepared.kind === 'pending') throw subscribeError({ kind: 'destination_change_pending' });
      const plan: KmsSubscriptionChallengePlan = prepared.plan;

      await challengeOnce(scope, id, input.url, input.secret);
      live(scope);
      const sealedUrl = await sealOnce(scope, bindingOf('callback-url', id, auth.ownerId, null), input.url);
      live(scope);
      const sealedSecret = await sealOnce(scope, bindingOf('callback-secret', id, auth.ownerId, secretHash), input.secret);
      live(scope);

      // 最終のscope/owner/Grant/版/世代の認可は登録storeを正とする（challengeの成功を保存の成功へ読み替えない）。1回だけ。
      const activated = await bounded(scope, storeActivate(plan, { sealedUrl, sealedSecret }, scope.operation));
      live(scope);
      const refreshBefore = refreshOf(activated.expiresAt);
      live(scope);
      return Object.freeze({ id, refreshBefore });
    } catch (error) {
      throw normalize(scope, error);
    } finally {
      scope?.release();
    }
  }

  async function unsubscribe(authInput: unknown, identityInput: unknown, operationInput: unknown): Promise<void> {
    let scope: RequestScope | null = null;
    try {
      scope = begin(operationInput);
      const auth = copyAuth(authInput);
      const identity = own(() => copyIdentity(identityInput));
      live(scope);
      // 同じid式で、要求Grant付きのcancelを1回。同ownerの別Grantによる取消を禁止しない。
      const id = subscriptionId(auth.ownerId, identity.name, identity.url);
      live(scope);
      await bounded(scope, storeCancel(auth, { id }, scope.operation));
      live(scope);
    } catch (error) {
      throw normalize(scope, error);
    } finally {
      scope?.release();
    }
  }

  const service: RequestScopedSubscriptionPort = Object.freeze({
    subscribe: subscribe as RequestScopedSubscriptionPort['subscribe'],
    unsubscribe: unsubscribe as RequestScopedSubscriptionPort['unsubscribe'],
  });

  return Object.freeze({
    service,
    dispose(): void {
      if (closed) return;
      // 先に閉鎖してから進行中の子をabortする（以後の新しいDB/KMS/challengeは0）。借用資源は閉じない。
      closed = true;
      lifetime.abort();
    },
  });
}
