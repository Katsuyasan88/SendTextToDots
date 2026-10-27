// KMS購読profileの要求内配送を、Functions第2世代onRequest 1つとして組み立てるfactory（送信API起動口から使う）。同期・I/Oなし（DB・
// Google/Firebase clientの初期化、秘密の取得、KMS呼出し、listen、起動時の乱数鍵生成は0）。
//   createCommandDeliveryAttempt → createKmsRequestDeliveryRuntime → createIngressOperationDeliveryRequestHandler（entryが観測した元期限つき入口）
//   → createRequestDeliveryFunction（API_FUNCTION_OPTIONS）を、1回だけ捕捉した同じclockで接続する。
// db・connect・identity・hasher・KMS transport・egressと呼出し元のdigestKeyは借用（凍結・書換え・close・terminate・0埋めしない）。所有は
// lifetime controller・単回送出・runtime（digest鍵の写し）だけで、close()と組立ての失敗で一度だけ清掃する。試験用のhooks・budgetMs・
// 任意の試行ID生成器・serviceは入力にしない（試行IDは実要求ごとの内部randomUUID）。optionsは決まった項目だけのplain data objectで、
// 未知の項目・accessor・Proxyは副作用の前に固定のerrorで拒否する。入力値・元の例外は返さない。ingress（trustedな内部source）は必須で、
// 起動時に呼ばずに捕捉してHTTP入口へつなぐ。

import { randomUUID } from 'node:crypto';
import { types } from 'node:util';

import type { Firestore } from '@google-cloud/firestore';
import type { HttpsFunction } from 'firebase-functions/https';

import { createCommandDeliveryAttempt, type CommandDeliveryAttempt, type CommandDeliveryEgress } from '../commands/delivery-attempt.js';
import type { ConnectStorage } from '../connect/firestore.js';
import type { EncryptionKeyEndpoint } from '../encryption/api.js';
import type { EncryptedCommandEndpoint, ValidatedCommandDelivery } from '../encryption/commands.js';
import type { IdentityVerifier, VerifiedIdentity } from '../identity/firebase.js';
import type { Clock } from '../policy.js';
import type { SecretHasher } from '../secrets.js';
import { createIngressOperationDeliveryRequestHandler, type DeliveryHttpIngress } from './api.js';
import { createRequestDeliveryFunction } from './functions.js';
import { createKmsRequestDeliveryRuntime, type KmsRequestDeliveryRuntime, type KmsRequestDeliveryRuntimeOptions } from './kms-runtime.js';

const REQUIRED = ['db', 'connect', 'hasher', 'digestKey', 'kms', 'identity', 'egress', 'clock', 'namespace', 'ingress'] as const;
const OPTIONAL = ['log', 'encryptionKeys', 'encryptedCommands'] as const;

export type KmsDeliveryFunctionErrorCode = 'delivery_function_invalid' | 'delivery_function_close_failed';

/** 組立て・closeの失敗。固定のmessageだけで、渡された値・元の例外を持たない。 */
export class KmsDeliveryFunctionError extends Error {
  constructor(readonly code: KmsDeliveryFunctionErrorCode) {
    super(code);
    this.name = 'KmsDeliveryFunctionError';
  }
}

export interface KmsRequestDeliveryFunctionOptions {
  /** 借用するFirestore instance（terminateしない）。 */
  readonly db: Firestore;
  /** 同じdbの接続保存（ConnectStorage）。配送用の4methodとfindOwnerを、thisを保って使う（closeしない）。 */
  readonly connect: KmsRequestDeliveryRuntimeOptions['connect'] & Pick<ConnectStorage, 'findOwner'>;
  /** 識別子HMAC（接続側と同じ値・同じnamespaceの組合せを呼出し元が渡す）。 */
  readonly hasher: SecretHasher;
  /** command digest HMAC鍵（32バイト）。runtimeが写しを作る。呼出し元のBufferは0埋めしない。 */
  readonly digestKey: Buffer;
  /** codec設定からclockを除いたもの（KmsRequestDeliveryRuntimeと同じ）。 */
  readonly kms: KmsRequestDeliveryRuntimeOptions['kms'];
  readonly identity: IdentityVerifier;
  /** 安全送出の指示用入口（借用）。 */
  readonly egress: CommandDeliveryEgress;
  readonly clock: Clock;
  /** 配送のnamespace（`t270_<小文字UUID>`）。 */
  readonly namespace: string;
  /** 要求固有storeから元のHTTP ingressを返すtrustedな内部source（起動時には呼ばない）。 */
  readonly ingress: () => DeliveryHttpIngress;
  readonly log?: ((entry: Record<string, unknown>) => void) | undefined;
  /** 本文暗号化が有効な配置だけ: 公開鍵取得のport（借用。HTTP入口が形を検査する）。無ければ/v2/encryption-keyは404。 */
  readonly encryptionKeys?: EncryptionKeyEndpoint | undefined;
  /** 本文暗号化が有効な配置だけ: 共通配送service（postValidated）から暗号文送信のportを作る関数（組立て時に1回だけ呼ぶ）。 */
  readonly encryptedCommands?: ((delivery: ValidatedCommandDelivery) => EncryptedCommandEndpoint) | undefined;
}

export interface KmsRequestDeliveryFunction {
  /** Functions第2世代onRequestの関数（既存のAPI_FUNCTION_OPTIONS）。 */
  readonly handler: HttpsFunction;
  /**
   * 呼んだ時点でHTTP入口のlifetimeを中止し、runtime.disposeで進行中のservice・単回送出を中止して所有のdigest鍵の写しを0埋めする。
   * 以後のHTTPは固定503。同じPromiseを返し、処理は一度だけ。借用資源は閉じない（SDK内の物理停止・送出済みの撤回は約束しない）。
   */
  close(): Promise<void>;
}

const invalid = () => new KmsDeliveryFunctionError('delivery_function_invalid');

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前は拒否、getterは呼ばない）。 */
function dataFields(value: unknown, required: readonly string[]): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) throw invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || (OPTIONAL as readonly string[]).includes(key))) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    if (descriptor.value !== undefined || required.includes(key)) taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) throw invalid();
  return taken;
}

/** methodをprototypeの連鎖からdescriptorで1回だけ取り出し、元のobjectへ束縛する（accessor・Proxyは拒否、getterは呼ばない）。 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) throw invalid();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) throw invalid();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  throw invalid();
}

/** 暗号文送信のportを、このruntimeの共通配送service（postValidated、thisを保つ）から1回だけ作る。関数でなければ不正。 */
function encryptedCommandsOf(factory: unknown, runtime: KmsRequestDeliveryRuntime): EncryptedCommandEndpoint {
  if (typeof factory !== 'function' || types.isProxy(factory)) throw invalid();
  const service = runtime.service;
  const delivery: ValidatedCommandDelivery = Object.freeze({
    postValidated: (...args: Parameters<ValidatedCommandDelivery['postValidated']>) => service.postValidated(...args),
  });
  return Reflect.apply(factory as Function, undefined, [delivery]) as EncryptedCommandEndpoint;
}

/**
 * KMS配送のFunctions handlerを組み立てる。{handler, close}を返す（凍結）。不正・組立ての失敗はKmsDeliveryFunctionError
 * （delivery_function_invalid）で、その時点までに所有した物（単回送出・runtime・lifetime）を一度だけ清掃してから投げる。
 */
export function createIngressKmsRequestDeliveryFunction(options: KmsRequestDeliveryFunctionOptions): KmsRequestDeliveryFunction {
  const fields = dataFields(options, REQUIRED);
  // ingress sourceは関数（Proxyでない）だけを捕捉する（呼ばない）。
  const given = fields.get('ingress');
  if (typeof given !== 'function' || types.isProxy(given)) throw invalid();
  const ingressFn = given as Function;
  const ingress = (): DeliveryHttpIngress => Reflect.apply(ingressFn, undefined, []) as DeliveryHttpIngress;

  // 同じ捕捉clockを単回送出・runtime・HTTP入口の全層へ渡す（own dataの`now`だけのplain object）。
  const clockNow = methodOf(fields.get('clock'), 'now');
  const clock: Clock = Object.freeze({ now: () => clockNow() as number });

  // owner解決は借用ConnectStorage.findOwnerへthisを保って接続し、検証済みのidentityだけを渡す。
  const findOwnerMethod = methodOf(fields.get('connect'), 'findOwner');
  const findOwner = (verified: VerifiedIdentity): Promise<string | undefined> => findOwnerMethod(verified) as Promise<string | undefined>;
  const identity = fields.get('identity');
  methodOf(identity, 'verifyIdToken');

  let log: ((entry: Record<string, unknown>) => void) | undefined;
  if (fields.has('log')) {
    const given = fields.get('log');
    if (typeof given !== 'function' || types.isProxy(given)) throw invalid();
    const logFn = given as Function;
    log = (entry) => {
      Reflect.apply(logFn, undefined, [entry]);
    };
  }

  let attempt: CommandDeliveryAttempt;
  try {
    attempt = createCommandDeliveryAttempt({ egress: fields.get('egress') as CommandDeliveryEgress, clock });
  } catch {
    throw invalid();
  }

  let runtime: KmsRequestDeliveryRuntime;
  try {
    runtime = createKmsRequestDeliveryRuntime({
      db: fields.get('db') as Firestore,
      connect: fields.get('connect') as KmsRequestDeliveryRuntimeOptions['connect'],
      namespace: fields.get('namespace') as string,
      hasher: fields.get('hasher') as SecretHasher,
      digestKey: fields.get('digestKey') as Buffer,
      attempt,
      clock,
      newAttemptId: randomUUID,
      kms: fields.get('kms') as KmsRequestDeliveryRuntimeOptions['kms'],
      ...(log !== undefined ? { log } : {}),
    });
  } catch {
    // runtimeは未成立: 所有の単回送出だけをdisposeする（digest鍵の写しはruntimeが失敗時に0埋めする）。
    try {
      attempt.dispose();
    } catch {
      // 清掃の失敗で元の失敗を変えない。
    }
    throw invalid();
  }

  const lifetime = new AbortController();
  let handler: HttpsFunction;
  try {
    const apiDeps = {
      identity: identity as IdentityVerifier,
      findOwner,
      service: runtime.service,
      clock,
      log,
      lifetime: lifetime.signal,
      ...(fields.has('encryptionKeys') ? { encryptionKeys: fields.get('encryptionKeys') as EncryptionKeyEndpoint } : {}),
      ...(fields.has('encryptedCommands') ? { encryptedCommands: encryptedCommandsOf(fields.get('encryptedCommands'), runtime) } : {}),
    };
    handler = createRequestDeliveryFunction(createIngressOperationDeliveryRequestHandler({ ...apiDeps, ingress }));
  } catch {
    // runtimeは成立済み: lifetimeを中止し、runtime.dispose（単回送出のdispose・写しの0埋め）を一度だけ行う。
    lifetime.abort();
    try {
      runtime.dispose();
    } catch {
      // 清掃の失敗で元の失敗を変えない。
    }
    throw invalid();
  }

  let closing: Promise<void> | undefined;
  const closeOnce = (): Promise<void> => {
    // 呼出しと同時にHTTP入口を中止し（以後は固定503）、進行中のservice・単回送出を中止して写しを0埋めする。再実行しない。
    lifetime.abort();
    try {
      runtime.dispose();
      return Promise.resolve();
    } catch {
      return Promise.reject(new KmsDeliveryFunctionError('delivery_function_close_failed'));
    }
  };
  return Object.freeze({
    handler,
    close: (): Promise<void> => (closing ??= closeOnce()),
  });
}
