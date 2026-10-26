// KMS購読profileの要求内配送（store・service）を組み立てるfactory。同期・I/Oなし（通信・DB初期化・KMS呼出し0）。
// 1回だけ捕捉した同じKMS購読policyと同じ時計を、同期の購読readerとKMS codecの両方へ渡す。dbとconnectは借用（terminate・closeしない）、
// 単回送出は所有を受け取りdisposeで一度だけdisposeする。KMS transportは開封（decrypt）だけを使い、encryptは呼ばない。
// optionsは決まった項目だけのplain data objectで、余分な項目・不正な型・Proxy・getterは固定のerrorで拒否し、getter・trapを起動しない。
// digest鍵の写しを作った後の組立ての失敗では、写しを0埋めしてから同じ例外を投げる。

import { types } from 'node:util';

import type { Firestore } from '@google-cloud/firestore';

import type { CommandDeliveryAttempt, CommandDeliveryRequest, CommandDeliveryResult } from '../commands/delivery-attempt.js';
import type { ConnectStorage } from '../connect/firestore.js';
import type { Clock } from '../policy.js';
import {
  createKmsSealingCodec,
  type KmsCallOptions,
  type KmsDecryptRequest,
  type KmsDecryptResponse,
  type KmsSealingCodec,
  type KmsSealingConfig,
} from '../protection/kms-sealing.js';
import type { SecretHasher } from '../secrets.js';
import { createKmsSubscriptionPolicy, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { API_BUDGET_MS } from './contract.js';
import { isKmsDeliveryNamespace, KmsRequestDeliveryStore, type KmsDeliveryConnect } from './kms-store.js';
import { KmsRequestDeliveryService, type KmsDeliveryTestHooks } from './kms-service.js';

const REQUIRED = ['db', 'connect', 'namespace', 'hasher', 'digestKey', 'attempt', 'clock', 'newAttemptId', 'kms'] as const;
const OPTIONAL = ['log', 'budgetMs', 'hooks'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const HOOK_KEYS = ['afterPrepare', 'afterOpen', 'beforeFinish', 'onTransaction', 'onOwned', 'onDigestKeyCopy'] as const;

/** factoryの入力の不正。固定のmessageだけで、渡された値・元の例外を持たない。 */
export class KmsDeliveryConfigError extends Error {
  readonly code = 'delivery_config_invalid';
  constructor() {
    super('delivery_config_invalid');
    this.name = 'KmsDeliveryConfigError';
  }
}

export interface KmsRequestDeliveryRuntimeOptions {
  /** 借用するFirestore instance（terminateしない）。Command・購読marker/owner文書の参照は全てここから作る。 */
  readonly db: Firestore;
  /** 接続保存（ConnectStorage）。owner・Grantの参照は毎回ref.firestore===dbを要求する。 */
  readonly connect: Pick<
    ConnectStorage,
    'ownerDocRef' | 'grantDocRef' | 'ownerDocActive' | 'grantDocLive' | 'accessDocRefForOwner' | 'grantMetaDocRef' | 'accessUseDecision' | 'grantUseDecision'
  >;
  /** `t270_<小文字UUID>`（sttdDelivery配下）。 */
  readonly namespace: string;
  /** 識別子HMAC（接続側と同じ値）。 */
  readonly hasher: SecretHasher;
  /** command digest HMAC鍵（32バイト）。factoryが写しを作る。 */
  readonly digestKey: Buffer;
  /** 既存の単回送出。所有を受け取り、disposeで一度だけdisposeする。 */
  readonly attempt: CommandDeliveryAttempt;
  readonly clock: Clock;
  readonly newAttemptId: () => string;
  /** KMS codec設定からclockを除いたもの。namespaceは購読namespace（`t268_<UUID>`）。 */
  readonly kms: Omit<KmsSealingConfig, 'clock'>;
  readonly log?: ((entry: Record<string, unknown>) => void) | undefined;
  /** 試験だけ: 正の整数・20000以下（既定20000、延長不可）。 */
  readonly budgetMs?: number | undefined;
  /** 試験だけ: 待ち合わせ・観測。製品の組立ては渡さない。 */
  readonly hooks?: KmsDeliveryTestHooks | undefined;
}

export interface KmsRequestDeliveryRuntime {
  readonly service: KmsRequestDeliveryService;
  readonly store: KmsRequestDeliveryStore;
  /** 進行中の要求を中止し、以後のpost/get/cancelを固定の非成功にする。単回送出を一度だけdispose。db・connect・transportは閉じない。 */
  dispose(): void;
}

function fail(): never {
  throw new KmsDeliveryConfigError();
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前は拒否、getterは呼ばない）。 */
function dataFields(value: unknown, required: readonly string[], optional: readonly string[]): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) fail();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || optional.includes(key))) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    if (descriptor.value !== undefined || required.includes(key)) taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) fail();
  return taken;
}

/**
 * objectのmethodを、prototypeの連鎖をdescriptorで辿って1回だけ取り出し、元のobjectへ束縛する（accessor・Proxyは拒否、getterは呼ばない）。
 * class instance（ConnectStorage等）のmethodも取り出せる。
 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) fail();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) fail();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  return fail();
}

function plainFunction(value: unknown): (...args: unknown[]) => unknown {
  if (typeof value !== 'function' || types.isProxy(value)) fail();
  const found = value as Function;
  return (...args: unknown[]) => Reflect.apply(found, undefined, args);
}

/** 試験のhooks（決まった名前の関数だけ）。 */
function copyHooks(value: unknown): KmsDeliveryTestHooks {
  if (value === undefined) return Object.freeze({});
  const fields = dataFields(value, [], HOOK_KEYS);
  const hooks: Record<string, unknown> = {};
  for (const [key, hook] of fields) hooks[key] = plainFunction(hook);
  return Object.freeze(hooks) as unknown as KmsDeliveryTestHooks;
}

/**
 * KMS購読profileの要求内配送を組み立てる。{service, store, dispose}を返す。全ての検査・捕捉はここで1回だけ行い、
 * 以後は入力objectを読み直さない（後からの改変は効かない）。不正はKmsDeliveryConfigError。
 */
export function createKmsRequestDeliveryRuntime(options: KmsRequestDeliveryRuntimeOptions): KmsRequestDeliveryRuntime {
  const fields = dataFields(options, REQUIRED, OPTIONAL);

  const namespace = fields.get('namespace');
  if (!isKmsDeliveryNamespace(namespace)) fail();

  // dbは借用。SDKのmethodの存在だけをdescriptorで確かめる（呼ばない・接続しない）。
  const db = fields.get('db');
  methodOf(db, 'collection');
  methodOf(db, 'runTransaction');
  const firestore = db as Firestore;

  const connectTarget = fields.get('connect');
  const ownerDocRef = methodOf(connectTarget, 'ownerDocRef');
  const grantDocRef = methodOf(connectTarget, 'grantDocRef');
  const ownerDocActive = methodOf(connectTarget, 'ownerDocActive');
  const grantDocLive = methodOf(connectTarget, 'grantDocLive');
  const accessDocRefForOwner = methodOf(connectTarget, 'accessDocRefForOwner');
  const grantMetaDocRef = methodOf(connectTarget, 'grantMetaDocRef');
  const accessUseDecision = methodOf(connectTarget, 'accessUseDecision');
  const grantUseDecision = methodOf(connectTarget, 'grantUseDecision');
  /** 利用許可の判定は既知の3値だけを採用し、他は一時障害（unavailable）へ閉じる。 */
  const decisionOf = (value: unknown): 'allowed' | 'denied' | 'unavailable' => (value === 'allowed' || value === 'denied' ? value : 'unavailable');
  const connect: KmsDeliveryConnect = Object.freeze({
    ownerDocRef: (ownerId: string) => ownerDocRef(ownerId) as ReturnType<KmsDeliveryConnect['ownerDocRef']>,
    grantDocRef: (grantId: string) => grantDocRef(grantId) as ReturnType<KmsDeliveryConnect['grantDocRef']>,
    ownerDocActive: (data: Record<string, unknown> | undefined, now: number) => ownerDocActive(data, now) === true,
    grantDocLive: (data: Record<string, unknown> | undefined, ownerId: string, grantId: string, now: number) =>
      grantDocLive(data, ownerId, grantId, now) === true,
    accessDocRefForOwner: (data: Record<string, unknown> | undefined) => accessDocRefForOwner(data) as ReturnType<KmsDeliveryConnect['accessDocRefForOwner']>,
    grantMetaDocRef: (grantId: string) => grantMetaDocRef(grantId) as ReturnType<KmsDeliveryConnect['grantMetaDocRef']>,
    accessUseDecision: (access: { readonly exists: boolean; readonly data: unknown }) => decisionOf(accessUseDecision(access)),
    grantUseDecision: (access: { readonly exists: boolean; readonly data: unknown }, meta: { readonly exists: boolean; readonly data: unknown }, ownerId: string) =>
      decisionOf(grantUseDecision(access, meta, ownerId)),
  });

  const hashMethod = methodOf(fields.get('hasher'), 'hash');
  const hash = (purpose: string, value: string): string => {
    const result = hashMethod(purpose, value);
    if (typeof result !== 'string') throw new KmsDeliveryConfigError();
    return result;
  };

  const digestInput = fields.get('digestKey');
  if (typeof digestInput !== 'object' || digestInput === null || types.isProxy(digestInput) || !Buffer.isBuffer(digestInput)) fail();
  if (digestInput.length !== 32) fail();
  const digestKey = Buffer.alloc(32);
  digestInput.copy(digestKey);
  // 写しを作った後の組立ての失敗（後続の入力検査・KMS設定・store生成）では、写しを0埋めしてから同じ例外を投げる。
  try {
    return assemble(fields, namespace, firestore, connect, hash, digestKey);
  } catch (error) {
    digestKey.fill(0);
    throw error;
  }
}

/** digest鍵の写しの後の組立て（失敗時の写しの清掃は呼出し元が行う）。 */
function assemble(
  fields: Map<string, unknown>,
  namespace: string,
  firestore: Firestore,
  connect: KmsDeliveryConnect,
  hash: (purpose: string, value: string) => string,
  digestKey: Buffer,
): KmsRequestDeliveryRuntime {
  const attemptTarget = fields.get('attempt');
  const sendMethod = methodOf(attemptTarget, 'send');
  const disposeAttempt = methodOf(attemptTarget, 'dispose');
  const send = (request: CommandDeliveryRequest) => sendMethod(request) as Promise<CommandDeliveryResult>;

  const clockTarget = fields.get('clock');
  const clockNow = methodOf(clockTarget, 'now');
  const clock: Clock = Object.freeze({ now: () => clockNow() as number });

  const newAttemptIdFn = plainFunction(fields.get('newAttemptId'));
  const newAttemptId = (): string => {
    const id = newAttemptIdFn();
    if (typeof id !== 'string') throw new KmsDeliveryConfigError();
    return id;
  };

  const logFn = fields.has('log') ? plainFunction(fields.get('log')) : undefined;
  const log = (entry: Record<string, unknown>): void => {
    logFn?.(entry);
  };

  let budgetMs = API_BUDGET_MS;
  if (fields.has('budgetMs')) {
    const given = fields.get('budgetMs');
    if (typeof given !== 'number' || !Number.isSafeInteger(given) || given <= 0 || given > API_BUDGET_MS) fail();
    budgetMs = given;
  }
  const hooks = copyHooks(fields.get('hooks'));

  // KMS設定: clockを持たせない（同じ捕捉clockを使う）。policyは共通の検査・昇順の正規化で1回捕捉する。
  const kms = dataFields(fields.get('kms'), KMS_KEYS, []);
  let policy: KmsSubscriptionPolicy;
  try {
    policy = createKmsSubscriptionPolicy({
      namespace: kms.get('namespace'),
      environment: kms.get('environment'),
      projectId: kms.get('projectId'),
      databaseId: kms.get('databaseId'),
      cryptoKey: kms.get('cryptoKey'),
      writeVersion: kms.get('writeVersion'),
      readVersions: kms.get('readVersions'),
    });
  } catch {
    return fail();
  }
  const decrypt = methodOf(kms.get('transport'), 'decrypt');
  const transport = Object.freeze({
    // 配送は開封だけ。封緘（encrypt）は呼ばない。
    encrypt: () => Promise.reject(new Error('delivery: read-only KMS port, encrypt is not used')),
    decrypt: (request: KmsDecryptRequest, callOptions: KmsCallOptions) => decrypt(request, callOptions) as PromiseLike<KmsDecryptResponse>,
  });
  let codec: KmsSealingCodec;
  try {
    codec = createKmsSealingCodec({
      environment: policy.environment,
      projectId: policy.projectId,
      databaseId: policy.databaseId,
      namespace: policy.namespace,
      cryptoKey: policy.cryptoKey,
      writeVersion: policy.writeVersion,
      readVersions: [...policy.readVersions],
      transport,
      clock,
    });
  } catch {
    return fail();
  }

  const store = new KmsRequestDeliveryStore({
    db: firestore,
    namespace,
    connect,
    hash,
    clock,
    policy,
    onTransaction: hooks.onTransaction,
  });
  const lifetime = new AbortController();
  const service = new KmsRequestDeliveryService({
    store,
    codec,
    hash,
    digestKey,
    send,
    clock,
    newAttemptId,
    log,
    budgetMs,
    lifetime: lifetime.signal,
    hooks,
  });
  try {
    hooks.onDigestKeyCopy?.(digestKey);
  } catch {
    // 観測の失敗で組立てを変えない。
  }

  let disposed = false;
  return Object.freeze({
    service,
    store,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      // 進行中の開封・DB待機・送出の要求を中止し、以後の要求を固定の非成功にする（始めたSDK処理の物理停止・届いたHTTPの撤回は約束しない）。
      lifetime.abort();
      try {
        disposeAttempt();
      } finally {
        digestKey.fill(0);
      }
    },
  });
}
