// KMS購読の登録を、要求Grantのscope同版証拠（helper）・精密な購読期待版・owner文書の取消世代と
// 同じtransactionで認可して原子的に保存する保存口（events/kms-subscription-runtime.tsが使う）。
// 借用したdb（terminateしない）の同じinstanceだけで、sttdAuth/{t268}/config/kms-subscription（既存の明示setup済みmarker）・
// sttdAuth/{t268}/subscriptions/{ownerId}（既存version2）・sttdConnect/{t256}/owners/{ownerId}・sttdConnect/{t256}/oidc/Grant_<64hex>を読む。
// 登録（prepareのchallenge前と最終activate）は同じtransactionでsttdConnect/{t256}/access/{identityHash}（運営者の明示許可）と
// sttdConnect/{t256}/grantMeta/{64hex}（要求Grantの利用許可の世代）も読み、activeかつ世代一致の時だけ進める（不許可は既存grant_inactive、
// 不正・読取り不能はunavailable）。取消（cancel）は利用許可を条件にしない。
// 全transactionの閉包は、全読取り→最新時計→同期の検査・投影→書込みだけで、暗号・開封・HTTP・乱数・ログを入れない（SDKが再実行しても同じ）。
// Grantの開封（decryptだけ）は閉包の外で、同じ元operationの期限・中止を渡す。各callは元の{deadlineAt, signal}を1回捕捉して延長せず、
// 開始前・各await後・新しいI/O前・閉包の更新前・返却前にsignal→時計→signalで検査する。期限・中止の後は新しいSDK呼出し・更新・遅い成功の
// 採用をしない（既に始めたSDKのcommitの物理的な取消は約束しない）。外側の再読・re-prove・自動再試行・process lockに依存しない。
// ownerの活動時刻（lastActiveAt）・失効・封緘UIDは読むだけで変えない。owner文書へ書くのは、認可済みのcancelによる取消世代+1だけ。

import { types } from 'node:util';

import type { DocumentReference, DocumentSnapshot, Firestore, Transaction } from '@google-cloud/firestore';

import { createKmsGrantAuthorization, KmsGrantAuthorizationError, type KmsGrantAuthorization, type KmsGrantProof } from '../../connect/kms-grant-authorization.js';
import { CONNECT_STORAGE_ROOT, isConnectNamespace } from '../../connect/firestore.js';
import type { Clock } from '../../policy.js';
import type { KmsCallOptions, KmsDecryptRequest, KmsDecryptResponse, KmsSealingConfig } from '../../protection/kms-sealing.js';
import {
  createKmsSubscriptionPolicy,
  emptyKmsState,
  kmsStateDocument,
  parseKmsState,
  requireKmsDocumentSize,
  requireKmsMarker,
  sweepKmsState,
  type KmsMutableState,
  type KmsSubscriptionPolicy,
} from './kms-subscription-format.js';
import { AUTH_STORAGE_ROOT, KMS_SUBSCRIPTION_CONFIG_DOC } from './kms-subscription-format.js';
import { grantReceiverGenerationOf } from '../../access/policy.js';
import { ownerReceiverGeneration } from './receiver-reset.js';
import {
  applyActivation,
  applyCancel,
  classify,
  copyAuth,
  copyCancel,
  copyCapsules,
  copyRequest,
  KmsSubscriptionRegistrationError,
  nextGeneration,
  ownerGeneration,
  projectBindings,
  registrationError,
  sameDocVersion,
  SUBSCRIPTION_GENERATION_FIELD,
  versionOf,
  type BindingVerdict,
  type DocVersion,
  type RegistrationAuth,
  type RegistrationRequest,
} from './kms-subscription-registration-rules.js';
import { isTime } from './checks.js';

export {
  KmsSubscriptionRegistrationError,
  MAX_REGISTRATION_TTL_MS,
  SUBSCRIPTION_GENERATION_FIELD,
  type KmsSubscriptionRegistrationErrorCode,
} from './kms-subscription-registration-rules.js';

/** SDKのtransactionの最大実行回数（既定と同じ5。外側で自動の再試行・再開をしない）。 */
const MAX_TRANSACTION_ATTEMPTS = 5;
const OPTION_KEYS = ['db', 'connect', 'connectNamespace', 'resource', 'kms', 'clock'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const OPERATION_KEYS = ['deadlineAt', 'signal'] as const;
const GRANT_DOC_ID = /^Grant_[0-9a-f]{64}$/;
/** 許可record（identityHash）・同意記録（grantHash）の文書ID。 */
const HEX_DOC_ID = /^[0-9a-f]{64}$/;

/** 接続保存のうち、この保存口が使う同期の参照・判定だけ（prototypeのdata methodを束縛して1回捕捉する）。 */
export interface KmsSubscriptionRegistrationConnect {
  ownerDocRef(ownerId: string): DocumentReference;
  grantDocRef(grantId: string): DocumentReference;
  ownerDocActive(data: Record<string, unknown> | undefined, now: number): boolean;
  grantDocLive(data: Record<string, unknown> | undefined, ownerId: string, grantId: string, now: number): boolean;
  accessDocRefForOwner(data: Record<string, unknown> | undefined): DocumentReference | null;
  grantMetaDocRef(grantId: string): DocumentReference;
  grantUseDecision(
    access: { readonly exists: boolean; readonly data: unknown },
    meta: { readonly exists: boolean; readonly data: unknown },
    ownerId: string,
  ): 'allowed' | 'denied' | 'unavailable';
}

export interface KmsSubscriptionRegistrationOptions {
  /** 借用するFirestore instance（terminate・closeしない）。全参照はこのinstanceのものだけを使う。 */
  readonly db: Firestore;
  readonly connect: KmsSubscriptionRegistrationConnect;
  /** 接続保存の`t256_<小文字UUID>`（owner・Grant文書とGrant helperのcodec namespace）。 */
  readonly connectNamespace: string;
  /** 固定MCP audience（Grant.resourcesのkey）。HTTPS URL、local-testだけloopbackのHTTPも可。 */
  readonly resource: string;
  /** codec設定からclockを除いたもの。namespaceはKMS購読の`t268_<小文字UUID>`。transportはGrantの開封（decrypt）だけに使う。 */
  readonly kms: Omit<KmsSealingConfig, 'clock'>;
  readonly clock: Clock;
}

/** 認証済みのowner（UUID）と要求のGrant（既存のKMS grant ID形式）。 */
export interface KmsSubscriptionRegistrationAuth {
  readonly ownerId: string;
  readonly grantId: string;
}

/** 元要求の絶対期限（clockと同じ基準の安全な整数ms）と中止。延長しない。 */
export interface KmsSubscriptionRegistrationOperation {
  readonly deadlineAt: number;
  readonly signal?: AbortSignal | undefined;
}

declare const KMS_SUBSCRIPTION_PLAN: unique symbol;
/** 中身を持たない不透明なchallenge plan。発行したstoreの最初のactivateで1回だけ使える。 */
export interface KmsSubscriptionChallengePlan {
  readonly [KMS_SUBSCRIPTION_PLAN]: never;
}

export type KmsSubscriptionPrepareResult =
  | { readonly kind: 'extended'; readonly id: string; readonly expiresAt: number | null }
  | { readonly kind: 'pending' }
  | { readonly kind: 'challenge'; readonly plan: KmsSubscriptionChallengePlan };

export interface KmsSubscriptionRegistrationStore {
  /** id=`sub_<64hex>`、secretHash=64hex、ttlMs=nullか整数1..86400000。 */
  prepare(
    auth: KmsSubscriptionRegistrationAuth,
    request: { readonly id: string; readonly secretHash: string; readonly ttlMs: number | null },
    operation: KmsSubscriptionRegistrationOperation,
  ): Promise<KmsSubscriptionPrepareResult>;
  activate(
    plan: KmsSubscriptionChallengePlan,
    capsules: { readonly sealedUrl: string; readonly sealedSecret: string },
    operation: KmsSubscriptionRegistrationOperation,
  ): Promise<{ readonly id: string; readonly expiresAt: number | null }>;
  cancel(auth: KmsSubscriptionRegistrationAuth, request: { readonly id: string }, operation: KmsSubscriptionRegistrationOperation): Promise<void>;
}

type Captured = Readonly<{ deadlineAt: number; signal: AbortSignal | undefined }>;

function invalid(): KmsSubscriptionRegistrationError {
  return registrationError('invalid_input');
}

function fail(): never {
  throw invalid();
}

/** 固定errorへ正規化する（元の例外・SDK error・文書の値を運ばない）。保存の形の不正・SDK失敗・下位portの例外はunavailable。 */
function fixed(error: unknown): KmsSubscriptionRegistrationError {
  if (error instanceof KmsSubscriptionRegistrationError) return registrationError(error.code);
  if (error instanceof KmsGrantAuthorizationError && (error.code === 'timed_out' || error.code === 'aborted')) return registrationError(error.code);
  return registrationError('unavailable');
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前を拒否、getterを呼ばない）。 */
function dataFields(value: unknown, required: readonly string[], optional: readonly string[]): Map<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) fail();
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

/** prototypeの連鎖をdescriptorで辿ってmethodを1回取り出し、元のobjectへ束縛する（accessor・Proxyを拒否、getterを呼ばない）。 */
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

function copyOperation(value: unknown): Captured {
  const fields = dataFields(value, ['deadlineAt'], OPERATION_KEYS.slice(1));
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) fail();
  if (signal !== undefined && (!isObject(signal) || !(signal instanceof AbortSignal))) fail();
  return Object.freeze({ deadlineAt, signal: signal as AbortSignal | undefined });
}

/** challenge planの中身（WeakMapの値だけ。公開しない）。 */
interface PlanRecord {
  readonly auth: RegistrationAuth;
  readonly request: RegistrationRequest;
  readonly operation: Captured;
  readonly ownerRef: DocumentReference;
  readonly subscriptionRef: DocumentReference;
  /** 要求Grantの同意記録（利用許可の世代）の参照。 */
  readonly metaRef: DocumentReference;
  /** 初回snapshotの購読の精密版とowner世代。 */
  readonly subscription: DocVersion;
  readonly generation: number;
  /** 要求Grant（先頭）と、初回snapshotのactive/pendingが束縛したGrant（重複なし・最大3）の証拠。 */
  readonly grants: readonly ProvenGrant[];
}

/** 同じtransactionで読んだ利用許可recordと要求Grantの同意記録。 */
interface AccessSnapshots {
  readonly access: DocumentSnapshot;
  readonly meta: DocumentSnapshot;
}

interface ProvenGrant {
  readonly grantId: string;
  readonly ref: DocumentReference;
  readonly proof: KmsGrantProof;
}

/**
 * KMS購読の登録保存口を組み立てる（同期・I/Oなし: 通信・DB初期化・KMS呼出し0）。全ての検査・捕捉はここで1回だけ行い、以後は入力objectを
 * 読み直さない。markerは既存の明示setup（配置時のmarker作成）が前提で、ここでは作らない。
 * 不正はKmsSubscriptionRegistrationError（invalid_input）。戻り値は凍結した{prepare, activate, cancel}。
 */
export function createKmsSubscriptionRegistrationStore(options: KmsSubscriptionRegistrationOptions): KmsSubscriptionRegistrationStore {
  const fields = dataFields(options, OPTION_KEYS, []);

  // dbは借用。SDKのmethodの存在だけをdescriptorで確かめる（呼ばない・接続しない）。
  const dbInput = fields.get('db');
  methodOf(dbInput, 'collection');
  const runTransaction = methodOf(dbInput, 'runTransaction');
  const db = dbInput as Firestore;

  const connectTarget = fields.get('connect');
  const ownerDocRef = methodOf(connectTarget, 'ownerDocRef');
  const grantDocRef = methodOf(connectTarget, 'grantDocRef');
  const ownerDocActive = methodOf(connectTarget, 'ownerDocActive');
  const grantDocLive = methodOf(connectTarget, 'grantDocLive');
  const accessDocRefForOwner = methodOf(connectTarget, 'accessDocRefForOwner');
  const grantMetaDocRef = methodOf(connectTarget, 'grantMetaDocRef');
  const grantUseDecision = methodOf(connectTarget, 'grantUseDecision');

  const connectNamespace = fields.get('connectNamespace');
  if (!isConnectNamespace(connectNamespace)) fail();

  const clockNow = methodOf(fields.get('clock'), 'now');
  /** 読めない・有限でない時計は残りのないもの（timed_out）として扱い、元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  const clock: Clock = Object.freeze({ now });

  // KMS設定: clockを持たせない（同じ捕捉clockを使う）。購読のpolicyは共通の検査・昇順の正規化で1回捕捉する。
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

  // Grant helperは内部で作る（任意のvalidator・別resourceのhelperを外から注入しない）。同じ環境/project/database/key/version/
  // transport/clockで、namespaceだけ接続保存のt256にする。開封はdecryptだけ（encryptは常にreject）。
  const helperConnect = Object.freeze({
    grantDocRef: (grantId: string) => grantDocRef(grantId),
    grantDocLive: (data: Record<string, unknown> | undefined, ownerId: string, grantId: string, at: number) =>
      grantDocLive(data, ownerId, grantId, at) === true,
  });
  let grants: KmsGrantAuthorization;
  try {
    grants = createKmsGrantAuthorization({
      db,
      connect: helperConnect as unknown as Parameters<typeof createKmsGrantAuthorization>[0]['connect'],
      resource: fields.get('resource') as string,
      kms: {
        environment: policy.environment,
        projectId: policy.projectId,
        databaseId: policy.databaseId,
        namespace: connectNamespace,
        cryptoKey: policy.cryptoKey,
        writeVersion: policy.writeVersion,
        readVersions: [...policy.readVersions],
        transport: Object.freeze({
          encrypt: () => Promise.reject(new Error('subscription registration: read-only KMS port, encrypt is not used')),
          decrypt: (request: KmsDecryptRequest, callOptions: KmsCallOptions) => decrypt(request, callOptions) as PromiseLike<KmsDecryptResponse>,
        }),
      },
      clock,
    });
  } catch {
    return fail();
  }

  const authRoot = db.collection(AUTH_STORAGE_ROOT).doc(policy.namespace);
  const markerRef = authRoot.collection('config').doc(KMS_SUBSCRIPTION_CONFIG_DOC);
  const subscriptionDocs = authRoot.collection('subscriptions');
  const connectPrefix = `${CONNECT_STORAGE_ROOT}/${connectNamespace}/`;
  const plans = new WeakMap<object, PlanRecord>();

  /** まだ進めてよいかを、最新のsignal→時計→signalの順に見て、その時刻を返す（時計の観測中の中止も見る）。 */
  function liveNow(operation: Captured): number {
    if (operation.signal?.aborted) throw registrationError('aborted');
    const at = now();
    if (operation.signal?.aborted) throw registrationError('aborted');
    if (!(at < operation.deadlineAt)) throw registrationError('timed_out');
    return at;
  }

  /**
   * 最終transactionの判定時刻（全読取りの後）。保存する時刻（requestedAt・expiresAt・until）はversion2のepochミリ秒（safe integer）なので、
   * 既存latest()と同じく、そうでない時計の値は固定unavailable（丸めて保存しない）。
   */
  function decisionTime(operation: Captured): number {
    const at = liveNow(operation);
    if (!isTime(at)) throw registrationError('unavailable');
    return at;
  }

  /**
   * 残りが正の時だけstartでSDK呼出しを始め、元期限か中止までに決まらなければ待つのをやめる（始めたSDK処理の取消とは扱わず、後のrejectは
   * 握りつぶし、後の完了は使わない）。結果の公開直前にも同じ検査を行い、遅い成功を採用しない。
   */
  function bounded<T>(operation: Captured, start: () => Promise<T>): Promise<T> {
    let remaining: number;
    let promise: Promise<T>;
    try {
      remaining = operation.deadlineAt - liveNow(operation);
      promise = start();
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    promise.catch(() => {});
    const { signal } = operation;
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (outcome: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        outcome();
      };
      const onAbort = () => finish(() => reject(registrationError('aborted')));
      const timer = setTimeout(() => finish(() => reject(registrationError('timed_out'))), Math.max(1, Math.ceil(remaining)));
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
      promise.then(
        (value) =>
          finish(() => {
            try {
              liveNow(operation);
              resolve(value);
            } catch (error) {
              reject(fixed(error));
            }
          }),
        (error: unknown) => finish(() => reject(fixed(error))),
      );
    });
  }

  /** 1つの論理transaction（SDK maxAttempts 5以下）。閉包の開始ごとに元期限/中止を検査する。 */
  function run<T>(operation: Captured, body: (tx: Transaction) => Promise<T>): Promise<T> {
    return bounded(operation, () =>
      runTransaction(
        async (tx: Transaction) => {
          liveNow(operation);
          return body(tx);
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ) as Promise<T>,
    );
  }

  /** 1回の読取り（各awaitの後に検査）。 */
  async function read(tx: Transaction, operation: Captured, refs: readonly DocumentReference[]): Promise<DocumentSnapshot[]> {
    const snapshots = await tx.getAll(...refs);
    liveNow(operation);
    if (snapshots.length !== refs.length) throw registrationError('unavailable');
    return snapshots;
  }

  /**
   * 接続保存の参照は、借用した同じinstance・同じt256 namespaceの決まったpathだけを使う（別instanceは同じproject文字列でも、
   * そのrefを使うI/Oの前に拒否）。実target・IAMの証明とはしない。
   */
  function ownConnectRef(make: () => unknown, collection: 'owners' | 'oidc' | 'access' | 'grantMeta', accept: (id: string) => boolean): DocumentReference {
    let ref: unknown;
    let firestore: unknown;
    let path: unknown;
    let id: unknown;
    try {
      ref = make();
      if (!isObject(ref)) fail();
      firestore = (ref as { firestore?: unknown }).firestore;
      path = (ref as { path?: unknown }).path;
      id = (ref as { id?: unknown }).id;
    } catch {
      return fail();
    }
    if (firestore !== db || typeof path !== 'string' || typeof id !== 'string' || !accept(id)) fail();
    if (path !== `${connectPrefix}${collection}/${id}`) fail();
    return ref as DocumentReference;
  }

  function ownerRefOf(ownerId: string): DocumentReference {
    return ownConnectRef(() => ownerDocRef(ownerId), 'owners', (id) => id === ownerId);
  }

  function grantRefOf(grantId: string): DocumentReference {
    return ownConnectRef(() => grantDocRef(grantId), 'oidc', (id) => GRANT_DOC_ID.test(id));
  }

  function grantMetaRefOf(grantId: string): DocumentReference {
    return ownConnectRef(() => grantMetaDocRef(grantId), 'grantMeta', (id) => HEX_DOC_ID.test(id));
  }

  /** owner文書のidentityHashから許可recordの参照（無い・形違い・別instance/pathはunavailable）。 */
  function accessRefOf(owner: DocumentSnapshot): DocumentReference {
    let made: unknown;
    try {
      made = accessDocRefForOwner(owner.data());
    } catch {
      throw registrationError('unavailable');
    }
    if (made === null) throw registrationError('unavailable');
    try {
      return ownConnectRef(() => made, 'access', (id) => HEX_DOC_ID.test(id));
    } catch {
      throw registrationError('unavailable');
    }
  }

  /**
   * 同じtransactionで、owner文書のidentityHashから許可recordを、要求Grantの同意記録と一緒に読む（ownerを読んだ後の追加の読取り）。
   * 判定は全ての読取りの後にrequireAccessで行う。
   */
  async function readAccess(tx: Transaction, operation: Captured, owner: DocumentSnapshot, metaRef: DocumentReference): Promise<AccessSnapshots> {
    const [access, meta] = (await read(tx, operation, [accessRefOf(owner), metaRef])) as [DocumentSnapshot, DocumentSnapshot];
    return { access, meta };
  }

  /**
   * 利用許可がactiveで、要求Grantの同意記録が同じownerの現在の世代か。不許可はgrant_inactive、不正・不明はunavailable。
   * さらに、要求Grantの受信reset世代がownerの現在の受信reset世代と同じこと（受信先設定一式を消した後に、前の同意のGrantで受信先設定を作らせない）。
   */
  function requireAccess(snapshots: AccessSnapshots, ownerId: string, owner: DocumentSnapshot): void {
    const decision = grantUseDecision(
      { exists: snapshots.access.exists, data: snapshots.access.exists ? snapshots.access.data() : undefined },
      { exists: snapshots.meta.exists, data: snapshots.meta.exists ? snapshots.meta.data() : undefined },
      ownerId,
    );
    if (decision === 'denied') throw registrationError('grant_inactive');
    if (decision !== 'allowed') throw registrationError('unavailable');
    const grantReceiver = grantReceiverGenerationOf(snapshots.meta.data());
    let ownerReceiver: number;
    try {
      ownerReceiver = ownerReceiverGeneration(owner.data());
    } catch {
      throw registrationError('unavailable');
    }
    if (grantReceiver === null) throw registrationError('unavailable');
    if (grantReceiver !== ownerReceiver) throw registrationError('grant_inactive');
  }

  function requireMarker(snapshot: DocumentSnapshot): void {
    if (!snapshot.exists) throw registrationError('unavailable');
    try {
      requireKmsMarker(snapshot.data(), policy);
    } catch {
      throw registrationError('unavailable');
    }
  }

  /** version2の購読文書を検査して写す（無ければundefined）。破損・別形式は固定unavailable（空・別ownerとして扱わない）。 */
  function readState(snapshot: DocumentSnapshot, ownerId: string): KmsMutableState | undefined {
    if (!snapshot.exists) return undefined;
    try {
      return parseKmsState(snapshot.data(), ownerId, policy);
    } catch {
      throw registrationError('unavailable');
    }
  }

  function ownerActive(snapshot: DocumentSnapshot, at: number): boolean {
    return ownerDocActive(snapshot.data(), at) === true;
  }

  function grantLive(snapshot: DocumentSnapshot, ownerId: string, grantId: string, at: number): boolean {
    return grantDocLive(snapshot.data(), ownerId, grantId, at) === true;
  }

  /** 最新の同じsnapshotでGrantの証拠を照合する（I/O・開封0）。staleは版違いのconflict。 */
  function verdictOf(proven: ProvenGrant, snapshot: DocumentSnapshot, ownerId: string, operation: Captured): BindingVerdict {
    const result = grants.check(proven.proof, snapshot, { ownerId, grantId: proven.grantId }, operation);
    if (result === 'stale') throw registrationError('conflict');
    return result;
  }

  /**
   * 最終transactionの共通の認可: marker・最新owner有効性・owner世代・全Grant証拠（stale→conflict）・要求Grant active。期待した購読版・
   * owner世代が与えられれば完全一致を要求する（取消・延長・再登録・Grantの再保存の後着をconflictにする）。
   */
  function authorize(
    operation: Captured,
    auth: RegistrationAuth,
    snapshots: { readonly owner: DocumentSnapshot; readonly marker: DocumentSnapshot; readonly grants: readonly DocumentSnapshot[] },
    proven: readonly ProvenGrant[],
    at: number,
  ): { readonly generation: number; readonly verdicts: ReadonlyMap<string, BindingVerdict> } {
    requireMarker(snapshots.marker);
    if (!ownerActive(snapshots.owner, at)) throw registrationError('grant_inactive');
    const generation = ownerGeneration(snapshots.owner.data());
    const verdicts = new Map<string, BindingVerdict>();
    proven.forEach((entry, index) => {
      const snapshot = snapshots.grants[index];
      if (snapshot === undefined) throw registrationError('unavailable');
      verdicts.set(entry.grantId, verdictOf(entry, snapshot, auth.ownerId, operation));
    });
    if (verdicts.get(auth.grantId) !== 'active') throw registrationError('grant_inactive');
    return { generation, verdicts };
  }

  /** 取得済みのGrant snapshotをtransactionの外で順に証拠化する（同じ元operation、各1回の開封）。 */
  async function proveAll(
    operation: Captured,
    ownerId: string,
    entries: readonly { readonly grantId: string; readonly ref: DocumentReference; readonly snapshot: DocumentSnapshot }[],
  ): Promise<ProvenGrant[]> {
    const proven: ProvenGrant[] = [];
    for (const entry of entries) {
      liveNow(operation);
      const proof = await grants.prove(entry.snapshot, { ownerId, grantId: entry.grantId }, operation);
      liveNow(operation);
      proven.push(Object.freeze({ grantId: entry.grantId, ref: entry.ref, proof }));
    }
    return proven;
  }

  function verdictLookup(verdicts: ReadonlyMap<string, BindingVerdict>): (grantId: string) => BindingVerdict {
    return (grantId) => {
      const verdict = verdicts.get(grantId);
      // 期待版が一致していれば束縛Grantは初回と同じ集合。知らないGrantは推測せずconflict。
      if (verdict === undefined) throw registrationError('conflict');
      return verdict;
    };
  }

  async function prepare(authInput: unknown, requestInput: unknown, operationInput: unknown): Promise<KmsSubscriptionPrepareResult> {
    try {
      // 最初のawaitの前に、入力・参照を捕捉・検査する（後の改変で束縛を変えない）。
      const operation = copyOperation(operationInput);
      const auth = copyAuth(authInput);
      const request = copyRequest(requestInput);
      liveNow(operation);
      const ownerRef = ownerRefOf(auth.ownerId);
      const requestGrantRef = grantRefOf(auth.grantId);
      const requestMetaRef = grantMetaRefOf(auth.grantId);
      const subscriptionRef = subscriptionDocs.doc(auth.ownerId);

      // 初回snapshot: 書込みなしの通常transaction。owner・marker・購読・要求Grantと、購読のactive/pendingが束縛したGrant（重複なし）を読む。
      const first = await run(operation, async (tx) => {
        const [owner, marker, subscription, requestGrant] = (await read(tx, operation, [ownerRef, markerRef, subscriptionRef, requestGrantRef])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
        ];
        const state = readState(subscription, auth.ownerId);
        const boundIds: string[] = [];
        for (const grantId of [state?.active?.grantId, state?.pending?.grantId]) {
          if (grantId !== undefined && grantId !== auth.grantId && !boundIds.includes(grantId)) boundIds.push(grantId);
        }
        const boundRefs = boundIds.map(grantRefOf);
        const boundSnapshots = boundRefs.length === 0 ? [] : await read(tx, operation, boundRefs);
        const accessSnapshots = await readAccess(tx, operation, owner, requestMetaRef);
        // 全ての読取りの後の最新時刻で、markerとowner・要求Grantのmetadata・利用許可を確かめる（不成立は開封前に全無書込みで失敗）。
        const at = liveNow(operation);
        requireMarker(marker);
        if (!ownerActive(owner, at)) throw registrationError('grant_inactive');
        const generation = ownerGeneration(owner.data());
        if (!grantLive(requestGrant, auth.ownerId, auth.grantId, at)) throw registrationError('grant_inactive');
        requireAccess(accessSnapshots, auth.ownerId, owner);
        return {
          subscription: versionOf(subscription),
          generation,
          grants: [
            { grantId: auth.grantId, ref: requestGrantRef, snapshot: requestGrant },
            ...boundIds.map((grantId, index) => ({ grantId, ref: boundRefs[index]!, snapshot: boundSnapshots[index]! })),
          ],
        };
      });

      // 閉包の外で、取得済みの各Grant snapshotの証拠を順に作る（最大3回、同じ元operation）。
      const proven = await proveAll(operation, auth.ownerId, first.grants);
      const grantRefs = proven.map((entry) => entry.ref);

      // 分類transaction: 同じrefを再読し、購読の精密版とowner世代の完全一致・marker・最新owner・要求Grant proof active・利用許可を
      // 要求する（challengeの前の最終確認）。
      const classified = await run(operation, async (tx) => {
        const [owner, marker, subscription, ...grantSnapshots] = (await read(tx, operation, [ownerRef, markerRef, subscriptionRef, ...grantRefs])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
          ...DocumentSnapshot[],
        ];
        const accessSnapshots = await readAccess(tx, operation, owner, requestMetaRef);
        const at = decisionTime(operation);
        const { generation, verdicts } = authorize(operation, auth, { owner, marker, grants: grantSnapshots }, proven, at);
        requireAccess(accessSnapshots, auth.ownerId, owner);
        if (generation !== first.generation || !sameDocVersion(versionOf(subscription), first.subscription)) throw registrationError('conflict');
        const state = readState(subscription, auth.ownerId) ?? emptyKmsState();
        projectBindings(state, at, verdictLookup(verdicts));
        const decision = classify(state, auth, request, at);
        // challengeの枝は掃除も含め書かない（期待版を自分の書込みで変えない）。
        if (decision.kind === 'challenge') return decision;
        requireKmsDocumentSizeOrUnavailable(auth.ownerId, state);
        liveNow(operation);
        tx.set(subscriptionRef, kmsStateDocument(auth.ownerId, state));
        return decision;
      });

      liveNow(operation);
      if (classified.kind === 'pending') return Object.freeze({ kind: 'pending' as const });
      if (classified.kind === 'extended') return Object.freeze({ kind: 'extended' as const, id: request.id, expiresAt: classified.expiresAt });
      const plan = Object.freeze(Object.create(null) as object);
      plans.set(
        plan,
        Object.freeze({
          auth,
          request,
          operation,
          ownerRef,
          subscriptionRef,
          metaRef: requestMetaRef,
          subscription: first.subscription,
          generation: first.generation,
          grants: Object.freeze(proven),
        }),
      );
      return Object.freeze({ kind: 'challenge' as const, plan: plan as KmsSubscriptionChallengePlan });
    } catch (error) {
      throw fixed(error);
    }
  }

  function requireKmsDocumentSizeOrUnavailable(ownerId: string, state: KmsMutableState): void {
    try {
      requireKmsDocumentSize(ownerId, state);
    } catch {
      throw registrationError('unavailable');
    }
  }

  async function activate(planInput: unknown, capsulesInput: unknown, operationInput: unknown): Promise<{ readonly id: string; readonly expiresAt: number | null }> {
    try {
      // planは最初のactivate呼出しで1回だけ消費する（以後の失敗・成功にかかわらず再利用0）。
      const record = isObject(planInput) ? plans.get(planInput) : undefined;
      if (record === undefined) fail();
      plans.delete(planInput as object);
      const operation = copyOperation(operationInput);
      if (operation.deadlineAt !== record.operation.deadlineAt || operation.signal !== record.operation.signal) fail();
      const capsules = copyCapsules(capsulesInput, policy);
      const { auth, request, ownerRef, subscriptionRef, metaRef } = record;
      liveNow(operation);

      const grantRefs = record.grants.map((entry) => entry.ref);
      const result = await run(operation, async (tx) => {
        const [owner, marker, subscription, ...grantSnapshots] = (await read(tx, operation, [ownerRef, markerRef, subscriptionRef, ...grantRefs])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
          ...DocumentSnapshot[],
        ];
        // challengeの待機中の停止・再登録（世代の変化）も、この最終transactionで拒否する。
        const accessSnapshots = await readAccess(tx, operation, owner, metaRef);
        const at = decisionTime(operation);
        const { generation, verdicts } = authorize(operation, auth, { owner, marker, grants: grantSnapshots }, record.grants, at);
        requireAccess(accessSnapshots, auth.ownerId, owner);
        // challengeの待機中の取消・再登録・延長・Grantの再保存は、同じid/hashへ戻っていても版違いのconflict（自動の再challenge・外側retry0）。
        if (generation !== record.generation || !sameDocVersion(versionOf(subscription), record.subscription)) throw registrationError('conflict');
        const state = readState(subscription, auth.ownerId) ?? emptyKmsState();
        projectBindings(state, at, verdictLookup(verdicts));
        const active = applyActivation(state, auth, request, capsules, at);
        requireKmsDocumentSizeOrUnavailable(auth.ownerId, state);
        liveNow(operation);
        tx.set(subscriptionRef, kmsStateDocument(auth.ownerId, state));
        return { id: active.id, expiresAt: active.expiresAt };
      });
      liveNow(operation);
      return Object.freeze({ id: result.id, expiresAt: result.expiresAt });
    } catch (error) {
      throw fixed(error);
    }
  }

  async function cancel(authInput: unknown, requestInput: unknown, operationInput: unknown): Promise<void> {
    try {
      const operation = copyOperation(operationInput);
      const auth = copyAuth(authInput);
      const { id } = copyCancel(requestInput);
      liveNow(operation);
      const ownerRef = ownerRefOf(auth.ownerId);
      const requestGrantRef = grantRefOf(auth.grantId);
      const subscriptionRef = subscriptionDocs.doc(auth.ownerId);

      // 初回snapshot: 要求Grantだけを証拠化するために読む（書込みなし）。対象のactive/pending Grantの開封を取消の条件にしない。
      const requestGrant = await run(operation, async (tx) => {
        const [owner, marker, grant] = (await read(tx, operation, [ownerRef, markerRef, requestGrantRef])) as [DocumentSnapshot, DocumentSnapshot, DocumentSnapshot];
        const at = liveNow(operation);
        requireMarker(marker);
        if (!ownerActive(owner, at)) throw registrationError('grant_inactive');
        ownerGeneration(owner.data());
        if (!grantLive(grant, auth.ownerId, auth.grantId, at)) throw registrationError('grant_inactive');
        return grant;
      });
      const proven = await proveAll(operation, auth.ownerId, [{ grantId: auth.grantId, ref: requestGrantRef, snapshot: requestGrant }]);

      // 確定transaction: 最新のowner・marker・購読・要求Grantを同じsnapshotで認可し、最新の同identityを取り消して世代を最新値+1にする。
      // 初回の購読版・世代へは固定しない。
      await run(operation, async (tx) => {
        const [owner, marker, subscription, grant] = (await read(tx, operation, [ownerRef, markerRef, subscriptionRef, requestGrantRef])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
        ];
        const at = decisionTime(operation);
        const { generation } = authorize(operation, auth, { owner, marker, grants: [grant] }, proven, at);
        const next = nextGeneration(generation);
        const state = readState(subscription, auth.ownerId) ?? emptyKmsState();
        const swept = sweepKmsState(state, at);
        const changed = applyCancel(state, id);
        if (swept || changed) requireKmsDocumentSizeOrUnavailable(auth.ownerId, state);
        liveNow(operation);
        // ownerの他のfield（lastActiveAt・revokedAt・sealedUid等）は変えない。購読は実際に変わった時だけ既存version2で保存する
        // （未作成の購読へ空文書を作らない・未検証idを既知にしない）。
        tx.update(ownerRef, { [SUBSCRIPTION_GENERATION_FIELD]: next });
        if (swept || changed) tx.set(subscriptionRef, kmsStateDocument(auth.ownerId, state));
      });
      liveNow(operation);
    } catch (error) {
      throw fixed(error);
    }
  }

  return Object.freeze({
    prepare: prepare as KmsSubscriptionRegistrationStore['prepare'],
    activate: activate as KmsSubscriptionRegistrationStore['activate'],
    cancel: cancel as KmsSubscriptionRegistrationStore['cancel'],
  });
}
