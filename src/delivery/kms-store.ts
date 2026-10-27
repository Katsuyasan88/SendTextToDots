// KMS購読profileの本文なしCommand保存。sttdDelivery/{t270_<UUID>}配下のcommands/ownersはversion1の文書・状態・判定（contract.ts）を使い、
// 認可は同じ借用dbの接続保存のowner・Grantと、KMS購読（sttdAuth/{t268_<UUID>}のconfig marker・version2 owner文書）を同じtransactionで読む。
// 全transactionの閉包は、全読取り→最新時計→同期の判定（contract.ts・kms-subscription-format.ts）→書込みだけで、暗号・開封・HTTP・
// 乱数・ログを入れない（試験の観測hookだけ）。各callは呼出し元の不変の{deadlineAt, signal}を1回捕捉し、開始前・各await後・更新直前・
// 返却直前にsignal→時計→signalで検査する。期限・中止の後は新しいSDK呼出し・更新・遅い成功の採用をしない（既に始めたSDKのcommitの
// 物理的な取消は約束しない）。旧secretのsealed/hashはRAMだけで渡し、Command・controlへ保存しない。

import { types } from 'node:util';

import type { DocumentReference, DocumentSnapshot, Firestore, Transaction } from '@google-cloud/firestore';

import type { Clock } from '../policy.js';
import { isHash, isUuid } from '../storage/firestore/checks.js';
import { parseKmsState, requireKmsMarker, type KmsMutableState, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';
import { AUTH_STORAGE_ROOT, KMS_SUBSCRIPTION_CONFIG_DOC } from '../storage/firestore/kms-subscription-format.js';
import {
  commandDocData,
  decideAbandon,
  decideCancel,
  decideDispatch,
  decideFinish,
  decidePrepare,
  DeliveryStateError,
  ownerControlData,
  parseCommandDoc,
  parseOwnerControl,
  usable,
  type AuthorizationView,
  type CancelDecision,
  type CommandDoc,
  type DeliveryReason,
  type DispatchDecision,
  type NewCommandRequest,
  type PrepareDecision,
} from './contract.js';

/** 配送の保存root（sttdDelivery/{namespace}）。 */
export const DELIVERY_STORAGE_ROOT = 'sttdDelivery';
export type TransactionOp = 'prepare' | 'dispatch' | 'finish' | 'abandon' | 'cancel';
export type FinalState = 'delivered' | 'failed' | 'expired' | 'delivery_unknown';

const NAMESPACE_PATTERN = /^t270_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COMMAND_KEY = /^[0-9a-f]{64}$/;
/** SDKのtransactionの最大実行回数（既定と同じ5。外側で自動の再試行・再開をしない）。 */
const MAX_TRANSACTION_ATTEMPTS = 5;
const OPERATION_KEYS = ['deadlineAt', 'signal'];
const EVIDENCE_KEYS = ['sealed', 'secretHash'];

/** KMS profileのCommand namespace（`t270_<小文字UUID>`）。 */
export function isKmsDeliveryNamespace(value: unknown): value is string {
  return typeof value === 'string' && NAMESPACE_PATTERN.test(value);
}

/** 各callの元要求の期限（clockと同じ基準の安全な整数ms）と中止。 */
export interface KmsDeliveryOperation {
  readonly deadlineAt: number;
  readonly signal?: AbortSignal | undefined;
}

export type KmsDeliveryOperationErrorCode = 'invalid_input' | 'foreign_reference' | 'timed_out' | 'aborted' | 'unavailable';

/** 期限・中止・SDK失敗・入力/参照の不正の固定error。元のSDK error・causeを持たない。保存の形の不正はDeliveryStateError。 */
export class KmsDeliveryOperationError extends Error {
  constructor(readonly code: KmsDeliveryOperationErrorCode) {
    super(`kms delivery: ${code}`);
    this.name = 'KmsDeliveryOperationError';
  }
}

/** 同じ猶予の旧secret（同じsnapshotのsealed・hash・until）。RAMだけで、保存しない。 */
export interface KmsPreparedPrevious {
  readonly sealed: string;
  readonly secretHash: string;
  readonly until: number;
}

export type KmsPrepareDecision =
  | Exclude<PrepareDecision, { readonly kind: 'prepared' }>
  | {
      readonly kind: 'prepared';
      readonly doc: CommandDoc;
      readonly sealedUrl: string;
      readonly sealedSecret: string;
      readonly previous: KmsPreparedPrevious | null;
    };

/** dispatchへ渡す旧secretの証拠（prepareで受け取った同じsealed・hash）。 */
export interface KmsPreviousEvidence {
  readonly sealed: string;
  readonly secretHash: string;
}

/** 接続保存のうち、この保存が使う同期の参照・判定だけ（呼出しはfactoryで捕捉済み）。 */
export interface KmsDeliveryConnect {
  ownerDocRef(ownerId: string): DocumentReference;
  grantDocRef(grantId: string): DocumentReference;
  ownerDocActive(data: Record<string, unknown> | undefined, now: number): boolean;
  grantDocLive(data: Record<string, unknown> | undefined, ownerId: string, grantId: string, now: number): boolean;
  /** owner文書のdataから本人の利用許可recordの参照（無ければnull）。 */
  accessDocRefForOwner(data: Record<string, unknown> | undefined): DocumentReference | null;
  /** Grantの同意記録（利用許可の世代を持つ）の参照。 */
  grantMetaDocRef(grantId: string): DocumentReference;
  /** 許可recordだけからの利用許可。 */
  accessUseDecision(access: { readonly exists: boolean; readonly data: unknown }): 'allowed' | 'denied' | 'unavailable';
  /** 許可recordとGrantの同意記録からの、このowner・Grantの新規利用の可否。 */
  grantUseDecision(
    access: { readonly exists: boolean; readonly data: unknown },
    meta: { readonly exists: boolean; readonly data: unknown },
    ownerId: string,
  ): 'allowed' | 'denied' | 'unavailable';
}

/**
 * 暗号文の経路だけが渡す送出権transaction内の鍵の照合（同じdbのtransactionで読むだけ。書込み0）。使えればtrue。
 * 平文の経路は渡さない（鍵への依存を加えない）。
 */
export type DispatchKeyCheck = (tx: Transaction) => Promise<boolean>;

export interface KmsRequestDeliveryStoreDeps {
  /** 借用したinstance（terminateしない）。全参照はここから作り、connectの参照もこのinstanceのものだけを受け付ける。 */
  readonly db: Firestore;
  readonly namespace: string;
  readonly connect: KmsDeliveryConnect;
  readonly hash: (purpose: string, value: string) => string;
  readonly clock: Clock;
  /** factoryで1回捕捉したKMS購読のpolicy（codecと同じ）。 */
  readonly policy: KmsSubscriptionPolicy;
  /** transactionの関数が実行されるたびに呼ぶ（試験の観測だけ。同期で、外へ送らない）。 */
  readonly onTransaction?: ((op: TransactionOp) => void) | undefined;
}

/** 呼出し元のoperationを、自分のdata propertyだけから1回読んで凍結する（getter・Proxy・余分なkeyを拒否）。 */
export function captureOperation(value: unknown): Readonly<{ deadlineAt: number; signal: AbortSignal | undefined }> {
  const invalid = () => new KmsDeliveryOperationError('invalid_input');
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) throw invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !OPERATION_KEYS.includes(key)) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    taken.set(key, descriptor.value);
  }
  const deadlineAt = taken.get('deadlineAt');
  const signal = taken.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) throw invalid();
  if (signal !== undefined && (typeof signal !== 'object' || signal === null || types.isProxy(signal) || !(signal instanceof AbortSignal))) {
    throw invalid();
  }
  return Object.freeze({ deadlineAt, signal: signal as AbortSignal | undefined });
}

/**
 * まだ進めてよいかを、最新のsignal→時計→signalの順に見て、その時刻を返す（時計の観測中に起きた中止も見る）。読めない・有限でない
 * 時計と期限到達はtimed_out、中止はaborted。
 */
export function liveNow(clock: Clock, operation: { readonly deadlineAt: number; readonly signal: AbortSignal | undefined }): number {
  if (operation.signal?.aborted) throw new KmsDeliveryOperationError('aborted');
  let at: unknown;
  try {
    at = clock.now();
  } catch {
    at = Number.NaN;
  }
  if (operation.signal?.aborted) throw new KmsDeliveryOperationError('aborted');
  if (typeof at !== 'number' || !Number.isFinite(at) || !(at < operation.deadlineAt)) throw new KmsDeliveryOperationError('timed_out');
  return at;
}

/** 固定errorへ正規化する（元の例外・SDK error・文書の値を運ばない）。 */
function fixed(error: unknown): Error {
  if (error instanceof KmsDeliveryOperationError) return new KmsDeliveryOperationError(error.code);
  if (error instanceof DeliveryStateError) return new DeliveryStateError();
  return new KmsDeliveryOperationError('unavailable');
}

/**
 * 残りが正の時だけstartでSDK呼出しを始め、元期限か中止までに決まらなければ待つのをやめる（始めたSDK処理の取消とは扱わず、
 * 後のrejectは握りつぶし、後の完了は使わない）。結果の公開直前にも同じ検査を行い、遅い成功を採用しない。
 */
function bounded<T>(clock: Clock, operation: Readonly<{ deadlineAt: number; signal: AbortSignal | undefined }>, start: () => Promise<T>): Promise<T> {
  let remaining: number;
  try {
    remaining = operation.deadlineAt - liveNow(clock, operation);
  } catch (error) {
    return Promise.reject(fixed(error));
  }
  let promise: Promise<T>;
  try {
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
    const onAbort = () => finish(() => reject(new KmsDeliveryOperationError('aborted')));
    const timer = setTimeout(() => finish(() => reject(new KmsDeliveryOperationError('timed_out'))), Math.max(1, Math.ceil(remaining)));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
    promise.then(
      (value) =>
        finish(() => {
          try {
            liveNow(clock, operation);
            resolve(value);
          } catch (error) {
            reject(fixed(error));
          }
        }),
      (error: unknown) => finish(() => reject(fixed(error))),
    );
  });
}

function requireOwner(ownerId: unknown): asserts ownerId is string {
  if (!isUuid(ownerId)) throw new KmsDeliveryOperationError('invalid_input');
}

function requireCommandKey(commandKey: unknown): asserts commandKey is string {
  if (typeof commandKey !== 'string' || !COMMAND_KEY.test(commandKey)) throw new KmsDeliveryOperationError('invalid_input');
}

/** dispatchの旧secretの証拠。nullか、exactな{sealed, secretHash}のplain data（getter・Proxy・余分なkeyを拒否）。 */
function copyEvidence(value: unknown): KmsPreviousEvidence | null {
  if (value === null) return null;
  const invalid = () => new KmsDeliveryOperationError('invalid_input');
  if (typeof value !== 'object' || types.isProxy(value) || Array.isArray(value)) throw invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const own = Reflect.ownKeys(value);
  if (own.length !== EVIDENCE_KEYS.length) throw invalid();
  const taken = new Map<string, unknown>();
  for (const key of own) {
    if (typeof key !== 'string' || !EVIDENCE_KEYS.includes(key)) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    taken.set(key, descriptor.value);
  }
  const sealed = taken.get('sealed');
  const secretHash = taken.get('secretHash');
  if (typeof sealed !== 'string' || sealed.length === 0 || !isHash(secretHash)) throw invalid();
  return Object.freeze({ sealed, secretHash });
}

/** 同期の購読reader。markerとowner文書の検査は純粋関数で、不正は全て保存の形の不正（DeliveryStateError）。 */
function createSubscriptionReader(db: Firestore, policy: KmsSubscriptionPolicy) {
  const root = db.collection(AUTH_STORAGE_ROOT).doc(policy.namespace);
  const markerRef = root.collection('config').doc(KMS_SUBSCRIPTION_CONFIG_DOC);
  const subscriptions = root.collection('subscriptions');
  return Object.freeze({
    markerRef,
    subscriptionRef: (ownerId: string): DocumentReference => subscriptions.doc(ownerId),
    check(snapshot: DocumentSnapshot): void {
      if (!snapshot.exists) throw new DeliveryStateError();
      try {
        requireKmsMarker(snapshot.data(), policy);
      } catch {
        throw new DeliveryStateError();
      }
    },
    read(snapshot: DocumentSnapshot, ownerId: string): KmsMutableState | undefined {
      if (!snapshot.exists) return undefined;
      try {
        return parseKmsState(snapshot.data(), ownerId, policy);
      } catch {
        throw new DeliveryStateError();
      }
    },
  });
}

type Captured = Readonly<{ deadlineAt: number; signal: AbortSignal | undefined }>;

/** 同じtransactionで読んだ認可の正本（全ての読取りの後の最新時刻つき）。 */
interface AuthorizationSnapshot {
  readonly command: DocumentSnapshot;
  readonly control: DocumentSnapshot;
  readonly ownerRef: DocumentReference;
  readonly state: KmsMutableState | undefined;
  readonly view: AuthorizationView;
  readonly now: number;
  /** 同じtransactionで読んだowner/Grant/許可のsnapshotから、指定時刻のviewを作り直す（純粋。DBの再読取り0）。 */
  readonly viewAt: (now: number) => AuthorizationView;
}

export class KmsRequestDeliveryStore {
  readonly #d: KmsRequestDeliveryStoreDeps;
  readonly #root: DocumentReference;
  readonly #reader: ReturnType<typeof createSubscriptionReader>;

  constructor(deps: KmsRequestDeliveryStoreDeps) {
    if (!isKmsDeliveryNamespace(deps.namespace)) throw new KmsDeliveryOperationError('invalid_input');
    this.#d = deps;
    this.#root = deps.db.collection(DELIVERY_STORAGE_ROOT).doc(deps.namespace);
    this.#reader = createSubscriptionReader(deps.db, deps.policy);
  }

  commandKey(ownerId: string, commandId: string): string {
    return this.#d.hash(`t270:${this.#d.namespace}:command`, `${ownerId}\0${commandId}`);
  }

  #commandRef(commandKey: string): DocumentReference {
    return this.#root.collection('commands').doc(commandKey);
  }

  #controlRef(ownerId: string): DocumentReference {
    return this.#root.collection('owners').doc(ownerId);
  }

  /** connectが返した参照は、借用した同じinstanceのものだけを使う（別instanceは同じproject文字列でも通信・書込み前に拒否）。 */
  #own(ref: unknown): DocumentReference {
    if (typeof ref !== 'object' || ref === null || types.isProxy(ref) || (ref as { firestore?: unknown }).firestore !== this.#d.db) {
      throw new KmsDeliveryOperationError('foreign_reference');
    }
    return ref as DocumentReference;
  }

  #run<T>(op: TransactionOp, operation: Captured, body: (tx: Transaction) => Promise<T>): Promise<T> {
    const { clock } = this.#d;
    return bounded(clock, operation, () =>
      this.#d.db.runTransaction(
        async (tx) => {
          this.#d.onTransaction?.(op);
          liveNow(clock, operation);
          return body(tx);
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ),
    );
  }

  /** 1回の読取りの後の検査（各awaitの後）。 */
  async #read(tx: Transaction, operation: Captured, refs: readonly DocumentReference[]): Promise<DocumentSnapshot[]> {
    const snapshots = await tx.getAll(...refs);
    liveNow(this.#d.clock, operation);
    if (snapshots.length !== refs.length) throw new KmsDeliveryOperationError('unavailable');
    return snapshots;
  }

  /**
   * Command・control・同dbのowner・購読marker・owner文書を同じsnapshotで読み、有効な購読が束縛したGrantも読んでから、最新の時計で
   * 認可の正本を作る。markerが無い・別policy・未知版・不正capsuleは保存の形の不正（fallback・修復しない）。
   */
  async #authorization(tx: Transaction, operation: Captured, ownerId: string, commandKey: string, ownerRef: DocumentReference): Promise<AuthorizationSnapshot> {
    const { connect } = this.#d;
    const [command, control, owner, marker, subscription] = await this.#read(tx, operation, [
      this.#commandRef(commandKey),
      this.#controlRef(ownerId),
      ownerRef,
      this.#reader.markerRef,
      this.#reader.subscriptionRef(ownerId),
    ]) as [DocumentSnapshot, DocumentSnapshot, DocumentSnapshot, DocumentSnapshot, DocumentSnapshot];
    const state = this.#reader.read(subscription, ownerId);
    const grantId = state?.active?.grantId;
    // 利用許可: owner文書のidentityHashから許可recordを、有効な購読が束縛したGrantの同意記録（世代）と一緒に同じtransactionで読む。
    const accessRefInput = connect.accessDocRefForOwner(owner.data());
    if (accessRefInput === null) throw new DeliveryStateError();
    const accessRef = this.#own(accessRefInput);
    let grantData: Record<string, unknown> | undefined;
    let access: DocumentSnapshot;
    let meta: DocumentSnapshot | undefined;
    if (grantId !== undefined) {
      const [grant, accessSnapshot, metaSnapshot] = await this.#read(tx, operation, [
        this.#own(connect.grantDocRef(grantId)),
        accessRef,
        this.#own(connect.grantMetaDocRef(grantId)),
      ]);
      grantData = grant!.data();
      access = accessSnapshot!;
      meta = metaSnapshot!;
    } else {
      [access] = (await this.#read(tx, operation, [accessRef])) as [DocumentSnapshot];
    }
    // 全ての読取りの後の最新時刻で判断する。
    const now = liveNow(this.#d.clock, operation);
    this.#reader.check(marker);
    const accessInput = { exists: access.exists, data: access.exists ? access.data() : undefined };
    const decision =
      grantId === undefined || meta === undefined
        ? connect.accessUseDecision(accessInput)
        : connect.grantUseDecision(accessInput, { exists: meta.exists, data: meta.exists ? meta.data() : undefined }, ownerId);
    // 読めない・不正な許可/同意記録は固定の一時障害（許可・拒否のどちらへも読み替えない。送出しない）。
    if (decision !== 'allowed' && decision !== 'denied') throw new DeliveryStateError();
    const ownerData = owner.data();
    const viewAt = (at: number): AuthorizationView => ({
      ownerActive: connect.ownerDocActive(ownerData, at),
      subscription: state,
      grantLive: grantId !== undefined && connect.grantDocLive(grantData, ownerId, grantId, at),
      access: decision,
    });
    return { command, control, ownerRef, state, now, view: viewAt(now), viewAt };
  }

  /** ownerの処理中参照が、このcommandを指していれば外す。controlDataは同じtransactionで先に読んだ値（ここでは読まない）。 */
  #release(tx: Transaction, ownerId: string, commandKey: string, controlData: unknown): void {
    if (controlData === undefined) return;
    const control = parseOwnerControl(controlData, ownerId);
    if (control.current?.commandKey === commandKey) tx.set(this.#controlRef(ownerId), ownerControlData(ownerId, control.rate, null));
  }

  /**
   * 受付（decidePrepare）。準備状態を確定した時だけ、採用された同じsnapshotの旧secretからsealed・hash・untilを写して
   * RAMで返す（Command・controlへは保存しない）。
   */
  prepare(request: NewCommandRequest, operation: KmsDeliveryOperation): Promise<KmsPrepareDecision> {
    let captured: Captured;
    let ownerRef: DocumentReference;
    try {
      captured = captureOperation(operation);
      requireOwner(request.ownerId);
      requireCommandKey(request.commandKey);
      ownerRef = this.#own(this.#d.connect.ownerDocRef(request.ownerId));
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    const { ownerId, commandKey } = request;
    return this.#run('prepare', captured, async (tx): Promise<KmsPrepareDecision> => {
      const snapshot = await this.#authorization(tx, captured, ownerId, commandKey, ownerRef);
      const existing = parseCommandDoc(snapshot.command.data(), ownerId);
      const control = parseOwnerControl(snapshot.control.data(), ownerId);
      const { now } = snapshot;
      const decision = decidePrepare(usable(existing, now), control, snapshot.view, request, now);
      if (decision.kind !== 'prepared') return decision;
      const latest = snapshot.state?.active?.previousSecret ?? null;
      if (decision.previous !== null && (latest === null || latest.sealed !== decision.previous.sealed || latest.until !== decision.previous.until)) {
        throw new DeliveryStateError();
      }
      const previous: KmsPreparedPrevious | null =
        decision.previous === null || latest === null ? null : { sealed: latest.sealed, secretHash: latest.secretHash, until: latest.until };
      // 更新の直前の検査。
      liveNow(this.#d.clock, captured);
      const commandRef = this.#commandRef(commandKey);
      // 利用期限を過ぎて残っている古い文書は、新しい準備状態で置き換える（古い本文は元々保存していない）。
      if (existing === undefined) tx.create(commandRef, commandDocData(decision.doc));
      else tx.set(commandRef, commandDocData(decision.doc));
      tx.set(this.#controlRef(ownerId), decision.control);
      tx.update(snapshot.ownerRef, { lastActiveAt: now });
      return { kind: 'prepared', doc: decision.doc, sealedUrl: decision.sealedUrl, sealedSecret: decision.sealedSecret, previous };
    });
  }

  /**
   * 送出権の確定（decideDispatch）。旧secretの証拠は、同じsnapshotの最新の旧secretのsealed・hashの両方と一致し、
   * 最新時刻<untilの時だけpreviousValid。猶予切れ・旧組の差替えだけなら現行secretだけで送出権を与える。
   */
  dispatch(
    ownerId: string,
    commandKey: string,
    attemptId: string,
    previous: KmsPreviousEvidence | null,
    operation: KmsDeliveryOperation,
    keyCheck?: DispatchKeyCheck,
  ): Promise<DispatchDecision> {
    let captured: Captured;
    let evidence: KmsPreviousEvidence | null;
    let ownerRef: DocumentReference;
    try {
      captured = captureOperation(operation);
      requireOwner(ownerId);
      requireCommandKey(commandKey);
      evidence = copyEvidence(previous);
      ownerRef = this.#own(this.#d.connect.ownerDocRef(ownerId));
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    return this.#run('dispatch', captured, async (tx): Promise<DispatchDecision> => {
      const snapshot = await this.#authorization(tx, captured, ownerId, commandKey, ownerRef);
      const current = parseCommandDoc(snapshot.command.data(), ownerId);
      const controlData = snapshot.control.data();
      let now = snapshot.now;
      // 暗号文の経路だけ: 同じtransactionの中で鍵ring（同じdb）の最新の本人・scope・kid・状態・期限を読む（期限は鍵の読取り後の最新時刻）。
      // 使えない鍵は利用不許可と同じく送出権を与えずに終端へ確定する（送出0）。読取りは書込みより前。鍵の読取りを待った後は、
      // 同じtransactionで読んだowner/Grant/許可のsnapshotから最新時刻でview全体を作り直し（無活動・Grant期限を古い時刻で判定しない）、
      // 以後の判定もその時刻で行う。
      let view = snapshot.view;
      if (keyCheck !== undefined) {
        const usable = await keyCheck(tx);
        now = liveNow(this.#d.clock, captured);
        view = snapshot.viewAt(now);
        if (!usable) view = { ...view, access: 'denied' };
      }
      const decision = decideDispatch(current, view, attemptId, evidence?.sealed ?? null, now);
      liveNow(this.#d.clock, captured);
      if (decision.kind !== 'unchanged') tx.set(this.#commandRef(commandKey), commandDocData(decision.doc));
      if (decision.kind === 'refused') this.#release(tx, ownerId, commandKey, controlData);
      if (decision.kind !== 'granted') return decision;
      const latest = snapshot.state?.active?.previousSecret ?? null;
      const previousValid =
        decision.previousValid &&
        evidence !== null &&
        latest !== null &&
        latest.sealed === evidence.sealed &&
        latest.secretHash === evidence.secretHash &&
        now < latest.until;
      return { kind: 'granted', doc: decision.doc, previousValid };
    });
  }

  /**
   * 送出の結果の確定。stopSubscriptionの時はmarkerと購読も同じtransactionで読み、受付時に固定した同じid・Grant・現行hashの購読だけの
   * activeを外す（既知の送信先・保留・終わり方・version2は残す）。別版・置換済み・同じGrantでもsecret変更済みには触らない。
   */
  finish(
    ownerId: string,
    commandKey: string,
    attemptId: string,
    state: FinalState,
    reason: DeliveryReason,
    stopSubscription: boolean,
    operation: KmsDeliveryOperation,
  ): Promise<CommandDoc | undefined> {
    let captured: Captured;
    try {
      captured = captureOperation(operation);
      requireOwner(ownerId);
      requireCommandKey(commandKey);
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    const stop = stopSubscription === true;
    return this.#run('finish', captured, async (tx): Promise<CommandDoc | undefined> => {
      const refs = [this.#commandRef(commandKey), this.#controlRef(ownerId)];
      if (stop) refs.push(this.#reader.markerRef, this.#reader.subscriptionRef(ownerId));
      const [command, control, marker, subscription] = await this.#read(tx, captured, refs);
      const now = liveNow(this.#d.clock, captured);
      const current = parseCommandDoc(command!.data(), ownerId);
      let active: KmsMutableState['active'] = null;
      if (stop) {
        this.#reader.check(marker!);
        active = this.#reader.read(subscription!, ownerId)?.active ?? null;
      }
      const next = decideFinish(current, attemptId, state, reason, now);
      if (next === undefined) return current;
      liveNow(this.#d.clock, captured);
      tx.set(this.#commandRef(commandKey), commandDocData(next));
      this.#release(tx, ownerId, commandKey, control!.data());
      const destination = next.destination;
      if (
        stop &&
        destination !== null &&
        active !== null &&
        active.id === destination.subscriptionId &&
        active.grantId === destination.grantId &&
        active.secretHash === destination.secretHash
      ) {
        tx.update(this.#reader.subscriptionRef(ownerId), { active: null });
      }
      return next;
    });
  }

  /** 送っていないことが確かな時の終わり方（decideAbandon）。購読は読まない。 */
  abandon(ownerId: string, commandKey: string, attemptId: string, reason: DeliveryReason, operation: KmsDeliveryOperation): Promise<CommandDoc | undefined> {
    let captured: Captured;
    try {
      captured = captureOperation(operation);
      requireOwner(ownerId);
      requireCommandKey(commandKey);
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    return this.#run('abandon', captured, async (tx): Promise<CommandDoc | undefined> => {
      const [command, control] = await this.#read(tx, captured, [this.#commandRef(commandKey), this.#controlRef(ownerId)]);
      const now = liveNow(this.#d.clock, captured);
      const current = parseCommandDoc(command!.data(), ownerId);
      const next = decideAbandon(current, attemptId, reason, now);
      if (next === undefined) return current;
      liveNow(this.#d.clock, captured);
      tx.set(this.#commandRef(commandKey), commandDocData(next));
      this.#release(tx, ownerId, commandKey, control!.data());
      return next;
    });
  }

  /** 中止（decideCancel）。ownerの有効性だけを確かめ、購読markerは読まない（壊れた購読が中止を妨げない）。 */
  cancel(ownerId: string, commandKey: string, operation: KmsDeliveryOperation): Promise<CancelDecision | 'denied'> {
    let captured: Captured;
    let ownerRef: DocumentReference;
    try {
      captured = captureOperation(operation);
      requireOwner(ownerId);
      requireCommandKey(commandKey);
      ownerRef = this.#own(this.#d.connect.ownerDocRef(ownerId));
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    return this.#run('cancel', captured, async (tx): Promise<CancelDecision | 'denied'> => {
      const [command, control, owner] = await this.#read(tx, captured, [this.#commandRef(commandKey), this.#controlRef(ownerId), ownerRef]);
      const now = liveNow(this.#d.clock, captured);
      const current = parseCommandDoc(command!.data(), ownerId);
      if (!this.#d.connect.ownerDocActive(owner!.data(), now)) return 'denied';
      const decision = decideCancel(usable(current, now), ownerId, now);
      if (decision.kind === 'observed') return decision;
      liveNow(this.#d.clock, captured);
      const commandRef = this.#commandRef(commandKey);
      if (decision.kind === 'tombstone') {
        if (current === undefined) tx.create(commandRef, commandDocData(decision.doc));
        else tx.set(commandRef, commandDocData(decision.doc));
      } else {
        tx.set(commandRef, commandDocData(decision.doc));
        this.#release(tx, ownerId, commandKey, control!.data());
      }
      return decision;
    });
  }

  /** 照会。transactionを使わず読むだけ（書込み・配送を起こさない）。利用期限は返却直前の時刻で投影する。 */
  read(ownerId: string, commandKey: string, operation: KmsDeliveryOperation): Promise<CommandDoc | undefined> {
    let captured: Captured;
    try {
      captured = captureOperation(operation);
      requireOwner(ownerId);
      requireCommandKey(commandKey);
    } catch (error) {
      return Promise.reject(fixed(error));
    }
    return bounded(this.#d.clock, captured, () => this.#commandRef(commandKey).get()).then((snapshot) => {
      try {
        const doc = parseCommandDoc(snapshot.data(), ownerId);
        return usable(doc, liveNow(this.#d.clock, captured));
      } catch (error) {
        throw fixed(error);
      }
    });
  }
}
