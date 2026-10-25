// KMS接続server（connect/kms-server.ts）のConnectionServiceへ渡す、ownerの購読の見え方（SubscriptionView）。
// 登録保存口と同じ文書（sttdAuth/{t268}/config/kms-subscription・sttdAuth/{t268}/subscriptions/{ownerId}・sttdConnect/{t256}/owners/{ownerId}・
// sttdConnect/{t256}/oidc/Grant_<64hex>）を、借用した同じdb instanceだけで読む。初回の読取りだけのtransactionでmarker・owner・取消世代・購読の
// 精密版と、active/pendingが束縛したGrant（重複なし・最大2）を捕捉し、Grantのscope同版証拠はtransactionの外でhelperを各1回作る。
// 最終transactionで同じ文書を最新snapshotで照合し（marker・owner有効性・世代・購読の期待版・Grant証拠のstale）、違えばconflict（自動の再読・
// re-prove・再試行0）。一致すればprojectBindings（期限・旧secret猶予のsweep→inactiveなGrantのactive/pending取下げ）を適用し、変わった
// 既存購読だけversion2で保存する（未作成の購読へ空文書を作らない）。owner文書（活動時刻・取消世代・失効・封緘UID）へは書かない。
// callback URL/secretは開封しない。開封はGrantの証拠だけ（decrypt）で、封緘・HTTP・乱数・ログ0。transactionの閉包は全読取り→最新時計→同期の
// 照合・投影→書込みだけで、KMSを入れない（SDKが再実行しても同じ）。db・connect・KMS transport・clockは借用し、閉じない。
// 各要求は元deadlineと開始+20000msの短い方を一度だけ決め（延長しない）、親signalとdisposeへ結んだ子operationを全工程へ同じobjectで渡す。
// 開始前・各await後・次のI/O前・閉包の更新前・返却前にsignal→時計→signalで検査し、遅い成功を採用しない（既に始めたSDK commitの物理的な取消は
// 約束しない）。外へ出す失敗は固定のKmsConnectionSubscriptionViewErrorだけで、元の例外・owner・Grant・文書の値を持たない。

import { types } from 'node:util';

import type { DocumentReference, DocumentSnapshot, Firestore, Transaction } from '@google-cloud/firestore';

import { createKmsGrantAuthorization, KmsGrantAuthorizationError, type KmsGrantAuthorization, type KmsGrantProof } from '../connect/kms-grant-authorization.js';
import { CONNECT_STORAGE_ROOT, isConnectNamespace } from '../connect/firestore.js';
import type { McpRequestOperation } from '../mcp/request-operation.js';
import type { Clock } from '../policy.js';
import type { KmsCallOptions, KmsDecryptRequest, KmsDecryptResponse, KmsSealingConfig } from '../protection/kms-sealing.js';
import { isTime, isUuid } from '../storage/firestore/checks.js';
import {
  createKmsSubscriptionPolicy,
  kmsStateDocument,
  parseKmsState,
  requireKmsDocumentSize,
  requireKmsMarker,
  type KmsMutableState,
  type KmsSubscriptionPolicy,
} from '../storage/firestore/kms-subscription-format.js';
import {
  ownerGeneration,
  projectBindings,
  sameDocVersion,
  versionOf,
  type BindingVerdict,
  type DocVersion,
} from '../storage/firestore/kms-subscription-registration-rules.js';
import { AUTH_STORAGE_ROOT, KMS_SUBSCRIPTION_CONFIG_DOC } from '../storage/firestore/kms-subscription-format.js';
import type { SubscriptionView } from './subscriptions.js';

/** 1回のviewForの上限（元期限と開始+この値の短い方）。延長しない。 */
const VIEW_REQUEST_BUDGET_MS = 20_000;
/** SDKのtransactionの最大実行回数（既定と同じ5。外側で自動の再試行・再開をしない）。 */
const MAX_TRANSACTION_ATTEMPTS = 5;
/** ECMAScriptのDateで表せる最大のepochミリ秒（ISO文字列の表現域）。 */
const MAX_ISO_TIME_MS = 8_640_000_000_000_000;
const OPTION_KEYS = ['db', 'connect', 'connectNamespace', 'resource', 'kms', 'clock'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const GRANT_DOC_ID = /^Grant_[0-9a-f]{64}$/;

export type KmsConnectionSubscriptionViewErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted' | 'closed' | 'conflict';

const ERROR_MESSAGES: Readonly<Record<KmsConnectionSubscriptionViewErrorCode, string>> = {
  invalid_input: 'kms subscription view: invalid input',
  unavailable: 'kms subscription view: unavailable',
  timed_out: 'kms subscription view: timed out',
  aborted: 'kms subscription view: aborted',
  closed: 'kms subscription view: closed',
  conflict: 'kms subscription view: conflict',
};

/** 固定の非成功。cause・owner・Grant・文書の値・元の例外を持たない。factoryの入力の不正もinvalid_input。 */
export class KmsConnectionSubscriptionViewError extends Error {
  override readonly name = 'KmsConnectionSubscriptionViewError';
  readonly code: KmsConnectionSubscriptionViewErrorCode;
  constructor(code: KmsConnectionSubscriptionViewErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

/** 接続保存のうち、このviewが使う同期の参照・判定だけ（prototypeのdata methodを束縛して1回捕捉する）。 */
export interface KmsConnectionSubscriptionViewConnect {
  ownerDocRef(ownerId: string): DocumentReference;
  grantDocRef(grantId: string): DocumentReference;
  ownerDocActive(data: Record<string, unknown> | undefined, now: number): boolean;
  grantDocLive(data: Record<string, unknown> | undefined, ownerId: string, grantId: string, now: number): boolean;
}

/** 登録保存口と同じ形の入力。 */
export interface KmsConnectionSubscriptionViewOptions {
  /** 借用するFirestore instance（terminateしない）。 */
  readonly db: Firestore;
  readonly connect: KmsConnectionSubscriptionViewConnect;
  /** 接続保存の`t256_<小文字UUID>`。 */
  readonly connectNamespace: string;
  /** 固定MCP audience（Grant.resourcesのkey）。 */
  readonly resource: string;
  /** codec設定からclockを除いたもの。namespaceはKMS購読の`t268_<小文字UUID>`。transportはGrantの開封（decrypt）だけに使う。 */
  readonly kms: Omit<KmsSealingConfig, 'clock'>;
  readonly clock: Clock;
}

export interface KmsConnectionSubscriptionView {
  /** ownerはUUID、operationはMCP入口と同じexact {deadlineAt, signal}（signal必須）。 */
  viewFor(ownerId: string, operation: McpRequestOperation): Promise<SubscriptionView>;
  /** 同期・冪等。先に閉鎖して進行中の採用を中止し、以後を固定closedにする。借用資源は閉じない。 */
  dispose(): void;
}

function viewError(code: KmsConnectionSubscriptionViewErrorCode): KmsConnectionSubscriptionViewError {
  return new KmsConnectionSubscriptionViewError(code);
}

function fail(): never {
  throw viewError('invalid_input');
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知/欠落の名前を拒否、getterを呼ばない）。 */
function dataFields(value: unknown, keys: readonly string[]): Map<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) fail();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !keys.includes(key)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    taken.set(key, descriptor.value);
  }
  for (const key of keys) if (!taken.has(key)) fail();
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

/** 数値の配列をdescriptorで写す（getter・Proxy・穴を拒否）。値の検査はpolicyで行う。 */
function arrayCopy(value: unknown): unknown[] {
  if (!isObject(value) || !Array.isArray(value)) fail();
  const length = (Object.getOwnPropertyDescriptor(value, 'length') as PropertyDescriptor).value as number;
  if (Reflect.ownKeys(value).length !== length + 1) fail();
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    out.push(descriptor.value);
  }
  return out;
}

/** 要求operation: exact {deadlineAt, signal}、deadlineAtは安全整数のepochミリ秒、signalは必須の本物のAbortSignal。 */
function copyOperation(value: unknown): McpRequestOperation {
  const fields = dataFields(value, ['deadlineAt', 'signal']);
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt) || deadlineAt < 0 || deadlineAt > MAX_ISO_TIME_MS) fail();
  if (!isObject(signal) || !(signal instanceof AbortSignal)) fail();
  return Object.freeze({ deadlineAt, signal });
}

/** 1つのviewForの子operation。要求ごとに作り、他の要求と共有しない。 */
interface ViewScope {
  /** helperへ渡す同じfrozen object（{deadlineAt, signal: 子signal}）。 */
  readonly operation: Readonly<{ deadlineAt: number; signal: AbortSignal }>;
  readonly deadlineAt: number;
  readonly parent: AbortSignal;
  readonly controller: AbortController;
  readonly release: () => void;
}

/** 初回snapshotで束縛を読んだGrant（要求Grantを含まない。active/pendingの重複なし・最大2）。 */
interface BoundGrant {
  readonly grantId: string;
  readonly ref: DocumentReference;
  readonly snapshot: DocumentSnapshot;
}

interface ProvenGrant {
  readonly grantId: string;
  readonly ref: DocumentReference;
  readonly proof: KmsGrantProof;
}

/** 印: 初回snapshotでownerが有効でない（none・全無書込み）。 */
const INACTIVE_OWNER: unique symbol = Symbol('inactive owner');

/**
 * 購読viewを組み立てる（同期・I/Oなし: 通信・DB初期化・KMS呼出し0）。全ての検査・捕捉はここで1回だけ行い、以後は入力objectを読み直さない。
 * 不正はKmsConnectionSubscriptionViewError（invalid_input）。戻り値は凍結した{viewFor, dispose}。markerは既存の明示setup済みが前提で作らない。
 */
export function createKmsConnectionSubscriptionView(options: KmsConnectionSubscriptionViewOptions): KmsConnectionSubscriptionView {
  const fields = dataFields(options, OPTION_KEYS);

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

  const connectNamespace = fields.get('connectNamespace');
  if (!isConnectNamespace(connectNamespace)) fail();
  const resource = fields.get('resource');
  if (typeof resource !== 'string') fail();

  const clockNow = methodOf(fields.get('clock'), 'now');
  /** 読めない・有限でない時計はNaN（残りのないもの・不正として扱う）。元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  const clock: Clock = Object.freeze({ now });

  // KMS設定: clockを持たせない。購読のpolicy（t268）は共通の検査・正規化で1回捕捉する。
  const kms = dataFields(fields.get('kms'), KMS_KEYS);
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
    return fail();
  }
  const decrypt = methodOf(kms.get('transport'), 'decrypt');

  // Grant helperは内部で作る（任意のvalidator・別resourceのhelperを外から注入しない）。保存口と同じく、同じ環境/project/
  // database/key/version/transport/clockでnamespaceだけ接続保存のt256にする。開封はdecryptだけ（encryptは常にreject）。
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
      resource,
      kms: {
        environment: policy.environment,
        projectId: policy.projectId,
        databaseId: policy.databaseId,
        namespace: connectNamespace,
        cryptoKey: policy.cryptoKey,
        writeVersion: policy.writeVersion,
        readVersions: [...policy.readVersions],
        transport: Object.freeze({
          encrypt: () => Promise.reject(new Error('subscription view: read-only KMS port, encrypt is not used')),
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

  const lifetime = new AbortController();
  let closed = false;

  /** 中止・閉鎖の分類（時計を読まない）。閉鎖→親の中止→子だけの中止（子期限のtimer）＝timed_outの順。 */
  function stopReason(scope: ViewScope): KmsConnectionSubscriptionViewError | null {
    if (closed) return viewError('closed');
    if (scope.parent.aborted) return viewError('aborted');
    if (scope.controller.signal.aborted) return viewError('timed_out');
    return null;
  }

  /** まだ進めてよいかを、signal→時計→signalの順に見て、その時刻を返す。不正な時刻は期限の根拠にせずunavailable。 */
  function live(scope: ViewScope): number {
    const before = stopReason(scope);
    if (before !== null) throw before;
    const at = now();
    const after = stopReason(scope);
    if (after !== null) throw after;
    if (!isTime(at) || at > MAX_ISO_TIME_MS) throw viewError('unavailable');
    if (!(at < scope.deadlineAt)) throw viewError('timed_out');
    return at;
  }

  /**
   * 新しい要求の子operationを作る（最初のawaitの前）。閉鎖・operation・中止・時計・元期限の順に検査し、元期限と開始+20000msの短い方を一度だけ
   * 決める。時計の観測の後にも閉鎖・中止を再確認してから、子controllerを親signal・disposeへ結び、子期限でもabortするowned timerを置く。
   */
  function begin(operationInput: unknown): ViewScope {
    if (closed) throw viewError('closed');
    const operation = copyOperation(operationInput);
    const parent = operation.signal;
    if (parent.aborted) throw viewError('aborted');
    const start = now();
    if (closed) throw viewError('closed');
    if (parent.aborted) throw viewError('aborted');
    if (!isTime(start) || start > MAX_ISO_TIME_MS) throw viewError('unavailable');
    if (!(start < operation.deadlineAt)) throw viewError('timed_out');
    const deadlineAt = Math.min(operation.deadlineAt, start + VIEW_REQUEST_BUDGET_MS);
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
    return Object.freeze({ operation: Object.freeze({ deadlineAt, signal: controller.signal }), deadlineAt, parent, controller, release });
  }

  /** 非成功の正規化。期限・中止・閉鎖を最優先にし、自分のconflictはそのまま、他（SDK・helper・形式の破損）は固定unavailable。 */
  function normalize(scope: ViewScope | null, error: unknown): KmsConnectionSubscriptionViewError {
    if (scope !== null) {
      try {
        live(scope);
      } catch (stop) {
        if (stop instanceof KmsConnectionSubscriptionViewError) return viewError(stop.code);
      }
    }
    if (error instanceof KmsConnectionSubscriptionViewError) return viewError(error.code);
    if (error instanceof KmsGrantAuthorizationError && (error.code === 'timed_out' || error.code === 'aborted')) return viewError(error.code);
    return viewError('unavailable');
  }

  /**
   * 1つのawaitを子期限・中止・閉鎖までで打ち切る。打切りの後に来た成功・失敗は採用せず、rejectは握りつぶす。
   * 成功は呼出し側が直後にliveで再検査する。
   */
  function bounded<T>(scope: ViewScope, start: () => Promise<T>): Promise<T> {
    let promise: Promise<T>;
    try {
      live(scope);
      promise = start();
    } catch (error) {
      return Promise.reject(error);
    }
    promise.catch(() => {});
    const signal = scope.controller.signal;
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (outcome: () => void) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        outcome();
      };
      const onAbort = () => finish(() => reject(stopReason(scope) ?? viewError('timed_out')));
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
        return;
      }
      promise.then(
        (value) => finish(() => resolve(value)),
        (error: unknown) => finish(() => reject(error)),
      );
    });
  }

  /** 1つの論理transaction（SDK maxAttempts 5以下）。閉包の開始ごとに子期限/中止を検査する。 */
  function run<T>(scope: ViewScope, body: (tx: Transaction) => Promise<T>): Promise<T> {
    return bounded(scope, () =>
      runTransaction(
        async (tx: Transaction) => {
          live(scope);
          return body(tx);
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ) as Promise<T>,
    );
  }

  /** 1回の読取り（awaitの後に検査）。 */
  async function read(tx: Transaction, scope: ViewScope, refs: readonly DocumentReference[]): Promise<DocumentSnapshot[]> {
    const snapshots = await tx.getAll(...refs);
    live(scope);
    if (snapshots.length !== refs.length) throw viewError('unavailable');
    return snapshots;
  }

  /** 接続保存の参照は、借用した同じinstance・同じt256 namespaceの決まったpathだけを使う（別instanceは同じproject文字列でもI/Oの前に拒否）。 */
  function ownConnectRef(make: () => unknown, collection: 'owners' | 'oidc', accept: (id: string) => boolean): DocumentReference {
    let ref: unknown;
    let firestore: unknown;
    let path: unknown;
    let id: unknown;
    try {
      ref = make();
      if (!isObject(ref)) throw viewError('unavailable');
      firestore = (ref as { firestore?: unknown }).firestore;
      path = (ref as { path?: unknown }).path;
      id = (ref as { id?: unknown }).id;
    } catch {
      throw viewError('unavailable');
    }
    if (firestore !== db || typeof path !== 'string' || typeof id !== 'string' || !accept(id)) throw viewError('unavailable');
    if (path !== `${connectPrefix}${collection}/${id}`) throw viewError('unavailable');
    return ref as DocumentReference;
  }

  function requireMarker(snapshot: DocumentSnapshot): void {
    if (!snapshot.exists) throw viewError('unavailable');
    try {
      requireKmsMarker(snapshot.data(), policy);
    } catch {
      throw viewError('unavailable');
    }
  }

  /** version2の購読文書を検査して写す（無ければundefined）。破損・別形式は固定unavailable（空・別ownerとして扱わない）。 */
  function readState(snapshot: DocumentSnapshot, ownerId: string): KmsMutableState | undefined {
    if (!snapshot.exists) return undefined;
    try {
      return parseKmsState(snapshot.data(), ownerId, policy);
    } catch {
      throw viewError('unavailable');
    }
  }

  /** owner文書の取消世代（欠落0）。破損は固定unavailable（0へ読み替えない）。 */
  function generationOf(snapshot: DocumentSnapshot): number {
    try {
      return ownerGeneration(snapshot.data());
    } catch {
      throw viewError('unavailable');
    }
  }

  function snapshotVersion(snapshot: DocumentSnapshot): DocVersion {
    try {
      return versionOf(snapshot);
    } catch {
      throw viewError('unavailable');
    }
  }

  function ownerActive(snapshot: DocumentSnapshot, at: number): boolean {
    return ownerDocActive(snapshot.data(), at) === true;
  }

  /** 投影後の状態の見え方: 保留→change_pending、有効→subscribed、直前が期限切れ→expired、他はnone。 */
  function classify(state: KmsMutableState | undefined): SubscriptionView {
    if (state === undefined) return 'none';
    if (state.pending !== null) return 'change_pending';
    if (state.active !== null) return 'subscribed';
    if (state.lastEnded === 'expired') return 'expired';
    return 'none';
  }

  async function viewFor(ownerIdInput: unknown, operationInput: unknown): Promise<SubscriptionView> {
    let scope: ViewScope | null = null;
    try {
      // 最初のawaitの前に、閉鎖・中止・時計・期限・入力・参照を捕捉する（後の改変で束縛を変えない）。
      scope = begin(operationInput);
      const current: ViewScope = scope;
      if (!isUuid(ownerIdInput)) throw viewError('invalid_input');
      const ownerId: string = ownerIdInput;
      live(current);
      const ownerRef = ownConnectRef(() => ownerDocRef(ownerId), 'owners', (id) => id === ownerId);
      const subscriptionRef = subscriptionDocs.doc(ownerId);

      // 初回snapshot: 書込みなしの通常transaction。owner・marker・購読と、active/pendingが束縛したGrant（重複なし・最大2）を読む。
      const first = await run(current, async (tx) => {
        const [owner, marker, subscription] = (await read(tx, current, [ownerRef, markerRef, subscriptionRef])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
        ];
        const state = readState(subscription, ownerId);
        const boundIds: string[] = [];
        for (const grantId of [state?.active?.grantId, state?.pending?.grantId]) {
          if (grantId !== undefined && !boundIds.includes(grantId)) boundIds.push(grantId);
        }
        const boundRefs = boundIds.map((grantId) => ownConnectRef(() => grantDocRef(grantId), 'oidc', (id) => GRANT_DOC_ID.test(id)));
        const boundSnapshots = boundRefs.length === 0 ? [] : await read(tx, current, boundRefs);
        // 全ての読取りの後の最新時刻で、markerとownerを確かめる（無効なownerは開封・投影・書込み0のnone）。
        const at = live(current);
        requireMarker(marker);
        if (!ownerActive(owner, at)) return INACTIVE_OWNER;
        return {
          generation: generationOf(owner),
          subscription: snapshotVersion(subscription),
          grants: boundIds.map((grantId, index): BoundGrant => ({ grantId, ref: boundRefs[index]!, snapshot: boundSnapshots[index]! })),
        };
      });
      live(current);
      if (first === INACTIVE_OWNER) return 'none';

      // 閉包の外で、取得済みの各Grant snapshotの証拠を順に作る（最大2回、同じ子operation）。
      const proven: ProvenGrant[] = [];
      for (const entry of first.grants) {
        live(current);
        const proof = await bounded(current, () => grants.prove(entry.snapshot, { ownerId, grantId: entry.grantId }, current.operation));
        live(current);
        proven.push(Object.freeze({ grantId: entry.grantId, ref: entry.ref, proof }));
      }
      const grantRefs = proven.map((entry) => entry.ref);

      // 最終transaction: 同じrefを再読し、marker・最新owner・世代・購読の期待版・Grant証拠（stale→conflict）を照合してから投影する。
      const view = await run(current, async (tx) => {
        const [owner, marker, subscription, ...grantSnapshots] = (await read(tx, current, [ownerRef, markerRef, subscriptionRef, ...grantRefs])) as [
          DocumentSnapshot,
          DocumentSnapshot,
          DocumentSnapshot,
          ...DocumentSnapshot[],
        ];
        const at = live(current);
        requireMarker(marker);
        // 初回の後に無効になったownerは、全無書込みのnone（取消・失効の後で投影・保存をしない）。
        if (!ownerActive(owner, at)) return 'none' as const;
        if (generationOf(owner) !== first.generation || !sameDocVersion(snapshotVersion(subscription), first.subscription)) throw viewError('conflict');
        const verdicts = new Map<string, BindingVerdict>();
        proven.forEach((entry, index) => {
          const snapshot = grantSnapshots[index];
          if (snapshot === undefined) throw viewError('unavailable');
          const result = grants.check(entry.proof, snapshot, { ownerId, grantId: entry.grantId }, current.operation);
          if (result === 'stale') throw viewError('conflict');
          verdicts.set(entry.grantId, result);
        });
        const state = readState(subscription, ownerId);
        if (state === undefined) return 'none' as const;
        const changed = projectBindings(state, at, (grantId) => {
          const verdict = verdicts.get(grantId);
          // 期待版が一致していれば束縛Grantは初回と同じ集合。知らないGrantは推測せずconflict。
          if (verdict === undefined) throw viewError('conflict');
          return verdict;
        });
        if (changed) {
          try {
            requireKmsDocumentSize(ownerId, state);
          } catch {
            throw viewError('unavailable');
          }
          live(current);
          // ownerの文書（活動時刻・取消世代・失効・封緘UID）は変えない。購読は実際に変わった時だけ既存version2で保存する。
          tx.set(subscriptionRef, kmsStateDocument(ownerId, state));
        }
        return classify(state);
      });
      live(current);
      return view;
    } catch (error) {
      throw normalize(scope, error);
    } finally {
      scope?.release();
    }
  }

  return Object.freeze({
    viewFor: viewFor as KmsConnectionSubscriptionView['viewFor'],
    dispose(): void {
      if (closed) return;
      // 先に閉鎖してから進行中の子をabortする（以後の新しいDB/KMSは0）。借用資源は閉じない。
      closed = true;
      lifetime.abort();
    },
  });
}
