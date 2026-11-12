// 許可元のFirestore adapter（接続保存と同じroot sttdConnect/{connectNamespace}の下）。
//   sources/{sourceId}          管理者が登録したsource（contract.tsのexact schema）。管理者削除は物理削除で、何も残さない
//   sourceReplay/{hash}         開発者要求署名のnonce（source＋nonceの鍵付きhashを文書IDに、論理期限expiresAtと掃除用deleteAfterだけ）
//   sourceApprovals/{hash}      接続承認（元interactionの鍵付きhashを文書IDに、本人/client/resourceのHMAC・binding・期限・単回状態・deleteAfter）
//   sourceGrants/{grantHash}    Grantへ結んだsource binding（同意の最終transactionでGrant metadataと一緒に作る。Grantと同じ保持で消す）
// 要求の認可は1 transactionでsourceの現在の状態を読み、全readの後の時刻で期限を判定し、署名/App IDを照合し、replay記録を作る
// （同じnonceの同時要求は1つだけ成功、DB待機中に失効した署名・登録鍵は通さない）。
// 不正なrecord・DB障害はSourceUnavailableError（成功にせず、自動修復しない）。本文・token・生証明・秘密鍵・平文UIDは保存しない。
// deleteAfterはTTLの掃除候補で、期限の判定は常にexpiresAtと時計で即時に行う（TTL設定の実適用は配置側）。

import type { DocumentReference, DocumentSnapshot, Firestore, Transaction } from '@google-cloud/firestore';

import {
  ACCESS_COLLECTION,
  ACCESS_SCOPE_WEB,
  accessSourceScopeVerdict,
  codeLoginWithin,
  isAccessGeneration,
  nextAccessRecord,
  parseAccessRecord,
  type AccessRecord,
} from '../access/policy.js';
import type { Clock } from '../policy.js';
import { hashesEqual } from '../secrets.js';
import { ACCOUNT_GRANT, APP_PAIR_TTL_MS, isAccountGrant, isAppLabel, newAppPairCode, type AppManagementRequest, type AppManagementResult } from './connected-apps.js';
import {
  APPROVAL_MAX_MS,
  ED25519_PUBLIC_KEY,
  isSourceBinding,
  parseSourceRecord,
  SOURCE_APPROVALS_COLLECTION,
  SOURCE_ID,
  SOURCE_RECORD_CLEANUP_MS,
  SOURCE_REPLAY_COLLECTION,
  sourceBindingVerdict,
  sourceRequestBindingVerdict,
  sourceRequestVerdict,
  SOURCES_COLLECTION,
  type SourceBinding,
  type SourceMethod,
  type SourceOperation,
  type SourceRecord,
  type SourceRejection,
  type SourceVerdict,
} from './contract.js';

export const CONNECT_ROOT_COLLECTION = 'sttdConnect';
export const SOURCE_GRANTS_COLLECTION = 'sourceGrants';
/** プレイグラウンドの本人ごとのWeb source binding（通常MCPの限定endpointだけが書く）。 */
export const PLAYGROUND_BINDINGS_COLLECTION = 'playgroundBindings';
const HASH = /^[0-9a-f]{64}$/;
const DEFAULT_ATTEMPTS = 3;
type ConnectedApp = { readonly name: string; readonly generation: string; readonly enabled: boolean };
type AppOwner = { readonly identityHash: string; readonly receiverGeneration: number };

/** 読取り・判定が一時的にできない（固定message。値・path・元例外を持たない）。 */
export class SourceUnavailableError extends Error {
  override readonly name = 'SourceUnavailableError';
  constructor() {
    super('source check is temporarily unavailable');
  }
}

export type RequestAuthorization =
  | { readonly kind: 'allowed'; readonly binding: SourceBinding }
  | { readonly kind: 'rejected'; readonly reason: SourceRejection | 'proof' | 'replay' };

export interface SourceRequestCheck {
  readonly sourceId: string;
  readonly method: SourceMethod;
  readonly operation: SourceOperation;
  readonly pairing?: true | undefined;
  readonly identityHash: string;
  /** recordの公開鍵/App IDで証明を照合する（同期・I/Oなし）。 */
  readonly proofMatches: (record: SourceRecord) => boolean;
  /** 全readの後の時刻で証明自体がまだ有効か（開発者署名の期限。App Checkは消費済みのため常にtrue）。 */
  readonly validAt?: ((now: number) => boolean) | undefined;
  /** 開発者方式だけ: replay記録（文書IDと論理期限ms）。 */
  readonly replay?: { readonly id: string; readonly until: number } | undefined;
}

export type ApprovalOutcome = { readonly kind: 'recorded'; readonly expiresAt: number } | { readonly kind: 'rejected'; readonly reason: SourceRejection | 'conflict' | 'expired' };

export interface ApprovalSubject {
  readonly approvalId: string;
  readonly identityHash: string;
  readonly clientHash: string;
  readonly resourceHash: string;
}

/** 同意transactionで読んだ承認（書込みは全ての読取りの後にapplyで行う）。 */
export type ApprovalRead =
  | { readonly kind: 'usable'; readonly binding: SourceBinding; readonly apply: () => void }
  | { readonly kind: 'rejected'; readonly reason: SourceRejection | 'missing_approval' | 'mismatch' | 'consumed' | 'expired' };

/** Web登録で作るsourceの操作（接続承認と送信だけ。鍵の取得・再発行や管理操作は含めない）。 */
export const WEB_OPERATIONS: readonly SourceOperation[] = Object.freeze(['send', 'connect'] as const);

/** Web登録の読取り結果（registeredのapplyは全readの後に呼ぶ）。 */
export type WebRegistrationRead =
  | { readonly kind: 'registered'; readonly binding: SourceBinding; readonly created: boolean; readonly apply: () => void }
  | { readonly kind: 'rejected'; readonly reason: 'denied' | 'expired' | 'source_unusable' };

/** Grantのbinding記録の状態（strictではunboundの旧Grantを使わない）。 */
export type GrantSourceState = { readonly kind: 'bound'; readonly binding: SourceBinding } | { readonly kind: 'unbound' } | { readonly kind: 'account' };

/** 使うFirestoreの範囲（runtimeの所有db・管理CLIのdbの両方）。 */
export type SourceDb = Pick<Firestore, 'collection' | 'runTransaction'>;

export interface SourceStoreDeps {
  readonly db: SourceDb;
  readonly namespace: string;
  readonly clock: Clock;
  readonly maxAttempts?: number | undefined;
}

function isHash(value: unknown): value is string {
  return typeof value === 'string' && HASH.test(value);
}

export class SourceStore {
  readonly #db: SourceDb;
  readonly #root: DocumentReference;
  readonly #clock: Clock;
  readonly #attempts: number;

  constructor(deps: SourceStoreDeps) {
    this.#db = deps.db;
    this.#root = deps.db.collection(CONNECT_ROOT_COLLECTION).doc(deps.namespace);
    this.#clock = deps.clock;
    this.#attempts = deps.maxAttempts ?? DEFAULT_ATTEMPTS;
  }

  sourceRef(sourceId: string): DocumentReference {
    if (!SOURCE_ID.test(sourceId)) throw new SourceUnavailableError();
    return this.#root.collection(SOURCES_COLLECTION).doc(sourceId);
  }

  #replayRef(id: string): DocumentReference {
    if (!isHash(id)) throw new SourceUnavailableError();
    return this.#root.collection(SOURCE_REPLAY_COLLECTION).doc(id);
  }

  #approvalRef(id: string): DocumentReference {
    if (!isHash(id)) throw new SourceUnavailableError();
    return this.#root.collection(SOURCE_APPROVALS_COLLECTION).doc(id);
  }

  /** 本人の利用許可record（接続保存と同じaccess/{identityHash}。読取りだけ）。 */
  #accessRef(identityHash: string): DocumentReference {
    if (!isHash(identityHash)) throw new SourceUnavailableError();
    return this.#root.collection(ACCESS_COLLECTION).doc(identityHash);
  }

  #appOwnerRef(identityHash: string): DocumentReference {
    if (!isHash(identityHash)) throw new SourceUnavailableError();
    return this.#root.collection('connectedAppOwners').doc(identityHash);
  }

  #appRef(identityHash: string, sourceId: string): DocumentReference {
    if (!SOURCE_ID.test(sourceId)) throw new SourceUnavailableError();
    return this.#appOwnerRef(identityHash).collection('apps').doc(sourceId);
  }

  #pairCodeRef(identityHash: string): DocumentReference {
    if (!isHash(identityHash)) throw new SourceUnavailableError();
    return this.#root.collection('appPairingCodes').doc(identityHash);
  }

  static #appOf(snapshot: DocumentSnapshot): ConnectedApp | null {
    if (!snapshot.exists) return null;
    const data = snapshot.data();
    if (!data || Object.keys(data).length !== 3 || !isAppLabel(data.name) ||
        !isSourceBinding({ sourceId: snapshot.id, generation: data.generation }) || typeof data.enabled !== 'boolean') {
      throw new SourceUnavailableError();
    }
    return { name: data.name, generation: data.generation, enabled: data.enabled };
  }

  async appCanSend(identityHash: string, source: SourceBinding): Promise<boolean> {
    return this.#run(async (tx) => {
      const record = SourceStore.recordOf(await tx.get(this.sourceRef(source.sourceId)));
      const paired = await this.pairingAllowsIn(tx, identityHash, record);
      return paired && sourceRequestBindingVerdict(record, source, 'send', this.now()).kind === 'usable';
    });
  }

  /** 旧接続は従来の認可を使う。移行済みの本人は、同じ世代の許可が必要。 */
  async pairingAllowsIn(tx: Transaction, identityHash: string, record: SourceRecord | null): Promise<boolean> {
    const owner = await tx.get(this.#appOwnerRef(identityHash));
    if (!owner.exists) return true;
    if (owner.data()?.version !== 1 || Object.keys(owner.data()!).length !== 1) throw new SourceUnavailableError();
    if (record === null) return false;
    const app = SourceStore.#appOf(await tx.get(this.#appRef(identityHash, record.sourceId)));
    return app?.enabled === true && app.generation === record.generation;
  }

  /** 独立したOAuth接続に移行する時、以前の受信タスクに結ばれた許可元だけを引き継ぐ。 */
  async accountGrantWritesIn(tx: Transaction, identityHash: string, grantHash: string, previous: SourceBinding | undefined): Promise<() => void> {
    const ownerRef = this.#appOwnerRef(identityHash);
    const grantRef = this.grantRef(grantHash);
    const owner = await tx.get(ownerRef);
    if (owner.exists) {
      if (owner.data()?.version !== 1 || Object.keys(owner.data()!).length !== 1) throw new SourceUnavailableError();
      return () => { tx.create(grantRef, ACCOUNT_GRANT); };
    }
    if (previous === undefined) return () => { tx.create(ownerRef, { version: 1 }); tx.create(grantRef, ACCOUNT_GRANT); };
    const ref = this.#appRef(identityHash, previous.sourceId);
    const [existing, source, playground] = await tx.getAll(
      ref, this.sourceRef(previous.sourceId), this.#root.collection(PLAYGROUND_BINDINGS_COLLECTION).doc(identityHash),
    );
    const record = SourceStore.recordOf(source!);
    const usable = !existing!.exists && sourceRequestBindingVerdict(record, previous, 'send', this.now()).kind === 'usable';
    const name = playground!.data()?.sourceId === previous.sourceId ? 'SendTextToDots Playground' : 'Previously connected app';
    return () => {
      tx.create(ownerRef, { version: 1 });
      tx.create(grantRef, ACCOUNT_GRANT);
      if (usable) tx.create(ref, { name, generation: previous.generation, enabled: true });
    };
  }

  async manageConnectedApps(request: AppManagementRequest, authorize: (tx: Transaction) => Promise<AppOwner | null>, hashCode: (code: string) => string, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }): Promise<AppManagementResult> {
    const code = request.kind === 'issue' ? newAppPairCode() : undefined;
    return this.#run(async (tx): Promise<AppManagementResult> => {
      const owner = await authorize(tx);
      if (owner === null || operation.signal.aborted || this.now() >= operation.deadlineAt) return { error: 'connection_required' };
      if (request.kind === 'issue' && code !== undefined) {
        const expiresAt = this.now() + APP_PAIR_TTL_MS;
        tx.set(this.#pairCodeRef(owner.identityHash), { hash: hashCode(code), expiresAt, name: request.name, receiverGeneration: owner.receiverGeneration });
        return { code, expiresAt: new Date(expiresAt).toISOString(), name: request.name };
      }
      if (request.kind === 'remove') {
        const ref = this.#appRef(owner.identityHash, request.appId);
        const app = SourceStore.#appOf(await tx.get(ref));
        if (operation.signal.aborted || this.now() >= operation.deadlineAt) return { error: 'connection_required' };
        if (app?.enabled !== true) return { removed: false };
        tx.update(ref, { enabled: false });
        return { removed: true };
      }
      const registered = await tx.get(this.#appOwnerRef(owner.identityHash).collection('apps'));
      const active = registered.docs.flatMap((doc) => {
        const app = SourceStore.#appOf(doc);
        return app?.enabled === true ? [{ appId: doc.id, ...app }] : [];
      });
      const sources = active.length === 0 ? [] : await tx.getAll(...active.map((app) => this.sourceRef(app.appId)));
      const now = this.now();
      return { apps: active.flatMap((app, index) => sourceRequestBindingVerdict(
        SourceStore.recordOf(sources[index]!), { sourceId: app.appId, generation: app.generation }, 'send', now,
      ).kind === 'usable' ? [{ appId: app.appId, name: app.name }] : []) };
    });
  }

  async clearConnectedAppsIn(tx: Transaction, identityHash: string): Promise<() => void> {
    const owner = this.#appOwnerRef(identityHash);
    const marker = await tx.get(owner);
    if (!marker.exists) return () => {};
    const apps = await tx.get(owner.collection('apps'));
    const code = await tx.get(this.#pairCodeRef(identityHash));
    return () => {
      for (const app of apps.docs) tx.delete(app.ref);
      if (code.exists) tx.delete(code.ref);
    };
  }

  /** 署名やApp Checkを検証済みのsourceを、同じ本人の単回コードへ結ぶ。 */
  async redeemApp(codeHash: string, source: SourceBinding, authorize: (tx: Transaction) => Promise<AppOwner | null>, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }): Promise<boolean> {
    return this.#run(async (tx) => {
      const owner = await authorize(tx);
      if (owner === null) return false;
      const codeRef = this.#pairCodeRef(owner.identityHash);
      const account = await tx.get(this.#appOwnerRef(owner.identityHash));
      const code = (await tx.get(codeRef)).data();
      const record = SourceStore.recordOf(await tx.get(this.sourceRef(source.sourceId)));
      if (!(await this.scopeAllowsIn(tx, owner.identityHash, record))) return false;
      const now = this.now();
      if (operation.signal.aborted || now >= operation.deadlineAt || account.data()?.version !== 1 || !code || !isHash(code.hash) || !hashesEqual(codeHash, code.hash) ||
          !isAppLabel(code.name) || !Number.isSafeInteger(code.expiresAt) || now >= code.expiresAt ||
          code.receiverGeneration !== owner.receiverGeneration ||
          sourceRequestBindingVerdict(record, source, 'send', now).kind !== 'usable') return false;
      tx.set(this.#appRef(owner.identityHash, source.sourceId), { name: code.name, generation: source.generation, enabled: true });
      tx.delete(codeRef);
      return true;
    });
  }

  /**
   * 利用許可の送信元範囲（Webだけの本人はdeveloper以外のsourceを使えない）。同じtransactionで読んだsnapshotから判定し、
   * 不正recordはSourceUnavailableError（許可へ読み替えない）。範囲外はtrue（拒否）。
   */
  static #outOfScope(access: DocumentSnapshot, record: SourceRecord | null): boolean {
    if (record === null) return false;
    const verdict = accessSourceScopeVerdict(access.exists, access.exists ? access.data() : undefined, record.kind);
    if (verdict === 'unavailable') throw new SourceUnavailableError();
    return verdict === 'scope';
  }

  grantRef(grantHash: string): DocumentReference {
    if (!isHash(grantHash)) throw new SourceUnavailableError();
    return this.#root.collection(SOURCE_GRANTS_COLLECTION).doc(grantHash);
  }

  /** 時計を読む（全readの後に呼ぶ）。不正はSourceUnavailableError。 */
  now(): number {
    let now: unknown;
    try {
      now = this.#clock.now();
    } catch {
      throw new SourceUnavailableError();
    }
    if (typeof now !== 'number' || !Number.isSafeInteger(now) || now < 0) throw new SourceUnavailableError();
    return now;
  }

  /** snapshotのrecord（不存在はnull、不正はSourceUnavailableError）。 */
  static recordOf(snapshot: DocumentSnapshot): SourceRecord | null {
    if (!snapshot.exists) return null;
    try {
      return parseSourceRecord(snapshot.data(), snapshot.id);
    } catch {
      throw new SourceUnavailableError();
    }
  }

  async #run<T>(body: (tx: Transaction) => Promise<T>): Promise<T> {
    try {
      return await this.#db.runTransaction(body, { maxAttempts: this.#attempts });
    } catch {
      throw new SourceUnavailableError();
    }
  }

  /** 要求1件の認可（source状態・証明・replayを1 transactionで。時刻は全readの後）。 */
  async authorizeRequest(check: SourceRequestCheck): Promise<RequestAuthorization> {
    const sourceRef = this.sourceRef(check.sourceId);
    const replayRef = check.replay === undefined ? undefined : this.#replayRef(check.replay.id);
    const accessRef = this.#accessRef(check.identityHash);
    return this.#run(async (tx) => {
      const snapshot = await tx.get(sourceRef);
      const seen = replayRef === undefined ? undefined : await tx.get(replayRef);
      const access = await tx.get(accessRef);
      const paired = check.pairing || check.operation === 'connect' ||
        await this.pairingAllowsIn(tx, check.identityHash, SourceStore.recordOf(snapshot));
      const now = this.now();
      if (check.validAt !== undefined && !check.validAt(now)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceRequestVerdict(SourceStore.recordOf(snapshot), { method: check.method, operation: check.operation, identityHash: check.identityHash, now });
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
      if (!paired) return { kind: 'rejected', reason: 'scope' };
      // Webだけの本人は、正しいApp Check証明があってもアプリsourceで接続承認・送信・鍵を使えない（証明照合・replay記録の前に拒否）。
      if (SourceStore.#outOfScope(access, verdict.record)) return { kind: 'rejected', reason: 'scope' };
      if (!check.proofMatches(verdict.record)) return { kind: 'rejected', reason: 'proof' };
      if (replayRef !== undefined && check.replay !== undefined && seen !== undefined) {
        // 記録が残っている間は期限後も再利用を拒否する（掃除前の物理TTL遅延を期限の判定に使わない）。
        if (seen.exists) return { kind: 'rejected', reason: 'replay' };
        tx.create(replayRef, { expiresAt: check.replay.until, deleteAfter: new Date(Math.max(check.replay.until, now) + SOURCE_RECORD_CLEANUP_MS) });
      }
      return { kind: 'allowed', binding: { sourceId: verdict.record.sourceId, generation: verdict.record.generation } };
    });
  }

  /**
   * 同じ本人の許可元承認を元interactionへ結んで保存する（1 interactionに1件・単回）。期限は元interactionの期限以内かつ最大5分。
   * 承認時点のsource世代が有効でconnect操作を許す時だけ。時刻は全readの後。
   */
  async recordApproval(subject: ApprovalSubject, binding: SourceBinding, interactionExpiresAt: number): Promise<ApprovalOutcome> {
    if (![subject.identityHash, subject.clientHash, subject.resourceHash].every(isHash)) throw new SourceUnavailableError();
    const approvalRef = this.#approvalRef(subject.approvalId);
    const sourceRef = this.sourceRef(binding.sourceId);
    const accessRef = this.#accessRef(subject.identityHash);
    return this.#run(async (tx) => {
      const source = await tx.get(sourceRef);
      const existing = await tx.get(approvalRef);
      const access = await tx.get(accessRef);
      const now = this.now();
      const expiresAt = Math.min(interactionExpiresAt, now + APPROVAL_MAX_MS);
      if (!(now < expiresAt)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceBindingVerdict(SourceStore.recordOf(source), binding, now);
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
      if (SourceStore.#outOfScope(access, verdict.record)) return { kind: 'rejected', reason: 'scope' };
      if (existing.exists) return { kind: 'rejected', reason: 'conflict' };
      tx.create(approvalRef, {
        identityHash: subject.identityHash,
        clientHash: subject.clientHash,
        resourceHash: subject.resourceHash,
        sourceId: binding.sourceId,
        generation: binding.generation,
        expiresAt,
        consumed: false,
        deleteAfter: new Date(expiresAt + SOURCE_RECORD_CLEANUP_MS),
      });
      return { kind: 'recorded', expiresAt };
    });
  }

  /**
   * 同意の最終transactionの中で承認とそのsourceを読む（呼出し側のowner/利用許可/receiverの読取りと同じtx）。呼出し側は全readの後に
   * judge(now)で判定し、usableなら書込みの段階でapplyを呼ぶ。別本人・別client/resource・期限切れ・消費済み・source停止/世代違いは拒否。
   */
  async readApprovalIn(tx: Transaction, subject: ApprovalSubject): Promise<(now: number) => ApprovalRead> {
    const approvalRef = this.#approvalRef(subject.approvalId);
    const snapshot = await tx.get(approvalRef);
    if (!snapshot.exists) return () => ({ kind: 'rejected', reason: 'missing_approval' });
    const data = snapshot.data() as Record<string, unknown> | undefined;
    const bound = { sourceId: data?.sourceId, generation: data?.generation };
    if (data === undefined || !isSourceBinding(bound) || typeof data.expiresAt !== 'number' || typeof data.consumed !== 'boolean') {
      throw new SourceUnavailableError();
    }
    const binding: SourceBinding = { sourceId: bound.sourceId, generation: bound.generation };
    const record = SourceStore.recordOf(await tx.get(this.sourceRef(binding.sourceId)));
    // 同意の最終txで本人の利用許可の範囲も読む（承認後に範囲を変えた・別経路の承認を流用する要求をGrantへ結ばない）。
    const outOfScope = SourceStore.#outOfScope(await tx.get(this.#accessRef(subject.identityHash)), record);
    const expiresAt = data.expiresAt;
    const consumed = data.consumed;
    const matches = data.identityHash === subject.identityHash && data.clientHash === subject.clientHash && data.resourceHash === subject.resourceHash;
    return (now: number): ApprovalRead => {
      if (!matches) return { kind: 'rejected', reason: 'mismatch' };
      if (consumed) return { kind: 'rejected', reason: 'consumed' };
      if (!(now < expiresAt)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceBindingVerdict(record, binding, now);
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
      if (outOfScope) return { kind: 'rejected', reason: 'scope' };
      return { kind: 'usable', binding, apply: () => void tx.update(approvalRef, { consumed: true }) };
    };
  }

  /**
   * 同意の前の読取りだけの確認（interactionを消費する前に、承認の無い同意を案内つきで止める）。未消費・期限内・同じclient/resourceの承認が
   * あればtrue。本人・source世代・単回消費の最終判定は同意のtransaction（readApprovalIn）で行う。
   */
  async approvalPending(request: { readonly approvalId: string; readonly clientHash: string; readonly resourceHash: string }): Promise<boolean> {
    let snapshot: DocumentSnapshot;
    try {
      snapshot = await this.#approvalRef(request.approvalId).get();
    } catch {
      throw new SourceUnavailableError();
    }
    if (!snapshot.exists) return false;
    const data = snapshot.data() as Record<string, unknown> | undefined;
    const bound = { sourceId: data?.sourceId, generation: data?.generation };
    if (data === undefined || data.consumed !== false || typeof data.expiresAt !== 'number' || !isSourceBinding(bound)) return false;
    if (data.clientHash !== request.clientHash || data.resourceHash !== request.resourceHash) return false;
    // 承認後に停止・削除・世代変更されたsourceの承認は待機中と同じ扱い（同意の消費・受信先設定の削除へ進めない）。
    let source: DocumentSnapshot;
    try {
      source = await this.sourceRef(bound.sourceId).get();
    } catch {
      throw new SourceUnavailableError();
    }
    const now = this.now();
    return now < data.expiresAt && sourceBindingVerdict(SourceStore.recordOf(source), { sourceId: bound.sourceId, generation: bound.generation }, now).kind === 'usable';
  }

  /**
   * プレイグラウンド（BFF）のWeb登録。検証済み本人1人に、登録済みサーバー鍵のdeveloper source（操作はconnect/sendだけ）を結ぶ限定操作。
   * 呼出し側のtransaction（BFFのbinding・quotaと同じtx）で読み、全readの後の時刻でjudge(now)し、registeredならapplyで書く。
   *   - 利用許可: 既存の正常activeはそのまま（世代・範囲・期限を変えない＝既存DPADAA許可にWebを追加しても同じ受信先を使える）。
   *     停止・コード期限切れは拒否（登録で復活させない）、不正はSourceUnavailableError。欠落はApple/Googleだけ新規にWebだけの範囲で作る
   *     （コードUIDの許可はコードの有効化だけが作る）。
   *   - source: 既存bindingがあれば同じID・世代・鍵・本人・connect/send・有効期限内の時だけ再利用（削除・停止・世代違いを再作成しない）。
   *     無ければ呼出し側が作った新しいID/世代で作成（同IDが既にあれば拒否）。管理API・他の操作・他の本人への書込みは無い。
   */
  async webRegistrationIn(
    tx: Transaction,
    input: {
      readonly identityHash: string;
      readonly publicKey: string;
      readonly expiresAt: number | null;
      readonly existing: SourceBinding | null;
      readonly fresh: SourceBinding;
      readonly newAccessGeneration: string;
      readonly codeIdentity: boolean;
    },
  ): Promise<(now: number) => WebRegistrationRead> {
    if (!ED25519_PUBLIC_KEY.test(input.publicKey) || !isAccessGeneration(input.newAccessGeneration) || !isSourceBinding(input.fresh)) throw new SourceUnavailableError();
    if (input.existing !== null && !isSourceBinding(input.existing)) throw new SourceUnavailableError();
    const accessRef = this.#accessRef(input.identityHash);
    const target = input.existing ?? input.fresh;
    const sourceRef = this.sourceRef(target.sourceId);
    const access = await tx.get(accessRef);
    const record = SourceStore.recordOf(await tx.get(sourceRef));
    let current: AccessRecord | null = null;
    if (access.exists) {
      try {
        current = parseAccessRecord(access.data());
      } catch {
        throw new SourceUnavailableError();
      }
    }
    return (now: number): WebRegistrationRead => {
      if (input.expiresAt !== null && !(now < input.expiresAt)) return { kind: 'rejected', reason: 'expired' };
      if (current !== null) {
        if (current.state !== 'active' || !codeLoginWithin(current.codeLoginExpiresAt, now)) return { kind: 'rejected', reason: 'denied' };
      } else if (input.codeIdentity) return { kind: 'rejected', reason: 'denied' };
      if (input.existing !== null) {
        const ok =
          record !== null &&
          record.kind === 'developer' &&
          record.state === 'active' &&
          record.generation === input.existing.generation &&
          record.publicKey === input.publicKey &&
          record.identityHash === input.identityHash &&
          record.operations.length === WEB_OPERATIONS.length &&
          WEB_OPERATIONS.every((op) => record.operations.includes(op)) &&
          (record.expiresAt === null || now < record.expiresAt);
        return ok ? { kind: 'registered', binding: input.existing, created: false, apply: () => undefined } : { kind: 'rejected', reason: 'source_unusable' };
      }
      if (record !== null) return { kind: 'rejected', reason: 'source_unusable' };
      if (input.expiresAt !== null && input.expiresAt <= now) return { kind: 'rejected', reason: 'expired' };
      const binding: SourceBinding = { sourceId: input.fresh.sourceId, generation: input.fresh.generation };
      return {
        kind: 'registered',
        binding,
        created: true,
        apply: () => {
          if (current === null) {
            const created = nextAccessRecord(null, 'active', now, input.newAccessGeneration, ACCESS_SCOPE_WEB);
            if (created === null) throw new SourceUnavailableError();
            tx.create(accessRef, { ...created });
          }
          tx.create(sourceRef, {
            schemaVersion: 1,
            sourceId: binding.sourceId,
            kind: 'developer',
            state: 'active',
            generation: binding.generation,
            operations: [...WEB_OPERATIONS],
            createdAt: now,
            updatedAt: now,
            publicKey: input.publicKey,
            identityHash: input.identityHash,
            expiresAt: input.expiresAt,
          });
        },
      };
    };
  }

  /**
   * 送出確定のtransactionで、本人の現在の利用許可の範囲がこのsourceの種別を許すか（Webだけの本人のApp Check sourceはfalse）。
   * 不正recordはSourceUnavailableError。
   */
  async scopeAllowsIn(tx: Transaction, identityHash: string, record: SourceRecord | null): Promise<boolean> {
    return !SourceStore.#outOfScope(await tx.get(this.#accessRef(identityHash)), record);
  }

  /** 固定登録元（設定の公開鍵）の署名nonceを単回で記録する。既にあればfalse（同じ署名の再利用）。 */
  async consumeReplay(id: string, until: number, validAt?: (now: number) => boolean): Promise<boolean> {
    const ref = this.#replayRef(id);
    return this.#run(async (tx) => {
      const seen = await tx.get(ref);
      const now = this.now();
      // DB待機中に署名の期限を過ぎた要求は、全readの後の時刻で拒否する（authorizeRequestと同じ）。
      if (seen.exists || !(now <= until) || (validAt !== undefined && !validAt(now))) return false;
      tx.create(ref, { expiresAt: until, deleteAfter: new Date(Math.max(until, now) + SOURCE_RECORD_CLEANUP_MS) });
      return true;
    });
  }

  /**
   * プレイグラウンドの本人登録（通常MCPの限定endpointだけが呼ぶ）。本人ごとのbinding（playgroundBindings/{identityHash}）をMCPのDBで保持し、
   * 同じtransactionでwebRegistrationInを判定・適用してbindingを初回だけ作る（再実行は同じsource・世代、書込み0）。
   * bindingの形が不正なら一時障害（再作成しない）。
   */
  async registerPlayground(input: {
    readonly identityHash: string;
    readonly publicKey: string;
    readonly expiresAt: number | null;
    readonly fresh: SourceBinding;
    readonly newAccessGeneration: string;
    readonly codeIdentity: boolean;
  }): Promise<WebRegistrationRead> {
    if (!isHash(input.identityHash)) throw new SourceUnavailableError();
    const bindingRef = this.#root.collection(PLAYGROUND_BINDINGS_COLLECTION).doc(input.identityHash);
    return this.#run(async (tx) => {
      const snapshot = await tx.get(bindingRef);
      let existing: SourceBinding | null = null;
      if (snapshot.exists) {
        const data = snapshot.data() as Record<string, unknown> | undefined;
        const bound = { sourceId: data?.sourceId, generation: data?.generation };
        if (data === undefined || Object.keys(data).length !== 3 || data.version !== 1 || !isSourceBinding(bound)) throw new SourceUnavailableError();
        existing = { sourceId: bound.sourceId, generation: bound.generation };
      }
      const judge = await this.webRegistrationIn(tx, { ...input, existing });
      const read = judge(this.now());
      if (read.kind === 'registered') {
        read.apply();
        if (read.created) tx.create(bindingRef, { version: 1, sourceId: read.binding.sourceId, generation: read.binding.generation });
      }
      return read;
    });
  }

  /** Grantのbinding記録を同じtransactionで読む（読取りだけ）。不正はSourceUnavailableError。 */
  async grantStateIn(tx: Transaction, grantHash: string): Promise<GrantSourceState> {
    const snapshot = await tx.get(this.grantRef(grantHash));
    return grantStateOf(snapshot);
  }

  /** bindingのsource recordを同じtransactionで読む（判定は呼出し側が全readの後の時刻でsourceBindingVerdict）。 */
  async sourceIn(tx: Transaction, binding: SourceBinding): Promise<SourceRecord | null> {
    return SourceStore.recordOf(await tx.get(this.sourceRef(binding.sourceId)));
  }

  /** 同意の書込み段階: Grantへbindingを結ぶ（Grant metadataの作成と同じtx）。 */
  bindGrantIn(tx: Transaction, grantHash: string, binding: SourceBinding): void {
    tx.set(this.grantRef(grantHash), { sourceId: binding.sourceId, generation: binding.generation });
  }

  /** Grantの終了と同じtxでbinding記録も消す。 */
  unbindGrantIn(tx: Transaction, grantHash: string): void {
    tx.delete(this.grantRef(grantHash));
  }

  /** transaction外のbinding照合（判定の時刻は読取りの後）。 */
  async bindingUsable(binding: SourceBinding): Promise<SourceVerdict> {
    let snapshot: DocumentSnapshot;
    try {
      snapshot = await this.sourceRef(binding.sourceId).get();
    } catch {
      throw new SourceUnavailableError();
    }
    return sourceBindingVerdict(SourceStore.recordOf(snapshot), binding, this.now());
  }

  /** transaction外のGrant照合（code交換・refresh・MCP入口）。最終保存/送出の順序は各最終transactionで決める。 */
  async grantUsable(grantHash: string): Promise<SourceVerdict | { readonly kind: 'rejected'; readonly reason: 'unbound' } | { readonly kind: 'usable' }> {
    try {
      const state = grantStateOf(await this.grantRef(grantHash).get());
      if (state.kind === 'unbound') return { kind: 'rejected', reason: 'unbound' };
      if (state.kind === 'account') return { kind: 'usable' };
      const record = SourceStore.recordOf(await this.sourceRef(state.binding.sourceId).get());
      return sourceBindingVerdict(record, state.binding, this.now());
    } catch {
      throw new SourceUnavailableError();
    }
  }

  // ---- 管理用（source/admin.tsだけが使う） ----

  /** 現在のrecordと版（不存在はabsent、存在はupdatedAtの数値文字列）。 */
  async status(sourceId: string): Promise<{ readonly record: SourceRecord | null; readonly version: string }> {
    let snapshot: DocumentSnapshot;
    try {
      snapshot = await this.sourceRef(sourceId).get();
    } catch {
      throw new SourceUnavailableError();
    }
    const record = SourceStore.recordOf(snapshot);
    return { record, version: versionOf(record) };
  }

  /** 新しいIDで1件作る（既存のIDへは書かない）。 */
  async create(record: SourceRecord): Promise<'created' | 'conflict'> {
    const ref = this.sourceRef(record.sourceId);
    return this.#run(async (tx) => {
      if ((await tx.get(ref)).exists) return 'conflict';
      tx.create(ref, { ...record, operations: [...record.operations] });
      return 'created';
    });
  }

  /** 期待版と一致した時だけ置き換える（nextがnullなら物理削除）。 */
  async change(
    sourceId: string,
    expected: string,
    next: (current: SourceRecord) => SourceRecord | null,
  ): Promise<{ readonly kind: 'changed'; readonly record: SourceRecord } | { readonly kind: 'deleted' } | { readonly kind: 'conflict' | 'missing' }> {
    const ref = this.sourceRef(sourceId);
    return this.#run(async (tx) => {
      const record = SourceStore.recordOf(await tx.get(ref));
      if (record === null) return { kind: 'missing' };
      if (versionOf(record) !== expected) return { kind: 'conflict' };
      const updated = next(record);
      if (updated === null) {
        tx.delete(ref);
        return { kind: 'deleted' };
      }
      tx.set(ref, { ...updated, operations: [...updated.operations] });
      return { kind: 'changed', record: updated };
    });
  }
}

function grantStateOf(snapshot: DocumentSnapshot): GrantSourceState {
  if (!snapshot.exists) return { kind: 'unbound' };
  const data = snapshot.data() as Record<string, unknown> | undefined;
  if (isAccountGrant(data)) return { kind: 'account' };
  const binding = { sourceId: data?.sourceId, generation: data?.generation };
  if (data === undefined || Object.keys(data).length !== 2 || !isSourceBinding(binding)) throw new SourceUnavailableError();
  return { kind: 'bound', binding: { sourceId: binding.sourceId, generation: binding.generation } };
}

export function versionOf(record: SourceRecord | null): string {
  return record === null ? 'absent' : String(record.updatedAt);
}
