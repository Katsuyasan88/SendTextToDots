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

import type { Clock } from '../policy.js';
import {
  APPROVAL_MAX_MS,
  isSourceBinding,
  parseSourceRecord,
  SOURCE_APPROVALS_COLLECTION,
  SOURCE_ID,
  SOURCE_RECORD_CLEANUP_MS,
  SOURCE_REPLAY_COLLECTION,
  sourceBindingVerdict,
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
const HASH = /^[0-9a-f]{64}$/;
const DEFAULT_ATTEMPTS = 3;

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

/** Grantのbinding記録の状態（strictではunboundの旧Grantを使わない）。 */
export type GrantSourceState = { readonly kind: 'bound'; readonly binding: SourceBinding } | { readonly kind: 'unbound' };

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
    return this.#run(async (tx) => {
      const snapshot = await tx.get(sourceRef);
      const seen = replayRef === undefined ? undefined : await tx.get(replayRef);
      const now = this.now();
      if (check.validAt !== undefined && !check.validAt(now)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceRequestVerdict(SourceStore.recordOf(snapshot), { method: check.method, operation: check.operation, identityHash: check.identityHash, now });
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
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
    return this.#run(async (tx) => {
      const source = await tx.get(sourceRef);
      const existing = await tx.get(approvalRef);
      const now = this.now();
      const expiresAt = Math.min(interactionExpiresAt, now + APPROVAL_MAX_MS);
      if (!(now < expiresAt)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceBindingVerdict(SourceStore.recordOf(source), binding, now);
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
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
    const expiresAt = data.expiresAt;
    const consumed = data.consumed;
    const matches = data.identityHash === subject.identityHash && data.clientHash === subject.clientHash && data.resourceHash === subject.resourceHash;
    return (now: number): ApprovalRead => {
      if (!matches) return { kind: 'rejected', reason: 'mismatch' };
      if (consumed) return { kind: 'rejected', reason: 'consumed' };
      if (!(now < expiresAt)) return { kind: 'rejected', reason: 'expired' };
      const verdict = sourceBindingVerdict(record, binding, now);
      if (verdict.kind !== 'usable') return { kind: 'rejected', reason: verdict.reason };
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
    return (
      data !== undefined &&
      data.consumed === false &&
      typeof data.expiresAt === 'number' &&
      this.now() < data.expiresAt &&
      data.clientHash === request.clientHash &&
      data.resourceHash === request.resourceHash
    );
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
  async grantUsable(grantHash: string): Promise<SourceVerdict | { readonly kind: 'rejected'; readonly reason: 'unbound' }> {
    try {
      const state = grantStateOf(await this.grantRef(grantHash).get());
      if (state.kind === 'unbound') return { kind: 'rejected', reason: 'unbound' };
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
  const binding = { sourceId: data?.sourceId, generation: data?.generation };
  if (data === undefined || Object.keys(data).length !== 2 || !isSourceBinding(binding)) throw new SourceUnavailableError();
  return { kind: 'bound', binding: { sourceId: binding.sourceId, generation: binding.generation } };
}

export function versionOf(record: SourceRecord | null): string {
  return record === null ? 'absent' : String(record.updatedAt);
}
