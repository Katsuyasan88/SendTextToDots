// 開発者向け6桁ログインコードの共有Firestore保存（接続保存のroot sttdConnect/{namespace}配下）。
//   developerLoginCodeReservations/{codeHmac}  予約（発行＋24時間のdeleteAfter。平文コードなし）
//   developerLoginOperations/{operationIdHash} 発行操作（予定UIDの封緘・照会secretのHMAC・状態）
//   developerCodeIdentities/{identityHash}     code由来の長期identity（予約のTTL削除と独立）
//   developerLoginRate/{bucketHash}            入力試行の短期件数（生IP・コードなし）
//   developerLoginState/meta                   鍵の指紋・発行回数・有効コード・発行元世代（同時有効数/発行回数の共有判定）
// 発行は候補ごとに1 transaction（SDKの再実行max5）で予約文書の不存在を読んでcreateする。存在すれば別候補（初回を含め20個まで）、
// 発行全体15秒。transaction内では乱数・画面表示・ユーザー作成・token署名をしない。SDK障害・期限は衝突と区別してunavailableで止める。
// 試行は照合と同じtransactionで件数を予約してから判定し、並行・interaction/IP変更で全体上限を回避させない。bucket障害は拒否。
// クライアントSDKからこれらのcollectionを読書きさせない（firestore.rules）。管理SDKの権限はIAM・この限定操作で絞る。

import { Timestamp, type DocumentReference, type Firestore, type Transaction } from '@google-cloud/firestore';

import { accessDocRef } from '../access/firestore.js';
import { AccessRecordError, nextAccessRecord, parseAccessRecord } from '../access/policy.js';
import { hashesEqual, type SecretHasher } from '../secrets.js';
import {
  CODE_AUTH_TTL_MS,
  DEVELOPER_LOGIN_LIMITS,
  DEVELOPER_LOGIN_VERSION,
  DeveloperLoginError,
  ISSUE_BUDGET_MS,
  MAX_CODE_CANDIDATES,
  MAX_TRANSACTION_ATTEMPTS,
  RESERVATION_HOLD_MS,
  checkScope,
  claimSecretHashOf,
  codeIdentityHashOf,
  dedupeKeyFingerprint,
  drawCode,
  exactKeys,
  isCode,
  isCodeUid,
  isOpaque,
  isUuid,
  newCodeUid,
  newReservation,
  operationIdHashOf,
  parseReservation,
  pruneTimes,
  rateBucketOf,
  reservationIdOf,
  reservationUsable,
  transitionReservation,
  windowCount,
  type Clock,
  type DeveloperLoginScope,
  type RandomPort,
  type ReservationRecord,
} from './developer-login.js';

export const RESERVATIONS = 'developerLoginCodeReservations';
export const OPERATIONS = 'developerLoginOperations';
export const CODE_IDENTITIES = 'developerCodeIdentities';
export const RATE_BUCKETS = 'developerLoginRate';
export const STATE = 'developerLoginState';
const CONNECT_ROOT = 'sttdConnect';
const PLANNED_UID_PURPOSE = 't265:dlc:planned-uid';

/** 予定UIDの封緘（接続保存のConnectSealingPortと同じ形の部分）。 */
export interface UidSealer {
  seal(purpose: string, plaintext: string): string | PromiseLike<string>;
  open(purpose: string, sealed: string): string | PromiseLike<string>;
}

export interface DeveloperLoginLimits {
  readonly namespaceActiveMax: number;
  readonly consoleActiveMax: number;
  readonly consoleIssuesPerHour: number;
  readonly namespaceIssuesPerHour: number;
  readonly attemptsPerInteraction: number;
  readonly attemptsPerSource: number;
  readonly namespaceFailures: number;
  readonly issueWindowMs: number;
  readonly attemptWindowMs: number;
  readonly rateHoldMs: number;
}

export interface DeveloperLoginStoreDeps {
  readonly db: Firestore;
  readonly scope: DeveloperLoginScope;
  /** dedupeKey（配置ごとのサーバー秘密）のHMAC。ブラウザ・配布物に置かない。 */
  readonly hasher: SecretHasher;
  readonly sealer: UidSealer;
  readonly clock: Clock;
  readonly random: RandomPort;
  /** 省略時は設計§7の初期値（DEVELOPER_LOGIN_LIMITS）。 */
  readonly limits?: DeveloperLoginLimits | undefined;
}

export type IssueOutcome = {
  readonly kind: 'issued';
  readonly code: string;
  readonly operationId: string;
  readonly issuedAt: number;
  readonly authExpiresAt: number;
  readonly candidates: number;
};

export type ConsumeOutcome =
  | {
      readonly kind: 'consumed';
      readonly operationIdHash: string;
      readonly issuanceId: string;
      readonly uid: string;
      readonly familyId: string;
    }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'rate_limited' };

export type ActivateOutcome = { readonly kind: 'active' } | { readonly kind: 'revoked' } | { readonly kind: 'conflict' };

export type ClaimOutcome =
  | { readonly kind: 'pending' }
  | { readonly kind: 'active'; readonly uid: string; readonly familyId: string }
  | { readonly kind: 'ended' };

export type CodeIdentityState = 'active' | 'revoked' | 'missing';

interface OperationRecord {
  readonly version: 1;
  readonly issuanceId: string;
  readonly reservationId: string;
  readonly consoleHash: string;
  readonly consoleGeneration: number;
  readonly sealedUid: string;
  readonly familyId: string;
  readonly state: 'issued' | 'provisioning' | 'active' | 'failed' | 'revoked';
  readonly identityHash: string | null;
  readonly createdAt: number;
  readonly deleteAfter: number;
}
const OPERATION_KEYS = [
  'version',
  'issuanceId',
  'reservationId',
  'consoleHash',
  'consoleGeneration',
  'sealedUid',
  'familyId',
  'state',
  'identityHash',
  'createdAt',
  'deleteAfter',
] as const;
const OPERATION_STATES: ReadonlySet<string> = new Set(['issued', 'provisioning', 'active', 'failed', 'revoked']);

interface IdentityRecord {
  readonly version: 1;
  readonly familyId: string;
  readonly consoleHash: string;
  readonly issuanceId: string;
  readonly currentGeneration: string;
  readonly accessIdentityHash: string;
  readonly state: 'active' | 'revoked';
  readonly createdAt: number;
  readonly revokedAt: number | null;
}
const IDENTITY_KEYS = [
  'version',
  'familyId',
  'consoleHash',
  'issuanceId',
  'currentGeneration',
  'accessIdentityHash',
  'state',
  'createdAt',
  'revokedAt',
] as const;

interface ConsoleEntry {
  readonly generation: number;
  readonly operationIdHash: string | null;
  readonly until: number;
}
interface MetaRecord {
  readonly version: 1;
  readonly fingerprint: string;
  readonly holdUntil: number;
  readonly issues: readonly { readonly at: number; readonly consoleHash: string }[];
  readonly active: readonly { readonly consoleHash: string; readonly issuanceId: string; readonly until: number }[];
  readonly consoles: Readonly<Record<string, ConsoleEntry>>;
}
interface RevokeTarget {
  readonly operation: OperationRecord;
  readonly operationIdHash: string;
  readonly reservation: ReservationRecord | null;
  readonly identity: IdentityRecord | null;
  readonly access: unknown;
  readonly accessExists: boolean;
}
const META_KEYS =['version', 'fingerprint', 'holdUntil', 'issues', 'active', 'consoles'] as const;
const RATE_KEYS = ['version', 'windowStart', 'count', 'deleteAfter'] as const;

function millisOf(value: unknown): number | null {
  if (value instanceof Timestamp) {
    const ms = value.toMillis();
    return Number.isSafeInteger(ms) ? ms : null;
  }
  return null;
}

function stamp(ms: number): Timestamp {
  return Timestamp.fromMillis(ms);
}

function unavailable(): DeveloperLoginError {
  return new DeveloperLoginError('unavailable');
}

function parseOperation(data: unknown): OperationRecord {
  const r = exactKeys(data, OPERATION_KEYS);
  const deleteAfter = millisOf(r.deleteAfter);
  if (r.version !== DEVELOPER_LOGIN_VERSION || !isUuid(r.issuanceId) || !isUuid(r.familyId)) throw unavailable();
  if (typeof r.reservationId !== 'string' || typeof r.consoleHash !== 'string' || typeof r.sealedUid !== 'string') throw unavailable();
  if (!Number.isSafeInteger(r.consoleGeneration) || (r.consoleGeneration as number) < 1) throw unavailable();
  if (typeof r.state !== 'string' || !OPERATION_STATES.has(r.state)) throw unavailable();
  if (r.identityHash !== null && typeof r.identityHash !== 'string') throw unavailable();
  if (typeof r.createdAt !== 'number' || deleteAfter === null) throw unavailable();
  return { ...(r as unknown as OperationRecord), deleteAfter };
}

function parseIdentity(data: unknown): IdentityRecord {
  const r = exactKeys(data, IDENTITY_KEYS);
  if (r.version !== DEVELOPER_LOGIN_VERSION || !isUuid(r.familyId) || !isUuid(r.issuanceId)) throw unavailable();
  if (typeof r.consoleHash !== 'string' || typeof r.currentGeneration !== 'string' || typeof r.accessIdentityHash !== 'string') throw unavailable();
  if (r.state !== 'active' && r.state !== 'revoked') throw unavailable();
  if (typeof r.createdAt !== 'number' || (r.revokedAt !== null && typeof r.revokedAt !== 'number')) throw unavailable();
  return r as unknown as IdentityRecord;
}

function parseMeta(data: unknown): MetaRecord {
  const r = exactKeys(data, META_KEYS);
  if (r.version !== DEVELOPER_LOGIN_VERSION || typeof r.fingerprint !== 'string' || typeof r.holdUntil !== 'number') throw unavailable();
  if (!Array.isArray(r.issues) || !Array.isArray(r.active) || typeof r.consoles !== 'object' || r.consoles === null) throw unavailable();
  return r as unknown as MetaRecord;
}

function parseRate(data: unknown): { windowStart: number; count: number } {
  const r = exactKeys(data, RATE_KEYS);
  if (r.version !== DEVELOPER_LOGIN_VERSION || typeof r.windowStart !== 'number' || !Number.isSafeInteger(r.count)) throw unavailable();
  return { windowStart: r.windowStart, count: r.count as number };
}

/** 各操作の元期限の既定（発行・交換と同じ15秒）。 */
const OPERATION_BUDGET_MS = ISSUE_BUDGET_MS;

/**
 * SDK・DBの例外は固定のunavailableへ閉じる（衝突として扱って別候補で叩き直さない）。deadline（epoch ms）までに返らなければ待つのをやめて
 * unavailable。開始済みのcommitの物理的な取消は約束しない（結果不明は成功として表示・解放しない）。
 */
async function guard<T>(task: () => Promise<T>, deadline?: number, clock?: Clock): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const running = task();
    if (deadline === undefined || clock === undefined) return await running;
    const remaining = deadline - clock.now();
    if (remaining <= 0) {
      running.catch(() => undefined);
      throw unavailable();
    }
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(unavailable()), remaining);
      timer.unref?.();
    });
    running.catch(() => undefined);
    return await Promise.race([running, expired]);
  } catch (error) {
    if (error instanceof DeveloperLoginError) throw error;
    throw unavailable();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class DeveloperLoginStore {
  readonly #d: DeveloperLoginStoreDeps;
  readonly #scope: DeveloperLoginScope;
  readonly #limits: DeveloperLoginLimits;
  readonly #root: DocumentReference;

  constructor(deps: DeveloperLoginStoreDeps) {
    this.#d = deps;
    this.#scope = checkScope(deps.scope);
    this.#limits = deps.limits ?? DEVELOPER_LOGIN_LIMITS;
    this.#root = deps.db.collection(CONNECT_ROOT).doc(this.#scope.namespace);
  }

  get scope(): DeveloperLoginScope {
    return this.#scope;
  }

  #reservationRef(id: string): DocumentReference {
    return this.#root.collection(RESERVATIONS).doc(id);
  }
  #operationRef(hash: string): DocumentReference {
    return this.#root.collection(OPERATIONS).doc(hash);
  }
  #identityRef(hash: string): DocumentReference {
    return this.#root.collection(CODE_IDENTITIES).doc(hash);
  }
  #rateRef(hash: string): DocumentReference {
    return this.#root.collection(RATE_BUCKETS).doc(hash);
  }
  #metaRef(): DocumentReference {
    return this.#root.collection(STATE).doc('meta');
  }

  /** 予約文書ID（試験・保守での存在確認用。平文コードは保存しない）。 */
  reservationIdOf(code: string): string {
    return reservationIdOf(this.#d.hasher, this.#scope, code);
  }

  /** code identity文書のhash（API/MCPの照合と管理表示）。 */
  identityHashOf(uid: string): string {
    return codeIdentityHashOf(this.#d.hasher, this.#scope, uid);
  }

  async #meta(tx: Transaction): Promise<MetaRecord | null> {
    const snapshot = await tx.get(this.#metaRef());
    return snapshot.exists ? parseMeta(snapshot.data()) : null;
  }

  // ---------- 発行・再発行 ----------

  /**
   * コンソールの明示操作による発行。previousOperationIdがあれば同じ発行元の再発行で、新予約の作成と旧family/予約の失効を同じ
   * transactionで確定する（新候補を確保できなければ旧接続を止めない）。照会secretは発行元helperのRAMだけにあり、DBはHMACだけ。
   */
  async issue(input: { readonly claimSecret: string; readonly previousOperationId?: string | undefined }): Promise<IssueOutcome> {
    const { hasher, clock, random } = this.#d;
    const consoleHash = claimSecretHashOf(hasher, this.#scope, input.claimSecret);
    const previousHash = input.previousOperationId === undefined ? null : operationIdHashOf(hasher, this.#scope, input.previousOperationId);
    const startedAt = clock.now();
    const deadline = startedAt + ISSUE_BUDGET_MS;
    const live = () => {
      if (clock.now() >= deadline) throw unavailable();
    };
    // 予定UID・operationId・familyはtransactionの外で1回だけ作る（再実行で値を変えない）。
    const uid = newCodeUid(random);
    const operationId = random.bytes(32).toString('base64url');
    const operationIdHash = operationIdHashOf(hasher, this.#scope, operationId);
    const issuanceId = random.uuid();
    const familyId = random.uuid();
    const sealedUid = await guard(async () => this.#d.sealer.seal(PLANNED_UID_PURPOSE, uid), deadline, clock);
    const fingerprint = dedupeKeyFingerprint(hasher, this.#scope);

    for (let candidate = 1; candidate <= MAX_CODE_CANDIDATES; candidate += 1) {
      live();
      const code = drawCode(random);
      const reservationId = reservationIdOf(hasher, this.#scope, code);
      const outcome = await guard(() =>
        this.#d.db.runTransaction(
          async (tx): Promise<'collision' | { issuedAt: number }> => {
            live();
            const reservationRef = this.#reservationRef(reservationId);
            const reserved = await tx.get(reservationRef);
            const meta = await this.#meta(tx);
            const previous = previousHash === null ? null : await this.#readOperationForRevoke(tx, previousHash, consoleHash);
            live();
            // 予約文書が物理的に残っている間は（deleteAfter後の削除遅延中も）同じ番号を使わない。
            if (reserved.exists) return 'collision';
            const now = clock.now();
            // 鍵の指紋が違えば時間に関係なく拒否する（24時間後もTTL削除待ちの旧予約が残り得て、新しい鍵では同番号が別IDになる）。
            // 解除は配置側が全予約の削除を確認してから行う明示の管理移行だけ（このmoduleに自動解除は無い）。
            if (meta !== null && meta.fingerprint !== fingerprint) throw new DeveloperLoginError('key_rotation_blocked');
            const prior = previous === null ? null : previous.operation;
            const issues = pruneTimes(
              (meta?.issues ?? []).map((entry) => entry.at),
              now,
              this.#limits.issueWindowMs,
            );
            const issueEntries = (meta?.issues ?? []).filter((entry) => issues.includes(entry.at));
            const active = (meta?.active ?? []).filter((entry) => entry.until > now && entry.issuanceId !== prior?.issuanceId);
            const consoles: Record<string, ConsoleEntry> = {};
            for (const [key, entry] of Object.entries(meta?.consoles ?? {})) if (entry.until > now || key === consoleHash) consoles[key] = entry;
            if (issueEntries.length >= this.#limits.namespaceIssuesPerHour) throw new DeveloperLoginError('rate_limited');
            if (issueEntries.filter((entry) => entry.consoleHash === consoleHash).length >= this.#limits.consoleIssuesPerHour) {
              throw new DeveloperLoginError('rate_limited');
            }
            if (active.length >= this.#limits.namespaceActiveMax) throw new DeveloperLoginError('rate_limited');
            if (active.filter((entry) => entry.consoleHash === consoleHash).length >= this.#limits.consoleActiveMax) {
              throw new DeveloperLoginError('rate_limited');
            }
            const current = consoles[consoleHash];
            if (previousHash !== null && (current === undefined || current.operationIdHash !== previousHash)) throw new DeveloperLoginError('not_owner');
            const generation = (current?.generation ?? 0) + 1;
            if (previous !== null) this.#writeRevoke(tx, previous, now);
            const record = newReservation({ issuanceId, consoleHash, consoleGeneration: generation, purpose: this.#scope.purpose, issuedAt: now });
            tx.create(reservationRef, { ...record, deleteAfter: stamp(record.deleteAfter), operationIdHash });
            tx.create(this.#operationRef(operationIdHash), {
              version: DEVELOPER_LOGIN_VERSION,
              issuanceId,
              reservationId,
              consoleHash,
              consoleGeneration: generation,
              sealedUid,
              familyId,
              state: 'issued',
              identityHash: null,
              createdAt: now,
              deleteAfter: stamp(record.deleteAfter),
            });
            consoles[consoleHash] = { generation, operationIdHash, until: record.deleteAfter };
            tx.set(this.#metaRef(), {
              version: DEVELOPER_LOGIN_VERSION,
              fingerprint,
              holdUntil: Math.max(meta?.holdUntil ?? 0, record.deleteAfter),
              issues: [...issueEntries, { at: now, consoleHash }],
              active: [...active, { consoleHash, issuanceId, until: record.authExpiresAt }],
              consoles,
            });
            live();
            return { issuedAt: now };
          },
          { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
        ),
        deadline,
        clock,
      );
      if (outcome === 'collision') continue;
      // DBへ登録できた後だけ表示する値を返す。
      return Object.freeze({
        kind: 'issued' as const,
        code,
        operationId,
        issuedAt: outcome.issuedAt,
        authExpiresAt: outcome.issuedAt + CODE_AUTH_TTL_MS,
        candidates: candidate,
      });
    }
    throw new DeveloperLoginError('issue_exhausted');
  }

  async #readOperationForRevoke(tx: Transaction, operationIdHash: string, consoleHash: string): Promise<RevokeTarget | null> {
    const snapshot = await tx.get(this.#operationRef(operationIdHash));
    if (!snapshot.exists) return null;
    const operation = parseOperation(snapshot.data());
    if (!hashesEqual(operation.consoleHash, consoleHash)) throw new DeveloperLoginError('not_owner');
    const reserved = await tx.get(this.#reservationRef(operation.reservationId));
    const reservation = reserved.exists ? this.#parseReservationDoc(reserved.data()) : null;
    // 同番号の再利用後の予約は別issuance（旧operationから触れない）。
    const ownReservation = reservation !== null && reservation.issuanceId === operation.issuanceId ? reservation : null;
    let identity: IdentityRecord | null = null;
    let access: unknown;
    let accessExists = false;
    if (operation.identityHash !== null) {
      const found = await tx.get(this.#identityRef(operation.identityHash));
      identity = found.exists ? parseIdentity(found.data()) : null;
      if (identity !== null) {
        const accessSnapshot = await tx.get(accessDocRef(this.#root, identity.accessIdentityHash));
        accessExists = accessSnapshot.exists;
        access = accessSnapshot.data();
      }
    }
    return { operation, operationIdHash, reservation: ownReservation, identity, access, accessExists };
  }

  #parseReservationDoc(data: unknown): ReservationRecord & { readonly operationIdHash: string } {
    if (typeof data !== 'object' || data === null) throw unavailable();
    const { operationIdHash, ...rest } = data as Record<string, unknown>;
    if (typeof operationIdHash !== 'string') throw unavailable();
    return { ...parseReservation(rest, millisOf), operationIdHash };
  }

  /** 旧予約の取消・旧operation/identityの失効・利用許可の新しい世代（disabled）。deleteAfterは縮めない。 */
  #writeRevoke(tx: Transaction, target: RevokeTarget, now: number): void {
    const { operation, operationIdHash, reservation, identity, access, accessExists } = target;
    if (reservation !== null && reservation.state !== 'revoked') {
      tx.update(this.#reservationRef(operation.reservationId), { state: transitionReservation(reservation, 'revoked').state });
    }
    if (operation.state !== 'revoked') tx.update(this.#operationRef(operationIdHash), { state: 'revoked' });
    if (identity !== null && identity.state === 'active' && operation.identityHash !== null) {
      tx.update(this.#identityRef(operation.identityHash), { state: 'revoked', revokedAt: now });
      if (accessExists) {
        let record;
        try {
          record = parseAccessRecord(access);
        } catch (error) {
          if (error instanceof AccessRecordError) throw unavailable();
          throw error;
        }
        const next = nextAccessRecord(record, 'disabled', now, this.#d.random.uuid());
        if (next !== null) tx.set(accessDocRef(this.#root, identity.accessIdentityHash), { ...next });
      }
    }
  }

  /** 同じ発行元の取消（未使用コードの取消、または接続済みならそのfamilyの失効）。 */
  async cancel(input: { readonly claimSecret: string; readonly operationId: string }): Promise<'revoked' | 'unknown'> {
    const consoleHash = claimSecretHashOf(this.#d.hasher, this.#scope, input.claimSecret);
    const operationIdHash = operationIdHashOf(this.#d.hasher, this.#scope, input.operationId);
    return guard(() =>
      this.#d.db.runTransaction(
        async (tx) => {
          const target = await this.#readOperationForRevoke(tx, operationIdHash, consoleHash);
          const meta = await this.#meta(tx);
          if (target === null) return 'unknown' as const;
          const now = this.#d.clock.now();
          this.#writeRevoke(tx, target, now);
          if (meta !== null) {
            tx.update(this.#metaRef(), { active: meta.active.filter((entry) => entry.issuanceId !== target.operation.issuanceId) });
          }
          return 'revoked' as const;
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ),
      this.#d.clock.now() + OPERATION_BUDGET_MS,
      this.#d.clock,
    );
  }

  // ---------- 交換（プラグインOAuth接続画面） ----------

  async #bump(tx: Transaction, ref: DocumentReference, now: number, limit: number): Promise<{ over: boolean; write: () => void }> {
    const snapshot = await tx.get(ref);
    const current = windowCount(snapshot.exists ? parseRate(snapshot.data()) : null, now, this.#limits.attemptWindowMs);
    return {
      over: current.count >= limit,
      write: () =>
        tx.set(ref, {
          version: DEVELOPER_LOGIN_VERSION,
          windowStart: current.windowStart,
          count: current.count + 1,
          deleteAfter: stamp(current.windowStart + this.#limits.attemptWindowMs + this.#limits.rateHoldMs),
        }),
    };
  }

  /**
   * コード消費と入力先interactionへの束縛を1 transactionで確定する。試行件数（interaction・送信元）を照合前に予約し、namespace全体の
   * 失敗件数も同じtransactionで読む。不存在・期限切れ・使用済み・取消・別世代は同じrejected。
   */
  async consume(input: { readonly code: string; readonly interactionKey: string; readonly sourceKey: string; readonly deadline?: number | undefined }): Promise<ConsumeOutcome> {
    const { hasher, clock } = this.#d;
    const deadline = input.deadline ?? clock.now() + OPERATION_BUDGET_MS;
    if (!isCode(input.code) || input.interactionKey.length === 0 || input.sourceKey.length === 0) throw new DeveloperLoginError('invalid_request');
    const reservationId = reservationIdOf(hasher, this.#scope, input.code);
    const interactionHash = rateBucketOf(hasher, this.#scope, 'interaction', input.interactionKey);
    const sourceHash = rateBucketOf(hasher, this.#scope, 'source', input.sourceKey);
    const namespaceHash = rateBucketOf(hasher, this.#scope, 'namespace', 'failures');
    const outcome = await guard(() =>
      this.#d.db.runTransaction(
        async (tx) => {
          const now = clock.now();
          const perInteraction = await this.#bump(tx, this.#rateRef(interactionHash), now, this.#limits.attemptsPerInteraction);
          const perSource = await this.#bump(tx, this.#rateRef(sourceHash), now, this.#limits.attemptsPerSource);
          const failures = await this.#bump(tx, this.#rateRef(namespaceHash), now, this.#limits.namespaceFailures);
          const reserved = await tx.get(this.#reservationRef(reservationId));
          const meta = await this.#meta(tx);
          const reservation = reserved.exists ? this.#parseReservationDoc(reserved.data()) : null;
          const operationSnapshot = reservation === null ? null : await tx.get(this.#operationRef(reservation.operationIdHash));
          const operation = operationSnapshot?.exists === true ? parseOperation(operationSnapshot.data()) : null;
          // 読取りを終えてから書く（Firestoreのtransactionは全読取りが書込みより前）。上限到達は照合しない。
          if (perInteraction.over || perSource.over || failures.over) return { kind: 'rate_limited' as const };
          perInteraction.write();
          perSource.write();
          const consoleEntry = reservation === null ? undefined : meta?.consoles[reservation.consoleHash];
          const valid =
            reservation !== null &&
            operation !== null &&
            reservation.purpose === this.#scope.purpose &&
            reservationUsable(reservation, now) &&
            operation.state === 'issued' &&
            operation.issuanceId === reservation.issuanceId &&
            consoleEntry !== undefined &&
            consoleEntry.generation === reservation.consoleGeneration;
          if (!valid) {
            failures.write();
            return { kind: 'rejected' as const };
          }
          tx.update(this.#reservationRef(reservationId), { state: 'provisioning', boundInteractionHash: interactionHash });
          tx.update(this.#operationRef(reservation.operationIdHash), { state: 'provisioning' });
          return { kind: 'consumed' as const, operationIdHash: reservation.operationIdHash, operation };
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ),
      deadline,
      clock,
    );
    if (outcome.kind !== 'consumed') return outcome;
    let uid: string;
    try {
      uid = await guard(async () => this.#d.sealer.open(PLANNED_UID_PURPOSE, outcome.operation.sealedUid), deadline, clock);
      if (!isCodeUid(uid)) throw unavailable();
    } catch (error) {
      // 消費済みの後の開封失敗はfailedで止める（未使用へ戻さない）。
      await this.fail({ operationIdHash: outcome.operationIdHash, issuanceId: outcome.operation.issuanceId }).catch(() => undefined);
      throw error;
    }
    return Object.freeze({
      kind: 'consumed' as const,
      operationIdHash: outcome.operationIdHash,
      issuanceId: outcome.operation.issuanceId,
      uid,
      familyId: outcome.operation.familyId,
    });
  }

  /**
   * Firebase作成・署名の失敗/応答消失/期限超過。消費をissuedへ戻さず、failedで止める（許可を作らない）。期限後に遅れて確定した
   * activeが見つかれば、そのidentityと利用許可を失効させる（結果不明のまま接続を解放しない）。
   */
  async fail(input: { readonly operationIdHash: string; readonly issuanceId: string }): Promise<void> {
    const { clock } = this.#d;
    await guard(
      () =>
      this.#d.db.runTransaction(
        async (tx) => {
          const opRef = this.#operationRef(input.operationIdHash);
          const snapshot = await tx.get(opRef);
          if (!snapshot.exists) return;
          const operation = parseOperation(snapshot.data());
          if (operation.issuanceId !== input.issuanceId) return;
          if (operation.state === 'active') {
            const target = await this.#readOperationForRevoke(tx, input.operationIdHash, operation.consoleHash);
            if (target !== null) this.#writeRevoke(tx, target, clock.now());
            return;
          }
          const reserved = await tx.get(this.#reservationRef(operation.reservationId));
          if (operation.state !== 'provisioning') return;
          tx.update(opRef, { state: 'failed' });
          if (reserved.exists) {
            const reservation = this.#parseReservationDoc(reserved.data());
            if (reservation.issuanceId === operation.issuanceId && reservation.state === 'provisioning') {
              tx.update(this.#reservationRef(operation.reservationId), { state: 'failed' });
            }
          }
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ),
      clock.now() + OPERATION_BUDGET_MS,
      clock,
    );
  }

  /**
   * Firebaseアカウント作成の後、同じissuance・発行元世代・非取消を再確認し、code identityとこのUID1件の利用許可（新しい世代）を
   * 一緒に確定する。既存のidentity/許可recordがあれば採用せずconflict。
   */
  async activate(input: {
    readonly operationIdHash: string;
    readonly issuanceId: string;
    readonly uid: string;
    readonly accessIdentityHash: string;
    /** 交換の元期限。これを過ぎた実行では確定を書かない（遅れた確定で接続を解放しない）。 */
    readonly deadline?: number | undefined;
  }): Promise<ActivateOutcome> {
    const { clock, random } = this.#d;
    const deadline = input.deadline ?? clock.now() + OPERATION_BUDGET_MS;
    const identityHash = this.identityHashOf(input.uid);
    const generation = random.uuid();
    return guard(() =>
      this.#d.db.runTransaction(
        async (tx): Promise<ActivateOutcome> => {
          const opRef = this.#operationRef(input.operationIdHash);
          const opSnapshot = await tx.get(opRef);
          const meta = await this.#meta(tx);
          const identitySnapshot = await tx.get(this.#identityRef(identityHash));
          const accessRef = accessDocRef(this.#root, input.accessIdentityHash);
          const accessSnapshot = await tx.get(accessRef);
          if (!opSnapshot.exists) return { kind: 'revoked' };
          const operation = parseOperation(opSnapshot.data());
          const reserved = await tx.get(this.#reservationRef(operation.reservationId));
          const reservation = reserved.exists ? this.#parseReservationDoc(reserved.data()) : null;
          if (operation.issuanceId !== input.issuanceId) return { kind: 'conflict' };
          if (operation.state !== 'provisioning' || reservation === null || reservation.issuanceId !== operation.issuanceId || reservation.state !== 'provisioning') {
            return { kind: 'revoked' };
          }
          const consoleEntry = meta?.consoles[operation.consoleHash];
          if (consoleEntry === undefined || consoleEntry.generation !== operation.consoleGeneration) return { kind: 'revoked' };
          if (identitySnapshot.exists || accessSnapshot.exists) return { kind: 'conflict' };
          const now = clock.now();
          if (now >= deadline) return { kind: 'revoked' };
          const access = nextAccessRecord(null, 'active', now, generation);
          if (access === null) return { kind: 'conflict' };
          tx.create(this.#identityRef(identityHash), {
            version: DEVELOPER_LOGIN_VERSION,
            familyId: operation.familyId,
            consoleHash: operation.consoleHash,
            issuanceId: operation.issuanceId,
            currentGeneration: generation,
            accessIdentityHash: input.accessIdentityHash,
            state: 'active',
            createdAt: now,
            revokedAt: null,
          });
          tx.create(accessRef, { ...access });
          tx.update(opRef, { state: 'active', identityHash });
          tx.update(this.#reservationRef(operation.reservationId), { state: 'active' });
          return { kind: 'active' };
        },
        { maxAttempts: MAX_TRANSACTION_ATTEMPTS },
      ),
      deadline,
      clock,
    );
  }

  // ---------- 発行元コンソールの照会 ----------

  /** 照会secretの証明付きでだけ状態を返す（6桁だけでは呼べない）。同番号の再利用後の旧operationは新予約へ触れない。 */
  async claim(input: { readonly claimSecret: string; readonly operationId: string }): Promise<ClaimOutcome> {
    const consoleHash = claimSecretHashOf(this.#d.hasher, this.#scope, input.claimSecret);
    const operationIdHash = operationIdHashOf(this.#d.hasher, this.#scope, input.operationId);
    const snapshot = await guard(() => this.#operationRef(operationIdHash).get(), this.#d.clock.now() + OPERATION_BUDGET_MS, this.#d.clock);
    if (!snapshot.exists) return { kind: 'ended' };
    const operation = parseOperation(snapshot.data());
    if (!hashesEqual(operation.consoleHash, consoleHash)) throw new DeveloperLoginError('not_owner');
    if (operation.state === 'issued' || operation.state === 'provisioning') return { kind: 'pending' };
    if (operation.state !== 'active' || operation.identityHash === null) return { kind: 'ended' };
    const identity = await this.identityState(operation.identityHash);
    if (identity.state !== 'active' || identity.familyId !== operation.familyId) return { kind: 'ended' };
    const uid = await guard(async () => this.#d.sealer.open(PLANNED_UID_PURPOSE, operation.sealedUid));
    if (!isCodeUid(uid) || this.identityHashOf(uid) !== operation.identityHash) throw unavailable();
    return Object.freeze({ kind: 'active' as const, uid, familyId: operation.familyId });
  }

  // ---------- API/MCPの照合 ----------

  async identityState(identityHash: string): Promise<{ readonly state: CodeIdentityState; readonly familyId: string | null; readonly generation: string | null }> {
    const snapshot = await guard(() => this.#identityRef(identityHash).get(), this.#d.clock.now() + OPERATION_BUDGET_MS, this.#d.clock);
    if (!snapshot.exists) return { state: 'missing', familyId: null, generation: null };
    const identity = parseIdentity(snapshot.data());
    return { state: identity.state, familyId: identity.familyId, generation: identity.currentGeneration };
  }

  /** 予約の保持期間（試験・文書用の固定値）。 */
  static readonly holdMs = RESERVATION_HOLD_MS;
}

export function isClaimSecret(value: unknown): value is string {
  return isOpaque(value);
}
