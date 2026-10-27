// 本文暗号化の鍵ringとcontrolsのFirestore adapter（同じDB、root sttdEncryption/{encryptionNamespace}）。
//   - 認可は既存の接続保存（sttdConnect/{connectNamespace}）のaccess/{identityHash}・identities/{identityHash}・owners/{ownerId}を
//     同じtransactionで読むだけ。ownerや許可を作らない・補完しない（owner未作成は作成0でconnection_required）。
//   - transactionの閉包の中は読取り→照合→書込みだけ。鍵生成・Secret・乱数・HTTPは閉包の外（service.ts）で1回だけ行い、
//     SDKが閉包を再実行しても候補を作り直さない。最大3回の試行。
//   - liveは呼出し元の元期限・中止の検査（過ぎていれば例外）。transactionの開始前・各実行の開始・各awaitの後・書込みの直前に呼び、
//     期限後に新しいtransaction・書込みを始めない。期限前に始めたcommitの物理的な取消は約束しない。
//   - 時計は安全な正の整数msだけを受け付け、保存窓より前の時刻（巻戻し）や不正な時刻は固定障害にする（rate枠を取り直さない）。
//   - rateは初期化前から使うcontrols/{scope}へ分け、鍵の無い仮ringを作らない。ring/controlsの不正schemaは修復せずEncryptionRecordError。
//   - 無活動期限（owner.lastActiveAt・ring.lastUsedAt）は成功した取得だけで更新し、拒否・失敗・期限切れでは延ばさない。
//   - checkKeyEvidenceは暗号文経路のdispatch（T073）が自分のtransactionの中で鍵状態・期限を最新snapshotで読むためのtyped port。

import type { DocumentReference, DocumentSnapshot, Firestore, Transaction } from '@google-cloud/firestore';

import { accessDocRef, accessVerdictOfSnapshot } from '../access/firestore.js';
import { CONNECT_STORAGE_ROOT } from '../connect/firestore.js';
import {
  CONTROLS_COLLECTION,
  ENCRYPTION_STORAGE_ROOT,
  EncryptionRecordError,
  MAX_REISSUES,
  REISSUE_PENDING_MAX_MS,
  REISSUE_SPACING_MS,
  REISSUE_WINDOW_MS,
  RING_INACTIVITY_MS,
  RINGS_COLLECTION,
  consumeRate,
  emptyControls,
  isScope,
  keyUsable,
  parseControlsRecord,
  parseRingRecord,
  pruneRing,
  reissuedResultOf,
  rotateKeys,
  type ControlsRecord,
  type KeyRecord,
  type PublicKeyResult,
  type RateKind,
  type RateWindow,
  type ReissuedKey,
  type ReissueMode,
  type ReissueRecord,
  type RingRecord,
} from './contract.js';

export const TRANSACTION_ATTEMPTS = 3;
/** owner無活動失効（接続保存と同じ90日）。 */
export const OWNER_INACTIVITY_MS = 90 * 24 * 60 * 60 * 1000;

/** 保存の読取り・判定が一時的にできない（固定message）。 */
export class EncryptionUnavailableError extends Error {
  override readonly name = 'EncryptionUnavailableError';
  constructor() {
    super('encryption storage is temporarily unavailable');
  }
}

export interface RingBinding {
  readonly identityHash: string;
  readonly ownerId: string;
  readonly scope: string;
}

export type AdmissionDenied = { readonly kind: 'connection_required' } | { readonly kind: 'access_denied' };

export type BeginOutcome =
  | AdmissionDenied
  | { readonly kind: 'rate_limited'; readonly retryAfterSec: number }
  /** 既存ringがあり、activeの最終利用から90日を過ぎている（再初期化で生き返らせない）。 */
  | { readonly kind: 'key_expired' }
  | { readonly kind: 'ready'; readonly binding: RingBinding; readonly ring: RingRecord }
  /** 既存ringに書込み版以外のSecret版で包んだ鍵がある（取得時rewrapの対象）。 */
  | { readonly kind: 'rewrap'; readonly binding: RingBinding; readonly ring: RingRecord }
  | { readonly kind: 'initialize'; readonly binding: RingBinding };

export type CommitOutcome =
  | AdmissionDenied
  | { readonly kind: 'key_expired' }
  | { readonly kind: 'created' | 'existing' | 'updated' | 'conflict'; readonly ring: RingRecord };

/** commit応答不明の後の採用read。 */
export type AdoptedOutcome = AdmissionDenied | { readonly kind: 'key_expired' } | { readonly kind: 'absent' } | { readonly kind: 'adopted'; readonly ring: RingRecord };

export type ReissueBeginOutcome =
  | AdmissionDenied
  | { readonly kind: 'rate_limited'; readonly retryAfterSec: number }
  | { readonly kind: 'key_not_initialized' | 'key_expired' | 'conflict' | 'in_flight' | 'in_progress' | 'failed' }
  | { readonly kind: 'completed'; readonly key: PublicKeyResult }
  | { readonly kind: 'reserved'; readonly binding: RingBinding; readonly ring: RingRecord };

export type ReissueCommitOutcome = AdmissionDenied | { readonly kind: 'key_expired' | 'failed' } | { readonly kind: 'completed'; readonly key: PublicKeyResult };

/** 保存用の写し（plain dataだけ。呼出し側のobjectと共有しない）。 */
function ringDocument(ring: RingRecord): Record<string, unknown> {
  return JSON.parse(JSON.stringify(ring)) as Record<string, unknown>;
}

/** 同IDのpendingを失敗にした写し（旧鍵・generationは変えない）。 */
function markFailed(ring: RingRecord, requestId: string, now: number): RingRecord {
  return {
    ...ring,
    reissues: ring.reissues.map((entry): ReissueRecord =>
      entry.requestId === requestId ? { requestId, mode: entry.mode, status: 'failed', reservedAt: entry.reservedAt } : entry,
    ),
    updatedAt: now,
  };
}

export type DecryptBeginOutcome =
  | AdmissionDenied
  | { readonly kind: 'rate_limited'; readonly retryAfterSec: number }
  | { readonly kind: 'admitted'; readonly binding: RingBinding; readonly ring: RingRecord | null; readonly now: number };

/** dispatch（T073）が渡す暗号文経路だけの鍵の証拠。 */
export interface KeyEvidence {
  readonly binding: RingBinding;
  readonly kid: string;
}

export type KeyEvidenceVerdict = 'usable' | 'unavailable_key' | 'unknown_key';

/** 元期限・中止の検査（過ぎていれば例外）。 */
export type Live = () => void;

export interface EncryptionStoreDeps {
  readonly db: Firestore;
  readonly connectNamespace: string;
  readonly encryptionNamespace: string;
  /** 現在の書込みSecret版（rewrap判定に使う非秘密の数値）。 */
  readonly writeSecretVersion: number;
  readonly clock: { now(): number };
}

type Owner = { readonly identityHash: unknown; readonly revokedAt: unknown; readonly lastActiveAt: unknown };
type Admitted = { readonly kind: 'admitted'; readonly ownerId: string; readonly ownerRef: DocumentReference };

function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

export class EncryptionKeyStore {
  readonly #d: EncryptionStoreDeps;
  readonly #connect: DocumentReference;
  readonly #root: DocumentReference;

  constructor(deps: EncryptionStoreDeps) {
    this.#d = deps;
    this.#connect = deps.db.collection(CONNECT_STORAGE_ROOT).doc(deps.connectNamespace);
    this.#root = deps.db.collection(ENCRYPTION_STORAGE_ROOT).doc(deps.encryptionNamespace);
  }

  /** server時刻（安全な正の整数msだけ。不正は固定障害）。 */
  #now(): number {
    const now = this.#d.clock.now();
    if (!isTime(now)) throw new EncryptionUnavailableError();
    return now;
  }

  #ringRef(scope: string): DocumentReference {
    if (!isScope(scope)) throw new EncryptionRecordError();
    return this.#root.collection(RINGS_COLLECTION).doc(scope);
  }

  #controlsRef(scope: string): DocumentReference {
    if (!isScope(scope)) throw new EncryptionRecordError();
    return this.#root.collection(CONTROLS_COLLECTION).doc(scope);
  }

  async #get(tx: Transaction, ref: DocumentReference, live: Live): Promise<DocumentSnapshot> {
    live();
    const snapshot = await tx.get(ref);
    live();
    return snapshot;
  }

  /**
   * 既存の許可・identity対応・ownerを同じtransactionで読む。欠落/disabledはaccess_denied、対応/owner無し・失効・90日無活動は
   * connection_required、許可の不正・ownerの時刻不正・束縛違いは一時障害。書込み0。
   */
  async #admit(tx: Transaction, identityHash: string, live: Live): Promise<Admitted | AdmissionDenied> {
    const access = accessVerdictOfSnapshot(await this.#get(tx, accessDocRef(this.#connect, identityHash), live));
    if (access.kind === 'unavailable') throw new EncryptionUnavailableError();
    if (access.kind === 'denied') return { kind: 'access_denied' };
    const mapped = (await this.#get(tx, this.#connect.collection('identities').doc(identityHash), live)).data() as { ownerId?: unknown } | undefined;
    if (mapped === undefined || typeof mapped.ownerId !== 'string') return { kind: 'connection_required' };
    const ownerRef = this.#connect.collection('owners').doc(mapped.ownerId);
    const owner = (await this.#get(tx, ownerRef, live)).data() as Owner | undefined;
    if (owner === undefined || owner.revokedAt !== null) return { kind: 'connection_required' };
    if (!isTime(owner.lastActiveAt) || owner.identityHash !== identityHash) throw new EncryptionUnavailableError();
    const now = this.#now();
    if (owner.lastActiveAt > now) throw new EncryptionUnavailableError();
    if (now - owner.lastActiveAt >= OWNER_INACTIVITY_MS) return { kind: 'connection_required' };
    return { kind: 'admitted', ownerId: mapped.ownerId, ownerRef };
  }

  #ringOf(snapshot: DocumentSnapshot, binding: RingBinding): RingRecord | null {
    return snapshot.exists ? parseRingRecord(snapshot.data(), binding) : null;
  }

  #controlsOf(snapshot: DocumentSnapshot, binding: RingBinding): ControlsRecord {
    return snapshot.exists ? parseControlsRecord(snapshot.data(), binding) : emptyControls(binding);
  }

  /** ringの無活動期限（未来のlastUsedAtは不正として固定障害）。 */
  #ringExpired(ring: RingRecord, now: number): boolean {
    if (ring.lastUsedAt > now) throw new EncryptionUnavailableError();
    return now - ring.lastUsedAt >= RING_INACTIVITY_MS;
  }

  #run<T>(live: Live, fn: (tx: Transaction) => Promise<T>): Promise<T> {
    live();
    return this.#d.db.runTransaction(async (tx) => {
      live();
      return fn(tx);
    }, { maxAttempts: TRANSACTION_ATTEMPTS });
  }

  /**
   * 取得の入口: 認可→ring/controlsを読み、取得rate（ring不在なら初期化rateも）を予約する。429は非消費。
   * 既存の有効ringは利用時刻を更新して返す（rewrap対象はcommitRewrapで更新）。scopeOfはownerIdからの純粋なHMAC。
   */
  async begin(identityHash: string, scopeOf: (ownerId: string) => string, live: Live): Promise<BeginOutcome> {
    return this.#run(live, async (tx): Promise<BeginOutcome> => {
      const admission = await this.#admit(tx, identityHash, live);
      if (admission.kind !== 'admitted') return admission;
      const binding: RingBinding = { identityHash, ownerId: admission.ownerId, scope: scopeOf(admission.ownerId) };
      const ringRef = this.#ringRef(binding.scope);
      const controlsRef = this.#controlsRef(binding.scope);
      const ringSnapshot = await this.#get(tx, ringRef, live);
      const controlsSnapshot = await this.#get(tx, controlsRef, live);
      const now = this.#now();
      const ring = this.#ringOf(ringSnapshot, binding);
      const controls = this.#controlsOf(controlsSnapshot, binding);
      const kinds: RateKind[] = ring === null ? ['fetch', 'init'] : ['fetch'];
      const windows = { ...controls.windows };
      for (const kind of kinds) {
        const used = consumeRate(windows[kind], kind, now);
        if ('retryAfterSec' in used) return { kind: 'rate_limited', retryAfterSec: used.retryAfterSec };
        windows[kind] = used.next;
      }
      const expired = ring !== null && this.#ringExpired(ring, now);
      live();
      tx.set(controlsRef, { ...controls, windows });
      if (ring === null) return { kind: 'initialize', binding };
      if (expired) return { kind: 'key_expired' };
      // 期限済みの過去鍵・24hを過ぎた操作は、Secret版のrewrapより先に回収する（不要な旧Secretを読まない）。
      const current = pruneRing(ring, now);
      if (current.keys.some((key) => key.secretVersion !== this.#d.writeSecretVersion)) return { kind: 'rewrap', binding, ring: current };
      const touched: RingRecord = { ...current, lastUsedAt: now };
      tx.set(ringRef, { ...touched });
      tx.update(admission.ownerRef, { lastActiveAt: now });
      return { kind: 'ready', binding, ring: touched };
    });
  }

  /**
   * 暗号文の受付（T073）: 認可→ring/controlsを読み、復号試行rate（分30/UTC日1000）を復号・形式検査の前に予約する（429は非消費）。
   * ringは作らない・補完しない（POSTで鍵を初期化しない）。無活動期限を延ばさない。返すringは開封の準備に使うsnapshotで、
   * 送出の可否はdispatchのtransactionでcheckKeyEvidenceが最新状態で決める。
   */
  async beginDecrypt(identityHash: string, scopeOf: (ownerId: string) => string, live: Live): Promise<DecryptBeginOutcome> {
    return this.#run(live, async (tx): Promise<DecryptBeginOutcome> => {
      const admission = await this.#admit(tx, identityHash, live);
      if (admission.kind !== 'admitted') return admission;
      const binding: RingBinding = { identityHash, ownerId: admission.ownerId, scope: scopeOf(admission.ownerId) };
      const ringSnapshot = await this.#get(tx, this.#ringRef(binding.scope), live);
      const controlsRef = this.#controlsRef(binding.scope);
      const controlsSnapshot = await this.#get(tx, controlsRef, live);
      const now = this.#now();
      const ring = this.#ringOf(ringSnapshot, binding);
      const controls = this.#controlsOf(controlsSnapshot, binding);
      const used = consumeRate(controls.windows.decrypt, 'decrypt', now);
      if ('retryAfterSec' in used) return { kind: 'rate_limited', retryAfterSec: used.retryAfterSec };
      if (ring !== null) this.#ringExpired(ring, now);
      live();
      tx.set(controlsRef, { ...controls, windows: { ...controls.windows, decrypt: used.next } });
      return { kind: 'admitted', binding, ring, now };
    });
  }

  /**
   * 再発行の予約（T074）: 認可・有効ring・取得のHTTP枠（GETと共用）を確かめ、同IDの記録があればその状態を返す（再発行枠・鍵生成枠を
   * 追加消費しない）。新しいIDは再発行の試行枠（分3/UTC日10）を消費し、activeなpendingが無く、24hに4件・60秒間隔の条件を満たす時だけ
   * 元operationの期限までのpendingを予約する。旧鍵は変えない。閉包の中で乱数・鍵生成・Secretを使わない。
   */
  async beginReissue(
    identityHash: string,
    scopeOf: (ownerId: string) => string,
    request: { readonly requestId: string; readonly mode: ReissueMode; readonly deadlineAt: number },
    live: Live,
  ): Promise<ReissueBeginOutcome> {
    return this.#run(live, async (tx): Promise<ReissueBeginOutcome> => {
      const admission = await this.#admit(tx, identityHash, live);
      if (admission.kind !== 'admitted') return admission;
      const binding: RingBinding = { identityHash, ownerId: admission.ownerId, scope: scopeOf(admission.ownerId) };
      const ringRef = this.#ringRef(binding.scope);
      const controlsRef = this.#controlsRef(binding.scope);
      const ringSnapshot = await this.#get(tx, ringRef, live);
      const controlsSnapshot = await this.#get(tx, controlsRef, live);
      const now = this.#now();
      const ring = this.#ringOf(ringSnapshot, binding);
      const controls = this.#controlsOf(controlsSnapshot, binding);
      // 429は全て非消費（fetch・試行枠・予約数を変えない）。同時に適用される制約の待ち（秒）を全て集め、最長をRetry-Afterにする。
      const waits: number[] = [];
      const fetch = consumeRate(controls.windows.fetch, 'fetch', now);
      if ('retryAfterSec' in fetch) waits.push(fetch.retryAfterSec);
      const limited = (): ReissueBeginOutcome => ({ kind: 'rate_limited', retryAfterSec: Math.max(1, ...waits) });
      const windows: Record<RateKind, RateWindow> = { ...controls.windows };
      if (!('retryAfterSec' in fetch)) windows.fetch = fetch.next;
      const writeControls = (): void => {
        live();
        tx.set(controlsRef, { ...controls, windows });
      };
      if (ring === null || this.#ringExpired(ring, now)) {
        if (waits.length > 0) return limited();
        writeControls();
        return { kind: ring === null ? 'key_not_initialized' : 'key_expired' };
      }
      const current = pruneRing(ring, now);
      const same = current.reissues.find((entry) => entry.requestId === request.requestId);
      if (same !== undefined) {
        // 同IDは新しい予約をしないので、HTTPの取得枠（fetch）だけを課す（試行枠・60秒・24h4件は課さない）。
        if (waits.length > 0) return limited();
        writeControls();
        if (same.mode !== request.mode) return { kind: 'conflict' };
        if (same.status === 'completed') return { kind: 'completed', key: reissuedResultOf(current, same.result) };
        if (same.status === 'pending' && now < same.deadlineAt) return { kind: 'in_flight' };
        return { kind: 'failed' };
      }
      const attempt = consumeRate(windows.reissueAttempt, 'reissueAttempt', now);
      if ('retryAfterSec' in attempt) waits.push(attempt.retryAfterSec);
      // activeなpendingがある時は新規予約をしないので、HTTP枠と試行枠だけを課す（60秒・24h4件は課さない）。
      if (current.reissues.some((entry) => entry.status === 'pending' && now < entry.deadlineAt)) {
        if (waits.length > 0) return limited();
        if (!('retryAfterSec' in attempt)) windows.reissueAttempt = attempt.next;
        writeControls();
        return { kind: 'in_progress' };
      }
      // 新規予約の時だけ、60秒間隔と24hに4件も含めた最長の待ちを評価する。
      if (current.reissues.length >= MAX_REISSUES) {
        waits.push(Math.ceil((Math.min(...current.reissues.map((entry) => entry.reservedAt)) + REISSUE_WINDOW_MS - now) / 1000));
      }
      if (current.reissues.length > 0) {
        const latestAt = Math.max(...current.reissues.map((entry) => entry.reservedAt));
        if (now - latestAt < REISSUE_SPACING_MS) waits.push(Math.ceil((latestAt + REISSUE_SPACING_MS - now) / 1000));
      }
      if (waits.length > 0) return limited();
      if (!('retryAfterSec' in attempt)) windows.reissueAttempt = attempt.next;
      const deadlineAt = Math.min(request.deadlineAt, now + REISSUE_PENDING_MAX_MS);
      if (!(deadlineAt > now)) throw new EncryptionUnavailableError();
      const pending: ReissueRecord = { requestId: request.requestId, mode: request.mode, status: 'pending', reservedAt: now, deadlineAt };
      const next: RingRecord = { ...current, reissues: [...current.reissues, pending], updatedAt: now };
      writeControls();
      tx.set(ringRef, ringDocument(next));
      return { kind: 'reserved', binding, ring: next };
    });
  }

  /**
   * 再発行の確定（CAS）: 同じpending ID/mode・元operationの期限内・期待generation・最新の認可と有効なringを確かめ、新鍵・旧鍵の状態・
   * 完了の操作記録を一括で保存する。generationの競合や過去鍵の上限は再生成せずfailedを記録する。lastUsedAt等の並行更新は最新を保つ。
   */
  async commitReissue(binding: RingBinding, requestId: string, mode: ReissueMode, expectedGeneration: number, key: KeyRecord, live: Live): Promise<ReissueCommitOutcome> {
    return this.#run(live, async (tx): Promise<ReissueCommitOutcome> => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return admission;
      const ringRef = this.#ringRef(binding.scope);
      const latest = this.#ringOf(await this.#get(tx, ringRef, live), binding);
      if (latest === null) throw new EncryptionUnavailableError();
      const now = this.#now();
      if (this.#ringExpired(latest, now)) return { kind: 'key_expired' };
      const current = pruneRing(latest, now);
      const op = current.reissues.find((entry) => entry.requestId === requestId);
      if (op === undefined || op.mode !== mode) throw new EncryptionUnavailableError();
      if (op.status === 'completed') return { kind: 'completed', key: reissuedResultOf(current, op.result) };
      if (op.status === 'failed' || now >= op.deadlineAt) return { kind: 'failed' };
      const keys = current.generation === expectedGeneration ? rotateKeys(current.keys, key, mode, now) : null;
      if (keys === null) {
        live();
        tx.set(ringRef, ringDocument(markFailed(current, requestId, now)));
        return { kind: 'failed' };
      }
      const result: ReissuedKey = { kid: key.kid, publicJwk: key.publicJwk, publicKeySpki: key.publicKeySpki, createdAt: key.createdAt };
      const reissues = current.reissues.map((entry): ReissueRecord =>
        entry.requestId === requestId ? { requestId, mode, status: 'completed', reservedAt: entry.reservedAt, result } : entry,
      );
      const next: RingRecord = {
        ...current,
        generation: current.generation + 1,
        activeKid: key.kid,
        keys,
        reissues,
        updatedAt: now,
        lastUsedAt: Math.max(current.lastUsedAt, now),
      };
      live();
      tx.set(ringRef, ringDocument(next));
      tx.update(admission.ownerRef, { lastActiveAt: now });
      return { kind: 'completed', key: reissuedResultOf(next, result) };
    });
  }

  /** 元operationの中で、同IDのpendingを失敗として記録する（期限後・中断後は書かない。旧鍵は変えない）。 */
  async failReissue(binding: RingBinding, requestId: string, live: Live): Promise<void> {
    await this.#run(live, async (tx): Promise<void> => {
      const ringRef = this.#ringRef(binding.scope);
      const latest = this.#ringOf(await this.#get(tx, ringRef, live), binding);
      if (latest === null) return;
      const now = this.#now();
      const op = latest.reissues.find((entry) => entry.requestId === requestId);
      if (op === undefined || op.status !== 'pending' || now >= op.deadlineAt) return;
      live();
      tx.set(ringRef, ringDocument(markFailed(latest, requestId, now)));
    });
  }

  /** commit応答不明の後の有限な読直し（書込み0）: 最新の認可と同じ操作の記録。completedなら元の公開結果。 */
  async readReissue(binding: RingBinding, requestId: string, live: Live): Promise<ReissueCommitOutcome | { readonly kind: 'unknown' }> {
    return this.#run(live, async (tx) => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return admission;
      const ring = this.#ringOf(await this.#get(tx, this.#ringRef(binding.scope), live), binding);
      if (ring === null) return { kind: 'unknown' as const };
      const op = ring.reissues.find((entry) => entry.requestId === requestId);
      if (op?.status === 'completed') return { kind: 'completed' as const, key: reissuedResultOf(ring, op.result) };
      if (op?.status === 'failed') return { kind: 'failed' as const };
      return { kind: 'unknown' as const };
    });
  }

  /** 最新の認可を再確認し、束縛（ownerId）が同じ時だけadmittedを返す。 */
  async #readmit(tx: Transaction, binding: RingBinding, live: Live): Promise<Admitted | AdmissionDenied> {
    const admission = await this.#admit(tx, binding.identityHash, live);
    if (admission.kind === 'admitted' && admission.ownerId !== binding.ownerId) throw new EncryptionUnavailableError();
    return admission;
  }

  /** 初期化CAS: 最新の認可とring不在を再確認してcreate。同時に勝った既存ringがあればそれを返す（候補は使わない）。 */
  async commitInitial(binding: RingBinding, candidate: RingRecord, live: Live): Promise<CommitOutcome> {
    return this.#run(live, async (tx): Promise<CommitOutcome> => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return admission;
      const ringRef = this.#ringRef(binding.scope);
      const existing = this.#ringOf(await this.#get(tx, ringRef, live), binding);
      const now = this.#now();
      if (existing !== null) return this.#ringExpired(existing, now) ? { kind: 'key_expired' } : { kind: 'existing', ring: existing };
      live();
      tx.create(ringRef, { ...candidate, keys: candidate.keys.map((key) => ({ ...key, publicJwk: { ...key.publicJwk } })) });
      tx.update(admission.ownerRef, { lastActiveAt: now });
      return { kind: 'created', ring: candidate };
    });
  }

  /** rewrap CAS: 期待generationと一致した時だけ、同じkid/公開鍵の包み直した鍵へ置き換える。不一致は最新ringをconflictで返す。 */
  async commitRewrap(binding: RingBinding, expectedGeneration: number, keys: readonly KeyRecord[], live: Live): Promise<CommitOutcome> {
    return this.#run(live, async (tx): Promise<CommitOutcome> => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return admission;
      const ringRef = this.#ringRef(binding.scope);
      const latest = this.#ringOf(await this.#get(tx, ringRef, live), binding);
      if (latest === null) throw new EncryptionUnavailableError();
      const now = this.#now();
      if (this.#ringExpired(latest, now)) return { kind: 'key_expired' };
      const current = pruneRing(latest, now);
      if (current.generation !== expectedGeneration) return { kind: 'conflict', ring: current };
      const sameKeys = keys.length === current.keys.length && keys.every((key, index) => {
        const was = current.keys[index];
        return was !== undefined && was.kid === key.kid && was.publicKeySpki === key.publicKeySpki && was.state === key.state;
      });
      if (!sameKeys) throw new EncryptionUnavailableError();
      const next: RingRecord = { ...current, generation: current.generation + 1, keys, updatedAt: now, lastUsedAt: now };
      live();
      tx.set(ringRef, { ...next, keys: keys.map((key) => ({ ...key, publicJwk: { ...key.publicJwk } })) });
      tx.update(admission.ownerRef, { lastActiveAt: now });
      return { kind: 'updated', ring: next };
    });
  }

  /**
   * commit応答不明・CAS不一致の後に1回だけ、最新の認可と同じscopeのringを読む（書込み0、無活動期限を延ばさない）。
   * activeの鍵が無活動期限内である時だけadopted。
   */
  async readAdopted(binding: RingBinding, live: Live): Promise<AdoptedOutcome> {
    return this.#run(live, async (tx): Promise<AdoptedOutcome> => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return admission;
      const ring = this.#ringOf(await this.#get(tx, this.#ringRef(binding.scope), live), binding);
      if (ring === null) return { kind: 'absent' };
      const now = this.#now();
      const active = ring.keys.find((key) => key.kid === ring.activeKid);
      if (active === undefined || this.#ringExpired(ring, now) || !keyUsable(ring, active, now)) return { kind: 'key_expired' };
      return { kind: 'adopted', ring };
    });
  }

  /**
   * 暗号文の送信が今回の要求で配送として確定した時だけ（呼出し側が判定）、同じ元operation・最新の認可の範囲でringの最終利用を更新する。
   * 鍵がその時点で使えない・ringが無い・期限切れ・認可の拒否なら書かない。generation・鍵は変えない。失敗は呼出し側が無視する
   * （応答の状態を変えない。非同期の再試行はしない）。
   */
  async touchAfterDelivery(binding: RingBinding, kid: string, live: Live): Promise<boolean> {
    return this.#run(live, async (tx): Promise<boolean> => {
      const admission = await this.#readmit(tx, binding, live);
      if (admission.kind !== 'admitted') return false;
      const ringRef = this.#ringRef(binding.scope);
      const ring = this.#ringOf(await this.#get(tx, ringRef, live), binding);
      const now = this.#now();
      if (ring === null || this.#ringExpired(ring, now)) return false;
      const key = ring.keys.find((entry) => entry.kid === kid);
      if (key === undefined || !keyUsable(ring, key, now) || now <= ring.lastUsedAt) return false;
      live();
      tx.set(ringRef, { ...ring, lastUsedAt: now });
      return true;
    });
  }

  /**
   * 呼出し元（暗号文のdispatch）のtransactionの中で、証拠のring/scope/owner/identityHash/kidと鍵状態・期限を最新snapshotで確かめる。
   * 別transactionで確認してからdispatchする使い方をしない。不正schemaはEncryptionRecordError。
   */
  async checkKeyEvidence(tx: Transaction, evidence: KeyEvidence): Promise<KeyEvidenceVerdict> {
    const ring = this.#ringOf(await tx.get(this.#ringRef(evidence.binding.scope)), evidence.binding);
    // 猶予・無活動の期限は、鍵の読取りを待った後の最新時刻で判断する（読取り前の時刻を使わない）。
    const now = this.#now();
    if (ring === null) return 'unknown_key';
    const key = ring.keys.find((entry) => entry.kid === evidence.kid);
    if (key === undefined) return 'unknown_key';
    if (ring.lastUsedAt > now) throw new EncryptionUnavailableError();
    return keyUsable(ring, key, now) ? 'usable' : 'unavailable_key';
  }
}
