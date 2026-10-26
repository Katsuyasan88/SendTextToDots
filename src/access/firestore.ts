// 利用許可recordのFirestore adapter（sttdConnect/{connectNamespace}/access/{identityHash}）。
//   - 通常runtime（接続保存・配送・購読）は読むだけ: 参照の組立てと、transactionで読んだsnapshotの同期判定（I/O・開封・乱数0）。
//   - 管理module（access/admin.ts）だけがchangeAccessで書く: 期待版（Firestore updateTime。初回は不存在）と完全一致した時だけ1件を
//     1 transactionで更新する。閉包の中は読取り→照合→書込みだけで、世代の乱数・時計は閉包の外で1回だけ決めた値を使う
//     （SDKが閉包を再実行しても期待版を取り直さず、別の値を作らない）。
// 平文UID・メール・Apple raw IDは扱わない（identityHashは接続保存の既存identity用HMAC）。

import type { DocumentReference, DocumentSnapshot, Firestore, Timestamp, Transaction } from '@google-cloud/firestore';

import {
  ACCESS_COLLECTION,
  AccessRecordError,
  accessVerdictOf,
  grantGenerationOf,
  isIdentityHash,
  nextAccessRecord,
  parseAccessRecord,
  type AccessRecord,
  type AccessState,
  type AccessVerdict,
  type GrantGeneration,
} from './policy.js';

/** 利用許可の読取り・判定が一時的にできない（固定message。値・path・元例外を持たない）。 */
export class AccessUnavailableError extends Error {
  override readonly name = 'AccessUnavailableError';
  constructor() {
    super('access check is temporarily unavailable');
  }
}

/** 接続保存のroot（sttdConnect/{namespace}）配下の許可record参照。identityHashの形が違えばAccessRecordError。 */
export function accessDocRef(connectRoot: DocumentReference, identityHash: string): DocumentReference {
  if (!isIdentityHash(identityHash)) throw new AccessRecordError();
  return connectRoot.collection(ACCESS_COLLECTION).doc(identityHash);
}

export function accessVerdictOfSnapshot(snapshot: DocumentSnapshot): AccessVerdict {
  return accessVerdictOf(snapshot.exists, snapshot.exists ? snapshot.data() : undefined);
}

export function grantGenerationOfSnapshot(snapshot: DocumentSnapshot): GrantGeneration {
  return grantGenerationOf(snapshot.exists, snapshot.exists ? snapshot.data() : undefined);
}

// ---- 管理用（access/admin.tsだけが使う） ----

/** 期待版の文字列: 不存在は`absent`、存在はupdateTimeの`<seconds>.<9桁nanos>`。 */
export type AccessVersion = string;
export const ABSENT_VERSION: AccessVersion = 'absent';
const VERSION_PATTERN = /^(?:absent|(?:0|[1-9][0-9]{0,15})\.[0-9]{9})$/;

export function isAccessVersion(value: unknown): value is AccessVersion {
  return typeof value === 'string' && VERSION_PATTERN.test(value);
}

function versionOfTime(time: Timestamp | undefined): AccessVersion {
  if (time === undefined) throw new AccessUnavailableError();
  const { seconds, nanoseconds } = time;
  if (!Number.isSafeInteger(seconds) || seconds < 0 || !Number.isInteger(nanoseconds) || nanoseconds < 0 || nanoseconds > 999_999_999) {
    throw new AccessUnavailableError();
  }
  return `${seconds}.${String(nanoseconds).padStart(9, '0')}`;
}

export interface AccessStatus {
  /** 不存在はnull。 */
  readonly record: AccessRecord | null;
  readonly version: AccessVersion;
}

/** snapshotの状態と版。不正なrecordは自動修復せずAccessRecordError。 */
export function accessStatusOf(snapshot: DocumentSnapshot): AccessStatus {
  if (!snapshot.exists) return { record: null, version: ABSENT_VERSION };
  return { record: parseAccessRecord(snapshot.data()), version: versionOfTime(snapshot.updateTime) };
}

export type AccessChangeOutcome =
  | { readonly kind: 'changed'; readonly record: AccessRecord }
  | { readonly kind: 'unchanged'; readonly record: AccessRecord | null }
  | { readonly kind: 'conflict' };

/**
 * 期待版と完全一致した時だけ目標状態へ1件更新する（1 transaction、SDKの最大実行回数maxAttempts）。同じ状態なら書込みなし。
 * 版違いはconflict（最新状態へ自動適用しない）。不正なrecordはAccessRecordError（修復しない）。
 */
export async function changeAccess(
  db: Firestore,
  ref: DocumentReference,
  change: {
    readonly expected: AccessVersion;
    readonly desired: AccessState;
    readonly now: number;
    readonly newGeneration: string;
    readonly maxAttempts: number;
  },
): Promise<AccessChangeOutcome> {
  const { expected, desired, now, newGeneration, maxAttempts } = change;
  if (!isAccessVersion(expected)) throw new AccessRecordError();
  return db.runTransaction(
    async (tx: Transaction): Promise<AccessChangeOutcome> => {
      const snapshot = await tx.get(ref);
      const status = accessStatusOf(snapshot);
      if (status.version !== expected) return { kind: 'conflict' };
      const next = nextAccessRecord(status.record, desired, now, newGeneration);
      if (next === null) return { kind: 'unchanged', record: status.record };
      if (status.record === null) tx.create(ref, { ...next });
      else tx.set(ref, { ...next });
      return { kind: 'changed', record: next };
    },
    { maxAttempts },
  );
}
