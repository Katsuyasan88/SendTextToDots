// 受信先設定一式のreset（プラグイン接続のApple login後、本人が明示確認した時だけ）の純関数。暗号・開封・通信・時計・ログを使わない。
//   - owner文書の受信reset世代（receiverGeneration）: 欠落は既存の0、不正は一時障害。resetの時だけ+1する。
//   - 購読文書（version2）の受信先設定の有無: 既存のparseKmsState（版・owner・exact field・状態の整合・capsule・大きさ）で検査し、
//     active・pending・knownDestinationIdのどれかがあれば「あり」。不正・別owner・未知の形は一時障害（消さない）。
//   - snapshotの材料: 表示した時の購読文書の版・設定の有無と、owner文書の取消世代・受信reset世代。確認の時に同じであることを要求する。
//   - resetの書込み: 購読文書を空の状態（version2の形のまま）、owner文書の取消世代と受信reset世代を各+1。
// 削除するのは受信先設定一式だけ（account・owner・identity・利用許可・鍵・送信履歴・Grantは触らない）。

import { emptyKmsState, kmsStateDocument, parseKmsState, type KmsSubscriptionPolicy } from './kms-subscription-format.js';
import { nextGeneration, ownerGeneration, SUBSCRIPTION_GENERATION_FIELD } from './kms-subscription-registration-rules.js';

/** owner文書の受信reset世代のfield。 */
export const RECEIVER_GENERATION_FIELD = 'receiverGeneration';

/** 受信reset世代・購読文書・取消世代が読めない（不正・障害）。削除へ進まない。 */
export class ReceiverResetUnavailableError extends Error {
  constructor() {
    super('receiver reset: unavailable');
    this.name = 'ReceiverResetUnavailableError';
  }
}

const unavailable = (): never => {
  throw new ReceiverResetUnavailableError();
};

/** owner文書のdataから受信reset世代を読む。欠落は0、null・負・小数・非安全整数・accessorは一時障害。 */
export function ownerReceiverGeneration(data: unknown): number {
  if (typeof data !== 'object' || data === null) return unavailable();
  const descriptor = Object.getOwnPropertyDescriptor(data, RECEIVER_GENERATION_FIELD);
  if (descriptor === undefined) return 0;
  if (!('value' in descriptor)) return unavailable();
  const value: unknown = descriptor.value;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return unavailable();
  return value;
}

/** owner文書の取消世代（既存の判定）。不正は一時障害。 */
function ownerSubscriptionGeneration(data: unknown): number {
  try {
    return ownerGeneration(data);
  } catch {
    return unavailable();
  }
}

/** 文書の版（exists・updateTimeの秒/ナノ秒）を文字列へ。秒は0以上の安全な整数、ナノ秒は0〜999999999。不明は一時障害。 */
function versionText(snapshot: { readonly exists: boolean; readonly updateTime?: unknown }): string {
  if (!snapshot.exists) return 'absent';
  const time = snapshot.updateTime as { readonly seconds?: unknown; readonly nanoseconds?: unknown } | undefined;
  if (typeof time !== 'object' || time === null) return unavailable();
  const { seconds, nanoseconds } = time;
  if (typeof seconds !== 'number' || !Number.isSafeInteger(seconds) || seconds < 0) return unavailable();
  if (typeof nanoseconds !== 'number' || !Number.isSafeInteger(nanoseconds) || nanoseconds < 0 || nanoseconds > 999_999_999) return unavailable();
  return `${String(seconds)}.${String(nanoseconds)}`;
}

/**
 * 購読文書の受信先設定の有無。文書が無ければ「なし」。既存のparseKmsState（policy付き）で検査し、active・pending・knownDestinationIdの
 * どれかがあれば「あり」。不正・別owner・未知の形は一時障害（推測で消さない）。
 */
export function receiverSettingsPresent(snapshot: { readonly exists: boolean; data(): unknown }, ownerId: string, policy: KmsSubscriptionPolicy): boolean {
  if (!snapshot.exists) return false;
  let state;
  try {
    state = parseKmsState(snapshot.data(), ownerId, policy);
  } catch {
    return unavailable();
  }
  return state.active !== null || state.pending !== null || state.knownDestinationId !== null;
}

/** 表示と確認の間で変わっていないことを確かめる材料（interaction・owner・購読文書の版と設定の有無・取消世代・受信reset世代）。値はhashしてから使う。 */
export function receiverSnapshotMaterial(input: {
  readonly interactionUid: string;
  readonly csrfHash: string;
  readonly ownerId: string;
  readonly subscription: { readonly exists: boolean; readonly updateTime?: unknown };
  readonly present: boolean;
  readonly ownerData: unknown;
}): string {
  return JSON.stringify([
    'receiver-reset-v2',
    input.interactionUid,
    input.csrfHash,
    input.ownerId,
    versionText(input.subscription),
    input.present,
    ownerSubscriptionGeneration(input.ownerData),
    ownerReceiverGeneration(input.ownerData),
  ]);
}

/** resetの書込み。購読文書を空の状態へ、owner文書の取消世代と受信reset世代を各+1。新しい受信reset世代も返す。 */
export function receiverResetWrites(ownerId: string, ownerData: unknown): { readonly ownerUpdate: Record<string, number>; readonly subscriptionDoc: Record<string, unknown>; readonly receiverGeneration: number } {
  const subscriptionGeneration = ownerSubscriptionGeneration(ownerData);
  const current = ownerReceiverGeneration(ownerData);
  if (!(current < Number.MAX_SAFE_INTEGER)) return unavailable();
  const receiverGeneration = current + 1;
  let nextSubscription: number;
  try {
    nextSubscription = nextGeneration(subscriptionGeneration);
  } catch {
    return unavailable();
  }
  return {
    ownerUpdate: { [SUBSCRIPTION_GENERATION_FIELD]: nextSubscription, [RECEIVER_GENERATION_FIELD]: receiverGeneration },
    subscriptionDoc: kmsStateDocument(ownerId, emptyKmsState()),
    receiverGeneration,
  };
}
