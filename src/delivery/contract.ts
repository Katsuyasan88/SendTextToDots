// 要求内の単回配送と中止の、本文なしCommandの状態と判定。正本は docs/API.md §2（送信・中止・待機時間）。
// ここは同期の純粋な判定だけで、DB・時計・乱数・送出・鍵を持たない
// （Firestoreのtransactionの関数から呼ばれ、再実行されても外へ何も起こさない）。
// 保存するのはowner・commandの鍵付きdigest・固定したGrant/購読/宛先版・state・attempt所有者・時刻・理由コードだけで、
// 本文・event bytes・callback URL・secretは文書へ入れない。

import { decideCommandRate, parseCommandRateState, type CommandRateState } from '../commands/rate.js';
import type { OwnerSubscriptionStateOf, SubscriptionExpiry } from '../stores.js';
import { hashesEqual } from '../secrets.js';

/** 文書の形式の版。 */
export const DELIVERY_FORMAT_VERSION = 1;
/** API処理の予算（受信から）。 */
export const API_BUDGET_MS = 20_000;
/** 送出を始めるのに必要な、元の期限までの残り（既存の単回送出の条件と同じ。ちょうど10秒は可）。 */
export const MIN_SEND_REMAINING_MS = 10_000;
/** 状態メタデータの利用・照会の上限（受信から）。物理削除は別の保守の範囲。 */
export const COMMAND_RETENTION_MS = 24 * 60 * 60 * 1000;

export const STORED_STATES = ['prepared', 'dispatching', 'delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown'] as const;
export type StoredState = (typeof STORED_STATES)[number];
/** 外へ返すstate。prepared・dispatchingは処理期限まではin_flight、過ぎたらdelivery_unknownへ投影する。 */
export type PublicState = 'in_flight' | 'delivered' | 'failed' | 'cancelled' | 'expired' | 'delivery_unknown';
const TERMINAL: ReadonlySet<string> = new Set(['delivered', 'failed', 'cancelled', 'expired', 'delivery_unknown']);

/** 理由コード（DBと通常ログだけ。公開応答には載せない）。 */
export type DeliveryReason =
  | 'acknowledged'
  | 'cancelled_before_dispatch'
  | 'cancelled_tombstone'
  | 'destination_changed'
  | 'authorization_lost'
  | 'deadline_passed'
  | 'receiver_rejected'
  | 'receiver_rate_limited'
  | 'receiver_server_error'
  | 'network_unavailable'
  | 'invalid_destination'
  | 'transport_ambiguous'
  | 'not_sendable'
  | 'local_error'
  | 'dispatch_unconfirmed';

/** 固定した送信先の版（受付時に束縛し、送出権の確定時に一致を要求する）。URLとsecretそのものは持たない。 */
export interface DestinationVersion {
  readonly subscriptionId: string;
  readonly grantId: string;
  readonly secretHash: string;
}

export interface CommandDoc {
  readonly version: typeof DELIVERY_FORMAT_VERSION;
  readonly ownerId: string;
  /** tombstoneは元POSTより先に届いた中止で、digest・宛先を持たない。 */
  readonly tombstone: boolean;
  readonly digest: string | null;
  readonly state: StoredState;
  readonly reason: DeliveryReason | null;
  readonly attemptId: string | null;
  readonly destination: DestinationVersion | null;
  readonly receivedAt: number;
  /** 有効期限 min(expiresAt, receivedAt+60秒)。tombstoneは記録時刻。 */
  readonly expiresAt: number;
  /** 処理期限 min(receivedAt+20秒, expiresAt)。これを過ぎた未完了は不明として投影する。 */
  readonly deadlineAt: number;
  readonly updatedAt: number;
  readonly acknowledgedAt: number | null;
  /** 利用・照会の上限（この時刻以後は無いものとして扱う）。 */
  readonly purgeAt: number;
}

const COMMAND_KEYS = [
  'version',
  'ownerId',
  'tombstone',
  'digest',
  'state',
  'reason',
  'attemptId',
  'destination',
  'receivedAt',
  'expiresAt',
  'deadlineAt',
  'updatedAt',
  'acknowledgedAt',
  'purgeAt',
];
const DESTINATION_KEYS = ['subscriptionId', 'grantId', 'secretHash'];
const OWNER_CONTROL_KEYS = ['version', 'ownerId', 'rate', 'current'];
const CURRENT_KEYS = ['commandKey', 'until'];

/** 保存の形が合わない（破損・別版）。値は持たない。 */
export class DeliveryStateError extends Error {
  constructor() {
    super('delivery_state_invalid');
    this.name = 'DeliveryStateError';
  }
}

const isTime = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isText = (value: unknown, max = 256): value is string => typeof value === 'string' && value.length > 0 && value.length <= max;
function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function must(condition: boolean): asserts condition {
  if (!condition) throw new DeliveryStateError();
}

/** 文書の検査。無ければundefined、形・ownerが違えば破損（空・別ownerとして扱わない）。 */
export function parseCommandDoc(data: unknown, ownerId: string): CommandDoc | undefined {
  if (data === undefined) return undefined;
  must(exact(data, COMMAND_KEYS));
  const { tombstone, digest, state, reason, attemptId, destination } = data;
  must(data.version === DELIVERY_FORMAT_VERSION && data.ownerId === ownerId && typeof tombstone === 'boolean');
  must(typeof state === 'string' && (STORED_STATES as readonly string[]).includes(state));
  must(reason === null || isText(reason, 64));
  must(attemptId === null || isText(attemptId, 64));
  must(digest === null || isText(digest, 128));
  for (const key of ['receivedAt', 'expiresAt', 'deadlineAt', 'updatedAt', 'purgeAt'] as const) must(isTime(data[key]));
  must(data.acknowledgedAt === null || isTime(data.acknowledgedAt));
  let fixed: DestinationVersion | null = null;
  if (destination !== null) {
    must(exact(destination, DESTINATION_KEYS));
    const { subscriptionId, grantId, secretHash } = destination;
    must(isText(subscriptionId) && isText(grantId) && isText(secretHash, 128));
    fixed = { subscriptionId, grantId, secretHash };
  }
  // tombstoneはdigest・宛先・attemptを持たず、cancelledだけ。
  must(tombstone ? digest === null && fixed === null && attemptId === null && state === 'cancelled' : digest !== null && fixed !== null);
  return {
    version: DELIVERY_FORMAT_VERSION,
    ownerId,
    tombstone,
    digest,
    state: state as StoredState,
    reason: reason as DeliveryReason | null,
    attemptId,
    destination: fixed,
    receivedAt: data.receivedAt as number,
    expiresAt: data.expiresAt as number,
    deadlineAt: data.deadlineAt as number,
    updatedAt: data.updatedAt as number,
    acknowledgedAt: data.acknowledgedAt as number | null,
    purgeAt: data.purgeAt as number,
  };
}

export function commandDocData(doc: CommandDoc): Record<string, unknown> {
  return {
    version: doc.version,
    ownerId: doc.ownerId,
    tombstone: doc.tombstone,
    digest: doc.digest,
    state: doc.state,
    reason: doc.reason,
    attemptId: doc.attemptId,
    destination: doc.destination && { ...doc.destination },
    receivedAt: doc.receivedAt,
    expiresAt: doc.expiresAt,
    deadlineAt: doc.deadlineAt,
    updatedAt: doc.updatedAt,
    acknowledgedAt: doc.acknowledgedAt,
    purgeAt: doc.purgeAt,
  };
}

export interface OwnerControl {
  readonly rate: CommandRateState | undefined;
  /** 現在の処理中command（鍵だけ。本文・宛先なし）。判定には使わず、記録と解放だけ。 */
  readonly current: { readonly commandKey: string; readonly until: number } | null;
}

export function parseOwnerControl(data: unknown, ownerId: string): OwnerControl {
  if (data === undefined) return { rate: undefined, current: null };
  must(exact(data, OWNER_CONTROL_KEYS) && data.version === DELIVERY_FORMAT_VERSION && data.ownerId === ownerId);
  let rate: CommandRateState | undefined;
  try {
    rate = data.rate === null ? undefined : parseCommandRateState(data.rate);
  } catch {
    throw new DeliveryStateError();
  }
  let current: OwnerControl['current'] = null;
  const stored: unknown = data.current;
  if (stored !== null) {
    must(exact(stored, CURRENT_KEYS));
    const { commandKey, until } = stored;
    must(isText(commandKey, 128) && isTime(until));
    current = { commandKey, until };
  }
  return { rate, current };
}

export function ownerControlData(ownerId: string, rate: CommandRateState | undefined, current: OwnerControl['current']): Record<string, unknown> {
  return {
    version: DELIVERY_FORMAT_VERSION,
    ownerId,
    rate: rate === undefined ? null : { updatedAt: rate.updatedAt, tokenUnits: rate.tokenUnits, hits: [...rate.hits] },
    current: current && { ...current },
  };
}

/** 利用期限を過ぎた文書は無いものとして扱う（物理削除の遅れで古い状態を返さない）。 */
export function usable(doc: CommandDoc | undefined, now: number): CommandDoc | undefined {
  return doc !== undefined && now < doc.purgeAt ? doc : undefined;
}

/** 照会・同ID再要求の投影。照会は何も書かない。 */
export function projectState(doc: CommandDoc, now: number): PublicState {
  if (TERMINAL.has(doc.state)) return doc.state as PublicState;
  return now < doc.deadlineAt ? 'in_flight' : 'delivery_unknown';
}

/** 受付・送出権の確定時の認可の正本（同じtransactionで読んだもの）。 */
export interface AuthorizationView {
  readonly ownerActive: boolean;
  readonly subscription: OwnerSubscriptionStateOf<SubscriptionExpiry> | undefined;
  /** 有効な購読が束縛したGrantが、同じownerの期限内のものか（無ければfalse）。 */
  readonly grantLive: boolean;
}

export type AuthorizationDenial = 'connection_revoked' | 'subscription_required' | 'destination_change_pending';

/** 有効な購読（期限・旧secretの猶予をnowで判定済み）。無ければ拒否の理由。 */
export function authorize(
  view: AuthorizationView,
  now: number,
):
  | { readonly ok: true; readonly destination: DestinationVersion; readonly sealedUrl: string; readonly sealedSecret: string; readonly previous: { readonly sealed: string; readonly until: number } | null }
  | { readonly ok: false; readonly denial: AuthorizationDenial } {
  if (!view.ownerActive) return { ok: false, denial: 'connection_revoked' };
  const state = view.subscription;
  if (state?.pending) return { ok: false, denial: 'destination_change_pending' };
  const active = state?.active ?? null;
  if (active === null || (active.expiresAt !== null && now >= active.expiresAt)) return { ok: false, denial: 'subscription_required' };
  // 束縛したGrantが失効した購読は使わない（同じownerの別Grantで代用しない）。
  if (!view.grantLive) return { ok: false, denial: 'subscription_required' };
  const previous = active.previousSecret && now < active.previousSecret.until ? active.previousSecret : null;
  return {
    ok: true,
    destination: { subscriptionId: active.id, grantId: active.grantId, secretHash: active.secretHash },
    sealedUrl: active.sealedUrl,
    sealedSecret: active.sealedSecret,
    previous: previous && { sealed: previous.sealed, until: previous.until },
  };
}

export interface NewCommandRequest {
  readonly ownerId: string;
  readonly commandKey: string;
  readonly digest: string;
  readonly attemptId: string;
  readonly receivedAt: number;
  /** 入力から決めた有効期限（resolveNewCommandExpiryの値）。時刻の不正は新規の時だけ拒否する。 */
  readonly expiresAt: number | 'clock_skew' | 'command_expired';
}

export type PrepareDecision =
  | { readonly kind: 'existing'; readonly doc: CommandDoc }
  | { readonly kind: 'conflict' }
  | { readonly kind: 'denied'; readonly denial: AuthorizationDenial }
  | { readonly kind: 'rate_limited'; readonly retryAfterSec: number }
  | { readonly kind: 'timing'; readonly code: 'clock_skew' | 'command_expired' }
  | {
      readonly kind: 'prepared';
      readonly doc: CommandDoc;
      readonly control: Record<string, unknown>;
      readonly sealedUrl: string;
      readonly sealedSecret: string;
      readonly previous: { readonly sealed: string; readonly until: number } | null;
    };

/**
 * 受付（準備状態の確定）。既存の同IDは本文digestの一致だけを見て保存状態を返し、配送を始めない。中止tombstoneは本文に関わらず中止。
 * 新規は、有効owner・唯一の有効購読と束縛Grant・期限（残り10秒以上）・件数枠を同じsnapshotで確かめ、本文なしの準備状態と
 * ownerの処理中参照・件数枠を書く値を返す。
 */
export function decidePrepare(
  existing: CommandDoc | undefined,
  control: OwnerControl,
  view: AuthorizationView,
  request: NewCommandRequest,
  now: number,
): PrepareDecision {
  if (existing !== undefined) {
    if (!view.ownerActive) return { kind: 'denied', denial: 'connection_revoked' };
    if (existing.tombstone) return { kind: 'existing', doc: existing };
    if (existing.digest === null || !hashesEqual(existing.digest, request.digest)) return { kind: 'conflict' };
    return { kind: 'existing', doc: existing };
  }
  const authorized = authorize(view, now);
  if (!authorized.ok) return { kind: 'denied', denial: authorized.denial };
  const expiresAt = request.expiresAt;
  if (typeof expiresAt !== 'number') return { kind: 'timing', code: expiresAt };
  if (expiresAt - Math.max(now, request.receivedAt) < MIN_SEND_REMAINING_MS) return { kind: 'timing', code: 'command_expired' };
  const rate = decideCommandRate(control.rate, now);
  if (rate.outcome === 'rate_limited') return { kind: 'rate_limited', retryAfterSec: rate.retryAfterSec };
  const deadlineAt = Math.min(request.receivedAt + API_BUDGET_MS, expiresAt);
  const doc: CommandDoc = {
    version: DELIVERY_FORMAT_VERSION,
    ownerId: request.ownerId,
    tombstone: false,
    digest: request.digest,
    state: 'prepared',
    reason: null,
    attemptId: request.attemptId,
    destination: authorized.destination,
    receivedAt: request.receivedAt,
    expiresAt,
    deadlineAt,
    updatedAt: now,
    acknowledgedAt: null,
    purgeAt: request.receivedAt + COMMAND_RETENTION_MS,
  };
  return {
    kind: 'prepared',
    doc,
    control: ownerControlData(request.ownerId, rate.nextState, { commandKey: request.commandKey, until: deadlineAt }),
    sealedUrl: authorized.sealedUrl,
    sealedSecret: authorized.sealedSecret,
    previous: authorized.previous,
  };
}

export type DispatchDecision =
  /** この試行だけに送出権を確定した。previousValidは旧secretの猶予がまだ続くか。 */
  | { readonly kind: 'granted'; readonly doc: CommandDoc; readonly previousValid: boolean }
  /** 送らずに終端へ確定した（中止・期限・宛先/認可の変更）。 */
  | { readonly kind: 'refused'; readonly doc: CommandDoc }
  /** 既に別の状態（先着の中止・別の確定）。何も書かない。 */
  | { readonly kind: 'unchanged'; readonly doc: CommandDoc | undefined };

/**
 * 送出権の確定。準備状態で同じattemptのものだけを、最新の認可・購読の宛先版・期限で再確認してdispatchingへ1回だけ進める。
 * 合わなければ送らない終端（cancelled以外はfailed/expired）を書く。再実行されても同じsnapshotなら同じ判定になる。
 */
export function decideDispatch(
  current: CommandDoc | undefined,
  view: AuthorizationView,
  attemptId: string,
  previousSealed: string | null,
  now: number,
): DispatchDecision {
  if (current === undefined || current.tombstone || current.state !== 'prepared' || current.attemptId !== attemptId) {
    return { kind: 'unchanged', doc: current };
  }
  const end = (state: 'failed' | 'expired', reason: DeliveryReason): DispatchDecision => ({
    kind: 'refused',
    doc: { ...current, state, reason, updatedAt: now },
  });
  if (now >= current.deadlineAt || current.expiresAt - now < MIN_SEND_REMAINING_MS) return end('expired', 'deadline_passed');
  const authorized = authorize(view, now);
  if (!authorized.ok) return end('failed', authorized.denial === 'destination_change_pending' ? 'destination_changed' : 'authorization_lost');
  const fixed = current.destination;
  const latest = authorized.destination;
  if (
    fixed === null ||
    fixed.subscriptionId !== latest.subscriptionId ||
    fixed.grantId !== latest.grantId ||
    !hashesEqual(fixed.secretHash, latest.secretHash)
  ) {
    return end('failed', 'destination_changed');
  }
  const previousValid = previousSealed !== null && authorized.previous !== null && authorized.previous.sealed === previousSealed;
  return { kind: 'granted', doc: { ...current, state: 'dispatching', updatedAt: now }, previousValid };
}

/** 送出の結果の確定。dispatchingで同じattemptのものだけ。それ以外は書かない。 */
export function decideFinish(
  current: CommandDoc | undefined,
  attemptId: string,
  state: 'delivered' | 'failed' | 'expired' | 'delivery_unknown',
  reason: DeliveryReason,
  now: number,
): CommandDoc | undefined {
  if (current === undefined || current.state !== 'dispatching' || current.attemptId !== attemptId) return undefined;
  return { ...current, state, reason, updatedAt: now, acknowledgedAt: state === 'delivered' ? now : null };
}

/**
 * 準備状態のまま終わらせる（送出権の確定を確認できなかった・送る前に止まった）。dispatchingは、この試行のものでも、
 * DBの確定が不明な場合があるため、送っていないことが確かな時だけ呼び出し側がこれを使う。
 */
export function decideAbandon(current: CommandDoc | undefined, attemptId: string, reason: DeliveryReason, now: number): CommandDoc | undefined {
  if (current === undefined || current.attemptId !== attemptId) return undefined;
  if (current.state !== 'prepared' && current.state !== 'dispatching') return undefined;
  return { ...current, state: 'failed', reason, updatedAt: now };
}

export type CancelDecision =
  /** 何も無かった。tombstoneを書く。 */
  | { readonly kind: 'tombstone'; readonly doc: CommandDoc }
  /** 準備状態を送出権なしで中止へ確定した。 */
  | { readonly kind: 'cancelled'; readonly doc: CommandDoc }
  /** 既に別の状態。書かない。 */
  | { readonly kind: 'observed'; readonly doc: CommandDoc };

/** 中止。準備状態だけを中止へ確定する。送出権の確定後は変えず「中止要求/結果不明」。二重の中止は冪等。 */
export function decideCancel(current: CommandDoc | undefined, ownerId: string, now: number): CancelDecision {
  if (current === undefined) {
    return {
      kind: 'tombstone',
      doc: {
        version: DELIVERY_FORMAT_VERSION,
        ownerId,
        tombstone: true,
        digest: null,
        state: 'cancelled',
        reason: 'cancelled_tombstone',
        attemptId: null,
        destination: null,
        receivedAt: now,
        expiresAt: now,
        deadlineAt: now,
        updatedAt: now,
        acknowledgedAt: null,
        purgeAt: now + COMMAND_RETENTION_MS,
      },
    };
  }
  if (current.state === 'prepared') {
    return { kind: 'cancelled', doc: { ...current, state: 'cancelled', reason: 'cancelled_before_dispatch', updatedAt: now } };
  }
  return { kind: 'observed', doc: current };
}

/** 中止の応答に返すstate。送出権の確定後で終端前は、配送されたか分からない。 */
export function cancelView(doc: CommandDoc, now: number): PublicState {
  if (doc.state === 'dispatching') return 'delivery_unknown';
  return projectState(doc, now);
}

/** 単回送出の固定分類（commands/delivery-attempt.ts）を、新しい終端stateへ写す。2xxだけがdelivered。 */
export function outcomeOf(
  kind: 'delivered' | 'retry' | 'failed' | 'uncertain' | 'unavailable',
  reason: string,
): { readonly state: 'delivered' | 'failed' | 'expired' | 'delivery_unknown'; readonly reason: DeliveryReason } {
  switch (kind) {
    case 'delivered':
      return { state: 'delivered', reason: 'acknowledged' };
    case 'failed':
      if (reason === 'invalid_destination') return { state: 'failed', reason: 'invalid_destination' };
      if (reason === 'local_error') return { state: 'failed', reason: 'local_error' };
      return { state: 'failed', reason: 'receiver_rejected' };
    case 'retry':
      // 再試行はしない。TLS成立前の失敗は本文を流していない。429は受信側の明示の拒否。
      if (reason === 'network_unavailable') return { state: 'failed', reason: 'network_unavailable' };
      if (reason === 'rate_limited') return { state: 'failed', reason: 'receiver_rate_limited' };
      // 5xxは受信側の処理の有無を確かめられないため、未送信確定にしない。
      return { state: 'delivery_unknown', reason: 'receiver_server_error' };
    case 'unavailable':
      // 送出を始める前の確認で止まった（何も送っていない）。
      return { state: 'expired', reason: 'not_sendable' };
    default:
      return { state: 'delivery_unknown', reason: 'transport_ambiguous' };
  }
}
