// 指示受付の件数枠の純粋な計算（delivery/contract.tsの受付判定が使う）。値の正本は docs/API.md §2。
// ownerごとの「rolling 60秒に10件」と「容量3・毎分10件の補充（整数のbucket）」を、渡された状態と時刻だけから同時に判定する。
// 同期の検査と計算だけで、時計・環境変数・乱数・暗号・DB・HTTP・global・cache・ログを持たない。入力は変更も保持もしない。
// 返す状態は、このmoduleが作った凍結済みの写し。形が合わない入力・安全でない数は、固定のStoreError（store_error）だけ
// （文言・cause・渡された値を持たない）。

import { StoreError } from '../storage/firestore/errors.js';

/** rollingの窓（ミリ秒）と、その中の上限。 */
export const COMMAND_RATE_WINDOW_MS = 60_000;
export const COMMAND_RATE_WINDOW_LIMIT = 10;
/** bucket。1件は60000 unit、1ミリ秒で10 unit補充、容量は3件分。 */
export const COMMAND_RATE_UNITS_PER_COMMAND = 60_000;
export const COMMAND_RATE_UNITS_PER_MS = 10;
export const COMMAND_RATE_CAPACITY_UNITS = 180_000;
/** この時間（ミリ秒）以上の経過は、積算せずに容量へ揃える。 */
export const COMMAND_RATE_FULL_REFILL_MS = 18_000;
/** 拒否のときの案内の上限（秒）。その秒数の後の許可の保証ではない。 */
export const COMMAND_RATE_MAX_RETRY_AFTER_SEC = 60;

export interface CommandRateState {
  /** 最後に枠を消費した判定時刻（epochミリ秒）。 */
  readonly updatedAt: number;
  /** bucketの残り（0〜COMMAND_RATE_CAPACITY_UNITS）。 */
  readonly tokenUnits: number;
  /** 窓の中の消費の判定時刻（古い順。同じ時刻の重複あり。最大COMMAND_RATE_WINDOW_LIMIT件）。 */
  readonly hits: readonly number[];
}

export type CommandRateDecision =
  | { readonly outcome: 'allowed'; readonly nextState: CommandRateState }
  | { readonly outcome: 'rate_limited'; readonly retryAfterSec: number };

const STATE_KEYS = ['updatedAt', 'tokenUnits', 'hits'];

const failed = () => new StoreError('store_error');

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** 決まった3つのdata propertyだけを持つplain objectから、値を1回ずつ取り出す。getterは呼ばない。 */
function takeFields(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw failed();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw failed();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== STATE_KEYS.length) throw failed();
  const taken: Record<string, unknown> = {};
  for (const key of STATE_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw failed();
    taken[key] = descriptor.value;
  }
  return taken;
}

/** 穴・余分な項目・accessorの無い配列から、要素を1回ずつ取り出す。 */
function takeHits(value: unknown): number[] {
  if (!Array.isArray(value)) throw failed();
  const length = value.length;
  if (length > COMMAND_RATE_WINDOW_LIMIT) throw failed();
  // 'length'と、0からlength-1までの添字だけ。
  if (Reflect.ownKeys(value).length !== length + 1) throw failed();
  const hits: number[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !('value' in descriptor)) throw failed();
    const hit: unknown = descriptor.value;
    if (!isCount(hit)) throw failed();
    hits.push(hit);
  }
  return hits;
}

function parse(value: unknown): CommandRateState {
  const fields = takeFields(value);
  const { updatedAt, tokenUnits } = fields;
  if (!isCount(updatedAt)) throw failed();
  if (!isCount(tokenUnits) || tokenUnits > COMMAND_RATE_CAPACITY_UNITS) throw failed();
  const hits = takeHits(fields.hits);
  let previous = 0;
  for (const hit of hits) {
    // 古い順（同じ時刻は可）で、updatedAtより後でなく、updatedAtの窓の中。
    if (hit < previous || hit > updatedAt || hit <= updatedAt - COMMAND_RATE_WINDOW_MS) throw failed();
    previous = hit;
  }
  return Object.freeze({ updatedAt, tokenUnits, hits: Object.freeze(hits) });
}

/**
 * 保存されていた状態の検査。合えば、このmoduleが作った凍結済みの写しを返す。合わなければ固定のstore_error
 * （期限切れ・初期状態へ読み替えない）。
 */
export function parseCommandRateState(value: unknown): CommandRateState {
  try {
    return parse(value);
  } catch {
    throw failed();
  }
}

function decide(state: unknown, now: unknown): CommandRateDecision {
  if (!isCount(now)) throw failed();
  // 状態が無いowner（永続の書込みは、まだ無い）。
  const current: CommandRateState = state === undefined ? { updatedAt: now, tokenUnits: COMMAND_RATE_CAPACITY_UNITS, hits: [] } : parse(state);
  // 時計が戻っていても、状態の時刻より前へは戻さない（枠を再充填しない）。
  const effectiveNow = Math.max(now, current.updatedAt);
  const recent = current.hits.filter((hit) => hit > effectiveNow - COMMAND_RATE_WINDOW_MS);
  const elapsed = effectiveNow - current.updatedAt;
  const units =
    elapsed >= COMMAND_RATE_FULL_REFILL_MS
      ? COMMAND_RATE_CAPACITY_UNITS
      : Math.min(COMMAND_RATE_CAPACITY_UNITS, current.tokenUnits + elapsed * COMMAND_RATE_UNITS_PER_MS);

  if (recent.length < COMMAND_RATE_WINDOW_LIMIT && units >= COMMAND_RATE_UNITS_PER_COMMAND) {
    return Object.freeze({
      outcome: 'allowed' as const,
      nextState: Object.freeze({
        updatedAt: effectiveNow,
        tokenUnits: units - COMMAND_RATE_UNITS_PER_COMMAND,
        hits: Object.freeze([...recent, effectiveNow]),
      }),
    });
  }

  const bucketWaitMs = units < COMMAND_RATE_UNITS_PER_COMMAND ? Math.ceil((COMMAND_RATE_UNITS_PER_COMMAND - units) / COMMAND_RATE_UNITS_PER_MS) : 0;
  const oldest = recent[0];
  const rollingWaitMs = recent.length >= COMMAND_RATE_WINDOW_LIMIT && oldest !== undefined ? oldest - effectiveNow + COMMAND_RATE_WINDOW_MS : 0;
  const waitMs = Math.max(bucketWaitMs, rollingWaitMs);
  const clockDebtMs = Math.min(COMMAND_RATE_WINDOW_MS, effectiveNow - now);
  const retryAfterSec = Math.min(COMMAND_RATE_MAX_RETRY_AFTER_SEC, Math.max(1, Math.ceil((clockDebtMs + waitMs) / 1000)));
  return Object.freeze({ outcome: 'rate_limited' as const, retryAfterSec });
}

/**
 * 1件の新しい指示を、nowで受け付けられるか。stateは、保存されていた状態か、状態の無いownerのundefined。
 * allowedのnextStateは、新しい保存が確定するときにだけ書く値（凍結済みの写し）。rate_limitedは、状態を返さない
 * （何も書かない・返金しない）。
 */
export function decideCommandRate(state: unknown, now: unknown): CommandRateDecision {
  try {
    return decide(state, now);
  } catch {
    throw failed();
  }
}
