// 保存文書の形の検査に共有する小さな述語（Firestore SDK・時計・乱数を使わない）。

import { StoreError } from './errors.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function isHash(value: unknown): value is string {
  return typeof value === 'string' && HASH_PATTERN.test(value);
}

/** epochミリ秒。 */
export function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** 不正な内部入力・上限超過・破損した文書は固定のStoreError（値は例外へ混ぜない）。 */
export function requireThat(condition: boolean): asserts condition {
  if (!condition) throw new StoreError('store_error');
}
