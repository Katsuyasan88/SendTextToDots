import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** base64urlの不透明値（128ビット以上）。CSRF・nonceの入力形式。 */
export const OPAQUE_VALUE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;

/** CSRF・challenge・nonceに使う256ビットの不透明値。 */
export function newOpaqueValue(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * 保存用の鍵付きhash。素のSHA-256では保存しない。purposeで用途を分け、別用途の値が同じhashにならないようにする。
 */
export interface SecretHasher {
  hash(purpose: string, value: string): string;
}

export function createHmacHasher(key: Buffer): SecretHasher {
  if (key.length < 32) {
    throw new Error('hash key must be at least 32 bytes');
  }
  return {
    hash(purpose, value) {
      return createHmac('sha256', key).update(purpose).update('\0').update(value).digest('hex');
    },
  };
}

export function hashesEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}
