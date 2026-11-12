import { randomBytes } from 'node:crypto';

export const PAIR_APP_PATH = '/v1/source/pair';
export const APP_PAIR_CODE = /^[A-Za-z0-9_-]{12}$/;
export const APP_PAIR_TTL_MS = 10 * 60_000;
export const ACCOUNT_GRANT = Object.freeze({ version: 1, kind: 'account' } as const);

export function isAccountGrant(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const data = value as Record<string, unknown>;
  return Object.keys(data).length === 2 && data.version === 1 && data.kind === 'account';
}

export function newAppPairCode(): string {
  return randomBytes(9).toString('base64url');
}

export function isAppLabel(value: unknown): value is string {
  return typeof value === 'string' && value.trim() === value && value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= 100 && !/[\p{Cc}\p{Cf}]/u.test(value);
}

export type AppManagementRequest =
  | { readonly kind: 'list' }
  | { readonly kind: 'issue'; readonly name: string }
  | { readonly kind: 'remove'; readonly appId: string };

export type AppManagementResult =
  | { readonly apps: ReadonlyArray<{ readonly appId: string; readonly name: string }> }
  | { readonly code: string; readonly expiresAt: string; readonly name: string }
  | { readonly removed: boolean }
  | { readonly error: 'connection_required' };
