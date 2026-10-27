// 開発者向け6桁ログインコードの純粋な状態・schema・数値（I/O 0）。保存はdeveloper-login-store.ts、本人確認はdeveloper-code-identity.ts。
//   - コードは000000〜999999の文字列（先頭0を保つ）。暗号学的乱数portから一様に選び、Math.random・時刻由来を使わない。
//   - authExpiresAt = issuedAt + 10分（now < authExpiresAtだけ認証可）。deleteAfter = issuedAt + 24時間で、消費・取消でも縮めない。
//   - 予約文書IDはHMAC(dedupeKey, project/database/namespace/purpose/code)。単純hashは6桁を総当たりできるため使わない。
//   - TTL（deleteAfter）は重複防止の保持だけに使い、認証期限の判定へ使わない。
// 平文コード・UID・照会secretを例外・記録へ入れない（固定codeだけ）。

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, randomInt } from 'node:crypto';

import type { SecretHasher } from '../secrets.js';

export const DEVELOPER_LOGIN_VERSION = 1;
export const CODE_DIGITS = 6;
export const CODE_SPACE = 1_000_000;
export const CODE_AUTH_TTL_MS = 10 * 60_000;
export const RESERVATION_HOLD_MS = 24 * 60 * 60_000;
export const MAX_CODE_CANDIDATES = 20;
export const MAX_TRANSACTION_ATTEMPTS = 5;
export const ISSUE_BUDGET_MS = 15_000;
export const EXCHANGE_BUDGET_MS = 15_000;
export const EXCHANGE_BODY_MAX_BYTES = 1024;
export const EXCHANGE_RESPONSE_MAX_BYTES = 16 * 1024;
export const CLAIM_SECRET_BYTES = 32;

/** 設計§7の小規模な自己配置用の初期値（無制限化しない）。 */
export const DEVELOPER_LOGIN_LIMITS = Object.freeze({
  namespaceActiveMax: 5,
  consoleActiveMax: 1,
  consoleIssuesPerHour: 3,
  namespaceIssuesPerHour: 20,
  attemptsPerInteraction: 5,
  attemptsPerSource: 5,
  namespaceFailures: 5,
  issueWindowMs: 60 * 60_000,
  attemptWindowMs: 10 * 60_000,
  /** 試行bucketの物理削除の目安（窓終了＋1時間）。 */
  rateHoldMs: 60 * 60_000,
});

/** 重複防止の用途（プラグイン接続。接続serverとoperator helperで同じ固定値）。 */
export const DEVELOPER_LOGIN_PURPOSE = 'plugin-connect';
export const CODE_PATTERN = /^[0-9]{6}$/;
/** code専用UID。Firebaseが自動で振るApple UIDと重ならない固定接頭辞＋推測不能な24byte。 */
export const CODE_UID_PREFIX = 'sttdc_';
export const CODE_UID_PATTERN = /^sttdc_[A-Za-z0-9_-]{32}$/;
/** custom tokenの認証marker（非秘密）と内部family参照のclaim名。 */
export const CODE_MARKER_CLAIM = 'sttd_dlc';
export const CODE_FAMILY_CLAIM = 'sttd_fam';
export const CODE_MARKER_VALUE = 1;
const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PURPOSE_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

export type DeveloperLoginFailure =
  | 'feature_off'
  | 'invalid_request'
  | 'code_rejected'
  | 'rate_limited'
  | 'issue_exhausted'
  | 'key_rotation_blocked'
  | 'not_owner'
  | 'conflict'
  | 'unavailable';

/** 固定codeだけを持つ失敗（コード・UID・secret・SDK例外を持たない）。 */
export class DeveloperLoginError extends Error {
  constructor(readonly code: DeveloperLoginFailure) {
    super(`developer login: ${code}`);
    this.name = 'DeveloperLoginError';
  }
}

/** 暗号学的乱数port（試験で合成値を注入する。通常runtimeはdefaultRandomだけ）。 */
export interface RandomPort {
  /** 0以上max未満の一様な整数。 */
  int(maxExclusive: number): number;
  bytes(length: number): Buffer;
  uuid(): string;
}

export const defaultRandom: RandomPort = Object.freeze({
  int: (maxExclusive: number) => randomInt(maxExclusive),
  bytes: (length: number) => randomBytes(length),
  uuid: () => globalThis.crypto.randomUUID(),
});

export interface Clock {
  now(): number;
}

/** 重複防止の範囲（同じFirebase project/database/connect namespace/用途）。 */
export interface DeveloperLoginScope {
  readonly projectId: string;
  readonly databaseId: string;
  readonly namespace: string;
  readonly purpose: string;
}

export function checkScope(scope: DeveloperLoginScope): DeveloperLoginScope {
  const { projectId, databaseId, namespace, purpose } = scope;
  for (const value of [projectId, databaseId, namespace]) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 128 || /[\0:/]/.test(value)) throw new DeveloperLoginError('invalid_request');
  }
  if (typeof purpose !== 'string' || !PURPOSE_PATTERN.test(purpose)) throw new DeveloperLoginError('invalid_request');
  return Object.freeze({ projectId, databaseId, namespace, purpose });
}

/** 一様な0〜999999を6桁の文字列へ（先頭0を保つ）。portが範囲外を返したら使わない。 */
export function drawCode(random: RandomPort): string {
  const value = random.int(CODE_SPACE);
  if (!Number.isSafeInteger(value) || value < 0 || value >= CODE_SPACE) throw new DeveloperLoginError('unavailable');
  return String(value).padStart(CODE_DIGITS, '0');
}

export function isCode(value: unknown): value is string {
  return typeof value === 'string' && CODE_PATTERN.test(value);
}

/** 入力欄の値（前後の空白だけ除く。全角・区切り・桁違いは受けない）。 */
export function parseCodeInput(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 16) return null;
  const trimmed = value.trim();
  return isCode(trimmed) ? trimmed : null;
}

/** 推測不能な長い値（照会secret・operationId。base64url 43字以上）。 */
export function newOpaque(random: RandomPort, bytes = CLAIM_SECRET_BYTES): string {
  if (bytes < CLAIM_SECRET_BYTES) throw new DeveloperLoginError('invalid_request');
  return random.bytes(bytes).toString('base64url');
}

export function isOpaque(value: unknown): value is string {
  return typeof value === 'string' && OPAQUE_PATTERN.test(value);
}

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function newCodeUid(random: RandomPort): string {
  return `${CODE_UID_PREFIX}${random.bytes(24).toString('base64url')}`;
}

export function isCodeUid(value: unknown): value is string {
  return typeof value === 'string' && CODE_UID_PATTERN.test(value);
}

// ---- HMAC（用途を分離。dedupeKeyはhasherの中にだけある） ----

function scopePurpose(scope: DeveloperLoginScope, use: string): string {
  return `t265:dlc:${use}:${scope.projectId}:${scope.databaseId}:${scope.namespace}:${scope.purpose}`;
}

export function reservationIdOf(hasher: SecretHasher, scope: DeveloperLoginScope, code: string): string {
  if (!isCode(code)) throw new DeveloperLoginError('invalid_request');
  return hasher.hash(scopePurpose(scope, 'reservation'), code);
}

export function operationIdHashOf(hasher: SecretHasher, scope: DeveloperLoginScope, operationId: string): string {
  if (!isOpaque(operationId)) throw new DeveloperLoginError('invalid_request');
  return hasher.hash(scopePurpose(scope, 'operation'), operationId);
}

export function claimSecretHashOf(hasher: SecretHasher, scope: DeveloperLoginScope, claimSecret: string): string {
  if (!isOpaque(claimSecret)) throw new DeveloperLoginError('invalid_request');
  return hasher.hash(scopePurpose(scope, 'claim'), claimSecret);
}

export function consoleHashOf(hasher: SecretHasher, scope: DeveloperLoginScope, consoleSecret: string): string {
  if (!isOpaque(consoleSecret)) throw new DeveloperLoginError('invalid_request');
  return hasher.hash(scopePurpose(scope, 'console'), consoleSecret);
}

export function codeIdentityHashOf(hasher: SecretHasher, scope: DeveloperLoginScope, uid: string): string {
  if (!isCodeUid(uid)) throw new DeveloperLoginError('invalid_request');
  return hasher.hash(scopePurpose(scope, 'identity'), uid);
}

/** 試行bucketの短期HMAC（生IP・interaction id・コードを保存しない）。 */
export function rateBucketOf(hasher: SecretHasher, scope: DeveloperLoginScope, kind: 'interaction' | 'source' | 'namespace', key: string): string {
  return hasher.hash(scopePurpose(scope, `rate-${kind}`), key);
}

/** 鍵の指紋（定数のHMAC）。鍵の切替を検出し、24時間の予約が残る間の切替で重複防止を回避させない。 */
export function dedupeKeyFingerprint(hasher: SecretHasher, scope: DeveloperLoginScope): string {
  return hasher.hash(scopePurpose(scope, 'key-fingerprint'), 'v1');
}

// ---- 配置秘密（dedupeKey）からの用途別の鍵 ----

/** dedupeKeyの最小長（32byte）。固定値を配布物へ埋め込まず、配置側のSecret Managerから読む。 */
export const DEDUPE_SECRET_MIN_BYTES = 32;

export interface DeveloperLoginKeys {
  readonly hasher: SecretHasher;
  /** 予定UIDの封緘（AES-256-GCM、AADは用途）。接続serverと発行helperが同じ配置秘密から導く。 */
  readonly sealer: { seal(purpose: string, plaintext: string): string; open(purpose: string, sealed: string): string };
}

export function developerLoginKeys(secret: Uint8Array): DeveloperLoginKeys {
  if (!(secret instanceof Uint8Array) || secret.length < DEDUPE_SECRET_MIN_BYTES) throw new DeveloperLoginError('invalid_request');
  const derive = (info: string) => Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), info, 32));
  const macKey = derive('t265:dlc:hmac:v1');
  const sealKey = derive('t265:dlc:seal:v1');
  return Object.freeze({
    hasher: Object.freeze({
      hash: (purpose: string, value: string) => createHmac('sha256', macKey).update(`${purpose}\0${value}`, 'utf8').digest('base64url'),
    }),
    sealer: Object.freeze({
      seal(purpose: string, plaintext: string): string {
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', sealKey, iv);
        cipher.setAAD(Buffer.from(purpose, 'utf8'));
        const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        return `v1.${Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url')}`;
      },
      open(purpose: string, sealed: string): string {
        if (typeof sealed !== 'string' || !sealed.startsWith('v1.')) throw new DeveloperLoginError('unavailable');
        const raw = Buffer.from(sealed.slice(3), 'base64url');
        if (raw.length < 29) throw new DeveloperLoginError('unavailable');
        try {
          const decipher = createDecipheriv('aes-256-gcm', sealKey, raw.subarray(0, 12));
          decipher.setAAD(Buffer.from(purpose, 'utf8'));
          decipher.setAuthTag(raw.subarray(12, 28));
          return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
        } catch {
          throw new DeveloperLoginError('unavailable');
        }
      },
    }),
  });
}

// ---- 状態 ----

export type ReservationState = 'issued' | 'provisioning' | 'active' | 'failed' | 'revoked';
const RESERVATION_STATES: ReadonlySet<string> = new Set(['issued', 'provisioning', 'active', 'failed', 'revoked']);

export interface ReservationRecord {
  readonly version: 1;
  readonly issuanceId: string;
  readonly consoleHash: string;
  readonly consoleGeneration: number;
  readonly purpose: string;
  readonly issuedAt: number;
  readonly authExpiresAt: number;
  /** epoch ms（保存はFirestore Timestamp）。 */
  readonly deleteAfter: number;
  readonly state: ReservationState;
  readonly boundInteractionHash: string | null;
}

export const RESERVATION_KEYS = [
  'version',
  'issuanceId',
  'consoleHash',
  'consoleGeneration',
  'purpose',
  'issuedAt',
  'authExpiresAt',
  'deleteAfter',
  'state',
  'boundInteractionHash',
] as const;

export function newReservation(input: {
  readonly issuanceId: string;
  readonly consoleHash: string;
  readonly consoleGeneration: number;
  readonly purpose: string;
  readonly issuedAt: number;
}): ReservationRecord {
  return Object.freeze({
    version: DEVELOPER_LOGIN_VERSION,
    issuanceId: input.issuanceId,
    consoleHash: input.consoleHash,
    consoleGeneration: input.consoleGeneration,
    purpose: input.purpose,
    issuedAt: input.issuedAt,
    authExpiresAt: input.issuedAt + CODE_AUTH_TTL_MS,
    deleteAfter: input.issuedAt + RESERVATION_HOLD_MS,
    state: 'issued',
    boundInteractionHash: null,
  });
}

function isEpoch(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** 正確なkey集合・型・版だけを受ける（未知版・追加key・欠落は不正で、自動修復しない）。 */
export function exactKeys(data: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new DeveloperLoginError('unavailable');
  const own = Object.keys(data);
  if (own.length !== keys.length || !keys.every((key) => Object.hasOwn(data, key))) throw new DeveloperLoginError('unavailable');
  return data as Record<string, unknown>;
}

export function parseReservation(data: unknown, deleteAfterMs: (value: unknown) => number | null): ReservationRecord {
  const record = exactKeys(data, RESERVATION_KEYS);
  const deleteAfter = deleteAfterMs(record.deleteAfter);
  const fail = () => new DeveloperLoginError('unavailable');
  if (record.version !== DEVELOPER_LOGIN_VERSION) throw fail();
  if (!isUuid(record.issuanceId) || typeof record.consoleHash !== 'string' || record.consoleHash.length === 0) throw fail();
  if (!Number.isSafeInteger(record.consoleGeneration) || (record.consoleGeneration as number) < 1) throw fail();
  if (typeof record.purpose !== 'string' || !PURPOSE_PATTERN.test(record.purpose)) throw fail();
  if (!isEpoch(record.issuedAt) || record.authExpiresAt !== record.issuedAt + CODE_AUTH_TTL_MS) throw fail();
  if (deleteAfter === null || deleteAfter < record.issuedAt + RESERVATION_HOLD_MS) throw fail();
  if (typeof record.state !== 'string' || !RESERVATION_STATES.has(record.state)) throw fail();
  if (record.boundInteractionHash !== null && typeof record.boundInteractionHash !== 'string') throw fail();
  if ((record.state === 'issued') !== (record.boundInteractionHash === null) && record.state !== 'revoked') throw fail();
  return Object.freeze({
    version: DEVELOPER_LOGIN_VERSION,
    issuanceId: record.issuanceId,
    consoleHash: record.consoleHash,
    consoleGeneration: record.consoleGeneration as number,
    purpose: record.purpose,
    issuedAt: record.issuedAt,
    authExpiresAt: record.authExpiresAt,
    deleteAfter,
    state: record.state as ReservationState,
    boundInteractionHash: record.boundInteractionHash,
  });
}

/** 認証に使えるか（issuedかつnow < authExpiresAt）。deleteAfter・物理削除は見ない。 */
export function reservationUsable(record: ReservationRecord, now: number): boolean {
  return record.state === 'issued' && now < record.authExpiresAt;
}

/** 期限切れ（issuedのまま10分を過ぎた）は時計だけで判定する。 */
export function reservationExpired(record: ReservationRecord, now: number): boolean {
  return record.state === 'issued' && now >= record.authExpiresAt;
}

/** 状態遷移。deleteAfterは常に元の値（短縮しない）。許されない遷移はconflict。 */
export function transitionReservation(record: ReservationRecord, next: ReservationState, interactionHash?: string): ReservationRecord {
  const allowed: Record<ReservationState, readonly ReservationState[]> = {
    issued: ['provisioning', 'revoked'],
    provisioning: ['active', 'failed', 'revoked'],
    active: ['revoked'],
    failed: ['revoked'],
    revoked: [],
  };
  if (!allowed[record.state].includes(next)) throw new DeveloperLoginError('conflict');
  const boundInteractionHash = next === 'provisioning' ? (interactionHash ?? null) : record.boundInteractionHash;
  if (next === 'provisioning' && boundInteractionHash === null) throw new DeveloperLoginError('invalid_request');
  return Object.freeze({ ...record, state: next, boundInteractionHash });
}

// ---- 固定窓の件数（同じtransactionで読んで書く） ----

export interface WindowCount {
  readonly windowStart: number;
  readonly count: number;
}

/** 窓内の現在件数（窓外なら0から）。 */
export function windowCount(current: WindowCount | null, now: number, windowMs: number): WindowCount {
  if (current === null || now < current.windowStart || now - current.windowStart >= windowMs) return { windowStart: now, count: 0 };
  return current;
}

/** 窓内の時刻だけを残す（発行回数の時間窓）。 */
export function pruneTimes(times: readonly number[], now: number, windowMs: number): number[] {
  return times.filter((time) => time <= now && now - time < windowMs);
}
