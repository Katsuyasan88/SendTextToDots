// 本文暗号化の鍵保存の型・版・純粋な検証（I/O・時計・乱数・SDK・ログ0。公開鍵の同一性だけNode組込みcryptoのSPKI解析を使う）。

//   ring文書: sttdEncryption/{encryptionNamespace}/rings/{scope}
//     exact {schemaVersion: 1, scope, identityHash, ownerId, generation, activeKid, keys(1〜5), reissues(0〜4), createdAt, updatedAt, lastUsedAt}
//   controls文書: sttdEncryption/{encryptionNamespace}/controls/{scope}（初期化前から使う有限窓のrateだけ。鍵を持たない）
//     exact {schemaVersion: 1, scope, identityHash, ownerId, windows: {init, fetch, decrypt, reissueAttempt}}
//   鍵の可変項目（state・猶予）はAEADのAADに入れず、ここでexactに検査する。不正は全てEncryptionRecordError（自動修復しない）。
// 本文・CEK・暗号文本文・生の秘密鍵・生の保護鍵・UIDは保存しない。

import { createPublicKey } from 'node:crypto';

export const ENCRYPTION_STORAGE_ROOT = 'sttdEncryption';
export const RINGS_COLLECTION = 'rings';
export const CONTROLS_COLLECTION = 'controls';
export const PAYLOAD_ENCRYPTION_MODE = 'jwe-rsa-oaep-256-a256gcm-v1';
export const RING_SCHEMA_VERSION = 1;
export const CONTROLS_SCHEMA_VERSION = 1;
/** wrappedPrivateKeyの形式（AES-256-GCM、nonce12/tag16、PKCS8 DER）。 */
export const WRAP_FORMAT_VERSION = 1;
export const WRAP_PURPOSE = 'sttd-private-key-v1';
export const SCOPE_PURPOSE = 'sttd-encryption-scope-v1';
export const RSA_MODULUS_BITS = 3072;
export const KEY_ALG = 'RSA-OAEP-256';
export const KEY_ENC = 'A256GCM';
export const MAX_KEYS = 5;
export const MAX_REISSUES = 4;
/** activeの最終利用から利用拒否までの無活動期間（90日）。 */
export const RING_INACTIVITY_MS = 90 * 24 * 60 * 60 * 1000;
export const MINUTE_MS = 60_000;
export const DAY_MS = 86_400_000;

export type RateKind = 'init' | 'fetch' | 'decrypt' | 'reissueAttempt';
export const RATE_KINDS: readonly RateKind[] = Object.freeze(['init', 'fetch', 'decrypt', 'reissueAttempt']);
/** owner/scope別の固定分・UTC日の上限。 */
export const RATE_LIMITS: Readonly<Record<RateKind, { readonly minute: number; readonly day: number }>> = Object.freeze({
  init: Object.freeze({ minute: 3, day: 10 }),
  fetch: Object.freeze({ minute: 60, day: 1000 }),
  decrypt: Object.freeze({ minute: 30, day: 1000 }),
  reissueAttempt: Object.freeze({ minute: 3, day: 10 }),
});

export type KeyState = 'active' | 'grace' | 'revoked';

export interface PublicJwk {
  readonly kty: 'RSA';
  readonly n: string;
  readonly e: string;
  readonly kid: string;
  readonly alg: typeof KEY_ALG;
  readonly use: 'enc';
}

export interface KeyRecord {
  readonly kid: string;
  readonly publicJwk: PublicJwk;
  /** SPKI DERのbase64url（padding無し）。 */
  readonly publicKeySpki: string;
  readonly createdAt: number;
  readonly state: KeyState;
  /** grace/revokedの開封期限（activeはnull）。 */
  readonly decryptUntil: number | null;
  /** 回収可能になる時刻（activeはnull）。 */
  readonly retireAfter: number | null;
  readonly secretVersion: number;
  readonly formatVersion: typeof WRAP_FORMAT_VERSION;
  /** nonce12‖ciphertext‖tag16のbase64url。 */
  readonly wrappedPrivateKey: string;
}

export interface ReissueRecord {
  readonly requestId: string;
  readonly mode: 'normal' | 'compromised';
  readonly kid: string;
  readonly at: number;
}

export interface RingRecord {
  readonly schemaVersion: typeof RING_SCHEMA_VERSION;
  readonly scope: string;
  readonly identityHash: string;
  readonly ownerId: string;
  readonly generation: number;
  readonly activeKid: string;
  readonly keys: readonly KeyRecord[];
  readonly reissues: readonly ReissueRecord[];
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly lastUsedAt: number;
}

export interface RateWindow {
  readonly minuteStart: number;
  readonly minuteCount: number;
  readonly dayStart: number;
  readonly dayCount: number;
}

export interface ControlsRecord {
  readonly schemaVersion: typeof CONTROLS_SCHEMA_VERSION;
  readonly scope: string;
  readonly identityHash: string;
  readonly ownerId: string;
  readonly windows: Readonly<Record<RateKind, RateWindow>>;
}

/** 保存recordの形が不正（固定message。値・pathを持たない）。 */
export class EncryptionRecordError extends Error {
  override readonly name = 'EncryptionRecordError';
  constructor() {
    super('encryption record is invalid');
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const IDENTITY_HASH = /^[0-9a-f]{64}$/;
const SCOPE = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const ENCRYPTION_NAMESPACE = /^t280_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isEncryptionNamespace(value: unknown): value is string {
  return typeof value === 'string' && ENCRYPTION_NAMESPACE.test(value);
}

/** 32byteのHMAC出力のcanonical base64url（43文字、末尾の余剰bit0）。DB pathにも使える。 */
export function isScope(value: unknown): value is string {
  return typeof value === 'string' && SCOPE.test(value);
}

export function isKid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

/** padding無しのcanonical base64url（decodeして再encodeが同じ）。 */
export function canonicalBase64url(value: unknown, maxLength: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || !B64URL.test(value) || value.length % 4 === 1) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function plain(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new EncryptionRecordError();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new EncryptionRecordError();
  return value as Record<string, unknown>;
}

/** exactなown data propertyだけを持つobjectのkey→値（余分・欠落・accessor・symbolは不正）。 */
function exact(value: unknown, keys: readonly string[]): Map<string, unknown> {
  const data = plain(value);
  const own = Reflect.ownKeys(data);
  if (own.length !== keys.length) throw new EncryptionRecordError();
  const fields = new Map<string, unknown>();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(data, key);
    if (descriptor === undefined || !('value' in descriptor)) throw new EncryptionRecordError();
    fields.set(key, descriptor.value);
  }
  return fields;
}

function items(value: unknown, min: number, max: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new EncryptionRecordError();
  if (value.length < min || value.length > max) throw new EncryptionRecordError();
  const out: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) throw new EncryptionRecordError();
    out.push(descriptor.value);
  }
  return out;
}

function need(condition: boolean): void {
  if (!condition) throw new EncryptionRecordError();
}

const JWK_KEYS = ['kty', 'n', 'e', 'kid', 'alg', 'use'] as const;
const KEY_KEYS = ['kid', 'publicJwk', 'publicKeySpki', 'createdAt', 'state', 'decryptUntil', 'retireAfter', 'secretVersion', 'formatVersion', 'wrappedPrivateKey'] as const;
const REISSUE_KEYS = ['requestId', 'mode', 'kid', 'at'] as const;
const RING_KEYS = ['schemaVersion', 'scope', 'identityHash', 'ownerId', 'generation', 'activeKid', 'keys', 'reissues', 'createdAt', 'updatedAt', 'lastUsedAt'] as const;
const CONTROLS_KEYS = ['schemaVersion', 'scope', 'identityHash', 'ownerId', 'windows'] as const;
const WINDOW_KEYS = ['minuteStart', 'minuteCount', 'dayStart', 'dayCount'] as const;
/** RSA3072のn（384byte）のbase64urlは512文字、SPKI DER（422byte）は563文字。 */
const N_LENGTH = 512;
const SPKI_MAX = 600;
/** PKCS8 DER（RSA3072は概ね1.7KiB）＋nonce/tagのbase64urlの上限。 */
const WRAPPED_MAX = 4096;

export function parsePublicJwk(value: unknown): PublicJwk {
  const f = exact(value, JWK_KEYS);
  const n = canonicalBase64url(f.get('n'), N_LENGTH);
  need(f.get('kty') === 'RSA' && f.get('e') === 'AQAB' && isKid(f.get('kid')) && f.get('alg') === KEY_ALG && f.get('use') === 'enc');
  need(n !== null && n.length === RSA_MODULUS_BITS / 8 && (n[0] ?? 0) >= 0x80);
  return { kty: 'RSA', n: f.get('n') as string, e: 'AQAB', kid: f.get('kid') as string, alg: KEY_ALG, use: 'enc' };
}

/**
 * 保存の公開JWKとSPKIが同じRSA3072/e=65537の鍵か（Node組込みcryptoのSPKI解析だけ。独自DER解析0）。
 * SPKIは再exportしたDERと同じbytesであること（余剰・非canonicalを拒否）、JWKのn/eはSPKIから導いた値と一致すること。
 */
function samePublicKey(jwk: PublicJwk, spki: Buffer): boolean {
  try {
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const details = key.asymmetricKeyDetails;
    if (key.asymmetricKeyType !== 'rsa' || details?.modulusLength !== RSA_MODULUS_BITS || details.publicExponent !== 65537n) return false;
    if (!key.export({ format: 'der', type: 'spki' }).equals(spki)) return false;
    const derived = key.export({ format: 'jwk' });
    return derived.n === jwk.n && derived.e === jwk.e;
  } catch {
    return false;
  }
}

export function parseKeyRecord(value: unknown): KeyRecord {
  const f = exact(value, KEY_KEYS);
  const kid = f.get('kid');
  const publicJwk = parsePublicJwk(f.get('publicJwk'));
  const state = f.get('state');
  const decryptUntil = f.get('decryptUntil');
  const retireAfter = f.get('retireAfter');
  const secretVersion = f.get('secretVersion');
  need(isKid(kid) && publicJwk.kid === kid);
  const spki = canonicalBase64url(f.get('publicKeySpki'), SPKI_MAX);
  need(spki !== null && samePublicKey(publicJwk, spki) && isTime(f.get('createdAt')));
  need(state === 'active' || state === 'grace' || state === 'revoked');
  if (state === 'active') need(decryptUntil === null && retireAfter === null);
  else need(isTime(decryptUntil) && isTime(retireAfter));
  need(typeof secretVersion === 'number' && Number.isSafeInteger(secretVersion) && secretVersion >= 1);
  need(f.get('formatVersion') === WRAP_FORMAT_VERSION);
  const wrapped = canonicalBase64url(f.get('wrappedPrivateKey'), WRAPPED_MAX);
  need(wrapped !== null && wrapped.length > 12 + 16);
  wrapped?.fill(0);
  return {
    kid: kid as string,
    publicJwk,
    publicKeySpki: f.get('publicKeySpki') as string,
    createdAt: f.get('createdAt') as number,
    state: state as KeyState,
    decryptUntil: decryptUntil as number | null,
    retireAfter: retireAfter as number | null,
    secretVersion: secretVersion as number,
    formatVersion: WRAP_FORMAT_VERSION,
    wrappedPrivateKey: f.get('wrappedPrivateKey') as string,
  };
}

function parseReissue(value: unknown): ReissueRecord {
  const f = exact(value, REISSUE_KEYS);
  const mode = f.get('mode');
  need(isKid(f.get('requestId')) && (mode === 'normal' || mode === 'compromised') && isKid(f.get('kid')) && isTime(f.get('at')));
  return { requestId: f.get('requestId') as string, mode: mode as ReissueRecord['mode'], kid: f.get('kid') as string, at: f.get('at') as number };
}

/** 束縛（scope/identityHash/ownerId）の期待値と一致するring文書だけを写す。 */
export function parseRingRecord(value: unknown, expected: { readonly scope: string; readonly identityHash: string; readonly ownerId: string }): RingRecord {
  const f = exact(value, RING_KEYS);
  need(f.get('schemaVersion') === RING_SCHEMA_VERSION);
  need(f.get('scope') === expected.scope && f.get('identityHash') === expected.identityHash && f.get('ownerId') === expected.ownerId);
  const generation = f.get('generation');
  need(typeof generation === 'number' && Number.isSafeInteger(generation) && generation >= 1);
  const keys = items(f.get('keys'), 1, MAX_KEYS).map(parseKeyRecord);
  const reissues = items(f.get('reissues'), 0, MAX_REISSUES).map(parseReissue);
  const kids = new Set(keys.map((key) => key.kid));
  need(kids.size === keys.length);
  const actives = keys.filter((key) => key.state === 'active');
  need(actives.length === 1 && actives[0]?.kid === f.get('activeKid'));
  need(isTime(f.get('createdAt')) && isTime(f.get('updatedAt')) && isTime(f.get('lastUsedAt')));
  return {
    schemaVersion: RING_SCHEMA_VERSION,
    scope: expected.scope,
    identityHash: expected.identityHash,
    ownerId: expected.ownerId,
    generation: generation as number,
    activeKid: f.get('activeKid') as string,
    keys,
    reissues,
    createdAt: f.get('createdAt') as number,
    updatedAt: f.get('updatedAt') as number,
    lastUsedAt: f.get('lastUsedAt') as number,
  };
}

function parseWindow(value: unknown): RateWindow {
  const f = exact(value, WINDOW_KEYS);
  need(isCount(f.get('minuteStart')) && isCount(f.get('minuteCount')) && isCount(f.get('dayStart')) && isCount(f.get('dayCount')));
  need((f.get('minuteStart') as number) % MINUTE_MS === 0 && (f.get('dayStart') as number) % DAY_MS === 0);
  return { minuteStart: f.get('minuteStart') as number, minuteCount: f.get('minuteCount') as number, dayStart: f.get('dayStart') as number, dayCount: f.get('dayCount') as number };
}

export function parseControlsRecord(value: unknown, expected: { readonly scope: string; readonly identityHash: string; readonly ownerId: string }): ControlsRecord {
  const f = exact(value, CONTROLS_KEYS);
  need(f.get('schemaVersion') === CONTROLS_SCHEMA_VERSION);
  need(f.get('scope') === expected.scope && f.get('identityHash') === expected.identityHash && f.get('ownerId') === expected.ownerId);
  const w = exact(f.get('windows'), RATE_KINDS);
  const windows = Object.fromEntries(RATE_KINDS.map((kind) => [kind, parseWindow(w.get(kind))])) as Record<RateKind, RateWindow>;
  return { schemaVersion: CONTROLS_SCHEMA_VERSION, scope: expected.scope, identityHash: expected.identityHash, ownerId: expected.ownerId, windows };
}

const EMPTY_WINDOW: RateWindow = Object.freeze({ minuteStart: 0, minuteCount: 0, dayStart: 0, dayCount: 0 });

export function emptyControls(binding: { readonly scope: string; readonly identityHash: string; readonly ownerId: string }): ControlsRecord {
  return {
    schemaVersion: CONTROLS_SCHEMA_VERSION,
    ...binding,
    windows: { init: EMPTY_WINDOW, fetch: EMPTY_WINDOW, decrypt: EMPTY_WINDOW, reissueAttempt: EMPTY_WINDOW },
  };
}

/**
 * server時刻で固定分・UTC日の窓を1件消費する。超過は消費せず、残る制約の最長待ちのceil秒（最小1）を返す。
 */
export function consumeRate(window: RateWindow, kind: RateKind, now: number): { readonly next: RateWindow } | { readonly retryAfterSec: number } {
  if (!isTime(now)) throw new EncryptionRecordError();
  const minuteStart = Math.floor(now / MINUTE_MS) * MINUTE_MS;
  const dayStart = Math.floor(now / DAY_MS) * DAY_MS;
  // 保存窓より前の時刻（時計の巻戻し）・未来の保存窓は枠の取り直しにせず固定障害にする。
  if (window.minuteStart > minuteStart || window.dayStart > dayStart) throw new EncryptionRecordError();
  const minuteCount = window.minuteStart === minuteStart ? window.minuteCount : 0;
  const dayCount = window.dayStart === dayStart ? window.dayCount : 0;
  const limit = RATE_LIMITS[kind];
  const waits: number[] = [];
  if (minuteCount >= limit.minute) waits.push(minuteStart + MINUTE_MS - now);
  if (dayCount >= limit.day) waits.push(dayStart + DAY_MS - now);
  if (waits.length > 0) return { retryAfterSec: Math.max(1, Math.ceil(Math.max(...waits) / 1000)) };
  return { next: { minuteStart, minuteCount: minuteCount + 1, dayStart, dayCount: dayCount + 1 } };
}

/** 鍵がこの時刻に開封へ使えるか（activeはring無活動期限まで、graceはdecryptUntil未満、revokedは不可）。 */
export function keyUsable(ring: RingRecord, key: KeyRecord, now: number): boolean {
  if (now - ring.lastUsedAt >= RING_INACTIVITY_MS) return false;
  if (key.state === 'active') return true;
  if (key.state === 'grace') return key.decryptUntil !== null && now < key.decryptUntil;
  return false;
}

/** 公開してよい本人の現在鍵（秘密要素・UID・ownerId・Secret参照を含めない）。 */
export interface PublicKeyResult {
  readonly version: 1;
  readonly kid: string;
  readonly alg: typeof KEY_ALG;
  readonly enc: typeof KEY_ENC;
  readonly scope: string;
  readonly publicJwk: PublicJwk;
  readonly publicKeySpki: string;
  readonly createdAt: number;
}

export function publicKeyResultOf(ring: RingRecord): PublicKeyResult {
  const key = ring.keys.find((entry) => entry.kid === ring.activeKid);
  if (key === undefined) throw new EncryptionRecordError();
  return Object.freeze({
    version: 1,
    kid: key.kid,
    alg: KEY_ALG,
    enc: KEY_ENC,
    scope: ring.scope,
    publicJwk: Object.freeze({ ...key.publicJwk }),
    publicKeySpki: key.publicKeySpki,
    createdAt: key.createdAt,
  });
}
