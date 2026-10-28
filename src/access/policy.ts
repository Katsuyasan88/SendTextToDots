// 利用許可（運営者が明示登録した利用者だけ）の純粋な判定。I/O・時計・乱数・SDK・ログ0。
//   許可record: sttdConnect/{connectNamespace}/access/{identityHash} の exact schema
//     {version: 1, state: 'active' | 'disabled', generation: <小文字UUID>, updatedAt: <epoch ms safe integer>}
//   - 欠落・disabled → denied（利用不許可）。
//   - 不正schema・未知版 → unavailable（固定の一時障害。activeへ読み替えず、永久の不許可やowner失効とも区別する）。
//   - 正常active → allowed（そのgenerationが利用許可の世代）。
//   Grantの同意記録（grantMeta）は exact {ownerId: 小文字UUID, authTimeSec: 正の安全な整数, createdAt: 正の安全な整数ms, accessGeneration}。
//   accessGenerationだけが無い正しい旧形式は移行前Grantとして新規利用に使えず（denied）、それ以外の形の不正はunavailable。
//   世代・ownerの不一致はdenied。
// identityHashは接続保存（ConnectStorage）の既存identity用HMACと同じ値で、ここでは形（64桁の小文字hex）だけを見る。

/** 許可recordの唯一の版。 */
export const ACCESS_RECORD_VERSION = 1;
/** 許可recordを置く接続保存配下のcollection名。 */
export const ACCESS_COLLECTION = 'access';

const GENERATION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDENTITY_HASH = /^[0-9a-f]{64}$/;
const RECORD_KEYS = ['version', 'state', 'generation', 'updatedAt'] as const;
const GRANT_META_LEGACY_KEYS = ['ownerId', 'authTimeSec', 'createdAt'] as const;
const GRANT_META_KEYS = ['ownerId', 'authTimeSec', 'createdAt', 'accessGeneration'] as const;
const GRANT_META_RECEIVER_KEYS = ['ownerId', 'authTimeSec', 'createdAt', 'accessGeneration', 'receiverGeneration'] as const;

/** 受信reset世代（ownerの受信先設定一式を消した回数）。安全な整数で、下限以上の時だけ有効。 */
function isReceiverGeneration(value: unknown, min: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min;
}

/**
 * grantMetaの受信reset世代（欠落は既存の0）。値はgrantGenerationOfでboundと判定した記録だけに使う。不正はnull。
 * 受信先の設定（購読）の利用だけに使い、利用許可の世代の判定（grantUseVerdict）は変えない。
 */
export function grantReceiverGenerationOf(value: unknown): number | null {
  const data = plainData(value);
  if (data === null) return null;
  try {
    if (!Object.hasOwn(data, 'receiverGeneration')) return 0;
    const generation = ownValue(data, 'receiverGeneration');
    return isReceiverGeneration(generation, 1) ? generation : null;
  } catch {
    return null;
  }
}
/** 接続保存の内部owner ID（randomUUIDの小文字UUID）。 */
const OWNER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type AccessState = 'active' | 'disabled';

export interface AccessRecord {
  readonly version: typeof ACCESS_RECORD_VERSION;
  readonly state: AccessState;
  readonly generation: string;
  readonly updatedAt: number;
}

/** 新規利用の可否。allowedだけが世代を持つ。 */
export type AccessVerdict =
  | { readonly kind: 'allowed'; readonly generation: string }
  | { readonly kind: 'denied' }
  | { readonly kind: 'unavailable' };

export const ACCESS_DENIED: AccessVerdict = Object.freeze({ kind: 'denied' });
export const ACCESS_UNAVAILABLE: AccessVerdict = Object.freeze({ kind: 'unavailable' });

/** 許可recordの形が不正（固定message。値・pathを持たない）。 */
export class AccessRecordError extends Error {
  override readonly name = 'AccessRecordError';
  constructor() {
    super('access record is invalid');
  }
}

export function isAccessGeneration(value: unknown): value is string {
  return typeof value === 'string' && GENERATION.test(value);
}

export function isIdentityHash(value: unknown): value is string {
  return typeof value === 'string' && IDENTITY_HASH.test(value);
}

function plainData(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  return value as Record<string, unknown>;
}

/** own data propertyの値だけを読む（accessor・symbolは不正）。 */
function ownValue(data: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(data, key);
  if (descriptor === undefined) return undefined;
  if (!('value' in descriptor)) throw new AccessRecordError();
  return descriptor.value;
}

/** 許可recordのexact schemaを検査して写す。余分・欠落・型違い・未知版は全てAccessRecordError。 */
export function parseAccessRecord(value: unknown): AccessRecord {
  const data = plainData(value);
  if (data === null) throw new AccessRecordError();
  const keys = Reflect.ownKeys(data);
  if (keys.length !== RECORD_KEYS.length || !keys.every((key) => typeof key === 'string' && (RECORD_KEYS as readonly string[]).includes(key))) {
    throw new AccessRecordError();
  }
  const version = ownValue(data, 'version');
  const state = ownValue(data, 'state');
  const generation = ownValue(data, 'generation');
  const updatedAt = ownValue(data, 'updatedAt');
  if (version !== ACCESS_RECORD_VERSION) throw new AccessRecordError();
  if (state !== 'active' && state !== 'disabled') throw new AccessRecordError();
  if (!isAccessGeneration(generation)) throw new AccessRecordError();
  if (typeof updatedAt !== 'number' || !Number.isSafeInteger(updatedAt) || updatedAt < 0) throw new AccessRecordError();
  return Object.freeze({ version: ACCESS_RECORD_VERSION, state, generation, updatedAt });
}

/** 許可recordの有無とdataから新規利用の可否を決める（不正は一時障害）。 */
export function accessVerdictOf(exists: boolean, data: unknown): AccessVerdict {
  if (!exists) return ACCESS_DENIED;
  let record: AccessRecord;
  try {
    record = parseAccessRecord(data);
  } catch {
    return ACCESS_UNAVAILABLE;
  }
  return record.state === 'active' ? Object.freeze({ kind: 'allowed' as const, generation: record.generation }) : ACCESS_DENIED;
}

/** owner文書のidentityHash（無い・形違いはnull）。 */
export function ownerIdentityHash(ownerData: unknown): string | null {
  const data = plainData(ownerData);
  if (data === null) return null;
  try {
    const value = ownValue(data, 'identityHash');
    return isIdentityHash(value) ? value : null;
  } catch {
    return null;
  }
}

/** grantMetaの世代の束縛。legacyは世代を持たない移行前Grant、invalidは形の不正。 */
export type GrantGeneration =
  | { readonly kind: 'bound'; readonly ownerId: string; readonly generation: string }
  | { readonly kind: 'missing' }
  | { readonly kind: 'legacy' }
  | { readonly kind: 'invalid' };

export function grantGenerationOf(exists: boolean, value: unknown): GrantGeneration {
  if (!exists) return { kind: 'missing' };
  const data = plainData(value);
  if (data === null) return { kind: 'invalid' };
  try {
    // exact key: 旧形式は{ownerId, authTimeSec, createdAt}、現行はそれにaccessGeneration（受信reset世代が1以上ならreceiverGenerationも）。余分・欠落は不正。
    const keys = Reflect.ownKeys(data);
    const legacy = !Object.hasOwn(data, 'accessGeneration');
    const expected: readonly string[] = legacy ? GRANT_META_LEGACY_KEYS : Object.hasOwn(data, 'receiverGeneration') ? GRANT_META_RECEIVER_KEYS : GRANT_META_KEYS;
    if (keys.length !== expected.length || !keys.every((key) => typeof key === 'string' && expected.includes(key))) return { kind: 'invalid' };
    const ownerId = ownValue(data, 'ownerId');
    const authTimeSec = ownValue(data, 'authTimeSec');
    const createdAt = ownValue(data, 'createdAt');
    // ownerは内部owner ID（小文字UUID）、認証時刻は正の安全な整数秒、作成時刻は正の安全な整数のepoch ms。
    if (typeof ownerId !== 'string' || !OWNER_ID.test(ownerId)) return { kind: 'invalid' };
    if (typeof authTimeSec !== 'number' || !Number.isSafeInteger(authTimeSec) || authTimeSec <= 0) return { kind: 'invalid' };
    if (typeof createdAt !== 'number' || !Number.isSafeInteger(createdAt) || createdAt <= 0) return { kind: 'invalid' };
    if (legacy) return { kind: 'legacy' };
    const generation = ownValue(data, 'accessGeneration');
    if (!isAccessGeneration(generation)) return { kind: 'invalid' };
    if (Object.hasOwn(data, 'receiverGeneration') && !isReceiverGeneration(ownValue(data, 'receiverGeneration'), 1)) return { kind: 'invalid' };
    return { kind: 'bound', ownerId, generation };
  } catch {
    return { kind: 'invalid' };
  }
}

/**
 * Grantを新規利用（code交換・refresh・購読・送信）に使えるか。許可がallowedで、grantMetaが同じownerと現在の世代へ束縛されている時だけallowed。
 * 許可・metadataの不正はunavailable、欠落・disabled・旧形式・旧世代・別ownerはdenied。
 */
export function grantUseVerdict(access: AccessVerdict, grant: GrantGeneration, ownerId: string): AccessVerdict {
  if (access.kind === 'unavailable' || grant.kind === 'invalid') return ACCESS_UNAVAILABLE;
  if (access.kind === 'denied') return ACCESS_DENIED;
  if (grant.kind !== 'bound' || grant.ownerId !== ownerId || grant.generation !== access.generation) return ACCESS_DENIED;
  return access;
}

/** 管理操作の目標状態への遷移。同じ状態・欠落の停止なら書込みなし（世代も変えない）。遷移・初回登録は新しい世代。 */
export function nextAccessRecord(current: AccessRecord | null, desired: AccessState, now: number, newGeneration: string): AccessRecord | null {
  if (!isAccessGeneration(newGeneration) || !Number.isSafeInteger(now) || now < 0) throw new AccessRecordError();
  // 欠落は既に利用不許可なので、停止で新しいrecordを作らない。
  if (current === null ? desired === 'disabled' : current.state === desired) return null;
  if (current !== null && current.generation === newGeneration) throw new AccessRecordError();
  return Object.freeze({ version: ACCESS_RECORD_VERSION, state: desired, generation: newGeneration, updatedAt: now });
}
