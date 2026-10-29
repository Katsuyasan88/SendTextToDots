// 許可元（source）の共通契約。正本はdocs/API.md「許可元の証明」・docs/CONFIGURATION.md「許可元の認可」。純粋（I/O・SDK・乱数・時計0）。
//   - 配置設定のsourceAuthorization: 省略/'compatible'は既存互換（source検査なし）。strictは{mode:'strict-v1', methods}を管理者が明示する。
//     空・未知・重複の方式は設定error（互換へ降格しない）。
//   - 登録record（sttdConnect/{connectNamespace}/sources/{sourceId}）のexact schemaと判定。source IDは不変で、削除は墓標を残し再利用しない。
//   - Grant/承認へ結ぶbinding（sourceId＋世代）。停止後の再有効化は新しい世代で、旧bindingは復活しない。
// 本文・token・生証明・秘密鍵はrecordへ入れない。開発者のUIDは接続保存の既存identity用HMAC（identityHash）だけを持つ。

export const SOURCE_STRICT_MODE = 'strict-v1';
export const SOURCE_METHODS = ['developer-key-v1', 'app-check-v1'] as const;
export type SourceMethod = (typeof SOURCE_METHODS)[number];
/** 許可操作: send=平文/暗号文の送信、keys=公開鍵の取得/再発行、connect=接続承認。 */
export const SOURCE_OPERATIONS = ['send', 'keys', 'connect'] as const;
export type SourceOperation = (typeof SOURCE_OPERATIONS)[number];

export const SOURCES_COLLECTION = 'sources';
export const SOURCE_REPLAY_COLLECTION = 'sourceReplay';
export const SOURCE_APPROVALS_COLLECTION = 'sourceApprovals';

/** `src_`＋base32小文字26文字（130bit）。 */
export const SOURCE_ID = /^src_[a-z2-7]{26}$/;
/** 失効世代（base64url 22文字＝128bit）。 */
export const SOURCE_GENERATION = /^[A-Za-z0-9_-]{22}$/;
/** Firebase App ID（`1:<projectNumber>:<ios|android|web>:<hex>`）。 */
export const FIREBASE_APP_ID = /^1:([1-9][0-9]{5,19}):(?:ios|android|web):[0-9a-f]{1,64}$/;
/** Ed25519公開鍵（raw 32byteのbase64url、43文字）。 */
export const ED25519_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/;
const IDENTITY_HASH = /^[0-9a-f]{64}$/;
const MAX_TIME_MS = 8_640_000_000_000_000;

/** 開発者要求署名の最大有効期間（発行から期限まで）。 */
export const SIGNATURE_MAX_LIFETIME_SEC = 60;
/** 開発者要求署名の時計許容。 */
export const SIGNATURE_CLOCK_SKEW_SEC = 30;
/** 接続承認の最大有効期間（元interactionの期限以内で、さらにこの上限）。 */
export const APPROVAL_MAX_MS = 5 * 60_000;
/** 消費済み承認・replay記録の掃除候補（deleteAfter）。論理期限の判定にはTTLを使わない。 */
export const SOURCE_RECORD_CLEANUP_MS = 24 * 60 * 60_000;

export type SourceAuthorizationConfig = 'compatible' | StrictSourcePolicy;

export interface StrictSourcePolicy {
  readonly mode: typeof SOURCE_STRICT_MODE;
  /** 管理者が選んだ方式（1〜2件・重複なし）。 */
  readonly methods: readonly SourceMethod[];
}

/** 契約・recordの不正（固定message。値・pathを持たない）。 */
export class SourceContractError extends Error {
  override readonly name = 'SourceContractError';
  constructor() {
    super('source contract invalid');
  }
}

function fail(): never {
  throw new SourceContractError();
}

/** namesちょうど（optionalは任意）のown data propertyだけを持つplain objectの写し。 */
function exactFields(value: unknown, required: readonly string[], optional: readonly string[] = []): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const fields = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || (!required.includes(key) && !optional.includes(key))) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    fields.set(key, descriptor.value);
  }
  for (const key of required) if (!fields.has(key)) fail();
  return fields;
}

function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME_MS;
}

/** 重複なしの既知値だけの配列（1件以上）。 */
function knownList<T extends string>(value: unknown, known: readonly T[]): T[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > known.length) fail();
  const items: T[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    const item: unknown = descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
    if (typeof item !== 'string' || !(known as readonly string[]).includes(item) || items.includes(item as T)) fail();
    items.push(item as T);
  }
  return items;
}

/** 配置設定のsourceAuthorization（欠落は呼出し側で'compatible'）。不正はSourceContractError。 */
export function parseSourceAuthorization(value: unknown): SourceAuthorizationConfig {
  if (value === 'compatible') return 'compatible';
  const fields = exactFields(value, ['mode', 'methods']);
  if (fields.get('mode') !== SOURCE_STRICT_MODE) fail();
  return Object.freeze({ mode: SOURCE_STRICT_MODE, methods: Object.freeze(knownList(fields.get('methods'), SOURCE_METHODS)) });
}

/** App IDのproject number（形が違えばnull）。 */
export function appIdProjectNumber(appId: unknown): string | null {
  if (typeof appId !== 'string') return null;
  const match = FIREBASE_APP_ID.exec(appId);
  return match === null ? null : (match[1] ?? null);
}

interface SourceRecordBase {
  readonly schemaVersion: 1;
  readonly sourceId: string;
  readonly state: 'active' | 'disabled';
  readonly generation: string;
  readonly operations: readonly SourceOperation[];
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface AppSourceRecord extends SourceRecordBase {
  readonly kind: 'app';
  /** 同じ配置projectのFirebase App ID。 */
  readonly appId: string;
}

export interface DeveloperSourceRecord extends SourceRecordBase {
  readonly kind: 'developer';
  readonly publicKey: string;
  /** 許可する本人（接続保存のidentity用HMAC）。 */
  readonly identityHash: string;
  /** 管理者が明示した期限。nullは管理者が明示した無期限。 */
  readonly expiresAt: number | null;
}

/** 管理者削除の墓標（IDの再利用を防ぎ、旧bindingを拒否し続ける）。 */
export interface DeletedSourceRecord {
  readonly schemaVersion: 1;
  readonly sourceId: string;
  readonly kind: 'deleted';
  readonly deletedAt: number;
}

export type SourceRecord = AppSourceRecord | DeveloperSourceRecord | DeletedSourceRecord;

const BASE_KEYS = ['schemaVersion', 'sourceId', 'kind', 'state', 'generation', 'operations', 'createdAt', 'updatedAt'] as const;

/** 保存dataのexact schema（文書IDと一致）。不正はSourceContractError（自動修復しない）。 */
export function parseSourceRecord(data: unknown, expectedId: string): SourceRecord {
  if (!SOURCE_ID.test(expectedId)) fail();
  const kind = typeof data === 'object' && data !== null ? (data as { kind?: unknown }).kind : undefined;
  if (kind === 'deleted') {
    const fields = exactFields(data, ['schemaVersion', 'sourceId', 'kind', 'deletedAt']);
    if (fields.get('schemaVersion') !== 1 || fields.get('sourceId') !== expectedId || !isTime(fields.get('deletedAt'))) fail();
    return Object.freeze({ schemaVersion: 1, sourceId: expectedId, kind: 'deleted', deletedAt: fields.get('deletedAt') as number });
  }
  const extra = kind === 'app' ? ['appId'] : kind === 'developer' ? ['publicKey', 'identityHash', 'expiresAt'] : fail();
  const fields = exactFields(data, [...BASE_KEYS, ...extra]);
  const state = fields.get('state');
  const generation = fields.get('generation');
  const createdAt = fields.get('createdAt');
  const updatedAt = fields.get('updatedAt');
  if (fields.get('schemaVersion') !== 1 || fields.get('sourceId') !== expectedId) fail();
  if ((state !== 'active' && state !== 'disabled') || typeof generation !== 'string' || !SOURCE_GENERATION.test(generation)) fail();
  if (!isTime(createdAt) || !isTime(updatedAt) || updatedAt < createdAt) fail();
  const operations = Object.freeze(knownList(fields.get('operations'), SOURCE_OPERATIONS));
  const base = { schemaVersion: 1 as const, sourceId: expectedId, state: state as 'active' | 'disabled', generation, operations, createdAt, updatedAt };
  if (kind === 'app') {
    const appId = fields.get('appId');
    if (appIdProjectNumber(appId) === null) fail();
    return Object.freeze({ ...base, kind: 'app', appId: appId as string });
  }
  const publicKey = fields.get('publicKey');
  const identityHash = fields.get('identityHash');
  const expiresAt = fields.get('expiresAt');
  if (typeof publicKey !== 'string' || !ED25519_PUBLIC_KEY.test(publicKey)) fail();
  if (typeof identityHash !== 'string' || !IDENTITY_HASH.test(identityHash)) fail();
  if (expiresAt !== null && (!isTime(expiresAt) || expiresAt <= createdAt)) fail();
  return Object.freeze({ ...base, kind: 'developer', publicKey, identityHash, expiresAt: expiresAt as number | null });
}

/** Grant・承認へ結ぶsourceの参照。 */
export interface SourceBinding {
  readonly sourceId: string;
  readonly generation: string;
}

export function isSourceBinding(value: unknown): value is SourceBinding {
  if (typeof value !== 'object' || value === null) return false;
  const { sourceId, generation } = value as { sourceId?: unknown; generation?: unknown };
  return typeof sourceId === 'string' && SOURCE_ID.test(sourceId) && typeof generation === 'string' && SOURCE_GENERATION.test(generation);
}

export type SourceRejection = 'missing' | 'deleted' | 'disabled' | 'expired' | 'operation' | 'subject' | 'method' | 'generation';

export type SourceVerdict = { readonly kind: 'usable'; readonly record: AppSourceRecord | DeveloperSourceRecord } | { readonly kind: 'rejected'; readonly reason: SourceRejection };

const rejected = (reason: SourceRejection): SourceVerdict => ({ kind: 'rejected', reason });

/** sourceのいまの状態（不存在・墓標・停止・期限・操作外を区別して拒否）。 */
function liveSource(record: SourceRecord | null, operation: SourceOperation, now: number): SourceVerdict {
  if (record === null) return rejected('missing');
  if (record.kind === 'deleted') return rejected('deleted');
  if (record.state !== 'active') return rejected('disabled');
  if (record.kind === 'developer' && record.expiresAt !== null && !(now < record.expiresAt)) return rejected('expired');
  if (!record.operations.includes(operation)) return rejected('operation');
  return { kind: 'usable', record };
}

/**
 * 要求1件の判定。方式とsource種別の一致（開発者鍵はdeveloper、App Checkはapp）、開発者は本人のidentityHashの一致も必要。
 * 署名の検証・App Checkのconsumeは呼出し側（このrecordの公開鍵/App IDで）。
 */
export function sourceRequestVerdict(
  record: SourceRecord | null,
  need: { readonly method: SourceMethod; readonly operation: SourceOperation; readonly identityHash: string; readonly now: number },
): SourceVerdict {
  const verdict = liveSource(record, need.operation, need.now);
  if (verdict.kind !== 'usable') return verdict;
  const expected = need.method === 'developer-key-v1' ? 'developer' : 'app';
  if (verdict.record.kind !== expected) return rejected('method');
  if (verdict.record.kind === 'developer' && verdict.record.identityHash !== need.identityHash) return rejected('subject');
  return verdict;
}

/** Grantに結んだbindingの継続判定（code交換・refresh・MCP・購読保存・配送確定）。世代違いは旧Grantとして拒否。 */
export function sourceBindingVerdict(record: SourceRecord | null, binding: SourceBinding, now: number): SourceVerdict {
  const verdict = liveSource(record, 'connect', now);
  if (verdict.kind !== 'usable') return verdict;
  if (verdict.record.generation !== binding.generation) return rejected('generation');
  return verdict;
}
