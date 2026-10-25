// KMS購読の保存形式（version2・sttdkms1 capsule・旧secretHashつきの猶予）とconfig marker、その同期検査。版1・未知の版は破損として
// 拒否する。ここは形だけを見る純粋な関数の集まりで、暗号化・開封・通信・乱数・時計・ログを使わない（capsuleの真正性/CRCは開封時に
// codecが確かめる。形の合格を認証済みとしない）。codec（protection/kms-sealing.ts）のparserと同じ正規形の規則を同期に再実装する。

import { Buffer } from 'node:buffer';
import { types } from 'node:util';

import { KMS_CAPSULE_PREFIX, KMS_LIMITS, KMS_REGION_PATTERN, type KmsSealingEnvironment } from '../../protection/kms-sealing.js';
import { isHash, isTime, isUuid, requireThat } from './checks.js';

/** config marker文書のid（sttdAuth/{namespace}/config/kms-subscription）。 */
export const KMS_SUBSCRIPTION_CONFIG_DOC = 'kms-subscription';
/** KMS購読の保存root（sttdAuth/{t268 namespace}）。 */
export const AUTH_STORAGE_ROOT = 'sttdAuth';
/** owner文書とconfig markerの形式の版。他の版は破損として拒否する。 */
export const KMS_SUBSCRIPTION_FORMAT_VERSION = 2;
export const KMS_SUBSCRIPTION_FORMAT = 'sttdkms1';
/** 旧secretの猶予の上限（既存の5分）。引数nowからこれより先の猶予は受け付けない。 */
export const KMS_SUBSCRIPTION_PREVIOUS_GRACE_MS = 300_000;
/** 内部の容量・破損の防御。公開APIの容量ではない。 */
export const MAX_KMS_GRANT_ID_BYTES = 256;
export const MAX_KMS_SUBSCRIPTION_CAPSULE_BYTES = KMS_LIMITS.capsuleBytes;
export const MAX_KMS_SUBSCRIPTION_DOCUMENT_BYTES = 900 * 1024;

const NAMESPACE_PATTERN = /^t268_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SUBSCRIPTION_ID_PATTERN = /^sub_[0-9a-f]{64}$/;
const SAFE_ASCII = /^[A-Za-z0-9_.:-]{1,256}$/;
const RESOURCE_ID = /^[A-Za-z0-9_-]{1,63}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ENVIRONMENTS: ReadonlySet<string> = new Set(['development', 'production', 'local-test']);

export const KMS_MARKER_KEYS = [
  'version',
  'format',
  'namespace',
  'environment',
  'projectId',
  'databaseId',
  'cryptoKey',
  'writeVersion',
  'readVersions',
] as const;
const DOC_KEYS = ['version', 'ownerId', 'active', 'knownDestinationId', 'pending', 'lastEnded'] as const;
const ACTIVE_KEYS = [
  'id',
  'ownerId',
  'grantId',
  'sealedUrl',
  'sealedSecret',
  'secretHash',
  'previousSecret',
  'expiresAt',
] as const;
const PREVIOUS_KEYS = ['sealed', 'secretHash', 'until'] as const;
const PENDING_KEYS = ['id', 'grantId', 'requestedAt'] as const;
const ENDED: readonly string[] = ['expired', 'cancelled', 'grant_ended'];

/** 旧secret。5分以内の猶予の間だけ、そのhashと一組で持つ。 */
export interface KmsPreviousSecret {
  readonly sealed: string;
  readonly secretHash: string;
  readonly until: number;
}

/** 有効な購読。callback URLとsecretはsttdkms1 capsuleだけを持ち、平文は渡さない。期限のnullは無期限。 */
export interface KmsSubscriptionRecord {
  readonly id: string;
  readonly ownerId: string;
  grantId: string;
  readonly sealedUrl: string;
  sealedSecret: string;
  secretHash: string;
  previousSecret: KmsPreviousSecret | null;
  expiresAt: number | null;
}

export interface KmsSubscriptionPending {
  readonly id: string;
  readonly grantId: string;
  readonly requestedAt: number;
}

export type KmsSubscriptionEnded = 'expired' | 'cancelled' | 'grant_ended' | null;

/** config markerと同じ値。factoryの作成時に検査・正規化（readVersionsは昇順）して捕捉する。 */
export interface KmsSubscriptionPolicy {
  readonly version: typeof KMS_SUBSCRIPTION_FORMAT_VERSION;
  readonly format: typeof KMS_SUBSCRIPTION_FORMAT;
  readonly namespace: string;
  readonly environment: KmsSealingEnvironment;
  readonly projectId: string;
  readonly databaseId: string;
  readonly cryptoKey: string;
  readonly writeVersion: number;
  readonly readVersions: readonly number[];
}

/** KMS購読の保存だけが使うnamespace（t268）。接続（t256）・配送（t270）とは互いに受け付けない。 */
export function isKmsSubscriptionNamespace(value: unknown): value is string {
  return typeof value === 'string' && NAMESPACE_PATTERN.test(value);
}

export function isKmsSubscriptionId(value: unknown): value is string {
  return typeof value === 'string' && SUBSCRIPTION_ID_PATTERN.test(value);
}

/** 空でなく、制御文字を含まない、256バイト以下の正しいUTF-8。 */
export function isKmsGrantId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_KMS_GRANT_ID_BYTES) return false;
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > MAX_KMS_GRANT_ID_BYTES || bytes.toString('utf8') !== value) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return false;
  }
  return true;
}

/**
 * 決まった名前のdata propertyだけを持つplain objectなら、値を1回だけ読んだ写しを返す。symbol・未知/欠落の名前・accessor・
 * Proxy・配列・class instanceは拒否する（getterは呼ばない）。拒否はstore_error。
 */
export function exactData(value: unknown, keys: readonly string[]): Record<string, unknown> {
  requireThat(typeof value === 'object' && value !== null && !types.isProxy(value) && !Array.isArray(value));
  const prototype: unknown = Object.getPrototypeOf(value);
  requireThat(prototype === Object.prototype || prototype === null);
  const own = Reflect.ownKeys(value);
  requireThat(own.length === keys.length);
  const taken = Object.create(null) as Record<string, unknown>;
  for (const key of own) {
    requireThat(typeof key === 'string' && keys.includes(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    requireThat(descriptor !== undefined && 'value' in descriptor);
    taken[key as string] = descriptor.value;
  }
  return taken;
}

/** 本物の配列（Proxy・accessor・余分なpropertyなし）の要素を1回だけ読む。 */
function arrayItems(value: unknown): unknown[] {
  requireThat(Array.isArray(value) && !types.isProxy(value) && Object.getPrototypeOf(value) === Array.prototype);
  const length = (value as unknown[]).length;
  requireThat(Reflect.ownKeys(value).length === length + 1);
  const items: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    requireThat(descriptor !== undefined && 'value' in descriptor);
    items.push(descriptor.value);
  }
  return items;
}

/** "." / ".." だけの値は安全文字でも拒否する（codecと同じ）。 */
function isSafeAscii(value: unknown): value is string {
  return typeof value === 'string' && SAFE_ASCII.test(value) && !/^\.+$/.test(value);
}

function isVersionNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** 制御文字・空白・非ASCII・query・fragment・".."を含む名前を拒否する（codecと同じ規則）。 */
function isAsciiResource(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= KMS_LIMITS.resourceNameBytes &&
    /^[\x21-\x7e]+$/.test(value) &&
    !/[?#%\\]/.test(value) &&
    !value.includes('..')
  );
}

function isCryptoKey(value: unknown, projectId: string): value is string {
  if (typeof value !== 'string' || !isAsciiResource(value)) return false;
  const parts = value.split('/');
  if (parts.length !== 8) return false;
  const [p, project, l, location, r, ring, c, key] = parts as [string, string, string, string, string, string, string, string];
  return (
    p === 'projects' &&
    project === projectId &&
    l === 'locations' &&
    KMS_REGION_PATTERN.test(location) &&
    r === 'keyRings' &&
    RESOURCE_ID.test(ring) &&
    c === 'cryptoKeys' &&
    RESOURCE_ID.test(key)
  );
}

export function kmsVersionName(cryptoKey: string, version: number): string {
  return `${cryptoKey}/cryptoKeyVersions/${version}`;
}

/**
 * markerの非秘密policyを検査して凍結した写しを返す。KMS codecと同じ安全ASCII・同project/単一regionのCryptoKey・正のsafe integerの
 * version・writeを含む重複なし1〜8件のreadVersions（昇順へ正規化）。transport・鍵・URL・秘密・hash・ownerは持たない。
 */
export function createKmsSubscriptionPolicy(input: {
  readonly namespace: unknown;
  readonly environment: unknown;
  readonly projectId: unknown;
  readonly databaseId: unknown;
  readonly cryptoKey: unknown;
  readonly writeVersion: unknown;
  readonly readVersions: unknown;
}): KmsSubscriptionPolicy {
  const { namespace, environment, projectId, databaseId, cryptoKey, writeVersion } = input;
  requireThat(isKmsSubscriptionNamespace(namespace));
  requireThat(typeof environment === 'string' && ENVIRONMENTS.has(environment));
  requireThat(isSafeAscii(projectId));
  requireThat(databaseId === '(default)' || isSafeAscii(databaseId));
  requireThat(isCryptoKey(cryptoKey, projectId));
  requireThat(isVersionNumber(writeVersion));
  const versions = arrayItems(input.readVersions);
  requireThat(versions.length >= 1 && versions.length <= KMS_LIMITS.readVersions);
  requireThat(versions.every(isVersionNumber) && new Set(versions).size === versions.length);
  requireThat(versions.includes(writeVersion));
  const readVersions = (versions as number[]).slice().sort((a, b) => a - b);
  requireThat(readVersions.every((version) => kmsVersionName(cryptoKey, version).length <= KMS_LIMITS.resourceNameBytes));
  return Object.freeze({
    version: KMS_SUBSCRIPTION_FORMAT_VERSION,
    format: KMS_SUBSCRIPTION_FORMAT,
    namespace,
    environment: environment as KmsSealingEnvironment,
    projectId,
    databaseId: databaseId as string,
    cryptoKey,
    writeVersion,
    readVersions: Object.freeze(readVersions),
  });
}

/** 保存するmarkerの文書（policyの写し。配列は新しい配列）。 */
export function kmsMarkerDocument(policy: KmsSubscriptionPolicy): Record<string, unknown> {
  return {
    version: policy.version,
    format: policy.format,
    namespace: policy.namespace,
    environment: policy.environment,
    projectId: policy.projectId,
    databaseId: policy.databaseId,
    cryptoKey: policy.cryptoKey,
    writeVersion: policy.writeVersion,
    readVersions: [...policy.readVersions],
  };
}

/** 読んだmarkerの値が、捕捉したpolicyと全て一致するか。余分field・getter・未知の版・別policyは不一致（store_error）。 */
export function requireKmsMarker(data: unknown, policy: KmsSubscriptionPolicy): void {
  const marker = exactData(data, KMS_MARKER_KEYS);
  requireThat(marker.version === policy.version && marker.format === policy.format);
  requireThat(marker.namespace === policy.namespace && marker.environment === policy.environment);
  requireThat(marker.projectId === policy.projectId && marker.databaseId === policy.databaseId);
  requireThat(marker.cryptoKey === policy.cryptoKey && marker.writeVersion === policy.writeVersion);
  const versions = arrayItems(marker.readVersions);
  requireThat(versions.length === policy.readVersions.length);
  requireThat(versions.every((version, index) => version === policy.readVersions[index]));
}

/**
 * KMS codecと同じsttdkms1 capsuleの正規形か（通信しない形の検査）。prefix・正規base64url・fatal UTF-8・ちょうど2文字列のJSON配列で
 * 再serializeが一致、keyVersionはpolicyの同keyの許可version名、raw ciphertextは正規base64urlで1〜131072byte。
 * 全体は262144 ASCII byte以下。暗号の真正性・CRCは見ない。
 */
export function isKmsCapsule(value: unknown, policy: KmsSubscriptionPolicy): value is string {
  if (typeof value !== 'string' || value.length > MAX_KMS_SUBSCRIPTION_CAPSULE_BYTES || !value.startsWith(KMS_CAPSULE_PREFIX)) {
    return false;
  }
  const encoded = value.slice(KMS_CAPSULE_PREFIX.length);
  if (!BASE64URL.test(encoded)) return false;
  const raw = Buffer.from(encoded, 'base64url');
  if (raw.toString('base64url') !== encoded) return false;
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  if (!Array.isArray(parsed) || parsed.length !== 2) return false;
  const [keyVersion, ciphertextText] = parsed as unknown[];
  if (typeof keyVersion !== 'string' || typeof ciphertextText !== 'string') return false;
  if (JSON.stringify([keyVersion, ciphertextText]) !== text) return false;
  if (!policy.readVersions.some((version) => kmsVersionName(policy.cryptoKey, version) === keyVersion)) return false;
  if (!BASE64URL.test(ciphertextText)) return false;
  const ciphertext = Buffer.from(ciphertextText, 'base64url');
  return (
    ciphertext.length >= 1 &&
    ciphertext.length <= KMS_LIMITS.ciphertextBytes &&
    ciphertext.toString('base64url') === ciphertextText
  );
}

function isEnded(value: unknown): value is KmsSubscriptionEnded {
  return value === null || (typeof value === 'string' && ENDED.includes(value));
}

/** 旧secret。nullか、exactな{sealed, secretHash, until}で、hashはcurrentと異なる。 */
function copyPrevious(value: unknown, currentHash: string, policy: KmsSubscriptionPolicy): KmsPreviousSecret | null {
  if (value === null) return null;
  const { sealed, secretHash, until } = exactData(value, PREVIOUS_KEYS);
  requireThat(isKmsCapsule(sealed, policy) && isHash(secretHash) && secretHash !== currentHash && isTime(until));
  return { sealed, secretHash, until };
}

/** 検査した上で、渡されたobjectと共有しない写しを作る（文書・activateの引数の両方）。 */
export function copyKmsRecord(value: unknown, ownerId: string, policy: KmsSubscriptionPolicy): KmsSubscriptionRecord {
  const fields = exactData(value, ACTIVE_KEYS);
  const { id, grantId, sealedUrl, sealedSecret, secretHash, expiresAt } = fields;
  requireThat(fields.ownerId === ownerId && isKmsSubscriptionId(id) && isKmsGrantId(grantId));
  requireThat(isKmsCapsule(sealedUrl, policy) && isKmsCapsule(sealedSecret, policy));
  requireThat(isHash(secretHash) && (isTime(expiresAt) || expiresAt === null));
  const previousSecret = copyPrevious(fields.previousSecret, secretHash, policy);
  return { id, ownerId, grantId, sealedUrl, sealedSecret, secretHash, previousSecret, expiresAt };
}

function copyPending(value: unknown): KmsSubscriptionPending {
  const { id, grantId, requestedAt } = exactData(value, PENDING_KEYS);
  requireThat(isKmsSubscriptionId(id) && isKmsGrantId(grantId) && isTime(requestedAt));
  return { id, grantId, requestedAt };
}

export interface KmsMutableState {
  active: KmsSubscriptionRecord | null;
  knownDestinationId: string | null;
  pending: KmsSubscriptionPending | null;
  lastEnded: KmsSubscriptionEnded;
}

export const emptyKmsState = (): KmsMutableState => ({ active: null, knownDestinationId: null, pending: null, lastEnded: null });

export function kmsStateDocument(ownerId: string, state: KmsMutableState): Record<string, unknown> {
  const { active, pending } = state;
  return {
    version: KMS_SUBSCRIPTION_FORMAT_VERSION,
    ownerId,
    active: active && {
      id: active.id,
      ownerId: active.ownerId,
      grantId: active.grantId,
      sealedUrl: active.sealedUrl,
      sealedSecret: active.sealedSecret,
      secretHash: active.secretHash,
      previousSecret: active.previousSecret && {
        sealed: active.previousSecret.sealed,
        secretHash: active.previousSecret.secretHash,
        until: active.previousSecret.until,
      },
      expiresAt: active.expiresAt,
    },
    knownDestinationId: state.knownDestinationId,
    pending: pending && { id: pending.id, grantId: pending.grantId, requestedAt: pending.requestedAt },
    lastEnded: state.lastEnded,
  };
}

/** 文書のUTF-8 JSONが900KiB以下（SendTextToDots内部の防御）。読取り・書込みの両方で見る。 */
export function requireKmsDocumentSize(ownerId: string, state: KmsMutableState): void {
  const bytes = Buffer.byteLength(JSON.stringify(kmsStateDocument(ownerId, state)), 'utf8');
  requireThat(bytes <= MAX_KMS_SUBSCRIPTION_DOCUMENT_BYTES);
}

/** 文書のdata（snapshot.data()）を検査する。形・束縛・版・capsuleが違えば破損として拒否する（空・別ownerとして扱わない）。 */
export function parseKmsState(data: unknown, ownerId: string, policy: KmsSubscriptionPolicy): KmsMutableState {
  requireThat(isUuid(ownerId));
  const fields = exactData(data, DOC_KEYS);
  const { knownDestinationId, lastEnded } = fields;
  requireThat(fields.version === KMS_SUBSCRIPTION_FORMAT_VERSION && fields.ownerId === ownerId);
  requireThat(knownDestinationId === null || isKmsSubscriptionId(knownDestinationId));
  requireThat(isEnded(lastEnded));
  const active = fields.active === null ? null : copyKmsRecord(fields.active, ownerId, policy);
  const pending = fields.pending === null ? null : copyPending(fields.pending);
  // 有効な購読は既知の送信先そのもので、保留は既知の送信先とは別の送信先。
  requireThat(active === null || active.id === knownDestinationId);
  requireThat(pending === null || (knownDestinationId !== null && pending.id !== knownDestinationId));
  const state = { active, knownDestinationId, pending, lastEnded };
  requireKmsDocumentSize(ownerId, state);
  return state;
}

/**
 * nowで期限に達した購読（封緘値と旧secret・旧hashを含む）と、猶予を過ぎた旧secret（sealedとhashの組）を外す。変えたらtrue。
 * 既知の送信先・保留は変えない。awaitしない。
 */
export function sweepKmsState(state: KmsMutableState, now: number): boolean {
  const { active } = state;
  if (!active) return false;
  if (active.expiresAt !== null && now >= active.expiresAt) {
    state.active = null;
    state.lastEnded = 'expired';
    return true;
  }
  if (active.previousSecret && now >= active.previousSecret.until) {
    active.previousSecret = null;
    return true;
  }
  return false;
}
