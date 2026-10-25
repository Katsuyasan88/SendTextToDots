// KMS購読の登録保存口（kms-subscription-registration-store.ts）が使う、awaitの無い純粋な規則。
// 固定error・入力の写し・文書の精密な版（exists・updateTimeの秒/ナノ秒）・owner文書の取消世代（subscriptionGeneration）・
// 既存version2状態への投影（期限の掃除・失効Grantの取下げ・保留/延長/有効化/取消）だけを持つ。暗号・開封・通信・乱数・時計・ログを使わない。
// 保存形式はversion2（kms-subscription-format.ts）をそのまま使い、新しい永続fieldを足さない（owner文書の世代を除く）。

import { types } from 'node:util';

import { isHash, isUuid } from './checks.js';
import {
  isKmsCapsule,
  isKmsGrantId,
  isKmsSubscriptionId,
  KMS_SUBSCRIPTION_PREVIOUS_GRACE_MS,
  sweepKmsState,
  type KmsMutableState,
  type KmsSubscriptionPolicy,
  type KmsSubscriptionRecord,
} from './kms-subscription-format.js';

/** 外へ出すのはこの6分類だけ。元の例外・cause・URL・secret・payload・owner・Grant・capsule・planを持たない。 */
export type KmsSubscriptionRegistrationErrorCode =
  | 'invalid_input'
  | 'unavailable'
  | 'timed_out'
  | 'aborted'
  | 'grant_inactive'
  | 'conflict';

const ERROR_MESSAGES: Readonly<Record<KmsSubscriptionRegistrationErrorCode, string>> = {
  invalid_input: 'kms subscription registration: invalid input',
  unavailable: 'kms subscription registration: unavailable',
  timed_out: 'kms subscription registration: timed out',
  aborted: 'kms subscription registration: aborted',
  grant_inactive: 'kms subscription registration: grant inactive',
  conflict: 'kms subscription registration: conflict',
};

export class KmsSubscriptionRegistrationError extends Error {
  override readonly name = 'KmsSubscriptionRegistrationError';
  readonly code: KmsSubscriptionRegistrationErrorCode;

  constructor(code: KmsSubscriptionRegistrationErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

export function registrationError(code: KmsSubscriptionRegistrationErrorCode): KmsSubscriptionRegistrationError {
  return new KmsSubscriptionRegistrationError(code);
}

/** 登録の期限（ms）。nullは無期限。公開入力の丸めは後のserviceの責務で、ここは範囲外を拒否する。 */
export const MAX_REGISTRATION_TTL_MS = 86_400_000;
/** owner文書の取消世代のfield。非秘密の競合制御metadataで、認可済みの取消だけが最新値+1へ進める。 */
export const SUBSCRIPTION_GENERATION_FIELD = 'subscriptionGeneration';

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知/欠落の名前を拒否、getterを呼ばない）。 */
export function exactFields(value: unknown, keys: readonly string[]): Map<string, unknown> {
  const invalid = () => registrationError('invalid_input');
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) throw invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length) throw invalid();
  const taken = new Map<string, unknown>();
  for (const key of own) {
    if (typeof key !== 'string' || !keys.includes(key)) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    taken.set(key, descriptor.value);
  }
  return taken;
}

export interface RegistrationAuth {
  readonly ownerId: string;
  readonly grantId: string;
}

export interface RegistrationRequest {
  readonly id: string;
  readonly secretHash: string;
  readonly ttlMs: number | null;
}

export interface RegistrationCapsules {
  readonly sealedUrl: string;
  readonly sealedSecret: string;
}

export function copyAuth(value: unknown): RegistrationAuth {
  const fields = exactFields(value, ['ownerId', 'grantId']);
  const ownerId = fields.get('ownerId');
  const grantId = fields.get('grantId');
  if (!isUuid(ownerId) || !isKmsGrantId(grantId)) throw registrationError('invalid_input');
  return Object.freeze({ ownerId, grantId });
}

function isTtl(value: unknown): value is number | null {
  return value === null || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= MAX_REGISTRATION_TTL_MS);
}

export function copyRequest(value: unknown): RegistrationRequest {
  const fields = exactFields(value, ['id', 'secretHash', 'ttlMs']);
  const id = fields.get('id');
  const secretHash = fields.get('secretHash');
  const ttlMs = fields.get('ttlMs');
  if (!isKmsSubscriptionId(id) || !isHash(secretHash) || !isTtl(ttlMs)) throw registrationError('invalid_input');
  return Object.freeze({ id, secretHash, ttlMs });
}

export function copyCancel(value: unknown): { readonly id: string } {
  const fields = exactFields(value, ['id']);
  const id = fields.get('id');
  if (!isKmsSubscriptionId(id)) throw registrationError('invalid_input');
  return Object.freeze({ id });
}

/** activateの封緘値。同じt268 policyの既存sttdkms1正規形・許可versionだけ（開封・codec呼出し0）。 */
export function copyCapsules(value: unknown, policy: KmsSubscriptionPolicy): RegistrationCapsules {
  const fields = exactFields(value, ['sealedUrl', 'sealedSecret']);
  const sealedUrl = fields.get('sealedUrl');
  const sealedSecret = fields.get('sealedSecret');
  if (!isKmsCapsule(sealedUrl, policy) || !isKmsCapsule(sealedSecret, policy)) throw registrationError('invalid_input');
  return Object.freeze({ sealedUrl, sealedSecret });
}

/** 文書の精密な版。existsとupdateTimeの秒/ナノ秒をそのまま持つ（toMillis・Dateへの丸め0、新しい永続revision0）。 */
export type DocVersion =
  | { readonly exists: false }
  | { readonly exists: true; readonly seconds: number; readonly nanoseconds: number };

/** 信頼済みのSDK snapshotから版を同期に捕捉する。形が違えば固定unavailable（推測で版を作らない）。 */
export function versionOf(snapshot: { readonly exists: unknown; readonly updateTime?: unknown }): DocVersion {
  const exists = snapshot.exists;
  if (exists === false) return Object.freeze({ exists: false });
  if (exists !== true) throw registrationError('unavailable');
  const updateTime = snapshot.updateTime as { readonly seconds?: unknown; readonly nanoseconds?: unknown } | undefined;
  if (typeof updateTime !== 'object' || updateTime === null) throw registrationError('unavailable');
  const { seconds, nanoseconds } = updateTime;
  if (typeof seconds !== 'number' || !Number.isSafeInteger(seconds)) throw registrationError('unavailable');
  if (typeof nanoseconds !== 'number' || !Number.isSafeInteger(nanoseconds) || nanoseconds < 0 || nanoseconds >= 1_000_000_000) {
    throw registrationError('unavailable');
  }
  return Object.freeze({ exists: true, seconds, nanoseconds });
}

export function sameDocVersion(a: DocVersion, b: DocVersion): boolean {
  if (!a.exists || !b.exists) return a.exists === b.exists;
  return a.seconds === b.seconds && a.nanoseconds === b.nanoseconds;
}

/**
 * owner文書のdataから取消世代を読む。fieldの欠落は0。null・負・小数・非有限・safe integerでない値・型の不正は固定unavailable
 * （破損を0へ読み替えない）。他のowner fieldは読まない。
 */
export function ownerGeneration(data: unknown): number {
  if (typeof data !== 'object' || data === null) throw registrationError('unavailable');
  const descriptor = Object.getOwnPropertyDescriptor(data, SUBSCRIPTION_GENERATION_FIELD);
  if (descriptor === undefined) return 0;
  if (!('value' in descriptor)) throw registrationError('unavailable');
  const value: unknown = descriptor.value;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw registrationError('unavailable');
  return value;
}

/** 取消の次の世代（最新値+1）。MAX_SAFE_INTEGERからはwrap・再利用せず固定unavailable。 */
export function nextGeneration(current: number): number {
  if (!(current < Number.MAX_SAFE_INTEGER)) throw registrationError('unavailable');
  return current + 1;
}

/** 束縛Grantの判定（同じsnapshotの証拠の照合結果。staleは呼出し元がconflictにする）。 */
export type BindingVerdict = 'active' | 'inactive';

/**
 * 最新の状態を、最新時刻で既存sweep（期限の購読と猶予切れの旧secretの組）→束縛Grantが現在inactiveの有効な購読（lastEnded=grant_ended）・
 * 保留の取下げの順に投影する。既知の送信先は変えない。変えたらtrue。awaitしない。
 */
export function projectBindings(state: KmsMutableState, now: number, verdictOf: (grantId: string) => BindingVerdict): boolean {
  let changed = sweepKmsState(state, now);
  if (state.active !== null && verdictOf(state.active.grantId) === 'inactive') {
    state.active = null;
    state.lastEnded = 'grant_ended';
    changed = true;
  }
  if (state.pending !== null && verdictOf(state.pending.grantId) === 'inactive') {
    state.pending = null;
    changed = true;
  }
  return changed;
}

export type Classification =
  | { readonly kind: 'pending' }
  | { readonly kind: 'extended'; readonly expiresAt: number | null }
  | { readonly kind: 'challenge' };

/** 最新時刻からの期限（nullは無期限）。 */
export function expiryFrom(now: number, ttlMs: number | null): number | null {
  return ttlMs === null ? null : now + ttlMs;
}

/**
 * 投影後の状態で登録要求を分類し、保留・延長ならstateを書き換える。既知の送信先が別idなら保留（新宛先の確認0、既知/有効は置換しない）、
 * liveな有効購読とid・hash・Grantが同じなら期限の延長（旧secretの猶予は足さない・延ばさない）、それ以外はchallenge（ここでは書かない）。
 */
export function classify(state: KmsMutableState, auth: RegistrationAuth, request: RegistrationRequest, now: number): Classification {
  if (state.knownDestinationId !== null && state.knownDestinationId !== request.id) {
    state.pending = { id: request.id, grantId: auth.grantId, requestedAt: now };
    return { kind: 'pending' };
  }
  const { active } = state;
  if (active !== null && active.id === request.id && active.secretHash === request.secretHash && active.grantId === auth.grantId) {
    const expiresAt = expiryFrom(now, request.ttlMs);
    active.expiresAt = expiresAt;
    return { kind: 'extended', expiresAt };
  }
  return { kind: 'challenge' };
}

/**
 * challengeを終えた登録を投影後の最新状態へ確定する。同じidのliveな現行secretのhashが変わる時だけ、その同じsnapshotのcurrent
 * sealed/hashを直前1個・最新時刻+5分の猶予へ写す。同じhashなら猶予を足さない・延ばさない（既存の猶予はそのまま）。束縛が失効・期限切れで
 * 投影から外れた旧購読のcurrent/previousは残さない（previous=null）。既知の送信先は同id・lastEnded=null、保留は変えない。
 * 別の送信先が既知・別idの有効購読はconflict（期待版が一致していれば起こらない防御）。
 */
export function applyActivation(
  state: KmsMutableState,
  auth: RegistrationAuth,
  request: RegistrationRequest,
  capsules: RegistrationCapsules,
  now: number,
): KmsSubscriptionRecord {
  if (state.knownDestinationId !== null && state.knownDestinationId !== request.id) throw registrationError('conflict');
  const current = state.active;
  if (current !== null && current.id !== request.id) throw registrationError('conflict');
  let previousSecret: KmsSubscriptionRecord['previousSecret'] = null;
  if (current !== null) {
    previousSecret =
      current.secretHash !== request.secretHash
        ? { sealed: current.sealedSecret, secretHash: current.secretHash, until: now + KMS_SUBSCRIPTION_PREVIOUS_GRACE_MS }
        : current.previousSecret && { ...current.previousSecret };
  }
  const record: KmsSubscriptionRecord = {
    id: request.id,
    ownerId: auth.ownerId,
    grantId: auth.grantId,
    sealedUrl: capsules.sealedUrl,
    sealedSecret: capsules.sealedSecret,
    secretHash: request.secretHash,
    previousSecret,
    expiresAt: expiryFrom(now, request.ttlMs),
  };
  state.active = record;
  state.knownDestinationId = request.id;
  state.lastEnded = null;
  return record;
}

/**
 * owner/identity単位の取消。該当のactive/pendingを外し、既知の送信先は残してlastEnded=cancelled。
 * 他のidentityは消さない。変えたらtrue。
 */
export function applyCancel(state: KmsMutableState, id: string): boolean {
  let changed = false;
  if (state.active?.id === id) {
    state.active = null;
    changed = true;
  }
  if (state.knownDestinationId === id && state.active === null && state.lastEnded !== 'cancelled') {
    state.lastEnded = 'cancelled';
    changed = true;
  }
  if (state.pending?.id === id) {
    state.pending = null;
    changed = true;
  }
  return changed;
}
