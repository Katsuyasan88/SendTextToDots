// KMS接続保存のGrantについて、transactionの外で開封した正確な文書の版（exists・updateTimeの秒/ナノ秒・sealed）へ、
// payloadのresource/scope（rejectedを差し引く）・owner・期限の確認結果を束縛する明示helper。購読登録の最終保存transactionは、同じ
// 文書を読んだsnapshotとこの証拠をcheckで同期に照合する（開封0）。Grantの存在/metadataだけの判定を完全なscope認可へ読み替えない。
// 呼出し元が取得したsnapshotだけを使い、helper自身はFirestoreの読取り・書込み・transaction・SDK呼出しをしない（snapshot/refの同期の
// 参照だけ）。ConnectStorage・grantDocLive・codec・DB形式は変えない。dbとKMS transportは借用し、閉じない。
// 証拠はfactory所有のWeakMapに置く凍結した空object。公開objectへowner・Grant・URL・payload・sealed・期限を載せず、共有cache・永続化・ログ0。

import { types } from 'node:util';

import type { DocumentSnapshot, Firestore } from '@google-cloud/firestore';

import { STTD_SCOPE } from '../oauth/provider.js';
import type { Clock } from '../policy.js';
import {
  KMS_LIMITS,
  KmsSealingError,
  createKmsSealingCodec,
  ownerBindingFromHash,
  type KmsCallOptions,
  type KmsDecryptRequest,
  type KmsDecryptResponse,
  type KmsSealingCodec,
  type KmsSealingConfig,
} from '../protection/kms-sealing.js';
import { isUuid } from '../storage/firestore/checks.js';
import { isKmsGrantId } from '../storage/firestore/kms-subscription-format.js';
import { CONNECT_STORAGE_ROOT, isConnectNamespace, type ConnectStorage } from './firestore.js';

/** 外へ出すのはこの4分類だけ。元の例外・cause・secret・token・URL・payload・owner・Grant・signal.reasonを持たない。 */
export type KmsGrantAuthorizationErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted';

const ERROR_MESSAGES: Readonly<Record<KmsGrantAuthorizationErrorCode, string>> = {
  invalid_input: 'kms grant authorization: invalid input',
  unavailable: 'kms grant authorization: unavailable',
  timed_out: 'kms grant authorization: timed out',
  aborted: 'kms grant authorization: aborted',
};

export class KmsGrantAuthorizationError extends Error {
  override readonly name = 'KmsGrantAuthorizationError';
  readonly code: KmsGrantAuthorizationErrorCode;

  constructor(code: KmsGrantAuthorizationErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

/** 接続保存のうち、このhelperが使う同期の参照・判定だけ（prototypeのdata methodを束縛して1回捕捉する）。 */
export type KmsGrantAuthorizationConnect = Pick<ConnectStorage, 'grantDocRef' | 'grantDocLive'>;

export interface KmsGrantAuthorizationOptions {
  /** 借用するFirestore instance（読取り・終了をしない）。snapshotとconnectの参照はこのinstanceのものだけを受け付ける。 */
  readonly db: Firestore;
  readonly connect: KmsGrantAuthorizationConnect;
  /** 固定MCP audience（Grant.resourcesのkey）。HTTPS URL、local-testだけloopbackのHTTPも可。 */
  readonly resource: string;
  /** codec設定からclockを除いたもの。namespaceは接続保存の`t256_<UUID>`。transportはdecryptだけを使う。 */
  readonly kms: Omit<KmsSealingConfig, 'clock'>;
  /** helperとcodecが同じ関数で時刻を読む。 */
  readonly clock: Clock;
}

/** 認証済みのowner（UUID）と要求のGrant（既存のKMS grant ID形式）。 */
export interface KmsGrantAuth {
  readonly ownerId: string;
  readonly grantId: string;
}

/** 元要求の絶対期限（clockと同じ基準の整数ms）と中止。延長しない。 */
export interface KmsGrantOperation {
  readonly deadlineAt: number;
  readonly signal?: AbortSignal | undefined;
}

declare const KMS_GRANT_PROOF: unique symbol;
/** 中身を持たない不透明な証拠。発行したfactory・同じowner/Grant・同じ元operationだけで使える。 */
export interface KmsGrantProof {
  readonly [KMS_GRANT_PROOF]: never;
}

export type KmsGrantCheckResult = 'active' | 'inactive' | 'stale';

export interface KmsGrantAuthorization {
  /** 取得済みのGrant snapshotをtransactionの外で検査・開封し、その版へ束縛した証拠を返す（無い・生存条件不成立はinactiveの証拠）。 */
  prove(snapshot: DocumentSnapshot, auth: KmsGrantAuth, operation: KmsGrantOperation): Promise<KmsGrantProof>;
  /** 最新のsnapshotと証拠を同期に照合する（I/O・開封0）。 */
  check(proof: KmsGrantProof, snapshot: DocumentSnapshot, auth: KmsGrantAuth, operation: KmsGrantOperation): KmsGrantCheckResult;
}

const OPTION_KEYS = ['db', 'connect', 'resource', 'kms', 'clock'] as const;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport'] as const;
const AUTH_KEYS = ['ownerId', 'grantId'] as const;
/** 既存OidcDoc（connect/firestore.ts）の7field。 */
const DOC_KEYS = ['model', 'sealed', 'expiresAt', 'grantHash', 'uidHash', 'ownerHash', 'consumedAt'] as const;
const PAYLOAD_KEYS = ['accountId', 'clientId', 'exp', 'resources', 'rejected'] as const;
const GRANT_DOC_ID = /^Grant_[0-9a-f]{64}$/;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);
const ENVIRONMENTS: ReadonlySet<string> = new Set(['development', 'production', 'local-test']);
const MAX_RESOURCE_LENGTH = 2048;
const NANOS_PER_SECOND = 1_000_000_000;

function invalid(): KmsGrantAuthorizationError {
  return new KmsGrantAuthorizationError('invalid_input');
}

function fail(): never {
  throw invalid();
}

/** 固定errorへ正規化する。codecの完全性の不備・下位portの例外は元の内容を運ばないunavailable。 */
function fixed(error: unknown): KmsGrantAuthorizationError {
  if (error instanceof KmsGrantAuthorizationError) return error;
  if (error instanceof KmsSealingError) {
    if (error.code === 'invalid_input' || error.code === 'timed_out' || error.code === 'aborted') return new KmsGrantAuthorizationError(error.code);
  }
  return new KmsGrantAuthorizationError('unavailable');
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前を拒否、getterを呼ばない）。 */
function dataFields(value: unknown, required: readonly string[], optional: readonly string[]): Map<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) fail();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || optional.includes(key))) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    if (descriptor.value !== undefined || required.includes(key)) taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) fail();
  return taken;
}

/** prototypeの連鎖をdescriptorで辿ってmethodを1回取り出し、元のobjectへ束縛する（accessor・Proxyを拒否、getterを呼ばない）。 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) fail();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) fail();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  return fail();
}

/** 配列（Proxyでない・own dataの要素だけ）を写す。 */
function copyArray(value: unknown): unknown[] {
  if (!isObject(value) || !Array.isArray(value)) fail();
  const out: unknown[] = [];
  const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || length > 64) fail();
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    out.push(descriptor.value);
  }
  return out;
}

function resourceOf(value: unknown, environment: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_RESOURCE_LENGTH || !URL.canParse(value)) fail();
  const url = new URL(value);
  if (url.username !== '' || url.password !== '' || url.hash !== '' || value.includes('#')) fail();
  const loopbackHttp = environment === 'local-test' && url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) fail();
  return value;
}

type Captured = Readonly<{ deadlineAt: number; signal: AbortSignal | undefined }>;

function copyOperation(value: unknown): Captured {
  const fields = dataFields(value, ['deadlineAt'], ['signal']);
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) fail();
  if (signal !== undefined && (!isObject(signal) || !(signal instanceof AbortSignal))) fail();
  return Object.freeze({ deadlineAt, signal: signal as AbortSignal | undefined });
}

function copyAuth(value: unknown): KmsGrantAuth {
  const fields = dataFields(value, AUTH_KEYS, []);
  const ownerId = fields.get('ownerId');
  const grantId = fields.get('grantId');
  if (!isUuid(ownerId) || !isKmsGrantId(grantId)) fail();
  return Object.freeze({ ownerId, grantId });
}

/** 文書の版。existsとupdateTimeの秒/ナノ秒をそのまま持つ（toMillis・Dateへの丸め0）。sealedも同一を照合する。 */
type Version =
  | { readonly exists: false }
  | { readonly exists: true; readonly seconds: number; readonly nanoseconds: number; readonly sealed: string };

function sameVersion(a: Version, b: Version): boolean {
  if (!a.exists || !b.exists) return a.exists === b.exists;
  return a.seconds === b.seconds && a.nanoseconds === b.nanoseconds && a.sealed === b.sealed;
}

/** 既存OidcDocの7field（plain own data）。 */
type GrantDoc = Readonly<{
  model: string;
  sealed: string;
  expiresAt: number | null;
  grantHash: string | null;
  uidHash: string | null;
  ownerHash: string | null;
  consumedAt: number | null;
}>;

function nullable<T>(value: unknown, check: (v: unknown) => v is T): value is T | null {
  return value === null || check(value);
}
const isString = (value: unknown): value is string => typeof value === 'string';
const isFiniteNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);

function copyGrantDoc(value: unknown): GrantDoc {
  const fields = dataFields(value, DOC_KEYS, []);
  const doc = Object.fromEntries(fields) as Record<string, unknown>;
  const ok =
    isString(doc.model) &&
    isString(doc.sealed) &&
    nullable(doc.expiresAt, isFiniteNumber) &&
    nullable(doc.grantHash, isString) &&
    nullable(doc.uidHash, isString) &&
    nullable(doc.ownerHash, isString) &&
    nullable(doc.consumedAt, isFiniteNumber);
  if (!ok) fail();
  return Object.freeze(doc) as GrantDoc;
}

/** JSONのscope map（own stringの値だけ）。 */
function scopeMap(value: unknown): Map<string, string> {
  const map = new Map<string, string>();
  if (!isObject(value) || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'string') fail();
    map.set(key, descriptor.value);
  }
  return map;
}

/** payloadから証拠に必要な派生だけを作る。account不一致・scope無し・明示rejectはnull（inactive）、破損/型の不正は固定error。 */
function evaluatePayload(plaintext: Buffer, auth: KmsGrantAuth, resource: string): { readonly expMs: number } | null {
  if (plaintext.length > KMS_LIMITS.plaintextBytes) fail();
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
  } catch {
    return fail();
  }
  if (!isObject(payload) || Array.isArray(payload) || Object.getPrototypeOf(payload) !== Object.prototype) fail();
  // 通常payloadの他のfield（iat・jti・kind・openid等）は読まず、転送・保持しない。
  const fields = new Map<string, unknown>();
  for (const key of PAYLOAD_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(payload, key);
    if (descriptor !== undefined) fields.set(key, descriptor.value);
  }
  const accountId = fields.get('accountId');
  const clientId = fields.get('clientId');
  const exp = fields.get('exp');
  if (typeof accountId !== 'string' || typeof clientId !== 'string' || clientId.length === 0 || !isFiniteNumber(exp)) fail();
  const granted = fields.has('resources') ? scopeMap(fields.get('resources')).get(resource) : undefined;
  let rejectedScope: string | undefined;
  if (fields.has('rejected')) {
    const rejected = fields.get('rejected');
    if (!isObject(rejected) || Array.isArray(rejected) || Object.getPrototypeOf(rejected) !== Object.prototype) fail();
    // rejected.rejectedは固定writerが作らない非canonical形（getResourceScopeが再帰する）。意味を推測しない。
    if (Object.hasOwn(rejected, 'rejected')) fail();
    const descriptor = Object.getOwnPropertyDescriptor(rejected, 'resources');
    if (descriptor !== undefined) {
      if (!('value' in descriptor)) fail();
      rejectedScope = scopeMap(descriptor.value).get(resource);
    }
  }
  if (accountId !== auth.ownerId) return null;
  // oidc-provider 9.12.2 Grant#getResourceScopeと同じ: resources[resource]が空でなければ、rejectedの同resourceのscopeを差し引く。
  if (granted === undefined || granted === '') return null;
  const scopes = new Set(granted.split(' '));
  if (rejectedScope !== undefined && rejectedScope !== '') for (const scope of rejectedScope.split(' ')) scopes.delete(scope);
  if (!scopes.has(STTD_SCOPE)) return null;
  return Object.freeze({ expMs: exp * 1000 });
}

/** 証拠の中身（WeakMapの値だけ。公開しない）。 */
interface ProofRecord {
  readonly ownerId: string;
  readonly grantId: string;
  readonly path: string;
  readonly deadlineAt: number;
  readonly signal: AbortSignal | undefined;
  readonly version: Version;
  /** 開封した同版のpayloadが同owner・scopeを満たした時だけ、そのexp（ms）。それ以外はnull（inactive）。 */
  readonly evidence: { readonly expMs: number } | null;
}

/** snapshotの同期読取り結果。 */
type SnapshotRead = { readonly version: Version; readonly doc: GrantDoc | undefined };

/**
 * Grant scopeの同版証拠のhelperを組み立てる。全ての検査・捕捉はここで1回だけ行い、以後は入力objectを読み直さない。
 * DB・KMS・ネットワーク0。不正はKmsGrantAuthorizationError（invalid_input）。
 */
export function createKmsGrantAuthorization(options: KmsGrantAuthorizationOptions): KmsGrantAuthorization {
  const fields = dataFields(options, OPTION_KEYS, []);

  // dbは借用。SDKのmethodの存在だけをdescriptorで確かめる（呼ばない・接続しない）。以後は参照の同一性だけに使う。
  const db = fields.get('db');
  methodOf(db, 'collection');

  const connectTarget = fields.get('connect');
  const grantDocRef = methodOf(connectTarget, 'grantDocRef');
  const grantDocLive = methodOf(connectTarget, 'grantDocLive');

  const kms = dataFields(fields.get('kms'), KMS_KEYS, []);
  const environment = kms.get('environment');
  const namespace = kms.get('namespace');
  if (typeof environment !== 'string' || !ENVIRONMENTS.has(environment) || !isConnectNamespace(namespace)) fail();
  const resource = resourceOf(fields.get('resource'), environment);
  const readVersions = copyArray(kms.get('readVersions'));

  const clockNow = methodOf(fields.get('clock'), 'now');
  /** 読めない・有限でない時計は残りのないもの（timed_out）として扱い、元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return isFiniteNumber(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };

  // Grantの開封はdecryptだけ。封緘（encrypt）は呼ばない。
  const decrypt = methodOf(kms.get('transport'), 'decrypt');
  const transport = Object.freeze({
    encrypt: () => Promise.reject(new Error('grant authorization: read-only KMS port, encrypt is not used')),
    decrypt: (request: KmsDecryptRequest, callOptions: KmsCallOptions) => decrypt(request, callOptions) as PromiseLike<KmsDecryptResponse>,
  });
  let codec: KmsSealingCodec;
  try {
    codec = createKmsSealingCodec({
      environment: environment as KmsSealingConfig['environment'],
      projectId: kms.get('projectId') as string,
      databaseId: kms.get('databaseId') as string,
      namespace,
      cryptoKey: kms.get('cryptoKey') as string,
      writeVersion: kms.get('writeVersion') as number,
      readVersions: readVersions as number[],
      transport,
      clock: Object.freeze({ now }),
    });
  } catch {
    return fail();
  }

  const grantPathPrefix = `${CONNECT_STORAGE_ROOT}/${namespace}/oidc/`;
  const proofs = new WeakMap<object, ProofRecord>();

  /** まだ進めてよいかを、最新のsignal→時計→signalの順に見て、その時刻を返す（時計の観測中の中止も見る）。 */
  function liveNow(deadlineAt: number, signal: AbortSignal | undefined): number {
    if (signal?.aborted) throw new KmsGrantAuthorizationError('aborted');
    const at = now();
    if (signal?.aborted) throw new KmsGrantAuthorizationError('aborted');
    if (!(at < deadlineAt)) throw new KmsGrantAuthorizationError('timed_out');
    return at;
  }

  /** このinstance・この接続namespaceのGrant文書の参照か（別instanceは同じproject文字列でも拒否）。pathとidを返す。 */
  function ownRef(ref: unknown): { readonly path: string; readonly id: string } {
    if (!isObject(ref)) fail();
    let firestore: unknown;
    let path: unknown;
    let id: unknown;
    try {
      firestore = (ref as { firestore?: unknown }).firestore;
      if (firestore !== db) fail();
      path = (ref as { path?: unknown }).path;
      id = (ref as { id?: unknown }).id;
    } catch {
      return fail();
    }
    if (typeof path !== 'string' || typeof id !== 'string' || !GRANT_DOC_ID.test(id) || path !== grantPathPrefix + id) fail();
    return { path, id };
  }

  /** connectが返す、要求Grantの期待参照。 */
  function expectedRef(grantId: string): { readonly path: string; readonly id: string } {
    let ref: unknown;
    try {
      ref = grantDocRef(grantId);
    } catch {
      throw new KmsGrantAuthorizationError('unavailable');
    }
    return ownRef(ref);
  }

  /** 信頼済みのSDK snapshotから、最初のawaitの前に参照・版・dataを1回だけ捕捉する。 */
  function readSnapshot(snapshot: unknown, expectedPath: string): SnapshotRead {
    if (!isObject(snapshot)) fail();
    let ref: unknown;
    let exists: unknown;
    try {
      ref = (snapshot as { ref?: unknown }).ref;
    } catch {
      return fail();
    }
    if (ownRef(ref).path !== expectedPath) fail();
    try {
      exists = (snapshot as { exists?: unknown }).exists;
    } catch {
      return fail();
    }
    if (exists === false) return { version: Object.freeze({ exists: false }), doc: undefined };
    if (exists !== true) fail();
    let seconds: unknown;
    let nanoseconds: unknown;
    let data: unknown;
    try {
      const updateTime: unknown = (snapshot as { updateTime?: unknown }).updateTime;
      if (!isObject(updateTime)) fail();
      seconds = (updateTime as { seconds?: unknown }).seconds;
      nanoseconds = (updateTime as { nanoseconds?: unknown }).nanoseconds;
      data = methodOf(snapshot, 'data')();
    } catch {
      return fail();
    }
    if (typeof seconds !== 'number' || !Number.isSafeInteger(seconds)) fail();
    if (typeof nanoseconds !== 'number' || !Number.isSafeInteger(nanoseconds) || nanoseconds < 0 || nanoseconds >= NANOS_PER_SECOND) fail();
    const doc = copyGrantDoc(data);
    return { version: Object.freeze({ exists: true, seconds, nanoseconds, sealed: doc.sealed }), doc };
  }

  function metadataLive(doc: GrantDoc | undefined, auth: KmsGrantAuth, at: number): doc is GrantDoc {
    if (doc === undefined) return false;
    try {
      return grantDocLive({ ...doc }, auth.ownerId, auth.grantId, at) === true;
    } catch {
      throw new KmsGrantAuthorizationError('unavailable');
    }
  }

  function publish(record: ProofRecord): KmsGrantProof {
    const proof = Object.freeze(Object.create(null) as object);
    proofs.set(proof, Object.freeze(record));
    return proof as KmsGrantProof;
  }

  async function prove(snapshotInput: DocumentSnapshot, authInput: KmsGrantAuth, operationInput: KmsGrantOperation): Promise<KmsGrantProof> {
    let plaintext: Buffer | undefined;
    try {
      // 最初のawaitの前に、入力・時計・snapshotの全てを捕捉する（後の改変で束縛を変えない）。
      const auth = copyAuth(authInput);
      const operation = copyOperation(operationInput);
      const { signal } = operation;
      const startedAt = liveNow(operation.deadlineAt, signal);
      // 1回の開封の期限は元期限とfloor(開始)+5000の短い方。await後・処理後・公開直前まで同じ期限/signalで再検査し、延長しない。
      const callDeadline = Math.min(operation.deadlineAt, Math.floor(startedAt) + KMS_LIMITS.callTimeoutMs);
      if (!(startedAt < callDeadline)) throw new KmsGrantAuthorizationError('timed_out');
      const target = expectedRef(auth.grantId);
      const read = readSnapshot(snapshotInput, target.path);
      const base = { ownerId: auth.ownerId, grantId: auth.grantId, path: target.path, deadlineAt: operation.deadlineAt, signal, version: read.version };
      const doc = read.doc;
      // snapshotの取り出しにかかった時間を0としない。捕捉後の最新時刻で開封の要否を決める。
      const capturedAt = liveNow(callDeadline, signal);
      if (!metadataLive(doc, auth, capturedAt)) {
        // 無い・期限切れ・別owner/Grantはinactiveの証拠（開封0）。
        liveNow(callDeadline, signal);
        return publish({ ...base, evidence: null });
      }
      // 復号の束縛は保存先の文書（model・ref.id）と保存メタのownerHashから作る。payload・capsule由来のownerを使わない。
      let ownerBinding: string;
      try {
        ownerBinding = ownerBindingFromHash(doc.ownerHash as string);
      } catch {
        return fail();
      }
      const binding = Object.freeze({ purpose: 'oidc' as const, model: 'Grant', recordId: target.id, ownerBinding, secretHash: null });
      plaintext = await codec.open(binding, doc.sealed, Object.freeze({ deadlineAt: callDeadline, signal }));
      liveNow(callDeadline, signal);
      const derived = evaluatePayload(plaintext, auth, resource);
      // 開封を待つ間にmetadataの期限を過ぎたもの、payloadのexpを過ぎたものはinactive（短い方より長く認可しない）。
      const at = liveNow(callDeadline, signal);
      const evidence = derived !== null && at < derived.expMs && metadataLive(doc, auth, at) ? derived : null;
      // 公開直前の再検査（同じ5秒期限・signal）。
      liveNow(callDeadline, signal);
      return publish({ ...base, evidence });
    } catch (error) {
      throw fixed(error);
    } finally {
      plaintext?.fill(0);
    }
  }

  function check(proofInput: KmsGrantProof, snapshotInput: DocumentSnapshot, authInput: KmsGrantAuth, operationInput: KmsGrantOperation): KmsGrantCheckResult {
    try {
      const auth = copyAuth(authInput);
      const operation = copyOperation(operationInput);
      const record = isObject(proofInput) ? proofs.get(proofInput) : undefined;
      if (record === undefined) fail();
      // 発行時と同じowner・Grant・元要求（deadline・signalの同一性）だけ。
      if (record.ownerId !== auth.ownerId || record.grantId !== auth.grantId) fail();
      if (record.deadlineAt !== operation.deadlineAt || record.signal !== operation.signal) fail();
      liveNow(operation.deadlineAt, operation.signal);
      if (expectedRef(auth.grantId).path !== record.path) fail();
      const read = readSnapshot(snapshotInput, record.path);
      // snapshotの版・dataを捕捉した後の最新時刻で判定する（取り出しの同期区間の経過を0としない）。
      const at = liveNow(operation.deadlineAt, operation.signal);
      const doc = read.doc;
      let result: KmsGrantCheckResult;
      if (!metadataLive(doc, auth, at)) result = 'inactive';
      else if (!sameVersion(read.version, record.version)) result = 'stale';
      else result = record.evidence !== null && at < record.evidence.expMs ? 'active' : 'inactive';
      // 全ての返却の直前に元期限/中止を検査する（期限後・中止後の正常分類0）。activeは最新時刻でmetadata expiryとpayload expも再検査し、
      // 元要求内でGrantだけが期限に達したならinactive。
      const last = liveNow(operation.deadlineAt, operation.signal);
      if (result === 'active') {
        const expiresAt = doc === undefined ? undefined : doc.expiresAt;
        const metadataUnexpired = expiresAt === null || (typeof expiresAt === 'number' && last < expiresAt);
        if (!metadataUnexpired || record.evidence === null || !(last < record.evidence.expMs)) return 'inactive';
      }
      return result;
    } catch (error) {
      throw fixed(error);
    }
  }

  return Object.freeze({ prove, check });
}
