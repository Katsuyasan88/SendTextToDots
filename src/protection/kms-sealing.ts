// 長期秘密のKMS封緘codec。用途・owner・recordへ束縛したAADを信頼できるconfig/bindingから毎回再生成し、
// SOFTWARE KMSの直接暗号化（正規化transport port経由）でversioned capsuleを作る/開く。追加DEK・鍵material・本文を扱わない。
// 実Google SDKへの接続・型変換・取消・内部retryの無効化はtransport adapter（google-kms-transport.ts）の責任。キャッシュ・自動再送・永続化・ログ0。

/** 固定messageだけを持つ失敗。元のSDK error・cause・stack内の秘密・signal.reasonを転記しない。 */
export type KmsSealingErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted' | 'integrity_failed';

const ERROR_MESSAGES: Readonly<Record<KmsSealingErrorCode, string>> = {
  invalid_input: 'kms sealing: invalid input',
  unavailable: 'kms sealing: unavailable',
  timed_out: 'kms sealing: timed out',
  aborted: 'kms sealing: aborted',
  integrity_failed: 'kms sealing: integrity check failed',
};

export class KmsSealingError extends Error {
  override readonly name = 'KmsSealingError';
  readonly code: KmsSealingErrorCode;

  constructor(code: KmsSealingErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

export const KMS_CAPSULE_PREFIX = 'sttdkms1.';
const AAD_TAG = 'sttdkms1';
export const KMS_LIMITS = Object.freeze({
  plaintextBytes: 65_536,
  aadBytes: 4096,
  ciphertextBytes: 131_072,
  capsuleBytes: 262_144,
  resourceNameBytes: 1024,
  callTimeoutMs: 5000,
  readVersions: 8,
});
/**
 * KMS key ringの地域ID（単一region形、例: `us-central1`）。global・multi-regionは受け付けない。どの地域かは配置設定
 * （src/config/deployment.ts）のlocationと起動層で照合する。
 */
export const KMS_REGION_PATTERN = /^[a-z]{2,20}-[a-z]{2,20}[1-9][0-9]?$/;

export type KmsSealingEnvironment = 'development' | 'production' | 'local-test';
export type KmsSealingPurpose = 'oidc' | 'owner-uid' | 'callback-url' | 'callback-secret';

export interface KmsSealingBinding {
  readonly purpose: KmsSealingPurpose;
  readonly model: string;
  readonly recordId: string;
  readonly ownerBinding: string | null;
  readonly secretHash: string | null;
}

export interface KmsSealingOperation {
  /** 絶対期限（clockと同じ基準の有限整数ms）。 */
  readonly deadlineAt: number;
  readonly signal?: AbortSignal | undefined;
}

export interface KmsCallOptions {
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  readonly maxAttempts: 1;
}

export interface KmsEncryptRequest {
  /** 固定のwriteVersion（CryptoKeyVersion名）。 */
  readonly name: string;
  readonly plaintext: Buffer;
  readonly plaintextCrc32c: number;
  readonly additionalAuthenticatedData: Buffer;
  readonly additionalAuthenticatedDataCrc32c: number;
}

export interface KmsDecryptRequest {
  /** 固定のcryptoKey名（capsule内の任意resourceへ接続しない）。 */
  readonly name: string;
  readonly ciphertext: Buffer;
  readonly ciphertextCrc32c: number;
  readonly additionalAuthenticatedData: Buffer;
  readonly additionalAuthenticatedDataCrc32c: number;
}

export interface KmsEncryptResponse {
  readonly name: string;
  readonly ciphertext: Buffer;
  readonly ciphertextCrc32c: number;
  readonly verifiedPlaintextCrc32c: boolean;
  readonly verifiedAdditionalAuthenticatedDataCrc32c: boolean;
  readonly protectionLevel: string;
}

export interface KmsDecryptResponse {
  readonly plaintext: Buffer;
  readonly plaintextCrc32c: number;
  readonly usedPrimary?: boolean;
  readonly protectionLevel: string;
}

/**
 * 正規化済みのKMS通信port（SDKではない）。1回のseal/openでencrypt/decryptを各1回まで呼ぶ。
 * 応答のBufferはcodecへ所有移転する（transportは返却後に参照・再利用しない）。requestのBufferはsettleまでcodecが所有する。
 */
export interface KmsTransport {
  encrypt(request: KmsEncryptRequest, options: KmsCallOptions): PromiseLike<KmsEncryptResponse>;
  decrypt(request: KmsDecryptRequest, options: KmsCallOptions): PromiseLike<KmsDecryptResponse>;
}

export interface KmsSealingClock {
  now(): number;
}

export interface KmsSealingConfig {
  readonly environment: KmsSealingEnvironment;
  readonly projectId: string;
  readonly databaseId: string;
  readonly namespace: string;
  /** projects/{projectId}/locations/{region}/keyRings/{ring}/cryptoKeys/{key} */
  readonly cryptoKey: string;
  /** 同keyの正の数値version。 */
  readonly writeVersion: number;
  /** 同keyの明示allowlist（writeVersionを含む1〜8件）。 */
  readonly readVersions: readonly number[];
  readonly transport: KmsTransport;
  readonly clock: KmsSealingClock;
}

export interface KmsSealingCodec {
  seal(binding: KmsSealingBinding, plaintext: Buffer, operation: KmsSealingOperation): Promise<string>;
  /** 成功時の返却Bufferはcallerへ所有移転する。 */
  open(binding: KmsSealingBinding, capsule: string, operation: KmsSealingOperation): Promise<Buffer>;
}

// ---- CRC32C（Castagnoli、reflected 0x82F63B78）。通常のCRC32ではない。空=0、ASCII "123456789"=0xe3069283。

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? (c >>> 1) ^ 0x82f63b78 : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) crc = (CRC32C_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8)) >>> 0;
  return (crc ^ 0xffffffff) >>> 0;
}

// ---- 値の検査

const SAFE_ASCII = /^[A-Za-z0-9_.:-]{1,256}$/;
const OWNER_HASH = /^[0-9a-f]{64}$/;
const OWNER_ID = /^[A-Za-z0-9_-]{1,128}$/;
const HASH_OWNER_BINDING = /^hash:[0-9a-f]{64}$/;
const ID_OWNER_BINDING = /^id:[A-Za-z0-9_-]{1,128}$/;
const RESOURCE_ID = /^[A-Za-z0-9_-]{1,63}$/;
const VERSION_NUMBER = /^[1-9][0-9]{0,15}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ENVIRONMENTS: ReadonlySet<string> = new Set(['development', 'production', 'local-test']);
/** 既存の接続保存（connect/firestore.tsのSHARED_OIDC_MODELS）と同じ8model。 */
const OIDC_MODELS: ReadonlySet<string> = new Set([
  'Session',
  'Interaction',
  'Grant',
  'AuthorizationCode',
  'AccessToken',
  'RefreshToken',
  'ReplayDetection',
  'Client',
]);
/** 未ログインでも存在し得るmodelだけownerBindingをnullにできる。 */
const OIDC_UNOWNED_MODELS: ReadonlySet<string> = new Set(['Client', 'ReplayDetection', 'Session', 'Interaction']);
const BINDING_KEYS = ['purpose', 'model', 'recordId', 'ownerBinding', 'secretHash'] as const;

function invalid(): KmsSealingError {
  return new KmsSealingError('invalid_input');
}

/** "." / ".." だけの値はresource名のpathを壊すので、安全文字でも拒否する。 */
function isSafeAscii(value: unknown): value is string {
  return typeof value === 'string' && SAFE_ASCII.test(value) && !/^\.+$/.test(value);
}

/** 既存文書のownerHash（64桁小文字hex）から、oidc用途のownerBindingを作る。 */
export function ownerBindingFromHash(ownerHash: string): string {
  if (typeof ownerHash !== 'string' || !OWNER_HASH.test(ownerHash)) throw invalid();
  return `hash:${ownerHash}`;
}

/** 認可済みの内部ownerIdから、oidc以外の用途のownerBindingを作る。 */
export function ownerBindingFromId(ownerId: string): string {
  if (typeof ownerId !== 'string' || !OWNER_ID.test(ownerId)) throw invalid();
  return `id:${ownerId}`;
}

/** 自分のdata propertyだけを1回読む（getter・継承・symbolを受けない）。 */
function plainRecord(value: unknown, keys: readonly string[], exact: boolean): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw invalid();
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw invalid();
  const own = Reflect.ownKeys(value);
  if (exact && (own.length !== keys.length || own.some((key) => typeof key !== 'string' || !keys.includes(key)))) throw invalid();
  const out = new Map<string, unknown>();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) {
      if (exact) throw invalid();
      continue;
    }
    if (!('value' in descriptor)) throw invalid();
    out.set(key, descriptor.value);
  }
  return out;
}

function copyBinding(value: unknown): KmsSealingBinding {
  const fields = plainRecord(value, BINDING_KEYS, true);
  const purpose = fields.get('purpose');
  const model = fields.get('model');
  const recordId = fields.get('recordId');
  const ownerBinding = fields.get('ownerBinding');
  const secretHash = fields.get('secretHash');
  if (typeof model !== 'string' || !isSafeAscii(recordId)) throw invalid();
  if (purpose === 'oidc') {
    if (!OIDC_MODELS.has(model)) throw invalid();
    const ownerOk =
      (typeof ownerBinding === 'string' && HASH_OWNER_BINDING.test(ownerBinding)) ||
      (ownerBinding === null && OIDC_UNOWNED_MODELS.has(model));
    if (!ownerOk) throw invalid();
  } else if (purpose === 'owner-uid' || purpose === 'callback-url' || purpose === 'callback-secret') {
    if (model !== (purpose === 'owner-uid' ? 'Owner' : 'Subscription')) throw invalid();
    if (typeof ownerBinding !== 'string' || !ID_OWNER_BINDING.test(ownerBinding)) throw invalid();
  } else {
    throw invalid();
  }
  if (purpose === 'callback-secret') {
    if (typeof secretHash !== 'string' || !OWNER_HASH.test(secretHash)) throw invalid();
  } else if (secretHash !== null) {
    throw invalid();
  }
  return Object.freeze({ purpose, model, recordId, ownerBinding: ownerBinding as string | null, secretHash: secretHash as string | null });
}

function copyOperation(value: unknown): { readonly deadlineAt: number; readonly signal: AbortSignal | undefined } {
  const fields = plainRecord(value, ['deadlineAt', 'signal'], false);
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) throw invalid();
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw invalid();
  return { deadlineAt, signal };
}

function asciiResource(value: string): boolean {
  // 制御文字・空白・非ASCII・query・fragment・".."を含む名前を拒否する（構造の正規表現より前に見る）。
  return value.length > 0 && value.length <= KMS_LIMITS.resourceNameBytes && /^[\x21-\x7e]+$/.test(value) && !/[?#%\\]/.test(value) && !value.includes('..');
}

function parseCryptoKey(value: unknown, projectId: string): string {
  if (typeof value !== 'string' || !asciiResource(value)) throw invalid();
  const parts = value.split('/');
  if (parts.length !== 8) throw invalid();
  const [p, project, l, location, r, ring, c, key] = parts as [string, string, string, string, string, string, string, string];
  if (p !== 'projects' || project !== projectId || l !== 'locations' || !KMS_REGION_PATTERN.test(location)) throw invalid();
  if (r !== 'keyRings' || !RESOURCE_ID.test(ring) || c !== 'cryptoKeys' || !RESOURCE_ID.test(key)) throw invalid();
  return value;
}

function isVersionNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function versionName(cryptoKey: string, version: number): string {
  const name = `${cryptoKey}/cryptoKeyVersions/${version}`;
  if (name.length > KMS_LIMITS.resourceNameBytes) throw invalid();
  return name;
}

function isUint32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

/** Buffer（と型違いで返ったUint8Array）をzeroする。 */
function zero(value: unknown): void {
  if (value instanceof Uint8Array) value.fill(0);
}

/** 応答objectから自分のdata propertyだけを1回読む。読めない形は完全性の不備。 */
function responseFields(value: unknown, keys: readonly string[]): Map<string, unknown> {
  try {
    return plainRecord(value, keys, false);
  } catch {
    throw new KmsSealingError('integrity_failed');
  }
}

/** 遅い/失敗した応答に含まれるBuffer（codecへ所有移転済み）をzeroする。形が壊れていても例外を外へ出さない。 */
function discardResponse(value: unknown): void {
  if (typeof value !== 'object' || value === null) return;
  for (const key of ['ciphertext', 'plaintext']) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor !== undefined && 'value' in descriptor) zero(descriptor.value);
    } catch {
      // proxy等で読めない値は触らない
    }
  }
}

type Bound<T extends unknown[], R> = (...args: T) => R;

function bindMethod<T extends unknown[], R>(target: unknown, key: string): Bound<T, R> {
  if (typeof target !== 'object' || target === null) throw invalid();
  const method: unknown = (target as Record<string, unknown>)[key];
  if (typeof method !== 'function') throw invalid();
  return (...args: T) => Reflect.apply(method, target, args) as R;
}

export function createKmsSealingCodec(config: KmsSealingConfig): KmsSealingCodec {
  const fields = plainRecord(
    config,
    ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions', 'transport', 'clock'],
    false,
  );
  const environment = fields.get('environment');
  const projectId = fields.get('projectId');
  const databaseId = fields.get('databaseId');
  const namespace = fields.get('namespace');
  if (typeof environment !== 'string' || !ENVIRONMENTS.has(environment)) throw invalid();
  if (!isSafeAscii(projectId) || !isSafeAscii(namespace)) throw invalid();
  if (databaseId !== '(default)' && !isSafeAscii(databaseId)) throw invalid();
  const cryptoKey = parseCryptoKey(fields.get('cryptoKey'), projectId);

  const writeVersion = fields.get('writeVersion');
  const readVersionsInput = fields.get('readVersions');
  if (!isVersionNumber(writeVersion) || !Array.isArray(readVersionsInput)) throw invalid();
  const readVersionList: number[] = [];
  for (let i = 0; i < readVersionsInput.length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(readVersionsInput, i);
    if (descriptor === undefined || !('value' in descriptor) || !isVersionNumber(descriptor.value)) throw invalid();
    readVersionList.push(descriptor.value);
  }
  const readVersions = new Set(readVersionList);
  if (readVersionList.length < 1 || readVersionList.length > KMS_LIMITS.readVersions || readVersions.size !== readVersionList.length) throw invalid();
  if (!readVersions.has(writeVersion)) throw invalid();
  const writeName = versionName(cryptoKey, writeVersion);
  const readNames = new Map<string, number>();
  for (const version of readVersions) readNames.set(versionName(cryptoKey, version), version);
  const versionPrefix = `${cryptoKey}/cryptoKeyVersions/`;

  const transport = fields.get('transport');
  const encrypt = bindMethod<[KmsEncryptRequest, KmsCallOptions], PromiseLike<KmsEncryptResponse>>(transport, 'encrypt');
  const decrypt = bindMethod<[KmsDecryptRequest, KmsCallOptions], PromiseLike<KmsDecryptResponse>>(transport, 'decrypt');
  const clockNow = bindMethod<[], unknown>(fields.get('clock'), 'now');
  /** 読めない時計は有限の残りがないもの（timed_out）として扱い、元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  const context = [AAD_TAG, environment, projectId, databaseId, namespace] as const;

  function aadOf(binding: KmsSealingBinding, keyVersion: string): Buffer {
    const json = JSON.stringify([...context, binding.purpose, binding.model, binding.recordId, binding.ownerBinding, binding.secretHash, keyVersion]);
    const aad = Buffer.from(json, 'utf8');
    if (aad.length > KMS_LIMITS.aadBytes) throw invalid();
    return aad;
  }

  /**
   * 最新のsignal→clock→signalの順に見て、まだ結果を返してよいか。中止を期限より先に分類する。
   * 時計の観測中に起きた中止（abort listenerの再入を含む）も、観測後のsignalでabortedにする。
   */
  function expiry(signal: AbortSignal | undefined, callDeadline: number, deadlineAt: number): 'aborted' | 'timed_out' | null {
    if (signal?.aborted) return 'aborted';
    const at = now();
    if (signal?.aborted) return 'aborted';
    return at < callDeadline && at < deadlineAt ? null : 'timed_out';
  }

  /**
   * transportを1回だけ呼ぶ。開始前に期限/abortを見て、残りが正の時だけ呼ぶ（clockの観測中に起きた中止もinvoke直前に見る）。
   * 待機期限/abortでcallerへ非成功を返し、内部のAbortControllerへ固定reasonで中止を伝える。応答後もclock/signalを再検査する。
   * 遅い/捨てた応答のBufferはzeroし、requestのBuffer（codec所有）はtransportが実際にsettleした時にzeroする。
   * transportのthenを通ってもseal/openのawait後の継続までに期限/中止が来得るので、結果の公開/所有移転の直前に
   * assertLiveで同じ検査をもう一度行う。
   */
  function call<R>(
    invoke: (options: KmsCallOptions) => PromiseLike<R>,
    owned: readonly Buffer[],
    deadlineAt: number,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly value: R; readonly assertLive: () => void }> {
    const release = () => {
      for (const buffer of owned) buffer.fill(0);
    };
    if (signal?.aborted) {
      release();
      return Promise.reject(new KmsSealingError('aborted'));
    }
    const startedAt = now();
    const remaining = deadlineAt - startedAt;
    if (signal?.aborted) {
      release();
      return Promise.reject(new KmsSealingError('aborted'));
    }
    if (!(remaining > 0)) {
      release();
      return Promise.reject(new KmsSealingError('timed_out'));
    }
    const timeoutMs = Math.min(Math.ceil(remaining), KMS_LIMITS.callTimeoutMs);
    const callDeadline = startedAt + timeoutMs;
    const controller = new AbortController();
    const assertLive = () => {
      const code = expiry(signal, callDeadline, deadlineAt);
      if (code !== null) throw new KmsSealingError(code);
    };

    return new Promise<{ readonly value: R; readonly assertLive: () => void }>((resolve, reject) => {
      let settled = false;
      /** 最初の決着だけを採る。既に決着していればfalse（呼出し元が値を捨てる）。 */
      const finish = (outcome: () => void): boolean => {
        if (settled) return false;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        outcome();
        return true;
      };
      const stop = (code: 'timed_out' | 'aborted') => {
        finish(() => reject(new KmsSealingError(code)));
        controller.abort(new KmsSealingError(code));
      };
      const onAbort = () => stop('aborted');
      const timer = setTimeout(() => stop('timed_out'), timeoutMs);
      signal?.addEventListener('abort', onAbort, { once: true });

      let pending: PromiseLike<R>;
      try {
        pending = invoke({ timeoutMs, signal: controller.signal, maxAttempts: 1 });
      } catch {
        pending = Promise.reject(new KmsSealingError('unavailable'));
      }
      Promise.resolve(pending).then(
        (value) => {
          release();
          if (settled) return discardResponse(value);
          const code = expiry(signal, callDeadline, deadlineAt);
          if (code !== null) {
            discardResponse(value);
            return stop(code);
          }
          // 受取からresolve確定までの間に中止/別の決着に負けた応答は、callerへ移転しないのでここで捨てる。
          if (!finish(() => resolve({ value, assertLive }))) discardResponse(value);
        },
        () => {
          release();
          finish(() => reject(new KmsSealingError('unavailable')));
        },
      );
    });
  }

  async function seal(bindingInput: KmsSealingBinding, plaintextInput: Buffer, operationInput: KmsSealingOperation): Promise<string> {
    const binding = copyBinding(bindingInput);
    const operation = copyOperation(operationInput);
    if (!Buffer.isBuffer(plaintextInput) || plaintextInput.length > KMS_LIMITS.plaintextBytes) throw invalid();
    const aad = aadOf(binding, writeName);
    const plaintext = Buffer.alloc(plaintextInput.length);
    plaintextInput.copy(plaintext);
    const request: KmsEncryptRequest = Object.freeze({
      name: writeName,
      plaintext,
      plaintextCrc32c: crc32c(plaintext),
      additionalAuthenticatedData: aad,
      additionalAuthenticatedDataCrc32c: crc32c(aad),
    });
    const called = await call((options) => encrypt(request, options), [plaintext, aad], operation.deadlineAt, operation.signal);
    const response: unknown = called.value;

    let ciphertext: unknown;
    try {
      const got = responseFields(response, [
        'name',
        'ciphertext',
        'ciphertextCrc32c',
        'verifiedPlaintextCrc32c',
        'verifiedAdditionalAuthenticatedDataCrc32c',
        'protectionLevel',
      ]);
      ciphertext = got.get('ciphertext');
      const ciphertextCrc32c = got.get('ciphertextCrc32c');
      const ok =
        got.get('name') === writeName &&
        got.get('verifiedPlaintextCrc32c') === true &&
        got.get('verifiedAdditionalAuthenticatedDataCrc32c') === true &&
        got.get('protectionLevel') === 'SOFTWARE' &&
        Buffer.isBuffer(ciphertext) &&
        ciphertext.length >= 1 &&
        ciphertext.length <= KMS_LIMITS.ciphertextBytes &&
        isUint32(ciphertextCrc32c) &&
        crc32c(ciphertext) === ciphertextCrc32c;
      if (!ok || !Buffer.isBuffer(ciphertext)) throw new KmsSealingError('integrity_failed');
      const body = Buffer.from(JSON.stringify([writeName, ciphertext.toString('base64url')]), 'utf8');
      const capsule = KMS_CAPSULE_PREFIX + body.toString('base64url');
      if (capsule.length > KMS_LIMITS.capsuleBytes) throw new KmsSealingError('integrity_failed');
      // capsuleを公開する直前の期限/中止の再検査。
      called.assertLive();
      return capsule;
    } finally {
      zero(ciphertext);
      discardResponse(response);
    }
  }

  /** capsuleを通信前に正規形として検査し、読取allowlistのversion名と暗号文を返す。 */
  function parseCapsule(capsule: unknown): { readonly keyVersion: string; readonly ciphertext: Buffer } {
    if (typeof capsule !== 'string' || capsule.length > KMS_LIMITS.capsuleBytes || !capsule.startsWith(KMS_CAPSULE_PREFIX)) throw invalid();
    const encoded = capsule.slice(KMS_CAPSULE_PREFIX.length);
    if (!BASE64URL.test(encoded)) throw invalid();
    const raw = Buffer.from(encoded, 'base64url');
    if (raw.toString('base64url') !== encoded) throw invalid();
    let text: string;
    let parsed: unknown;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
      parsed = JSON.parse(text);
    } catch {
      throw invalid();
    }
    if (!Array.isArray(parsed) || parsed.length !== 2) throw invalid();
    const [keyVersion, ciphertextText] = parsed as unknown[];
    if (typeof keyVersion !== 'string' || typeof ciphertextText !== 'string') throw invalid();
    if (JSON.stringify([keyVersion, ciphertextText]) !== text) throw invalid();
    if (!asciiResource(keyVersion) || !keyVersion.startsWith(versionPrefix)) throw invalid();
    const versionText = keyVersion.slice(versionPrefix.length);
    if (!VERSION_NUMBER.test(versionText) || !readNames.has(keyVersion)) throw invalid();
    if (!BASE64URL.test(ciphertextText)) throw invalid();
    const ciphertext = Buffer.from(ciphertextText, 'base64url');
    if (ciphertext.length < 1 || ciphertext.length > KMS_LIMITS.ciphertextBytes || ciphertext.toString('base64url') !== ciphertextText) throw invalid();
    return { keyVersion, ciphertext };
  }

  async function open(bindingInput: KmsSealingBinding, capsuleInput: string, operationInput: KmsSealingOperation): Promise<Buffer> {
    const binding = copyBinding(bindingInput);
    const operation = copyOperation(operationInput);
    const { keyVersion, ciphertext } = parseCapsule(capsuleInput);
    const aad = aadOf(binding, keyVersion);
    const request: KmsDecryptRequest = Object.freeze({
      name: cryptoKey,
      ciphertext,
      ciphertextCrc32c: crc32c(ciphertext),
      additionalAuthenticatedData: aad,
      additionalAuthenticatedDataCrc32c: crc32c(aad),
    });
    const called = await call((options) => decrypt(request, options), [ciphertext, aad], operation.deadlineAt, operation.signal);
    const response: unknown = called.value;

    let plaintext: unknown;
    try {
      const got = responseFields(response, ['plaintext', 'plaintextCrc32c', 'protectionLevel']);
      plaintext = got.get('plaintext');
      const plaintextCrc32c = got.get('plaintextCrc32c');
      const ok =
        got.get('protectionLevel') === 'SOFTWARE' &&
        Buffer.isBuffer(plaintext) &&
        plaintext.length <= KMS_LIMITS.plaintextBytes &&
        isUint32(plaintextCrc32c) &&
        crc32c(plaintext) === plaintextCrc32c;
      if (!ok || !Buffer.isBuffer(plaintext)) throw new KmsSealingError('integrity_failed');
      // usedPrimaryは許可済みold versionを拒否する根拠にしない（読まない）。callerへは専用のBufferを渡す。
      const owned = Buffer.alloc(plaintext.length);
      plaintext.copy(owned);
      // 平文Bufferの所有をcallerへ移す直前の期限/中止の再検査。不成立なら未移転のcopyもzeroする。
      try {
        called.assertLive();
      } catch (error) {
        owned.fill(0);
        throw error;
      }
      return owned;
    } finally {
      zero(plaintext);
      discardResponse(response);
    }
  }

  return Object.freeze({ seal, open });
}
