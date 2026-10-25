// 接続保存（ConnectStorage）のAS payload・UIDの封緘portを、KMS codecへつなぐadapter。束縛（AAD）はstorageが渡す信頼済みcontextと、
// 固定purposeとの完全一致から作り、capsuleや開封したpayloadからは作らない。sttdkms1 capsuleだけを書き・読む（他形式へのfallback0）。
// 要求contextはoperation（RequestAuthContext.current）から毎回受ける。
// codecの公開直前検査の後、adapterのawait継続までにも期限/中止が来得るので、adapter全体の期限
// （元deadlineとadapter開始+5000msの短い方）をcodecと共有し、capsule/文字列を返す直前にも同じ時計とsignalで再検査する。

import {
  KMS_LIMITS,
  KmsSealingError,
  createKmsSealingCodec,
  ownerBindingFromHash,
  ownerBindingFromId,
  type KmsSealingBinding,
  type KmsSealingConfig,
  type KmsSealingOperation,
} from '../protection/kms-sealing.js';
import { SHARED_OIDC_MODELS, isConnectNamespace, type ConnectSealingContext, type ConnectSealingPort } from './firestore.js';

/** 各seal/openの開始時に1回だけ同期で呼び、その要求のdeadlineAt/signalを返す。要求間で値を共有・キャッシュしない。 */
export type ConnectKmsOperationSource = () => KmsSealingOperation;

export interface ConnectKmsSealingPortOptions {
  /** codec設定。namespaceは接続保存のnamespace（isConnectNamespace）で、purpose照合とAADの両方に使う。 */
  readonly kms: KmsSealingConfig;
  readonly operation: ConnectKmsOperationSource;
}

const CONFIG_KEYS = [
  'environment',
  'projectId',
  'databaseId',
  'namespace',
  'cryptoKey',
  'writeVersion',
  'readVersions',
  'transport',
  'clock',
] as const;
const OIDC_CONTEXT_KEYS = ['kind', 'model', 'recordId', 'ownerHash'] as const;
const OWNER_UID_CONTEXT_KEYS = ['kind', 'ownerId'] as const;

function invalid(): KmsSealingError {
  return new KmsSealingError('invalid_input');
}

/** 自分のdata propertyだけを1回読む（getter・継承・symbol・余分なkeyをexactの時に受けない）。 */
function ownData(value: unknown, keys: readonly string[], exact: boolean): Map<string, unknown> {
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

/** 孤立したsurrogateを含まない（UTF-8へ置換なしで往復できる）文字列か。 */
function wellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** 文字列全体をBufferにする前に、正確なUTF-8であることとbyte上限を確かめる。 */
function utf8Of(text: unknown): Buffer {
  if (typeof text !== 'string' || text.length > KMS_LIMITS.plaintextBytes || !wellFormed(text)) throw invalid();
  if (Buffer.byteLength(text, 'utf8') > KMS_LIMITS.plaintextBytes) throw invalid();
  return Buffer.from(text, 'utf8');
}

/** 開封したBufferをfatalなUTF-8で文字列にする（BOMも値として残す）。不正なUTF-8は完全性の不備。 */
function textOf(plaintext: Buffer): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
  } catch {
    throw new KmsSealingError('integrity_failed');
  }
}

/** codecの固定errorだけを外へ出す。それ以外の例外は元のmessage・causeを転記せずunavailableにする。 */
function fixedError(error: unknown): KmsSealingError {
  return error instanceof KmsSealingError ? error : new KmsSealingError('unavailable');
}

export function createConnectKmsSealingPort(options: ConnectKmsSealingPortOptions): ConnectSealingPort {
  const fields = ownData(options, ['kms', 'operation'], false);
  const operationInput = fields.get('operation');
  if (typeof operationInput !== 'function') throw invalid();
  const operationSource: Function = operationInput;
  // 設定は1回だけ読んでコピーし、同じnamespaceをcodecのAADとpurpose照合の両方へ使う。
  const kmsFields = ownData(fields.get('kms'), CONFIG_KEYS, false);
  const namespace = kmsFields.get('namespace');
  if (!isConnectNamespace(namespace)) throw invalid();
  // 時計のnowを1回だけ捕捉し、codecとadapterが同じ関数で時刻を読む。
  const clockTarget = kmsFields.get('clock');
  if (typeof clockTarget !== 'object' || clockTarget === null) throw invalid();
  const clockMethodInput: unknown = (clockTarget as Record<string, unknown>).now;
  if (typeof clockMethodInput !== 'function') throw invalid();
  const clockMethod: Function = clockMethodInput;
  const clockNow = (): unknown => Reflect.apply(clockMethod, clockTarget, []);
  kmsFields.set('clock', Object.freeze({ now: clockNow }));
  const codec = createKmsSealingCodec(Object.fromEntries(kmsFields) as unknown as KmsSealingConfig);
  const oidcPrefix = `t256:${namespace}:oidc:`;
  const ownerUidPrefix = `t256:${namespace}:owner-uid:`;

  /** 読めない・有限でない時計は残りのないもの（timed_out）として扱い、元の例外を外へ出さない。 */
  const now = (): number => {
    try {
      const value = clockNow();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };

  /**
   * operationを1回だけ呼び、deadlineAt/signalを不変の値として捕捉する。adapter全体の期限は元のdeadlineと、
   * 取得直後（binding・UTF-8の準備前）の時刻+5000msの短い方。同じ期限と外部signalをcodecにも渡す。
   */
  function captureOperation(): KmsSealingOperation {
    let value: unknown;
    try {
      value = Reflect.apply(operationSource, undefined, []);
    } catch {
      throw new KmsSealingError('unavailable');
    }
    const got = ownData(value, ['deadlineAt', 'signal'], false);
    const deadlineAt = got.get('deadlineAt');
    const signalInput = got.get('signal');
    if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt)) throw invalid();
    if (signalInput !== undefined && !(signalInput instanceof AbortSignal)) throw invalid();
    const signal = signalInput as AbortSignal | undefined;
    if (signal?.aborted) throw new KmsSealingError('aborted');
    const startedAt = now();
    // 時計の観測中に起きた中止も見る。
    if (signal?.aborted) throw new KmsSealingError('aborted');
    if (!Number.isFinite(startedAt)) throw new KmsSealingError('timed_out');
    const effective = Math.min(deadlineAt, Math.floor(startedAt) + KMS_LIMITS.callTimeoutMs);
    if (!(startedAt < effective)) throw new KmsSealingError('timed_out');
    return Object.freeze({ deadlineAt: effective, signal });
  }

  /** 結果（capsule・文字列）を公開する直前の、最新のsignal→clock→signalの再検査。 */
  function assertLive(operation: KmsSealingOperation): void {
    if (operation.signal?.aborted) throw new KmsSealingError('aborted');
    const at = now();
    if (operation.signal?.aborted) throw new KmsSealingError('aborted');
    if (!(at < operation.deadlineAt)) throw new KmsSealingError('timed_out');
  }

  /** storageのcontextと、保存済みデータが使うpurpose文字列（`t256:<namespace>:oidc:`・`t256:<namespace>:owner-uid:`）の完全一致から、codecのbindingを作る（通信前に検査）。 */
  function bindingOf(purpose: unknown, context: unknown): KmsSealingBinding {
    const kind = ownData(context, ['kind'], false).get('kind');
    if (kind === 'oidc') {
      const got = ownData(context, OIDC_CONTEXT_KEYS, true);
      const model = got.get('model');
      const recordId = got.get('recordId');
      const ownerHash = got.get('ownerHash');
      if (typeof model !== 'string' || !SHARED_OIDC_MODELS.has(model)) throw invalid();
      if (typeof recordId !== 'string' || purpose !== oidcPrefix + recordId) throw invalid();
      // ownerのnullは未ログインのmodelだけ（判定はcodecが通信前に行う）。
      const ownerBinding = ownerHash === null ? null : ownerBindingFromHash(ownerHash as string);
      return { purpose: 'oidc', model, recordId, ownerBinding, secretHash: null };
    }
    if (kind === 'owner-uid') {
      const ownerId = ownData(context, OWNER_UID_CONTEXT_KEYS, true).get('ownerId');
      const ownerBinding = ownerBindingFromId(ownerId as string);
      if (purpose !== ownerUidPrefix + (ownerId as string)) throw invalid();
      return { purpose: 'owner-uid', model: 'Owner', recordId: ownerId as string, ownerBinding, secretHash: null };
    }
    throw invalid();
  }

  async function seal(purpose: string, plaintext: string, context?: ConnectSealingContext): Promise<string> {
    let input: Buffer | undefined;
    try {
      const operation = captureOperation();
      const binding = bindingOf(purpose, context);
      input = utf8Of(plaintext);
      const capsule = await codec.seal(binding, input, operation);
      // codecの検査の後、このawaitの継続までに期限/中止が来得るので、capsuleを返す直前にもう一度見る。
      assertLive(operation);
      return capsule;
    } catch (error) {
      throw fixedError(error);
    } finally {
      input?.fill(0);
    }
  }

  async function open(purpose: string, sealed: string, context?: ConnectSealingContext): Promise<string> {
    let plaintext: Buffer | undefined;
    try {
      const operation = captureOperation();
      const binding = bindingOf(purpose, context);
      plaintext = await codec.open(binding, sealed, operation);
      const text = textOf(plaintext);
      // 文字列にした後、返す直前の再検査。不成立なら開封Bufferはfinallyでzeroする。
      assertLive(operation);
      return text;
    } catch (error) {
      throw fixedError(error);
    } finally {
      plaintext?.fill(0);
    }
  }

  return Object.freeze({ seal, open });
}
