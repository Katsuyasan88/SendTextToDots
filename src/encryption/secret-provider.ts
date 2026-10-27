// 本文暗号化の専用保護鍵（Secret Manager、配置設定で許可した同一secretの固定数値版だけ）の遅延読取り。
//   - 読む版は配置設定のreadSecretVersions（writeSecretVersionを含む最大3）だけ。DBの値から任意のresource名を組み立てる口は無い。
//   - 要求ごとのsession内だけでmemoし、版ごとに最大1回読む。dispose（finally）で全Bufferを0埋めする。process横断のcacheは無い。
//   - 秘密の実値は32byteのcanonical base64url（43 ASCII）。形が違えば固定のEncryptionSecretError（値・原因を持たない）。
//   - 暗号化offの配置ではこのproviderを作らない（Secret読取り0）。
// 実際のSecret Manager呼出しはEncryptionSecretSource（借用SDK clientのadapter）へ委ね、ここは版の許可・memo・decode・清掃だけ。

import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import { crc32c } from '../protection/kms-sealing.js';
import {
  bytesOf,
  captureClock,
  captureInnerApiCall,
  closeScope,
  createCallScope,
  GoogleSdkPortError,
  isEpochMs,
  isRealSignal,
  ownedCopy,
  ownValue,
  runSdkCall,
  SDK_CALL_LIMIT_MS,
  uint32Of,
  zero,
} from '../protection/google-sdk-call.js';
import { canonicalBase64url } from './contract.js';
import { PROTECTION_KEY_BYTES } from './crypto.js';

/** 専用secretのpayload（43 ASCII）より十分大きいが既存上限（64KiB）より小さい読取り上限。 */
const PAYLOAD_LIMIT = 1024;
const SECRET_NAME = /^projects\/[1-9][0-9]{0,19}\/secrets\/[A-Za-z0-9_-]{1,255}$/;

export interface GoogleEncryptionSecretSourceOptions {
  /** callerが`initialize()`を完了させた借用client（adapterは初期化・closeしない）。 */
  readonly client: SecretManagerServiceClient;
  readonly policy: EncryptionSecretPolicy;
  readonly clock: { now(): number };
}

export interface GoogleEncryptionSecretSource extends EncryptionSecretSource {
  /** 同期・冪等。進行中をcancelして固定closed、以後の新RPC0。借用clientは閉じない。 */
  dispose(): void;
}

/**
 * 固定の公式SDK（@google-cloud/secret-manager）の借用clientのinnerApiCalls.accessSecretVersionで、配置設定が許可した専用secretの
 * 固定数値版だけを1回読む。既存のgoogle-sdk-call（retry:null・元期限と開始+5000msの短い方・routing header・cancel・late cleanup）を共用し、
 * 応答のname一致とCRC32C一致を必須にする。成功copyの所有をcallerへ移し、SDKのbytesは（lateを含め）0埋めする。
 * 既存4用途のreader（google-secret-reader.ts）には新しい必須秘密を追加しない。
 */
export function createGoogleEncryptionSecretSource(options: GoogleEncryptionSecretSourceOptions): GoogleEncryptionSecretSource {
  const { policy } = options;
  if (typeof policy.secret !== 'string' || !SECRET_NAME.test(policy.secret)) throw new EncryptionSecretError();
  const allowed = new Set(policy.readSecretVersions.map((version) => `${policy.secret}/versions/${version}`));
  const accessCall = captureInnerApiCall(options.client, 'accessSecretVersion');
  const now = captureClock(options.clock);
  const scope = createCallScope();
  return Object.freeze({
    async read(name: string, operation: EncryptionSecretOperation): Promise<Buffer> {
      if (scope.closed) throw new GoogleSdkPortError('closed');
      if (!allowed.has(name)) throw new EncryptionSecretError();
      if (!isEpochMs(operation.deadlineAt) || !isRealSignal(operation.signal)) throw new EncryptionSecretError();
      if (operation.signal.aborted) throw new GoogleSdkPortError('aborted');
      const startedAt = now();
      if (startedAt === null) throw new GoogleSdkPortError('unavailable');
      const capped = startedAt + SDK_CALL_LIMIT_MS;
      if (!isEpochMs(capped)) throw new GoogleSdkPortError('unavailable');
      return runSdkCall<Buffer>(scope, {
        call: accessCall,
        request: { name },
        routingName: name,
        deadline: Math.min(operation.deadlineAt, capped),
        signal: operation.signal,
        now,
        owned: [],
        normalize: (response) => {
          const payload = ownValue(response, 'payload');
          const bytes = bytesOf(ownValue(payload, 'data'));
          const crc = uint32Of(ownValue(payload, 'dataCrc32c'));
          const ok = ownValue(response, 'name') === name && bytes !== null && bytes.length >= 1 && bytes.length <= PAYLOAD_LIMIT && crc !== null && crc32c(bytes) === crc;
          if (!ok || bytes === null) throw new GoogleSdkPortError('integrity_failed');
          return ownedCopy(bytes);
        },
        discard: (response) => zero(ownValue(ownValue(response, 'payload'), 'data')),
        release: (value) => value.fill(0),
      });
    },
    dispose: () => closeScope(scope),
  });
}

export class EncryptionSecretError extends Error {
  override readonly name = 'EncryptionSecretError';
  constructor() {
    super('encryption secret is unavailable');
  }
}

export interface EncryptionSecretOperation {
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

/** 完全名の固定数値版を1回読む（成功Bufferの所有をcallerへ移す）。 */
export interface EncryptionSecretSource {
  read(versionName: string, operation: EncryptionSecretOperation): Promise<Buffer>;
}

export interface EncryptionSecretPolicy {
  /** projects/{projectNumber}/secrets/{secretId}（版を含まない）。 */
  readonly secret: string;
  readonly writeSecretVersion: number;
  readonly readSecretVersions: readonly number[];
}

/** 1要求の保護鍵session。get(版)は許可版だけ、版ごとに最大1読取り。disposeで0埋め。 */
export interface EncryptionSecretSession {
  readonly writeVersion: number;
  get(version: number): Promise<Buffer>;
  dispose(): void;
}

export interface EncryptionSecretProvider {
  open(operation: EncryptionSecretOperation): EncryptionSecretSession;
}

export function createEncryptionSecretProvider(source: EncryptionSecretSource, policy: EncryptionSecretPolicy): EncryptionSecretProvider {
  const allowed = new Map<number, string>(policy.readSecretVersions.map((version) => [version, `${policy.secret}/versions/${version}`]));
  if (!allowed.has(policy.writeSecretVersion)) throw new EncryptionSecretError();
  return Object.freeze({
    open(operation: EncryptionSecretOperation): EncryptionSecretSession {
      const memo = new Map<number, Promise<Buffer>>();
      const owned: Buffer[] = [];
      let disposed = false;
      async function load(name: string): Promise<Buffer> {
        let raw: Buffer | null = null;
        try {
          raw = await source.read(name, operation);
        } catch {
          throw new EncryptionSecretError();
        }
        try {
          if (disposed) throw new EncryptionSecretError();
          const text = raw.length === 43 ? raw.toString('latin1') : '';
          const key = canonicalBase64url(text, 43);
          if (key === null || key.length !== PROTECTION_KEY_BYTES) {
            key?.fill(0);
            throw new EncryptionSecretError();
          }
          owned.push(key);
          return key;
        } finally {
          raw.fill(0);
        }
      }
      return Object.freeze({
        writeVersion: policy.writeSecretVersion,
        get(version: number): Promise<Buffer> {
          if (disposed) return Promise.reject(new EncryptionSecretError());
          const name = allowed.get(version);
          if (name === undefined) return Promise.reject(new EncryptionSecretError());
          let pending = memo.get(version);
          if (pending === undefined) {
            pending = load(name);
            memo.set(version, pending);
          }
          return pending;
        },
        dispose(): void {
          disposed = true;
          for (const key of owned) key.fill(0);
          owned.length = 0;
        },
      });
    },
  });
}
