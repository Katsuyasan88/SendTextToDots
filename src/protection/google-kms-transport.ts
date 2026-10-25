// KmsTransport（protection/kms-sealing.ts）を、固定の公式SDK @google-cloud/kms 6.3.0の初期化済み借用
// KeyManagementServiceClientのinnerApiCalls.encrypt/decrypt（google-gax 6.5.0のcancel付きcall）へ接ぐ。
// 1回のcallでRPC1回・retry:null・残り時間のtimeout・routing headerだけ。requestは所有copy（callerのBufferは0埋めしない）、
// 応答はtupleの第1要素だけを正規化（bytes/CRC32C int64/SOFTWARE/名前/verified）して別の所有Bufferをcodecへ移し、SDKのbytesは
// lateを含め必ず0埋めする。正規化後もcodec側の検査は省かれない。借用client/SDKをclose/terminate/dispose0、RPC・鍵取得・初期化をfactoryで行わない。
// 実Google（標準endpoint/TLS・SA・IAM）への接続はSDK起動口（google-runtime/development.ts）の責任。

import { types } from 'node:util';
import type { KeyManagementServiceClient } from '@google-cloud/kms';
import {
  crc32c,
  KMS_LIMITS,
  KMS_REGION_PATTERN,
  type KmsCallOptions,
  type KmsDecryptRequest,
  type KmsDecryptResponse,
  type KmsEncryptRequest,
  type KmsEncryptResponse,
  type KmsTransport,
} from './kms-sealing.js';
import {
  arrayItems,
  bytesOf,
  captureClock,
  captureInnerApiCall,
  closeScope,
  createCallScope,
  dataFields,
  GoogleSdkPortError,
  hasOwnData,
  invalid,
  isEpochMs,
  isRealSignal,
  ownedCopy,
  ownValue,
  runSdkCall,
  SDK_CALL_LIMIT_MS,
  uint32Of,
  zero,
} from './google-sdk-call.js';

export { GoogleSdkPortError, type GoogleSdkPortErrorCode } from './google-sdk-call.js';

export interface GoogleKmsTransportOptions {
  /** callerが`initialize()`を完了させた借用client（adapterは初期化・closeしない）。 */
  readonly client: KeyManagementServiceClient;
  readonly projectId: string;
  /** projects/{projectId}/locations/{region}/keyRings/{ring}/cryptoKeys/{key} */
  readonly cryptoKey: string;
  /** 同keyの正の数値version（encryptのnameに固定）。 */
  readonly writeVersion: number;
  /** 同keyの明示allowlist（writeVersionを含む1〜8件、KMS codecと同じ）。 */
  readonly readVersions: readonly number[];
  readonly clock: { now(): number };
}

export interface GoogleKmsTransport extends KmsTransport {
  encrypt(request: KmsEncryptRequest, options: KmsCallOptions): Promise<KmsEncryptResponse>;
  decrypt(request: KmsDecryptRequest, options: KmsCallOptions): Promise<KmsDecryptResponse>;
  /** 同期・冪等。進行中をcancelして固定closed、以後の新RPC0。借用clientは閉じない。 */
  dispose(): void;
}

const OPTION_KEYS = ['client', 'projectId', 'cryptoKey', 'writeVersion', 'readVersions', 'clock'] as const;
const ENCRYPT_KEYS = ['name', 'plaintext', 'plaintextCrc32c', 'additionalAuthenticatedData', 'additionalAuthenticatedDataCrc32c'] as const;
const DECRYPT_KEYS = ['name', 'ciphertext', 'ciphertextCrc32c', 'additionalAuthenticatedData', 'additionalAuthenticatedDataCrc32c'] as const;
const CALL_KEYS = ['timeoutMs', 'signal', 'maxAttempts'] as const;
const SAFE_ASCII = /^[A-Za-z0-9_.:-]{1,256}$/;
const RESOURCE_ID = /^[A-Za-z0-9_-]{1,63}$/;
/** 固定proto google.cloud.kms.v1.ProtectionLevel.SOFTWARE。 */
const SOFTWARE_ENUM = 1;

function parseCryptoKey(value: unknown, projectId: string): string {
  if (typeof value !== 'string' || value.length > KMS_LIMITS.resourceNameBytes || !/^[\x21-\x7e]+$/.test(value) || /[?#%\\]/.test(value) || value.includes('..')) {
    throw invalid();
  }
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

function isUint32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

/** callerのBuffer（Proxy無し）。 */
function callerBuffer(value: unknown, max: number): Buffer {
  if (!Buffer.isBuffer(value) || types.isProxy(value) || value.length > max) throw invalid();
  return value;
}

/** protobuf Int64Value（KMS）の { value } からuint32。 */
function int64ValueOf(wrapper: unknown): number | null {
  if (typeof wrapper !== 'object' || wrapper === null || types.isProxy(wrapper) || !hasOwnData(wrapper, 'value')) return null;
  return uint32Of(ownValue(wrapper, 'value'));
}

function isSoftware(value: unknown): boolean {
  return value === SOFTWARE_ENUM || value === 'SOFTWARE';
}

function integrity(): GoogleSdkPortError {
  return new GoogleSdkPortError('integrity_failed');
}

function discardKey(key: string): (response: unknown) => void {
  return (response) => zero(ownValue(response, key));
}

export function createGoogleKmsTransport(options: GoogleKmsTransportOptions): GoogleKmsTransport {
  const fields = dataFields(options, OPTION_KEYS);
  const projectId = fields.get('projectId');
  if (typeof projectId !== 'string' || !SAFE_ASCII.test(projectId) || /^\.+$/.test(projectId)) throw invalid();
  const cryptoKey = parseCryptoKey(fields.get('cryptoKey'), projectId);
  const writeVersion = fields.get('writeVersion');
  if (!isVersionNumber(writeVersion)) throw invalid();
  const readList = arrayItems(fields.get('readVersions'));
  if (readList.length < 1 || readList.length > KMS_LIMITS.readVersions || !readList.every(isVersionNumber)) throw invalid();
  const readVersions = new Set(readList as number[]);
  if (readVersions.size !== readList.length || !readVersions.has(writeVersion)) throw invalid();
  const writeName = `${cryptoKey}/cryptoKeyVersions/${writeVersion}`;
  if (writeName.length > KMS_LIMITS.resourceNameBytes) throw invalid();
  for (const version of readVersions) if (`${cryptoKey}/cryptoKeyVersions/${version}`.length > KMS_LIMITS.resourceNameBytes) throw invalid();

  const client = fields.get('client');
  const encryptCall = captureInnerApiCall(client, 'encrypt');
  const decryptCall = captureInnerApiCall(client, 'decrypt');
  const now = captureClock(fields.get('clock'));
  const scope = createCallScope();

  /** exact call options（timeoutMs 1..5000の安全整数・本物signal・maxAttempts 1）。 */
  function callOptions(value: unknown): { readonly timeoutMs: number; readonly signal: AbortSignal } {
    const got = dataFields(value, CALL_KEYS);
    const timeoutMs = got.get('timeoutMs');
    const signal = got.get('signal');
    if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > SDK_CALL_LIMIT_MS) throw invalid();
    if (!isRealSignal(signal) || got.get('maxAttempts') !== 1) throw invalid();
    return { timeoutMs, signal };
  }

  /** 開始時の安全な時計で元期限=start+timeoutMsを一度だけ決める。 */
  function deadlineOf(timeoutMs: number, signal: AbortSignal): number {
    if (scope.closed) throw new GoogleSdkPortError('closed');
    if (signal.aborted) throw new GoogleSdkPortError('aborted');
    const startedAt = now();
    if (scope.closed) throw new GoogleSdkPortError('closed');
    if (signal.aborted) throw new GoogleSdkPortError('aborted');
    if (startedAt === null) throw new GoogleSdkPortError('unavailable');
    // 加算後もDateの範囲内の時だけ（範囲外は新timer/RPCの前に非成功）。
    const deadline = startedAt + timeoutMs;
    if (!isEpochMs(deadline)) throw new GoogleSdkPortError('unavailable');
    return deadline;
  }

  async function encrypt(requestInput: KmsEncryptRequest, optionsInput: KmsCallOptions): Promise<KmsEncryptResponse> {
    if (scope.closed) throw new GoogleSdkPortError('closed');
    const got = dataFields(requestInput, ENCRYPT_KEYS);
    const { timeoutMs, signal } = callOptions(optionsInput);
    if (got.get('name') !== writeName) throw invalid();
    const plaintextIn = callerBuffer(got.get('plaintext'), KMS_LIMITS.plaintextBytes);
    const aadIn = callerBuffer(got.get('additionalAuthenticatedData'), KMS_LIMITS.aadBytes);
    const plaintextCrc = got.get('plaintextCrc32c');
    const aadCrc = got.get('additionalAuthenticatedDataCrc32c');
    if (!isUint32(plaintextCrc) || !isUint32(aadCrc) || crc32c(plaintextIn) !== plaintextCrc || crc32c(aadIn) !== aadCrc) throw invalid();
    const deadline = deadlineOf(timeoutMs, signal);
    const plaintext = ownedCopy(plaintextIn);
    const aad = ownedCopy(aadIn);
    return runSdkCall<KmsEncryptResponse>(scope, {
      call: encryptCall,
      request: {
        name: writeName,
        plaintext,
        additionalAuthenticatedData: aad,
        plaintextCrc32c: { value: plaintextCrc },
        additionalAuthenticatedDataCrc32c: { value: aadCrc },
      },
      routingName: writeName,
      deadline,
      signal,
      now,
      owned: [plaintext, aad],
      normalize: (response) => {
        const bytes = bytesOf(ownValue(response, 'ciphertext'));
        const crc = int64ValueOf(ownValue(response, 'ciphertextCrc32c'));
        const ok =
          ownValue(response, 'name') === writeName &&
          ownValue(response, 'verifiedPlaintextCrc32c') === true &&
          ownValue(response, 'verifiedAdditionalAuthenticatedDataCrc32c') === true &&
          isSoftware(ownValue(response, 'protectionLevel')) &&
          bytes !== null &&
          bytes.length >= 1 &&
          bytes.length <= KMS_LIMITS.ciphertextBytes &&
          crc !== null &&
          crc32c(bytes) === crc;
        if (!ok || bytes === null || crc === null) throw integrity();
        return Object.freeze({
          name: writeName,
          ciphertext: ownedCopy(bytes),
          ciphertextCrc32c: crc,
          verifiedPlaintextCrc32c: true,
          verifiedAdditionalAuthenticatedDataCrc32c: true,
          protectionLevel: 'SOFTWARE',
        });
      },
      discard: discardKey('ciphertext'),
      release: (value) => value.ciphertext.fill(0),
    });
  }

  async function decrypt(requestInput: KmsDecryptRequest, optionsInput: KmsCallOptions): Promise<KmsDecryptResponse> {
    if (scope.closed) throw new GoogleSdkPortError('closed');
    const got = dataFields(requestInput, DECRYPT_KEYS);
    const { timeoutMs, signal } = callOptions(optionsInput);
    // decryptのnameは固定CryptoKeyだけ（capsule内の任意resourceへ接続しない。versionはKMSが暗号文から選ぶ）。
    if (got.get('name') !== cryptoKey) throw invalid();
    const ciphertextIn = callerBuffer(got.get('ciphertext'), KMS_LIMITS.ciphertextBytes);
    const aadIn = callerBuffer(got.get('additionalAuthenticatedData'), KMS_LIMITS.aadBytes);
    if (ciphertextIn.length < 1) throw invalid();
    const ciphertextCrc = got.get('ciphertextCrc32c');
    const aadCrc = got.get('additionalAuthenticatedDataCrc32c');
    if (!isUint32(ciphertextCrc) || !isUint32(aadCrc) || crc32c(ciphertextIn) !== ciphertextCrc || crc32c(aadIn) !== aadCrc) throw invalid();
    const deadline = deadlineOf(timeoutMs, signal);
    const ciphertext = ownedCopy(ciphertextIn);
    const aad = ownedCopy(aadIn);
    return runSdkCall<KmsDecryptResponse>(scope, {
      call: decryptCall,
      request: {
        name: cryptoKey,
        ciphertext,
        additionalAuthenticatedData: aad,
        ciphertextCrc32c: { value: ciphertextCrc },
        additionalAuthenticatedDataCrc32c: { value: aadCrc },
      },
      routingName: cryptoKey,
      deadline,
      signal,
      now,
      owned: [ciphertext, aad],
      normalize: (response) => {
        const bytes = bytesOf(ownValue(response, 'plaintext'));
        const crc = int64ValueOf(ownValue(response, 'plaintextCrc32c'));
        const usedPrimary = ownValue(response, 'usedPrimary');
        const ok =
          isSoftware(ownValue(response, 'protectionLevel')) &&
          (usedPrimary === undefined || typeof usedPrimary === 'boolean') &&
          bytes !== null &&
          bytes.length <= KMS_LIMITS.plaintextBytes &&
          crc !== null &&
          crc32c(bytes) === crc;
        if (!ok || bytes === null || crc === null) throw integrity();
        const plaintext = ownedCopy(bytes);
        return Object.freeze(
          typeof usedPrimary === 'boolean'
            ? { plaintext, plaintextCrc32c: crc, usedPrimary, protectionLevel: 'SOFTWARE' }
            : { plaintext, plaintextCrc32c: crc, protectionLevel: 'SOFTWARE' },
        );
      },
      discard: discardKey('plaintext'),
      release: (value) => value.plaintext.fill(0),
    });
  }

  return Object.freeze({
    encrypt,
    decrypt,
    dispose: () => closeScope(scope),
  });
}
