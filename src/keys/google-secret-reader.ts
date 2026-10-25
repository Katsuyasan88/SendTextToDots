// 固定の公式SDK @google-cloud/secret-manager 7.2.0の初期化済み借用SecretManagerServiceClientの
// innerApiCalls.accessSecretVersion（google-gax 6.5.0のcancel付きcall）で、用途ごとに固定した数値版の秘密を1回だけ読む。
// 4用途（jwks・cookieKeys・identifierKey・commandDigestKey）は別secret、名前は同じ正規10進projectNumberのglobal resource形式の完全名だけ
// （latest/alias/regional/caller指定名0）。要求/応答とも固定numberの完全名を照合する（projectIdとの対応は配置設定 src/config/deployment.ts の非秘密値）。
// 1回のreadにaccess1・retry:null・残り時間のtimeout・routing headerだけ。payloadはCRC32C必須・一致、成功copyの所有をcallerへ移し
// SDKのbytesは（lateを含め）0埋め。値の共有cache・永続化・出力0。借用clientをclose/terminate0。payloadの内容は解釈しない。

import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { crc32c } from '../protection/kms-sealing.js';
import {
  bytesOf,
  captureClock,
  captureInnerApiCall,
  closeScope,
  createCallScope,
  dataFields,
  GoogleSdkPortError,
  invalid,
  isEpochMs,
  isRealSignal,
  ownedCopy,
  ownValue,
  runSdkCall,
  SDK_CALL_LIMIT_MS,
  uint32Of,
  zero,
} from '../protection/google-sdk-call.js';

export { GoogleSdkPortError, type GoogleSdkPortErrorCode } from '../protection/google-sdk-call.js';

export type GoogleSecretPurpose = 'jwks' | 'cookieKeys' | 'identifierKey' | 'commandDigestKey';

export const GOOGLE_SECRET_PURPOSES: readonly GoogleSecretPurpose[] = Object.freeze(['jwks', 'cookieKeys', 'identifierKey', 'commandDigestKey']);

/** Secret Managerのpayload上限（64KiB）。 */
export const GOOGLE_SECRET_PAYLOAD_LIMIT = 65_536;

export interface GoogleSecretVersions {
  /** projects/{projectNumber}/secrets/{secretId}/versions/{正の数値版} */
  readonly jwks: string;
  readonly cookieKeys: string;
  readonly identifierKey: string;
  readonly commandDigestKey: string;
}

export interface GoogleSecretReaderOptions {
  /** callerが`initialize()`を完了させた借用client（adapterは初期化・closeしない）。 */
  readonly client: SecretManagerServiceClient;
  /** 正規10進のproject number（project IDではない）。 */
  readonly projectNumber: string;
  readonly versions: GoogleSecretVersions;
  readonly clock: { now(): number };
}

export interface GoogleSecretReadOperation {
  /** 絶対期限（epoch ms、安全整数）。readは元期限と開始+5000msの短い方で打ち切る。 */
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

export interface GoogleSecretReader {
  /** 成功時の返却Bufferはcallerへ所有移転する（呼出し元が使い終えたら0埋めする）。 */
  read(purpose: GoogleSecretPurpose, operation: GoogleSecretReadOperation): Promise<Buffer>;
  /** 同期・冪等。進行中をcancelして固定closed、以後の新RPC0。借用clientは閉じない。 */
  dispose(): void;
}

const OPTION_KEYS = ['client', 'projectNumber', 'versions', 'clock'] as const;
const OPERATION_KEYS = ['deadlineAt', 'signal'] as const;
const PROJECT_NUMBER = /^[1-9][0-9]{0,19}$/;
const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
const VERSION_NUMBER = /^[1-9][0-9]{0,15}$/;

/** global resource形式の固定数値版の完全名だけ（latest/alias/regional・別project・非正規の数字を拒否）。secret IDを返す。 */
function parseVersionName(value: unknown, projectNumber: string): string {
  if (typeof value !== 'string' || value.length > 1024) throw invalid();
  const parts = value.split('/');
  if (parts.length !== 6) throw invalid();
  const [p, project, s, secretId, v, version] = parts as [string, string, string, string, string, string];
  if (p !== 'projects' || project !== projectNumber || s !== 'secrets' || v !== 'versions') throw invalid();
  if (!SECRET_ID.test(secretId) || !VERSION_NUMBER.test(version) || !Number.isSafeInteger(Number(version))) throw invalid();
  return secretId;
}

export function createGoogleSecretReader(options: GoogleSecretReaderOptions): GoogleSecretReader {
  const fields = dataFields(options, OPTION_KEYS);
  const projectNumber = fields.get('projectNumber');
  if (typeof projectNumber !== 'string' || !PROJECT_NUMBER.test(projectNumber)) throw invalid();
  const versionFields = dataFields(fields.get('versions'), GOOGLE_SECRET_PURPOSES);
  const names = new Map<GoogleSecretPurpose, string>();
  const secretIds = new Set<string>();
  for (const purpose of GOOGLE_SECRET_PURPOSES) {
    const name = versionFields.get(purpose);
    secretIds.add(parseVersionName(name, projectNumber));
    names.set(purpose, name as string);
  }
  // 4用途は別secret（用途間の流用0）。
  if (secretIds.size !== GOOGLE_SECRET_PURPOSES.length) throw invalid();

  const accessCall = captureInnerApiCall(fields.get('client'), 'accessSecretVersion');
  const now = captureClock(fields.get('clock'));
  const scope = createCallScope();

  async function read(purpose: GoogleSecretPurpose, operationInput: GoogleSecretReadOperation): Promise<Buffer> {
    if (scope.closed) throw new GoogleSdkPortError('closed');
    const name = typeof purpose === 'string' && (GOOGLE_SECRET_PURPOSES as readonly string[]).includes(purpose) ? names.get(purpose) : undefined;
    if (name === undefined) throw invalid();
    const got = dataFields(operationInput, OPERATION_KEYS);
    const deadlineAt = got.get('deadlineAt');
    const signal = got.get('signal');
    if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) throw invalid();
    if (signal.aborted) throw new GoogleSdkPortError('aborted');
    const startedAt = now();
    if (scope.closed) throw new GoogleSdkPortError('closed');
    if (signal.aborted) throw new GoogleSdkPortError('aborted');
    if (startedAt === null) throw new GoogleSdkPortError('unavailable');
    // 元期限と開始+5000msの短い方を一度だけ決める（加算はDateの範囲内の時だけ）。
    const capped = startedAt + SDK_CALL_LIMIT_MS;
    if (!isEpochMs(capped)) throw new GoogleSdkPortError('unavailable');
    const deadline = Math.min(deadlineAt, capped);
    return runSdkCall<Buffer>(scope, {
      call: accessCall,
      request: { name },
      routingName: name,
      deadline,
      signal,
      now,
      owned: [],
      normalize: (response) => {
        const payload = ownValue(response, 'payload');
        const bytes = bytesOf(ownValue(payload, 'data'));
        const crc = uint32Of(ownValue(payload, 'dataCrc32c'));
        const ok =
          ownValue(response, 'name') === name &&
          bytes !== null &&
          bytes.length >= 1 &&
          bytes.length <= GOOGLE_SECRET_PAYLOAD_LIMIT &&
          crc !== null &&
          crc32c(bytes) === crc;
        if (!ok || bytes === null) throw new GoogleSdkPortError('integrity_failed');
        return ownedCopy(bytes);
      },
      discard: (response) => zero(ownValue(ownValue(response, 'payload'), 'data')),
      release: (value) => value.fill(0),
    });
  }

  return Object.freeze({
    read,
    dispose: () => closeScope(scope),
  });
}
