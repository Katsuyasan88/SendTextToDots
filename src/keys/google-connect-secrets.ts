// KMS接続serverのKmsConnectSecretSourceとしてのload。借用したGoogleSecretReaderのreadで、jwks→cookieKeys→identifierKeyを
// 各1回・逐次に、loadごとに1回作る元5秒のoperation（同じ期限/signal）で取得する。commandDigestKeyはこのloadでは取得0。
// 生成・fallback・cache0。後着は採用せず0埋め、部分成功でも失敗なら所有する全Bufferを0埋めする。成功はfrozen {jwks,cookieKeys,identifierKey}
// で各Bufferの所有をcallerへ移す。秘密を出力・永続化しない。readerをclose/disposeしない。
// secret形式: jwksはfatal UTF-8/JSONの{keys:[private ES256, private RS256]}（serverのcopyKeysと同じ2鍵/各field string/
// alg・kty・crv・dの条件）、cookieKeysは32byte鍵を順に連結したraw bytes（32の正倍数）、identifierKeyはraw 32byte。
// JWKのJS文字列（JSON本文・復号文字列を含む）やSDK/OS内部のcopyの完全消去は保証しない。所有する元payload/部分Bufferはfinallyで0埋めする。

import type { JWKS } from 'oidc-provider';
import type { KmsConnectKeys, KmsConnectSecretSource } from '../connect/kms-server.js';
import { captureClock, dataFields, GoogleSdkPortError, type GoogleSdkPortErrorCode, isEpochMs, methodOf, zero } from '../protection/google-sdk-call.js';
import type { GoogleSecretPurpose, GoogleSecretReadOperation } from './google-secret-reader.js';

export { GoogleSdkPortError, type GoogleSdkPortErrorCode } from '../protection/google-sdk-call.js';

export interface GoogleConnectSecretSourceOptions {
  /** createGoogleSecretReaderの借用reader（readだけを使う。dispose0）。 */
  readonly reader: { read(purpose: GoogleSecretPurpose, operation: GoogleSecretReadOperation): Promise<Buffer> };
  readonly clock: { now(): number };
}

export interface GoogleConnectSecretSource extends KmsConnectSecretSource {
  load(): Promise<KmsConnectKeys>;
  /** 同期・冪等。進行中のloadを中止（固定closed）、以後のload0。readerは閉じない。 */
  dispose(): void;
}

/** 起動時の秘密読込み全体の元期限（起動load最大5秒と同じ）。 */
export const GOOGLE_CONNECT_SECRET_LOAD_MS = 5000;
const KEY_BYTES = 32;
const LOAD_ORDER = ['jwks', 'cookieKeys', 'identifierKey'] as const;

function malformed(): GoogleSdkPortError {
  return new GoogleSdkPortError('integrity_failed');
}

/** jwksのpayload（fatal UTF-8のJSON）を、serverのcopyKeysと同じ条件で検査して新しいobjectへ写す。 */
function parseJwks(raw: Buffer): JWKS {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(raw));
  } catch {
    throw malformed();
  }
  let listed: unknown;
  try {
    listed = dataFields(parsed, ['keys']).get('keys');
  } catch {
    throw malformed();
  }
  if (!Array.isArray(listed) || listed.length !== 2) throw malformed();
  const keys: Record<string, string>[] = [];
  const algs = new Set<string>();
  for (const entry of listed as unknown[]) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry) || Object.getPrototypeOf(entry) !== Object.prototype) throw malformed();
    const copy: Record<string, string> = {};
    for (const key of Object.keys(entry)) {
      const value = (Object.getOwnPropertyDescriptor(entry, key) as PropertyDescriptor).value as unknown;
      // JSON.parseは"__proto__"もown propertyにする。写しの代入でprototypeを変えないよう拒否する。
      if (key === '__proto__' || typeof value !== 'string') throw malformed();
      Object.defineProperty(copy, key, { value, enumerable: true, writable: true, configurable: true });
    }
    const alg = copy.alg;
    if (alg !== 'ES256' && alg !== 'RS256') throw malformed();
    if (typeof copy.d !== 'string' || copy.d === '') throw malformed();
    if (alg === 'ES256' ? copy.kty !== 'EC' || copy.crv !== 'P-256' : copy.kty !== 'RSA') throw malformed();
    algs.add(alg);
    keys.push(Object.freeze(copy) as Record<string, string>);
  }
  if (algs.size !== 2) throw malformed();
  return Object.freeze({ keys: Object.freeze(keys) }) as unknown as JWKS;
}

/** 32byte鍵を順に連結したraw bytesを、各32byteの所有Bufferへ分ける。 */
function splitCookieKeys(raw: Buffer): Buffer[] {
  if (raw.length < KEY_BYTES || raw.length % KEY_BYTES !== 0) throw malformed();
  const out: Buffer[] = [];
  for (let offset = 0; offset < raw.length; offset += KEY_BYTES) {
    const key = Buffer.alloc(KEY_BYTES);
    raw.copy(key, 0, offset, offset + KEY_BYTES);
    out.push(key);
  }
  return out;
}

export function createGoogleConnectSecretSource(options: GoogleConnectSecretSourceOptions): GoogleConnectSecretSource {
  const fields = dataFields(options, ['reader', 'clock']);
  const read = methodOf(fields.get('reader'), 'read');
  const now = captureClock(fields.get('clock'));
  let closed = false;
  const active = new Set<(code: GoogleSdkPortErrorCode) => void>();

  async function load(): Promise<KmsConnectKeys> {
    if (closed) throw new GoogleSdkPortError('closed');
    const startedAt = now();
    if (closed) throw new GoogleSdkPortError('closed');
    if (startedAt === null) throw new GoogleSdkPortError('unavailable');
    // 加算後もDateの範囲内の時だけ（範囲外は新timer/readの前に非成功）。
    const deadlineAt = startedAt + GOOGLE_CONNECT_SECRET_LOAD_MS;
    if (!isEpochMs(deadlineAt)) throw new GoogleSdkPortError('unavailable');
    const controller = new AbortController();
    const operation: GoogleSecretReadOperation = Object.freeze({ deadlineAt, signal: controller.signal });
    /** loadが所有するBuffer（read結果・分割後の鍵）。失敗時は全て0埋め。 */
    const owned: Buffer[] = [];
    let stopCode: GoogleSdkPortErrorCode | null = null;
    let wake: (() => void) | null = null;
    const stop = (code: GoogleSdkPortErrorCode): void => {
      if (stopCode !== null) return;
      stopCode = code;
      controller.abort();
      wake?.();
    };
    const timer = setTimeout(() => stop('timed_out'), GOOGLE_CONNECT_SECRET_LOAD_MS);
    active.add(stop);

    /** stop→clock→stopの順で、まだ続けてよいか。 */
    const assertLive = (): void => {
      if (stopCode !== null) throw new GoogleSdkPortError(stopCode);
      const at = now();
      if (stopCode !== null) throw new GoogleSdkPortError(stopCode);
      if (at === null) {
        stop('unavailable');
        throw new GoogleSdkPortError('unavailable');
      }
      if (!(at < deadlineAt)) {
        stop('timed_out');
        throw new GoogleSdkPortError('timed_out');
      }
    };

    /**
     * 1回のread。中止/期限で待機を打ち切り、後着のBufferは0埋めする。readが同期にdispose/時計更新して
     * pendingを返した場合も、後始末handlerを付けた直後に停止/時計を検査して待機を解放する（元5秒のtimerを待たない）。
     */
    const readOnce = (purpose: (typeof LOAD_ORDER)[number]): Promise<Buffer> => {
      assertLive();
      let pending: Promise<unknown>;
      try {
        pending = Promise.resolve(read(purpose, operation));
      } catch {
        return Promise.reject(new GoogleSdkPortError('unavailable'));
      }
      return new Promise<Buffer>((resolve, reject) => {
        let done = false;
        const release = (code: GoogleSdkPortErrorCode): void => {
          if (done) return;
          done = true;
          reject(new GoogleSdkPortError(code));
        };
        wake = () => release(stopCode ?? 'aborted');
        pending.then(
          (value) => {
            if (done || stopCode !== null) {
              zero(value);
              if (!done) {
                done = true;
                reject(new GoogleSdkPortError(stopCode ?? 'aborted'));
              }
              return;
            }
            done = true;
            if (!Buffer.isBuffer(value)) {
              zero(value);
              reject(malformed());
              return;
            }
            owned.push(value);
            resolve(value);
          },
          (error: unknown) => {
            if (done) return;
            done = true;
            reject(new GoogleSdkPortError(stopCode ?? (error instanceof GoogleSdkPortError ? error.code : 'unavailable')));
          },
        );
        // 後始末handlerを付けた後で、read中の同期のdispose/中止・時計の更新を検査する（stop→clock→stop）。
        if (stopCode !== null) return release(stopCode);
        const at = now();
        if (stopCode !== null) return release(stopCode);
        if (at === null) return stop('unavailable');
        if (!(at < deadlineAt)) return stop('timed_out');
      });
    };

    let success = false;
    try {
      const jwksRaw = await readOnce(LOAD_ORDER[0]);
      assertLive();
      const jwks = parseJwks(jwksRaw);
      const cookieRaw = await readOnce(LOAD_ORDER[1]);
      assertLive();
      const cookieKeys = splitCookieKeys(cookieRaw);
      owned.push(...cookieKeys);
      const identifierKey = await readOnce(LOAD_ORDER[2]);
      assertLive();
      if (identifierKey.length !== KEY_BYTES) throw malformed();
      // 所有をcallerへ移す直前の再検査。
      assertLive();
      success = true;
      jwksRaw.fill(0);
      cookieRaw.fill(0);
      return Object.freeze({ jwks, cookieKeys: Object.freeze(cookieKeys) as unknown as readonly Buffer[], identifierKey });
    } catch (error) {
      // 元の例外・causeを持ち越さない固定の失敗へ写す。
      throw new GoogleSdkPortError(error instanceof GoogleSdkPortError ? error.code : 'unavailable');
    } finally {
      clearTimeout(timer);
      active.delete(stop);
      wake = null;
      if (stopCode === null) controller.abort();
      if (!success) for (const buffer of owned) buffer.fill(0);
    }
  }

  return Object.freeze({
    load,
    dispose: () => {
      if (closed) return;
      closed = true;
      for (const stop of [...active]) stop('closed');
    },
  });
}
