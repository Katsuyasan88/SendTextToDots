// 許可元の証明（wireの形と開発者要求署名）。正本はdocs/API.md「許可元の証明」。Node標準cryptoだけで、I/O・DB・SDK 0。
//   X-STTD-Source:            登録済みsource ID（両方式で必須）
//   X-Firebase-AppCheck:      App Check方式のlimited-use token（毎要求consume。bearerで、本文・宛先・本人tokenへは束縛しない）
//   X-STTD-Source-Signature:  開発者方式 `v1.<issuedAt秒>.<expiresAt秒>.<nonce>.<Ed25519署名>`
// 署名対象は固定の改行区切り（下のsigningInput）。宛先origin・method・path・query・wire本文のSHA-256・本人Bearer tokenのSHA-256・
// Idempotency-Key・source ID・時刻・nonceを含め、別本文/宛先/本人token/期限/IDへの流用を拒否する。任意algorithm・外部JWKSは受けない。
// 秘密鍵はこのmoduleが保存・出力しない（signSourceRequestは呼出し側のKeyObjectを使うだけ）。

import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';

import type { SecretHasher } from '../secrets.js';
import { ED25519_PUBLIC_KEY, SIGNATURE_CLOCK_SKEW_SEC, SIGNATURE_MAX_LIFETIME_SEC, SOURCE_ID } from './contract.js';

export const SOURCE_HEADER = 'x-sttd-source';
export const APP_CHECK_HEADER = 'x-firebase-appcheck';
export const SIGNATURE_HEADER = 'x-sttd-source-signature';
const SIGNING_LABEL = 'STTD-SOURCE-SIG-V1';
const SIGNATURE = /^v1\.([1-9][0-9]{0,11})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22,43})\.([A-Za-z0-9_-]{86})$/;
/** App Check tokenはJWT（3 part・base64url）。上限4096。 */
const APP_CHECK_TOKEN = /^[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,2048}$/;
const IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,128}$/;

/** 署名に結ぶ要求の要素。 */
export interface SignedRequest {
  /** 固定の宛先origin（配置設定のapi.publicOrigin）。 */
  readonly audience: string;
  readonly method: string;
  readonly path: string;
  /** `?`を含むquery（無ければ空文字）。 */
  readonly search: string;
  readonly sourceId: string;
  readonly body: Uint8Array;
  readonly bearer: string;
  readonly idempotencyKey: string | undefined;
}

export interface SignatureClaims {
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
}

export type SourceProof =
  | { readonly method: 'app-check-v1'; readonly sourceId: string; readonly token: string }
  | { readonly method: 'developer-key-v1'; readonly sourceId: string; readonly claims: SignatureClaims; readonly signature: Buffer };

/** 欠落（どの証明headerも無い）と不正（形違い・重複・両方式の併記）を区別する。 */
export type SourceProofParse = { readonly kind: 'present'; readonly proof: SourceProof } | { readonly kind: 'missing' } | { readonly kind: 'malformed' };

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('base64url');
}

/** 署名対象のbytes（固定順・改行区切り、各要素は改行を含まない形）。 */
export function signingInput(request: SignedRequest, claims: SignatureClaims): Buffer {
  const lines = [
    SIGNING_LABEL,
    request.audience,
    request.method,
    request.path,
    request.search,
    request.sourceId,
    sha256(request.body),
    sha256(request.bearer),
    request.idempotencyKey ?? '-',
    String(claims.issuedAt),
    String(claims.expiresAt),
    claims.nonce,
  ];
  if (lines.some((line) => /[\r\n]/.test(line))) throw new Error('source signing input invalid');
  return Buffer.from(lines.join('\n'), 'utf8');
}

/** 開発者環境（CLI/helper）が要求へ付ける署名header値。privateKeyはEd25519のKeyObject（保存・出力しない）。 */
export function signSourceRequest(request: SignedRequest, claims: SignatureClaims, privateKey: KeyObject): string {
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('source signing key invalid');
  const signature = sign(null, signingInput(request, claims), privateKey).toString('base64url');
  return `v1.${claims.issuedAt}.${claims.expiresAt}.${claims.nonce}.${signature}`;
}

function single(headers: Readonly<Record<string, string | string[] | undefined>>, name: string): string | undefined | null {
  const value = headers[name];
  if (value === undefined) return undefined;
  // 重複header（配列・Nodeが結合した値）は不正。
  return typeof value === 'string' ? value : null;
}

/** headerから証明を取り出す（形の検査だけ。検証・DB 0）。 */
export function parseSourceProof(headers: Readonly<Record<string, string | string[] | undefined>>): SourceProofParse {
  const sourceId = single(headers, SOURCE_HEADER);
  const token = single(headers, APP_CHECK_HEADER);
  const signature = single(headers, SIGNATURE_HEADER);
  if (sourceId === undefined && token === undefined && signature === undefined) return { kind: 'missing' };
  if (sourceId === null || token === null || signature === null) return { kind: 'malformed' };
  if (sourceId === undefined || !SOURCE_ID.test(sourceId)) return { kind: 'malformed' };
  if ((token === undefined) === (signature === undefined)) return { kind: 'malformed' };
  if (token !== undefined) {
    return token.length <= 4096 && APP_CHECK_TOKEN.test(token) ? { kind: 'present', proof: { method: 'app-check-v1', sourceId, token } } : { kind: 'malformed' };
  }
  const match = SIGNATURE.exec(signature ?? '');
  if (match === null) return { kind: 'malformed' };
  const issuedAt = Number(match[1]);
  const expiresAt = Number(match[2]);
  const decoded = Buffer.from(match[4] ?? '', 'base64url');
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || decoded.length !== 64) return { kind: 'malformed' };
  return { kind: 'present', proof: { method: 'developer-key-v1', sourceId, claims: { issuedAt, expiresAt, nonce: match[3] ?? '' }, signature: decoded } };
}

/** 署名の時刻（最大60秒の有効期間・時計許容30秒）。期限は論理的に即時判定する。 */
export function signatureTimeVerdict(claims: SignatureClaims, nowMs: number): 'ok' | 'invalid' | 'expired' | 'not_yet_valid' {
  const lifetime = claims.expiresAt - claims.issuedAt;
  if (!(lifetime > 0) || lifetime > SIGNATURE_MAX_LIFETIME_SEC) return 'invalid';
  const nowSec = Math.floor(nowMs / 1000);
  if (claims.issuedAt > nowSec + SIGNATURE_CLOCK_SKEW_SEC) return 'not_yet_valid';
  if (nowSec > claims.expiresAt + SIGNATURE_CLOCK_SKEW_SEC) return 'expired';
  return 'ok';
}

/** replay記録を論理的に拒否し続ける期限（ms）。 */
export function signatureReplayUntil(claims: SignatureClaims): number {
  return (claims.expiresAt + SIGNATURE_CLOCK_SKEW_SEC) * 1000;
}

/** 登録公開鍵（raw 32byteのbase64url）でEd25519署名を検証する。形違い・検証失敗はfalse（例外を外へ出さない）。 */
export function verifySourceSignature(publicKey: string, request: SignedRequest, claims: SignatureClaims, signature: Uint8Array): boolean {
  if (!ED25519_PUBLIC_KEY.test(publicKey) || signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
    return verify(null, signingInput(request, claims), key, signature);
  } catch {
    return false;
  }
}

/** 公開鍵（SPKI PEM、またはraw 32byteのbase64url）を登録形（raw base64url）へ。Ed25519以外・不正はnull。 */
export function normalizeSourcePublicKey(input: string): string | null {
  // 秘密鍵のPEMは公開鍵を導出できても受けない（管理CLIへ秘密鍵を渡させない）。SPKIの公開鍵PEMだけ。
  const pem = /^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/;
  if (!ED25519_PUBLIC_KEY.test(input) && !pem.test(input)) return null;
  try {
    const key = ED25519_PUBLIC_KEY.test(input)
      ? createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: input }, format: 'jwk' })
      : createPublicKey({ key: input, format: 'pem' });
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') return null;
    const x = (key.export({ format: 'jwk' }) as { x?: unknown }).x;
    return typeof x === 'string' && ED25519_PUBLIC_KEY.test(x) ? x : null;
  } catch {
    return null;
  }
}

/** replay記録の文書ID（source＋nonceの鍵付きhash。nonce・署名・本文は保存しない）。 */
export function sourceReplayId(hasher: SecretHasher, namespace: string, sourceId: string, nonce: string): string {
  return hasher.hash(`t256:${namespace}:source-replay`, `${sourceId}\0${nonce}`);
}

/** 接続承認の文書ID（元interactionの鍵付きhash）。 */
export function sourceApprovalId(hasher: SecretHasher, namespace: string, interactionId: string): string {
  return hasher.hash(`t256:${namespace}:source-approval`, interactionId);
}

/** Idempotency-Keyの値（形が違えばundefinedとして署名の'-'に揃えない: null）。 */
export function idempotencyKeyOf(headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined | null {
  const value = single(headers, 'idempotency-key');
  if (value === undefined) return undefined;
  return value !== null && IDEMPOTENCY_KEY.test(value) ? value : null;
}
