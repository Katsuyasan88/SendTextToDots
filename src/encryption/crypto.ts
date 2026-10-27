// 本人鍵の候補生成と秘密鍵の保護（Node22組込みcryptoだけ。独自primitive0）。
//   - 候補: RSA3072/e=65537をOS乱数で生成し、PKCS8 DER・SPKI DER・公開JWK（kty/n/e）を取り出す。kidはserver生成の小文字UUID。
//   - wrap: 専用保護鍵32byteでAES-256-GCM（毎回新しいnonce12・tag16）。AADは固定順配列のJSON
//     [用途, projectNumber, databaseId, connectNamespace, deliveryNamespace, encryptionNamespace, identityHash, ownerId, scope, kid,
//      formatVersion, secretVersion, publicKeySpki]。別本人/環境/鍵ID/公開鍵/Secret版へ移したrecordは認証に失敗する。
//   - unwrap後は秘密鍵から導いた公開鍵（SPKI）が保存の公開鍵と一致することを確かめる。
// 所有Bufferは呼出し側またはここのfinallyで0埋めする。JS文字列・KeyObject・OS内の完全消去は保証しない。

import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, generateKeyPair, randomBytes, randomUUID, timingSafeEqual, type KeyObject } from 'node:crypto';

import { canonicalBase64url, KEY_ALG, RSA_MODULUS_BITS, WRAP_FORMAT_VERSION, WRAP_PURPOSE, type PublicJwk } from './contract.js';

export const PROTECTION_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** 開封・保護の失敗（固定message。原因・値を持たない）。 */
export class KeyProtectionError extends Error {
  override readonly name = 'KeyProtectionError';
  constructor() {
    super('key protection failed');
  }
}

/** AADへ束縛する環境・本人・鍵の値（全て非秘密）。 */
export interface WrapBinding {
  readonly projectNumber: string;
  readonly databaseId: string;
  readonly connectNamespace: string;
  readonly deliveryNamespace: string;
  readonly encryptionNamespace: string;
  readonly identityHash: string;
  readonly ownerId: string;
  readonly scope: string;
  readonly kid: string;
  readonly secretVersion: number;
  readonly publicKeySpki: string;
}

export function wrapAad(binding: WrapBinding): Buffer {
  return Buffer.from(
    JSON.stringify([
      WRAP_PURPOSE,
      binding.projectNumber,
      binding.databaseId,
      binding.connectNamespace,
      binding.deliveryNamespace,
      binding.encryptionNamespace,
      binding.identityHash,
      binding.ownerId,
      binding.scope,
      binding.kid,
      WRAP_FORMAT_VERSION,
      binding.secretVersion,
      binding.publicKeySpki,
    ]),
    'utf8',
  );
}

/** 生成した候補（RAMのみ）。pkcs8は所有Bufferで、使い終えたらdisposeで0埋めする。 */
export interface KeyCandidate {
  readonly kid: string;
  readonly pkcs8: Buffer;
  readonly publicKeySpki: string;
  readonly publicJwk: PublicJwk;
  dispose(): void;
}

export type KeyPairGenerator = () => Promise<{ readonly privateKey: KeyObject; readonly publicKey: KeyObject }>;

/** 組込みのRSA3072/e=65537生成（非同期のthread pool）。 */
export const generateRsaKeyPair: KeyPairGenerator = () =>
  new Promise((resolve, reject) => {
    generateKeyPair('rsa', { modulusLength: RSA_MODULUS_BITS, publicExponent: 0x10001 }, (error, publicKey, privateKey) => {
      if (error) reject(new KeyProtectionError());
      else resolve({ publicKey, privateKey });
    });
  });

export function publicPartsOf(publicKey: KeyObject, kid: string): { readonly publicKeySpki: string; readonly publicJwk: PublicJwk } {
  if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails?.modulusLength !== RSA_MODULUS_BITS) throw new KeyProtectionError();
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || jwk.e !== 'AQAB') throw new KeyProtectionError();
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKeySpki: spki.toString('base64url'),
    publicJwk: { kty: 'RSA', n: jwk.n, e: 'AQAB', kid, alg: KEY_ALG, use: 'enc' },
  };
}

export async function createKeyCandidate(generate: KeyPairGenerator = generateRsaKeyPair): Promise<KeyCandidate> {
  const pair = await generate();
  const kid = randomUUID();
  const parts = publicPartsOf(pair.publicKey, kid);
  const pkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  return {
    kid,
    pkcs8,
    ...parts,
    dispose: () => {
      pkcs8.fill(0);
    },
  };
}

function requireProtectionKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== PROTECTION_KEY_BYTES) throw new KeyProtectionError();
}

/** 秘密鍵PKCS8 DERを保護鍵で包む（毎回新しいnonce）。nonce‖ciphertext‖tagのbase64urlを返す。 */
export function wrapPrivateKey(pkcs8: Buffer, protectionKey: Buffer, binding: WrapBinding): string {
  requireProtectionKey(protectionKey);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', protectionKey, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(wrapAad(binding));
  const body = Buffer.concat([cipher.update(pkcs8), cipher.final()]);
  const sealed = Buffer.concat([nonce, body, cipher.getAuthTag()]);
  body.fill(0);
  const encoded = sealed.toString('base64url');
  sealed.fill(0);
  return encoded;
}

/**
 * 包んだ秘密鍵を開き、そこから導いた公開鍵が保存の公開鍵（binding.publicKeySpki）と一致することを確かめる。
 * 成功時は所有権を移したPKCS8 DERを返す（呼出し側が0埋め）。改ざん・入替・版違い・不一致は全てKeyProtectionError。
 */
export function unwrapPrivateKey(wrapped: string, protectionKey: Buffer, binding: WrapBinding): Buffer {
  requireProtectionKey(protectionKey);
  const sealed = canonicalBase64url(wrapped, 4096);
  if (sealed === null || sealed.length <= NONCE_BYTES + TAG_BYTES) throw new KeyProtectionError();
  let pkcs8: Buffer | null = null;
  // updateが返す未認証の平文は、finalのtag検証が失敗しても必ず0埋めする（所有Bufferとして先に保持する）。
  let body: Buffer | null = null;
  let tail: Buffer | null = null;
  try {
    const nonce = sealed.subarray(0, NONCE_BYTES);
    const tag = sealed.subarray(sealed.length - TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', protectionKey, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(wrapAad(binding));
    decipher.setAuthTag(tag);
    body = decipher.update(sealed.subarray(NONCE_BYTES, sealed.length - TAG_BYTES));
    tail = decipher.final();
    pkcs8 = Buffer.concat([body, tail]);
    const derived = createPublicKey(createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' });
    const stored = canonicalBase64url(binding.publicKeySpki, 600);
    if (stored === null || stored.length !== derived.length || !timingSafeEqual(stored, derived)) throw new KeyProtectionError();
    const out = pkcs8;
    pkcs8 = null;
    return out;
  } catch {
    throw new KeyProtectionError();
  } finally {
    body?.fill(0);
    tail?.fill(0);
    pkcs8?.fill(0);
    sealed.fill(0);
  }
}
