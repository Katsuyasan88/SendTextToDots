// 暗号文の送信（POST /v2/encrypted-commands、application/jose）の受付・復号と、平文と共通の配送への接続。
//   - wire: JWE Compact Serialization（RFC7516）の5セグメント、alg=RSA-OAEP-256・enc=A256GCMだけ。全体12288byte（HTTP入口が認証の前に
//     読み出しを打ち切る）・protected header 1536byte・CEK暗号文384byte・IV12・tag16・ciphertext 1〜4096byte。base64urlはpaddingなしの
//     canonicalだけ。protected headerはBOMなしのfatal UTF-8で、9項目ちょうど（重複はescape後の名前で拒否、未知・型違いは拒否）。
//     圧縮・任意alg/enc・外部鍵・非保護header・JSON JWE・複数recipientの形は受け付けない。
//   - 順序: 認可（既存owner・許可・90日）と復号試行rateを復号・形式検査の前に確かめて消費する（不正形式・未知/失効kid・tag失敗・
//     Secret障害も消費）。ringは作らない。scopeは認証文脈から再計算した値と一致しなければ開かない。
//   - 開封: 本人の指定kidのwrapped秘密鍵を専用保護鍵（固定数値版）で開き、RSA-OAEP-256（SHA-256/MGF1 SHA-256・label空）でCEKを、
//     AES-256-GCM（AADはprotected headerセグメントのASCII bytes）でtextを開く。9項目は全てAADに束縛される。
//   - 論理5項目は復号textとheaderの元表記のcommandId/createdAt/expiresAtから、平文と同じ論理検査（validateCommandFields）・canonical・
//     digestへ通す（暗号文/nonce/kidはdigestへ混ぜない）。配送は既存のKMS配送service（postValidated）で、送出権のtransactionの中で
//     同じdbの鍵ringの最新状態を照合する（checkKeyEvidence）。
//   - 応答は既存の状態応答か固定のerrorだけ。本文・暗号文・CEK・秘密鍵をDB・log・応答へ出さない。所有Bufferはfinallyで0埋めする
//     （JS文字列・KeyObject・OS内の完全消去は保証しない）。

import { constants, createDecipheriv, createPrivateKey, privateDecrypt } from 'node:crypto';

import type { Transaction } from '@google-cloud/firestore';

import { readFlatJsonObject, validateCommandFields, type ValidatedCommandInput } from '../commands/input.js';
import { connectIdentityHash } from '../connect/firestore.js';
import type { DeliveryRequestOperation } from '../delivery/api.js';
import { errorResponse, type DeliveryResponse } from '../delivery/event.js';
import type { VerifiedIdentity } from '../identity/firebase.js';
import type { SecretHasher } from '../secrets.js';
import { canonicalBase64url, isKid, isScope, keyUsable, KEY_ALG, KEY_ENC } from './contract.js';
import { unwrapPrivateKey } from './crypto.js';
import type { EncryptionSecretProvider } from './secret-provider.js';
import { encryptionScope, type EncryptionEnvironment } from './service.js';
import type { EncryptionKeyStore, RingBinding } from './store.js';

/** 暗号文wireの上限（平文の8192とは別）。 */
export const ENCRYPTED_WIRE_MAX_BYTES = 12_288;
export const ENCRYPTED_CONTENT_TYPE = /^application\/jose\s*$/i;
const PROTECTED_HEADER_MAX_BYTES = 1536;
const ENCRYPTED_KEY_BYTES = 384;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = 4096;
const TYP = 'sttd-command+jwe';
const HEADER_NAMES: ReadonlySet<string> = new Set(['alg', 'enc', 'typ', 'kid', 'sttdVersion', 'scope', 'commandId', 'createdAt', 'expiresAt']);
const WIRE = /^[A-Za-z0-9_.-]+$/;

export interface ProtectedHeader {
  readonly kid: string;
  readonly scope: string;
  readonly commandId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface ParsedJwe {
  readonly header: ProtectedHeader;
  /** AAD（protected headerセグメントのASCII）。 */
  readonly aad: Buffer;
  readonly encryptedKey: Buffer;
  readonly iv: Buffer;
  readonly ciphertext: Buffer;
  readonly tag: Buffer;
  dispose(): void;
}

/** wireの形が不正（固定message。原因・値を持たない）。 */
export class EncryptedRequestError extends Error {
  override readonly name = 'EncryptedRequestError';
  constructor() {
    super('invalid_encrypted_request');
  }
}

function segment(value: string, min: number, max: number): Buffer {
  const bytes = canonicalBase64url(value, Math.ceil((max * 4) / 3));
  if (bytes === null || bytes.length < min || bytes.length > max) {
    bytes?.fill(0);
    throw new EncryptedRequestError();
  }
  return bytes;
}

/** JWE compactの形・上限・protected headerの9項目を検査する（暗号処理0）。不正は全てEncryptedRequestError。 */
export function parseCompactJwe(wire: Buffer): ParsedJwe {
  if (!Buffer.isBuffer(wire) || wire.length < 1 || wire.length > ENCRYPTED_WIRE_MAX_BYTES) throw new EncryptedRequestError();
  const text = wire.toString('latin1');
  if (!WIRE.test(text)) throw new EncryptedRequestError();
  const parts = text.split('.');
  if (parts.length !== 5) throw new EncryptedRequestError();
  const [protectedPart, keyPart, ivPart, cipherPart, tagPart] = parts as [string, string, string, string, string];
  const owned: Buffer[] = [];
  try {
    const headerBytes = segment(protectedPart, 1, PROTECTED_HEADER_MAX_BYTES);
    owned.push(headerBytes);
    if (headerBytes.length >= 3 && headerBytes[0] === 0xef && headerBytes[1] === 0xbb && headerBytes[2] === 0xbf) throw new EncryptedRequestError();
    let members: ReadonlyMap<string, unknown>;
    try {
      members = readFlatJsonObject(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(headerBytes), HEADER_NAMES);
    } catch {
      throw new EncryptedRequestError();
    }
    if (members.size !== HEADER_NAMES.size) throw new EncryptedRequestError();
    const str = (name: string): string => {
      const value = members.get(name);
      if (typeof value !== 'string') throw new EncryptedRequestError();
      return value;
    };
    if (str('alg') !== KEY_ALG || str('enc') !== KEY_ENC || str('typ') !== TYP || members.get('sttdVersion') !== 1) throw new EncryptedRequestError();
    const kid = str('kid');
    const scope = str('scope');
    if (!isKid(kid) || !isScope(scope)) throw new EncryptedRequestError();
    const header: ProtectedHeader = Object.freeze({ kid, scope, commandId: str('commandId'), createdAt: str('createdAt'), expiresAt: str('expiresAt') });
    const encryptedKey = segment(keyPart, ENCRYPTED_KEY_BYTES, ENCRYPTED_KEY_BYTES);
    owned.push(encryptedKey);
    const iv = segment(ivPart, IV_BYTES, IV_BYTES);
    owned.push(iv);
    const ciphertext = segment(cipherPart, 1, MAX_CIPHERTEXT_BYTES);
    owned.push(ciphertext);
    const tag = segment(tagPart, TAG_BYTES, TAG_BYTES);
    owned.push(tag);
    const aad = Buffer.from(protectedPart, 'latin1');
    owned.push(aad);
    const result: ParsedJwe = Object.freeze({
      header,
      aad,
      encryptedKey,
      iv,
      ciphertext,
      tag,
      dispose: () => {
        for (const buffer of owned) buffer.fill(0);
      },
    });
    return result;
  } catch (error) {
    for (const buffer of owned) buffer.fill(0);
    throw error instanceof EncryptedRequestError ? error : new EncryptedRequestError();
  }
}

/**
 * 本人の秘密鍵（PKCS8 DER、借用）でCEKとtextを開く。成功はtextのUTF-8 bytes（所有移転）。CEK・未認証の平文Bufferは
 * 全経路で0埋めする。失敗は全てEncryptedRequestError（原因を区別しない）。
 */
export function decryptCompactJwe(parsed: ParsedJwe, pkcs8: Buffer): Buffer {
  let cek: Buffer | null = null;
  let body: Buffer | null = null;
  let tail: Buffer | null = null;
  try {
    const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    cek = privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, parsed.encryptedKey);
    if (cek.length !== 32) throw new EncryptedRequestError();
    const decipher = createDecipheriv('aes-256-gcm', cek, parsed.iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(parsed.aad);
    decipher.setAuthTag(parsed.tag);
    body = decipher.update(parsed.ciphertext);
    tail = decipher.final();
    return Buffer.concat([body, tail]);
  } catch {
    throw new EncryptedRequestError();
  } finally {
    cek?.fill(0);
    body?.fill(0);
    tail?.fill(0);
  }
}

/** 共通配送の入口（KmsRequestDeliveryService.postValidated）。 */
export interface ValidatedCommandDelivery {
  postValidated(
    ownerId: string,
    input: ValidatedCommandInput,
    receivedAt: number,
    parentOperation: DeliveryRequestOperation,
    keyCheck: (tx: Transaction) => Promise<boolean>,
  ): Promise<DeliveryResponse>;
}

/** 送信APIの入口が使う暗号文送信のport。 */
export interface EncryptedCommandEndpoint {
  post(identity: VerifiedIdentity, idempotencyKey: string | undefined, wire: Buffer, receivedAt: number, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
}

export interface EncryptedCommandDeps {
  readonly environment: EncryptionEnvironment;
  readonly store: EncryptionKeyStore;
  readonly secrets: EncryptionSecretProvider;
  readonly hasher: SecretHasher;
  readonly clock: { now(): number };
  readonly delivery: ValidatedCommandDelivery;
}

const invalidEncrypted = () => errorResponse(400, 'invalid_encrypted_request');
const unavailable = () => errorResponse(503, 'temporarily_unavailable', true);

class Stopped extends Error {}

export function createEncryptedCommandEndpoint(deps: EncryptedCommandDeps): EncryptedCommandEndpoint {
  const { environment, store, secrets, hasher, clock, delivery } = deps;
  async function post(identity: VerifiedIdentity, idempotencyKey: string | undefined, wire: Buffer, receivedAt: number, operation: DeliveryRequestOperation): Promise<DeliveryResponse> {
    // 元のingressの期限・中断（20秒を取り直さない）。時計の不正も続行不可。
    const live = (): void => {
      if (operation.signal.aborted) throw new Stopped();
      const now = clock.now();
      if (!Number.isSafeInteger(now) || now <= 0 || now >= operation.deadlineAt) throw new Stopped();
    };
    let parsed: ParsedJwe | null = null;
    let textBytes: Buffer | null = null;
    try {
      live();
      if (identity.projectId !== environment.projectId) return unavailable();
      const identityHash = connectIdentityHash(hasher, environment.connectNamespace, identity);
      const begun = await store.beginDecrypt(identityHash, (ownerId) => encryptionScope(hasher, environment, identityHash, ownerId), live);
      live();
      if (begun.kind === 'connection_required') return errorResponse(409, 'connection_required');
      if (begun.kind === 'access_denied') return errorResponse(403, 'access_denied');
      if (begun.kind === 'rate_limited') return errorResponse(429, 'rate_limited', true, { 'Retry-After': String(begun.retryAfterSec) });
      // ここから先の不正形式・鍵不明・失効・tag失敗・Secret障害は、消費済みの復号試行として扱う。
      try {
        parsed = parseCompactJwe(wire);
      } catch {
        return invalidEncrypted();
      }
      const { binding, ring, now } = begun;
      const header = parsed.header;
      // 他人のscope・他人/未知のkidは同じ400（存在を区別しない）。
      if (header.scope !== binding.scope || ring === null) return invalidEncrypted();
      const key = ring.keys.find((entry) => entry.kid === header.kid);
      if (key === undefined) return invalidEncrypted();
      if (!keyUsable(ring, key, now)) return errorResponse(409, 'encryption_key_unavailable');
      const session = secrets.open(operation);
      let pkcs8: Buffer | null = null;
      try {
        const protectionKey = await session.get(key.secretVersion);
        live();
        pkcs8 = unwrapPrivateKey(key.wrappedPrivateKey, protectionKey, {
          projectNumber: environment.projectNumber,
          databaseId: environment.databaseId,
          connectNamespace: environment.connectNamespace,
          deliveryNamespace: environment.deliveryNamespace,
          encryptionNamespace: environment.encryptionNamespace,
          identityHash: binding.identityHash,
          ownerId: binding.ownerId,
          scope: binding.scope,
          kid: key.kid,
          secretVersion: key.secretVersion,
          publicKeySpki: key.publicKeySpki,
        });
      } catch (error) {
        if (error instanceof Stopped) throw error;
        // 保護鍵・保存した鍵の開封の障害はサーバー側の一時障害（平文の経路は止めない）。
        return unavailable();
      } finally {
        session.dispose();
      }
      // Secret・開封を待った後の最新時刻で、本文を開く直前にもう一度鍵の猶予・無活動期限を確かめる。
      if (!keyUsable(ring, key, clock.now())) {
        pkcs8.fill(0);
        return errorResponse(409, 'encryption_key_unavailable');
      }
      try {
        textBytes = decryptCompactJwe(parsed, pkcs8);
      } catch {
        return invalidEncrypted();
      } finally {
        pkcs8.fill(0);
      }
      live();
      let input: ValidatedCommandInput;
      try {
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(textBytes);
        input = validateCommandFields(idempotencyKey as string, {
          schemaVersion: 2,
          commandId: header.commandId,
          text,
          createdAt: header.createdAt,
          expiresAt: header.expiresAt,
        });
      } catch {
        return invalidEncrypted();
      }
      const evidence = { binding: binding satisfies RingBinding, kid: key.kid };
      // 送出権のtransactionで鍵が使えると確認できた（＝この要求が送出へ進んだ）か。重複の既存結果・照会では呼ばれない。
      let keyAccepted = false;
      const keyCheck = async (tx: Transaction): Promise<boolean> => {
        const usable = (await store.checkKeyEvidence(tx, evidence)) === 'usable';
        keyAccepted = usable;
        return usable;
      };
      const response = await delivery.postValidated(binding.ownerId, input, receivedAt, operation, keyCheck);
      // この要求の配送がcallback成功として確定した時だけ、同じ本人・ring・元operationの範囲でringの最終利用を更新する。
      // 失敗・結果不明・重複・拒否では延ばさない。更新の失敗は応答を変えない（非同期の再試行はしない）。
      if (keyAccepted && response.status === 200 && (response.body as { state?: unknown } | null)?.state === 'delivered') {
        try {
          await store.touchAfterDelivery(binding, key.kid, live);
        } catch {
          // 最終利用の更新ができなくても、配送の結果は偽らない。
        }
      }
      return response;
    } catch {
      return unavailable();
    } finally {
      parsed?.dispose();
      textBytes?.fill(0);
    }
  }
  return Object.freeze({ post });
}
