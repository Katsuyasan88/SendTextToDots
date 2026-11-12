// 審査・テスト専用ログインの許可元承認（strictの配置だけ）。審査用のconnect専用source（運用者が事前登録したdeveloper方式、
// 本人＝審査UIDのidentityHashに結んだ記録）の秘密鍵を、サーバー側の専用署名port（Playgroundの登録鍵とは別）が保持する。
// 同意の明示操作（同じbrowser・CSRF・login済みの審査owner）の後だけ、サーバーがこのinteraction・審査UID・OAuth client・resourceを
// 固定の要求に組み、既存の署名形式（proof.tsのsigningInput／Ed25519）で署名する。検証は既存のsource gate（登録公開鍵・source状態・世代・
// connect操作・本人の束縛・時刻・nonceの単回記録）をそのまま使い、承認の記録・Grantでの単回消費も既存の経路に乗る。
// 入力（要求本文・header）から送信元・署名先・宛先を選ばせない。値は全て設定とサーバーが確かめた状態から作る。署名・鍵を記録・出力しない。

import { randomBytes } from 'node:crypto';
import { createPrivateKey, sign, type KeyObject } from 'node:crypto';

import { SIGNATURE_MAX_LIFETIME_SEC, SOURCE_ID } from './contract.js';
import { signingInput, type SignatureClaims, type SignedRequest, type SourceProof } from './proof.js';

/** 審査承認の署名の有効期間（秒）。既存の最大60秒より短い固定値。 */
export const REVIEWER_APPROVAL_LIFETIME_SEC = 30;

/**
 * 審査承認の専用署名port。sourceIdは運用者が登録した審査用source、reviewerUidは現在の設定の唯一の審査UID（署名の直前に保存済みowner UIDと
 * 完全一致を要求する）、signは署名対象bytesのEd25519署名（64byte）を返す。
 */
export interface ReviewerApprovalSigner {
  readonly sourceId: string;
  readonly reviewerUid: string;
  sign(input: Buffer): Promise<Uint8Array> | Uint8Array;
}

/** 審査承認の秘密鍵を渡す専用の固定環境変数（Secret ManagerからCloud Runへ注入。値はcanonical base64のEd25519 PKCS8 DER）。 */
export const REVIEWER_APPROVAL_KEY_ENV = 'STTD_REVIEWER_APPROVAL_ED25519_PKCS8';
/** Ed25519のPKCS8 DERは48byte（base64で64文字）。余裕を持たせた上限。 */
const REVIEWER_APPROVAL_KEY_MAX_CHARS = 256;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * 環境変数の値（canonical base64のPKCS8 DER）をEd25519の秘密鍵KeyObjectへ。長さ・base64の正規形・PKCS8・Ed25519の種別を検査し、
 * 不正は値を含まないReviewerApprovalError。復号したbytesは使い終えたら0埋めする。
 */
export function parseReviewerApprovalKey(text: unknown): KeyObject {
  if (typeof text !== 'string' || text.length < 4 || text.length > REVIEWER_APPROVAL_KEY_MAX_CHARS || !CANONICAL_BASE64.test(text)) throw new ReviewerApprovalError();
  const der = Buffer.from(text, 'base64');
  try {
    if (der.toString('base64') !== text) throw new ReviewerApprovalError();
    let key: KeyObject;
    try {
      key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    } catch {
      throw new ReviewerApprovalError();
    }
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new ReviewerApprovalError();
    return key;
  } finally {
    der.fill(0);
  }
}

export class ReviewerApprovalError extends Error {
  override readonly name = 'ReviewerApprovalError';
  constructor() {
    super('reviewer approval unavailable');
  }
}

/** ローカル・試験用: Ed25519のKeyObject（秘密鍵）から署名portを作る（実配置では専用の鍵管理境界のportを渡す）。 */
export function createKeyObjectReviewerSigner(sourceId: string, privateKey: KeyObject, reviewerUid: string): ReviewerApprovalSigner {
  if (!SOURCE_ID.test(sourceId) || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') throw new ReviewerApprovalError();
  if (typeof reviewerUid !== 'string' || !/^[A-Za-z0-9]{20,128}$/.test(reviewerUid)) throw new ReviewerApprovalError();
  return Object.freeze({ sourceId, reviewerUid, sign: (input: Buffer) => sign(null, input, privateKey) });
}

export interface ReviewerApprovalTarget {
  /** 署名の宛先（通常MCPのpublic origin）。 */
  readonly audience: string;
  /** 元のOAuth interaction ID（同意画面のURLの値）。 */
  readonly interactionId: string;
  /** サーバーが保存済みのownerから開封した審査UID。 */
  readonly reviewerUid: string;
  readonly clientId: string;
  readonly resource: string;
}

/** 審査承認の固定要求（method・path・本文の形は固定。本文はinteraction・UID・client・resourceの正規JSON）。Bearerは持たない（空）。 */
export function reviewerApprovalRequest(target: ReviewerApprovalTarget, sourceId: string): SignedRequest {
  const body = Buffer.from(
    JSON.stringify({ v: 1, purpose: 'reviewer-connect', interaction: target.interactionId, uid: target.reviewerUid, client: target.clientId, resource: target.resource }),
    'utf8',
  );
  return Object.freeze({
    audience: target.audience,
    method: 'POST',
    path: `/interaction/${target.interactionId}/reviewer-approval`,
    search: '',
    sourceId,
    body,
    bearer: '',
    idempotencyKey: undefined,
  });
}

/**
 * 審査承認を1回署名する（nonceは毎回新しい乱数、期限は30秒）。戻り値は既存gateへそのまま渡すproofと、同じ要求。
 * 署名portの失敗・形違いはReviewerApprovalError（署名の無い承認は作らない）。
 */
export async function issueReviewerApproval(
  signer: ReviewerApprovalSigner,
  target: ReviewerApprovalTarget,
  nowMs: number,
): Promise<{ readonly proof: SourceProof; readonly request: SignedRequest }> {
  if (!SOURCE_ID.test(signer.sourceId) || !Number.isSafeInteger(nowMs) || nowMs <= 0) throw new ReviewerApprovalError();
  if (REVIEWER_APPROVAL_LIFETIME_SEC > SIGNATURE_MAX_LIFETIME_SEC) throw new ReviewerApprovalError();
  const issuedAt = Math.floor(nowMs / 1000);
  const claims: SignatureClaims = Object.freeze({ issuedAt, expiresAt: issuedAt + REVIEWER_APPROVAL_LIFETIME_SEC, nonce: randomBytes(24).toString('base64url') });
  const request = reviewerApprovalRequest(target, signer.sourceId);
  let signature: Uint8Array;
  try {
    signature = await signer.sign(signingInput(request, claims));
  } catch {
    throw new ReviewerApprovalError();
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new ReviewerApprovalError();
  return Object.freeze({
    proof: Object.freeze({ method: 'developer-key-v1' as const, sourceId: signer.sourceId, claims, signature: Buffer.from(signature) }),
    request,
  });
}
