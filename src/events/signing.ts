// Standard Webhooksの署名。計算は公式ライブラリに任せ、ここで再実装しない。
import { Webhook } from 'standardwebhooks';

import { SECRET_MAX_BYTES, SECRET_MIN_BYTES, SECRET_PREFIX } from './contract.js';

export interface SignedHeaders {
  'webhook-id': string;
  'webhook-timestamp': string;
  'webhook-signature': string;
}

/** `whsec_` に続くbase64が24〜64バイトへ復号できること。 */
export function isValidSecret(secret: string): boolean {
  if (!secret.startsWith(SECRET_PREFIX)) return false;
  const encoded = secret.slice(SECRET_PREFIX.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) return false;
  const decoded = Buffer.from(encoded, 'base64');
  try {
    return decoded.length >= SECRET_MIN_BYTES && decoded.length <= SECRET_MAX_BYTES;
  } finally {
    // ここで作ったdecodeの範囲だけを0にする（借りた文字列・共有poolの他の範囲には触れない。文字列の消去は保証しない）。
    decoded.fill(0);
  }
}

/**
 * 正確な本文バイト列へ、secretごとに1つ署名する。鍵の移行中は新旧の署名を空白区切りで並べ、
 * どちらの鍵でも同じ本文を検証できるようにする。
 */
export function signBody(messageId: string, body: string, signedAt: Date, secrets: readonly string[]): SignedHeaders {
  const signatures = secrets.map((secret) => new Webhook(secret).sign(messageId, signedAt, body));
  return {
    'webhook-id': messageId,
    'webhook-timestamp': String(Math.floor(signedAt.getTime() / 1000)),
    'webhook-signature': signatures.join(' '),
  };
}

/**
 * 指示の配送用の署名。本文はBufferのまま公式ライブラリへ渡し、secretは生のbytes（24〜64バイト、新旧で1〜2個）を
 * rawの形式で渡す。計算は公式ライブラリのもので、ここで式を書かない。借りた本文・secretは書き換えず、ここで作るsecretの写しは
 * 返す前に0で上書きする（ライブラリの中の文字列・配列までは消せない）。入力が合わなければ、固定の文言のErrorだけを投げる。
 */
export function signCommandBody(eventId: string, body: Buffer, signedAt: Date, secrets: readonly Buffer[]): SignedHeaders {
  const valid =
    typeof eventId === 'string' &&
    Buffer.isBuffer(body) &&
    signedAt instanceof Date &&
    Number.isFinite(signedAt.getTime()) &&
    Array.isArray(secrets) &&
    secrets.length >= 1 &&
    secrets.length <= 2 &&
    secrets.every((secret) => Buffer.isBuffer(secret) && secret.length >= SECRET_MIN_BYTES && secret.length <= SECRET_MAX_BYTES);
  if (!valid) throw new Error('invalid_signing_input');
  const owned: Buffer[] = [];
  try {
    const signatures: string[] = [];
    for (const secret of secrets) {
      const copy = Buffer.allocUnsafeSlow(secret.length);
      owned.push(copy);
      secret.copy(copy);
      signatures.push(new Webhook(copy, { format: 'raw' }).sign(eventId, signedAt, body));
    }
    return {
      'webhook-id': eventId,
      'webhook-timestamp': String(Math.floor(signedAt.getTime() / 1000)),
      'webhook-signature': signatures.join(' '),
    };
  } finally {
    for (const copy of owned) copy.fill(0);
  }
}
