// 接続Web・interactionのHTTP本文の読取り（上限つき）と形の検査。

import type { IncomingMessage } from 'node:http';

import { z } from 'zod';

import { apiErrors } from '../errors.js';
import { MAX_BODY_BYTES } from '../policy.js';

/** 上限を超えた時点で読取りを打ち切る。呼び出し側は応答後に接続を閉じる。上限の既定は独自APIの4096バイト。 */
async function readBody(req: IncomingMessage, maxBytes: number = MAX_BODY_BYTES): Promise<Buffer> {
  const declared = req.headers['content-length'];
  if (declared !== undefined && !(Number(declared) <= maxBytes)) throw apiErrors.invalidRequest();

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > maxBytes) throw apiErrors.invalidRequest();
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function mediaType(req: IncomingMessage): string {
  return (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
}

/** JSON Content-Type必須。スキーマは未知フィールドを拒否するstrictObjectで渡す。 */
export async function readJson<T>(req: IncomingMessage, schema: z.ZodType<T>): Promise<T> {
  if (mediaType(req) !== 'application/json') throw apiErrors.invalidRequest();
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    throw apiErrors.invalidRequest();
  }
  const result = schema.safeParse(parsed);
  if (!result.success) throw apiErrors.invalidRequest();
  return result.data;
}

/** 元browserのform POST。指定したフィールドだけを1つずつ受け付ける。 */
export async function readForm(req: IncomingMessage, fields: readonly string[]): Promise<Map<string, string>> {
  if (mediaType(req) !== 'application/x-www-form-urlencoded') throw apiErrors.invalidRequest();
  const params = new URLSearchParams((await readBody(req)).toString('utf8'));
  const values = new Map<string, string>();
  for (const [name, value] of params) {
    if (!fields.includes(name) || values.has(name)) throw apiErrors.invalidRequest();
    values.set(name, value);
  }
  return values;
}

/** 本文なしの要求（GET）。 */
export async function assertNoBody(req: IncomingMessage): Promise<void> {
  if ((await readBody(req)).length !== 0) throw apiErrors.invalidRequest();
}

