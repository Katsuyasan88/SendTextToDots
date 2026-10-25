// 送信APIの指示入力の検証・再送比較（同期の純粋な部品2つ）。項目の契約は docs/API.md §2。
// 検証の成功は受付ではない。owner・Grant・購読・rate・保存・配送は扱わない（delivery/kms-service.tsが呼ぶ）。
// 日時の表記（UTCの大文字T/Z、小数秒0〜3桁）とcanonicalの形はこの部品の受付条件。
// 時計・乱数を読まず、ログ・global・cacheへ何も残さない。元の本文のBufferは読むだけで、書き換えも保持もしない。

import { Buffer } from 'node:buffer';

import { MAX_COMMAND_BODY_BYTES } from '../policy.js';
import { CommandApiError } from './errors.js';

const MAX_TEXT_BYTES = 4096;
const COMMAND_LIFETIME_MS = 60_000;
const MAX_CLOCK_SKEW_MS = 30_000;
const MIN_REMAINING_MS = 10_000;

/** HTTP入口と同じ36文字hex-hyphen形。版・variantは見ない。 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** UTCだけ。大文字のTとZ、小数秒は無しか1〜3桁。 */
const TIMESTAMP_PATTERN = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z$/;
const LONE_SURROGATE = /\p{Cs}/u;
/** JSONの数値1つ（先頭から）。 */
const NUMBER_TOKEN = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const LITERALS: readonly (readonly [string, boolean | null])[] = [
  ['true', true],
  ['false', false],
  ['null', null],
];
/** canonicalの項目順（docs/API.md §2の例の順）。 */
const FIELD_NAMES: ReadonlySet<string> = new Set(['schemaVersion', 'commandId', 'text', 'createdAt', 'expiresAt']);

/** 送られた5項目。文字列は元の表記のまま（UUIDの大小・日時の表記を変えない。切り詰め・trim・正規化をしない）。 */
export interface CommandInputFields {
  readonly schemaVersion: 2;
  readonly commandId: string;
  readonly text: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface ValidatedCommandInput {
  /** 凍結済み。 */
  readonly fields: CommandInputFields;
  /** 小文字へ揃えたcommandId（内部の照合用）。 */
  readonly commandId: string;
  readonly createdAtMs: number;
  /** createdAtMs + 60000。新規受付の有効期限そのものではない（resolveNewCommandExpiry）。 */
  readonly expiresAtMs: number;
  /**
   * 5項目を固定順でJSON.stringifyしたUTF-8。呼び出しごとに独立して確保したBufferで、元の本文と領域を共有しない。
   * 呼び出し側が使い終えたらfill(0)する。fieldsのJS文字列やNode内部の写しの消去までは保証しない。
   */
  readonly canonicalBytes: Buffer;
}

type Primitive = string | number | boolean | null;

const invalid = () => new CommandApiError('invalid_request');

function skipWhitespace(text: string, start: number): number {
  let at = start;
  for (;;) {
    const ch = text[at];
    if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') return at;
    at += 1;
  }
}

/** startの位置の文字列token。escapeの解釈は、このtokenだけをJSON.parseへ渡して行う。 */
function readString(text: string, start: number): { value: string; end: number } {
  if (text[start] !== '"') throw invalid();
  let at = start + 1;
  for (;;) {
    const ch = text[at];
    if (ch === undefined) throw invalid();
    if (ch === '"') break;
    at += ch === '\\' ? 2 : 1;
  }
  const value: unknown = JSON.parse(text.slice(start, at + 1));
  if (typeof value !== 'string') throw invalid();
  return { value, end: at + 1 };
}

/** 文字列・数値・true・false・nullだけ。objectと配列はここで拒否になる。 */
function readPrimitive(text: string, start: number): { value: Primitive; end: number } {
  if (text[start] === '"') return readString(text, start);
  for (const [literal, value] of LITERALS) {
    if (text.startsWith(literal, start)) return { value, end: start + literal.length };
  }
  NUMBER_TOKEN.lastIndex = start;
  const match = NUMBER_TOKEN.exec(text);
  if (match === null) throw invalid();
  return { value: Number(match[0]), end: start + match[0].length };
}

/**
 * 最上位のobjectを自前で読む。key名はescapeを解いた後の名前で比べ、5項目以外と、同じ名前の2回目（値が同じでも）を拒否する。
 * JSON.parseの後勝ちには頼らない。文字列の中のquote・波括弧・keyらしい並びは、文字列tokenとして読み飛ばす。
 */
function readMembers(text: string): Map<string, Primitive> {
  const members = new Map<string, Primitive>();
  let at = skipWhitespace(text, 0);
  if (text[at] !== '{') throw invalid();
  at = skipWhitespace(text, at + 1);
  if (text[at] === '}') {
    at += 1;
  } else {
    for (;;) {
      const name = readString(text, at);
      if (!FIELD_NAMES.has(name.value) || members.has(name.value)) throw invalid();
      at = skipWhitespace(text, name.end);
      if (text[at] !== ':') throw invalid();
      const member = readPrimitive(text, skipWhitespace(text, at + 1));
      members.set(name.value, member.value);
      at = skipWhitespace(text, member.end);
      const separator = text[at];
      at += 1;
      if (separator === '}') break;
      if (separator !== ',') throw invalid();
      at = skipWhitespace(text, at);
    }
  }
  if (skipWhitespace(text, at) !== text.length) throw invalid();
  return members;
}

function uuid(value: Primitive | undefined): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw invalid();
  return value;
}

/** 空・空白のみ・対にならないsurrogate・UTF-8のバイト上限超過を拒否する。trimは判定だけで、値は元のまま返す。 */
function boundedText(value: Primitive | undefined): string {
  if (typeof value !== 'string' || LONE_SURROGATE.test(value) || value.trim() === '' || Buffer.byteLength(value, 'utf8') > MAX_TEXT_BYTES) {
    throw invalid();
  }
  return value;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

/** 1970〜9999年の実在する日時のepochミリ秒。うるう秒・24時・存在しない日は拒否する。 */
function timestampMs(value: Primitive | undefined): number {
  if (typeof value !== 'string') throw invalid();
  const match = TIMESTAMP_PATTERN.exec(value);
  if (match === null) throw invalid();
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) {
    throw invalid();
  }
  return Date.UTC(year, month - 1, day, hour, minute, second, Number((match[7] ?? '').padEnd(3, '0')));
}

function validate(idempotencyKey: string, rawBody: Buffer): ValidatedCommandInput {
  if (!Buffer.isBuffer(rawBody) || rawBody.length < 1 || rawBody.length > MAX_COMMAND_BODY_BYTES) throw invalid();
  if (typeof idempotencyKey !== 'string' || !UUID_PATTERN.test(idempotencyKey)) throw invalid();
  if (rawBody.length >= 3 && rawBody[0] === 0xef && rawBody[1] === 0xbb && rawBody[2] === 0xbf) throw invalid();
  const members = readMembers(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(rawBody));
  // 5項目以外と重複は読取りで拒否済みなので、個数が合えば5項目がちょうど1つずつある。
  if (members.size !== FIELD_NAMES.size) throw invalid();

  if (members.get('schemaVersion') !== 2) throw invalid();
  const commandId = uuid(members.get('commandId'));
  if (commandId.toLowerCase() !== idempotencyKey.toLowerCase()) throw invalid();
  const text = boundedText(members.get('text'));
  const createdAt = members.get('createdAt');
  const expiresAt = members.get('expiresAt');
  const createdAtMs = timestampMs(createdAt);
  const expiresAtMs = timestampMs(expiresAt);
  if (typeof createdAt !== 'string' || typeof expiresAt !== 'string' || expiresAtMs !== createdAtMs + COMMAND_LIFETIME_MS) throw invalid();

  const fields: CommandInputFields = Object.freeze({
    schemaVersion: 2,
    commandId,
    text,
    createdAt,
    expiresAt,
  });
  const json = JSON.stringify(fields);
  // Buffer.fromの共有poolを使わず、この結果だけの領域へ書く。
  const canonicalBytes = Buffer.alloc(Buffer.byteLength(json, 'utf8'));
  canonicalBytes.write(json, 'utf8');
  return Object.freeze({ fields, commandId: commandId.toLowerCase(), createdAtMs, expiresAtMs, canonicalBytes });
}

/**
 * Idempotency-Keyと元の本文（1〜8192バイト）の全検証。成功なら、凍結した5項目・小文字のcommandId・日時のepochミリ秒・
 * canonicalのbytesを返す。失敗は、理由によらず固定のCommandApiError('invalid_request')だけで、元の例外・入力の値・causeを付けない。
 */
export function validateCommandInput(idempotencyKey: string, rawBody: Buffer): ValidatedCommandInput {
  try {
    return validate(idempotencyKey, rawBody);
  } catch {
    throw invalid();
  }
}

const isInstant = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

function decideExpiry(input: ValidatedCommandInput, receivedAt: number, now: number): number | 'clock_skew' | 'command_expired' {
  const { createdAtMs, expiresAtMs } = input;
  if (!isInstant(createdAtMs) || !isInstant(expiresAtMs) || !isInstant(receivedAt) || !isInstant(now)) throw invalid();
  const receiptLimit = receivedAt + COMMAND_LIFETIME_MS;
  if (!Number.isSafeInteger(receiptLimit)) throw invalid();
  if (createdAtMs - receivedAt > MAX_CLOCK_SKEW_MS) return 'clock_skew';
  const effectiveExpiresAt = Math.min(expiresAtMs, receiptLimit);
  // 戻った時計では受領時刻より前へ戻さない。
  if (effectiveExpiresAt - Math.max(receivedAt, now) < MIN_REMAINING_MS) return 'command_expired';
  return effectiveExpiresAt;
}

/**
 * 新規の受付だけに使う時間の判定。既存の同じIDの照会・同じcanonicalの応答では呼ばない。
 * receivedAtはHTTP入口が最初の待機より前に一度だけ捕捉した到着時刻、nowは呼び出し側が最後の待機の後に捕捉した時刻（どちらも
 * epochミリ秒）。ここでは時計を読まず、時刻の取り直しで期限を延ばさない。保存の確定の直前に、最新のnowでもう一度呼ぶ想定。
 * 返すのは有効期限 min(expiresAtMs, receivedAt + 60000) だけで、inputは変更しない。
 * 失敗は固定のCommandApiError（clock_skew・command_expired、内部の値が不正ならinvalid_request）だけ。
 */
export function resolveNewCommandExpiry(input: ValidatedCommandInput, receivedAt: number, now: number): number {
  let outcome: number | 'clock_skew' | 'command_expired';
  try {
    outcome = decideExpiry(input, receivedAt, now);
  } catch {
    throw invalid();
  }
  if (typeof outcome !== 'number') throw new CommandApiError(outcome);
  return outcome;
}
