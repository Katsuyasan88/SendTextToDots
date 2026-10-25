// MCP Eventsの3メソッドのwire形と、入力・エラーの製品契約（正本は docs/API.md「MCP Events」）。草案からこのprojectが選んだ契約で、
// 実ホストの受入の確認ではない。
import * as z from 'zod';

export const EVENT_NAME = 'text.submitted';

export const SECRET_PREFIX = 'whsec_';
export const SECRET_MIN_BYTES = 24;
export const SECRET_MAX_BYTES = 64;

/** CallbackEndpointError。data.reasonは分類だけで、URL・secret・応答本文を含めない。 */
export const ERROR_CALLBACK_ENDPOINT = -32015;
export type CallbackEndpointReason =
  | 'connection_refused'
  | 'timeout'
  | 'tls_error'
  | 'http_4xx'
  | 'http_5xx'
  | 'challenge_failed';

/** NotFound。未知のイベント名はdata.kind=event。 */
export const ERROR_NOT_FOUND = -32011;
/** Forbidden。data.reasonは下の2種類だけ。 */
export const ERROR_FORBIDDEN = -32012;
export type ForbiddenReason = 'destination_change_pending' | 'access_revoked';
/** Unsupported。履歴cursorはdata.feature=cursor。 */
export const ERROR_UNSUPPORTED = -32014;

// docs/API.md §4。textのmaxLengthは文字数の粗い上限で、4096 UTF-8 byte・空白/surrogateの厳密な検査は送信APIの入力検証が行う。
export const EVENT_INPUT_SCHEMA = { type: 'object', properties: {}, additionalProperties: false } as const;
export const EVENT_PAYLOAD_SCHEMA = {
  type: 'object',
  properties: {
    schemaVersion: { type: 'integer', const: 2 },
    commandId: { type: 'string', format: 'uuid' },
    text: { type: 'string', minLength: 1, maxLength: 4096 },
    expiresAt: { type: 'string', format: 'date-time' },
  },
  required: ['schemaVersion', 'commandId', 'text', 'expiresAt'],
  additionalProperties: false,
} as const;

// SDKは予約済みのenvelopeキーを_metaから取り出してからdispatchするが、_meta自体は残り得る。
// 未知フィールドを拒否するstrictObjectで、許す追加キーはこれだけ。ownerの指定は入力に存在しない。
const meta = { _meta: z.looseObject({}).optional() };
const eventArguments = z.strictObject({}).optional();

export const EventsListParams = z.strictObject({ ...meta, cursor: z.string().optional() });

export const EventsSubscribeParams = z.strictObject({
  ...meta,
  name: z.string(),
  arguments: eventArguments,
  delivery: z.strictObject({
    mode: z.literal('webhook'),
    url: z.string(),
    secret: z.string(),
  }),
  // 履歴の再送はしない。形の正しい非nullのcursorは受理せず、serviceがUnsupportedで返す。
  cursor: z.string().nullable().optional(),
  // 0〜Number.MAX_SAFE_INTEGERの整数だけ受理する。再生がないため効果はなく、TTLにも使わない。
  maxAgeMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  ttlMs: z.number().int().positive().nullable().optional(),
});

// identityだけ。secretとsubscription idは入力ではない。
export const EventsUnsubscribeParams = z.strictObject({
  ...meta,
  name: z.string(),
  arguments: eventArguments,
  delivery: z.strictObject({
    mode: z.literal('webhook'),
    url: z.string(),
  }),
});

export function eventsListResult() {
  return {
    events: [
      {
        name: EVENT_NAME,
        description: "Text submitted by the owner's authenticated input source, delivered to the owner's subscribed destination.",
        inputSchema: EVENT_INPUT_SCHEMA,
        payloadSchema: EVENT_PAYLOAD_SCHEMA,
        delivery: ['webhook'],
      },
    ],
  };
}

/** refreshBeforeのnullは無期限購読（新接続profileの明示ttlMs:nullだけ）。 */
export function subscribeResult(id: string, refreshBefore: string | null) {
  return { id, refreshBefore, cursor: null, truncated: false };
}
