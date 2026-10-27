// 認証・接続の期限と本文上限の製品値。値の正本は docs/API.md と docs/SECURITY.md。

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const DAY = 24 * 60 * MINUTE;

export interface AuthPolicy {
  /** ownerの最終認証利用からの無活動失効。 */
  readonly ownerInactivityMs: number;
  /** 接続画面のinteraction（login/consent）とprovider sessionの寿命。 */
  readonly interactionTtlMs: number;
  readonly accessTokenTtlSec: number;
  readonly authorizationCodeTtlSec: number;
  /** refresh tokenの無活動窓とGrantの上限。 */
  readonly refreshFamilyMaxSec: number;
}

export const PRODUCT_POLICY: AuthPolicy = Object.freeze({
  ownerInactivityMs: 90 * DAY,
  interactionTtlMs: 5 * MINUTE,
  accessTokenTtlSec: 15 * 60,
  authorizationCodeTtlSec: 60,
  refreshFamilyMaxSec: 90 * 24 * 60 * 60,
});

/** 接続Web・interactionの本文上限（バイト）。 */
export const MAX_BODY_BYTES = 4096;
/** POST /v2/commandsだけの本文上限（バイト）。値の正本は docs/API.md §2。 */
export const MAX_COMMAND_BODY_BYTES = 8192;
/**
 * 内部で組み立てて送る署名event（指示の配送の本文）の上限（バイト）。受信の上限（平文8192・暗号文12288）とは別。
 * 本文4096バイトの全文字がJSONの`\u00XX`（6バイト）へ展開されても収まるよう、4096×6＋固定envelope 512 = 25088。
 */
export const MAX_SIGNED_EVENT_BYTES = 4096 * 6 + 512;
/** /mcpの本文上限（バイト）。callback URLとsecretを含む購読要求が収まる値。 */
export const MAX_MCP_BODY_BYTES = 16 * 1024;

export interface Clock {
  /** 現在時刻（epochミリ秒）。 */
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };
