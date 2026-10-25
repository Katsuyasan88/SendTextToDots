// 購読の要求・結果・失敗とcallback検証の送出境界の型（KMS購読runtime・MCP入口・接続Webが共有する）。

import type { CallbackEndpointReason } from './contract.js';

export interface VerificationRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface VerificationResponse {
  readonly status: number;
  readonly body: string;
}

/** 送出側が区別して戻せる失敗。HTTP statusによる分類（http_4xx / http_5xx）はruntimeが応答から決める。 */
export type VerificationFailure = Extract<
  CallbackEndpointReason,
  'connection_refused' | 'timeout' | 'tls_error' | 'challenge_failed'
>;

/** 送出の失敗を固定分類だけで戻す。URL・IP・元例外を持たせない。 */
export class VerificationSendError extends Error {
  constructor(readonly reason: VerificationFailure) {
    super(reason);
    this.name = 'VerificationSendError';
  }
}

/**
 * callback検証の送出境界。runtimeはURLへ自分では接続せず、注入された関数（egress/verification-sender.ts）だけを呼ぶ。
 * 失敗はVerificationSendErrorで戻し、それ以外の例外はchallenge_failedとして扱う。signalは応答待ち上限で中断される。
 */
export type VerificationSender = (request: VerificationRequest, signal: AbortSignal) => Promise<VerificationResponse>;

export type SubscribeFailure =
  | { readonly kind: 'invalid_request' }
  /** 形は正しいが、提供していないイベント名。 */
  | { readonly kind: 'unknown_event' }
  /** 履歴の再送を求める非nullのcursor。 */
  | { readonly kind: 'cursor_unsupported' }
  | { readonly kind: 'destination_change_pending' }
  | { readonly kind: 'callback_endpoint'; readonly reason: CallbackEndpointReason }
  /** 要求元のgrantが、入口または検証後の確定前に有効でなかった（取消・reuse検知・期限・ownerの失効）。 */
  | { readonly kind: 'grant_inactive' }
  /** 保存側の確定条件が、確認後に変わっていた（並行する別の更新）。 */
  | { readonly kind: 'conflict' };

export class SubscribeError extends Error {
  constructor(readonly failure: SubscribeFailure) {
    super(failure.kind);
    this.name = 'SubscribeError';
  }
}

export interface SubscribeInput {
  readonly name: string;
  readonly url: string;
  readonly secret: string;
  readonly ttlMs?: number | null | undefined;
  /** 履歴cursor。省略とnullだけを受理する。 */
  readonly cursor?: string | null | undefined;
}

export interface SubscribeOutcome {
  readonly id: string;
  /** nullは無期限の購読（明示ttlMs:null）。 */
  readonly refreshBefore: string | null;
}

/** GET /v1/web/connection が購読について知る必要のある区別だけ。 */
export type SubscriptionView = 'change_pending' | 'subscribed' | 'expired' | 'none';

/** 認証済みのOAuth tokenから解決した要求元。要求本文やAPI入力からは作らない。 */
export interface SubscriptionAuth {
  readonly ownerId: string;
  readonly grantId: string;
}
