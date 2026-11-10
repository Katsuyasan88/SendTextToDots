// MCP入口（request-scoped-entry.ts）が認証の前に1回だけ作る要求operationと、それを受け取るresolver・購読portの型、入口の公開形、
// 固定のerror。

import type { IncomingMessage, ServerResponse } from 'node:http';

import type { OAuthProtectedResourceMetadata } from '@modelcontextprotocol/server';

import type { SubscribeInput, SubscribeOutcome, SubscriptionAuth } from '../events/subscriptions.js';
import type { ResolvedOAuthOwner } from '../oauth/owner.js';
import type { Clock } from '../policy.js';

/** 要求全体の元期限。延長しない。 */
export const MCP_REQUEST_BUDGET_MS = 20_000;
/** entry.closeがSDK handlerのcloseを待つ上限。 */
export const MCP_CLOSE_BUDGET_MS = 5_000;

/**
 * 1つのHTTP要求の元期限と中止。handleの最初（最初のawaitの前）に1回だけ作るfrozen object。
 * deadlineAtは捕捉clockのepochミリ秒。signalは期限・切断・entry.closeでabortされる。
 * 受け取ったportは、各await・I/Oの前に最新のdeadlineAt/signalを守る契約を持つ（entryはport内部の物理停止を保証しない）。
 */
export interface McpRequestOperation {
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

/** access token→owner解決（要求operationつき）。 */
export type RequestScopedOwnerResolver = (accessToken: string, operation: McpRequestOperation) => Promise<ResolvedOAuthOwner | null>;

/** 購読port。unsubscribeにも認証済みのowner/Grantを渡す。 */
export interface RequestScopedSubscriptionPort {
  subscribe(auth: SubscriptionAuth, input: SubscribeInput, operation: McpRequestOperation): Promise<SubscribeOutcome>;
  unsubscribe(auth: SubscriptionAuth, identity: { readonly name: string; readonly url: string }, operation: McpRequestOperation): Promise<void>;
}

/** `get_receiving_status`の結果の状態（アカウント単位）。 */
export type ReceivingState = 'change_pending' | 'subscribed' | 'expired' | 'linked';

/**
 * 受信状態の照会port（読取りだけ）。入口の認証で確定したowner/Grantだけを渡す。要求Grant・利用許可の不成立は既存の
 * SubscribeError（grant_inactive）、版の競合はSubscribeError（conflict）、他は任意の例外（入口が固定InternalErrorにする）。
 */
export interface RequestScopedReceivingStatusPort {
  statusFor(auth: SubscriptionAuth, operation: McpRequestOperation): Promise<ReceivingState>;
}

/** MCP入口の公開形。 */
export interface McpEntry {
  /** 認証なしで取得できる公開情報だけ。 */
  readonly protectedResourceMetadata: OAuthProtectedResourceMetadata;
  /** protected resource metadataのパス（401の `resource_metadata` が指す先）。 */
  readonly metadataPath: string;
  handle(req: IncomingMessage, res: ServerResponse): Promise<void>;
  close(): Promise<void>;
}

/** onErrorへ渡す固定の分類だけ。元例外・owner/grant/token/params/operationは渡さない。 */
export type McpRequestErrorCategory = 'sdk' | 'adapter' | 'clock' | 'resolver' | 'context' | 'port';

export interface RequestScopedMcpEntryOptions {
  readonly issuer: string;
  /** issuer配下の `/mcp`。access tokenのaudienceと同じ値。 */
  readonly resource: string;
  readonly clock: Clock;
  readonly resolveOAuthOwner: RequestScopedOwnerResolver;
  readonly subscriptions: RequestScopedSubscriptionPort;
  readonly onError: (category: McpRequestErrorCategory) => void;
  /** 渡された時だけ`get_receiving_status`を一覧・呼出しに出す（無ければ`tools/list`は空、`tools/call`は未提供）。 */
  readonly receivingStatus?: RequestScopedReceivingStatusPort | undefined;
  /** 試験だけ: 正の整数・20000以下（既定20000、延長不可）。 */
  readonly budgetMs?: number | undefined;
  /** 試験だけ: 正の整数・5000以下（既定5000、延長不可）。 */
  readonly closeBudgetMs?: number | undefined;
}

/** factoryの入力の不正。固定のmessageだけで、渡された値・元の例外を持たない。 */
export class McpRequestEntryConfigError extends Error {
  readonly code = 'mcp_entry_config_invalid';
  constructor() {
    super('mcp_entry_config_invalid');
    this.name = 'McpRequestEntryConfigError';
  }
}

/** entry.closeがSDK handlerを上限内に閉じられなかった（または閉鎖が失敗した）。完了と偽らない。 */
export class McpRequestEntryCloseError extends Error {
  readonly code = 'mcp_entry_close_failed';
  constructor() {
    super('mcp_entry_close_failed');
    this.name = 'McpRequestEntryCloseError';
  }
}
