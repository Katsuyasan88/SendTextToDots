// MCP入口。要求ごとの元期限・中止とowner/Grantを、resolverと購読portへ渡す。
// SDKの公開APIだけを使う（createMcpHandler・Server・verifyBearerToken・bearerAuthChallengeResponse・toNodeHandler）。node_modulesは変更しない。
// handleの最初に捕捉clockから元期限を1回だけ決め、要求専用のAbortControllerと合わせたfrozen operationを作る。
// verifyBearerTokenが返したAuthInfo objectとoperationをentry所有のWeakMapで結び、固定SDKのreq.auth→ctx.http.authInfoの
// pass-throughで同じobjectからoperationを引く。見つからない（SDKがcopyした等）時は固定の非成功で、グローバル/無期限contextを作らない。
// resolverの例外（OAuthErrorを含む）と不正な戻り値は元の値を捨てて固定500にし、無効な資格情報はnullだけで表す。
// optionsは決まった項目だけのplain data objectで、余分な項目・不正な型・Proxy・getterは固定のerrorで拒否し、getter・trapを起動しない。

import type { IncomingMessage, ServerResponse } from 'node:http';
import { types } from 'node:util';

import { toNodeHandler, type NodeIncomingMessageLike } from '@modelcontextprotocol/node';
import {
  bearerAuthChallengeResponse,
  buildOAuthProtectedResourceMetadata,
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  OAuthError,
  OAuthErrorCode,
  ProtocolError,
  ProtocolErrorCode,
  Server,
  verifyBearerToken,
  type AuthInfo,
  type ServerCapabilities,
  type ServerContext,
  type VerifyBearerTokenOptions,
} from '@modelcontextprotocol/server';

import {
  ERROR_CALLBACK_ENDPOINT,
  ERROR_FORBIDDEN,
  ERROR_NOT_FOUND,
  ERROR_UNSUPPORTED,
  EventsListParams,
  EventsSubscribeParams,
  EventsUnsubscribeParams,
  eventsListResult,
  subscribeResult,
  type CallbackEndpointReason,
  type ForbiddenReason,
} from '../events/contract.js';
import { SubscribeError, type SubscribeInput, type SubscriptionAuth } from '../events/subscriptions.js';
import { STTD_SCOPE, OAUTH_ROUTES } from '../oauth/provider.js';
import { MAX_MCP_BODY_BYTES } from '../policy.js';
import {
  MCP_CLOSE_BUDGET_MS,
  MCP_REQUEST_BUDGET_MS,
  McpRequestEntryCloseError,
  McpRequestEntryConfigError,
  type McpEntry,
  type McpRequestErrorCategory,
  type McpRequestOperation,
  type ReceivingState,
  type RequestScopedMcpEntryOptions,
} from './request-operation.js';

export {
  MCP_CLOSE_BUDGET_MS,
  MCP_REQUEST_BUDGET_MS,
  McpRequestEntryCloseError,
  McpRequestEntryConfigError,
  type McpRequestErrorCategory,
  type McpRequestOperation,
  type RequestScopedMcpEntryOptions,
  type ReceivingState,
  type RequestScopedOwnerResolver,
  type RequestScopedReceivingStatusPort,
  type RequestScopedSubscriptionPort,
} from './request-operation.js';

import { isAppLabel, type AppManagementRequest } from '../source/connected-apps.js';
import { SOURCE_ID } from '../source/contract.js';

const SERVER_INFO = { name: 'sttd-server', version: '0.0.0' };

/** `events` はSDKのServerCapabilities型にないため、型だけを広げて渡す。 */
type EventsCapabilities = ServerCapabilities & { events: Record<string, never> };

const APP_TOOLS = [
  {
    name: 'list_connected_apps',
    title: 'List connected sending apps',
    description: 'List apps allowed to send text to your Dot for the connected SendTextToDots account.',
    inputSchema: { type: 'object' as const, properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'add_connected_app',
    title: 'Create a sending app registration code',
    description: 'Issue a one-time code valid for 10 minutes. Issuing a new code immediately invalidates any previous unused registration code for this account. Show the code to the user to enter in the sending app while signed in to the same SendTextToDots account. The app is registered when the code is redeemed.',
    inputSchema: { type: 'object' as const, properties: { name: { type: 'string', minLength: 1, maxLength: 100 } }, required: ['name'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  {
    name: 'remove_connected_app',
    title: 'Remove a connected sending app',
    description: 'When explicitly requested, use the app ID from list_connected_apps to revoke that app’s permission to send text. The connected Dot and other apps keep working.',
    inputSchema: { type: 'object' as const, properties: { appId: { type: 'string', pattern: SOURCE_ID.source } }, required: ['appId'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
];

function parseAppManagementRequest(name: string, args: unknown): AppManagementRequest | undefined {
  if (!APP_TOOLS.some((tool) => tool.name === name)) return undefined;
  const keys = args === undefined ? [] : typeof args === 'object' && args !== null && !Array.isArray(args) ? Reflect.ownKeys(args) : null;
  if (name === 'list_connected_apps' && keys?.length === 0) return { kind: 'list' };
  if (keys?.length === 1 && typeof args === 'object' && args !== null) {
    const label: unknown = Object.getOwnPropertyDescriptor(args, 'name')?.value;
    const id: unknown = Object.getOwnPropertyDescriptor(args, 'appId')?.value;
    if (name === 'add_connected_app' && isAppLabel(label)) return { kind: 'issue', name: label };
    if (name === 'remove_connected_app' && typeof id === 'string' && SOURCE_ID.test(id)) return { kind: 'remove', appId: id };
  }
  throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Invalid arguments');
}

const REQUIRED = ['issuer', 'resource', 'clock', 'resolveOAuthOwner', 'subscriptions', 'onError'] as const;
const OPTIONAL = ['budgetMs', 'closeBudgetMs', 'receivingStatus', 'sendText', 'connectedApps'] as const;

/** 受信状態の照会tool（状態照会portを渡された入口だけが一覧・呼出しに出す）。 */
const RECEIVING_STATUS_TOOL = 'get_receiving_status';
const SEND_TEXT_TOOL = 'send_text';
const SEND_TEXT_RESULTS = ['delivered', 'not_delivered', 'delivery_unknown'] as const;
const RECEIVING_STATES: readonly ReceivingState[] = ['change_pending', 'subscribed', 'expired', 'linked'];

/** `tools/list`に出す定義（固定。owner・Grant・購読の値を含まない）。 */
function receivingStatusToolDefinition() {
  return {
    name: RECEIVING_STATUS_TOOL,
    title: 'Get receiving status',
    description:
      "Use this when the user asks whether their SendTextToDots account is ready to receive text, or why text is not arriving. " +
      'Read-only, account-level check of the signed-in user only: returns one state - change_pending (a new delivery destination awaits the user\'s confirmation), ' +
      'subscribed (an active subscription exists), expired (the last subscription expired), or linked (connected, waiting for a subscription). ' +
      'It does not return message text, history, destinations or identifiers, and "subscribed" does not guarantee delivery of any individual message. ' +
      'Do not call it to send text or to change subscriptions.',
    inputSchema: { type: 'object' as const, properties: {}, additionalProperties: false },
    outputSchema: {
      type: 'object' as const,
      properties: { state: { type: 'string', enum: [...RECEIVING_STATES] } },
      required: ['state'],
      additionalProperties: false,
    },
    annotations: { title: 'Get receiving status', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  };
}

function isReceivingState(value: unknown): value is ReceivingState {
  return (RECEIVING_STATES as readonly unknown[]).includes(value);
}

function sendTextToolDefinition() {
  return {
    name: SEND_TEXT_TOOL,
    title: 'Send text to your Dot',
    description: 'Send the exact text explicitly requested by the user to the receiving task registered to their connected SendTextToDots account. Use once per request. If delivery is unknown, ask the user to check their Dot before sending again.',
    inputSchema: { type: 'object' as const, properties: { text: { type: 'string', minLength: 1, maxLength: 4096 } }, required: ['text'], additionalProperties: false },
    outputSchema: { type: 'object' as const, properties: { status: { type: 'string', enum: [...SEND_TEXT_RESULTS] } }, required: ['status'], additionalProperties: false },
    annotations: { title: 'Send text to your Dot', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  };
}

/**
 * `events/subscribe`の1回の結果の固定分類（診断の通知だけに使う）。成功は`ok`、portの失敗はkind（callbackはreasonつき）、
 * 期限・中止・close・contextの不一致は`context_unavailable`、それ以外は`other`。error.message等の内容は使わない。
 * `Mcp-Method: events/subscribe`の要求が、handlerへ届かずに終わった時（SDKのparams検証・認証・入口の拒否）は`request_rejected`。
 */
export type McpSubscribeOutcome =
  | 'ok'
  | 'invalid_request'
  | 'unknown_event'
  | 'cursor_unsupported'
  | 'destination_change_pending'
  | 'grant_inactive'
  | 'conflict'
  | `callback_endpoint.${CallbackEndpointReason}`
  | 'context_unavailable'
  | 'request_rejected'
  | 'other';

/** entryの任意の通知（第2引数）。onSubscribeは`events/subscribe`の1回につき最大1回呼び、例外は無視して応答を変えない。 */
export interface RequestScopedMcpEntryAudit {
  readonly onSubscribe?: ((outcome: McpSubscribeOutcome) => void) | undefined;
}

const CALLBACK_REASONS: readonly CallbackEndpointReason[] = [
  'connection_refused',
  'timeout',
  'tls_error',
  'http_4xx',
  'http_5xx',
  'challenge_failed',
];

/** portの失敗のkindのうち、そのまま固定の分類にするもの（callback_endpointはreasonつきで別に写す）。 */
const SUBSCRIBE_FAILURE_KINDS = ['invalid_request', 'unknown_event', 'cursor_unsupported', 'destination_change_pending', 'grant_inactive', 'conflict'] as const;

function isSubscribeFailureKind(kind: unknown): kind is (typeof SUBSCRIBE_FAILURE_KINDS)[number] {
  return (SUBSCRIBE_FAILURE_KINDS as readonly unknown[]).includes(kind);
}

function isCallbackReason(reason: unknown): reason is CallbackEndpointReason {
  return (CALLBACK_REASONS as readonly unknown[]).includes(reason);
}

/** portの失敗のkind・reasonを、固定の分類へ写す（toProtocolErrorの写し方と同じ。未知は`other`）。 */
function subscribeOutcomeOf(kind: unknown, reason: unknown): McpSubscribeOutcome {
  if (isSubscribeFailureKind(kind)) return kind;
  if (kind === 'callback_endpoint' && isCallbackReason(reason)) return `callback_endpoint.${reason}`;
  return 'other';
}

/** 期限・中止・closeで要求が採用できなくなった印（verifierからverifyBearerTokenの外へ運ぶだけ）。 */
const UNAVAILABLE: unique symbol = Symbol('mcp_request_unavailable');
/** 待機を中止で打ち切った印。 */
const ABORTED: unique symbol = Symbol('mcp_request_aborted');
/**
 * resolverの例外（OAuthErrorを含む）・不正な戻り値の印。元の値を捨て、固定の500（server_error）にする。
 * 非OAuthErrorなのでSDKのbearerAuthChallengeResponseは固定body・WWW-Authenticateなしを返す。
 */
const RESOLVER_FAILED: unique symbol = Symbol('mcp_resolver_failed');

/** 認証前・SDK前に要求を採用できない時の固定の汎用応答。 */
const UNAVAILABLE_BODY = Buffer.from(JSON.stringify({ error: { code: 'temporarily_unavailable', retryable: true } }));

interface RequestState {
  readonly operation: McpRequestOperation;
  readonly controller: AbortController;
  /** verifierが採用したowner/Grant（SDKのauthInfo.extraと照合する）。 */
  auth: SubscriptionAuth | undefined;
  /** verifierが採用したaccess tokenの期限（epoch秒。SDKのAuthInfo.expiresAtと同じ単位）。受信状態の照会だけが使う。 */
  tokenExpiresAt: number | undefined;
  /** verifyBearerTokenが返し、req.authとしてSDKへ渡したobject。 */
  authInfo: AuthInfo | undefined;
  /** SDK（toNodeHandler）へ渡した後か。以後の中止は応答を書かずに接続を終える。 */
  sdkStarted: boolean;
  /** この要求の購読の通知（要求ごとに1つ）。 */
  readonly subscribeGate: SubscribeGate;
}

/** 1つのHTTP要求の購読の通知の状態。handlerが始まったか、通知を出したか（最大1回）。 */
interface SubscribeGate {
  handlerStarted: boolean;
  notified: boolean;
}

function fail(): never {
  throw new McpRequestEntryConfigError();
}

/** 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知の名前は拒否、getterは呼ばない）。 */
function dataFields(value: unknown, required: readonly string[], optional: readonly string[]): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) fail();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || optional.includes(key))) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) fail();
    if (descriptor.value !== undefined || required.includes(key)) taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) fail();
  return taken;
}

/** objectのmethodを、prototypeの連鎖をdescriptorで辿って1回だけ取り出し、元のobjectへ束縛する（accessor・Proxyは拒否、getterは呼ばない）。 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) fail();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) fail();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  return fail();
}

function plainFunction(value: unknown): (...args: unknown[]) => unknown {
  if (typeof value !== 'function' || types.isProxy(value)) fail();
  const found = value as Function;
  return (...args: unknown[]) => Reflect.apply(found, undefined, args);
}

function urlString(value: unknown): string {
  if (typeof value !== 'string' || value === '' || !URL.canParse(value)) fail();
  return value;
}

function boundedInteger(value: unknown, fallback: number, max: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0 || value > max) fail();
  return value;
}

/** 同期の例外もrejectにして、外部の関数を1回だけ呼ぶ。 */
function invoke<T>(call: () => T | PromiseLike<T>): Promise<T> {
  return new Promise<T>((resolve) => resolve(call()));
}

/**
 * promiseを、signalのabortまでで待つ。abortが先ならABORTEDで解決し、遅い値・rejectは捨てる（未処理rejectにしない）。
 * abortの listener はpromiseの決着でも外す。
 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T | typeof ABORTED> {
  return new Promise<T | typeof ABORTED>((resolve, reject) => {
    if (signal.aborted) {
      promise.catch(() => {});
      resolve(ABORTED);
      return;
    }
    const onAbort = (): void => resolve(ABORTED);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

/** resolverの戻り値から捕捉した既知5fieldだけ（余分なfieldは転送しない）。 */
interface CapturedOwner {
  readonly ownerId: string;
  readonly grantId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: number;
}

/** own data propertyの値だけを読む（accessorは呼ばずに拒否）。 */
function ownData(target: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || !('value' in descriptor)) throw RESOLVER_FAILED;
  return descriptor.value;
}

/**
 * nonnullのresolverの戻り値を、plain dataの既知5fieldとして1回だけ捕捉する。Proxy・getter・iterator・valueOf等を
 * 起動する前に拒否し、owner/grantは非空string、clientIdはstring、scopesはown dataのstring配列、expiresAtは有限number。
 * scope不足・期限切れの意味の検証は、verifyBearerToken（SDK）に任せる。不正はRESOLVER_FAILED。
 */
function captureOwner(value: unknown): CapturedOwner {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) throw RESOLVER_FAILED;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw RESOLVER_FAILED;
  const ownerId = ownData(value, 'ownerId');
  const grantId = ownData(value, 'grantId');
  const clientId = ownData(value, 'clientId');
  const scopesValue = ownData(value, 'scopes');
  const expiresAt = ownData(value, 'expiresAt');
  if (typeof ownerId !== 'string' || ownerId === '' || typeof grantId !== 'string' || grantId === '') throw RESOLVER_FAILED;
  if (typeof clientId !== 'string') throw RESOLVER_FAILED;
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) throw RESOLVER_FAILED;
  if (typeof scopesValue !== 'object' || scopesValue === null || types.isProxy(scopesValue) || !Array.isArray(scopesValue)) throw RESOLVER_FAILED;
  if (Object.getPrototypeOf(scopesValue) !== Array.prototype) throw RESOLVER_FAILED;
  const length = ownData(scopesValue, 'length');
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) throw RESOLVER_FAILED;
  const scopes: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const scope = ownData(scopesValue, String(index));
    if (typeof scope !== 'string') throw RESOLVER_FAILED;
    scopes.push(scope);
  }
  return { ownerId, grantId, clientId, scopes, expiresAt };
}

function authOf(ctx: ServerContext): SubscriptionAuth {
  // ownerとgrantは入口の認証結果だけから得る。paramsからは受け取らない。
  const { ownerId, grantId } = ctx.http?.authInfo?.extra ?? {};
  if (typeof ownerId !== 'string' || ownerId === '' || typeof grantId !== 'string' || grantId === '') {
    throw new ProtocolError(ProtocolErrorCode.InternalError, 'Owner not resolved');
  }
  return { ownerId, grantId };
}

/** 要求contextが無い・失われた・期限/中止/close後。値・理由を区別して返さない。 */
function contextUnavailable(): ProtocolError {
  return new ProtocolError(ProtocolErrorCode.InternalError, 'Request context unavailable');
}

function internalError(): ProtocolError {
  return new ProtocolError(ProtocolErrorCode.InternalError, 'Internal error');
}

/** protected resource metadata（認証なしで取得できる公開情報だけ）。組立ての失敗は固定のconfig error。 */
function publicMetadata(
  issuer: string,
  resource: string,
): { resourceUrl: URL; metadataUrl: string; protectedResourceMetadata: McpEntry['protectedResourceMetadata'] } {
  try {
    const resourceUrl = new URL(resource);
    const metadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
    const protectedResourceMetadata = {
      ...buildOAuthProtectedResourceMetadata({
        oauthMetadata: {
          issuer,
          authorization_endpoint: issuer + OAUTH_ROUTES.authorization,
          token_endpoint: issuer + OAUTH_ROUTES.token,
          response_types_supported: ['code'],
        },
        resourceServerUrl: resourceUrl,
        scopesSupported: [STTD_SCOPE],
      }),
      bearer_methods_supported: ['header'],
    };
    return { resourceUrl, metadataUrl, protectedResourceMetadata };
  } catch {
    return fail();
  }
}

/**
 * MCP入口を組み立てる。McpEntry（protectedResourceMetadata・metadataPath・handle・close）を返す。
 * 全ての検査・捕捉はここで1回だけ行い、以後は入力objectを読み直さない。不正はMcpRequestEntryConfigError。
 */
export function createRequestScopedMcpEntry(options: RequestScopedMcpEntryOptions, audit?: RequestScopedMcpEntryAudit): McpEntry {
  const fields = dataFields(options, REQUIRED, OPTIONAL);
  const auditFields = audit === undefined ? new Map<string, unknown>() : dataFields(audit, [], ['onSubscribe']);
  const onSubscribeFn = auditFields.has('onSubscribe') ? plainFunction(auditFields.get('onSubscribe')) : undefined;
  const issuer = urlString(fields.get('issuer'));
  const resource = urlString(fields.get('resource'));
  const clockNow = methodOf(fields.get('clock'), 'now');
  const resolve = plainFunction(fields.get('resolveOAuthOwner'));
  const portTarget = fields.get('subscriptions');
  const subscribe = methodOf(portTarget, 'subscribe');
  const unsubscribe = methodOf(portTarget, 'unsubscribe');
  const manageApps = fields.has('connectedApps') ? methodOf(fields.get('connectedApps'), 'manage') : undefined;
  const statusFor = fields.has('receivingStatus') ? methodOf(fields.get('receivingStatus'), 'statusFor') : undefined;
  const sendText = fields.has('sendText') ? methodOf(fields.get('sendText'), 'send') : undefined;
  const onErrorFn = plainFunction(fields.get('onError'));
  const budgetMs = boundedInteger(fields.get('budgetMs'), MCP_REQUEST_BUDGET_MS, MCP_REQUEST_BUDGET_MS);
  const closeBudgetMs = boundedInteger(fields.get('closeBudgetMs'), MCP_CLOSE_BUDGET_MS, MCP_CLOSE_BUDGET_MS);

  const report = (category: McpRequestErrorCategory): void => {
    try {
      onErrorFn(category);
    } catch {
      // 通知の失敗で要求の扱いを変えない。
    }
  };

  /** 要求ごとのgateで、最初の1回だけ通知する。 */
  const notifySubscribe = (gate: SubscribeGate, outcome: McpSubscribeOutcome): void => {
    if (gate.notified) return;
    gate.notified = true;
    if (onSubscribeFn === undefined) return;
    try {
      onSubscribeFn(outcome);
    } catch {
      // 通知の失敗で要求の扱いを変えない。
    }
  };

  const { resourceUrl, metadataUrl, protectedResourceMetadata } = publicMetadata(issuer, resource);

  /** entry所有: SDKへ渡したAuthInfo object → その要求のstate。handleの終了・closeで外す。 */
  const states = new WeakMap<AuthInfo, RequestState>();
  const active = new Set<RequestState>();
  let closed = false;
  let closing: Promise<void> | undefined;

  /** 最新のclock・signal・closeで、要求がまだ有効か。無効なら要求を中止する。 */
  const alive = (state: RequestState): boolean => {
    if (closed || state.controller.signal.aborted) return false;
    let now: unknown;
    try {
      now = clockNow();
    } catch {
      report('clock');
      state.controller.abort();
      return false;
    }
    if (typeof now !== 'number' || !Number.isFinite(now) || now >= state.operation.deadlineAt) {
      state.controller.abort();
      return false;
    }
    // clockの観測中のclose・中止も見る。
    return !closed && !state.controller.signal.aborted;
  };

  /** callbackの実作業の開始時: 同じAuthInfo objectのstateと、元authOfのowner/Grantの一致、最新の期限・中止を確かめる。 */
  const stateOf = (ctx: ServerContext): RequestState => {
    const authInfo = ctx.http?.authInfo;
    const state = authInfo === undefined ? undefined : states.get(authInfo);
    if (state === undefined || state.auth === undefined) {
      report('context');
      throw contextUnavailable();
    }
    const auth = authOf(ctx);
    if (auth.ownerId !== state.auth.ownerId || auth.grantId !== state.auth.grantId) {
      report('context');
      throw contextUnavailable();
    }
    if (!alive(state)) throw contextUnavailable();
    return state;
  };

  /**
   * 受信状態の照会だけ: 最新の捕捉clockで、認証が採用したaccess token自身の期限（epoch秒）に達していないことを確かめる。
   * 期限と等しい時刻以降は状態なしの固定error。clockの例外・不正値は既存の扱い（clockの通知・要求の中止・context unavailable）。
   */
  const requireTokenLive = (state: RequestState): void => {
    const expiresAt = state.tokenExpiresAt;
    if (expiresAt === undefined) {
      report('context');
      throw contextUnavailable();
    }
    let now: unknown;
    try {
      now = clockNow();
    } catch {
      report('clock');
      state.controller.abort();
      throw contextUnavailable();
    }
    if (typeof now !== 'number' || !Number.isFinite(now)) {
      state.controller.abort();
      throw contextUnavailable();
    }
    if (!(now < expiresAt * 1000)) throw new ProtocolError(ProtocolErrorCode.InternalError, 'Access token expired');
  };

  /**
   * portの失敗を、固定のProtocolErrorへ写す。それ以外（未知の例外・不正な分類）は固定InternalError。
   * classifiedがあれば、写した固定の分類を書く（未知はそのまま）。
   */
  const toProtocolError = (error: unknown, classified?: { outcome: McpSubscribeOutcome }): ProtocolError => {
    let kind: unknown;
    let reason: unknown;
    try {
      if (error instanceof SubscribeError) {
        const failure: unknown = error.failure;
        if (typeof failure === 'object' && failure !== null) {
          kind = (failure as { kind?: unknown }).kind;
          if (kind === 'callback_endpoint') reason = (failure as { reason?: unknown }).reason;
        }
      }
    } catch {
      kind = undefined;
    }
    if (classified) classified.outcome = subscribeOutcomeOf(kind, reason);
    switch (kind) {
      case 'invalid_request':
        return new ProtocolError(ProtocolErrorCode.InvalidParams, 'Invalid subscription request');
      case 'callback_endpoint':
        if (CALLBACK_REASONS.includes(reason as CallbackEndpointReason)) {
          return new ProtocolError(ERROR_CALLBACK_ENDPOINT, 'Callback endpoint verification failed', { reason });
        }
        break;
      case 'unknown_event':
        return new ProtocolError(ERROR_NOT_FOUND, 'Unknown event', { kind: 'event' });
      case 'cursor_unsupported':
        return new ProtocolError(ERROR_UNSUPPORTED, 'Cursor is not supported', { feature: 'cursor' });
      case 'destination_change_pending': {
        const forbidden: ForbiddenReason = 'destination_change_pending';
        return new ProtocolError(ERROR_FORBIDDEN, 'Destination change is pending approval', { reason: forbidden });
      }
      case 'grant_inactive': {
        const forbidden: ForbiddenReason = 'access_revoked';
        return new ProtocolError(ERROR_FORBIDDEN, 'Access was revoked', { reason: forbidden });
      }
      case 'conflict':
        return new ProtocolError(ProtocolErrorCode.InternalError, 'Subscription changed concurrently');
    }
    report('port');
    return internalError();
  };

  /**
   * portを呼び、元operationの中止までで待つ。await後・SDKへ戻す前にも元operationを再検査する。
   * classifiedがあれば、失敗の固定の分類を書く（期限・中止・closeは`context_unavailable`）。
   */
  const callPort = async <T>(state: RequestState, call: () => T | PromiseLike<T>, classified?: { outcome: McpSubscribeOutcome }): Promise<T> => {
    let result: T | typeof ABORTED;
    try {
      result = await untilAborted(invoke(call), state.operation.signal);
    } catch (error) {
      if (!alive(state)) {
        if (classified) classified.outcome = 'context_unavailable';
        throw contextUnavailable();
      }
      throw toProtocolError(error, classified);
    }
    if (result === ABORTED || !alive(state)) {
      if (classified) classified.outcome = 'context_unavailable';
      throw contextUnavailable();
    }
    return result;
  };

  const handler = createMcpHandler(
    () => {
      // 構成済みのツールだけを公開する。
      const capabilities: EventsCapabilities = { events: {}, tools: {} };
      const server = new Server(SERVER_INFO, { capabilities });

      server.setRequestHandler('tools/list', (_request, ctx) =>
        (async () => {
          authOf(ctx);
          return { tools: [...(statusFor === undefined ? [] : [receivingStatusToolDefinition()]), ...(sendText === undefined ? [] : [sendTextToolDefinition()]), ...(manageApps === undefined ? [] : APP_TOOLS)] };
        })(),
      );

      if (statusFor !== undefined || sendText !== undefined || manageApps !== undefined) {
        server.setRequestHandler('tools/call', (request, ctx) =>
          (async () => {
            // 名前と引数はportを呼ぶ前に検査する。
            const { name, arguments: args } = request.params;
            const appRequest = manageApps === undefined ? undefined : parseAppManagementRequest(name, args);
            if (appRequest !== undefined && manageApps !== undefined) {
              const state = stateOf(ctx);
              requireTokenLive(state);
              const auth = Object.freeze({ ...state.auth! });
              const operation = Object.freeze({ signal: state.operation.signal, deadlineAt: Math.min(state.operation.deadlineAt, state.tokenExpiresAt! * 1000) });
              const result = await callPort(state, () => manageApps(auth, appRequest, operation));
              requireTokenLive(state);
              if (typeof result !== 'object' || result === null) throw internalError();
              return { content: [{ type: 'text' as const, text: JSON.stringify(result) }], structuredContent: result, isError: 'error' in result };
            }
            if (name === SEND_TEXT_TOOL && sendText !== undefined) {
              const value = typeof args === 'object' && args !== null ? ownData(args, 'text') : undefined;
              if (typeof value !== 'string' || Reflect.ownKeys(args!).length !== 1 || value.trim().length === 0 || Buffer.byteLength(value, 'utf8') > 4096) {
                throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Invalid text');
              }
              const state = stateOf(ctx);
              requireTokenLive(state);
              const auth = Object.freeze({ ...state.auth! });
              const operation = Object.freeze({ signal: state.operation.signal, deadlineAt: Math.min(state.operation.deadlineAt, state.tokenExpiresAt! * 1000) });
              const outcome = await callPort(state, () => sendText(auth, value, operation));
              if (!(SEND_TEXT_RESULTS as readonly unknown[]).includes(outcome)) throw internalError();
              const structured = { status: outcome };
              return { content: [{ type: 'text' as const, text: JSON.stringify(structured) }], structuredContent: structured, isError: false };
            }
            if (name !== RECEIVING_STATUS_TOOL || statusFor === undefined) throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Unknown tool');
            if (args !== undefined && (typeof args !== 'object' || args === null || Array.isArray(args) || Reflect.ownKeys(args).length !== 0)) {
              throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Invalid arguments');
            }
            const state = stateOf(ctx);
            // 照会の開始前と結果を返す直前に、要求期限（alive）に加えてaccess token自身の期限も確かめる（照会中の期限到達で状態を出さない）。
            requireTokenLive(state);
            const auth = Object.freeze({ ...state.auth! });
            const outcome: unknown = await callPort(state, () => statusFor(auth, state.operation));
            if (!isReceivingState(outcome)) {
              report('port');
              throw internalError();
            }
            if (!alive(state)) throw contextUnavailable();
            requireTokenLive(state);
            if (!alive(state)) throw contextUnavailable();
            const structured = { state: outcome };
            return { content: [{ type: 'text' as const, text: JSON.stringify(structured) }], structuredContent: structured, isError: false };
          })(),
        );
      }

      server.setRequestHandler('events/list', { params: EventsListParams }, (_params, ctx) =>
        (async () => {
          authOf(ctx);
          return eventsListResult();
        })(),
      );

      server.setRequestHandler('events/subscribe', { params: EventsSubscribeParams }, (params, ctx) =>
        (async () => {
          // この1回の結果の固定の分類。最後に1回だけ、この要求のgateで通知する（stateOfの失敗はcontext）。
          // 要求のstateが引けない時はここでは出さず、入口が`request_rejected`として出す。
          const authInfo = ctx.http?.authInfo;
          const gate = authInfo === undefined ? undefined : states.get(authInfo)?.subscribeGate;
          if (gate !== undefined) gate.handlerStarted = true;
          const classified: { outcome: McpSubscribeOutcome } = { outcome: 'context_unavailable' };
          try {
            const state = stateOf(ctx);
            classified.outcome = 'other';
            const auth = Object.freeze({ ...state.auth! });
            const input: SubscribeInput = Object.freeze({
              name: params.name,
              url: params.delivery.url,
              secret: params.delivery.secret,
              ttlMs: params.ttlMs,
              cursor: params.cursor,
            });
            const outcome: unknown = await callPort(state, () => subscribe(auth, input, state.operation), classified);
            // portの結果はsubscribeResultの形（id文字列・refreshBefore文字列/null）の時だけ写す。
            let id: unknown;
            let refreshBefore: unknown;
            try {
              ({ id, refreshBefore } = outcome as { id?: unknown; refreshBefore?: unknown });
            } catch {
              id = undefined;
            }
            const refresh = refreshBefore === null ? null : typeof refreshBefore === 'string' ? refreshBefore : undefined;
            if (typeof id !== 'string' || refresh === undefined) {
              report('port');
              throw internalError();
            }
            if (!alive(state)) {
              classified.outcome = 'context_unavailable';
              throw contextUnavailable();
            }
            const result = subscribeResult(id, refresh);
            classified.outcome = 'ok';
            return result;
          } finally {
            if (gate !== undefined) notifySubscribe(gate, classified.outcome);
          }
        })(),
      );

      server.setRequestHandler('events/unsubscribe', { params: EventsUnsubscribeParams }, (params, ctx) =>
        (async () => {
          const state = stateOf(ctx);
          const auth = Object.freeze({ ...state.auth! });
          const identity = Object.freeze({ name: params.name, url: params.delivery.url });
          await callPort(state, () => unsubscribe(auth, identity, state.operation));
          return {};
        })(),
      );

      return server;
    },
    {
      // 2026-07-28だけを扱う。ハンドラーは途中の通知を出さないため、既定のresponseModeで応答は1つのJSONになる。
      legacy: 'reject',
      maxRequestBodySize: MAX_MCP_BODY_BYTES,
      onerror: () => report('sdk'),
    },
  );

  const serve = toNodeHandler(
    {
      async fetch(request, fetchOptions) {
        const response = await handler.fetch(request, fetchOptions);
        const headers = new Headers(response.headers);
        headers.set('Cache-Control', 'no-store');
        headers.set('X-Content-Type-Options', 'nosniff');
        return new Response(response.body, { status: response.status, headers });
      },
    },
    { maxRequestBodySize: MAX_MCP_BODY_BYTES, onerror: () => report('adapter') },
  );

  /** SDKへ渡す前の固定の非成功。接続が既に無ければ書かずに閉じる。 */
  const refuse = (req: IncomingMessage, res: ServerResponse): void => {
    if (res.headersSent || res.destroyed || req.aborted === true) {
      if (!res.writableEnded) res.destroy();
      return;
    }
    res.writeHead(503, {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      // 本文を読まずに答えるため、接続を再利用させない。
      Connection: 'close',
      'Content-Type': 'application/json',
      'Content-Length': UNAVAILABLE_BODY.length,
    });
    res.end(UNAVAILABLE_BODY);
  };

  const challenge = async (error: unknown, bearer: VerifyBearerTokenOptions, res: ServerResponse): Promise<void> => {
    const response = bearerAuthChallengeResponse(error, bearer);
    const payload = Buffer.from(await response.arrayBuffer());
    const challengeHeader = response.headers.get('www-authenticate');
    if (res.headersSent || res.destroyed) return;
    res.writeHead(response.status, {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      Connection: 'close',
      'Content-Type': 'application/json',
      'Content-Length': payload.length,
      ...(challengeHeader === null ? {} : { 'WWW-Authenticate': challengeHeader }),
    });
    res.end(payload);
  };

  /**
   * 1要求を扱う。`Mcp-Method`のheaderが固定の`events/subscribe`で、handlerが始まらないまま終わった時だけ、
   * `request_rejected`を1回通知する（本文・応答は読まない。別のmethod・headerなしは通知しない）。
   */
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const subscribeRequest = req.headers['mcp-method'] === 'events/subscribe';
    const gate: SubscribeGate = { handlerStarted: false, notified: false };
    try {
      await serveRequest(req, res, gate);
    } finally {
      if (subscribeRequest && !gate.handlerStarted) notifySubscribe(gate, 'request_rejected');
    }
  }

  async function serveRequest(req: IncomingMessage, res: ServerResponse, subscribeGate: SubscribeGate): Promise<void> {
    // 最初のawaitより前に、closed・clock・既に切れた接続を見る。
    if (closed) return refuse(req, res);
    let receivedAt: unknown;
    try {
      receivedAt = clockNow();
    } catch {
      report('clock');
      return refuse(req, res);
    }
    if (typeof receivedAt !== 'number' || !Number.isFinite(receivedAt) || receivedAt < 0) {
      report('clock');
      return refuse(req, res);
    }
    if (closed || req.aborted === true || res.destroyed) return refuse(req, res);

    const deadlineAt = Math.floor(receivedAt) + budgetMs;
    const controller = new AbortController();
    const operation: McpRequestOperation = Object.freeze({ deadlineAt, signal: controller.signal });
    const state: RequestState = { operation, controller, auth: undefined, tokenExpiresAt: undefined, authInfo: undefined, sdkStarted: false, subscribeGate };
    active.add(state);

    const abort = (): void => controller.abort();
    // 正常完了（全て書き終えた）後のcloseは中止にしない。
    const onResponseClose = (): void => {
      if (!res.writableFinished) controller.abort();
    };
    // SDKへ渡した後の中止は、未完了のHTTP接続を終える（正常結果を公開しない。別のJSON-RPC応答を重ねない）。
    const onAbort = (): void => {
      if (state.sdkStarted && !res.writableEnded) res.destroy();
    };
    const timer = setTimeout(abort, Math.max(0, deadlineAt - receivedAt));
    req.once('aborted', abort);
    res.once('close', onResponseClose);
    controller.signal.addEventListener('abort', onAbort, { once: true });

    try {
      // Bearer検証は既存の公開verifyBearerTokenと同じissuer/resource/scopeの契約。verifierは要求内の閉包で、同じoperationをresolverへ渡す。
      const bearer: VerifyBearerTokenOptions = {
        verifier: {
          async verifyAccessToken(token): Promise<AuthInfo> {
            if (!alive(state)) throw UNAVAILABLE;
            let resolved: unknown;
            try {
              resolved = await untilAborted(invoke(() => resolve(token, operation)), controller.signal);
            } catch {
              // 下位のOAuthErrorを含む全ての例外は元の値を捨てる（SDKのhelperへ渡すとmessageが応答/見出しへ出る）。期限・中止を優先する。
              throw alive(state) ? RESOLVER_FAILED : UNAVAILABLE;
            }
            // 認証結果は、期限・中止の再検査の後だけ採用する。
            if (resolved === ABORTED || !alive(state)) throw UNAVAILABLE;
            // 無効な資格情報はnullだけ。理由（不明・期限切れ・失効・別resource・端末token）を区別して返さない。
            if (resolved === null) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid access token');
            const owner = captureOwner(resolved);
            const auth = { ownerId: owner.ownerId, grantId: owner.grantId };
            state.auth = Object.freeze({ ...auth });
            state.tokenExpiresAt = owner.expiresAt;
            return {
              // 受け取ったtokenをMCPのハンドラーへ引き回さない。
              token: '',
              clientId: owner.clientId,
              scopes: [...owner.scopes],
              expiresAt: owner.expiresAt,
              resource: resourceUrl,
              extra: Object.freeze({ ...auth }),
            };
          },
        },
        requiredScopes: [STTD_SCOPE],
        resourceMetadataUrl: metadataUrl,
        expectedResource: resourceUrl,
      };

      let verified: AuthInfo | typeof ABORTED;
      try {
        verified = await untilAborted(invoke(() => verifyBearerToken(req.headers.authorization, bearer)), controller.signal);
      } catch (error) {
        if (error === UNAVAILABLE || !alive(state)) return refuse(req, res);
        if (error === RESOLVER_FAILED) {
          // 非OAuthErrorの印だけを渡し、SDKの固定500（server_error・WWW-Authenticateなし）にする。
          report('resolver');
          return await challenge(RESOLVER_FAILED, bearer, res);
        }
        // ここに来るOAuthErrorは、entry自身（null）とSDK（header不正・resource・scope不足・期限切れ）が作ったものだけ。
        if (!(error instanceof OAuthError)) report('sdk');
        return await challenge(error, bearer, res);
      }
      if (verified === ABORTED || !alive(state) || state.auth === undefined) return refuse(req, res);

      // verifyBearerTokenが返した同じobjectをreq.authとしてSDKへ渡し、そのobjectでstateを引けるようにする。
      const authInfo: AuthInfo = verified;
      state.authInfo = authInfo;
      states.set(authInfo, state);
      state.sdkStarted = true;
      let served: void | typeof ABORTED;
      try {
        // IncomingMessageの任意項目の型がexactOptionalPropertyTypesでadapterの構造型と合わないため、型だけ合わせる。
        served = await untilAborted(invoke(() => serve(Object.assign(req, { auth: authInfo }) as NodeIncomingMessageLike, res)), controller.signal);
      } catch {
        report('adapter');
        if (!res.writableEnded) res.destroy();
        return;
      }
      if (served === ABORTED && !res.writableEnded) res.destroy();
    } finally {
      clearTimeout(timer);
      req.off('aborted', abort);
      res.off('close', onResponseClose);
      controller.signal.removeEventListener('abort', onAbort);
      active.delete(state);
      if (state.authInfo !== undefined) states.delete(state.authInfo);
    }
  }

  function close(): Promise<void> {
    if (closing !== undefined) return closing;
    // 先にclosedを確定し、進行中の要求を中止してmapから外す。以後のhandleは新resolver/SDK/portを始めない。
    closed = true;
    for (const state of active) {
      state.controller.abort();
      if (state.authInfo !== undefined) states.delete(state.authInfo);
    }
    closing = (async () => {
      let timer: NodeJS.Timeout | undefined = undefined;
      const sdkClose = invoke(() => handler.close());
      sdkClose.catch(() => {});
      try {
        await Promise.race([
          sdkClose,
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => reject(new McpRequestEntryCloseError()), closeBudgetMs);
          }),
        ]);
      } catch {
        throw new McpRequestEntryCloseError();
      } finally {
        clearTimeout(timer);
      }
    })();
    return closing;
  }

  return Object.freeze({
    protectedResourceMetadata,
    metadataPath: new URL(metadataUrl).pathname,
    handle,
    close,
  });
}
