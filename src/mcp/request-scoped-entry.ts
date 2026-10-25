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
  type RequestScopedOwnerResolver,
  type RequestScopedSubscriptionPort,
} from './request-operation.js';

const SERVER_INFO = { name: 'sttd-server', version: '0.0.0' };

/** `events` はSDKのServerCapabilities型にないため、型だけを広げて渡す。 */
type EventsCapabilities = ServerCapabilities & { events: Record<string, never> };

const REQUIRED = ['issuer', 'resource', 'clock', 'resolveOAuthOwner', 'subscriptions', 'onError'] as const;
const OPTIONAL = ['budgetMs', 'closeBudgetMs'] as const;

const CALLBACK_REASONS: readonly CallbackEndpointReason[] = [
  'connection_refused',
  'timeout',
  'tls_error',
  'http_4xx',
  'http_5xx',
  'challenge_failed',
];

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
  /** verifyBearerTokenが返し、req.authとしてSDKへ渡したobject。 */
  authInfo: AuthInfo | undefined;
  /** SDK（toNodeHandler）へ渡した後か。以後の中止は応答を書かずに接続を終える。 */
  sdkStarted: boolean;
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
export function createRequestScopedMcpEntry(options: RequestScopedMcpEntryOptions): McpEntry {
  const fields = dataFields(options, REQUIRED, OPTIONAL);
  const issuer = urlString(fields.get('issuer'));
  const resource = urlString(fields.get('resource'));
  const clockNow = methodOf(fields.get('clock'), 'now');
  const resolve = plainFunction(fields.get('resolveOAuthOwner'));
  const portTarget = fields.get('subscriptions');
  const subscribe = methodOf(portTarget, 'subscribe');
  const unsubscribe = methodOf(portTarget, 'unsubscribe');
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

  /** portの失敗を、固定のProtocolErrorへ写す。それ以外（未知の例外・不正な分類）は固定InternalError。 */
  const toProtocolError = (error: unknown): ProtocolError => {
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

  /** portを呼び、元operationの中止までで待つ。await後・SDKへ戻す前にも元operationを再検査する。 */
  const callPort = async <T>(state: RequestState, call: () => T | PromiseLike<T>): Promise<T> => {
    let result: T | typeof ABORTED;
    try {
      result = await untilAborted(invoke(call), state.operation.signal);
    } catch (error) {
      if (!alive(state)) throw contextUnavailable();
      throw toProtocolError(error);
    }
    if (result === ABORTED || !alive(state)) throw contextUnavailable();
    return result;
  };

  const handler = createMcpHandler(
    () => {
      // tools:{}は空一覧のためだけ。実行可能なtoolとtools/callは提供しない。
      const capabilities: EventsCapabilities = { events: {}, tools: {} };
      const server = new Server(SERVER_INFO, { capabilities });

      server.setRequestHandler('tools/list', (_request, ctx) =>
        (async () => {
          authOf(ctx);
          return { tools: [] };
        })(),
      );

      server.setRequestHandler('events/list', { params: EventsListParams }, (_params, ctx) =>
        (async () => {
          authOf(ctx);
          return eventsListResult();
        })(),
      );

      server.setRequestHandler('events/subscribe', { params: EventsSubscribeParams }, (params, ctx) =>
        (async () => {
          const state = stateOf(ctx);
          const auth = Object.freeze({ ...state.auth! });
          const input: SubscribeInput = Object.freeze({
            name: params.name,
            url: params.delivery.url,
            secret: params.delivery.secret,
            ttlMs: params.ttlMs,
            cursor: params.cursor,
          });
          const outcome: unknown = await callPort(state, () => subscribe(auth, input, state.operation));
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
          if (!alive(state)) throw contextUnavailable();
          return subscribeResult(id, refresh);
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

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
    const state: RequestState = { operation, controller, auth: undefined, authInfo: undefined, sdkStarted: false };
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
