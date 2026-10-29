// 既存URLを保つgateway配置（topology gateway-v1）の契約。配置設定のtopologyを副作用の前に検証し、role（API/MCP）ごとの固定
// backend（transport authority＝IAM audienceの正式service URL）・gatewayの実行主体・入口の量の上限を返す。省略は従来のdirect配置
// （gatewayもbackendも使わない）。不正な値はdirect/匿名へ降格せず設定errorにする。
//   - route表は既存handlerの公開routeだけ（prefixだけで任意pathを通さない）。pathはwireの生bytesのまま照合し、decode・正規化しない。
//   - gatewayが付ける内部headerは2つだけ（IAMのX-Serverless-Authorizationと残時間）。外部から来た同名は常に除去して作り直す。
// このmoduleはpureで、SDK・資格・env・network 0。

import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { dataFields } from '../protection/google-sdk-call.js';

export const GATEWAY_TOPOLOGY_MODE = 'gateway-v1';
/** 元の要求予算（gateway受付から共有し、backendで延長しない）。 */
export const GATEWAY_REQUEST_BUDGET_MS = 20_000;
/** gateway→backendの残時間（ミリ秒の正規十進）。外部入力は除去する。 */
export const GATEWAY_BUDGET_HEADER = 'x-sttd-gateway-budget-ms';
/** Cloud Run service間認証のheader（利用者のAuthorizationとは別）。外部入力は除去する。 */
export const SERVERLESS_AUTHORIZATION_HEADER = 'x-serverless-authorization';

export type GatewayRole = 'api' | 'connect';

/** 受付時刻の時計（epoch ms）。 */
export interface GatewayClock {
  now(): number;
}

export interface GatewayRoleTopology {
  /** 業務backendのCloud Run service名（K_SERVICE gate）。 */
  readonly backendServiceName: string;
  /** 業務backendの正式なservice URL（`https://<host>`）。transport HostとIAM audienceの両方に使う。 */
  readonly backendOrigin: string;
  /** gatewayの実行主体（業務backendの主体とは別）。 */
  readonly gatewayServiceAccount: string;
}

export interface GatewayLimits {
  /** 転送する要求本文の上限（byte）。 */
  readonly maxBodyBytes: number;
  /** process内の同時処理slot（待機列0）。 */
  readonly maxConcurrent: number;
  /** process内token bucketの補充（毎秒）。 */
  readonly ratePerSecond: number;
  /** token bucketの容量。 */
  readonly burst: number;
}

export interface GatewayTopology {
  readonly mode: typeof GATEWAY_TOPOLOGY_MODE;
  readonly api: GatewayRoleTopology;
  readonly connect: GatewayRoleTopology;
  readonly limits: GatewayLimits;
}

/** topologyの検証に使う、検証済みの配置値。 */
export interface GatewayTopologyContext {
  readonly apiServiceName: string;
  readonly connectServiceName: string;
  readonly apiPublicOrigin: string;
  readonly connectPublicOrigin: string;
  readonly apiServiceAccount: string;
  readonly connectServiceAccount: string;
  readonly isServiceAccount: (value: string) => boolean;
}

const ROLE_KEYS = ['backendServiceName', 'backendOrigin', 'gatewayServiceAccount'] as const;
const LIMIT_KEYS = ['maxBodyBytes', 'maxConcurrent', 'ratePerSecond', 'burst'] as const;
const TOP_KEYS = ['mode', 'api', 'connect', 'limits'] as const;
const CLOUD_RUN_NAME = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const LIMIT_MAX: Readonly<Record<(typeof LIMIT_KEYS)[number], number>> = { maxBodyBytes: 1_048_576, maxConcurrent: 1_000, ratePerSecond: 10_000, burst: 10_000 };

/** 固定の設定error（値・causeを持たない）。 */
export class GatewayTopologyError extends Error {
  override readonly name = 'GatewayTopologyError';
  constructor() {
    super('gateway_topology_invalid');
  }
}

function fail(): never {
  throw new GatewayTopologyError();
}

/** `https://<host>`のauthority（検証済みoriginだけ）。 */
export function authorityOf(origin: string): string {
  return new URL(origin).host;
}

function roleOf(value: unknown, isServiceAccount: (value: string) => boolean): GatewayRoleTopology {
  const fields = dataFields(value, ROLE_KEYS);
  const backendServiceName = fields.get('backendServiceName');
  const backendOrigin = fields.get('backendOrigin');
  const gatewayServiceAccount = fields.get('gatewayServiceAccount');
  if (typeof backendServiceName !== 'string' || !CLOUD_RUN_NAME.test(backendServiceName)) fail();
  if (!isDevelopmentPublicOrigin(backendOrigin)) fail();
  if (typeof gatewayServiceAccount !== 'string' || !isServiceAccount(gatewayServiceAccount)) fail();
  return Object.freeze({ backendServiceName, backendOrigin: backendOrigin as string, gatewayServiceAccount });
}

/**
 * 配置設定のtopologyを検証する。省略（undefined）とliteral 'direct'はundefined（従来のdirect配置）。それ以外は完全なgateway-v1だけ
 * （欠落・未知key・同じ名前/主体/originの共用・範囲外の上限は設定error）。
 */
export function parseGatewayTopology(raw: unknown, context: GatewayTopologyContext): GatewayTopology | undefined {
  if (raw === undefined || raw === 'direct') return undefined;
  try {
    const top = dataFields(raw, TOP_KEYS);
    if (top.get('mode') !== GATEWAY_TOPOLOGY_MODE) fail();
    const api = roleOf(top.get('api'), context.isServiceAccount);
    const connect = roleOf(top.get('connect'), context.isServiceAccount);
    const names = new Set([context.apiServiceName, context.connectServiceName, api.backendServiceName, connect.backendServiceName]);
    if (names.size !== 4) fail();
    const origins = new Set([context.apiPublicOrigin, context.connectPublicOrigin, api.backendOrigin, connect.backendOrigin].map(authorityOf));
    if (origins.size !== 4) fail();
    const accounts = new Set([context.apiServiceAccount, context.connectServiceAccount, api.gatewayServiceAccount, connect.gatewayServiceAccount]);
    if (accounts.size !== 4) fail();
    const limitFields = dataFields(top.get('limits'), LIMIT_KEYS);
    const limits: Record<string, number> = {};
    for (const key of LIMIT_KEYS) {
      const value = limitFields.get(key);
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > LIMIT_MAX[key]) fail();
      limits[key] = value;
    }
    return Object.freeze({ mode: GATEWAY_TOPOLOGY_MODE, api, connect, limits: Object.freeze(limits as unknown as GatewayLimits) });
  } catch {
    throw new GatewayTopologyError();
  }
}

// ---------- route表（既存handlerの公開routeだけ） ----------

interface Route {
  readonly path: string | RegExp;
  readonly methods: readonly string[];
}

const ID = '[A-Za-z0-9_-]{1,128}';

/** 送信API（delivery/api.ts・console-cors.ts）の公開route。CORS preflightを含む。 */
const API_ROUTES: readonly Route[] = Object.freeze([
  { path: '/v2/commands', methods: ['POST', 'OPTIONS'] },
  { path: new RegExp(`^/v2/commands/${ID}(?:/cancel)?$`), methods: ['GET', 'POST', 'DELETE', 'OPTIONS'] },
  { path: '/v2/encryption-key', methods: ['GET', 'OPTIONS'] },
  { path: '/v2/encryption-key/reissue', methods: ['POST', 'OPTIONS'] },
  { path: '/v2/encrypted-commands', methods: ['POST', 'OPTIONS'] },
]);

/** MCP接続（connect/kms-server.ts）の公開route: discovery・OAuth・interaction・許可元承認・MCP・接続照会/切断・既存script。 */
const CONNECT_ROUTES: readonly Route[] = Object.freeze([
  { path: '/mcp', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'] },
  { path: /^\/\.well-known\/(?:oauth-authorization-server|openid-configuration|oauth-protected-resource)(?:\/mcp)?$/, methods: ['GET', 'OPTIONS'] },
  { path: new RegExp(`^/oauth/(?:authorize|token|jwks|revoke|introspect|userinfo|me|reg|session/end|session/end/confirm|backchannel|device/auth)(?:/${ID})?$`), methods: ['GET', 'POST', 'OPTIONS'] },
  { path: new RegExp(`^/interaction/${ID}(?:/[a-z][a-z-]{0,31})?$`), methods: ['GET', 'POST'] },
  { path: new RegExp(`^/v1/source/approvals/${ID}$`), methods: ['GET', 'POST'] },
  { path: '/v1/web/connection', methods: ['GET', 'OPTIONS'] },
  { path: '/v1/web/disconnect', methods: ['POST', 'OPTIONS'] },
  { path: /^\/(?:static|assets)\/[A-Za-z0-9_-]{1,64}(?:\.[A-Za-z0-9_-]{1,16}){0,2}\.(?:js|css|svg|png|ico)$/, methods: ['GET'] },
]);

const ROUTES: Readonly<Record<GatewayRole, readonly Route[]>> = { api: API_ROUTES, connect: CONNECT_ROUTES };

/** origin-formのrequest-target（`/`始まり・可視ASCIIだけ・`//`始まり/`#`なし）。 */
const ORIGIN_FORM = /^\/(?!\/)[\x21-\x22\x24-\x7e]*$/;

export type RouteMatch = 'allowed' | 'not_found' | 'method_not_allowed' | 'invalid_target';

/** request-targetを生bytesのまま分け、role表と照合する（decode・正規化0）。 */
export function matchGatewayRoute(role: GatewayRole, method: string, target: string): RouteMatch {
  if (typeof target !== 'string' || target.length > 4096 || !ORIGIN_FORM.test(target)) return 'invalid_target';
  const query = target.indexOf('?');
  const path = query === -1 ? target : target.slice(0, query);
  const route = ROUTES[role].find((item) => (typeof item.path === 'string' ? item.path === path : item.path.test(path)));
  if (route === undefined) return 'not_found';
  return route.methods.includes(method) ? 'allowed' : 'method_not_allowed';
}
