// 既存URLを保つgateway配置（topology gateway-v1）の契約。配置設定のtopologyを副作用の前に検証し、role（API/MCP）ごとの固定
// backend（transport authority＝IAM audienceの正式service URL）・gatewayの実行主体・入口の量の上限を返す。省略は従来のdirect配置
// （gatewayもbackendも使わない）。不正な値はdirect/匿名へ降格せず設定errorにする。
//   - route表は既存handlerの公開routeだけ（prefixだけで任意pathを通さない）。pathはwireの生bytesのまま照合し、decode・正規化しない。
//   - gatewayが付ける内部headerは2つだけ（IAMのX-Serverless-Authorizationと絶対期限）。外部から来た同名は常に除去して作り直す。
// このmoduleはpureで、SDK・資格・env・network 0。

import { isDevelopmentPublicOrigin } from '../http/origin.js';
import { dataFields } from '../protection/google-sdk-call.js';
import { MAX_BODY_BYTES, MAX_COMMAND_BODY_BYTES, MAX_MCP_BODY_BYTES } from '../policy.js';

export const GATEWAY_TOPOLOGY_MODE = 'gateway-v1';
/** 元の要求予算（gateway受付から共有し、backendで延長しない）。 */
export const GATEWAY_REQUEST_BUDGET_MS = 20_000;
/** gateway受付で確定した絶対期限（UNIX ms・正規十進）。外部入力は除去して作り直す。backendは自身の最大20秒と短い方を使う。 */
export const GATEWAY_DEADLINE_HEADER = 'x-sttd-gateway-deadline';
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

// ---------- route表（既存handler・pinned Providerの実routeと同じpath/method・route別の本文上限） ----------
// 照合元: delivery/api.ts（COMMAND_PATH・method・本文上限）とdeployment/console-cors.ts（preflightはcommand routeだけ）、
// connect/kms-server.ts（interaction/承認/接続照会・切断/MCP/metadata）、connect/pages.ts（INTERACTION_SCRIPT_PATH）、
// oauth/provider.ts（OAUTH_ROUTES・無効のuserinfo/registration/introspection/PAR/device/rpInitiatedLogout・enableHttpPostMethods既定false）と
// oidc-provider 9.12.2の登録（authorization GET・resume・token・jwks・revocation・end_session/confirm・2つのdiscovery）。
// 本文上限は元実装の値（http/body.tsの既定4096・承認64・送信/取消MAX_COMMAND_BODY_BYTES・暗号ENCRYPTED_WIRE_MAX_BYTES・再発行
// REISSUE_BODY_MAX_BYTES・MCP MAX_MCP_BODY_BYTES・Providerのselective_body 56KiB）で、本文の無いrouteは0。拡大しない。

interface Route {
  readonly path: string | RegExp;
  /** method → そのrouteの本文上限（byte）。 */
  readonly methods: Readonly<Record<string, number>>;
}

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const ID = '[A-Za-z0-9_-]{1,128}';
/** http/body.tsの既定上限（login・consent・deny・codeのJSON/form）。 */
const FORM_MAX = MAX_BODY_BYTES;
/** source/http.tsの承認本文上限。 */
const APPROVAL_MAX = 64;
/** oidc-provider 9.12.2のselective_body上限。 */
const PROVIDER_MAX = 56 * 1024;
/** delivery/api.tsのENCRYPTED_WIRE_MAX_BYTES・encryption/api.tsのREISSUE_BODY_MAX_BYTES（業務moduleをimportしない写し。試験で一致を確認）。 */
export const ENCRYPTED_WIRE_MAX = 12_288;
export const REISSUE_MAX = 1024;

/** 送信API（delivery/api.ts・console-cors.ts）の公開route。 */
const API_ROUTES: readonly Route[] = Object.freeze([
  { path: '/v2/commands', methods: { POST: MAX_COMMAND_BODY_BYTES, OPTIONS: 0 } },
  { path: new RegExp(`^/v2/commands/${UUID}$`), methods: { GET: 0, OPTIONS: 0 } },
  { path: new RegExp(`^/v2/commands/${UUID}/cancel$`), methods: { POST: MAX_COMMAND_BODY_BYTES, OPTIONS: 0 } },
  { path: '/v2/encryption-key', methods: { GET: 0 } },
  { path: '/v2/encryption-key/reissue', methods: { POST: REISSUE_MAX } },
  { path: '/v2/encrypted-commands', methods: { POST: ENCRYPTED_WIRE_MAX } },
]);

/** MCP接続（connect/kms-server.ts・oauth/provider.ts・pinned Provider）の公開route。 */
const CONNECT_ROUTES: readonly Route[] = Object.freeze([
  { path: '/disconnect', methods: { GET: 0 } },
  { path: '/disconnect/review', methods: { GET: 0 } },
  { path: '/disconnect/app.js', methods: { GET: 0 } },
  { path: '/interaction/app.js', methods: { GET: 0 } },
  { path: new RegExp(`^/interaction/${ID}$`), methods: { GET: 0 } },
  { path: new RegExp(`^/interaction/${ID}/(?:login|consent|deny|code)$`), methods: { POST: FORM_MAX } },
  { path: new RegExp(`^/v1/source/approvals/${ID}$`), methods: { GET: 0, POST: APPROVAL_MAX } },
  { path: '/v1/web/connection', methods: { GET: 0 } },
  { path: '/v1/web/disconnect', methods: { POST: 0 } },
  { path: '/v1/web/disconnect/reviewer', methods: { POST: 0 } },
  { path: '/mcp', methods: { POST: MAX_MCP_BODY_BYTES, GET: 0, DELETE: 0 } },
  { path: '/.well-known/oauth-protected-resource/mcp', methods: { GET: 0 } },
  { path: '/.well-known/oauth-authorization-server', methods: { GET: 0, OPTIONS: 0 } },
  { path: '/.well-known/openid-configuration', methods: { GET: 0, OPTIONS: 0 } },
  { path: '/oauth/authorize', methods: { GET: 0 } },
  { path: new RegExp(`^/oauth/authorize/${ID}$`), methods: { GET: 0 } },
  { path: '/oauth/token', methods: { POST: PROVIDER_MAX, OPTIONS: 0 } },
  { path: '/oauth/revoke', methods: { POST: PROVIDER_MAX, OPTIONS: 0 } },
  { path: '/oauth/jwks', methods: { GET: 0, OPTIONS: 0 } },
  { path: '/oauth/session/end/confirm', methods: { POST: PROVIDER_MAX } },
]);

const ROUTES: Readonly<Record<GatewayRole, readonly Route[]>> = { api: API_ROUTES, connect: CONNECT_ROUTES };

/** origin-formのrequest-target（`/`始まり・可視ASCIIだけ・`//`始まり/`#`なし）。 */
const ORIGIN_FORM = /^\/(?!\/)[\x21-\x22\x24-\x7e]*$/;

export type RouteMatch =
  | { readonly kind: 'allowed'; readonly maxBodyBytes: number }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'method_not_allowed' }
  | { readonly kind: 'invalid_target' };

/** request-targetを生bytesのまま分け、role表と照合する（decode・正規化0）。本文上限はmin(配置上限, route上限)。 */
export function matchGatewayRoute(role: GatewayRole, method: string, target: string, deploymentMaxBodyBytes: number = Number.MAX_SAFE_INTEGER): RouteMatch {
  if (typeof target !== 'string' || target.length > 4096 || !ORIGIN_FORM.test(target)) return { kind: 'invalid_target' };
  const query = target.indexOf('?');
  const path = query === -1 ? target : target.slice(0, query);
  const route = ROUTES[role].find((item) => (typeof item.path === 'string' ? item.path === path : item.path.test(path)));
  if (route === undefined) return { kind: 'not_found' };
  if (!Object.hasOwn(route.methods, method)) return { kind: 'method_not_allowed' };
  return { kind: 'allowed', maxBodyBytes: Math.min(deploymentMaxBodyBytes, route.methods[method] ?? 0) };
}
