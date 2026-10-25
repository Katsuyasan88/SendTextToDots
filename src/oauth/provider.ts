// MCP/OAuthのauthorization server（固定oidc-provider 9.12.2）。KMS接続server（connect/kms-server.ts）が使う唯一のprofile
// connect-kms-developmentを組み立てる: issuerは固定のhttps://DNS-host（publicOrigin）、clientはCIMD＋private_key_jwtの許可1件だけ、
// Bearer専用（DPoP・mTLS無効）、refresh tokenは正当なrefreshごとに次のtokenへ無活動窓（refreshFamilyMaxSec＝90日）を新しく与える
// （familyの初回発行からの絶対打切りを置かない。同じGrantの延長は保存adapterがrefresh tokenの単回消費と同じtransactionで行う）。
// 待受は内部のHTTPで、外側の固定TLS終端の後の要求として扱う（proxy設定。要求のForwarded系列は待受が固定値へ置換済み）。

import Provider, { errors, interactionPolicy, type AdapterFactory, type Configuration, type JWKS } from 'oidc-provider';

import type { SafeEgress } from '../egress/safe-egress.js';
import { isDevelopmentPublicOrigin } from '../http/origin.js';
import type { AuthPolicy, Clock } from '../policy.js';
import type { AssertionReplayStore } from '../stores.js';
import {
  CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC,
  createCimdClientPolicy,
  type CimdAllowedClient,
  type CimdFetchOutcome,
  type CimdFetchTarget,
} from './cimd.js';

/** SendTextToDotsのMCP入口が受け付ける唯一のscope。 */
export const STTD_SCOPE = 'sttd:events';
const INTERACTION_PATH_PREFIX = '/interaction/';

export const OAUTH_ROUTES = Object.freeze({
  authorization: '/oauth/authorize',
  token: '/oauth/token',
  revocation: '/oauth/revoke',
  jwks: '/oauth/jwks',
  // RP起点のlogoutは無効だが、ライブラリは別ownerへのbrowser session切替でこの配下の/confirmを使う。
  end_session: '/oauth/session/end',
});

/** KMS接続serverのprofile。 */
export interface ConnectKmsOAuthProfile {
  readonly kind: 'connect-kms-development';
  /** 正規形の`https://<小文字DNS-host>`だけ。 */
  readonly issuer: string;
  readonly adapter: AdapterFactory;
  /** 署名鍵（Secret Managerの固定秘密）。 */
  readonly jwks: JWKS;
  /** cookie署名鍵（Secret Managerの固定秘密）。 */
  readonly cookieKeys: readonly Buffer[];
  /** 完全一致で許可した1つのclient文書とJWKSだけを、渡された安全な送出で取得する。 */
  readonly client: CimdAllowedClient;
  readonly egress: Pick<SafeEgress, 'getJson'>;
  readonly assertionReplay: AssertionReplayStore;
  readonly clock: Clock;
  readonly onFetch?: (outcome: CimdFetchOutcome, target: CimdFetchTarget | 'other') => void;
}

export interface OAuthProviderDeps {
  readonly profile: ConnectKmsOAuthProfile;
  readonly policy: AuthPolicy;
  /**
   * ownerが有効か（失効・無活動でない）。認可コード交換・refreshでは、そのtokenのgrantIdも渡る（そのgrantへ同意した時点の本人確認が
   * いまも有効かを確かめるため）。認可端点ではgrantIdはundefined。
   */
  readonly isOwnerActive: (ownerId: string, grantId?: string) => Promise<boolean>;
}

/** MCPのresource識別子。issuer配下の `/mcp` だけ。 */
export function resourceFor(issuer: string): string {
  return `${issuer}/mcp`;
}

export function createOAuthProvider(deps: OAuthProviderDeps): Provider {
  const { profile, policy, isOwnerActive } = deps;
  if (profile.kind !== 'connect-kms-development' || !isDevelopmentPublicOrigin(profile.issuer)) {
    throw new Error('only the connect-kms-development profile on the fixed https origin is available');
  }
  const clientRegistration = cimdClientRegistration(profile);
  const resource = resourceFor(profile.issuer);
  const linkTtlSec = Math.floor(policy.interactionTtlMs / 1000);

  // 新しい認可要求は毎回、接続画面のinteraction（login/consent）を通す。今回の要求に対する完了結果（interactionFinishedで渡した
  // grant）がない限り、browser sessionにlogin/consentが残っていても、clientがpromptを指定しなくても、interactionを要求する。
  // refresh token交換は認可端点を通らないため、この検査の対象にならない。
  const interactionChecks = interactionPolicy.base();
  const consentPrompt = interactionChecks.get('consent');
  if (!consentPrompt) throw new Error('consent prompt is missing from the interaction policy');
  consentPrompt.checks.add(
    new interactionPolicy.Check(
      'device_approval_required',
      'device approval is required for every authorization request',
      'interaction_required',
      (ctx) =>
        ctx.oidc.result?.consent?.grantId
          ? interactionPolicy.Check.NO_NEED_TO_PROMPT
          : interactionPolicy.Check.REQUEST_PROMPT,
    ),
  );

  const provider = new Provider(profile.issuer, {
    adapter: profile.adapter,
    ...clientRegistration.settings,
    jwks: profile.jwks,
    cookies: {
      keys: [...profile.cookieKeys],
      // 下のproxy設定で要求がsecureと認識され、ライブラリ（cookies）がSecureを付ける。
      short: { httpOnly: true, sameSite: 'lax', signed: true },
      long: { httpOnly: true, sameSite: 'lax', signed: true },
    },
    routes: OAUTH_ROUTES,
    responseTypes: ['code'],
    // 氏名・メール等のclaimsを定義しない。OP側のscopeも定義せず、resource serverのscopeだけにする。
    claims: {},
    scopes: [],
    // S256以外のmethodはライブラリが拒否する。code_challengeなしの要求もここで必ず拒否する。
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: false },
      registration: { enabled: false },
      ...clientRegistration.features,
      rpInitiatedLogout: { enabled: false },
      // 固定版の既定は有効で、discoveryがPAR端点（/request）を広告する。PARは採用フローに含めず、HTTP入口も
      // この経路をproviderへ渡さないため、無効にして広告と受付をなくす。
      pushedAuthorizationRequests: { enabled: false },
      // 鍵束縛token（DPoP・mTLS）を発行・広告しないBearer専用（固定版のDPoP既定は有効なので既定に頼らない）。
      dPoP: { enabled: false },
      mTLS: { enabled: false },
      revocation: {
        enabled: true,
        // 取消できるのは、そのtokenを発行されたclientだけ。他clientのtokenには何もせず同じ応答を返す。
        allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId,
      },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo: (_ctx, resourceIndicator) => {
          if (resourceIndicator !== resource) throw new errors.InvalidTarget();
          return {
            scope: STTD_SCOPE,
            audience: resource,
            accessTokenTTL: policy.accessTokenTtlSec,
            // 保存adapterで即時失効を確認できる不透明token。
            accessTokenFormat: 'opaque',
          };
        },
        useGrantedResource: () => true,
      },
    },
    ttl: {
      AccessToken: policy.accessTokenTtlSec,
      AuthorizationCode: policy.authorizationCodeTtlSec,
      Grant: policy.refreshFamilyMaxSec,
      // 正当なrefreshごとに次のrefresh tokenへ無活動窓を新しく与える（familyの絶対上限を持たない）。
      RefreshToken: () => policy.refreshFamilyMaxSec,
      // 認可要求とprovider sessionは接続画面のinteractionと同じ5分で切る。
      Interaction: linkTtlSec,
      Session: linkTtlSec,
    },
    rotateRefreshToken: true,
    // 既定はoffline_access scopeを要求する。このserviceのscopeはsttd:eventsだけなのでgrant typeで判断する。
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    // 既定ではbrowser sessionの終了でtokenも失効する。接続はinteractionとgrantで管理する。
    expiresWithSession: () => false,
    // どのtokenの取消・再利用検知でもgrant全体を失効させる。
    revokeGrantPolicy: () => true,
    // browser sessionに残ったgrantを再利用しない（上のdevice_approval_requiredと二重の防御）。
    loadExistingGrant: async (ctx) => {
      const grantId = ctx.oidc.result?.consent?.grantId;
      return grantId ? ctx.oidc.provider.Grant.find(grantId) : undefined;
    },
    findAccount: async (_ctx, sub, token) => {
      const grantId = token !== undefined && 'grantId' in token && typeof token.grantId === 'string' ? token.grantId : undefined;
      if (!(await isOwnerActive(sub, grantId))) return undefined;
      return { accountId: sub, claims: () => ({ sub }) };
    },
    interactions: {
      policy: interactionChecks,
      url: (_ctx, interaction) => `${INTERACTION_PATH_PREFIX}${interaction.uid}`,
    },
    // 入力値やerror_descriptionを画面へ反映しない。
    renderError: (ctx, out) => {
      ctx.type = 'html';
      ctx.body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SendTextToDots</title></head><body><p data-sttd-error="${
        /^[a-z_]{1,64}$/.test(out.error) ? out.error : 'error'
      }">接続を完了できませんでした。</p></body></html>`;
    },
  });

  // ライブラリはOP側のscopeが空でもdiscoveryへopenidだけを広告し、resource serverのscopeを載せない。
  // 公開APIのpost middleware（v9.12.2 docs/README.md「Pre- and post-middlewares」）で、成功したGETの
  // discovery応答のscopes_supportedだけをSendTextToDotsの唯一のscopeへ合わせる。OPTIONS（route名cors.discovery）・エラー・
  // 他routeの応答には触れず、認可要求の検証・付与・tokenの処理も変えない。
  provider.use(async (ctx: DiscoveryMiddlewareContext, next) => {
    await next();
    if (ctx.method !== 'GET' || ctx.status !== 200 || ctx.oidc?.route !== 'discovery') return;
    const { body } = ctx;
    if (typeof body !== 'object' || body === null || Array.isArray(body) || Buffer.isBuffer(body)) return;
    ctx.body = { ...body, scopes_supported: [STTD_SCOPE] };
  });

  // 固定のTLS終端の後の内部HTTPとして、X-Forwarded-Proto・X-Forwarded-Hostを読む（Koaのproxy）。これを信頼してよいのは、待受が
  // クライアント由来のForwarded全系列を除去し、固定deploymentのhttps・authorityへ置き換えた要求だけを渡すため（connect/kms-server.ts）。
  provider.proxy = true;

  return provider;
}

interface ClientRegistration {
  readonly settings: Pick<
    Configuration,
    'clients' | 'clientAuthMethods' | 'clockTolerance' | 'fetch' | 'fetchResponseBodyLimits' | 'assertJwtClientAuthClaimsAndHeader'
  >;
  readonly features: Pick<NonNullable<Configuration['features']>, 'clientIdMetadataDocument'>;
}

/** CIMD＋private_key_jwt。固定clientを持たず、認証なし（none）も受け付けない。 */
function cimdClientRegistration(profile: ConnectKmsOAuthProfile): ClientRegistration {
  const cimd = createCimdClientPolicy({
    allowed: profile.client,
    egress: profile.egress,
    assertionReplay: profile.assertionReplay,
    clock: profile.clock,
    ...(profile.onFetch ? { onFetch: profile.onFetch } : {}),
  });
  return {
    settings: {
      clients: [],
      clientAuthMethods: ['private_key_jwt'],
      clockTolerance: CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC,
      fetch: cimd.fetch,
      fetchResponseBodyLimits: cimd.fetchResponseBodyLimits,
      assertJwtClientAuthClaimsAndHeader: cimd.assertJwtClientAuthClaimsAndHeader,
    },
    features: { clientIdMetadataDocument: cimd.feature },
  };
}

/**
 * post middlewareが読む範囲だけの型。固定型（@types/oidc-provider 9.12.1）はKoa由来のuseのcontextに、
 * ライブラリがroute一致後に足すoidcを含めないため、ここで使う2項目だけを補う。
 */
interface DiscoveryMiddlewareContext {
  readonly method: string;
  readonly status: number;
  body: unknown;
  readonly oidc?: { readonly route: string };
}
