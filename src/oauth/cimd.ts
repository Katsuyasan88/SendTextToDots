// CIMD（Client ID Metadata Document）＋private_key_jwtのclient登録・認証部品（docs/SECURITY.md「MCP/OAuth認証」）。
// 固定oidc-provider 9.12.2の公開設定（features.clientIdMetadataDocumentのallowFetch /
// allowClient、fetch、fetchResponseBodyLimits、assertJwtClientAuthClaimsAndHeader）だけへ渡し、ライブラリの内部は
// 書き換えない。文書とJWKSの取得は安全な送出（egress/）のGETだけで、ここから別の経路で外へ接続しない。

import { createHash } from 'node:crypto';

import { errors, type Client, type KoaContextWithOIDC } from 'oidc-provider';

import { EGRESS_MAX_RESPONSE_BYTES, type SafeEgress } from '../egress/safe-egress.js';
import { EgressError, type EgressResponse } from '../egress/transport.js';
import type { Clock } from '../policy.js';
import type { AssertionReplayStore } from '../stores.js';

/** 完全一致で受け付ける1つのclient。3つとも正規化済みのhttps URL。 */
export interface CimdAllowedClient {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly jwksUri: string;
}

/**
 * 許可する唯一のChatGPT client（取得した公開文書と一致する値）。本人のプラグイン管理画面や実要求と異なれば、ここを推測で
 * 変えずに仕様判断へ戻す。
 */
export const CHATGPT_CIMD_CANDIDATE: CimdAllowedClient = Object.freeze({
  clientId: 'https://chatgpt.com/oauth/client.json',
  redirectUri: 'https://chatgpt.com/connector_platform_oauth_redirect',
  jwksUri: 'https://chatgpt.com/oauth/jwks.json',
});

/** 実装済みのCIMD draft（固定版のfeatures.clientIdMetadataDocumentが要求するack）。 */
export const CIMD_DRAFT_ACK = 'draft-02';
/** ライブラリが外部取得へ付ける期限（AbortSignal.timeout(2500)）と同じ値を、送出の絶対期限にする。 */
export const CIMD_FETCH_TIMEOUT_MS = 2500;
/**
 * 同じURLを再取得しない最短間隔。固定版はCIMD由来のclientを要求ごとに作り直し、JWKSの鮮度（最短60秒）を
 * 要求をまたいで持たないため、未知kidや失敗を理由にした取得が要求数に比例しないよう、取得の入口で抑える。
 */
export const CIMD_FETCH_MIN_INTERVAL_MS = 60_000;
/** client assertionの検証で許す時計のずれ（秒）。ライブラリ既定と同じ値を明示する。 */
export const CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC = 15;

const JTI_PATTERN = /^[\x21-\x7e]{1,256}$/;
const ALLOWED_GRANT_TYPES: ReadonlySet<string> = new Set(['authorization_code', 'refresh_token']);

export type CimdFetchTarget = 'client_metadata' | 'jwks';
/** fetched: 送出した。reused: 間隔内の結果を再利用した。refused: 許可していない要求で、送出していない。 */
export type CimdFetchOutcome = 'fetched' | 'reused' | 'refused';

export interface CimdClientPolicyDeps {
  readonly allowed: CimdAllowedClient;
  /** 安全な送出のGETだけを使う。 */
  readonly egress: Pick<SafeEgress, 'getJson'>;
  readonly assertionReplay: AssertionReplayStore;
  readonly clock: Clock;
  /** 取得の計数用。URL・本文・エラーの内容は渡さない。 */
  readonly onFetch?: (outcome: CimdFetchOutcome, target: CimdFetchTarget | 'other') => void;
}

function assertCanonicalHttpsUrl(value: string): void {
  const url = URL.parse(value);
  if (!url || url.protocol !== 'https:' || url.href !== value || url.username !== '' || url.password !== '' || url.hash !== '') {
    throw new Error('CIMD allowlist entries must be canonical https URLs');
  }
}

/**
 * providerのfetch設定へ渡す取得関数。許可した2つのURLへのGETだけを安全な送出で行い、呼び出し元（ライブラリ）の
 * 見出し・signal・dispatcherは外へ渡さない。redirect・圧縮・巨大応答・禁止宛先は送出側が拒否する。
 */
export function createCimdFetch(deps: CimdClientPolicyDeps): typeof fetch {
  const { allowed, egress, clock, onFetch } = deps;
  const targets = new Map<string, CimdFetchTarget>([
    [allowed.clientId, 'client_metadata'],
    [allowed.jwksUri, 'jwks'],
  ]);
  const recent = new Map<string, { readonly at: number; readonly result: Promise<EgressResponse> }>();

  return async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : undefined;
    const target = url === undefined ? undefined : targets.get(url);
    const method = init?.method ?? 'GET';
    if (url === undefined || target === undefined || method !== 'GET' || (init?.body ?? null) !== null) {
      onFetch?.('refused', target ?? 'other');
      throw new EgressError('destination_forbidden');
    }

    const now = clock.now();
    let entry = recent.get(url);
    // 成功も失敗も、間隔内は同じ結果を返す。時計が戻った場合は取り直す。
    if (!entry || now < entry.at || now - entry.at >= CIMD_FETCH_MIN_INTERVAL_MS) {
      entry = { at: now, result: egress.getJson(url, { timeoutMs: CIMD_FETCH_TIMEOUT_MS }) };
      recent.set(url, entry);
      onFetch?.('fetched', target);
    } else {
      onFetch?.('reused', target);
    }

    const response = await entry.result;
    if (!Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
      throw new EgressError('protocol_error');
    }
    // 応答見出しは渡さない。cacheの期限はライブラリの下限（文書30秒、JWKS60秒）になる。
    return new Response(response.body === '' ? null : response.body, { status: response.status });
  };
}

/** 文書を取得してよいclient_idか。正規化前の入力文字列との完全一致だけ。 */
export function createAllowFetch(allowed: CimdAllowedClient) {
  return (_ctx: KoaContextWithOIDC | undefined, clientId: string): boolean => clientId === allowed.clientId;
}

/**
 * 取得した文書から作られたclientを使ってよいか。cacheから作り直したときも毎回呼ばれる。ctxは、providerの
 * 要求処理の外（認可画面からのClient.find）ではundefinedになるため、判断に使わない。
 */
export function createAllowClient(allowed: CimdAllowedClient) {
  return (_ctx: KoaContextWithOIDC | undefined, client: Client): boolean => {
    const metadata = client.metadata();
    const redirectUris = metadata.redirect_uris ?? [];
    const grantTypes = metadata.grant_types ?? [];
    const responseTypes = metadata.response_types ?? [];
    return (
      metadata.client_id === allowed.clientId &&
      redirectUris.length === 1 &&
      redirectUris[0] === allowed.redirectUri &&
      metadata.token_endpoint_auth_method === 'private_key_jwt' &&
      metadata.jwks_uri === allowed.jwksUri &&
      // 文書へ埋め込んだ鍵は使わない。鍵は許可したJWKSのURLからだけ得る。
      metadata.jwks === undefined &&
      metadata.client_secret === undefined &&
      responseTypes.length === 1 &&
      responseTypes[0] === 'code' &&
      grantTypes.includes('authorization_code') &&
      grantTypes.every((grantType) => ALLOWED_GRANT_TYPES.has(grantType))
    );
  };
}

/**
 * 署名検証を通ったclient assertionへの追加検査。ライブラリが見ないsub（client_idと一致）とjtiの形を確認し、
 * client_idとjtiの組を原子的に予約する。この後にライブラリ標準のreplay記録も行われる。
 */
export function createAssertClientAssertion(deps: Pick<CimdClientPolicyDeps, 'assertionReplay' | 'clock'>) {
  const { assertionReplay, clock } = deps;
  return async (
    _ctx: KoaContextWithOIDC,
    claims: Record<string, unknown>,
    _header: Record<string, unknown>,
    client: Client,
  ): Promise<void> => {
    const { sub, jti, exp } = claims;
    if (sub !== client.clientId) {
      throw new errors.InvalidClientAuth('sub (JWT subject) must be the client_id');
    }
    if (typeof jti !== 'string' || !JTI_PATTERN.test(jti)) {
      throw new errors.InvalidClientAuth('jti (JWT ID) has an unsupported form');
    }
    if (typeof exp !== 'number' || !Number.isSafeInteger(exp)) {
      throw new errors.InvalidClientAuth('exp must be an integer');
    }
    const key = createHash('sha256').update(`${client.clientId}\n${jti}`).digest('base64url');
    const reserved = await assertionReplay.reserve(
      key,
      (exp + CLIENT_ASSERTION_CLOCK_TOLERANCE_SEC) * 1000,
      clock.now(),
    );
    if (!reserved) {
      throw new errors.InvalidClientAuth('client assertion tokens must only be used once');
    }
  };
}

/** providerへ渡すCIMD設定の組。 */
export function createCimdClientPolicy(deps: CimdClientPolicyDeps) {
  const { allowed } = deps;
  assertCanonicalHttpsUrl(allowed.clientId);
  assertCanonicalHttpsUrl(allowed.redirectUri);
  assertCanonicalHttpsUrl(allowed.jwksUri);
  return {
    feature: {
      enabled: true,
      ack: CIMD_DRAFT_ACK,
      allowFetch: createAllowFetch(allowed),
      allowClient: createAllowClient(allowed),
    },
    fetch: createCimdFetch(deps),
    // 文書はライブラリ既定の5KiB、JWKSは送出の上限と同じ値。どちらも送出側の8192バイト上限の内側。
    fetchResponseBodyLimits: { 'client_id metadata document': 5 * 1024, jwks_uri: EGRESS_MAX_RESPONSE_BYTES },
    assertJwtClientAuthClaimsAndHeader: createAssertClientAssertion(deps),
  };
}
