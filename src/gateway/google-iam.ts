// gatewayのGoogle IAM ID token（固定backendのaudienceだけ）。実行環境の付与主体の短期tokenを、pinned google-gaxが公開する
// google-auth-libraryのComputeクラス（metadata server）のfetchIdTokenだけで取得する。key file・別資格・匿名へのfallback 0。
//   - 取得は単一化（同時に1つだけ。期限切れ前の共有tokenはRAMだけで保持し、永続化・ログ0）。要求ごとの待機は呼出し側の元期限と
//     取得上限の短い方まで。上限を過ぎた取得は失敗として返し、その要求で再取得しない（SDK/metadataの内部retryも外側の上限内）。
//   - 取得したtokenは形・audience・期限だけを確かめる（署名の検証はbackend側のCloud Run IAMの責務で、ここでは認可票として扱わない）。
//   - Compute clientは最初の取得の時だけ作る（gatewayのimport・起動で資格・metadataを読まない。業務SDKはimportしない）。

import gax from 'google-gax';

import type { GatewayClock } from './contract.js';

/** 固定codeだけの取得失敗（元error・token・audienceを持たない）。 */
export class GatewayIdTokenError extends Error {
  override readonly name = 'GatewayIdTokenError';
  readonly code: 'unavailable' | 'timed_out' | 'aborted';
  constructor(code: 'unavailable' | 'timed_out' | 'aborted') {
    super(`gateway_id_token_${code}`);
    this.code = code;
  }
}

/** 固定audienceのID tokenを1回取得するport（実runtimeはgoogleComputeIdTokenFetcher）。 */
export type IdTokenFetcher = (audience: string) => Promise<string>;

export interface IdTokenSource {
  /** 有効なtokenを返す（元期限・signalまで）。失敗は固定のGatewayIdTokenError。 */
  get(deadlineAt: number, signal: AbortSignal): Promise<string>;
  /** 共有tokenを捨て、以後の取得を拒否する。 */
  close(): void;
}

export interface IdTokenSourceOptions {
  readonly audience: string;
  readonly fetcher: IdTokenFetcher;
  readonly clock: GatewayClock;
  /** 1回の取得の上限（既定5秒）。 */
  readonly fetchLimitMs?: number;
  /** 期限の手前で更新する余裕（既定60秒）。 */
  readonly refreshMarginMs?: number;
}

const JWT = /^[A-Za-z0-9_-]{2,2048}\.([A-Za-z0-9_-]{2,4096})\.[A-Za-z0-9_-]{2,2048}$/;

/** 形・audience・期限だけを読む（不正はnull）。 */
function expiryOf(token: unknown, audience: string): number | null {
  if (typeof token !== 'string') return null;
  const match = JWT.exec(token);
  if (match === null) return null;
  try {
    const payload: unknown = JSON.parse(Buffer.from(match[1] ?? '', 'base64url').toString('utf8'));
    if (typeof payload !== 'object' || payload === null) return null;
    const { aud, exp } = payload as { aud?: unknown; exp?: unknown };
    if (aud !== audience || typeof exp !== 'number' || !Number.isSafeInteger(exp)) return null;
    return exp * 1000;
  } catch {
    return null;
  }
}

export function createIdTokenSource(options: IdTokenSourceOptions): IdTokenSource {
  const { audience, fetcher, clock } = options;
  const fetchLimitMs = options.fetchLimitMs ?? 5_000;
  const refreshMarginMs = options.refreshMarginMs ?? 60_000;
  let cached: { readonly token: string; readonly expiresAt: number } | undefined;
  let inflight: Promise<{ readonly token: string; readonly expiresAt: number } | null> | undefined;
  let inflightStartedAt = 0;
  let closed = false;

  const start = (): Promise<{ readonly token: string; readonly expiresAt: number } | null> => {
    const startedAt = clock.now();
    inflightStartedAt = startedAt;
    let timer: NodeJS.Timeout | undefined;
    const limit = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), fetchLimitMs);
    });
    let call: Promise<string>;
    try {
      call = Promise.resolve(fetcher(audience));
    } catch {
      call = Promise.reject(new Error('fetch'));
    }
    const fetched = call.then(
      (token) => {
        const expiresAt = expiryOf(token, audience);
        return expiresAt !== null && expiresAt - refreshMarginMs > startedAt ? { token, expiresAt } : null;
      },
      () => null,
    );
    const outcome = Promise.race([fetched, limit]).then((value) => {
      clearTimeout(timer);
      if (value !== null && !closed) cached = value;
      return value;
    });
    // 上限で打ち切っても、元の取得がsettleするまでは同じinflightを共有し、新しい取得を重ねない。
    const settled = Promise.allSettled([fetched]).then(() => undefined);
    inflight = outcome;
    void Promise.all([outcome, settled]).then(() => {
      if (inflight === outcome) inflight = undefined;
    });
    return outcome;
  };

  return Object.freeze({
    async get(deadlineAt: number, signal: AbortSignal): Promise<string> {
      if (closed || signal.aborted) throw new GatewayIdTokenError('aborted');
      const now = clock.now();
      if (!(now < deadlineAt)) throw new GatewayIdTokenError('timed_out');
      if (cached !== undefined && now < cached.expiresAt - refreshMarginMs) return cached.token;
      cached = undefined;
      // 応答しない取得は、上限の4倍を過ぎるまで新しい取得を重ねない（同時に残る取得は最大1つずつ）。
      const pending = inflight !== undefined && now - inflightStartedAt < fetchLimitMs * 4 ? inflight : start();
      let timer: NodeJS.Timeout | undefined;
      let onAbort: (() => void) | undefined;
      const stop = new Promise<'timed_out' | 'aborted'>((resolve) => {
        timer = setTimeout(() => resolve('timed_out'), Math.max(0, deadlineAt - now));
        onAbort = () => resolve('aborted');
        signal.addEventListener('abort', onAbort, { once: true });
      });
      try {
        const result = await Promise.race([pending, stop]);
        if (result === 'timed_out' || result === 'aborted') throw new GatewayIdTokenError(result);
        if (result === null || closed) throw new GatewayIdTokenError('unavailable');
        if (!(clock.now() < result.expiresAt)) throw new GatewayIdTokenError('unavailable');
        return result.token;
      } finally {
        clearTimeout(timer);
        if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
      }
    },
    close(): void {
      closed = true;
      cached = undefined;
    },
  });
}

/**
 * 実runtimeのfetcher: pinned google-gaxが公開するgoogleAuthLibrary.Compute（metadata serverの既定主体）のfetchIdTokenだけ。
 * clientは最初の呼出しで1回だけ作る。key file・impersonation・別資格の選択口は無い。
 */
export function googleComputeIdTokenFetcher(): IdTokenFetcher {
  let client: { fetchIdToken(audience: string): Promise<string> } | undefined;
  return async (audience: string) => {
    client ??= new gax.googleAuthLibrary.Compute();
    return client.fetchIdToken(audience);
  };
}
