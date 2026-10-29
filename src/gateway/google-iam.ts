// gatewayのGoogle IAM ID token（固定backendのaudienceだけ）。実行環境の既定主体の短期tokenを、Google公式のmetadata identity
// endpoint（`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity`・`Metadata-Flavor: Google`）
// へのNode標準HTTPの一回の要求で取得する。宛先・主体・資格をenv/HTTPから差し替える口は無く、key file・別資格・匿名へのfallback 0。
//   - 取得は単一化（同時に1つだけ。期限切れ前の共有tokenはRAMだけで保持し、永続化・ログ0）。1回の取得の上限は短い既定5秒と開始者の
//     元期限の早い方で、signal/timer/socket/listenerを清掃して必ず終わり、redirect追跡・再送0。後から加わる待機者は上限を延長しない。
//     待機者が全て中止・期限切れになった取得は、その時点で物理的に中止する。cacheへの採用は、元期限・中止を再確認した生きた待機者だけが
//     行う（中止・期限切れ・close後の後着tokenは採用しない）。closeは進行中の取得を中止する。
//   - 応答はstatus 200・`Metadata-Flavor: Google`・有限byte（8KiB）・JWTの形・固定audience・期限だけを確かめる（署名による利用許可は
//     backend側のCloud Run IAMの責務で、ここでは認可票として扱わない）。業務SDKはimportしない。

import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from 'node:http';

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

/** 固定audienceのID tokenを1回取得するport（signalで必ず中止できること）。 */
export type IdTokenFetcher = (audience: string, signal: AbortSignal) => Promise<string>;

export interface IdTokenSource {
  /** 有効なtokenを返す（元期限・signalまで）。失敗は固定のGatewayIdTokenError。 */
  get(deadlineAt: number, signal: AbortSignal): Promise<string>;
  /** 共有tokenを捨て、進行中の取得を中止し、以後の取得を拒否する。 */
  close(): void;
  /** 試験・監視用の計数（値だけ）。 */
  readonly stats: { readonly started: number; readonly inflight: boolean };
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

type Cached = { readonly token: string; readonly expiresAt: number };

export function createIdTokenSource(options: IdTokenSourceOptions): IdTokenSource {
  const { audience, fetcher, clock } = options;
  const fetchLimitMs = options.fetchLimitMs ?? 5_000;
  const refreshMarginMs = options.refreshMarginMs ?? 60_000;
  let cached: Cached | undefined;
  let inflight: { readonly promise: Promise<Cached | null>; readonly controller: AbortController; waiters: number } | undefined;
  let closed = false;
  let started = 0;

  /** 1回だけの取得（min(取得上限, 開始者の元期限)で中止し、settleしたら共有を外す）。cacheへは入れない。 */
  const start = (deadlineAt: number): NonNullable<typeof inflight> => {
    started += 1;
    const startedAt = clock.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(0, Math.min(fetchLimitMs, deadlineAt - startedAt)));
    // 上限・closeでの中止は、portがsignalに応じない場合も、この取得をその時点で失敗として終える（共有を残さない）。
    const stopped = new Promise<never>((_resolve, reject) => {
      controller.signal.addEventListener('abort', () => reject(new GatewayIdTokenError('aborted')), { once: true });
    });
    let call: Promise<string>;
    try {
      call = Promise.race([Promise.resolve(fetcher(audience, controller.signal)), stopped]);
    } catch {
      call = Promise.reject(new Error('fetch'));
    }
    const promise = call
      .then(
        (token): Cached | null => {
          const expiresAt = expiryOf(token, audience);
          return expiresAt !== null && expiresAt - refreshMarginMs > startedAt ? { token, expiresAt } : null;
        },
        () => null,
      )
      .then((value) => {
        clearTimeout(timer);
        // 中止・close後の後着は結果にしない。
        return value === null || closed || controller.signal.aborted ? null : value;
      })
      .finally(() => {
        if (inflight?.promise === promise) inflight = undefined;
      });
    const flight = { promise, controller, waiters: 0 };
    inflight = flight;
    return flight;
  };

  return {
    async get(deadlineAt: number, signal: AbortSignal): Promise<string> {
      if (closed || signal.aborted) throw new GatewayIdTokenError('aborted');
      const now = clock.now();
      if (!(now < deadlineAt)) throw new GatewayIdTokenError('timed_out');
      if (cached !== undefined && now < cached.expiresAt - refreshMarginMs) return cached.token;
      cached = undefined;
      const flight = inflight ?? start(deadlineAt);
      flight.waiters += 1;
      let timer: NodeJS.Timeout | undefined;
      let onAbort: (() => void) | undefined;
      const stop = new Promise<'timed_out' | 'aborted'>((resolve) => {
        timer = setTimeout(() => resolve('timed_out'), Math.max(0, deadlineAt - now));
        onAbort = () => resolve('aborted');
        signal.addEventListener('abort', onAbort, { once: true });
      });
      try {
        const result = await Promise.race([flight.promise, stop]);
        if (result === 'timed_out' || result === 'aborted') throw new GatewayIdTokenError(result);
        // 呼出し側が中止・期限切れの後に届いたtokenは使わない。
        if (signal.aborted) throw new GatewayIdTokenError('aborted');
        if (!(clock.now() < deadlineAt)) throw new GatewayIdTokenError('timed_out');
        if (result === null || closed || !(clock.now() < result.expiresAt)) throw new GatewayIdTokenError('unavailable');
        // 元期限・中止を再確認した生きた待機者だけがcacheへ採用する。
        cached = result;
        return result.token;
      } finally {
        clearTimeout(timer);
        if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
        flight.waiters -= 1;
        // 待機者が全ていなくなった未完の取得は物理的に中止する（後着は採用しない）。
        if (flight.waiters === 0 && inflight === flight) flight.controller.abort();
      }
    },
    close(): void {
      closed = true;
      cached = undefined;
      inflight?.controller.abort();
    },
    get stats() {
      return { started, inflight: inflight !== undefined };
    },
  };
}

/** Google公式metadata identity endpoint（固定。env/HTTPで差し替えない）。 */
export const METADATA_IDENTITY_HOST = 'metadata.google.internal';
export const METADATA_IDENTITY_PATH = '/computeMetadata/v1/instance/service-accounts/default/identity';
const METADATA_RESPONSE_MAX = 8 * 1024;

/** metadataへの要求port（実runtimeはnode:httpのrequest。試験の合成transportだけが差し替える）。 */
export type MetadataTransport = (options: RequestOptions, onResponse: (res: IncomingMessage) => void) => ClientRequest;

/**
 * 実runtimeのfetcher: 固定metadata identity endpointへの一回のHTTP GET（`audience`だけをencodeしたquery）。redirect追跡・再送0、
 * 応答はstatus 200・`Metadata-Flavor: Google`・8KiB以内の本文だけ。signalで要求・socket・listenerを清掃する。
 */
export function metadataIdTokenFetcher(transport: MetadataTransport = (options, onResponse) => httpRequest(options, onResponse)): IdTokenFetcher {
  return (audience: string, signal: AbortSignal) =>
    new Promise<string>((resolve, reject) => {
      if (signal.aborted) return reject(new GatewayIdTokenError('aborted'));
      let settled = false;
      let req: ClientRequest | undefined;
      const finish = (error: GatewayIdTokenError | undefined, token?: string): void => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        if (error === undefined && token !== undefined) resolve(token);
        else reject(error ?? new GatewayIdTokenError('unavailable'));
      };
      const onAbort = (): void => {
        req?.destroy();
        finish(new GatewayIdTokenError('aborted'));
      };
      signal.addEventListener('abort', onAbort, { once: true });
      try {
        req = transport(
          {
            host: METADATA_IDENTITY_HOST,
            port: 80,
            method: 'GET',
            path: `${METADATA_IDENTITY_PATH}?audience=${encodeURIComponent(audience)}`,
            headers: { 'Metadata-Flavor': 'Google' },
            agent: false,
            signal,
          },
          (res) => {
            const flavor = res.headers['metadata-flavor'];
            if (res.statusCode !== 200 || flavor !== 'Google') {
              res.destroy();
              return finish(new GatewayIdTokenError('unavailable'));
            }
            const chunks: Buffer[] = [];
            let size = 0;
            res.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > METADATA_RESPONSE_MAX) {
                res.destroy();
                return finish(new GatewayIdTokenError('unavailable'));
              }
              chunks.push(chunk);
            });
            res.once('end', () => finish(undefined, Buffer.concat(chunks).toString('ascii').trim()));
            res.once('error', () => finish(new GatewayIdTokenError('unavailable')));
            res.once('aborted', () => finish(new GatewayIdTokenError('unavailable')));
          },
        );
      } catch {
        return finish(new GatewayIdTokenError('unavailable'));
      }
      req.on('error', () => finish(new GatewayIdTokenError(signal.aborted ? 'aborted' : 'unavailable')));
      req.end();
    });
}
