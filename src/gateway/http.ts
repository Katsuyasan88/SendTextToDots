// gatewayのHTTP中継（role別の固定backendへ一回だけ）。入口で行うのは形式・量・期限の制限と転送だけで、DB・KMS・Secret・本人/source
// 検証・App Checkの消費・配送は行わない（全てbackendの既存handlerで一回）。
//   - 受付時刻から元20秒を1回だけ作り、本文待機・IAM token取得・転送・応答の全てで共有する。backendへは残時間だけを渡す。
//   - 未知route/method・不正なrequest-target・Host/Content-Length/Transfer-Encodingの重複や曖昧な本文境界・圧縮本文・上限超過は、
//     rate/slot・token取得・転送より前に固定の4xxで拒否する。rateはprocess内token bucket（429）、同時処理は固定slot（503・待機列0）。
//   - 転送先は設定の固定origin（transport Host・TLS SNI・IAM audience）だけ。method・生のrequest-target（path/query）・本文bytes・
//     利用者のAuthorization・Cookie・Origin・Idempotency-Key・source署名等のend-to-end headerは順序・多値のまま渡す。外部の
//     Forwarded/X-Forwarded-*・内部header・hop-by-hop（Connectionが列挙する名前を含む）は除去し、内部headerは作り直す。
//   - 業務upstreamは要求ごとに最大1回。redirectは追わず、401/503等も再送しない。中断・期限の後に新しい呼出しを始めない。
//   - 応答はstatus・本文（stream）・複数Set-Cookie・WWW-Authenticate・Location・CORS・MCPのheaderをそのまま返す（hop-by-hopだけ除く）。
//     応答headerへbackendのauthorityが現れたら返さずに固定502にする。
//   - ログ・例外へ本文・token・UID・URL・header値を出さない（固定codeだけ）。自分で読んだ本文は終了時に0で上書きする。

import type { ClientRequest, IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';

import {
  authorityOf,
  GATEWAY_BUDGET_HEADER,
  GATEWAY_REQUEST_BUDGET_MS,
  matchGatewayRoute,
  SERVERLESS_AUTHORIZATION_HEADER,
  type GatewayClock,
  type GatewayLimits,
  type GatewayRole,
} from './contract.js';
import type { IdTokenSource } from './google-iam.js';

/** 転送のport（実runtimeはnode:httpsのrequest）。 */
export type GatewayTransport = (options: RequestOptions, onResponse: (res: IncomingMessage) => void) => ClientRequest;

export interface GatewayHandlerOptions {
  readonly role: GatewayRole;
  /** 検証済みの固定backend origin（`https://<host>`）。 */
  readonly backendOrigin: string;
  /** MCPだけ: 受け付けるHost（設定の公開authority）。APIは既存Functionsの複数URLを保つため照合しない。 */
  readonly publicAuthority?: string | undefined;
  readonly limits: GatewayLimits;
  readonly tokens: IdTokenSource;
  readonly clock: GatewayClock;
  /** 試験の合成loopbackだけが差し替える（既定はhttps.requestで、接続先はbackend originのhost:443）。 */
  readonly transport?: GatewayTransport | undefined;
  /** 試験の合成loopbackだけ: TCPの接続先（Host・SNI・audienceは常にbackend origin）。 */
  readonly connectTo?: { readonly host: string; readonly port: number } | undefined;
  /** 固定eventだけの記録（任意）。 */
  readonly log?: ((entry: { readonly event: string; readonly code: string }) => void) | undefined;
}

export interface GatewayHandler {
  /** 1要求を処理する。rawBodyはframeworkが既に読んだwire bytes（Functions）。無ければstreamを上限まで読む。 */
  handle(req: IncomingMessage, res: ServerResponse, rawBody?: Buffer | undefined): Promise<void>;
  /** 新規要求を503にし、進行中の要求を中止してIAM tokenを捨てる。 */
  close(): void;
  /** 試験・監視用の計数（値だけ）。 */
  readonly stats: { readonly forwarded: number; readonly active: number };
}

const HOP_BY_HOP: ReadonlySet<string> = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
  'http2-settings',
]);

/** 外部入力から除去する転送・内部header（作り直すものを含む）。 */
function isStrippedRequestHeader(name: string): boolean {
  return (
    HOP_BY_HOP.has(name) ||
    name === 'forwarded' ||
    name.startsWith('x-forwarded-') ||
    name === 'x-real-ip' ||
    name === SERVERLESS_AUTHORIZATION_HEADER ||
    name.startsWith('x-sttd-gateway-') ||
    name.startsWith('x-google-') ||
    name.startsWith('x-appengine-') ||
    name === 'function-execution-id'
  );
}

const JSON_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'application/json; charset=utf-8' };
const BODIES: Readonly<Record<number, Buffer>> = {
  400: Buffer.from('{"error":{"code":"invalid_request"}}', 'utf8'),
  404: Buffer.from('{"error":{"code":"not_found"}}', 'utf8'),
  405: Buffer.from('{"error":{"code":"method_not_allowed"}}', 'utf8'),
  413: Buffer.from('{"error":{"code":"payload_too_large"}}', 'utf8'),
  429: Buffer.from('{"error":{"code":"rate_limited","retryable":true}}', 'utf8'),
  502: Buffer.from('{"error":{"code":"bad_gateway"}}', 'utf8'),
  503: Buffer.from('{"error":{"code":"temporarily_unavailable","retryable":true}}', 'utf8'),
};

/** 書込める時だけ固定の応答（no-store・JSON）。 */
function refuse(res: ServerResponse, status: keyof typeof BODIES): void {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  const body = BODIES[status] ?? BODIES[503]!;
  res.writeHead(status, { ...JSON_HEADERS, 'Content-Length': String(body.length) });
  res.end(body);
}

class Refusal extends Error {
  readonly status: keyof typeof BODIES;
  constructor(status: keyof typeof BODIES) {
    super('gateway_refused');
    this.status = status;
  }
}

/** 生headerの境界を検査する（Host1件・Content-Length最大1件・TEはchunkedだけでCLと併存しない・本文の圧縮なし）。 */
function checkFraming(req: IncomingMessage, publicAuthority: string | undefined): void {
  const raw = req.rawHeaders;
  let hosts = 0;
  let lengths = 0;
  let encodings = 0;
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = (raw[index] ?? '').toLowerCase();
    const value = raw[index + 1] ?? '';
    if (name === 'host') {
      hosts += 1;
      if (publicAuthority !== undefined && value !== publicAuthority) throw new Refusal(400);
    } else if (name === 'content-length') {
      lengths += 1;
      if (!/^(?:0|[1-9][0-9]{0,15})$/.test(value)) throw new Refusal(400);
    } else if (name === 'transfer-encoding') {
      encodings += 1;
      if (value.toLowerCase() !== 'chunked') throw new Refusal(400);
    } else if (name === 'content-encoding') {
      if (value.toLowerCase() !== 'identity') throw new Refusal(400);
    }
  }
  if (hosts !== 1 || lengths > 1 || encodings > 1 || (lengths === 1 && encodings === 1)) throw new Refusal(400);
  if (publicAuthority !== undefined && req.headers.host !== publicAuthority) throw new Refusal(400);
}

/** 本文を上限・中断・期限まで読む（自分で読んだbufferは呼出し側が0で上書きする）。 */
function readBody(req: IncomingMessage, max: number, signal: AbortSignal): Promise<Buffer> {
  const declared = req.headers['content-length'];
  if (typeof declared === 'string' && Number(declared) > max) return Promise.reject(new Refusal(413));
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const cleanup = (): void => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onError);
      signal.removeEventListener('abort', onError);
    };
    const wipe = (): void => {
      for (const chunk of chunks) chunk.fill(0);
    };
    const onData = (chunk: Buffer): void => {
      size += chunk.length;
      chunks.push(chunk);
      if (size > max) {
        cleanup();
        wipe();
        req.resume();
        reject(new Refusal(413));
      }
    };
    const onEnd = (): void => {
      cleanup();
      const body = Buffer.concat(chunks, size);
      wipe();
      resolve(body);
    };
    const onError = (): void => {
      cleanup();
      wipe();
      reject(new Refusal(503));
    };
    if (signal.aborted) return onError();
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onError);
    signal.addEventListener('abort', onError, { once: true });
  });
}

/** 転送する要求header（元の順序・多値を保ち、除去対象とConnectionが列挙する名前を外して内部headerを足す）。 */
function forwardHeaders(req: IncomingMessage, backendAuthority: string, body: Buffer, token: string, remainingMs: number): string[] {
  const raw = req.rawHeaders;
  const listed = new Set<string>();
  for (let index = 0; index + 1 < raw.length; index += 2) {
    if ((raw[index] ?? '').toLowerCase() !== 'connection') continue;
    for (const item of (raw[index + 1] ?? '').split(',')) listed.add(item.trim().toLowerCase());
  }
  const out: string[] = ['Host', backendAuthority];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index] ?? '';
    const lower = name.toLowerCase();
    if (isStrippedRequestHeader(lower) || listed.has(lower)) continue;
    out.push(name, raw[index + 1] ?? '');
  }
  const method = req.method ?? 'GET';
  if (body.length > 0 || !['GET', 'HEAD', 'OPTIONS', 'DELETE'].includes(method)) out.push('Content-Length', String(body.length));
  out.push('X-Serverless-Authorization', `Bearer ${token}`, 'X-STTD-Gateway-Budget-Ms', String(remainingMs));
  return out;
}

/** 返す応答header（hop-by-hopとConnectionが列挙する名前だけ除く）。backendのauthorityを含む値はnull。 */
function responseHeaders(upstream: IncomingMessage, backendAuthority: string): string[] | null {
  const raw = upstream.rawHeaders;
  const listed = new Set<string>();
  for (let index = 0; index + 1 < raw.length; index += 2) {
    if ((raw[index] ?? '').toLowerCase() !== 'connection') continue;
    for (const item of (raw[index + 1] ?? '').split(',')) listed.add(item.trim().toLowerCase());
  }
  const needle = backendAuthority.toLowerCase();
  const out: string[] = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index] ?? '';
    const value = raw[index + 1] ?? '';
    const lower = name.toLowerCase();
    if (lower !== 'content-length' && (HOP_BY_HOP.has(lower) || listed.has(lower))) continue;
    if (value.toLowerCase().includes(needle)) return null;
    out.push(name, value);
  }
  return out;
}

export function createGatewayHandler(options: GatewayHandlerOptions): GatewayHandler {
  const { role, limits, tokens, clock } = options;
  const backend = new URL(options.backendOrigin);
  const backendAuthority = authorityOf(options.backendOrigin);
  const transport: GatewayTransport = options.transport ?? ((requestOptions, onResponse) => httpsRequest(requestOptions, onResponse));
  const connectHost = options.connectTo?.host ?? backend.hostname;
  const connectPort = options.connectTo?.port ?? 443;
  const log = (code: string): void => {
    try {
      options.log?.({ event: 'gateway.request', code });
    } catch {
      // 記録の失敗で要求の扱いを変えない。
    }
  };
  const active = new Set<AbortController>();
  const stats = { forwarded: 0, active: 0 };
  let closing = false;
  let bucket = limits.burst;
  let refilledAt = clock.now();

  /** process内token bucket（1要求で1）。 */
  const takeRate = (now: number): boolean => {
    const elapsed = Math.max(0, now - refilledAt);
    refilledAt = now;
    bucket = Math.min(limits.burst, bucket + (elapsed * limits.ratePerSecond) / 1000);
    if (bucket < 1) return false;
    bucket -= 1;
    return true;
  };

  async function handle(req: IncomingMessage, res: ServerResponse, rawBody?: Buffer | undefined): Promise<void> {
    const receivedAt = clock.now();
    const deadlineAt = receivedAt + GATEWAY_REQUEST_BUDGET_MS;
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    const onResponseClose = (): void => {
      if (!res.writableFinished) controller.abort();
    };
    req.once('aborted', abort);
    res.once('close', onResponseClose);
    const timer = setTimeout(abort, GATEWAY_REQUEST_BUDGET_MS);
    let slot = false;
    let owned: Buffer | undefined;
    try {
      if (closing) throw new Refusal(503);
      const method = req.method ?? '';
      const match = matchGatewayRoute(role, method, req.url ?? '');
      if (match === 'invalid_target') throw new Refusal(400);
      if (match === 'not_found') throw new Refusal(404);
      if (match === 'method_not_allowed') throw new Refusal(405);
      checkFraming(req, options.publicAuthority);
      if (!takeRate(receivedAt)) throw new Refusal(429);
      if (stats.active >= limits.maxConcurrent) throw new Refusal(503);
      slot = true;
      stats.active += 1;
      active.add(controller);
      let body: Buffer;
      if (Buffer.isBuffer(rawBody)) {
        if (rawBody.length > limits.maxBodyBytes) throw new Refusal(413);
        body = rawBody;
      } else {
        body = owned = await readBody(req, limits.maxBodyBytes, controller.signal);
      }
      const token = await tokens.get(deadlineAt, controller.signal).catch(() => {
        throw new Refusal(503);
      });
      const now = clock.now();
      if (closing || controller.signal.aborted || !(now < deadlineAt)) throw new Refusal(503);
      const headers = forwardHeaders(req, backendAuthority, body, token, Math.max(1, Math.floor(deadlineAt - now)));
      stats.forwarded += 1;
      await forwardOnce(method, req.url ?? '/', headers, body, res, controller.signal);
      log('forwarded');
    } catch (error) {
      const status = error instanceof Refusal ? error.status : 503;
      log(String(status));
      refuse(res, status);
    } finally {
      clearTimeout(timer);
      req.off('aborted', abort);
      res.off('close', onResponseClose);
      active.delete(controller);
      controller.abort();
      if (slot) stats.active -= 1;
      owned?.fill(0);
    }
  }

  /** 1回だけ転送し、応答をそのまま返す（redirect追跡・再送0）。 */
  function forwardOnce(method: string, path: string, headers: string[], body: Buffer, res: ServerResponse, signal: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Refusal): void => {
        if (settled) return;
        settled = true;
        if (error === undefined) resolve();
        else reject(error);
      };
      let upstream: ClientRequest;
      try {
        upstream = transport(
          {
            host: connectHost,
            port: connectPort,
            servername: backend.hostname,
            method,
            path,
            headers: headers as unknown as OutgoingHttpHeaders,
            setHost: false,
            agent: false,
            signal,
          },
          (incoming) => {
            const kept = responseHeaders(incoming, backendAuthority);
            if (kept === null || res.headersSent || res.destroyed) {
              incoming.destroy();
              return finish(new Refusal(502));
            }
            res.writeHead(incoming.statusCode ?? 502, kept as unknown as OutgoingHttpHeaders);
            incoming.on('error', () => {
              res.destroy();
              finish();
            });
            res.once('close', () => {
              if (!incoming.complete) incoming.destroy();
              finish();
            });
            incoming.pipe(res);
            incoming.once('end', () => finish());
          },
        );
      } catch {
        return finish(new Refusal(503));
      }
      upstream.on('error', () => {
        if (res.headersSent) {
          res.destroy();
          finish();
        } else finish(new Refusal(503));
      });
      upstream.end(body);
    });
  }

  return {
    handle,
    close(): void {
      closing = true;
      for (const controller of active) controller.abort();
      tokens.close();
    },
    get stats() {
      return { forwarded: stats.forwarded, active: stats.active };
    },
  };
}
