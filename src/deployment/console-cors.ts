// Functions入口（command v2の3 route）の固定originだけのCORS。許可するOriginは配置設定のMCP origin（connect.publicOrigin）1つだけで、そのoriginの
// browserからの直接要求を照合する。現在の送信画面は利用者のパソコンのローカルhelper（src/console/local-server.ts）が配信・中継し、helperからの
// 要求はOriginを付けないため、このCORSを使わない（localhostを許可originへ足さず、許可範囲を広げない）。Cloud Runは/consoleを配信しない。
//   - Originが無い要求（native client）はCORS headerを足さない。
//   - Originが設定のMCP originと完全一致し、1つだけの時だけ許可。異なる・重複・route外は固定403（wildcard・任意origin・credential cookie許可0）。
//   - OPTIONSはroute・Access-Control-Request-Method・Access-Control-Request-Headers（authorization・content-type・idempotency-keyだけ）を
//     検査して204を返す。SDK・DB・秘密の初期化より前に処理し、本人確認は行わない（実要求は既存のBearer Firebase認証を必ず通る）。
//   - 実応答は許可origin・Vary: Origin・Retry-Afterのexposeだけを足す。実CloudのIAM・公開設定は変えない。

import type { IncomingMessage, ServerResponse } from 'node:http';

import { loadDeploymentConfig } from '../config/validate.js';

/** 許可する唯一のOrigin（配置設定のMCP origin。送信画面の配信元ではない）。配置設定が不正なら固定のDeploymentConfigError。 */
export function consoleAllowedOrigin(): string {
  return loadDeploymentConfig().connect.publicOrigin;
}
const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const COMMAND = new RegExp(`^/v2/commands/(${UUID})(/cancel)?$`);
const ALLOWED_REQUEST_HEADERS: ReadonlySet<string> = new Set(['authorization', 'content-type', 'idempotency-key']);
const PREFLIGHT_MAX_AGE_SEC = '600';
const FORBIDDEN_BODY = Buffer.from(JSON.stringify({ error: { code: 'forbidden', retryable: false } }), 'utf8');

export type ConsoleCorsDecision =
  | { readonly kind: 'none' }
  | { readonly kind: 'reject' }
  | { readonly kind: 'preflight'; readonly headers: Readonly<Record<string, string>> }
  | { readonly kind: 'allow'; readonly headers: Readonly<Record<string, string>> };

/** pathのcommand routeが受けるmethod（route外はnull）。 */
function routeMethod(url: string): 'GET' | 'POST' | null {
  let path: string;
  try {
    path = new URL(url, 'http://function.invalid').pathname;
  } catch {
    return null;
  }
  if (path === '/v2/commands') return 'POST';
  const match = COMMAND.exec(path);
  if (match === null) return null;
  return match[2] === undefined ? 'GET' : 'POST';
}

/** rawHeadersから、名前（大小無視）の値を全て取り出す。 */
function headerValues(rawHeaders: readonly string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) if (rawHeaders[index]!.toLowerCase() === name) values.push(rawHeaders[index + 1]!);
  return values;
}

/** CORSの判定（pure）。要求のmethod・url・rawHeadersだけを読む。 */
export function decideConsoleCors(method: string, url: string, rawHeaders: readonly string[]): ConsoleCorsDecision {
  const origins = headerValues(rawHeaders, 'origin');
  if (origins.length === 0) return { kind: 'none' };
  const CONSOLE_ALLOWED_ORIGIN = consoleAllowedOrigin();
  if (origins.length !== 1 || origins[0] !== CONSOLE_ALLOWED_ORIGIN) return { kind: 'reject' };
  const allowed = routeMethod(url);
  if (allowed === null) return { kind: 'reject' };
  if (method === 'OPTIONS') {
    const requestMethods = headerValues(rawHeaders, 'access-control-request-method');
    if (requestMethods.length !== 1 || requestMethods[0] !== allowed) return { kind: 'reject' };
    const requested = headerValues(rawHeaders, 'access-control-request-headers');
    if (requested.length > 1) return { kind: 'reject' };
    const names = requested.length === 0 ? [] : requested[0]!.split(',').map((name) => name.trim().toLowerCase());
    if (names.some((name) => !ALLOWED_REQUEST_HEADERS.has(name))) return { kind: 'reject' };
    return {
      kind: 'preflight',
      headers: {
        'Access-Control-Allow-Origin': CONSOLE_ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': allowed,
        'Access-Control-Allow-Headers': [...ALLOWED_REQUEST_HEADERS].join(', '),
        'Access-Control-Max-Age': PREFLIGHT_MAX_AGE_SEC,
        Vary: 'Origin',
      },
    };
  }
  return { kind: 'allow', headers: { 'Access-Control-Allow-Origin': CONSOLE_ALLOWED_ORIGIN, 'Access-Control-Expose-Headers': 'Retry-After', Vary: 'Origin' } };
}

/**
 * 要求へCORSを適用する。preflight（204）と拒否（固定403）はここで応答を書き終えてtrueを返す（呼出元はSDK初期化・処理へ進まない）。
 * 許可された実要求は応答headerを足してfalse（既存の処理・Bearer認証へ進む）。Originなしは何もしない。
 */
export function applyConsoleCors(req: IncomingMessage, res: ServerResponse): boolean {
  const decision = decideConsoleCors(req.method ?? '', req.url ?? '/', req.rawHeaders);
  if (decision.kind === 'none') return false;
  if (decision.kind === 'allow') {
    for (const [name, value] of Object.entries(decision.headers)) res.setHeader(name, value);
    return false;
  }
  if (res.headersSent || res.writableEnded) return true;
  if (decision.kind === 'preflight') {
    res.writeHead(204, { ...decision.headers, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Length': '0' });
    res.end();
    return true;
  }
  res.writeHead(403, {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(FORBIDDEN_BODY.length),
  });
  res.end(FORBIDDEN_BODY);
  return true;
}
