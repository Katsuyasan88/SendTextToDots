// gateway-v1配置の送信API入口（Cloud Functions 2nd gen）。既存と同じnamed export sendtexttodotsapi・Functions名/URLを保ち、要求を
// 設定の固定API backendへ一回だけ中継する（src/gateway/http.ts）。DB・KMS・Secret・Firebase Admin・App Checkの消費・配送はしない。
//   - 配置設定はimportの最初に1回だけ検証し、未設定・不整合・topologyなし（direct配置）は固定errorでimport（discovery）を止める。
//     declared optionsは既存API_FUNCTION_OPTIONS＋location・gatewayの実行主体（topology.api.gatewayServiceAccount）＋invoker:'private'。
//   - 最初の要求で1回だけ実行環境のgate（K_SERVICE・資格/metadata/proxyの差替え名なし）とhandlerを組み立てる。失敗はlatchし、以後
//     固定503（token取得・転送0）。IAM tokenは最初の転送の時だけ取得する。
//   - 初回の組立ての時だけSIGTERM/SIGINTを登録し、進行中の転送を中止して共有tokenを捨てる。
// ログは固定eventだけ（本文・token・URL・header値0）。

import { onRequest, type HttpsFunction } from 'firebase-functions/https';

import { loadDeploymentConfig } from '../config/validate.js';
import { API_FUNCTION_OPTIONS } from '../delivery/functions.js';
import type { GatewayHandler } from '../gateway/http.js';
import { createGatewayRuntime, requireGatewayTopology } from '../gateway/runtime.js';
import { systemClock } from '../policy.js';

/** 検証済みの配置設定とgateway-v1のtopology（不正ならここで固定errorを投げ、metadataを作らない）。 */
const M = loadDeploymentConfig();
const T = requireGatewayTopology(M);

type Request = Parameters<HttpsFunction>[0];
type Response = Parameters<HttpsFunction>[1];

const UNAVAILABLE_BODY = Buffer.from(JSON.stringify({ error: { code: 'temporarily_unavailable', retryable: true } }), 'utf8');

let handler: GatewayHandler | null | undefined;

const onSignal = (): void => {
  handler?.close();
};

/** 1回だけ組み立てる（失敗はnullでlatchし、固定1行だけ記録する）。 */
function current(): GatewayHandler | null {
  if (handler !== undefined) return handler;
  try {
    handler = createGatewayRuntime({ role: 'api', config: M, env: process.env, clock: systemClock });
    process.on('SIGTERM', onSignal);
    process.on('SIGINT', onSignal);
  } catch {
    handler = null;
    try {
      process.stderr.write('{"event":"sttd_api_gateway.start_failed"}\n');
    } catch {
      // 記録の失敗は結果を変えない。
    }
  }
  return handler;
}

function refuse(res: Response): void {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(UNAVAILABLE_BODY.length) });
  res.end(UNAVAILABLE_BODY);
}

async function serve(req: Request, res: Response): Promise<void> {
  const gateway = current();
  if (gateway === null) {
    refuse(res);
    return;
  }
  // frameworkが読んだwire bytes（rawBody）をそのまま使う。本文が既に読み終わってrawBodyが無い時は空。
  const rawBody = (req as { rawBody?: unknown }).rawBody;
  await gateway.handle(req, res, Buffer.isBuffer(rawBody) ? rawBody : req.readableEnded ? Buffer.alloc(0) : undefined);
}

/** export名は既存と同じ（設定のapi.functionName）。実行主体だけgateway専用。 */
export const sendtexttodotsapi = onRequest(
  { ...API_FUNCTION_OPTIONS, region: M.location, serviceAccount: T.api.gatewayServiceAccount, invoker: M.api.invoker },
  (req, res) => serve(req, res),
);
