// 送信APIをFunctions第2世代のHTTP（onRequest）1つとして組み立てる。Callable固有のwireは使わない。
// 宣言値は1vCPU/1GiB・min0/max3・concurrency20・timeout30秒。region（配置設定のlocation）・invoker・runtime SAはentryが足す。rawBodyを持つreq/resで直接呼べる。

import { onRequest, type HttpsFunction } from 'firebase-functions/https';

import type { ServerResponse } from 'node:http';

import type { DeliveryRequest } from './api.js';

export const API_FUNCTION_OPTIONS = Object.freeze({
  timeoutSeconds: 30,
  memory: '1GiB',
  cpu: 1,
  minInstances: 0,
  maxInstances: 3,
  concurrency: 20,
} as const);

export function createRequestDeliveryFunction(handler: (req: DeliveryRequest, res: ServerResponse) => Promise<void>): HttpsFunction {
  return onRequest({ ...API_FUNCTION_OPTIONS }, (req, res) => handler(req, res));
}
