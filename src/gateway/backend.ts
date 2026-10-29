// IAM必須の業務backend（gateway-v1配置）の入口adapter。Cloud RunのInvoker IAMを前提とし（IAMの効力そのものはCloud側の構成で、
// ここでは実証しない）、route・本人・許可元の検査より前に次だけを行う:
//   - Hostが設定のtransport authority（backendの正式service URL）とちょうど1件で一致すること。不成立は固定400で、DB・本人確認・KMS・
//     Providerを呼ばない。
//   - gatewayが付けた絶対期限（UNIX msの正規十進・ちょうど1件）を読み、backend受付から最大20秒と短い方を期限に使う（中継遅延で
//     延長しない）。欠落・重複・不正・過去は拒否する。
//   - Hostを固定のlogical public authorityへ置き換え、内部header（X-Serverless-Authorization・期限）を除去してから既存handlerへ渡す。
//     X-Serverless-AuthorizationはCloud Runがcontainerへ渡す前に署名を除くため、認可票として再検証・信頼しない。
//     外部から来た「元URL」「許可済み」「UID」等の値は根拠にしない（本人/source/Grantは既存handlerが一回だけ検査する）。

import { AsyncLocalStorage } from 'node:async_hooks';
import type { IncomingMessage, ServerResponse } from 'node:http';

import type { DeliveryHttpIngress } from '../delivery/api.js';
import { GATEWAY_DEADLINE_HEADER, GATEWAY_REQUEST_BUDGET_MS, SERVERLESS_AUTHORIZATION_HEADER, type GatewayClock } from './contract.js';

const DEADLINE = /^[1-9][0-9]{0,15}$/;

export interface BackendAuthorities {
  /** 設定のbackend authority（物理transport Host）。 */
  readonly transportAuthority: string;
  /** 設定の公開authority（issuer/resource/署名の宛先）。 */
  readonly logicalAuthority: string;
}

/**
 * transport authorityを検査してlogical authorityへ結び、この要求の絶対期限（min(gatewayの期限, now+20秒)）を返す。不成立・過去は
 * null（呼出し側が固定400）。成立した時だけheaders・rawHeadersの両方を書き換える。
 */
export function admitBackendRequest(req: IncomingMessage, authorities: BackendAuthorities, now: number): number | null {
  const raw = req.rawHeaders;
  let hosts = 0;
  let budgets = 0;
  let budget = 0;
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = (raw[index] ?? '').toLowerCase();
    const value = raw[index + 1] ?? '';
    if (name === 'host') {
      hosts += 1;
      if (value !== authorities.transportAuthority) return null;
    } else if (name === GATEWAY_DEADLINE_HEADER) {
      budgets += 1;
      if (!DEADLINE.test(value)) return null;
      budget = Number(value);
    }
  }
  if (hosts !== 1 || req.headers.host !== authorities.transportAuthority) return null;
  if (budgets !== 1 || !Number.isSafeInteger(budget) || !Number.isSafeInteger(now) || !(now < budget)) return null;
  const deadlineAt = Math.min(budget, now + GATEWAY_REQUEST_BUDGET_MS);
  const kept: string[] = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index] ?? '';
    const lower = name.toLowerCase();
    if (lower === GATEWAY_DEADLINE_HEADER || lower === SERVERLESS_AUTHORIZATION_HEADER) continue;
    kept.push(name, lower === 'host' ? authorities.logicalAuthority : (raw[index + 1] ?? ''));
  }
  raw.length = 0;
  raw.push(...kept);
  delete req.headers[GATEWAY_DEADLINE_HEADER];
  delete req.headers[SERVERLESS_AUTHORIZATION_HEADER];
  req.headers.host = authorities.logicalAuthority;
  return deadlineAt;
}

const INVALID_BODY = Buffer.from('{"error":{"code":"invalid_request"}}', 'utf8');
const UNAVAILABLE_BODY = Buffer.from(JSON.stringify({ error: { code: 'temporarily_unavailable', retryable: true } }), 'utf8');

function refuse(res: ServerResponse, status: 400 | 503): void {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  const body = status === 400 ? INVALID_BODY : UNAVAILABLE_BODY;
  res.writeHead(status, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(body.length) });
  res.end(body);
}

export interface ApiBackendServeOptions extends BackendAuthorities {
  readonly clock: GatewayClock;
  /** 既存のconsole CORS（preflight・拒否を書いたらtrue）。adapterの後・業務handlerの前に呼ぶ。 */
  readonly cors: (req: IncomingMessage, res: ServerResponse) => boolean;
}

export interface ApiBackendServe {
  /** 所有handlerへ渡すingress source（要求slot外は固定throw→所有handlerが固定503）。 */
  readonly ingress: () => DeliveryHttpIngress;
  /** adapter→CORS→要求固有の期限/中断を作り、runを1回awaitする。 */
  serve(req: IncomingMessage, res: ServerResponse, run: (req: IncomingMessage, res: ServerResponse, ingress: DeliveryHttpIngress) => Promise<void>): Promise<void>;
  /** 進行中の要求を中止し、新しい要求を503にする。 */
  close(): void;
}

/** API backendの要求処理（Run上のnode:http）。期限はgatewayの絶対期限とbackend受付+20秒の短い方（元20秒を延長しない）。 */
export function createApiBackendServe(options: ApiBackendServeOptions): ApiBackendServe {
  const store = new AsyncLocalStorage<{ readonly ingress: DeliveryHttpIngress }>();
  const active = new Set<AbortController>();
  let closing = false;
  const ingress = (): DeliveryHttpIngress => {
    const current = store.getStore();
    if (current === undefined) throw new Error('api backend ingress: no request slot');
    return current.ingress;
  };
  return Object.freeze({
    ingress,
    async serve(req: IncomingMessage, res: ServerResponse, run: (req: IncomingMessage, res: ServerResponse, ingress: DeliveryHttpIngress) => Promise<void>): Promise<void> {
      const receivedAt = options.clock.now();
      let deadlineAt: number | null;
      try {
        deadlineAt = admitBackendRequest(req, options, receivedAt);
      } catch {
        deadlineAt = null;
      }
      if (deadlineAt === null) {
        refuse(res, 400);
        return;
      }
      if (options.cors(req, res)) return;
      const controller = new AbortController();
      const current: DeliveryHttpIngress = Object.freeze({ receivedAt, deadlineAt, signal: controller.signal });
      const abort = (): void => controller.abort();
      const onResponseClose = (): void => {
        if (!res.writableFinished) controller.abort();
      };
      active.add(controller);
      req.once('aborted', abort);
      res.once('close', onResponseClose);
      const timer = setTimeout(abort, Math.max(0, deadlineAt - options.clock.now()));
      try {
        if (closing || !(options.clock.now() < deadlineAt)) {
          refuse(res, 503);
          return;
        }
        await store.run({ ingress: current }, () => run(req, res, current));
      } catch {
        refuse(res, 503);
      } finally {
        clearTimeout(timer);
        req.off('aborted', abort);
        res.off('close', onResponseClose);
        active.delete(controller);
        controller.abort();
      }
    },
    close(): void {
      closing = true;
      for (const controller of active) controller.abort();
    },
  });
}
