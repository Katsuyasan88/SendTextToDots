// 送信APIのHTTP入口（Functions第2世代onRequestへ渡すhandler）。正本はdocs/API.md §2。
//   POST /v2/commands                 新規は要求内の結果を200＋state、同ID処理中は202＋in_flight
//   GET  /v2/commands/{commandId}     読取りだけ。不在と他ownerは同じ404
//   POST /v2/commands/{commandId}/cancel
//   GET  /v2/encryption-key           本人の公開鍵（本文暗号化が有効な配置だけ。offは404。body・queryは400）
//   POST /v2/encrypted-commands       暗号文（application/jose、12288byte以下）。平文と同じ状態応答（offは404）
// 旧v1の3 routeはroute外（404 not_found、serviceを呼ばない）。新旧の変換・redirectはしない。
// 公開鍵の取得は検証済みidentityだけを鍵service（encryption/api.ts）へ渡す。ownerはserviceが作らずに読む（findOwnerは呼ばない）。
// 本人確認はBearer Firebase ID token（verifyIdToken・失効確認・apple.com）だけで、UID→ownerは接続保存（ConnectStorage.findOwner）から引く
// （作らない）。Node標準のreq/resだけを使う。本文は、frameworkが既に読んだrawBody（wireのbytes）があればそれを使い、無ければ通常のstreamを
// 上限・元期限つきで自分で読む（途中の切断・超過・期限は処理せず拒否）。
// 元の受信時刻・元期限（受信+20秒以内）・中断は、trustedなHTTP entryが観測した値を内部のsource（要求ごとに1回だけ呼ぶ）から受ける。
// 不正・未来・延長・既中断・期限切れは新しい20秒へfallbackせず固定503。本文・本人確認・owner照会・serviceの各段階の前とawait後の採用前に
// 同じoperationのsignal→時計→signalを確かめ、serviceのpost/get/cancelも同じoperationの中断までで待つ（中断・期限後の結果は採用せず503）。
// 例外を外へ投げない（Functionsの既定のエラーログへ要求の値を渡さない）。応答・ログに本文・token・secret・URLを出さない。

import type { IncomingMessage, ServerResponse } from 'node:http';
import { types } from 'node:util';

import type { EncryptionKeyEndpoint } from '../encryption/api.js';
import { ENCRYPTED_CONTENT_TYPE, ENCRYPTED_WIRE_MAX_BYTES, type EncryptedCommandEndpoint } from '../encryption/commands.js';
import { IdentityError, type IdentityVerifier, type VerifiedIdentity } from '../identity/firebase.js';
import { MAX_COMMAND_BODY_BYTES, type Clock } from '../policy.js';
import { isRealSignal } from '../protection/google-sdk-call.js';
import { errorResponse, type DeliveryResponse } from './event.js';

const BEARER_ID_TOKEN = /^Bearer ([A-Za-z0-9._-]{1,4096})$/;
const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const COMMAND_PATH = new RegExp(`^/v2/commands/(${UUID})(/cancel)?$`);
const ENCRYPTION_KEY_PATH = '/v2/encryption-key';
const ENCRYPTED_COMMANDS_PATH = '/v2/encrypted-commands';

/** onRequestのreqが持つwireの本文。 */
export type DeliveryRequest = IncomingMessage & { readonly rawBody?: Buffer | undefined };

function write(res: ServerResponse, response: DeliveryResponse): void {
  if (res.headersSent || res.writableEnded) return;
  const payload = Buffer.from(JSON.stringify(response.body), 'utf8');
  res.writeHead(response.status, {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...response.headers,
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(payload.length),
  });
  res.end(payload);
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return typeof value === 'string' ? value : undefined;
}

function isJson(req: IncomingMessage): boolean {
  const type = header(req, 'content-type');
  return type !== undefined && /^application\/json\s*(;\s*charset=utf-8\s*)?$/i.test(type.trim());
}

/** 元期限の上限（20秒固定。注入口は無い）。 */
const OPERATION_BUDGET_MS = 20_000;
const MAX_ISO_TIME_MS = 8_640_000_000_000_000;

/** 1つのHTTP要求の元期限（clockと同じepoch ms）と中断。frozen。 */
export interface DeliveryRequestOperation {
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

/**
 * 入口が使うservice port（KmsRequestDeliveryServiceの任意parentOperationつきcallと同じ形）。
 * postのrawBodyは借用。serviceは必要な検証・コピーを最初のawaitより前に済ませ、operationの中断後に元のBufferを使わない（入口は中断で
 * 待機を終えると、自分で読んだ本文をfinallyで0埋めする。frameworkのrawBodyは上書きしない）。入口が待機を終えても、既に始まった
 * service内の処理・送出を撤回できるわけではない。
 */
export interface OperationDeliveryService {
  post(ownerId: string, idempotencyKey: string, rawBody: Buffer, receivedAt: number, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
  get(ownerId: string, commandId: string, receivedAt: number, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
  cancel(ownerId: string, commandId: string, receivedAt: number, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
}

/**
 * trustedなHTTP entryが観測した元の受信時刻・元期限・中断（exact own data）。両時刻は安全整数・非負・ISO表現域、
 * receivedAt < deadlineAt <= receivedAt+20秒、signalは本物のAbortSignal。HTTP callerから渡せるfield・route・headerではない。
 */
export interface DeliveryHttpIngress {
  readonly receivedAt: number;
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

export interface IngressOperationDeliveryApiDeps {
  readonly identity: IdentityVerifier;
  /** 検証済みの本人から、作らずに有効なownerを引く（ConnectStorage.findOwner）。 */
  readonly findOwner: (verified: VerifiedIdentity) => Promise<string | undefined>;
  readonly service: OperationDeliveryService;
  readonly clock: Clock;
  readonly log?: ((entry: Record<string, unknown>) => void) | undefined;
  /** runtimeの寿命。中止されると、進行中の要求も中断し、新しい段階を始めない。 */
  readonly lifetime: AbortSignal;
  /** 要求固有storeから元ingressを返すtrustedな内部source。 */
  readonly ingress: () => DeliveryHttpIngress;
  /** 本文暗号化が有効な配置だけ: 本人の公開鍵取得（frozenでown dataの`get`関数を持つobject）。無ければ/v2/encryption-keyは404。 */
  readonly encryptionKeys?: EncryptionKeyEndpoint | undefined;
  /** 本文暗号化が有効な配置だけ: 暗号文の送信（frozenでown dataの`post`関数を持つobject）。無ければ/v2/encrypted-commandsは404。 */
  readonly encryptedCommands?: EncryptedCommandEndpoint | undefined;
}

/** depsの不正（ingress sourceが関数でない・Proxy・accessor）。固定のmessageだけ。 */
export class DeliveryIngressConfigError extends Error {
  override readonly name = 'DeliveryIngressConfigError';
  readonly code = 'delivery_ingress_config_invalid';
  constructor() {
    super('delivery_ingress_config_invalid');
  }
}

const INGRESS_KEYS = ['receivedAt', 'deadlineAt', 'signal'] as const;

/** 安全整数・非負・ISO表現域のepoch ms。 */
function isTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_ISO_TIME_MS;
}

/** namesちょうどのown data propertyだけのplain object（Proxy・accessor・symbol・未知/欠落・Promise等を拒否、getterを呼ばない）の写し。 */
function exactOwnData(value: unknown, names: readonly string[]): Map<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) return undefined;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length) return undefined;
  const taken = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== 'string' || !names.includes(key)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) return undefined;
    taken.set(key, descriptor.value);
  }
  return taken;
}

/** operationの中断・期限・不正な時計の印（応答は固定503）。 */
const STOPPED: unique symbol = Symbol('delivery request stopped');

/** 時計の値を1回読む（安全な整数・非負・ISO表現域で、20秒を足しても表現域内）。throw・不正はundefined。 */
function readClock(clock: Clock): number | undefined {
  let value: unknown;
  try {
    value = clock.now();
  } catch {
    return undefined;
  }
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_ISO_TIME_MS - OPERATION_BUDGET_MS ? value : undefined;
}

/** promiseの結果をsignalの中断までで待つ（後着の成功・失敗は処理済みとして消化する）。中断はSTOPPED。 */
function untilStopped<T>(start: () => Promise<T>, signal: AbortSignal): Promise<T | typeof STOPPED> {
  if (signal.aborted) return Promise.resolve(STOPPED);
  let promise: Promise<T>;
  try {
    promise = Promise.resolve(start());
  } catch (error) {
    return Promise.reject(error);
  }
  promise.catch(() => {});
  return new Promise<T | typeof STOPPED>((resolve, reject) => {
    let settled = false;
    const finish = (outcome: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      outcome();
    };
    const onAbort = () => finish(() => resolve(STOPPED));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    promise.then(
      (value) => finish(() => resolve(value)),
      (error: unknown) => finish(() => reject(error)),
    );
  });
}

/** 本文（自分で読んだものはowned）。上限超過・切断・読めない状態はundefined（400）。中断・期限はSTOPPED（503）。 */
type OperationBodyRead = { readonly body: Buffer; readonly owned: boolean } | undefined | typeof STOPPED;

/**
 * 本文: rawBodyがあれば借用（上書きしない・参照を新たに保存しない）、無ければstreamを上限・operationの中断・元期限まで読む。
 * 中断はSTOPPED。どの終わり方でも、全listener・timerを外し、溜めたchunkを0で上書きして手放す。
 */
function operationBodyOf(req: DeliveryRequest, max: number, remainingMs: number, signal: AbortSignal): Promise<OperationBodyRead> {
  if (signal.aborted) return Promise.resolve(STOPPED);
  if (Buffer.isBuffer(req.rawBody)) return Promise.resolve<OperationBodyRead>(req.rawBody.length <= max ? { body: req.rawBody, owned: false } : undefined);
  if (req.readableEnded) return Promise.resolve<OperationBodyRead>({ body: Buffer.alloc(0), owned: true });
  if (req.destroyed) return Promise.resolve<OperationBodyRead>(undefined);
  if (!(remainingMs > 0)) return Promise.resolve(STOPPED);
  return new Promise<OperationBodyRead>((resolve) => {
    let chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const done = (value: OperationBodyRead) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('aborted', onAbort);
      req.off('error', onAbort);
      req.off('close', onClose);
      signal.removeEventListener('abort', onStop);
      for (const chunk of chunks) chunk.fill(0);
      chunks = [];
      // 残りのdataはlistener無しで流して捨てる（参照を持たない）。
      if (!req.destroyed && !req.readableEnded) req.resume();
      resolve(value);
    };
    const onData = (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > max) done(undefined);
      else chunks.push(chunk);
    };
    const onEnd = () => done({ body: Buffer.concat(chunks), owned: true });
    const onAbort = () => done(undefined);
    const onClose = () => {
      if (!req.complete) done(undefined);
    };
    const onStop = () => done(STOPPED);
    const timer = setTimeout(() => done(STOPPED), remainingMs);
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('aborted', onAbort);
    req.once('error', onAbort);
    req.once('close', onClose);
    signal.addEventListener('abort', onStop, { once: true });
    if (signal.aborted) onStop();
  });
}

/**
 * 送信APIの入口。ingress sourceはfactoryで1回捕捉し（関数・Proxyでないこと）、factoryでは呼ばない。各HTTP要求の最初（本文・本人確認・
 * owner・serviceの前）に1回だけ呼び、結果をexact own dataの写しとして捕捉・検査する。例外・Promise・undefined・不正・未来・延長・既中断・
 * 期限切れは固定503（書込める時だけ）。要求固有のAbortControllerをreqの中断・未完了のres close・lifetimeの中止・ingressの中断・元期限へ
 * 結び、要求のfinallyで終了印→controllerのabort→timer・listenerの解除。
 */
export function createIngressOperationDeliveryRequestHandler(deps: IngressOperationDeliveryApiDeps): (req: DeliveryRequest, res: ServerResponse) => Promise<void> {
  if (typeof deps !== 'object' || deps === null || types.isProxy(deps)) throw new DeliveryIngressConfigError();
  const descriptor = Object.getOwnPropertyDescriptor(deps, 'ingress');
  if (descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) {
    throw new DeliveryIngressConfigError();
  }
  const source = descriptor.value as Function;
  const encryptionKeys = captureEncryptionKeys(deps);
  const encryptedCommands = captureEncryptedCommands(deps);
  return buildOperationHandler(deps, () => Reflect.apply(source, undefined, []) as unknown, encryptionKeys, encryptedCommands);
}

/** 任意のport（欠落/undefinedは無効）。own dataのfrozen objectで、own dataのmethod関数だけを捕捉する（Proxy・accessorは拒否）。 */
function capturePort(deps: object, name: string, method: string): ((...args: unknown[]) => unknown) | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(deps, name);
  if (descriptor === undefined) return undefined;
  if (!('value' in descriptor)) throw new DeliveryIngressConfigError();
  const value: unknown = descriptor.value;
  if (value === undefined) return undefined;
  if (typeof value !== 'object' || value === null || types.isProxy(value) || !Object.isFrozen(value)) throw new DeliveryIngressConfigError();
  const own = Object.getOwnPropertyDescriptor(value, method);
  if (own === undefined || !('value' in own) || typeof own.value !== 'function' || types.isProxy(own.value)) throw new DeliveryIngressConfigError();
  const fn = own.value as Function;
  return (...args: unknown[]) => Reflect.apply(fn, value, args);
}

function captureEncryptionKeys(deps: object): EncryptionKeyEndpoint | undefined {
  const get = capturePort(deps, 'encryptionKeys', 'get');
  return get === undefined ? undefined : Object.freeze({ get: (identity: VerifiedIdentity, operation: DeliveryRequestOperation) => get(identity, operation) as Promise<DeliveryResponse> });
}

function captureEncryptedCommands(deps: object): EncryptedCommandEndpoint | undefined {
  const post = capturePort(deps, 'encryptedCommands', 'post');
  return post === undefined
    ? undefined
    : Object.freeze({
        post: (identity: VerifiedIdentity, key: string | undefined, wire: Buffer, receivedAt: number, operation: DeliveryRequestOperation) =>
          post(identity, key, wire, receivedAt, operation) as Promise<DeliveryResponse>,
      });
}

/** 1つの要求の開始（受信時刻・元期限・timerの残り・結ぶ親signal）。不成立はundefined（固定503）。 */
interface RequestStart {
  readonly receivedAt: number;
  readonly deadlineAt: number;
  readonly timerMs: number;
  readonly parent: AbortSignal;
}

/**
 * ingressの開始。sourceを1回だけ呼び、exact own dataの写しを検査する（receivedAt <= 入口のnow、receivedAt < deadlineAt <=
 * receivedAt+20秒、genuine AbortSignal・未中断、now < deadlineAt）。timerはdeadlineAtと現在の時計の差だけ（20秒を取り直さない）。
 */
function ingressStart(source: () => unknown, clock: Clock): RequestStart | undefined {
  // sourceの例外・結果の検査中の例外（own accessorのthrow等）も、固定503（undefined）へ閉じる。
  try {
    const fields = exactOwnData(source(), INGRESS_KEYS);
    if (fields === undefined) return undefined;
    const receivedAt = fields.get('receivedAt');
    const deadlineAt = fields.get('deadlineAt');
    const signal = fields.get('signal');
    if (!isTime(receivedAt) || receivedAt > MAX_ISO_TIME_MS - OPERATION_BUDGET_MS) return undefined;
    if (!isTime(deadlineAt) || !(receivedAt < deadlineAt) || deadlineAt > receivedAt + OPERATION_BUDGET_MS) return undefined;
    if (!isRealSignal(signal) || signal.aborted) return undefined;
    const now = readClock(clock);
    if (now === undefined || receivedAt > now || !(now < deadlineAt) || signal.aborted) return undefined;
    return { receivedAt, deadlineAt, timerMs: deadlineAt - now, parent: signal };
  } catch {
    return undefined;
  }
}

function buildOperationHandler(
  deps: IngressOperationDeliveryApiDeps,
  ingress: () => unknown,
  encryptionKeys: EncryptionKeyEndpoint | undefined,
  encryptedCommands: EncryptedCommandEndpoint | undefined,
): (req: DeliveryRequest, res: ServerResponse) => Promise<void> {
  const { identity, findOwner, service, clock, lifetime } = deps;
  const log = (entry: Record<string, unknown>) => {
    try {
      deps.log?.(entry);
    } catch {
      // ログの失敗で処理を変えない。
    }
  };
  const unavailable = () => errorResponse(503, 'temporarily_unavailable', true);

  return async (req, res) => {
    // ingress sourceは最初のawaitより前に1回だけ呼ぶ（不正なら何も始めない）。
    const start = ingressStart(ingress, clock);
    const controller = new AbortController();
    const signal = controller.signal;
    let ended = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const abort = (): void => controller.abort();
    const onResponseClose = (): void => {
      // 正常に書き終えた後のcloseは中断にしない。
      if (!res.writableFinished) controller.abort();
    };
    let label = 'rejected';
    let response: DeliveryResponse | undefined;
    try {
      if (start === undefined) {
        response = unavailable();
        return;
      }
      const { receivedAt } = start;
      const operation: DeliveryRequestOperation = Object.freeze({ deadlineAt: start.deadlineAt, signal });
      // 結びつけ（終了の後には足さない）。既に中断済みの接続・lifetime・親（ingress）は、本文・本人確認・owner・serviceを始めない。
      req.once('aborted', abort);
      res.once('close', onResponseClose);
      lifetime.addEventListener('abort', abort, { once: true });
      start.parent.addEventListener('abort', abort, { once: true });
      if (!ended) timer = setTimeout(abort, start.timerMs);
      if (lifetime.aborted || start.parent.aborted || req.aborted || res.destroyed || (req.destroyed && !req.complete)) controller.abort();

      /** 新しい段階の前・await後の採用前の検査（signal→時計→signal）。期限・不正な時計は中断にしてSTOPPED。 */
      const live = (): boolean => {
        if (signal.aborted) return false;
        const now = readClock(clock);
        if (signal.aborted) return false;
        if (now === undefined || !(now < operation.deadlineAt)) {
          controller.abort();
          return false;
        }
        return true;
      };

      const method = req.method ?? '';
      let path: string;
      let search: string;
      try {
        const url = new URL(req.url ?? '/', 'http://function.invalid');
        path = url.pathname;
        search = url.search;
      } catch {
        response = errorResponse(400, 'invalid_request');
        return;
      }
      const match = COMMAND_PATH.exec(path);
      label = path === '/v2/commands' ? 'commands.post' : match ? (match[2] ? 'commands.cancel' : 'commands.get') : 'not_found';
      // 公開鍵の取得は暗号化が有効な配置だけ（offは他の未知pathと同じ404。鍵service・Secretを呼ばない）。
      if (path === ENCRYPTION_KEY_PATH && encryptionKeys !== undefined) label = 'encryption_key.get';
      if (path === ENCRYPTED_COMMANDS_PATH && encryptedCommands !== undefined) label = 'encrypted_commands.post';
      if (label === 'not_found') {
        response = errorResponse(404, 'not_found');
        return;
      }
      const allowed = label === 'commands.get' || label === 'encryption_key.get' ? 'GET' : 'POST';
      const encrypted = label === 'encrypted_commands.post';
      if (method !== allowed) {
        response = errorResponse(405, 'method_not_allowed');
        return;
      }
      // 公開鍵の取得はqueryで本人・鍵・Secretを選ばせない（空でなければ400）。
      if (label === 'encryption_key.get' && search !== '') {
        response = errorResponse(400, 'invalid_request');
        return;
      }

      if (!live()) {
        response = unavailable();
        return;
      }
      const now = readClock(clock);
      // 暗号文のwireは平文の8192とは別の12288で、超過は本人確認・DB・復号試行の前に読み出しを打ち切って400（暗号処理・rate消費0）。
      const max = encrypted ? ENCRYPTED_WIRE_MAX_BYTES : MAX_COMMAND_BODY_BYTES;
      const read = await operationBodyOf(req, max, now === undefined ? 0 : operation.deadlineAt - now, signal);
      if (read === STOPPED || !live()) {
        if (read !== STOPPED && read !== undefined && read.owned) read.body.fill(0);
        response = unavailable();
        return;
      }
      if (read === undefined) {
        response = errorResponse(400, encrypted ? 'invalid_encrypted_request' : 'invalid_request');
        return;
      }
      try {
        response = await handleWith(req, label, match, read.body, receivedAt, operation, live);
      } finally {
        // 自分で読んだ本文だけを0で上書きする（frameworkのrawBodyには触れない）。
        if (read.owned) read.body.fill(0);
      }
    } catch {
      log({ event: 'http.unexpected_error' });
      response = unavailable();
    } finally {
      ended = true;
      controller.abort();
      clearTimeout(timer);
      req.off('aborted', abort);
      res.off('close', onResponseClose);
      lifetime.removeEventListener('abort', abort);
      start?.parent.removeEventListener('abort', abort);
      const final = response ?? unavailable();
      // 中断済み・書込めない接続へは応答の成功を主張しない（書込める時だけ）。
      const writable = !res.destroyed && !res.writableEnded && !res.headersSent;
      if (writable) write(res, final);
      const state = (final.body as { state?: unknown } | null)?.state;
      log({ event: 'http.request', route: label, status: writable ? final.status : 0, ...(writable && typeof state === 'string' ? { state } : {}) });
    }
  };

  async function handleWith(
    req: DeliveryRequest,
    label: string,
    match: RegExpExecArray | null,
    body: Buffer,
    receivedAt: number,
    operation: DeliveryRequestOperation,
    live: () => boolean,
  ): Promise<DeliveryResponse> {
    if (label === 'commands.post') {
      if (!isJson(req) || body.length < 1) return errorResponse(400, 'invalid_request');
    } else if (label !== 'encrypted_commands.post' && body.length > 0) {
      return errorResponse(400, 'invalid_request');
    }
    if (label === 'encryption_key.get') {
      const verified = await verifiedWith(req, operation, live);
      if (!('uid' in verified)) return verified;
      return adopted(() => encryptionKeys!.get(verified, operation), operation, live);
    }
    if (label === 'encrypted_commands.post') {
      const type = header(req, 'content-type');
      if (type === undefined || !ENCRYPTED_CONTENT_TYPE.test(type.trim()) || body.length < 1) return errorResponse(400, 'invalid_encrypted_request');
      const verified = await verifiedWith(req, operation, live);
      if (!('uid' in verified)) return verified;
      const key = header(req, 'idempotency-key');
      return adopted(() => encryptedCommands!.post(verified, key, body, receivedAt, operation), operation, live);
    }
    const resolved = await ownerWith(req, operation, live);
    if (typeof resolved !== 'string') return resolved;
    if (!live()) return unavailable();
    if (label === 'commands.post') {
      const key = header(req, 'idempotency-key');
      if (key === undefined) return errorResponse(400, 'invalid_request');
      return adopted(() => service.post(resolved, key, body, receivedAt, operation), operation, live);
    }
    const commandId = match![1]!.toLowerCase();
    if (label === 'commands.get') return adopted(() => service.get(resolved, commandId, receivedAt, operation), operation, live);
    return adopted(() => service.cancel(resolved, commandId, receivedAt, operation), operation, live);
  }

  /**
   * serviceも同じoperationの中断までで待ち、await後の採用前にもう一度live()を確かめる。中断・元期限後の結果（成功・非成功）は
   * 採用せず固定503。後着のrejectはuntilStoppedが処理済みにする。期限内のrejectは外側のcatch（固定503）。
   */
  async function adopted(start: () => Promise<DeliveryResponse>, operation: DeliveryRequestOperation, live: () => boolean): Promise<DeliveryResponse> {
    const result = await untilStopped(start, operation.signal);
    if (result === STOPPED || !live()) return unavailable();
    return result;
  }

  /** Bearer tokenの本人確認だけ（owner照会なし）。不成立は401/503の応答。 */
  async function verifiedWith(req: IncomingMessage, operation: DeliveryRequestOperation, live: () => boolean): Promise<VerifiedIdentity | DeliveryResponse> {
    const match = BEARER_ID_TOKEN.exec(header(req, 'authorization') ?? '');
    if (!match) return errorResponse(401, 'authentication_required');
    if (!live()) return unavailable();
    let verified: VerifiedIdentity | typeof STOPPED;
    try {
      verified = await untilStopped(() => identity.verifyIdToken(match[1]!), operation.signal);
    } catch (error) {
      if (!live()) return unavailable();
      const code = error instanceof IdentityError ? error.code : 'unavailable';
      log({ event: 'identity.rejected', code });
      return code === 'unavailable' ? unavailable() : errorResponse(401, 'authentication_required');
    }
    if (verified === STOPPED || !live()) return unavailable();
    return verified;
  }

  async function ownerWith(req: IncomingMessage, operation: DeliveryRequestOperation, live: () => boolean): Promise<string | DeliveryResponse> {
    const match = BEARER_ID_TOKEN.exec(header(req, 'authorization') ?? '');
    if (!match) return errorResponse(401, 'authentication_required');
    if (!live()) return unavailable();
    let verified: VerifiedIdentity | typeof STOPPED;
    try {
      verified = await untilStopped(() => identity.verifyIdToken(match[1]!), operation.signal);
    } catch (error) {
      if (!live()) return unavailable();
      const code = error instanceof IdentityError ? error.code : 'unavailable';
      log({ event: 'identity.rejected', code });
      return code === 'unavailable' ? unavailable() : errorResponse(401, 'authentication_required');
    }
    // 遅い本人確認の結果（成功・非成功）は採用せず、owner照会・serviceを始めない。
    if (verified === STOPPED || !live()) return unavailable();
    const verifiedIdentity: VerifiedIdentity = verified;
    let ownerId: string | undefined | typeof STOPPED;
    try {
      ownerId = await untilStopped(() => findOwner(verifiedIdentity), operation.signal);
    } catch {
      return unavailable();
    }
    if (ownerId === STOPPED || !live()) return unavailable();
    // 未接続・失効・無活動のownerは、新しく作らずに拒否する（外部入力からownerを選ばせない）。
    if (ownerId === undefined) return errorResponse(403, 'connection_revoked');
    return ownerId;
  }
}
