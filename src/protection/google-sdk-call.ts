// Google公式SDK（KMS 6.3.0・Secret Manager 7.2.0・google-gax 6.5.0）の借用clientを、既存portへ接ぐ共通部品。
// callerが初期化した借用clientの公開property innerApiCallsから対象のGAX callを1回だけ捕捉し、そのcancel付きPromiseを保持して
// 1回のRPC（retry:null・残り時間のtimeout・routing headerだけ）を待つ。生成SDKのpublic wrapper（encrypt/decrypt/accessSecretVersion）は
// GAXのcancel付きPromiseを.then/.catchで普通のPromiseへ変え、request/responseのdebug logも持つので使わない。
// SDKのprivate field（_opts/_log/_defaults等）・stub・initialize・ADC・metadata・global envには触れない。innerApiCallsへの依存は
// 上の固定版に対する結合で、SDK更新時は再確認する（同じと推測しない）。値のcache・永続化・ログ0。

import { stringify as stringifyQuery } from 'node:querystring';
import { types } from 'node:util';
import type { CallOptions } from 'google-gax';

/** 固定codeと固定messageだけを持つ失敗。元のSDK error・cause・statusDetails・stack・signal.reasonを転記しない。 */
export type GoogleSdkPortErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted' | 'closed' | 'integrity_failed';

const ERROR_MESSAGES: Readonly<Record<GoogleSdkPortErrorCode, string>> = {
  invalid_input: 'google sdk port: invalid input',
  unavailable: 'google sdk port: unavailable',
  timed_out: 'google sdk port: timed out',
  aborted: 'google sdk port: aborted',
  closed: 'google sdk port: closed',
  integrity_failed: 'google sdk port: integrity check failed',
};

export class GoogleSdkPortError extends Error {
  override readonly name = 'GoogleSdkPortError';
  readonly code: GoogleSdkPortErrorCode;

  constructor(code: GoogleSdkPortErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

/** 設定の不正（副作用の前に投げる）。 */
export function invalid(): GoogleSdkPortError {
  return new GoogleSdkPortError('invalid_input');
}

/** 1回のRPCの上限（KMS codecのcallTimeoutMsと同じ5秒）。 */
export const SDK_CALL_LIMIT_MS = 5000;
/** ECMAScriptのDateが表せる最大のepoch ms。 */
const MAX_EPOCH_MS = 8.64e15;

function isObjectLike(value: unknown): value is object {
  return (typeof value === 'object' || typeof value === 'function') && value !== null && !types.isProxy(value);
}

/**
 * 決まった名前のown data propertyだけを持つplain object（Object.prototype/null、Proxy・accessor・symbol・未知の名前なし）から
 * 値を1回だけ読む。requiredは全て必要、optionalは無くてよい。
 */
export function dataFields(value: unknown, required: readonly string[], optional: readonly string[] = []): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) throw invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !(required.includes(key) || optional.includes(key))) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    taken.set(key, descriptor.value);
  }
  for (const key of required) if (!taken.has(key)) throw invalid();
  return taken;
}

/** 本物の配列（Proxy・accessor・穴・余分なpropertyなし）の要素を1回だけ読む。 */
export function arrayItems(value: unknown): unknown[] {
  if (!isObjectLike(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw invalid();
  const length = (Object.getOwnPropertyDescriptor(value, 'length') as PropertyDescriptor).value as number;
  if (Reflect.ownKeys(value).length !== length + 1) throw invalid();
  const out: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) throw invalid();
    out.push(descriptor.value);
  }
  return out;
}

/** prototypeの連鎖をdescriptorで辿ってmethodを1回取り出し、元のobjectへ束縛する（accessor・Proxyを拒否、getterを呼ばない）。 */
export function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if (!isObjectLike(target)) throw invalid();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) throw invalid();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) throw invalid();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  throw invalid();
}

/**
 * 初期化済みの借用SDK clientから、公開property innerApiCallsの対象GAX callを1回だけ捕捉する（innerApiCallsへ束縛）。
 * 未初期化（innerApiCallsが空）・必要callなし・accessor・Proxyは副作用の前に拒否する。initialize・stub・private fieldを呼ばない/読まない。
 */
export function captureInnerApiCall(client: unknown, name: string): (request: object, options: CallOptions) => unknown {
  if (typeof client !== 'object' || client === null || types.isProxy(client)) throw invalid();
  const holder = Object.getOwnPropertyDescriptor(client, 'innerApiCalls');
  if (holder === undefined || !('value' in holder)) throw invalid();
  const calls: unknown = holder.value;
  if (typeof calls !== 'object' || calls === null || types.isProxy(calls)) throw invalid();
  const descriptor = Object.getOwnPropertyDescriptor(calls, name);
  if (descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) throw invalid();
  const call = descriptor.value as Function;
  return (request: object, options: CallOptions) => Reflect.apply(call, calls, [request, options]);
}

/** 安全整数・非負・Dateの範囲のepoch msだけを返す時計。読めない/不正は null（呼出し元が固定失敗にする）。 */
export function captureClock(clock: unknown): () => number | null {
  const now = methodOf(clock, 'now');
  return () => {
    try {
      const value = now();
      return isEpochMs(value) ? value : null;
    } catch {
      return null;
    }
  };
}

export function isEpochMs(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_EPOCH_MS;
}

const abortedGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;

/** 本物のAbortSignal（prototypeだけを似せたobject・Proxyを拒否。internal slotの無いobjectではgetterが投げる）。 */
export function isRealSignal(value: unknown): value is AbortSignal {
  if (!(value instanceof AbortSignal) || types.isProxy(value) || abortedGetter === undefined) return false;
  try {
    return typeof Reflect.apply(abortedGetter, value, []) === 'boolean';
  } catch {
    return false;
  }
}

/** Buffer/Uint8Array（Proxyなし）だけをbytesとして扱う。base64 string等は採用しない。 */
export function bytesOf(value: unknown): Uint8Array | null {
  return value instanceof Uint8Array && !types.isProxy(value) ? value : null;
}

/** pool共有の無い新しいBufferへの所有copy。 */
export function ownedCopy(bytes: Uint8Array): Buffer {
  const out = Buffer.alloc(bytes.length);
  out.set(bytes);
  return out;
}

/** Buffer/Uint8Arrayを0埋めする（それ以外は触らない）。 */
export function zero(value: unknown): void {
  if (value instanceof Uint8Array && !types.isProxy(value)) value.fill(0);
}

/** own data propertyの値（accessor・継承・Proxyは読まない＝undefined）。 */
export function ownValue(target: unknown, key: string): unknown {
  if (typeof target !== 'object' || target === null || types.isProxy(target)) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

/** own data propertyとして存在するか（値がundefinedでも）。 */
export function hasOwnData(target: unknown, key: string): boolean {
  if (typeof target !== 'object' || target === null || types.isProxy(target)) return false;
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor !== undefined && 'value' in descriptor;
}

const UINT32_DECIMAL = /^(?:0|[1-9][0-9]{0,9})$/;

/**
 * protobufのint64（CRC32C）を、uint32のnumber・正規十進string・固定SDK（long）Longのlow/highから損失なく正規化する。
 * 負数・上位32bit・NaN・小数・非正規string・不正型はnull。
 */
export function uint32Of(value: unknown): number | null {
  if (typeof value === 'number') return Number.isInteger(value) && value >= 0 && value <= 0xffffffff ? value : null;
  if (typeof value === 'string') {
    if (!UINT32_DECIMAL.test(value)) return null;
    const parsed = Number(value);
    return parsed <= 0xffffffff ? parsed : null;
  }
  if (typeof value === 'object' && value !== null && !types.isProxy(value) && !Array.isArray(value)) {
    if (!hasOwnData(value, 'low') || !hasOwnData(value, 'high') || !hasOwnData(value, 'unsigned')) return null;
    const low = ownValue(value, 'low');
    const high = ownValue(value, 'high');
    const unsigned = ownValue(value, 'unsigned');
    if (typeof low !== 'number' || typeof high !== 'number' || typeof unsigned !== 'boolean') return null;
    if ((low | 0) !== low || (high | 0) !== high) return null;
    // 値 = high×2^32 + (low>>>0)。uint32に収まるのは上位32bitが0の時だけ（signedで負ならhighは-1）。
    return high === 0 ? low >>> 0 : null;
  }
  return null;
}

/** GAX/SDKと同じ形（querystring.stringify）のrouting header値。 */
export function routingHeader(name: string): string {
  return stringifyQuery({ name });
}

/** 1つのadapter instanceのdispose状態と、進行中callの停止関数。 */
export interface CallScope {
  closed: boolean;
  readonly active: Set<(code: GoogleSdkPortErrorCode) => void>;
}

export function createCallScope(): CallScope {
  return { closed: false, active: new Set() };
}

/** 同期・冪等。以後の新RPC0、進行中はcancelして固定closedにする。借用clientは閉じない。 */
export function closeScope(scope: CallScope): void {
  if (scope.closed) return;
  scope.closed = true;
  for (const stop of [...scope.active]) stop('closed');
}

export interface SdkCallPlan<R> {
  /** captureInnerApiCallで捕捉したGAX call。 */
  readonly call: (request: object, options: CallOptions) => unknown;
  /** このadapterが作った（所有の）SDK request。 */
  readonly request: object;
  /** routing header（x-goog-request-params）に載せるresource名。 */
  readonly routingName: string;
  /** 一度だけ決めた元の絶対期限（epoch ms）。 */
  readonly deadline: number;
  /** callerの中止。abortは固定aborted。 */
  readonly signal: AbortSignal;
  readonly now: () => number | null;
  /** requestの所有copy。終了時（GAXのsettle、取消できない時は停止時）に0埋めする。 */
  readonly owned: readonly Buffer[];
  /** SDK応答（tupleの第1要素）を正規化した別の所有値にする。SDKのbytesを持ち越さない。不成立はGoogleSdkPortErrorを投げる。 */
  readonly normalize: (response: unknown) => R;
  /** SDK応答のbytesを0埋めする（late・失敗・成功の全てで呼ぶ）。投げない。 */
  readonly discard: (response: unknown) => void;
  /** 採用しなかった正規化済みの値（所有copy）を0埋めする。 */
  readonly release: (value: R) => void;
}

/** GAXのcancel付きPromiseを返したか。cancelはown data propertyだけを読む（返却時の検査）。 */
function cancelOf(value: Promise<unknown>): (() => void) | null {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'cancel');
    if (descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) return null;
    const cancel = descriptor.value as Function;
    return () => {
      Reflect.apply(cancel, value, []);
    };
  } catch {
    return null;
  }
}

/** GAX tupleの第1要素（本物の配列のindex 0のdata property）。形が違えばundefined。 */
function firstOf(tuple: unknown): unknown {
  if (!Array.isArray(tuple) || types.isProxy(tuple)) return undefined;
  return ownValue(tuple, '0');
}

const promiseThen = Promise.prototype.then;

/**
 * 1回のRPC。呼出し直前にdispose→signal→最新clock→signalを1回だけ観測し、その同じ観測値から元期限までの残り（1..5000）を
 * GAXのtimeoutと所有timerの両方に使う（古い開始時刻の残りで待たない）。retry:null・routing headerだけの
 * CallOptionsで捕捉済みcallを1回だけ呼ぶ。元期限/親abort/disposeで固定非成功にしてGAX cancelを最大1回呼び、所有request copyは
 * 全ての停止時に即時0埋めする（GAXのsettle・物理RPCの取消完了を待たない。callerのbytesは触らない）。遅い成功/失敗は採用せず、
 * 遅いbytesも0埋め。cancelの無い戻り値は非成功（既に始めたPromiseにも後始末を付ける）。SDK Promiseへ後始末handlerを付けた直後、
 * 応答後・正規化後（返却の直前）にもdispose/signal/clockを再検査する（同期call中の時計更新・abort・disposeを元timerまで放置しない）。
 * 物理RPCの取消完了・サーバー側の取消は保証しない。
 */
export function runSdkCall<R>(scope: CallScope, plan: SdkCallPlan<R>): Promise<R> {
  const { signal, now, deadline, owned } = plan;
  let requestWiped = false;
  const wipeRequest = (): void => {
    if (requestWiped) return;
    requestWiped = true;
    for (const buffer of owned) buffer.fill(0);
  };
  /** 最新のdispose→signal→clock→signalの順で、まだ続けてよいか。時計の観測中の中止（再入）も観測後に見る。 */
  const liveCode = (): GoogleSdkPortErrorCode | null => {
    if (scope.closed) return 'closed';
    if (signal.aborted) return 'aborted';
    const at = now();
    if (scope.closed) return 'closed';
    if (signal.aborted) return 'aborted';
    if (at === null) return 'unavailable';
    return at < deadline ? null : 'timed_out';
  };
  const early = (code: GoogleSdkPortErrorCode): Promise<R> => {
    wipeRequest();
    return Promise.reject(new GoogleSdkPortError(code));
  };

  if (!isEpochMs(deadline)) return early('unavailable');
  if (scope.closed) return early('closed');
  if (signal.aborted) return early('aborted');
  const at = now();
  if (scope.closed) return early('closed');
  if (signal.aborted) return early('aborted');
  if (at === null) return early('unavailable');
  const remaining = deadline - at;
  if (!(remaining >= 1)) return early('timed_out');
  // 同じ観測値の残り。元期限は開始+5000以内なので、上限5000は越えない値の安全側の切詰め。
  const timeout = Math.min(remaining, SDK_CALL_LIMIT_MS);
  // GAXへ渡すのはこの3つだけ（retry:nullでGAXの再試行を無効、timeoutはGAXのdeadline、headersはSDK public wrapperと同じrouting）。
  const options: CallOptions = {
    timeout,
    retry: null,
    otherArgs: { headers: { 'x-goog-request-params': routingHeader(plan.routingName) } },
  };

  return new Promise<R>((resolve, reject) => {
    let settled = false;
    let gaxSettled = false;
    let cancel: (() => void) | null = null;
    let cancelUsed = false;
    const cancelOnce = (): void => {
      if (cancelUsed || gaxSettled || cancel === null) return;
      cancelUsed = true;
      try {
        cancel();
      } catch {
        // cancelの例外は元の内容を出さない（待機は既に固定非成功）。
      }
    };
    const finish = (outcome: () => void): boolean => {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      scope.active.delete(stop);
      outcome();
      return true;
    };
    function stop(code: GoogleSdkPortErrorCode): void {
      if (!finish(() => reject(new GoogleSdkPortError(code)))) return;
      cancelOnce();
      // 停止した時点で所有request copyを0埋めする（cancelが効かずGAXがsettleしなくても残さない）。
      wipeRequest();
    }
    const onAbort = (): void => stop('aborted');
    const timer = setTimeout(() => stop('timed_out'), timeout);
    signal.addEventListener('abort', onAbort, { once: true });
    scope.active.add(stop);

    let returned: unknown;
    try {
      returned = plan.call(plan.request, options);
    } catch {
      stop('unavailable');
      return;
    }
    if (!types.isPromise(returned)) {
      // cancel付きPromiseでない戻り値（thenable等）はthenを呼ばずに非成功。
      stop('unavailable');
      return;
    }
    const pending = returned as Promise<unknown>;
    cancel = cancelOf(pending);
    Reflect.apply(promiseThen, pending, [
      (tuple: unknown) => {
        gaxSettled = true;
        wipeRequest();
        const response = firstOf(tuple);
        if (settled) return plan.discard(response);
        const before = liveCode();
        if (before !== null) {
          plan.discard(response);
          return stop(before);
        }
        let value: R;
        try {
          value = plan.normalize(response);
        } catch (error) {
          return stop(error instanceof GoogleSdkPortError ? error.code : 'integrity_failed');
        } finally {
          plan.discard(response);
        }
        // 所有値をcallerへ移す直前の再検査（正規化中の時計・中止・disposeを含む）。
        const after = liveCode();
        if (after !== null) {
          plan.release(value);
          return stop(after);
        }
        if (!finish(() => resolve(value))) plan.release(value);
      },
      () => {
        gaxSettled = true;
        wipeRequest();
        if (settled) return;
        stop(liveCode() ?? 'unavailable');
      },
    ]);
    // 後始末handlerを付けた後で終了を検査する。呼出し中の同期の再入（abort/dispose）で既に止まっていれば、ここでcancelする。
    if (settled) {
      cancelOnce();
      return;
    }
    if (cancel === null) {
      // cancelを持たないPromise（取消不能）は非成功。上の後始末handlerは付けたまま、requestの所有copyは停止で0埋めする。
      stop('unavailable');
      return;
    }
    // 同期callの中で時計が期限を越えた/中止・disposeされた場合も、元timerの発火を待たずに止める。
    const after = liveCode();
    if (after !== null) stop(after);
  });
}
