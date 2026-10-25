// 実AS（固定oidc-provider 9.12.2）の不透明access tokenを、要求ごとのAsyncLocalStorage slotの中で同じ元期限・中止のまま
// AccessToken→Grant→ownerの順に検証する、RequestScopedOwnerResolver。同じslotのcurrent()をAS/UIDのKMS port（
// `operation`）へ渡すと、AccessToken/Grantの開封も同じ元期限・中止で打ち切られる。
// 任意のtoken decoder・owner verifier・Grant validator・fixture resolverの注入口は無い。
// factoryは同期・I/Oなし（DB・KMS・通信0）。provider・connect・clock・KMS transportは借用で、close・terminate・disposeしない。
// contextはcreateRequestAuthContextが作った同じinstanceだけを認め（module内WeakMap）、要求外・終了後・中止・期限・閉鎖のcurrent()は固定の非成功。
// 各await前後・新しいtimer/listenerの作成前・正常返却の直前にsignal→時計→signalで検査し、遅い成功を採用せず、遅いrejectは握りつぶす。
// 既に始めたSDK・DB・KMSの内部I/Oの物理的な停止、取消との完全な原子性は約束しない（購読の最終認可は登録storeが正）。
// 開始時だけでなく要求中の全ての時計の観測を、同じ検証（有限の安全整数・非負・ISO表現域、throwなし）に通す。
// 不正な観測は期限の根拠にせず固定unavailable（観測の前後の閉鎖・中止・slot終了が優先）。正しい時刻での期限の到達だけがtimed_out。
// 通常Bearer専用。AccessTokenにown jkt/x5t#S256が存在すれば値を問わずnull（DPoP/mTLSのproof検証は行わず、降格しない）。

import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';

import Provider from 'oidc-provider';

import { ConnectStorage } from '../connect/firestore.js';
import type { McpRequestOperation, RequestScopedOwnerResolver } from '../mcp/request-operation.js';
import type { Clock } from '../policy.js';
import { isUuid } from '../storage/firestore/checks.js';
import type { ResolvedOAuthOwner } from './owner.js';
import { STTD_SCOPE } from './provider.js';

/** 1つのslotの上限（元期限・入れ子の親slotの期限と、run開始+この値の最小）。延長しない。 */
const REQUEST_AUTH_BUDGET_MS = 20_000;
/** 受け付けるaccess tokenのUTF-8の上限（byte）。超えるものは資格情報の不成立。 */
const MAX_ACCESS_TOKEN_BYTES = 8192;
/** ECMAScriptのDateで表せる最大のepochミリ秒（ISO文字列の表現域）。 */
const MAX_ISO_TIME_MS = 8_640_000_000_000_000;

/** factoryの入力の不正。固定のcode/messageだけで、渡された値・元の例外を持たない。 */
export class RequestAuthConfigError extends Error {
  override readonly name = 'RequestAuthConfigError';
  readonly code = 'request_auth_config_invalid';
  constructor() {
    super('request_auth_config_invalid');
  }
}

export type RequestAuthContextErrorCode = 'invalid_input' | 'unavailable' | 'timed_out' | 'aborted' | 'closed' | 'no_context';

const ERROR_MESSAGES: Readonly<Record<RequestAuthContextErrorCode, string>> = {
  invalid_input: 'request auth context: invalid input',
  unavailable: 'request auth context: unavailable',
  timed_out: 'request auth context: timed out',
  aborted: 'request auth context: aborted',
  closed: 'request auth context: closed',
  no_context: 'request auth context: no context',
};

/** contextとresolverの固定の非成功。cause・元の値・token・owner/Grantを持たない。 */
export class RequestAuthContextError extends Error {
  override readonly name = 'RequestAuthContextError';
  readonly code: RequestAuthContextErrorCode;
  constructor(code: RequestAuthContextErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.code = code;
  }
}

export interface RequestAuthContextOptions {
  /** 共通の時計（nowを1回だけ捕捉し元instanceへ束縛）。同じclockをAS/UID KMS portのcodec設定へも呼出し元が渡す。 */
  readonly clock: Clock;
}

export interface RequestAuthContext {
  /**
   * operation（MCP入口と同じexact {deadlineAt, signal}）の要求slotを作り、その中でworkを1回呼ぶ。slotの期限は元期限・入れ子なら現slotの期限・
   * 開始+20000msの最小を一度だけ決める。期限・中止・閉鎖で打ち切り、遅い成功を採用しない。workの例外は固定unavailable。
   */
  run<T>(operation: McpRequestOperation, work: () => T | PromiseLike<T>): Promise<T>;
  /** 同じslotのfrozen {deadlineAt, signal}。slot無し・終了後・中止・期限・閉鎖は固定のRequestAuthContextError（同期のthrow）。 */
  current(): McpRequestOperation;
  /** 同期・冪等。先に閉鎖して進行中の全slotを中止する。借用のclockは閉じない。 */
  dispose(): void;
}

export interface RequestScopedOAuthOwnerResolverOptions {
  /** 固定oidc-provider 9.12.2の本物のProvider instance（借用）。公開getterのAccessToken/Grantを1回だけ取得する。 */
  readonly provider: Provider;
  /** providerと同じ構成の接続保存（借用）。isOwnerActiveだけを使い、owner活動時刻を延長しない。 */
  readonly connect: ConnectStorage;
  /** createRequestAuthContextが作った同じinstance。 */
  readonly context: RequestAuthContext;
  /** 固定MCP audience（access tokenのaud・Grant.resourcesのkey）。 */
  readonly resource: string;
}

/** 1つの要求slot。runごとに作り、他の要求と共有しない。 */
interface Slot {
  /** 外へ渡す同じfrozen object（{deadlineAt, signal: 子signal}）。 */
  readonly operation: McpRequestOperation;
  readonly deadlineAt: number;
  /** 元operationのsignal。 */
  readonly parent: AbortSignal;
  /** 入れ子の時の外側のslot。 */
  readonly outer: Slot | undefined;
  readonly controller: AbortController;
  /** runのfinallyで最初にtrueにする（以後のcurrent()は失敗）。 */
  ended: boolean;
  release(): void;
}

interface ContextState {
  readonly storage: AsyncLocalStorage<Slot>;
  /** 捕捉した時計。throw・有限の安全整数でない・負・ISO表現域外の観測はnull（全観測で同じ検証）。 */
  readonly now: () => number | null;
  readonly lifetime: AbortController;
  readonly active: Set<Slot>;
  closed: boolean;
}

/** このmoduleが作ったcontext → 内部状態。外から渡された別objectを認めない。 */
const CONTEXTS = new WeakMap<object, ContextState>();

function configFail(): never {
  throw new RequestAuthConfigError();
}

function contextError(code: RequestAuthContextErrorCode): RequestAuthContextError {
  return new RequestAuthContextError(code);
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !types.isProxy(value);
}

/**
 * 決まった名前のown data propertyだけのplain objectから値を1回読む（Proxy・accessor・symbol・未知・欠落の名前を拒否、getterを呼ばない）。
 */
function dataFields(value: unknown, keys: readonly string[], onInvalid: () => Error): Map<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) throw onInvalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw onInvalid();
  const taken = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !keys.includes(key)) throw onInvalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) throw onInvalid();
    taken.set(key, descriptor.value);
  }
  for (const key of keys) if (!taken.has(key)) throw onInvalid();
  return taken;
}

/** prototypeの連鎖をdescriptorで辿ってmethodを1回取り出し、元のobjectへ束縛する（accessor・Proxyを拒否、getterを呼ばない）。 */
function methodOf(target: unknown, name: string): (...args: unknown[]) => unknown {
  if ((typeof target !== 'object' && typeof target !== 'function') || target === null || types.isProxy(target)) configFail();
  let holder: unknown = target;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (types.isProxy(holder)) configFail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      if (!('value' in descriptor) || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) configFail();
      const found = descriptor.value as Function;
      return (...args: unknown[]) => Reflect.apply(found, target, args);
    }
    holder = Object.getPrototypeOf(holder);
  }
  return configFail();
}

/** prototypeの連鎖から、SDKのgetter（isValid・isExpired等）またはmethodの関数を1回取り出す（呼ぶ時にinstanceを渡す）。 */
function prototypeMember(prototype: unknown, name: string, kind: 'get' | 'value'): Function {
  let holder: unknown = prototype;
  for (let depth = 0; depth < 16 && holder !== null; depth += 1) {
    if (!isObject(holder)) configFail();
    const descriptor = Object.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) {
      const member: unknown = kind === 'get' ? descriptor.get : descriptor.value;
      if (typeof member !== 'function' || types.isProxy(member)) configFail();
      return member;
    }
    holder = Object.getPrototypeOf(holder);
  }
  return configFail();
}

/** own data propertyの値だけ（accessor・継承は読まずにundefined）。 */
function ownValue(target: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
}

/** 同期の例外もrejectにして、外部の関数を1回だけ呼ぶ。 */
function invoke<T>(call: () => T | PromiseLike<T>): Promise<T> {
  return new Promise<T>((resolve) => resolve(call()));
}

/** 要求operation: exact {deadlineAt, signal}、deadlineAtは安全整数のepochミリ秒（ISO表現域）、signalは必須の本物のAbortSignal。 */
function copyOperation(value: unknown): McpRequestOperation {
  const fields = dataFields(value, ['deadlineAt', 'signal'], () => contextError('invalid_input'));
  const deadlineAt = fields.get('deadlineAt');
  const signal = fields.get('signal');
  if (typeof deadlineAt !== 'number' || !Number.isSafeInteger(deadlineAt) || deadlineAt < 0 || deadlineAt > MAX_ISO_TIME_MS) {
    throw contextError('invalid_input');
  }
  if (!isObject(signal) || !(signal instanceof AbortSignal)) throw contextError('invalid_input');
  return Object.freeze({ deadlineAt, signal });
}

/** 中止・閉鎖・終了の分類（時計を読まない）。閉鎖→slotの終了→元の中止→外側slot→自分の期限timerの順。 */
function stopReason(state: ContextState, slot: Slot): RequestAuthContextErrorCode | null {
  if (state.closed) return 'closed';
  if (slot.ended) return 'no_context';
  if (slot.parent.aborted) return 'aborted';
  if (slot.outer !== undefined) {
    const outer = stopReason(state, slot.outer);
    if (outer !== null) return outer;
  }
  if (slot.controller.signal.aborted) return 'timed_out';
  return null;
}

/**
 * まだ進めてよいかを、signal→時計→signalの順に見て、その時刻を返す。観測の前後の閉鎖・中止・外側・slot終了を優先し、不正な時刻の観測は
 * 期限の根拠にせず固定unavailable。正しい時刻での期限の到達だけを、子をabortしてtimed_outにする。
 */
function live(state: ContextState, slot: Slot): number {
  const before = stopReason(state, slot);
  if (before !== null) throw contextError(before);
  const at = state.now();
  const after = stopReason(state, slot);
  if (after !== null) throw contextError(after);
  if (at === null) throw contextError('unavailable');
  if (!(at < slot.deadlineAt)) {
    slot.controller.abort();
    throw contextError('timed_out');
  }
  return at;
}

/** 実行中のasync contextのslot（同じcontextのものだけ）を最新の状態で検査する。 */
function currentSlot(state: ContextState): Slot {
  const slot = state.storage.getStore();
  if (slot === undefined) throw contextError('no_context');
  live(state, slot);
  return slot;
}

/** 印: 待機をslotの中止・期限・閉鎖で打ち切った。外へは出さない。 */
const STOPPED: unique symbol = Symbol('request auth slot stopped');

/**
 * 1つのawaitをslotの中止・期限・閉鎖までで打ち切る。listenerを作る前にsignal→時計→signalを検査し、打切りの後に来た成功・失敗は採用せず、
 * rejectは握りつぶす。成功は呼出し側が直後に再検査する。
 */
function waitFor<T>(state: ContextState, slot: Slot, promise: Promise<T>): Promise<T> {
  promise.catch(() => {});
  try {
    live(state, slot);
  } catch (error) {
    return Promise.reject(error);
  }
  const signal = slot.controller.signal;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(STOPPED);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

/**
 * 新しいslotを作る（最初のawaitの前）。閉鎖・operation・work・外側slot・元の中止・時計・期限の順に検査し、時計の観測の後にも閉鎖・中止・外側を
 * 再確認してから、子controller・親/外側/lifetimeのlistener・期限timerを作る（同期の再入abort・dispose後の資源作成0）。
 */
function openSlot(state: ContextState, operationInput: unknown): Slot {
  if (state.closed) throw contextError('closed');
  const operation = copyOperation(operationInput);
  const outer = state.storage.getStore();
  const recheck = (): void => {
    if (state.closed) throw contextError('closed');
    if (outer !== undefined) {
      const reason = stopReason(state, outer);
      if (reason !== null) throw contextError(reason);
    }
    if (operation.signal.aborted) throw contextError('aborted');
  };
  recheck();
  const start = state.now();
  recheck();
  // 時計は有限の安全整数のepochミリ秒（ISOの表現域内）。throw・不正な値は固定unavailable（liveと同じ検証）。
  if (start === null) throw contextError('unavailable');
  let deadlineAt = Math.min(operation.deadlineAt, start + REQUEST_AUTH_BUDGET_MS);
  if (outer !== undefined) deadlineAt = Math.min(deadlineAt, outer.deadlineAt);
  if (!(start < deadlineAt)) throw contextError('timed_out');

  const controller = new AbortController();
  const abortChild = (): void => controller.abort();
  const outerSignal = outer?.controller.signal;
  operation.signal.addEventListener('abort', abortChild, { once: true });
  outerSignal?.addEventListener('abort', abortChild, { once: true });
  state.lifetime.signal.addEventListener('abort', abortChild, { once: true });
  const timer = setTimeout(abortChild, Math.max(1, deadlineAt - start));
  const slot: Slot = {
    operation: Object.freeze({ deadlineAt, signal: controller.signal }),
    deadlineAt,
    parent: operation.signal,
    outer,
    controller,
    ended: false,
    release() {
      if (slot.ended) return;
      // 先に失効させてから子をabortし、owned timer・親/外側/lifetimeのlistener・登録を解除する。
      slot.ended = true;
      controller.abort();
      clearTimeout(timer);
      operation.signal.removeEventListener('abort', abortChild);
      outerSignal?.removeEventListener('abort', abortChild);
      state.lifetime.signal.removeEventListener('abort', abortChild);
      state.active.delete(slot);
    },
  };
  state.active.add(slot);
  return slot;
}

/** 非成功の正規化。slotの中止・期限・閉鎖・終了を優先し、それ以外（workの任意の例外）は元の情報を捨てて固定unavailable。 */
function normalize(state: ContextState, slot: Slot): RequestAuthContextError {
  try {
    live(state, slot);
  } catch (stop) {
    if (stop instanceof RequestAuthContextError) return contextError(stop.code);
  }
  return contextError('unavailable');
}

/** slotを開き、その中でworkを1回呼び、slotの期限・中止までで待つ。返す直前にも再検査する。finallyでslotを閉じる。 */
async function runScoped<T>(state: ContextState, slot: Slot, work: (slot: Slot) => T | PromiseLike<T>): Promise<T> {
  try {
    let pending: Promise<T>;
    try {
      pending = state.storage.run(slot, () => invoke(() => work(slot)));
    } catch {
      pending = Promise.reject(contextError('unavailable'));
    }
    let value: T;
    try {
      value = await waitFor(state, slot, pending);
    } catch {
      throw normalize(state, slot);
    }
    live(state, slot);
    return value;
  } catch (error) {
    throw error instanceof RequestAuthContextError ? error : contextError('unavailable');
  } finally {
    slot.release();
  }
}

function startRun<T>(state: ContextState, operationInput: unknown, work: (slot: Slot) => T | PromiseLike<T>): Promise<T> {
  let slot: Slot;
  try {
    slot = openSlot(state, operationInput);
  } catch (error) {
    return Promise.reject(error instanceof RequestAuthContextError ? error : contextError('unavailable'));
  }
  return runScoped(state, slot, work);
}

/**
 * 要求contextを組み立てる（同期・I/Oなし）。optionsはexact {clock}。戻り値は凍結した{run, current, dispose}で、
 * createRequestScopedOAuthOwnerResolverはこの同じinstanceだけを受け付ける。
 */
export function createRequestAuthContext(options: RequestAuthContextOptions): RequestAuthContext {
  const fields = dataFields(options, ['clock'], () => new RequestAuthConfigError());
  const clockNow = methodOf(fields.get('clock'), 'now');
  /** 全ての時計の観測（slotの開始・要求中のlive/current・返却直前）で使う同じ検証。元の例外・値を外へ出さない。 */
  const now = (): number | null => {
    let value: unknown;
    try {
      value = clockNow();
    } catch {
      return null;
    }
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_ISO_TIME_MS ? value : null;
  };
  const state: ContextState = {
    storage: new AsyncLocalStorage<Slot>(),
    now,
    lifetime: new AbortController(),
    active: new Set(),
    closed: false,
  };

  function run<T>(operation: McpRequestOperation, work: () => T | PromiseLike<T>): Promise<T> {
    const workInput: unknown = work;
    if (state.closed) return Promise.reject(contextError('closed'));
    if (typeof workInput !== 'function' || types.isProxy(workInput)) return Promise.reject(contextError('invalid_input'));
    const target = workInput as Function;
    return startRun(state, operation, () => Reflect.apply(target, undefined, []) as T | PromiseLike<T>);
  }

  function current(): McpRequestOperation {
    return currentSlot(state).operation;
  }

  function dispose(): void {
    if (state.closed) return;
    // 先に閉鎖してから進行中の全slotを中止する（以後のrun・currentは固定closed）。借用の時計は閉じない。
    state.closed = true;
    state.lifetime.abort();
  }

  const context: RequestAuthContext = Object.freeze({ run, current, dispose });
  CONTEXTS.set(context, state);
  return context;
}

/** 検証済みのaccess tokenから捕捉した値。 */
interface TokenView {
  readonly ownerId: string;
  readonly grantId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly exp: number;
}

/** 鍵束縛（sender-constrained）を表すAccessTokenの項目。存在だけで通常Bearerとして扱わない。 */
const SENDER_CONSTRAINT_KEYS: readonly string[] = ['jkt', 'x5t#S256'];

/** 印: SDKの戻り値が想定外（資格情報の不成立ではなく内部の不整合）。固定unavailableにする。 */
const INTERNAL: unique symbol = Symbol('request auth internal');

/**
 * 実ASの不透明access tokenをownerへ解決するRequestScopedOwnerResolverを組み立てる（同期・I/Oなし）。optionsはexact
 * {provider, connect, context, resource}。providerは本物のProvider instanceで、公開getterのAccessToken/Grantを1回だけ取得し、findを
 * 元のmodel classへ束縛する。不正はRequestAuthConfigError。
 */
export function createRequestScopedOAuthOwnerResolver(options: RequestScopedOAuthOwnerResolverOptions): RequestScopedOwnerResolver {
  const fields = dataFields(options, ['provider', 'connect', 'context', 'resource'], () => new RequestAuthConfigError());

  const provider = fields.get('provider');
  if (!isObject(provider) || !(provider instanceof Provider)) configFail();
  /** Provider.prototypeの公開getter（AccessToken・Grant）を本物のinstanceで1回だけ呼ぶ。偽のinstanceはSDKのprivate fieldで失敗する。 */
  const modelOf = (name: 'AccessToken' | 'Grant'): Function => {
    const getter = prototypeMember(Provider.prototype, name, 'get');
    let model: unknown;
    try {
      model = Reflect.apply(getter, provider, []);
    } catch {
      return configFail();
    }
    if (typeof model !== 'function' || types.isProxy(model)) configFail();
    return model;
  };
  const accessTokenModel = modelOf('AccessToken');
  const grantModel = modelOf('Grant');
  const findToken = methodOf(accessTokenModel, 'find');
  const findGrant = methodOf(grantModel, 'find');
  const tokenPrototype = ownValue(accessTokenModel, 'prototype');
  const grantPrototype = ownValue(grantModel, 'prototype');
  const tokenIsValid = prototypeMember(tokenPrototype, 'isValid', 'get');
  const grantIsExpired = prototypeMember(grantPrototype, 'isExpired', 'get');
  const grantResourceScope = prototypeMember(grantPrototype, 'getResourceScope', 'value');

  const connectTarget = fields.get('connect');
  if (!isObject(connectTarget) || !(connectTarget instanceof ConnectStorage)) configFail();
  const isOwnerActive = methodOf(connectTarget, 'isOwnerActive');

  const contextTarget = fields.get('context');
  const found = isObject(contextTarget) ? CONTEXTS.get(contextTarget) : undefined;
  if (found === undefined) return configFail();
  const state: ContextState = found;

  const resource = fields.get('resource');
  if (typeof resource !== 'string' || resource === '' || !URL.canParse(resource)) configFail();

  /** expは正の安全整数のepoch秒で、最新の時刻（ミリ秒）より後。 */
  const after = (exp: unknown, at: number): exp is number => typeof exp === 'number' && Number.isSafeInteger(exp) && exp > 0 && exp * 1000 > at;

  /** AccessToken.findの結果を検証して捕捉する。資格情報の不成立はnull、SDKの想定外の値はINTERNAL。 */
  function viewToken(token: unknown, at: number): TokenView | null {
    if (token === undefined || token === null) return null;
    if (!isObject(token) || Object.getPrototypeOf(token) !== tokenPrototype) throw INTERNAL;
    // このresolverは通常Bearer専用。DPoP（jkt）・mTLS（x5t#S256）の鍵束縛がown propertyとして存在すれば、値（空・null・
    // 不正を含む）を読まずにnull。proofを検証できないので、鍵束縛tokenをBearerへ降格しない（Grant/owner読取り0）。
    if (SENDER_CONSTRAINT_KEYS.some((key) => Object.getOwnPropertyDescriptor(token, key) !== undefined)) return null;
    if (Reflect.apply(tokenIsValid, token, []) !== true) return null;
    const exp = ownValue(token, 'exp');
    const aud = ownValue(token, 'aud');
    const ownerId = ownValue(token, 'accountId');
    const grantId = ownValue(token, 'grantId');
    const clientId = ownValue(token, 'clientId');
    const scope = ownValue(token, 'scope');
    if (!after(exp, at) || aud !== resource || !isUuid(ownerId)) return null;
    if (typeof grantId !== 'string' || grantId === '' || typeof clientId !== 'string' || clientId === '') return null;
    if (typeof scope !== 'string') return null;
    const scopes = [...new Set(scope.split(' ').filter((entry) => entry !== ''))];
    if (!scopes.includes(STTD_SCOPE)) return null;
    return { ownerId, grantId, clientId, scopes, exp };
  }

  /** Grant.findの結果が、tokenと同じowner/client/Grantで、期限内・このresourceにsttd:events（拒否scopeを控除した実SDKの結果）を持つか。 */
  function grantAccepts(grant: unknown, view: TokenView, at: number): boolean {
    if (grant === undefined || grant === null) return false;
    if (!isObject(grant) || Object.getPrototypeOf(grant) !== grantPrototype) throw INTERNAL;
    if (Reflect.apply(grantIsExpired, grant, []) !== false) return false;
    const exp = ownValue(grant, 'exp');
    if (exp !== undefined && !after(exp, at)) return false;
    if (ownValue(grant, 'jti') !== view.grantId) return false;
    if (ownValue(grant, 'accountId') !== view.ownerId || ownValue(grant, 'clientId') !== view.clientId) return false;
    const scope: unknown = Reflect.apply(grantResourceScope, grant, [resource]);
    if (typeof scope !== 'string') throw INTERNAL;
    return scope.split(' ').includes(STTD_SCOPE);
  }

  const same = (a: TokenView, b: TokenView): boolean =>
    a.ownerId === b.ownerId && a.grantId === b.grantId && a.clientId === b.clientId && a.exp === b.exp && a.scopes.join(' ') === b.scopes.join(' ');

  async function resolveIn(slot: Slot, accessToken: unknown): Promise<ResolvedOAuthOwner | null> {
    // 資格情報として形が成り立たないものはI/Oの前にnull。
    if (typeof accessToken !== 'string' || accessToken === '' || accessToken.length > MAX_ACCESS_TOKEN_BYTES) return null;
    if (Buffer.byteLength(accessToken, 'utf8') > MAX_ACCESS_TOKEN_BYTES) return null;
    const check = (): number => {
      const at = live(state, slot);
      // 同じasync contextの同じslotの中であること（context.currentと同じ判定）。
      if (state.storage.getStore() !== slot) throw contextError('no_context');
      return at;
    };

    check();
    const token: unknown = await waitFor(state, slot, invoke(() => findToken(accessToken)));
    const view = viewToken(token, check());
    if (view === null) return null;

    check();
    const grant: unknown = await waitFor(state, slot, invoke(() => findGrant(view.grantId)));
    if (!grantAccepts(grant, view, check())) return null;

    check();
    const active: unknown = await waitFor(state, slot, invoke(() => isOwnerActive(view.ownerId)));
    check();
    if (typeof active !== 'boolean') throw INTERNAL;
    if (!active) return null;

    // 正常返却の直前: 最新の時刻でtoken/Grantの期限・属性・scopeと元期限を再検査する。
    const at = check();
    const again = viewToken(token, at);
    if (again === null || !same(again, view) || !grantAccepts(grant, view, at)) return null;
    check();
    return Object.freeze({
      ownerId: view.ownerId,
      grantId: view.grantId,
      clientId: view.clientId,
      scopes: Object.freeze([...view.scopes]),
      expiresAt: view.exp,
    });
  }

  const resolver: RequestScopedOwnerResolver = (accessToken, operation) =>
    startRun(state, operation, (slot) => resolveIn(slot, accessToken));
  return Object.freeze(resolver);
}
