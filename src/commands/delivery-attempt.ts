// 署名付きの単回配送（Standard Webhooks署名・安全送出の指示用入口への最大1回）。
// 送信API（delivery/kms-service.ts）が、認可・送出権を確かめて開封した1回分のeventのbytesを受け取り、同じbytesへ署名して、
// 安全な送出の指示用の入口（postCommandCallback）へ1回だけ渡し、結果を固定の分類へ落とす。
// ここは認可をしない。宛先のURLと署名secretを持つ呼び出し元を信頼し、公開の入力を直接受け取らない。保存・鍵の破棄・
// 再試行の予定・購読の停止の書込みはしない（stopSubscriptionは分類で、停止の成功ではない）。
// eventのJSONは組み立て直さない。受け取ったbytesと署名secretは最初のawaitより前に写し、写しだけを署名と送出へ渡して、返す前に
// 0で上書きする。標準の署名ライブラリ・Node・TLSの中の文字列や写しの消去までは保証しない。
// 時計の確認とdisposeは、このadapterの中の同期の確認だけで、取消と送出の開始の分散した排他ではない。

import { isUtf8 } from 'node:buffer';
import { types } from 'node:util';

import { parseEgressUrl, type CommandCallbackPost, type CommandEgressOptions } from '../egress/safe-egress.js';
import { EgressError, type CommandEgressResponse } from '../egress/transport.js';
import { signCommandBody } from '../events/signing.js';
import { MAX_SIGNED_EVENT_BYTES, type Clock } from '../policy.js';

/** 署名eventの上限（安全送出と共通の値。policy.ts）。 */
const MAX_EVENT_BYTES = MAX_SIGNED_EVENT_BYTES;
const MAX_URL_LENGTH = 2048;
const SECRET_MIN_BYTES = 24;
const SECRET_MAX_BYTES = 64;
/** 送出を始めるのに必要な、元の期限までの残り（ちょうど10秒は可）。HTTPの期限の上限でもある。 */
const MAX_SEND_MS = 10_000;
/** 9999-12-31T23:59:59.999Z。 */
const MAX_INSTANT_MS = 253_402_300_799_999;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SUBSCRIPTION_ID_PATTERN = /^sub_[0-9a-f]{64}$/;
const OPTION_NAMES = ['egress', 'clock'] as const;
const REQUEST_NAMES = ['eventBytes', 'eventId', 'subscriptionId', 'url', 'secrets', 'expiresAt', 'leaseUntil', 'signal'] as const;

export type CommandDeliveryKind = 'delivered' | 'retry' | 'failed' | 'uncertain' | 'unavailable';
export type CommandDeliveryReason =
  | 'acknowledged'
  | 'rate_limited'
  | 'server_error'
  | 'subscription_gone'
  | 'size_violation'
  | 'client_error'
  | 'invalid_destination'
  | 'network_unavailable'
  | 'transport_ambiguous'
  | 'local_error'
  | 'not_sendable';

/** sendの結果。固定の3項目だけで、本文・URL・secret・見出し・HTTPのstatus・元の例外を含めない。 */
export interface CommandDeliveryResult {
  readonly kind: CommandDeliveryKind;
  readonly reason: CommandDeliveryReason;
  /** 購読を止めるべき分類か（指示だけ。ここでは止めない）。 */
  readonly stopSubscription: boolean;
}

export type CommandDeliveryAttemptErrorCode = 'invalid_input' | 'send_error';

/** 入力の形・時計の不正と、分類できない内部の失敗。messageは分類名だけで、causeを持たない。 */
export class CommandDeliveryAttemptError extends Error {
  constructor(readonly code: CommandDeliveryAttemptErrorCode) {
    super(code);
    this.name = 'CommandDeliveryAttemptError';
  }
}

/** 安全な送出の、指示用の入口だけ。 */
export interface CommandDeliveryEgress {
  postCommandCallback(url: string, post: CommandCallbackPost, options?: CommandEgressOptions): Promise<CommandEgressResponse>;
}

export interface CommandDeliveryAttemptOptions {
  readonly egress: CommandDeliveryEgress;
  readonly clock: Clock;
}

export interface CommandDeliveryRequest {
  /** 送るeventのUTF-8（1〜MAX_SIGNED_EVENT_BYTES=25088バイト）。借りるだけで、書き換えない。 */
  readonly eventBytes: Buffer;
  readonly eventId: string;
  readonly subscriptionId: string;
  readonly url: string;
  /** 署名secretの生のbytes（各24〜64バイト）。新旧で1〜2個。借りるだけで、書き換えない。 */
  readonly secrets: readonly Buffer[];
  /** 指示の元の期限（epochミリ秒）。 */
  readonly expiresAt: number;
  /** 配送のleaseの期限（epochミリ秒。expiresAt以下）。 */
  readonly leaseUntil: number;
  readonly signal: AbortSignal | null;
}

export interface CommandDeliveryAttempt {
  send(request: CommandDeliveryRequest): Promise<CommandDeliveryResult>;
  /** 進行中の送出を中断し、以後のsendを送らずに返す。何度呼んでも同じ。借りたegressは閉じない。 */
  dispose(): void;
}

const invalidInput = () => new CommandDeliveryAttemptError('invalid_input');
const sendError = () => new CommandDeliveryAttemptError('send_error');

const outcome = (kind: CommandDeliveryKind, reason: CommandDeliveryReason, stopSubscription = false): CommandDeliveryResult =>
  Object.freeze({ kind, reason, stopSubscription });

/**
 * Object.prototypeかnull prototypeの、namesちょうどのown data propertyだけのobjectなら、値を1回だけ読んだ写しを返す。
 * Proxyは、項目を読む前に拒否する。symbol・余分な項目・accessorも拒否し、getterは呼ばない。合わなければundefined。
 */
function plain<Name extends string>(value: unknown, names: readonly Name[]): Record<Name, unknown> | undefined {
  if (typeof value !== 'object' || value === null || types.isProxy(value)) return undefined;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  if (Reflect.ownKeys(value).length !== names.length) return undefined;
  const copy = Object.create(null) as Record<Name, unknown>;
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) return undefined;
    copy[name] = descriptor.value;
  }
  return copy;
}

/** 1970〜9999年のepochミリ秒（非負の安全な整数。-0は拒否）。 */
const isInstant = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_INSTANT_MS && !Object.is(value, -0);

/** 普通のBuffer（Proxy・派生class・lengthを差し替えたものは拒否）で、長さが範囲内。 */
function isBytes(value: unknown, min: number, max: number): value is Buffer {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || !Buffer.isBuffer(value)) return false;
  if (Object.getPrototypeOf(value) !== Buffer.prototype || Object.getOwnPropertyDescriptor(value, 'length') !== undefined) return false;
  return value.length >= min && value.length <= max;
}

/** 普通の配列（Proxy・派生class・穴・accessor・余分な項目は拒否）の、1〜2個のsecret。合わなければundefined。 */
function secretList(value: unknown): Buffer[] | undefined {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || !Array.isArray(value)) return undefined;
  if (Object.getPrototypeOf(value) !== Array.prototype) return undefined;
  const count = (Object.getOwnPropertyDescriptor(value, 'length')?.value ?? 0) as number;
  if (count < 1 || count > 2 || Reflect.ownKeys(value).length !== count + 1) return undefined;
  const secrets: Buffer[] = [];
  for (let index = 0; index < count; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) return undefined;
    const secret: unknown = descriptor.value;
    if (!isBytes(secret, SECRET_MIN_BYTES, SECRET_MAX_BYTES)) return undefined;
    secrets.push(secret);
  }
  return secrets;
}

/** 応答のstatusの分類。2xxは要求の受領で、Dotsの処理の完了ではない。 */
function classifyStatus(status: unknown): CommandDeliveryResult {
  if (typeof status !== 'number' || !Number.isInteger(status)) return outcome('uncertain', 'transport_ambiguous');
  if (status >= 200 && status <= 299) return outcome('delivered', 'acknowledged');
  if (status >= 300 && status <= 399) return outcome('failed', 'invalid_destination', true);
  if (status === 410) return outcome('failed', 'subscription_gone', true);
  if (status === 413) return outcome('failed', 'size_violation');
  if (status === 429) return outcome('retry', 'rate_limited');
  if (status >= 400 && status <= 499) return outcome('failed', 'client_error');
  if (status >= 500 && status <= 599) return outcome('retry', 'server_error');
  return outcome('uncertain', 'transport_ambiguous');
}

/** 送出の失敗の分類。分類の分からない失敗は、結果の不明にする。 */
function classifyFailure(error: unknown): CommandDeliveryResult {
  const kind = typeof error === 'object' && error !== null && !types.isProxy(error) && error instanceof EgressError ? error.kind : undefined;
  switch (kind) {
    case 'redirect':
    case 'invalid_url':
    case 'destination_forbidden':
      return outcome('failed', 'invalid_destination', true);
    // この送出は、TLSの成立より前に本文を流さない。
    case 'dns_failed':
    case 'connect_failed':
    case 'tls_failed':
      return outcome('retry', 'network_unavailable');
    case 'invalid_request':
      return outcome('failed', 'local_error');
    default:
      return outcome('uncertain', 'transport_ambiguous');
  }
}

export function createCommandDeliveryAttempt(options: CommandDeliveryAttemptOptions): CommandDeliveryAttempt {
  const given = plain(options, OPTION_NAMES);
  if (given === undefined) throw invalidInput();
  const { egress } = given;
  const clock = plain(given.clock, ['now']);
  if (clock === undefined || typeof clock.now !== 'function' || types.isProxy(clock.now)) throw invalidInput();
  if (typeof egress !== 'object' || egress === null || types.isProxy(egress)) throw invalidInput();
  const postDescriptor = Object.getOwnPropertyDescriptor(egress, 'postCommandCallback');
  if (postDescriptor === undefined || typeof postDescriptor.value !== 'function' || types.isProxy(postDescriptor.value)) throw invalidInput();
  // 送出の入口と時計は、ここで1回だけ読む。
  const post = postDescriptor.value as (...args: unknown[]) => unknown;
  const now = clock.now as () => unknown;

  let disposed = false;
  /** これまでに読んだ時刻の最大。時計が巻き戻っても、期限の判定を延ばさない。 */
  let latest = 0;
  const active = new Set<AbortController>();

  /** いまの時刻（これまでの最大）。時計の値が不正・例外なら、固定のエラー。 */
  const readNow = (): number => {
    let value: unknown;
    try {
      value = now();
    } catch {
      throw invalidInput();
    }
    if (!isInstant(value)) throw invalidInput();
    if (value > latest) latest = value;
    return latest;
  };

  async function send(request: CommandDeliveryRequest): Promise<CommandDeliveryResult> {
    const input = plain(request, REQUEST_NAMES);
    if (input === undefined) throw invalidInput();
    const { eventBytes, eventId, subscriptionId, url, expiresAt, leaseUntil, signal } = input;
    if (!isBytes(eventBytes, 1, MAX_EVENT_BYTES) || !isUtf8(eventBytes)) throw invalidInput();
    if (typeof eventId !== 'string' || !UUID_PATTERN.test(eventId)) throw invalidInput();
    if (typeof subscriptionId !== 'string' || !SUBSCRIPTION_ID_PATTERN.test(subscriptionId)) throw invalidInput();
    if (typeof url !== 'string' || url.length < 1 || url.length > MAX_URL_LENGTH) throw invalidInput();
    const secrets = secretList(input.secrets);
    if (secrets === undefined) throw invalidInput();
    if (!isInstant(expiresAt) || !isInstant(leaseUntil) || leaseUntil > expiresAt) throw invalidInput();
    if (signal !== null && (typeof signal !== 'object' || types.isProxy(signal) || !(signal instanceof AbortSignal))) throw invalidInput();

    // 宛先として受け付けないURLは、何も送らずに固定の失敗にする。
    try {
      parseEgressUrl(url);
    } catch {
      return outcome('failed', 'invalid_destination', true);
    }

    const owned: Buffer[] = [];
    const copyOf = (bytes: Buffer): Buffer => {
      const copy = Buffer.allocUnsafeSlow(bytes.length);
      owned.push(copy);
      Buffer.prototype.copy.call(bytes, copy);
      return copy;
    };
    const controller = new AbortController();
    const onCallerAbort = () => controller.abort();
    try {
      const startedAt = readNow();
      // 最初の確認。lease・元の期限までの残り（10秒以上）・中断・dispose。満たさなければ、何も送らない。
      if (disposed || signal?.aborted === true || !(startedAt < leaseUntil) || expiresAt - startedAt < MAX_SEND_MS) {
        return outcome('unavailable', 'not_sendable');
      }
      const timeoutMs = Math.min(MAX_SEND_MS, expiresAt - startedAt, leaseUntil - startedAt);

      // ここまでawaitは無い。以後、呼び出し元のBufferは読まない。
      const body = copyOf(eventBytes);
      const keys = secrets.map(copyOf);

      /** 接続の前後の確認。いまの時刻が両方の期限より前で、dispose・中断がされていないこと。 */
      const sendable = (): boolean => {
        if (disposed || controller.signal.aborted) return false;
        let current: number;
        try {
          current = readNow();
        } catch {
          return false;
        }
        return current < leaseUntil && current < expiresAt;
      };

      let pending: unknown;
      try {
        const signed = signCommandBody(eventId, body, new Date(startedAt), keys);
        active.add(controller);
        signal?.addEventListener('abort', onCallerAbort, { once: true });
        // 署名からここまでawaitは無い。
        pending = Reflect.apply(post, egress, [
          url,
          {
            headers: {
              'content-type': 'application/json',
              'webhook-id': signed['webhook-id'],
              'webhook-timestamp': signed['webhook-timestamp'],
              'webhook-signature': signed['webhook-signature'],
              'x-mcp-subscription-id': subscriptionId,
            },
            body,
          },
          { signal: controller.signal, timeoutMs, beforeConnect: sendable },
        ]);
      } catch {
        throw sendError();
      }

      let response: unknown;
      try {
        // 送出は、実際の要求が閉じてから返る。
        response = await pending;
      } catch (error) {
        return classifyFailure(error);
      }
      const status: unknown =
        typeof response === 'object' && response !== null && !types.isProxy(response) ? (response as { status?: unknown }).status : undefined;
      const result = classifyStatus(status);
      // 期限・dispose・中断の後に届いた受領は、成功にしない。
      if (result.kind === 'delivered' && !sendable()) return outcome('uncertain', 'transport_ambiguous');
      return result;
    } catch (error) {
      // 固定のエラーだけを外へ出す。元の例外は運ばない。
      throw error instanceof CommandDeliveryAttemptError ? new CommandDeliveryAttemptError(error.code) : sendError();
    } finally {
      signal?.removeEventListener('abort', onCallerAbort);
      active.delete(controller);
      for (const buffer of owned) buffer.fill(0);
    }
  }

  function dispose(): void {
    disposed = true;
    for (const controller of active) controller.abort();
  }

  return Object.freeze({ send, dispose });
}
