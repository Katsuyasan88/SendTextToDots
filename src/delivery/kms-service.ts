// KMS購読profileの要求内単回配送・照会・中止（HTTPに依存しない部分）。入力検証（commands/input.ts）・event組立て（event.ts）・
// digest/eventIdの用途・単回送出（commands/delivery-attempt.ts）を使う。
// 1回のPOST: 入力の全検証 → 準備のtransaction（本文なし、旧secretのsealed/hashはRAMだけ） → transactionの外でKMS codecによる
// URL・現行secret・あれば旧secretの非同期開封（AADは固定destinationと認可済みownerから再生成） → 残り10秒・中止の確認 → 送出権の
// transaction（最新の認可・宛先・旧hash・猶予・先着中止を再照合） → 送出直前の確認 → 既存の単回送出を最大1回 → 結果のtransaction。
// 全体の期限は受信+min(予算,20秒)とCommandの処理期限・有効期限の短い方で、await後に取り直さない。本文・event bytes・secretはこの要求の
// RAMだけで、終わったBufferは0で上書きする（JSの文字列・SDK・OSの写しの消去は保証しない）。送出権の確定が不明なら送らない。
// post（第5引数）・get/cancel（第4引数）は任意のparentOperation（HTTP要求の元期限と中断）を受け取れる。与えられた
// 時だけ、exact own dataのdeadlineAt/signal（実AbortSignal必須）を検査し、期限をmin(受信+予算, parent.deadlineAt)に固定して延長せず、
// 要求固有のcontrollerをruntime lifetimeとparent.signalの両方へ結ぶ。開始済みの中止・期限切れはprepare/read/cancel・試行IDの生成の前に
// 拒否する。不正・中止・期限は503 temporarily_unavailable（入力の例外を外へ投げない）。
// 結果なし（abandon/finish）の保存はlifetimeで行う（HTTP切断後に新しい配送を始める権限にはしない）。

import { createHmac } from 'node:crypto';

import { CommandDeliveryAttemptError, type CommandDeliveryRequest, type CommandDeliveryResult } from '../commands/delivery-attempt.js';
import { resolveNewCommandExpiry, validateCommandInput, type CommandInputFields, type ValidatedCommandInput } from '../commands/input.js';
import { CommandApiError } from '../commands/errors.js';
import { SECRET_PREFIX } from '../events/contract.js';
import { isValidSecret } from '../events/signing.js';
import type { Clock } from '../policy.js';
import type { KmsSealingBinding, KmsSealingCodec } from '../protection/kms-sealing.js';
import {
  cancelView,
  MIN_SEND_REMAINING_MS,
  outcomeOf,
  projectState,
  type CancelDecision,
  type CommandDoc,
  type DeliveryReason,
  type DispatchDecision,
  type PublicState,
} from './contract.js';
import { captureOperation, KmsDeliveryOperationError, liveNow, type FinalState, type KmsPrepareDecision, type KmsRequestDeliveryStore, type TransactionOp } from './kms-store.js';
import { buildEventBytes, errorResponse, eventIdFor, type DeliveryResponse } from './event.js';

const DIGEST_PURPOSE = 't257:command-digest';
/** 1回の開封の上限（codecの1callの上限と同じ）。 */
const OPEN_CALL_MS = 5000;
const MAX_URL_LENGTH = 2048;

/** 試験だけが渡す待ち合わせ・観測（製品の組立ては渡さない）。 */
export interface KmsDeliveryTestHooks {
  /** 準備の確定の後・開封の前。 */
  readonly afterPrepare?: (() => Promise<void>) | undefined;
  /** 開封の後・送出権の前。 */
  readonly afterOpen?: (() => Promise<void>) | undefined;
  /** 送出の結果の後・結果のtransactionの前。例外は結果の保存の失敗として扱う。 */
  readonly beforeFinish?: (() => Promise<void>) | undefined;
  /** transactionの関数の実行（同期・観測だけ）。 */
  readonly onTransaction?: ((op: TransactionOp) => void) | undefined;
  /** codecから所有移転を受けた開封Buffer・この要求が作った署名鍵/event bytesの観測（後の0上書きの確認用）。 */
  readonly onOwned?: ((buffer: Buffer) => void) | undefined;
  /** factoryが作ったdigest鍵の写しの観測（dispose後の0上書きの確認用）。 */
  readonly onDigestKeyCopy?: ((buffer: Buffer) => void) | undefined;
}

export interface KmsRequestDeliveryServiceDeps {
  readonly store: KmsRequestDeliveryStore;
  readonly codec: KmsSealingCodec;
  readonly hash: (purpose: string, value: string) => string;
  /** factoryが作った写し（disposeで0上書き）。 */
  readonly digestKey: Buffer;
  readonly send: (request: CommandDeliveryRequest) => Promise<CommandDeliveryResult>;
  readonly clock: Clock;
  readonly newAttemptId: () => string;
  readonly log: (entry: Record<string, unknown>) => void;
  readonly budgetMs: number;
  /** runtimeのdisposeで中止される。以後のpost/get/cancelは固定の非成功で、新しいSDK・KMS・送出を始めない。 */
  readonly lifetime: AbortSignal;
  readonly hooks: KmsDeliveryTestHooks;
}

const iso = (ms: number) => new Date(ms).toISOString();
const unavailable = () => errorResponse(503, 'temporarily_unavailable', true);

/** 呼出し元（HTTP要求）の元期限と中断。clockと同じepoch msの安全な整数と、実AbortSignal。 */
export interface KmsDeliveryParentOperation {
  readonly deadlineAt: number;
  readonly signal: AbortSignal;
}

type Parent = Readonly<{ deadlineAt: number; signal: AbortSignal }>;

/** 省略はnull。与えられた時はexact own dataのdeadlineAt/signal（実AbortSignal必須）だけ。不正は'invalid'（例外を投げない）。 */
function parentOf(value: unknown): Parent | null | 'invalid' {
  if (value === undefined) return null;
  try {
    const captured = captureOperation(value);
    if (captured.signal === undefined) return 'invalid';
    return Object.freeze({ deadlineAt: captured.deadlineAt, signal: captured.signal });
  } catch {
    return 'invalid';
  }
}

function statusBody(commandId: string, doc: CommandDoc | undefined, state: PublicState, acknowledgedAt?: number): Record<string, string> {
  const body: Record<string, string> = { commandId, state };
  if (doc !== undefined && !doc.tombstone) body.expiresAt = iso(doc.expiresAt);
  const ack = acknowledgedAt ?? (state === 'delivered' ? (doc?.acknowledgedAt ?? undefined) : undefined);
  if (state === 'delivered' && ack !== undefined) body.acknowledgedAt = iso(ack);
  return body;
}

/** 孤立したsurrogateを含まない文字列か。 */
function wellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** 開封したBufferをfatalなUTF-8で文字列にする。不正なUTF-8は例外。 */
function textOf(bytes: Buffer): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

export class KmsRequestDeliveryService {
  readonly #d: KmsRequestDeliveryServiceDeps;
  /** このprocessで開封・送出中のcommandの中断（同じprocessの中止・disposeだけが使う。別process間の強制終了はしない）。 */
  readonly #inflight = new Map<string, AbortController>();

  constructor(deps: KmsRequestDeliveryServiceDeps) {
    this.#d = deps;
  }

  #log(entry: Record<string, unknown>): void {
    try {
      this.#d.log(entry);
    } catch {
      // ログの失敗で処理を変えない。
    }
  }

  #observe(buffer: Buffer): void {
    try {
      this.#d.hooks.onOwned?.(buffer);
    } catch {
      // 観測の失敗で処理を変えない。
    }
  }

  /**
   * 受信からの元の期限（await後に取り直さない）。受信時刻が不正なら期限なし（何も始めない）。parentがあればその期限との短い方
   * （延長しない）。
   */
  #until(receivedAt: number, parent: Parent | null = null): number | undefined {
    const own = Math.floor(receivedAt) + this.#d.budgetMs;
    if (!Number.isSafeInteger(own)) return undefined;
    return parent === null ? own : Math.min(own, parent.deadlineAt);
  }

  /** parentがある時だけ、開始済みの中止・期限切れか（signal→時計→signal）。省略時は検査しない（false）。 */
  #parentStopped(parent: Parent | null, until: number): boolean {
    if (parent === null) return false;
    try {
      liveNow(this.#d.clock, { deadlineAt: until, signal: parent.signal });
      return false;
    } catch {
      return true;
    }
  }

  /** この要求専用のcontroller。runtimeのdisposeでも中止される。parentがあれば、そのsignalの中止でも中止される。 */
  #controller(parent: Parent | null = null): { readonly controller: AbortController; readonly release: () => void } {
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    this.#d.lifetime.addEventListener('abort', onAbort, { once: true });
    parent?.signal.addEventListener('abort', onAbort, { once: true });
    if (this.#d.lifetime.aborted || parent?.signal.aborted === true) controller.abort();
    return {
      controller,
      release: () => {
        this.#d.lifetime.removeEventListener('abort', onAbort);
        parent?.signal.removeEventListener('abort', onAbort);
      },
    };
  }

  /** 送出を始めてよいか: 中止・disposeがなく、min(元期限, 処理期限, 有効期限)までの最新の残りが10秒以上（ちょうどは可）。 */
  #sendable(limit: number, signal: AbortSignal): boolean {
    if (this.#d.lifetime.aborted) return false;
    try {
      const now = liveNow(this.#d.clock, { deadlineAt: limit, signal });
      return limit - now >= MIN_SEND_REMAINING_MS && !signal.aborted;
    } catch {
      return false;
    }
  }

  async post(
    ownerId: string,
    idempotencyKey: string,
    rawBody: Buffer,
    receivedAt: number,
    parentOperation?: KmsDeliveryParentOperation,
  ): Promise<DeliveryResponse> {
    if (this.#d.lifetime.aborted) return unavailable();
    const { store, clock } = this.#d;
    const parent = parentOf(parentOperation);
    if (parent === 'invalid') return unavailable();
    const until = this.#until(receivedAt, parent);
    if (until === undefined) return unavailable();
    // 開始済みの中止・期限切れは、入力の処理・準備・試行IDの生成の前に止める。
    if (this.#parentStopped(parent, until)) return unavailable();
    let input: ValidatedCommandInput;
    try {
      input = validateCommandInput(idempotencyKey, rawBody);
    } catch {
      return errorResponse(400, 'invalid_request');
    }
    const digest = createHmac('sha256', this.#d.digestKey).update(DIGEST_PURPOSE).update('\0').update(input.canonicalBytes).digest('hex');
    input.canonicalBytes.fill(0);
    const { commandId, fields } = input;
    let expiresAt: number | 'clock_skew' | 'command_expired';
    try {
      expiresAt = resolveNewCommandExpiry(input, receivedAt, clock.now());
    } catch (error) {
      if (!(error instanceof CommandApiError) || (error.code !== 'clock_skew' && error.code !== 'command_expired')) {
        return errorResponse(400, 'invalid_request');
      }
      expiresAt = error.code;
    }
    if (this.#d.lifetime.aborted) return unavailable();
    const { controller, release } = this.#controller(parent);
    try {
      // 結んだ後（入力の処理の間に来た中止・期限を含む）も、準備・試行IDの生成の前に見る。
      if (controller.signal.aborted || this.#parentStopped(parent, until)) return unavailable();
      const commandKey = store.commandKey(ownerId, commandId);
      const attemptId = this.#d.newAttemptId();
      let decision: KmsPrepareDecision | undefined;
      try {
        decision = await store.prepare(
          { ownerId, commandKey, digest, attemptId, receivedAt, expiresAt },
          { deadlineAt: until, signal: controller.signal },
        );
      } catch {
        decision = undefined;
      }
      if (decision === undefined) {
        // 準備の確定は不明。送出権を得ていないので何も送らない（同じIDの照会で状態を読む）。
        this.#log({ event: 'delivery.prepare', outcome: 'unavailable' });
        return unavailable();
      }
      this.#log({ event: 'delivery.prepare', outcome: decision.kind });
      switch (decision.kind) {
        case 'existing': {
          const state = projectState(decision.doc, clock.now());
          return { status: state === 'in_flight' ? 202 : 200, body: statusBody(commandId, decision.doc, state) };
        }
        case 'conflict':
          return errorResponse(409, 'idempotency_conflict');
        case 'denied':
          // 利用許可の拒否は接続の失効と区別する固定403（retryable false）。
          if (decision.denial === 'access_denied') return errorResponse(403, 'access_denied');
          return decision.denial === 'connection_revoked' ? errorResponse(403, 'connection_revoked') : errorResponse(409, decision.denial);
        case 'rate_limited':
          return errorResponse(429, 'rate_limited', true, { 'Retry-After': String(decision.retryAfterSec) });
        case 'timing':
          return errorResponse(422, decision.code);
        case 'prepared':
          break;
      }
      return await this.#deliver(ownerId, commandId, commandKey, attemptId, fields, decision, until, controller);
    } finally {
      release();
    }
  }

  /**
   * 元期限と開始+5000msの短い方・この要求のsignalで1つのcapsuleを開き、所有移転されたBufferを返す。codecが公開した後、
   * このawaitの継続までに来た期限・中止も、codecへ渡した同じ捕捉operation（時計を取り直さず5秒を延長しない）で公開前に見る。
   */
  async #open(binding: KmsSealingBinding, capsule: string, limit: number, signal: AbortSignal, owned: Buffer[]): Promise<Buffer> {
    const startedAt = liveNow(this.#d.clock, { deadlineAt: limit, signal });
    const operation = Object.freeze({ deadlineAt: Math.min(limit, Math.floor(startedAt) + OPEN_CALL_MS), signal });
    const bytes = await this.#d.codec.open(binding, capsule, operation);
    owned.push(bytes);
    this.#observe(bytes);
    // 遅い結果は使わず、所有移転を受けたBufferは呼出し元のfinallyで0にする。
    liveNow(this.#d.clock, operation);
    return bytes;
  }

  async #deliver(
    ownerId: string,
    commandId: string,
    commandKey: string,
    attemptId: string,
    fields: CommandInputFields,
    prepared: Extract<KmsPrepareDecision, { readonly kind: 'prepared' }>,
    until: number,
    controller: AbortController,
  ): Promise<DeliveryResponse> {
    const { store, clock, hooks, lifetime } = this.#d;
    const doc = prepared.doc;
    const destination = doc.destination!;
    const limit = Math.min(until, doc.deadlineAt, doc.expiresAt);
    const signal = controller.signal;
    const respond = (state: PublicState, final?: CommandDoc, acknowledgedAt?: number): DeliveryResponse => ({
      status: 200,
      body: statusBody(commandId, final ?? doc, state, acknowledgedAt),
    });
    /** 送っていないことが確かな時の終わり方。dispose後は新しいSDKを始めない。保存できなくても応答は未送信の失敗。 */
    const abandon = async (reason: DeliveryReason): Promise<DeliveryResponse> => {
      if (!lifetime.aborted) {
        try {
          const saved = await store.abandon(ownerId, commandKey, attemptId, reason, { deadlineAt: limit, signal: lifetime });
          if (saved !== undefined && saved.attemptId === attemptId && saved.state === 'cancelled') return respond('cancelled', saved);
        } catch {
          this.#log({ event: 'delivery.record_failed', step: 'abandon' });
        }
      }
      this.#log({ event: 'delivery.not_sent', reason });
      return respond('failed');
    };

    this.#inflight.set(commandKey, controller);
    const owned: Buffer[] = [];
    try {
      if (hooks.afterPrepare) await hooks.afterPrepare();

      // RAMで宛先と署名材料を準備する（開封はtransactionの外。AADは固定destinationと認可済みownerから作り、capsule・平文から採らない）。
      let url: string;
      let eventBytes: Buffer;
      const secrets: Buffer[] = [];
      const ownerBinding = `id:${ownerId}`;
      const binding = (purpose: 'callback-url' | 'callback-secret', secretHash: string | null): KmsSealingBinding => ({
        purpose,
        model: 'Subscription',
        recordId: destination.subscriptionId,
        ownerBinding,
        secretHash,
      });
      const secretOf = (bytes: Buffer): Buffer => {
        const text = textOf(bytes);
        if (!isValidSecret(text)) throw new Error('invalid_secret');
        const raw = Buffer.from(text.slice(SECRET_PREFIX.length), 'base64');
        owned.push(raw);
        this.#observe(raw);
        return raw;
      };
      try {
        const urlBytes = await this.#open(binding('callback-url', null), prepared.sealedUrl, limit, signal, owned);
        url = textOf(urlBytes);
        if (url.length < 1 || url.length > MAX_URL_LENGTH || !wellFormed(url)) throw new Error('invalid_url');
        secrets.push(secretOf(await this.#open(binding('callback-secret', destination.secretHash), prepared.sealedSecret, limit, signal, owned)));
        if (prepared.previous !== null) {
          const previous = prepared.previous;
          secrets.push(secretOf(await this.#open(binding('callback-secret', previous.secretHash), previous.sealed, limit, signal, owned)));
        }
        eventBytes = buildEventBytes(fields, eventIdFor({ hash: this.#d.hash }, ownerId, commandId), doc.receivedAt, doc.expiresAt);
        owned.push(eventBytes);
        this.#observe(eventBytes);
        if (hooks.afterOpen) await hooks.afterOpen();
      } catch (error) {
        const code = error instanceof KmsDeliveryOperationError ? error.code : undefined;
        return await abandon(code === 'timed_out' ? 'deadline_passed' : code === 'aborted' ? 'not_sendable' : 'local_error');
      }
      const eventId = eventIdFor({ hash: this.#d.hash }, ownerId, commandId);

      // 開封を待った後の最新の残り・中止。短ければ送出権へ進まない。
      if (!this.#sendable(limit, signal)) return await abandon(signal.aborted ? 'not_sendable' : 'deadline_passed');

      // 送出権（この試行だけ、1回だけ）。最新の認可・宛先・旧hash・猶予をDBで再照合する。確定を確認できなければ送らない。
      let dispatch: DispatchDecision | undefined;
      try {
        const evidence = prepared.previous && { sealed: prepared.previous.sealed, secretHash: prepared.previous.secretHash };
        dispatch = await store.dispatch(ownerId, commandKey, attemptId, evidence, { deadlineAt: limit, signal });
      } catch {
        dispatch = undefined;
      }
      if (dispatch === undefined) {
        this.#log({ event: 'delivery.dispatch', outcome: 'unconfirmed' });
        return await abandon('dispatch_unconfirmed');
      }
      this.#log({ event: 'delivery.dispatch', outcome: dispatch.kind });
      if (dispatch.kind === 'unchanged') {
        const current = dispatch.doc;
        // 先着の中止など。送っていない。
        if (current !== undefined && current.state === 'cancelled') return respond('cancelled', current);
        return respond('failed');
      }
      if (dispatch.kind === 'refused') return respond(dispatch.doc.state as PublicState, dispatch.doc);

      const granted = dispatch.doc;
      // 旧secretの署名は、送出権のtransactionが同じsnapshotで旧sealed/hash/猶予を確かめた時だけ加える。
      const keys = dispatch.previousValid ? secrets : secrets.slice(0, 1);
      // 送出の直前の最新の残り・中止。送っていないことが確かなので、準備状態へ戻さず未送信の失敗として終える。
      if (!this.#sendable(limit, signal)) return await abandon('not_sendable');

      let outcome: { readonly state: FinalState; readonly reason: DeliveryReason };
      let stopSubscription = false;
      try {
        const result = await this.#d.send({
          eventBytes,
          eventId,
          subscriptionId: destination.subscriptionId,
          url,
          secrets: keys,
          expiresAt: granted.expiresAt,
          leaseUntil: Math.min(granted.deadlineAt, until),
          signal,
        });
        stopSubscription = result.stopSubscription === true;
        outcome = result.kind === 'unavailable' && signal.aborted ? { state: 'failed', reason: 'not_sendable' } : outcomeOf(result.kind, result.reason);
      } catch (error) {
        // 入力の不正は送出の前に止まる。それ以外は送ったか分からない。
        outcome =
          error instanceof CommandDeliveryAttemptError && error.code === 'invalid_input'
            ? { state: 'failed', reason: 'local_error' }
            : { state: 'delivery_unknown', reason: 'transport_ambiguous' };
      }
      const decidedAt = clock.now();
      this.#log({ event: 'delivery.sent', state: outcome.state, reason: outcome.reason, stopSubscription });

      let recorded: CommandDoc | undefined;
      if (!lifetime.aborted) {
        try {
          if (hooks.beforeFinish) await hooks.beforeFinish();
          // 元期限の後・dispose後は結果のtransactionを始めない（応答は実際の送出の結果のまま）。
          recorded = await store.finish(ownerId, commandKey, attemptId, outcome.state, outcome.reason, stopSubscription, {
            deadlineAt: limit,
            signal: lifetime,
          });
        } catch {
          this.#log({ event: 'delivery.record_failed', step: 'finish' });
        }
      }
      // 応答は実際の送出の結果。保存できなかった時もDBの照会結果で上書きしない。
      return respond(outcome.state, recorded ?? granted, outcome.state === 'delivered' ? (recorded?.acknowledgedAt ?? decidedAt) : undefined);
    } finally {
      if (this.#inflight.get(commandKey) === controller) this.#inflight.delete(commandKey);
      for (const buffer of owned) buffer.fill(0);
    }
  }

  async get(ownerId: string, commandId: string, receivedAt: number, parentOperation?: KmsDeliveryParentOperation): Promise<DeliveryResponse> {
    if (this.#d.lifetime.aborted) return unavailable();
    const parent = parentOf(parentOperation);
    if (parent === 'invalid') return unavailable();
    const until = this.#until(receivedAt, parent);
    if (until === undefined) return unavailable();
    if (this.#parentStopped(parent, until)) return unavailable();
    let doc: CommandDoc | undefined;
    // parentがあれば、lifetimeとparentを結んだ要求固有のsignalをstoreへ渡し、finallyで解除する（省略時はlifetime）。
    const joined = parent === null ? null : this.#controller(parent);
    try {
      doc = await this.#d.store.read(ownerId, this.#d.store.commandKey(ownerId, commandId), {
        deadlineAt: until,
        signal: joined === null ? this.#d.lifetime : joined.controller.signal,
      });
    } catch {
      return unavailable();
    } finally {
      joined?.release();
    }
    if (doc === undefined) return errorResponse(404, 'not_found');
    return { status: 200, body: statusBody(commandId, doc, projectState(doc, this.#d.clock.now())) };
  }

  async cancel(ownerId: string, commandId: string, receivedAt: number, parentOperation?: KmsDeliveryParentOperation): Promise<DeliveryResponse> {
    if (this.#d.lifetime.aborted) return unavailable();
    const parent = parentOf(parentOperation);
    if (parent === 'invalid') return unavailable();
    const until = this.#until(receivedAt, parent);
    if (until === undefined) return unavailable();
    if (this.#parentStopped(parent, until)) return unavailable();
    const commandKey = this.#d.store.commandKey(ownerId, commandId);
    let decision: CancelDecision | 'denied';
    // parentがあれば要求固有の結合signal（finallyで解除）。この中断は同IDのinflight中止へは伝えない（中止はcancelの確定で行う）。
    const joined = parent === null ? null : this.#controller(parent);
    try {
      decision = await this.#d.store.cancel(ownerId, commandKey, {
        deadlineAt: until,
        signal: joined === null ? this.#d.lifetime : joined.controller.signal,
      });
    } catch {
      return unavailable();
    } finally {
      joined?.release();
    }
    if (decision === 'denied') return errorResponse(403, 'connection_revoked');
    this.#log({ event: 'delivery.cancel', outcome: decision.kind });
    const state = cancelView(decision.doc, this.#d.clock.now());
    // 準備中の中止は開封中でも同じprocessの処理を止める。送出権の確定の後は「中止要求/結果不明」で、同じprocessの送出だけを
    // 可能な範囲で中断する（届いたHTTPは撤回できない）。
    if (decision.kind === 'cancelled' || (decision.kind === 'observed' && decision.doc.state === 'dispatching')) {
      this.#inflight.get(commandKey)?.abort();
    }
    return { status: 200, body: statusBody(commandId, decision.doc, state) };
  }
}
