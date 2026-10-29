// 送信APIの許可元gate（strictの配置だけ）。delivery/api.tsが平文/暗号文の送信・公開鍵の取得/再発行で使う。
//   inspect: headerの形だけ（本人確認・DB・外部呼出しの前）。欠落はsource_required、形違い・重複・両方式の併記はsource_rejected。
//   authorize: 本人確認の後に1回。方式が配置で有効か → App Checkはconsume（外部）→ 1 transactionでsource状態・App ID/署名・replay。
// 照会/取消（commands GET・cancel）は最小回復としてgateを通さない（現行の本人/owner条件のまま）。拒否の理由は固定codeだけをlogへ出し、
// source ID・token・署名・本文は出さない。

import { connectIdentityHash } from '../connect/firestore.js';
import type { VerifiedIdentity } from '../identity/firebase.js';
import type { SecretHasher } from '../secrets.js';
import type { AppCheckVerifier } from './app-check.js';
import type { Transaction } from '@google-cloud/firestore';

import { sourceRequestBindingVerdict, type SourceBinding, type SourceOperation, type StrictSourcePolicy } from './contract.js';
import type { RequestAuthorization, SourceStore } from './firestore.js';
import { parseSourceProof, signatureReplayUntil, signatureTimeVerdict, sourceReplayId, verifySourceSignature, type SignedRequest, type SourceProof } from './proof.js';

export type SourceInspection = { readonly kind: 'present'; readonly proof: SourceProof } | { readonly kind: 'denied'; readonly code: 'source_required' | 'source_rejected' };

export type SourceDecision =
  | { readonly kind: 'allowed'; readonly sourceId: string; readonly generation: string }
  | { readonly kind: 'denied'; readonly code: 'source_rejected'; readonly reason: string }
  | { readonly kind: 'unavailable' };

export interface SourceAuthorizeInput {
  readonly identity: VerifiedIdentity;
  readonly operation: SourceOperation;
  readonly method: string;
  readonly path: string;
  readonly search: string;
  readonly body: Uint8Array;
  readonly bearer: string;
  readonly idempotencyKey: string | undefined;
}

export interface SourceGate {
  inspect(headers: Readonly<Record<string, string | string[] | undefined>>): SourceInspection;
  authorize(proof: SourceProof, input: SourceAuthorizeInput): Promise<SourceDecision>;
  /**
   * 送出確定のtransaction（kms-storeのdispatch）で、入口で認可したsourceを同じtxで読み直し、全readの後の時刻で照合する関数。
   * 停止・削除・期限・世代違いはfalse（送出0）。不正・障害はthrow（送出しない）。
   */
  dispatchCheck(binding: SourceBinding, operation: SourceOperation): (tx: Transaction) => Promise<boolean>;
}

export interface SourceGateDeps {
  readonly policy: StrictSourcePolicy;
  readonly store: Pick<SourceStore, 'authorizeRequest' | 'sourceIn' | 'now'>;
  readonly hasher: SecretHasher;
  readonly namespace: string;
  /** 署名の宛先（配置設定のapi.publicOrigin）。 */
  readonly audience: string;
  readonly clock: { now(): number };
  /** App Check方式が有効な配置だけ（無いのに有効化されていれば組立てを拒否）。 */
  readonly appCheck?: AppCheckVerifier | undefined;
}

/** 接続承認のPOST本文（明示承認だけ。余分なfield・空白なし）。 */
export const APPROVE_BODY = '{"approve":true}';
const APPROVAL_BODY_MAX_BYTES = 64;

/**
 * 接続承認のPOST本文を、元要求のoperation（期限・中止）の中だけで最大64byte読む。超過・切断・中止・期限はnullで、どの終わり方でも
 * timer・全listenerを外し、読んだchunkを0埋めし、残りの本文は捨てる（元期限を延長しない。新しいretry・待機は作らない）。
 */
export function readApprovalBody(
  req: NodeJS.ReadableStream & { readonly complete?: boolean; readonly destroyed?: boolean },
  operation: { readonly deadlineAt: number; readonly signal: AbortSignal },
  clock: { now(): number },
): Promise<Buffer | null> {
  return new Promise((resolve) => {
    let chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (value: Buffer | null): void => {
      if (done) return;
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onStop);
      req.off('aborted', onStop);
      req.off('close', onClose);
      operation.signal.removeEventListener('abort', onStop);
      const body = value === null ? null : Buffer.concat(chunks);
      for (const chunk of chunks) chunk.fill(0);
      chunks = [];
      if (value === null && req.destroyed !== true) req.resume();
      resolve(body);
    };
    const onData = (chunk: Buffer | string): void => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
      size += buffer.length;
      if (size > APPROVAL_BODY_MAX_BYTES) {
        buffer.fill(0);
        finish(null);
      } else chunks.push(buffer);
    };
    const onEnd = (): void => finish(Buffer.alloc(0));
    const onStop = (): void => finish(null);
    const onClose = (): void => {
      if (req.complete !== true) finish(null);
    };
    let remaining: number;
    try {
      remaining = operation.deadlineAt - clock.now();
    } catch {
      remaining = Number.NaN;
    }
    if (operation.signal.aborted || !(remaining > 0)) {
      finish(null);
      return;
    }
    timer = setTimeout(onStop, remaining);
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onStop);
    req.once('aborted', onStop);
    req.once('close', onClose);
    operation.signal.addEventListener('abort', onStop, { once: true });
  });
}

export class SourceGateConfigError extends Error {
  override readonly name = 'SourceGateConfigError';
  constructor() {
    super('source gate config invalid');
  }
}

export function createSourceGate(deps: SourceGateDeps): SourceGate {
  const { policy, store, hasher, namespace, audience, clock, appCheck } = deps;
  const appCheckEnabled = policy.methods.includes('app-check-v1');
  const developerEnabled = policy.methods.includes('developer-key-v1');
  if (policy.methods.length < 1 || (appCheckEnabled && appCheck === undefined)) throw new SourceGateConfigError();
  const denied = (reason: string): SourceDecision => ({ kind: 'denied', code: 'source_rejected', reason });

  return Object.freeze({
    inspect(headers: Readonly<Record<string, string | string[] | undefined>>): SourceInspection {
      const parsed = parseSourceProof(headers);
      if (parsed.kind === 'missing') return { kind: 'denied', code: 'source_required' };
      if (parsed.kind === 'malformed') return { kind: 'denied', code: 'source_rejected' };
      return { kind: 'present', proof: parsed.proof };
    },

    async authorize(proof: SourceProof, input: SourceAuthorizeInput): Promise<SourceDecision> {
      const identityHash = connectIdentityHash(hasher, namespace, input.identity);
      let result: RequestAuthorization;
      try {
        if (proof.method === 'app-check-v1') {
          if (!appCheckEnabled || appCheck === undefined) return denied('method');
          const consumed = await appCheck.consume(proof.token);
          if (consumed.kind === 'unavailable') return { kind: 'unavailable' };
          if (consumed.kind === 'rejected') return denied(consumed.reason);
          const appId = consumed.appId;
          result = await store.authorizeRequest({
            sourceId: proof.sourceId,
            method: 'app-check-v1',
            operation: input.operation,
            identityHash,
            proofMatches: (record) => record.kind === 'app' && record.appId === appId,
          });
        } else {
          if (!developerEnabled) return denied('method');
          const time = signatureTimeVerdict(proof.claims, clock.now());
          if (time !== 'ok') return denied(time);
          const request: SignedRequest = {
            audience,
            method: input.method,
            path: input.path,
            search: input.search,
            sourceId: proof.sourceId,
            body: input.body,
            bearer: input.bearer,
            idempotencyKey: input.idempotencyKey,
          };
          result = await store.authorizeRequest({
            sourceId: proof.sourceId,
            method: 'developer-key-v1',
            operation: input.operation,
            identityHash,
            proofMatches: (record) => record.kind === 'developer' && verifySourceSignature(record.publicKey, request, proof.claims, proof.signature),
            // DB待機中に署名の期限を過ぎた要求は、全readの後の時刻で拒否する。
            validAt: (now) => signatureTimeVerdict(proof.claims, now) === 'ok',
            replay: { id: sourceReplayId(hasher, namespace, proof.sourceId, proof.claims.nonce), until: signatureReplayUntil(proof.claims) },
          });
        }
      } catch {
        // SourceUnavailableError・verifierの想定外の失敗とも、結果不明として通さない。
        return { kind: 'unavailable' };
      }
      if (result.kind === 'rejected') return denied(result.reason);
      return { kind: 'allowed', sourceId: result.binding.sourceId, generation: result.binding.generation };
    },

    dispatchCheck(binding: SourceBinding, operation: SourceOperation): (tx: Transaction) => Promise<boolean> {
      const bound: SourceBinding = Object.freeze({ sourceId: binding.sourceId, generation: binding.generation });
      return async (tx: Transaction): Promise<boolean> => {
        const record = await store.sourceIn(tx, bound);
        return sourceRequestBindingVerdict(record, bound, operation, store.now()).kind === 'usable';
      };
    },
  });
}
