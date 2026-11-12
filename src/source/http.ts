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
  readonly pairing?: true | undefined;
}

export interface SourceGate {
  inspect(headers: Readonly<Record<string, string | string[] | undefined>>): SourceInspection;
  authorize(proof: SourceProof, input: SourceAuthorizeInput): Promise<SourceDecision>;
  /**
   * 送出確定のtransaction（kms-storeのdispatch）で、入口で認可したsourceを同じtxで読み直し、全readの後の時刻で照合する関数。
   * 停止・削除・期限・世代違いはfalse（送出0）。不正・障害はthrow（送出しない）。
   */
  dispatchCheck(binding: SourceBinding, operation: SourceOperation, identity?: VerifiedIdentity): (tx: Transaction) => Promise<boolean>;
}

export interface SourceGateDeps {
  readonly policy: StrictSourcePolicy;
  readonly store: Pick<SourceStore, 'authorizeRequest' | 'sourceIn' | 'now'> & Partial<Pick<SourceStore, 'scopeAllowsIn' | 'pairingAllowsIn'>>;
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
  maxBytes: number = APPROVAL_BODY_MAX_BYTES,
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
      if (size > maxBytes) {
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
            ...(input.pairing ? { pairing: true as const } : {}),
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
            ...(input.pairing ? { pairing: true as const } : {}),
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

    dispatchCheck(binding: SourceBinding, operation: SourceOperation, identity?: VerifiedIdentity): (tx: Transaction) => Promise<boolean> {
      const bound: SourceBinding = Object.freeze({ sourceId: binding.sourceId, generation: binding.generation });
      const identityHash = identity === undefined ? null : connectIdentityHash(hasher, namespace, identity);
      return async (tx: Transaction): Promise<boolean> => {
        const record = await store.sourceIn(tx, bound);
        // 送出確定でも同じ本人の現在の利用許可の範囲を読む（Webだけへ変わった本人のApp Check要求は送出0）。範囲を読めない構成は送出しない。
        if (identityHash !== null) {
          if (store.scopeAllowsIn === undefined) return false;
          if (!(await store.scopeAllowsIn(tx, identityHash, record))) return false;
          if (store.pairingAllowsIn !== undefined && !(await store.pairingAllowsIn(tx, identityHash, record))) return false;
        }
        return sourceRequestBindingVerdict(record, bound, operation, store.now()).kind === 'usable';
      };
    },
  });
}

// ---- プレイグラウンド専用の限定endpoint（通常MCPで明示設定した時だけ） ----
//   POST /v1/playground/register     本人1人のWeb source（connect/send）登録。Bearerは本人のFirebase ID token、本文は"{}"だけ。
//   POST /v1/playground/code/issue   既存の6桁コードの自己発行（発行元の範囲はサーバーが'web'に固定）。本文 {claimSecret[,previousOperationId]}。
//   POST /v1/playground/code/claim   同じclaim secretの発行元だけが結果（custom token）を受け取る。本文 {claimSecret, operationId}。
// 全て設定で固定したBFFの公開鍵・source IDのdeveloper-key-v1署名（宛先origin・method・path・query・本文・Bearer・nonce・期限）を検証し、
// nonceを単回記録する。App Check・未知のID/鍵・過大な本文・同じ署名の再利用は拒否。管理操作・他の本人・他の操作への書込みは無い。

export const PLAYGROUND_PATHS = Object.freeze(['/v1/playground/register', '/v1/playground/code/issue', '/v1/playground/code/claim'] as const);
export const PLAYGROUND_BODY_MAX_BYTES = 1024;

export interface PlaygroundEndpointDeps {
  readonly store: Pick<SourceStore, 'registerPlayground' | 'consumeReplay'>;
  readonly hasher: SecretHasher;
  readonly namespace: string;
  /** 署名の宛先（通常MCPのpublic origin）。 */
  readonly audience: string;
  readonly clock: { now(): number };
  /** 設定で固定したBFFの登録元（公開鍵はraw Ed25519のbase64url）。 */
  readonly registrar: { readonly sourceId: string; readonly publicKey: string };
  readonly verifyIdentity: (idToken: string) => Promise<VerifiedIdentity>;
  /** 既存の6桁コードの保存層と同じ配置のcustom token発行（機能offならnull＝code endpointは404）。 */
  readonly code: {
    issue(input: { readonly claimSecret: string; readonly previousOperationId?: string | undefined; readonly sourceScope: 'web' }): Promise<{ readonly code: string; readonly operationId: string; readonly issuedAt: number; readonly authExpiresAt: number }>;
    token(input: { readonly claimSecret: string; readonly operationId: string }): Promise<{ readonly kind: string; readonly customToken?: string }>;
  } | null;
  readonly newIds: () => { readonly fresh: SourceBinding; readonly accessGeneration: string };
}

export interface PlaygroundRequest {
  readonly method: string;
  readonly path: string;
  readonly search: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: Uint8Array;
}

export type PlaygroundResponse = { readonly status: number; readonly body: Record<string, unknown> };

const pgError = (status: number, code: string): PlaygroundResponse => ({ status, body: { error: { code } } });
const CLAIM_SECRET = /^[A-Za-z0-9_-]{32,128}$/;
const OPERATION_ID = /^[A-Za-z0-9_-]{32,128}$/;

function exactJson(body: Uint8Array, required: readonly string[], optional: readonly string[]): Record<string, string> | null {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  if (!required.every((k) => keys.includes(k)) || !keys.every((k) => required.includes(k) || optional.includes(k))) return null;
  for (const k of keys) if (typeof (value as Record<string, unknown>)[k] !== 'string') return null;
  return value as Record<string, string>;
}

export function createPlaygroundEndpoint(deps: PlaygroundEndpointDeps): { handle(request: PlaygroundRequest): Promise<PlaygroundResponse> } {
  const { store, hasher, namespace, audience, clock, registrar } = deps;
  return Object.freeze({
    async handle(request: PlaygroundRequest): Promise<PlaygroundResponse> {
      const path = request.path as (typeof PLAYGROUND_PATHS)[number];
      if (!PLAYGROUND_PATHS.includes(path)) return pgError(404, 'not_found');
      if (path !== '/v1/playground/register' && deps.code === null) return pgError(404, 'not_found');
      if (request.method !== 'POST') return pgError(405, 'method_not_allowed');
      if (request.search !== '') return pgError(400, 'invalid_request');
      if (request.body.length > PLAYGROUND_BODY_MAX_BYTES) return pgError(413, 'payload_too_large');
      const parsed = parseSourceProof(request.headers);
      // App Checkでの代用・欠落・形違い・未知のsource IDは拒否（署名の検証より前に固定の403）。
      if (parsed.kind !== 'present') return pgError(403, 'source_rejected');
      const proof = parsed.proof;
      if (proof.method !== 'developer-key-v1' || proof.sourceId !== registrar.sourceId) return pgError(403, 'source_rejected');
      const authorization = request.headers.authorization;
      const bearerMatch = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9._-]{1,4096})$/.exec(authorization) : null;
      const bearer = path === '/v1/playground/register' ? bearerMatch?.[1] : authorization === undefined ? '' : undefined;
      if (bearer === undefined) return pgError(path === '/v1/playground/register' ? 401 : 400, path === '/v1/playground/register' ? 'authentication_required' : 'invalid_request');
      if (signatureTimeVerdict(proof.claims, clock.now()) !== 'ok') return pgError(403, 'source_rejected');
      const signed: SignedRequest = { audience, method: 'POST', path, search: '', sourceId: registrar.sourceId, body: request.body, bearer, idempotencyKey: undefined };
      if (!verifySourceSignature(registrar.publicKey, signed, proof.claims, proof.signature)) return pgError(403, 'source_rejected');
      try {
        if (!(await store.consumeReplay(sourceReplayId(hasher, namespace, registrar.sourceId, proof.claims.nonce), signatureReplayUntil(proof.claims), (now) => signatureTimeVerdict(proof.claims, now) === 'ok'))) {
          return pgError(403, 'source_rejected');
        }
      } catch {
        return pgError(503, 'temporarily_unavailable');
      }
      if (path === '/v1/playground/register') {
        if (Buffer.from(request.body).toString('utf8') !== '{}') return pgError(400, 'invalid_request');
        let identity: VerifiedIdentity;
        try {
          identity = await deps.verifyIdentity(bearer);
        } catch {
          return pgError(401, 'authentication_required');
        }
        const ids = deps.newIds();
        try {
          const read = await store.registerPlayground({
            identityHash: connectIdentityHash(hasher, namespace, identity),
            publicKey: registrar.publicKey,
            expiresAt: null,
            fresh: ids.fresh,
            newAccessGeneration: ids.accessGeneration,
            codeIdentity: identity.method === 'developer_code',
          });
          if (read.kind === 'registered') return { status: 200, body: { sourceId: read.binding.sourceId, generation: read.binding.generation } };
          return pgError(read.reason === 'source_unusable' ? 409 : 403, read.reason === 'source_unusable' ? 'source_unusable' : 'access_denied');
        } catch {
          return pgError(503, 'temporarily_unavailable');
        }
      }
      const code = deps.code;
      if (code === null) return pgError(404, 'not_found');
      try {
        if (path === '/v1/playground/code/issue') {
          const input = exactJson(request.body, ['claimSecret'], ['previousOperationId']);
          if (input === null || !CLAIM_SECRET.test(input.claimSecret!) || (input.previousOperationId !== undefined && !OPERATION_ID.test(input.previousOperationId))) return pgError(400, 'invalid_request');
          const issued = await code.issue({ claimSecret: input.claimSecret!, previousOperationId: input.previousOperationId, sourceScope: 'web' });
          return { status: 200, body: { code: issued.code, operationId: issued.operationId, issuedAt: issued.issuedAt, authExpiresAt: issued.authExpiresAt } };
        }
        const input = exactJson(request.body, ['claimSecret', 'operationId'], []);
        if (input === null || !CLAIM_SECRET.test(input.claimSecret!) || !OPERATION_ID.test(input.operationId!)) return pgError(400, 'invalid_request');
        const outcome = await code.token({ claimSecret: input.claimSecret!, operationId: input.operationId! });
        return { status: 200, body: outcome.kind === 'active' ? { kind: 'active', customToken: outcome.customToken } : { kind: outcome.kind } };
      } catch (error) {
        const known = typeof (error as { code?: unknown })?.code === 'string' ? (error as { code: string }).code : '';
        if (known === 'rate_limited' || known === 'issue_exhausted') return pgError(429, 'rate_limited');
        if (known === 'not_owner') return pgError(403, 'not_owner');
        return pgError(503, 'temporarily_unavailable');
      }
    },
  });
}
