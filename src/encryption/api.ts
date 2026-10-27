// 本人の公開鍵取得（GET /v2/encryption-key）のservice接続とAPI runtimeでの組立て。HTTPのroute・認証・元ingressは送信APIの入口
// （delivery/api.ts）が担い、ここは検証済みidentityと元operationを鍵service（T071）へ渡して、固定の応答へ写すだけ。
//   - 200は公開の8項目（version/kid/alg/enc/scope/publicJwk/publicKeySpki/createdAt）だけ。raw UID・ownerId・Secret参照・SDK例外を含めない。
//   - owner未作成/失効/90日は409 connection_required、許可拒否は403 access_denied、ringの90日無使用は409 encryption_key_unavailable
//     （再初期化しない）、rateは429＋Retry-After、DB/Secret/期限は503 temporarily_unavailable。
//   - 組立ては暗号化offならnull（専用Secretのclientに触れない）。有効時も起動時のSecret読取り0で、要求で必要になった時だけ読む。
//     disposeで専用Secretのadapterを閉じる（以後の読取り0）。借用のdb・client・hasherは閉じない。

import type { Firestore } from '@google-cloud/firestore';
import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import type { DeploymentConfig } from '../config/validate.js';
import type { DeliveryRequestOperation } from '../delivery/api.js';
import { errorResponse, type DeliveryResponse } from '../delivery/event.js';
import type { VerifiedIdentity } from '../identity/firebase.js';
import type { SecretHasher } from '../secrets.js';
import { createEncryptedCommandEndpoint, type EncryptedCommandEndpoint, type ValidatedCommandDelivery } from './commands.js';
import { createEncryptionSecretProvider, createGoogleEncryptionSecretSource } from './secret-provider.js';
import { readFlatJsonObject } from '../commands/input.js';
import type { ReissueMode } from './contract.js';
import { EncryptionKeyService, type KeyServiceOutcome, type ReissueServiceOutcome } from './service.js';
import { EncryptionKeyStore } from './store.js';

/** 送信APIの入口が使う公開鍵取得のport（T073の暗号文入口も同じ入口へ別portで足す）。 */
export interface EncryptionKeyEndpoint {
  get(identity: VerifiedIdentity, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
  /** 本人の明示再発行（requestIdは小文字へ揃えた検証済みのUUID）。 */
  reissue(identity: VerifiedIdentity, request: ReissueRequest, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
}

export interface ReissueRequest {
  readonly requestId: string;
  readonly mode: ReissueMode;
}

export interface EncryptionKeySource {
  getOrInitialize(identity: { readonly projectId: string; readonly uid: string }, operation: DeliveryRequestOperation): Promise<KeyServiceOutcome>;
  reissue(identity: { readonly projectId: string; readonly uid: string }, request: ReissueRequest, operation: DeliveryRequestOperation): Promise<ReissueServiceOutcome>;
}

/** 再発行の本文の上限（バイト）。 */
export const REISSUE_BODY_MAX_BYTES = 1024;
const REISSUE_FIELDS: ReadonlySet<string> = new Set(['requestId', 'mode']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * 再発行の本文（HTTP入口が本人確認・DBより前に呼ぶ）: BOMなしのfatal UTF-8、exact {requestId, mode}（重複・未知key・型違いは拒否）、
 * requestIdはUUIDでIdempotency-Keyと大小無視で一致、modeはnormal/compromised。不成立はnull。
 */
export function parseReissueBody(body: Buffer, idempotencyKey: string | undefined): ReissueRequest | null {
  try {
    if (body.length < 1 || body.length > REISSUE_BODY_MAX_BYTES) return null;
    if (body.length >= 3 && body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) return null;
    const members = readFlatJsonObject(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body), REISSUE_FIELDS);
    const requestId = members.get('requestId');
    const mode = members.get('mode');
    if (members.size !== 2 || typeof requestId !== 'string' || !UUID.test(requestId)) return null;
    if (mode !== 'normal' && mode !== 'compromised') return null;
    if (idempotencyKey === undefined || idempotencyKey.toLowerCase() !== requestId.toLowerCase()) return null;
    return Object.freeze({ requestId: requestId.toLowerCase(), mode });
  } catch {
    return null;
  }
}

function reissueResponseOf(outcome: ReissueServiceOutcome, requestId: string): DeliveryResponse {
  switch (outcome.kind) {
    case 'ok':
      return responseOf(outcome);
    case 'in_flight':
      return { status: 202, body: { requestId, state: 'in_flight' }, headers: { 'Retry-After': '1' } };
    case 'conflict':
      return errorResponse(409, 'idempotency_conflict');
    case 'in_progress':
      return errorResponse(409, 'key_reissue_in_progress', true);
    case 'failed':
      return errorResponse(409, 'key_reissue_failed');
    case 'key_not_initialized':
      return errorResponse(409, 'key_not_initialized');
    default:
      return responseOf(outcome);
  }
}

function responseOf(outcome: KeyServiceOutcome | Exclude<ReissueServiceOutcome, { readonly kind: 'in_flight' | 'conflict' | 'in_progress' | 'failed' | 'key_not_initialized' }>): DeliveryResponse {
  switch (outcome.kind) {
    case 'ok': {
      const key = outcome.key;
      return {
        status: 200,
        body: {
          version: key.version,
          kid: key.kid,
          alg: key.alg,
          enc: key.enc,
          scope: key.scope,
          publicJwk: { kty: key.publicJwk.kty, n: key.publicJwk.n, e: key.publicJwk.e, kid: key.publicJwk.kid, alg: key.publicJwk.alg, use: key.publicJwk.use },
          publicKeySpki: key.publicKeySpki,
          createdAt: new Date(key.createdAt).toISOString(),
        },
      };
    }
    case 'connection_required':
      return errorResponse(409, 'connection_required');
    case 'access_denied':
      return errorResponse(403, 'access_denied');
    case 'rate_limited':
      return errorResponse(429, 'rate_limited', true, { 'Retry-After': String(outcome.retryAfterSec) });
    case 'key_expired':
      return errorResponse(409, 'encryption_key_unavailable');
    default:
      return errorResponse(503, 'temporarily_unavailable', true);
  }
}

/** 検証済みidentityのprojectId/uidと元operationだけを鍵serviceへ渡す（他の値・自己申告を渡す口は無い）。 */
export function createEncryptionKeyEndpoint(source: EncryptionKeySource): EncryptionKeyEndpoint {
  return Object.freeze({
    async get(identity: VerifiedIdentity, operation: DeliveryRequestOperation): Promise<DeliveryResponse> {
      const outcome = await source.getOrInitialize(
        { projectId: identity.projectId, uid: identity.uid },
        Object.freeze({ deadlineAt: operation.deadlineAt, signal: operation.signal }),
      );
      return responseOf(outcome);
    },
    async reissue(identity: VerifiedIdentity, request: ReissueRequest, operation: DeliveryRequestOperation): Promise<DeliveryResponse> {
      const outcome = await source.reissue(
        { projectId: identity.projectId, uid: identity.uid },
        Object.freeze({ requestId: request.requestId, mode: request.mode }),
        Object.freeze({ deadlineAt: operation.deadlineAt, signal: operation.signal }),
      );
      return reissueResponseOf(outcome, request.requestId);
    },
  });
}

export interface EncryptionKeyRuntimeOptions {
  /** 借用（terminateしない）。接続保存と同じdatabase。 */
  readonly db: Firestore;
  /** 借用の初期化済みSecret Manager client（closeしない）。 */
  readonly secretClient: SecretManagerServiceClient;
  readonly deployment: Pick<DeploymentConfig, 'projectId' | 'projectNumber' | 'databaseId' | 'connectNamespace' | 'deliveryNamespace' | 'payloadEncryption'>;
  /** 接続保存と同じidentifierKeyのHMAC（借用）。 */
  readonly hasher: SecretHasher;
  readonly clock: { now(): number };
}

export interface EncryptionKeyRuntime {
  readonly endpoint: EncryptionKeyEndpoint;
  /** 暗号文送信のport（共通配送serviceへ接続する。同じdb・hasher・専用Secret）。 */
  readonly commands: (delivery: ValidatedCommandDelivery) => EncryptedCommandEndpoint;
  /** 同期・冪等。専用Secretのadapterを閉じる（進行中はcancel、以後の読取り0）。 */
  dispose(): void;
}

/** API runtimeの組立て（同期・I/O・Secret読取り0）。暗号化offならnull。 */
export function createEncryptionKeyRuntime(options: EncryptionKeyRuntimeOptions): EncryptionKeyRuntime | null {
  const { deployment, clock } = options;
  const setting = deployment.payloadEncryption;
  if (setting === 'off') return null;
  const policy = { secret: setting.secret, writeSecretVersion: setting.writeSecretVersion, readSecretVersions: [...setting.readSecretVersions] };
  const source = createGoogleEncryptionSecretSource({ client: options.secretClient, policy, clock });
  const store = new EncryptionKeyStore({
    db: options.db,
    connectNamespace: deployment.connectNamespace,
    encryptionNamespace: setting.namespace,
    writeSecretVersion: setting.writeSecretVersion,
    clock,
  });
  const environment = {
    projectId: deployment.projectId,
    projectNumber: deployment.projectNumber,
    databaseId: deployment.databaseId,
    connectNamespace: deployment.connectNamespace,
    deliveryNamespace: deployment.deliveryNamespace,
    encryptionNamespace: setting.namespace,
  };
  const secrets = createEncryptionSecretProvider(source, policy);
  const service = new EncryptionKeyService({ environment, store, secrets, hasher: options.hasher, clock });
  return Object.freeze({
    endpoint: createEncryptionKeyEndpoint(service),
    commands: (delivery: ValidatedCommandDelivery) => createEncryptedCommandEndpoint({ environment, store, secrets, hasher: options.hasher, clock, delivery }),
    dispose: () => source.dispose(),
  });
}
