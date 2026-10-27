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
import { createEncryptionSecretProvider, createGoogleEncryptionSecretSource } from './secret-provider.js';
import { EncryptionKeyService, type KeyServiceOutcome } from './service.js';
import { EncryptionKeyStore } from './store.js';

/** 送信APIの入口が使う公開鍵取得のport（T073の暗号文入口も同じ入口へ別portで足す）。 */
export interface EncryptionKeyEndpoint {
  get(identity: VerifiedIdentity, operation: DeliveryRequestOperation): Promise<DeliveryResponse>;
}

export interface EncryptionKeySource {
  getOrInitialize(identity: { readonly projectId: string; readonly uid: string }, operation: DeliveryRequestOperation): Promise<KeyServiceOutcome>;
}

function responseOf(outcome: KeyServiceOutcome): DeliveryResponse {
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
  const service = new EncryptionKeyService({
    environment: {
      projectId: deployment.projectId,
      projectNumber: deployment.projectNumber,
      databaseId: deployment.databaseId,
      connectNamespace: deployment.connectNamespace,
      deliveryNamespace: deployment.deliveryNamespace,
      encryptionNamespace: setting.namespace,
    },
    store,
    secrets: createEncryptionSecretProvider(source, policy),
    hasher: options.hasher,
    clock,
  });
  return Object.freeze({ endpoint: createEncryptionKeyEndpoint(service), dispose: () => source.dispose() });
}
