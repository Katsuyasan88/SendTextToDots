// 本人鍵の取得・遅延初期化・Secret版rewrapの調停（HTTP入口はT072、ここは入口が使うservice）。
//   1. begin（transaction）: 既存の許可・owner・90日を読み、取得rate（ring不在なら初期化rateも）を予約する。owner/許可は作らない。
//   2. transactionの外で1回だけ: RSA3072候補の生成、書込みSecret版の遅延取得、wrap、自己開封と公開鍵の一致確認。
//   3. commitInitial（CAS）: 最新の認可とring不在を再確認してcreate。既存ringが勝っていればそれを返し候補は捨てる（RAMのみ）。
//      commit応答不明は同じscopeを1回readして採用結果を返し、読めなければunavailable（自動で再生成しない）。
//   4. 書込み版以外で包んだ鍵がある既存ringは、同じkid/秘密鍵を新版で包み直してgeneration CAS。旧版欠落・途中失敗はringをそのまま残しunavailable。
// 応答は公開鍵の結果だけ（raw UID・ownerId・Secret参照・秘密要素を含めない）。所有Bufferはfinallyで0埋めする。

import { connectIdentityHash } from '../connect/firestore.js';
import type { SecretHasher } from '../secrets.js';
import type { DeploymentConfig } from '../config/validate.js';
import { publicKeyResultOf, RING_SCHEMA_VERSION, SCOPE_PURPOSE, WRAP_FORMAT_VERSION, type KeyRecord, type PublicKeyResult, type RingRecord } from './contract.js';
import { createKeyCandidate, generateRsaKeyPair, unwrapPrivateKey, wrapPrivateKey, type KeyPairGenerator, type WrapBinding } from './crypto.js';
import type { EncryptionSecretOperation, EncryptionSecretProvider, EncryptionSecretSession } from './secret-provider.js';
import type { EncryptionKeyStore, RingBinding } from './store.js';

/** AAD・scopeへ束縛する配置の非秘密値。 */
export interface EncryptionEnvironment {
  readonly projectId: string;
  readonly projectNumber: string;
  readonly databaseId: string;
  readonly connectNamespace: string;
  readonly deliveryNamespace: string;
  readonly encryptionNamespace: string;
}

export interface EncryptionKeyServiceDeps {
  readonly environment: EncryptionEnvironment;
  readonly store: EncryptionKeyStore;
  readonly secrets: EncryptionSecretProvider;
  /** identifierKeyのHMAC（既存identityHashと、別用途のscope）。 */
  readonly hasher: SecretHasher;
  readonly clock: { now(): number };
  readonly generate?: KeyPairGenerator;
}

export type KeyServiceOutcome =
  | { readonly kind: 'ok'; readonly key: PublicKeyResult }
  | { readonly kind: 'connection_required' }
  | { readonly kind: 'access_denied' }
  | { readonly kind: 'rate_limited'; readonly retryAfterSec: number }
  | { readonly kind: 'key_expired' }
  | { readonly kind: 'unavailable' };

const UNAVAILABLE: KeyServiceOutcome = Object.freeze({ kind: 'unavailable' });

class DeadlineError extends Error {}

/** 検証済みidentity（projectId/uid）の既存identityHashと、ownerIdからのscope（別用途HMAC、base64url43文字）。 */
export function encryptionScope(hasher: SecretHasher, environment: EncryptionEnvironment, identityHash: string, ownerId: string): string {
  const input = JSON.stringify([
    SCOPE_PURPOSE,
    environment.projectNumber,
    environment.databaseId,
    environment.connectNamespace,
    environment.deliveryNamespace,
    environment.encryptionNamespace,
    identityHash,
    ownerId,
  ]);
  const hex = hasher.hash(`t280:${environment.encryptionNamespace}:scope`, input);
  return Buffer.from(hex, 'hex').toString('base64url');
}

export class EncryptionKeyService {
  readonly #d: EncryptionKeyServiceDeps;

  constructor(deps: EncryptionKeyServiceDeps) {
    this.#d = deps;
  }

  #wrapBinding(binding: RingBinding, kid: string, secretVersion: number, publicKeySpki: string): WrapBinding {
    const env = this.#d.environment;
    return {
      projectNumber: env.projectNumber,
      databaseId: env.databaseId,
      connectNamespace: env.connectNamespace,
      deliveryNamespace: env.deliveryNamespace,
      encryptionNamespace: env.encryptionNamespace,
      identityHash: binding.identityHash,
      ownerId: binding.ownerId,
      scope: binding.scope,
      kid,
      secretVersion,
      publicKeySpki,
    };
  }

  /**
   * 認証済みidentityの現在の公開鍵を返す（ring不在なら遅延初期化）。operationは元ingressの期限・中止で、20秒を取り直さない。
   */
  async getOrInitialize(identity: { readonly projectId: string; readonly uid: string }, operation: EncryptionSecretOperation): Promise<KeyServiceOutcome> {
    const env = this.#d.environment;
    // 元ingressの期限・中止。時計の不正値も続行不可。全てのstore操作・候補生成・Secret読取りの前後で検査する。
    const live = (): void => {
      if (operation.signal.aborted) throw new DeadlineError();
      const now = this.#d.clock.now();
      if (!Number.isSafeInteger(now) || now <= 0 || now >= operation.deadlineAt) throw new DeadlineError();
    };
    try {
      live();
      if (identity.projectId !== env.projectId) return UNAVAILABLE;
      const identityHash = connectIdentityHash(this.#d.hasher, env.connectNamespace, identity);
      const begun = await this.#d.store.begin(identityHash, (ownerId) => encryptionScope(this.#d.hasher, env, identityHash, ownerId), live);
      // 期限・中止の後に完了した結果は採用しない。
      live();
      if (begun.kind === 'ready') return { kind: 'ok', key: publicKeyResultOf(begun.ring) };
      if (begun.kind === 'initialize' || begun.kind === 'rewrap') {
        live();
        const session = this.#d.secrets.open(operation);
        try {
          return begun.kind === 'initialize' ? await this.#initialize(begun.binding, session, live) : await this.#rewrap(begun.binding, begun.ring, session, live);
        } finally {
          session.dispose();
        }
      }
      return begun;
    } catch {
      return UNAVAILABLE;
    }
  }

  async #initialize(binding: RingBinding, session: EncryptionSecretSession, live: () => void): Promise<KeyServiceOutcome> {
    // 候補の生成時間も元の予算に含める（生成後に期限を過ぎていれば候補を捨てる）。
    const candidate = await createKeyCandidate(this.#d.generate ?? generateRsaKeyPair);
    try {
      live();
      const writeVersion = session.writeVersion;
      const protectionKey = await session.get(writeVersion);
      live();
      const wrapBinding = this.#wrapBinding(binding, candidate.kid, writeVersion, candidate.publicKeySpki);
      const wrappedPrivateKey = wrapPrivateKey(candidate.pkcs8, protectionKey, wrapBinding);
      unwrapPrivateKey(wrappedPrivateKey, protectionKey, wrapBinding).fill(0);
      const now = this.#d.clock.now();
      const key: KeyRecord = {
        kid: candidate.kid,
        publicJwk: candidate.publicJwk,
        publicKeySpki: candidate.publicKeySpki,
        createdAt: now,
        state: 'active',
        decryptUntil: null,
        retireAfter: null,
        secretVersion: writeVersion,
        formatVersion: WRAP_FORMAT_VERSION,
        wrappedPrivateKey,
      };
      const ring: RingRecord = {
        schemaVersion: RING_SCHEMA_VERSION,
        ...binding,
        generation: 1,
        activeKid: candidate.kid,
        keys: [key],
        reissues: [],
        createdAt: now,
        updatedAt: now,
        lastUsedAt: now,
      };
      live();
      return await this.#settle(binding, () => this.#d.store.commitInitial(binding, ring, live), live);
    } finally {
      candidate.dispose();
    }
  }

  async #rewrap(binding: RingBinding, ring: RingRecord, session: EncryptionSecretSession, live: () => void): Promise<KeyServiceOutcome> {
    const writeVersion = session.writeVersion;
    const keys: KeyRecord[] = [];
    for (const key of ring.keys) {
      if (key.secretVersion === writeVersion) {
        keys.push(key);
        continue;
      }
      const oldKey = await session.get(key.secretVersion);
      const newKey = await session.get(writeVersion);
      live();
      const pkcs8 = unwrapPrivateKey(key.wrappedPrivateKey, oldKey, this.#wrapBinding(binding, key.kid, key.secretVersion, key.publicKeySpki));
      try {
        const next = this.#wrapBinding(binding, key.kid, writeVersion, key.publicKeySpki);
        const wrappedPrivateKey = wrapPrivateKey(pkcs8, newKey, next);
        unwrapPrivateKey(wrappedPrivateKey, newKey, next).fill(0);
        keys.push({ ...key, secretVersion: writeVersion, wrappedPrivateKey });
      } finally {
        pkcs8.fill(0);
      }
    }
    live();
    return this.#settle(binding, () => this.#d.store.commitRewrap(binding, ring.generation, keys, live), live);
  }

  /**
   * CASの結果を公開結果へ収束する。commit応答不明は、同じ元operationで最新の認可・同じscopeのring・activeの期限を1回だけ
   * 読み直し（書込み0）、採用できなければその拒否/unavailable。期限後の結果は採用しない。
   */
  async #settle(binding: RingBinding, commit: () => ReturnType<EncryptionKeyStore['commitInitial']>, live: () => void): Promise<KeyServiceOutcome> {
    let outcome: Awaited<ReturnType<EncryptionKeyStore['commitInitial']>>;
    try {
      outcome = await commit();
    } catch (error) {
      if (error instanceof DeadlineError) throw error;
      const adopted = await this.#d.store.readAdopted(binding, live);
      live();
      if (adopted.kind === 'adopted') return { kind: 'ok', key: publicKeyResultOf(adopted.ring) };
      return adopted.kind === 'absent' ? UNAVAILABLE : adopted;
    }
    live();
    if (outcome.kind === 'connection_required' || outcome.kind === 'access_denied' || outcome.kind === 'key_expired') return outcome;
    return { kind: 'ok', key: publicKeyResultOf(outcome.ring) };
  }
}

/** 配置設定の暗号化がoff（欠落を含む）ならnull。factoryを呼ばない（Secret読取り0・鍵作成0）。 */
export function createEncryptionKeyServiceFor(
  config: Pick<DeploymentConfig, 'payloadEncryption'>,
  factory: (enabled: Exclude<DeploymentConfig['payloadEncryption'], 'off'>) => EncryptionKeyService,
): EncryptionKeyService | null {
  const setting = config.payloadEncryption;
  return setting === 'off' ? null : factory(setting);
}
