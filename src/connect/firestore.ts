// 接続Web・MCP認可が別processで共有する状態の、Firestore保存。全て sttdConnect/{namespace} の配下。
//   oidc/{model}_{idHash}       oidc-providerの全model（Session・Interaction・Grant・AuthorizationCode・AccessToken・RefreshToken・
//                               ReplayDetection・Client）。payloadは用途・文書へ束縛して封緘し、平文の値・token・uidを索引に置かない
//   identities/{identityHash}   Firebase project＋検証済みUID → 内部owner（一意）
//   owners/{ownerId}            封緘したUID・最終利用・失効。氏名・メールは持たない
//   interactions/{uidHash}      元OAuth interactionへ束縛したCSRFのhash・ログインしたowner・単回の同意
//   grantMeta/{grantHash}       同意したGrantのowner・Firebase認証時刻・利用許可の世代（交換・refresh時の失効確認と新規利用の許可に使う）
//   access/{identityHash}       運営者が明示登録した利用許可（access/policy.ts。ここでは読むだけで、書くのは管理module）
//   replay/{keyHash}            client assertionの単回予約
// メモリー保存へ切り替える経路はない。保存の失敗はそのまま例外で伝える。
// 封緘portは同期の値もPromiseも返せる。結果は必ずawaitしてから使い、Firestoreが再実行し得るtransactionの関数の中では
// 封緘・開封・乱数生成をしない（owner候補とrefreshのGrant延長はtransactionの外で準備し、関数の中では準備に使った文書の版を照合するだけ）。

import { randomUUID } from 'node:crypto';

import type { DocumentReference, DocumentSnapshot, Firestore, Timestamp, Transaction } from '@google-cloud/firestore';
import { errors, type Adapter, type AdapterFactory, type AdapterPayload } from 'oidc-provider';

import { isConnectNamespace, type Clock } from '../policy.js';
import { hashesEqual, newOpaqueValue, type SecretHasher } from '../secrets.js';
import type { AssertionReplayStore } from '../stores.js';
import type { VerifiedIdentity } from '../identity/firebase.js';
import { accessDocRef, accessVerdictOfSnapshot, AccessUnavailableError, grantGenerationOfSnapshot } from '../access/firestore.js';
import {
  accessVerdictOf,
  ACCESS_UNAVAILABLE,
  codeLoginWithin,
  grantGenerationOf,
  grantReceiverGenerationOf,
  grantUseVerdict,
  ownerIdentityHash,
  type AccessVerdict,
} from '../access/policy.js';
import { ownerReceiverGeneration, receiverResetWrites, receiverSettingsPresent, receiverSnapshotMaterial, RECEIVER_GENERATION_FIELD, ReceiverResetUnavailableError } from '../storage/firestore/receiver-reset.js';
import { parseKmsState, type KmsSubscriptionPolicy } from '../storage/firestore/kms-subscription-format.js';

import { isSourceBinding, parseSourceRecord, sourceBindingVerdict, type SourceBinding } from '../source/contract.js';
import { isAccountGrant } from '../source/connected-apps.js';
import { SOURCE_GRANTS_COLLECTION, type SourceStore } from '../source/firestore.js';

/** strictの同意で消費する許可元承認の位置と、元interactionのclient/resourceのHMAC（本人のhashはowner文書から同じtxで読む）。 */
export interface SourceApprovalRequest {
  readonly approvalId: string;
  readonly clientHash: string;
  readonly resourceHash: string;
}

export const CONNECT_STORAGE_ROOT = 'sttdConnect';

/** owner文書の受信reset世代（欠落は0）。不正は一時障害（AccessUnavailableError）。 */
function receiverGenerationOrUnavailable(owner: unknown): number {
  try {
    return ownerReceiverGeneration(owner);
  } catch {
    throw new AccessUnavailableError();
  }
}
// 名前空間の判定はSDK非依存の../policy.jsに置く（配置設定の検証・gatewayがこのmoduleを読み込まないため）。
export { isConnectNamespace };



/** 値そのものが資格情報になるmodel。payloadからjti（平文の値）を外して保存する。 */
const BEARER_MODELS: ReadonlySet<string> = new Set(['AccessToken', 'RefreshToken', 'AuthorizationCode']);
/** このprofileで有効な機能が使うmodel。それ以外（DeviceCode・PAR等）は機能を無効にしてあり、呼ばれたら拒否する。 */
export const SHARED_OIDC_MODELS: ReadonlySet<string> = new Set([
  'Session',
  'Interaction',
  'Grant',
  'AuthorizationCode',
  'AccessToken',
  'RefreshToken',
  'ReplayDetection',
  'Client',
]);
const DELETE_PAGE = 200;

type OidcDoc = {
  readonly model: string;
  readonly sealed: string;
  readonly expiresAt: number | null;
  readonly grantHash: string | null;
  readonly uidHash: string | null;
  readonly ownerHash: string | null;
  readonly consumedAt: number | null;
};

/**
 * 封緘の束縛を、capsuleや開封したpayloadではなく保存先から再生成するための信頼済みcontext。
 * oidcは保存先の文書（model・ref.id・保存メタのownerHash）、owner-uidは内部ownerId（Firebase UIDそのものは含めない）。
 */
export type ConnectSealingContext =
  | { readonly kind: 'oidc'; readonly model: string; readonly recordId: string; readonly ownerHash: string | null }
  | { readonly kind: 'owner-uid'; readonly ownerId: string };

/**
 * AS payload・UIDの封緘port（KMS用途）。同期の値を返す実装も、Promiseを返す実装もそのまま渡せる。
 * openの改変・鍵違い・用途違いは例外かreject。失敗を空データや別の値へ読み替えない。
 * ConnectStorageは全seal/openで第3引数のcontextを渡す。
 */
export interface ConnectSealingPort {
  seal(purpose: string, plaintext: string, context?: ConnectSealingContext): string | PromiseLike<string>;
  open(purpose: string, sealed: string, context?: ConnectSealingContext): string | PromiseLike<string>;
}

/**
 * transactionの外で準備に使った文書が、確定の時点で変わった・消えた・期限を過ぎた（staleな準備）。何も書かずに返す一時的な
 * 保存失敗で、再使用・本人取消とは扱わない（次の要求でproviderが通常どおり判定する）。自動で準備をやり直さない。
 */
export class ConnectStaleError extends Error {
  constructor() {
    super('connect storage: prepared state is stale');
    this.name = 'ConnectStaleError';
  }
}

/** 準備に使った文書の版（無い、または更新時刻と封緘値）。 */
type DocVersion = { readonly exists: false } | { readonly exists: true; readonly updateTime: Timestamp; readonly sealed: unknown };

function versionOf(snapshot: DocumentSnapshot): DocVersion {
  if (!snapshot.exists || snapshot.updateTime === undefined) return { exists: false };
  return { exists: true, updateTime: snapshot.updateTime, sealed: snapshot.get('sealed') };
}

function sameVersion(snapshot: DocumentSnapshot, version: DocVersion): boolean {
  const current = versionOf(snapshot);
  if (!current.exists || !version.exists) return current.exists === version.exists;
  return current.updateTime.isEqual(version.updateTime) && current.sealed === version.sealed;
}

/** refresh tokenの消費のため、transactionの外で準備したもの。grantは未消費tokenの時だけ（既消費はreuseの判定だけに使う）。 */
type PreparedRefresh = {
  readonly token: DocVersion;
  readonly grant: {
    readonly ref: DocumentReference;
    readonly version: DocVersion;
    /** 延ばす時だけ、新しいexpで封緘したpayloadと文書の期限。 */
    readonly update: { readonly sealed: string; readonly expiresAt: number } | null;
  } | null;
};

export interface ConnectStorageDeps {
  readonly db: Firestore;
  readonly namespace: string;
  /** 識別子HMAC（Secret Manager用途）。 */
  readonly hasher: SecretHasher;
  /** AS payload・UIDの封緘（KMS用途のport）。同期・Promiseのどちらも可。 */
  readonly box: ConnectSealingPort;
  readonly clock: Clock;
  /** owner無活動失効（90日）。 */
  readonly ownerInactivityMs: number;
  /** 接続interactionの単回期限（5分）。 */
  readonly interactionTtlMs: number;
  /** 正当なrefreshで同じGrantへ与える無活動期限（90日、providerのrefresh tokenの窓と同じ値）。 */
  readonly grantInactivityMs: number;
  /**
   * 受信先設定（同じFirestoreの購読保存、sttdAuth/{t268}/subscriptions/{ownerId}）の参照。無い構成では、受信先設定の削除の確認を出さない。
   */
  readonly connectedApps?: boolean | undefined;
  readonly receiverSubscriptions?: ReceiverSubscriptions | undefined;
}

/** 受信先設定の参照と、その形を検査する既存の購読policy（productionの配線から渡す）。 */
export interface ReceiverSubscriptions {
  readonly refFor: (ownerId: string) => DocumentReference;
  readonly policy: KmsSubscriptionPolicy;
}

export type BindOutcome = 'ok' | 'rejected' | 'other_owner';

/** interactionのlogin方法（検証済みのID tokenから決めた値だけ。clientの申告は使わない）。 */
export type InteractionLoginMethod = 'apple' | 'developer_code' | 'google' | 'reviewer';

export interface ConsentRecord {
  readonly ownerId: string;
  readonly authTimeSec: number;
  /** login時に確かめた利用許可の世代。 */
  readonly accessGeneration: string;
  /** 同意を消費した時のownerの受信reset世代（欠落は既存の0）。grantMetaへ束縛し、保存時に現在値と一致しなければ作らない。 */
  readonly receiverGeneration?: number;
  /** この同意で、受信先設定一式を消した（確定済み）。 */
  readonly receiverReset?: boolean;
  readonly previousSource?: SourceBinding;
}

/**
 * ログイン後の同意画面のsnapshot（表示用の不透明token）。設定が無くても出し、同意の消費のtransactionで表示時と同じかを確かめる。
 * presentは承認時に削除する受信先設定があること。
 */
export interface ReceiverSnapshot {
  readonly token: string;
  readonly present: boolean;
}

/** 同意の消費の結果。changedは表示後の受信先設定の変化（消費・削除0）。 */
export type CheckedConsent = ConsentRecord | 'denied' | 'changed' | undefined;

/** login（owner解決）の結果。deniedは利用不許可（ownerを作らない）、inactiveは既存ownerの失効・無活動。許可の一時障害はAccessUnavailableError。 */
export type OwnerAdmission =
  | { readonly kind: 'admitted'; readonly ownerId: string; readonly accessGeneration: string }
  | { readonly kind: 'denied' }
  | { readonly kind: 'inactive' };

/** 接続画面の表示用の利用許可（UID・世代・一覧を含めない）。 */
export type AccessDisplay = 'allowed' | 'denied' | 'unavailable';

export { AccessUnavailableError };

/**
 * 検証済みidentityの接続保存用HMAC（identities/{hash}・access/{hash}の位置）。開発者向けコードの確定（developer-code-identity.ts）が
 * 予定UID1件の利用許可を同じ位置へ作るために使う。
 */
/** 開発者向けコード専用UIDの形（identity/developer-login.tsのCODE_UID_PATTERNと同じ）。旧コード接続の判別だけに使う。 */
const CODE_UID_FORM = /^sttdc_[A-Za-z0-9_-]{32}$/;
export function isLegacyCodeUid(uid: unknown): boolean {
  return typeof uid === 'string' && CODE_UID_FORM.test(uid);
}

export function connectIdentityHash(hasher: SecretHasher, namespace: string, identity: Pick<VerifiedIdentity, 'projectId' | 'uid'>): string {
  return hasher.hash(`t256:${namespace}:identity`, `${identity.projectId}\0${identity.uid}`);
}

export class ConnectStorage {
  readonly #d: ConnectStorageDeps;
  readonly #root: DocumentReference;

  constructor(deps: ConnectStorageDeps) {
    if (!isConnectNamespace(deps.namespace)) throw new Error('connect storage: invalid namespace');
    this.#d = deps;
    this.#root = deps.db.collection(CONNECT_STORAGE_ROOT).doc(deps.namespace);
  }

  #hash(purpose: string, value: string): string {
    return this.#d.hasher.hash(`t256:${this.#d.namespace}:${purpose}`, value);
  }

  // ---- 許可元strict（配置設定で明示した時だけ。起動口が1回だけ結ぶ） ----

  #sources: SourceStore | undefined;

  /** strictの配置だけ: 同意でGrantへsource bindingを作り、code交換/refresh/最終保存/送出でsourceの現在の状態・世代を照合する。 */
  useSources(sources: SourceStore): void {
    if (this.#sources !== undefined) throw new Error('connect storage: sources already bound');
    this.#sources = sources;
  }

  get sourcesEnabled(): boolean {
    return this.#sources !== undefined;
  }

  /** Grantのsource binding記録の位置（sourceGrants/{grantHash}）。strictでなければnull。 */
  grantSourceDocRef(grantId: string): DocumentReference | null {
    return this.#sources === undefined ? null : this.#sources.grantRef(this.#hash('grant', grantId));
  }

  /** MCP入口のGrant照合（transaction外の読取り）。strictでなければtrue。不正・障害はSourceUnavailableError。 */
  async grantSourceUsable(grantId: string): Promise<boolean> {
    if (this.#sources === undefined) return true;
    return (await this.#sources.grantUsable(this.#hash('grant', grantId))).kind === 'usable';
  }

  /** grantMetaと同じGrantの鍵付きhashからbinding記録の位置（購読保存のtransactionが読む）。strictでなければnull。 */
  grantSourceDocRefByHash(grantHash: string): DocumentReference | null {
    return this.#sources === undefined ? null : this.#sources.grantRef(grantHash);
  }

  /** binding記録のsnapshotからsource文書の参照（unbound/不正はnull＝拒否側）。strictでなければnull。 */
  grantSourceRecordRef(binding: { readonly exists: boolean; readonly data: unknown }): DocumentReference | null {
    if (this.#sources === undefined || !binding.exists) return null;
    const data = binding.data as Record<string, unknown> | undefined;
    const value = { sourceId: data?.sourceId, generation: data?.generation };
    return isSourceBinding(value) ? this.#sources.sourceRef(value.sourceId) : null;
  }

  /**
   * transactionで読んだbinding記録とsource文書（全readの後の時刻now）からの、Grantのsource面の可否。strictでなければ'allowed'。
   * unbound（旧Grant）・停止・削除・世代違い・connect操作外は'denied'、不正は'unavailable'（allowedへ読み替えない）。
   */
  grantSourceDecision(
    binding: { readonly exists: boolean; readonly data: unknown },
    source: { readonly exists: boolean; readonly id: string; readonly data: unknown } | null,
    now: number,
  ): 'allowed' | 'denied' | 'unavailable' {
    if (this.#sources === undefined) return 'allowed';
    if (binding.exists && isAccountGrant(binding.data)) return 'allowed';
    if (!binding.exists || source === null) return 'denied';
    try {
      const data = binding.data as Record<string, unknown>;
      const bound = { sourceId: data.sourceId, generation: data.generation };
      if (!isSourceBinding(bound) || Object.keys(data).length !== 2) return 'unavailable';
      const record = source.exists ? parseSourceRecord(source.data, source.id) : null;
      return sourceBindingVerdict(record, bound, now).kind === 'usable' ? 'allowed' : 'denied';
    } catch {
      return 'unavailable';
    }
  }

  /** 接続承認の照会/承認のための元interaction（login済み・期限内だけ）。ownerと期限だけを返す。 */
  async interactionForApproval(uid: string): Promise<{ readonly ownerId: string; readonly expiresAt: number } | undefined> {
    const data = (await this.#interactionRef(uid).get()).data() as Record<string, unknown> | undefined;
    if (data === undefined || data.state !== 'authenticated' || typeof data.ownerId !== 'string' || typeof data.expiresAt !== 'number') return undefined;
    if (!(this.#d.clock.now() < data.expiresAt)) return undefined;
    return { ownerId: data.ownerId, expiresAt: data.expiresAt };
  }

  /**
   * 審査承認の発行前の読取りだけの確認（strictの審査ログイン）。interactionが審査ログインでlogin済み・期限内・CSRFが現行で、
   * ownerが審査専用（loginKind='reviewer'）で現在active、owner→許可recordがactiveで、login時の利用許可の世代と同じ時だけ、ownerと期限を返す。
   * それ以外はundefined（承認を作らない）。許可の不正・障害はAccessUnavailableError。最終の照合・単回消費はputGrantMetaのtransaction。
   */
  async reviewerApprovalTarget(uid: string, csrf: string): Promise<{ readonly ownerId: string; readonly expiresAt: number; readonly authTimeSec: number } | undefined | null> {
    const data = (await this.#interactionRef(uid).get()).data() as Record<string, unknown> | undefined;
    // 審査ログインのinteractionでなければnull（呼出し側は通常の経路のまま）。審査ログインで条件が不成立ならundefined（拒否）。
    if (data === undefined || data.loginMethod !== 'reviewer') return null;
    if (data.state !== 'authenticated' || typeof data.ownerId !== 'string') return undefined;
    if (typeof data.expiresAt !== 'number' || typeof data.accessGeneration !== 'string' || !this.#csrfMatches(data, csrf)) return undefined;
    if (typeof data.authTimeSec !== 'number' || !Number.isSafeInteger(data.authTimeSec) || data.authTimeSec <= 0) return undefined;
    const ownerId = data.ownerId;
    const owner = (await this.#ownerRef(ownerId).get()).data();
    const now = this.#d.clock.now();
    if (!(now < data.expiresAt)) return undefined;
    if (owner?.loginKind !== 'reviewer' || !this.#activeOwner(owner, now)) return undefined;
    const identityHash = ownerIdentityHash(owner);
    if (identityHash === null) return undefined;
    const access = accessVerdictOfSnapshot(await this.#accessRef(identityHash).get(), this.#d.clock.now());
    if (access.kind === 'unavailable') throw new AccessUnavailableError();
    if (access.kind === 'denied' || access.generation !== data.accessGeneration) return undefined;
    return { ownerId, expiresAt: data.expiresAt, authTimeSec: data.authTimeSec };
  }

  // ---- oidc-provider adapter ----

  #oidcRef(model: string, id: string): DocumentReference {
    return this.#root.collection('oidc').doc(`${model}_${this.#hash(`oidc-id:${model}`, id)}`);
  }

  #sealPurpose(ref: DocumentReference): string {
    return `t256:${this.#d.namespace}:oidc:${ref.id}`;
  }

  /** 保存先の文書（model・ref.id）と保存メタのownerHashからのcontext。payload・capsuleからは作らない。 */
  #oidcContext(model: string, ref: DocumentReference, ownerHash: string | null): ConnectSealingContext {
    return { kind: 'oidc', model, recordId: ref.id, ownerHash };
  }

  #ownerUidPurpose(ownerId: string): string {
    return `t256:${this.#d.namespace}:owner-uid:${ownerId}`;
  }

  async #seal(purpose: string, plaintext: string, context: ConnectSealingContext): Promise<string> {
    const sealed = await this.#d.box.seal(purpose, plaintext, context);
    if (typeof sealed !== 'string' || sealed.length === 0) throw new Error('connect storage: seal failed');
    return sealed;
  }

  async #unseal(purpose: string, sealed: string, context: ConnectSealingContext): Promise<string> {
    const plaintext = await this.#d.box.open(purpose, sealed, context);
    if (typeof plaintext !== 'string') throw new Error('connect storage: open failed');
    return plaintext;
  }

  async #open(ref: DocumentReference, doc: OidcDoc): Promise<AdapterPayload> {
    const context = this.#oidcContext(doc.model, ref, doc.ownerHash);
    return JSON.parse(await this.#unseal(this.#sealPurpose(ref), doc.sealed, context)) as AdapterPayload;
  }

  #live(doc: OidcDoc | undefined, model: string): doc is OidcDoc {
    return doc !== undefined && doc.model === model && (doc.expiresAt === null || this.#d.clock.now() < doc.expiresAt);
  }

  readonly adapterFactory: AdapterFactory = (model) => {
    if (!SHARED_OIDC_MODELS.has(model)) {
      const refuse = () => Promise.reject(new Error('connect storage: model is not enabled'));
      return {
        upsert: refuse,
        find: refuse,
        findByUid: refuse,
        findByUserCode: refuse,
        consume: refuse,
        destroy: refuse,
        revokeByGrantId: refuse,
      } satisfies Adapter;
    }
    const storage = this;
    return {
      async upsert(id, payload, expiresIn) {
        const ref = storage.#oidcRef(model, id);
        const stored: AdapterPayload = { ...payload };
        if (BEARER_MODELS.has(model)) delete stored.jti;
        delete stored.consumed;
        const accountId = typeof payload.accountId === 'string' ? payload.accountId : undefined;
        const grantId = model === 'Grant' ? id : typeof payload.grantId === 'string' ? payload.grantId : undefined;
        // 期限は封緘を待つ前の時刻から数える（遅い封緘で寿命を延ばさない）。
        const expiresAt = typeof expiresIn === 'number' ? storage.#d.clock.now() + expiresIn * 1000 : null;
        // ownerHashは1回だけ求め、封緘のcontextと保存メタへ同じ値を使う。
        const ownerHash = accountId === undefined ? null : storage.#hash('owner', accountId);
        const context = storage.#oidcContext(model, ref, ownerHash);
        const doc: OidcDoc = {
          model,
          sealed: await storage.#seal(storage.#sealPurpose(ref), JSON.stringify(stored), context),
          expiresAt,
          grantHash: grantId === undefined ? null : storage.#hash('grant', grantId),
          uidHash: typeof payload.uid === 'string' ? storage.#hash(`oidc-uid:${model}`, payload.uid) : null,
          ownerHash,
          consumedAt: null,
        };
        await ref.set(doc);
      },
      async find(id) {
        const ref = storage.#oidcRef(model, id);
        const doc = (await ref.get()).data() as OidcDoc | undefined;
        if (!storage.#live(doc, model)) return undefined;
        const payload = await storage.#open(ref, doc);
        // 開封を待つ間に期限を過ぎたものは有効として返さない。
        if (!storage.#live(doc, model)) return undefined;
        if (doc.consumedAt !== null) payload.consumed = doc.consumedAt;
        if (BEARER_MODELS.has(model)) payload.jti = id;
        return payload;
      },
      async findByUid(uid) {
        const snapshot = await storage.#root
          .collection('oidc')
          .where('uidHash', '==', storage.#hash(`oidc-uid:${model}`, uid))
          .limit(2)
          .get();
        for (const entry of snapshot.docs) {
          const doc = entry.data() as OidcDoc;
          if (!storage.#live(doc, model)) continue;
          const payload = await storage.#open(entry.ref, doc);
          if (storage.#live(doc, model)) return payload;
        }
        return undefined;
      },
      async findByUserCode() {
        return undefined;
      },
      async consume(id) {
        const ref = storage.#oidcRef(model, id);
        // refresh tokenの単回消費は、providerがFirebase account・owner・Grant・再利用を確かめた後だけ届く。
        // その同じtransactionで同じGrantの無活動期限を延ばす（拒否・確認不能・再利用の要求はここへ来ないので延ばさない）。
        // 開封・封緘はtransactionの外で準備する。準備の失敗は何も書かずに例外（tokenを消費しない）。
        const prepared = model === 'RefreshToken' ? await storage.#prepareRefresh(ref) : undefined;
        // 同じcode・refresh tokenの同時の使用は、ここで1つだけ通す。2つ目はgrant全体を取り消して拒否する。
        const reusedGrant = await storage.#d.db.runTransaction(async (tx) => {
          const tokenSnapshot = await tx.get(ref);
          const doc = tokenSnapshot.data() as OidcDoc | undefined;
          // 既消費は準備の新旧によらず、最新の文書で元のreuse（同Grantの失効）。
          if (doc !== undefined && doc.consumedAt !== null) return doc.grantHash ?? '';
          if (prepared === undefined) {
            if (doc === undefined) return null;
            tx.update(ref, { consumedAt: Math.floor(storage.#d.clock.now() / 1000) });
            return null;
          }
          // refresh token: 準備に使った版のまま、最新の時刻でtokenと同じGrantが有効で、束縛が一致する時だけ消費する。
          // 変化・消失・期限切れは何も書かずに一時失敗（tokenだけの消費で認可の失効を吸収しない）。延長が不要な時も同じ検査。
          if (doc === undefined || prepared.grant === null || !sameVersion(tokenSnapshot, prepared.token)) throw new ConnectStaleError();
          const grantSnapshot = await tx.get(prepared.grant.ref);
          if (!sameVersion(grantSnapshot, prepared.grant.version)) throw new ConnectStaleError();
          const grantDoc = grantSnapshot.data() as OidcDoc | undefined;
          if (!storage.#live(doc, model) || !storage.#live(grantDoc, 'Grant')) throw new ConnectStaleError();
          if (!storage.#sameBinding(doc, grantDoc)) throw new Error('connect storage: grant binding mismatch');
          tx.update(ref, { consumedAt: Math.floor(storage.#d.clock.now() / 1000) });
          if (prepared.grant.update !== null) tx.update(prepared.grant.ref, { ...prepared.grant.update });
          return null;
        });
        if (reusedGrant !== null) {
          if (reusedGrant !== '') await storage.#deleteByGrantHash(reusedGrant);
          throw new errors.InvalidGrant('grant reuse detected');
        }
      },
      async destroy(id) {
        await storage.#oidcRef(model, id).delete();
      },
      async revokeByGrantId(grantId) {
        await storage.#deleteByGrantHash(storage.#hash('grant', grantId), model);
      },
    } satisfies Adapter;
  };

  /**
   * refresh tokenのGrantの期限を「今から無活動窓」へ延ばす書込み（payloadのexpと文書の期限）を、transactionの外で準備する。縮めない。
   * 準備に使ったtoken・Grantの文書の版を返し、確定のtransactionはその版と一致する時だけ書く。既消費のtokenは準備しない（reuseの判定へ）。
   * 無い・期限切れのtoken、Grantが無い・期限切れは、何も書かずに一時失敗。grantIdの無いrefresh tokenは非成功。
   */
  async #prepareRefresh(tokenRef: DocumentReference): Promise<PreparedRefresh> {
    const tokenSnapshot = await tokenRef.get();
    const token = versionOf(tokenSnapshot);
    const tokenDoc = tokenSnapshot.data() as OidcDoc | undefined;
    if (tokenDoc !== undefined && tokenDoc.consumedAt !== null) return { token, grant: null };
    if (!this.#live(tokenDoc, 'RefreshToken')) throw new ConnectStaleError();
    const grantId = (await this.#open(tokenRef, tokenDoc)).grantId;
    if (typeof grantId !== 'string') throw new Error('connect storage: refresh token has no grant');
    const grantRef = this.#oidcRef('Grant', grantId);
    const grantSnapshot = await grantRef.get();
    const version = versionOf(grantSnapshot);
    const grantDoc = grantSnapshot.data() as OidcDoc | undefined;
    const now = this.#d.clock.now();
    if (!this.#live(grantDoc, 'Grant')) throw new ConnectStaleError();
    const expiresAt = now + this.#d.grantInactivityMs;
    if (grantDoc.expiresAt !== null && grantDoc.expiresAt >= expiresAt) {
      return { token, grant: { ref: grantRef, version, update: null } };
    }
    const payload = await this.#open(grantRef, grantDoc);
    payload.exp = Math.floor(expiresAt / 1000);
    // 再封緘のcontextも保存メタから（開封したpayloadのaccountIdからは作らない）。確定時に同じ版を照合する。
    const context = this.#oidcContext(grantDoc.model, grantRef, grantDoc.ownerHash);
    const sealed = await this.#seal(this.#sealPurpose(grantRef), JSON.stringify(payload), context);
    return { token, grant: { ref: grantRef, version, update: { sealed, expiresAt } } };
  }

  /** tokenとGrantの文書が、同じGrant・同じownerを指すか（索引のhashで比べる。開封しない）。 */
  #sameBinding(tokenDoc: OidcDoc, grantDoc: OidcDoc): boolean {
    const same = (a: string | null, b: string | null) => (a === null || b === null ? a === b : hashesEqual(a, b));
    return tokenDoc.grantHash !== null && same(tokenDoc.grantHash, grantDoc.grantHash) && same(tokenDoc.ownerHash, grantDoc.ownerHash);
  }

  async #deleteByGrantHash(grantHash: string, model?: string): Promise<void> {
    for (;;) {
      let query = this.#root.collection('oidc').where('grantHash', '==', grantHash);
      if (model !== undefined) query = query.where('model', '==', model);
      const snapshot = await query.limit(DELETE_PAGE).get();
      if (snapshot.empty) break;
      const batch = this.#d.db.batch();
      for (const entry of snapshot.docs) batch.delete(entry.ref);
      await batch.commit();
      if (snapshot.size < DELETE_PAGE) break;
    }
    if (model === undefined || model === 'Grant') {
      await this.#root.collection('grantMeta').doc(grantHash).delete();
      // Grantのsource binding記録もGrantと同じ保持で消す（strictでない配置では存在しない）。
      await this.#root.collection(SOURCE_GRANTS_COLLECTION).doc(grantHash).delete();
    }
  }

  /** ownerの保存済みpayloadのうち、指定modelの期限内のもの（grantIdの列挙に使う）。 */
  async #ownerPayloads(ownerId: string, models: readonly string[]): Promise<AdapterPayload[]> {
    const snapshot = await this.#root.collection('oidc').where('ownerHash', '==', this.#hash('owner', ownerId)).get();
    const payloads: AdapterPayload[] = [];
    for (const entry of snapshot.docs) {
      const doc = entry.data() as OidcDoc;
      if (!models.includes(doc.model) || !this.#live(doc, doc.model)) continue;
      const payload = await this.#open(entry.ref, doc);
      // 開封を待つ間に期限を過ぎたものは含めない。
      if (this.#live(doc, doc.model)) payloads.push(payload);
    }
    return payloads;
  }

  /** clientへaccess/refresh tokenを発行済みのGrantのid（重複なし）。有効性の正本はproviderのGrant。 */
  async issuedGrantIds(ownerId: string): Promise<string[]> {
    const ids = new Set<string>();
    for (const payload of await this.#ownerPayloads(ownerId, ['AccessToken', 'RefreshToken'])) {
      if (typeof payload.grantId === 'string') ids.add(payload.grantId);
    }
    return [...ids];
  }

  /** 接続解除。認可と受信先設定を同じtransactionで削除し、以前の設定を参照していた処理を世代で失効させる。 */
  async revokeOwner(identity: VerifiedIdentity): Promise<string | undefined> {
    const identityRef = this.#identityRef(identity);
    return this.#d.db.runTransaction(async (tx) => {
      const mapped = (await tx.get(identityRef)).data();
      if (typeof mapped?.ownerId !== 'string' || mapped.ownerId.length === 0) return undefined;
      const ownerId = mapped.ownerId;
      const ownerRef = this.#ownerRef(ownerId);
      const owner = await tx.get(ownerRef);
      const ownerData = owner.data();
      if (!owner.exists || (identity.method === 'reviewer') !== (ownerData?.loginKind === 'reviewer')) return undefined;
      if (ownerIdentityHash(ownerData) !== identityRef.id) throw new AccessUnavailableError();
      // 有効期間を過ぎた接続も、本人が保存済みの設定を削除できるようにする。
      const subscriptionRef = this.#d.receiverSubscriptions?.refFor(ownerId);
      const subscription = subscriptionRef === undefined ? null : await tx.get(subscriptionRef);
      const authorizations = this.#root.collection('oidc').where('ownerHash', '==', this.#hash('owner', ownerId));
      const oidc = await tx.get(authorizations);
      const clearApps = await this.#sources?.clearConnectedAppsIn(tx, identityRef.id);
      clearApps?.();
      if (oidc.empty && subscription?.exists !== true) return ownerId;
      const reset = receiverResetWrites(ownerId, ownerData);
      tx.update(ownerRef, reset.ownerUpdate);
      if (subscription?.exists === true) tx.delete(subscription.ref);
      const grantHashes = new Set<string>();
      for (const entry of oidc.docs) {
        const doc = entry.data() as OidcDoc;
        if (typeof doc.grantHash === 'string') grantHashes.add(doc.grantHash);
        tx.delete(entry.ref);
      }
      for (const hash of grantHashes) {
        tx.delete(this.#root.collection('grantMeta').doc(hash));
        tx.delete(this.#root.collection(SOURCE_GRANTS_COLLECTION).doc(hash));
      }
      return ownerId;
    }, { maxAttempts: 1 });
  }

  // ---- owner ----

  #identityRef(identity: Pick<VerifiedIdentity, 'projectId' | 'uid'>): DocumentReference {
    return this.#root.collection('identities').doc(connectIdentityHash(this.#d.hasher, this.#d.namespace, identity));
  }

  #ownerRef(ownerId: string): DocumentReference {
    return this.#root.collection('owners').doc(ownerId);
  }

  #activeOwner(data: Record<string, unknown> | undefined, now: number): boolean {
    return (
      data !== undefined &&
      data.revokedAt === null &&
      typeof data.lastActiveAt === 'number' &&
      now - data.lastActiveAt < this.#d.ownerInactivityMs &&
      // 明示kindは'normal'と審査専用の'reviewer'だけ。期限とkindの両方を持つ・未知kindは不正（fail closed）。
      (!Object.hasOwn(data, 'loginKind') || ((data.loginKind === 'normal' || data.loginKind === 'reviewer') && !Object.hasOwn(data, 'codeLoginExpiresAt'))) &&
      // コードloginのownerはログイン成立から10分の絶対期限（isOwnerActive＝MCPの既存access token・ownerDocActive＝配送/購読の最終txの共通判定）。
      // 期限fieldが形違い・時刻不正ならfail closed。Apple/Googleのownerは期限fieldを持たない。
      codeLoginWithin(Object.hasOwn(data, 'codeLoginExpiresAt') ? (data.codeLoginExpiresAt ?? 0) : undefined, now)
    );
  }

  #accessRef(identityHash: string): DocumentReference {
    return accessDocRef(this.#root, identityHash);
  }

  #grantMetaRef(grantId: string): DocumentReference {
    return this.#root.collection('grantMeta').doc(this.#hash('grant', grantId));
  }

  /** owner文書（transactionで読んだdata）から許可recordを同じtransactionで読む。identityHashが無い・形違いはunavailable。 */
  async #accessForOwner(tx: Transaction, ownerData: unknown): Promise<AccessVerdict> {
    const identityHash = ownerIdentityHash(ownerData);
    if (identityHash === null) return ACCESS_UNAVAILABLE;
    return accessVerdictOfSnapshot(await tx.get(this.#accessRef(identityHash)), this.#d.clock.now());
  }

  /**
   * 検証済みの本人から内部ownerを一意に解決し、無ければ作る（利用許可がactiveの時だけ。欠落・disabledはdeniedでownerを作らない）。
   * 失効・無活動のownerはinactive（再利用・振替をしない）。
   * 新規の候補ownerIdと封緘UIDはtransactionの外で1回だけ準備する。関数の中は最新のidentity対応・owner状態を読み、既存の
   * 対応を優先する（候補は使わずに捨てる）。候補を作れない競合（同じidの既存文書など）はcreateの失敗として非成功。
   */
  async resolveOwner(identity: VerifiedIdentity): Promise<OwnerAdmission> {
    const identityRef = this.#identityRef(identity);
    const accessRef = this.#accessRef(identityRef.id);
    const candidateId = randomUUID();
    const sealedUid = await this.#seal(this.#ownerUidPurpose(candidateId), identity.uid, { kind: 'owner-uid', ownerId: candidateId });
    return this.#d.db.runTransaction(async (tx): Promise<OwnerAdmission> => {
      // 利用許可（運営者の明示登録）を同じtransactionで読む。欠落・disabledはowner作成・活動更新の前に拒否、不正・障害は一時障害。
      const access = accessVerdictOfSnapshot(await tx.get(accessRef), this.#d.clock.now());
      const mapped = (await tx.get(identityRef)).data() as { ownerId?: unknown } | undefined;
      if (access.kind === 'unavailable') throw new AccessUnavailableError();
      if (access.kind === 'denied') return { kind: 'denied' };
      // 期限属性の無い旧コード接続（この版より前にactivateされたcode identityの許可）は受けない。新しいコードで接続し直す（新しい10分を足して復活させない）。
      // code UIDの判定は検証済みidentity（サーバー側のID token検証の結果）だけで行う。
      if (access.codeLoginExpiresAt === undefined && (identity.method === 'developer_code' || isLegacyCodeUid(identity.uid))) return { kind: 'denied' };
      // 審査・テスト専用ログインは期限付きのコード許可とは混ぜない。
      const reviewer = identity.method === 'reviewer';
      if (reviewer && (access.codeLoginExpiresAt !== undefined || isLegacyCodeUid(identity.uid))) return { kind: 'denied' };
      // コードloginの許可の絶対期限をowner文書へ写す（以後の要求はowner文書だけで同じ期限を判定できる。延長・削除しない）。
      const codeExpiry = access.codeLoginExpiresAt !== undefined ? { codeLoginExpiresAt: access.codeLoginExpiresAt } : {};
      if (mapped !== undefined) {
        if (typeof mapped.ownerId !== 'string') return { kind: 'inactive' };
        const ownerRef = this.#ownerRef(mapped.ownerId);
        const owner = (await tx.get(ownerRef)).data();
        // 有効性は、この実行で最新の文書を読んだ後の時刻で判断する（再実行の間に無活動期限を過ぎたownerを古い時刻で延ばさない）。
        const now = this.#d.clock.now();
        if (!this.#activeOwner(owner, now)) return { kind: 'inactive' };
        // 許可は検証済みidentityのhashへ結ぶ。owner文書のidentityHashが同じ対応を指さなければ付け替えず一時障害。
        if (ownerIdentityHash(owner) !== identityRef.id) throw new AccessUnavailableError();
        // 審査専用ownerは審査ログインだけ、他のownerは審査ログインで使わない（種別を付け替えない）。
        if (reviewer !== (owner?.loginKind === 'reviewer')) return { kind: 'inactive' };
        // 既存ownerの期限は付け替え・延長しない（無い時だけ許可の期限を写す）。通常login（Apple/Google）の既存ownerは明示kindを付ける。
        const marked = owner !== undefined && (Object.hasOwn(owner, 'codeLoginExpiresAt') || Object.hasOwn(owner, 'loginKind'));
        const mark = marked ? {} : access.codeLoginExpiresAt !== undefined ? codeExpiry : { loginKind: 'normal' };
        tx.update(ownerRef, { lastActiveAt: now, ...mark });
        return { kind: 'admitted', ownerId: mapped.ownerId, accessGeneration: access.generation };
      }
      const now = this.#d.clock.now();
      const ownerId = candidateId;
      tx.create(identityRef, { ownerId, createdAt: now });
      tx.create(this.#ownerRef(ownerId), {
        identityHash: identityRef.id,
        sealedUid,
        createdAt: now,
        lastActiveAt: now,
        revokedAt: null,
        // コードloginは期限、通常login（Apple/Google）は明示kind、審査専用ログインは'reviewer'（要求ごとの封緘UID開封を不要にする。判別できるownerだけを作る）。
        ...(reviewer ? { loginKind: 'reviewer' } : access.codeLoginExpiresAt !== undefined ? codeExpiry : { loginKind: 'normal' }),
      });
      return { kind: 'admitted', ownerId, accessGeneration: access.generation };
    });
  }

  /**
   * 作らずに引く（状態表示・送信API・許可元承認。いずれも一般の本人確認の入口）。審査・テスト専用ownerは、設定・起動口の
   * 組合せに関わらず一般の入口からは引かない（審査のデータへ一般認証で権限を付与しない）。
   */
  async findOwner(identity: VerifiedIdentity): Promise<string | undefined> {
    const mapped = (await this.#identityRef(identity).get()).data() as { ownerId?: unknown } | undefined;
    if (typeof mapped?.ownerId !== 'string' || mapped.ownerId.length === 0) return undefined;
    if (identity.method === 'reviewer') return undefined;
    const data = (await this.#ownerRef(mapped.ownerId).get()).data();
    if (data?.loginKind === 'reviewer') return undefined;
    return (await this.#ownerDataActive(mapped.ownerId, data)) ? mapped.ownerId : undefined;
  }

  /**
   * 検証済みの本人の利用許可を表示用に読む（ownerの有無・状態とは独立）。読めない・不正はunavailable（例外を外へ出さない）。
   * 照会・取消・解除の可否はこれに依存させない。
   */
  async accessDisplay(identity: VerifiedIdentity): Promise<AccessDisplay> {
    try {
      return accessVerdictOfSnapshot(await this.#accessRef(this.#identityRef(identity).id).get(), this.#d.clock.now()).kind;
    } catch {
      return 'unavailable';
    }
  }

  /**
   * GrantをこのownerがいまOAuthの新規利用（code交換・refresh）に使えるか。owner文書のidentityHash→許可record、grantMetaの世代を
   * 同じtransactionで読む。falseは資格不成立（欠落・disabled・旧形式・旧世代・別owner）、不正・障害はAccessUnavailableError。
   */
  async grantUsable(ownerId: string, grantId: string): Promise<boolean> {
    const ownerRef = this.#ownerRef(ownerId);
    const metaRef = this.#grantMetaRef(grantId);
    const bindingRef = this.grantSourceDocRef(grantId);
    const verdict = await this.#d.db.runTransaction(async (tx): Promise<AccessVerdict | { readonly kind: 'source_denied' }> => {
      const owner = await tx.get(ownerRef);
      const meta = await tx.get(metaRef);
      const access = await this.#accessForOwner(tx, owner.data());
      // 移行前の審査Grantの期限は引き続き検証し、失効済みの認可を復活させない。
      const result = grantUseVerdict(access, grantGenerationOfSnapshot(meta), ownerId, this.#d.clock.now());
      if (bindingRef === null || result.kind !== 'allowed') return result;
      // strict: Grantのsource binding・sourceを同じtransactionで読み、全readの後の時刻で判定する（旧Grant・停止・世代違いは不成立）。
      const binding = await tx.get(bindingRef);
      const bindingInput = { exists: binding.exists, data: binding.data() };
      const sourceRef = this.grantSourceRecordRef(bindingInput);
      const source = sourceRef === null ? null : await tx.get(sourceRef);
      const decision = this.grantSourceDecision(bindingInput, source === null ? null : { exists: source.exists, id: source.id, data: source.data() }, this.#d.clock.now());
      if (decision === 'unavailable') return { kind: 'unavailable' };
      return decision === 'allowed' ? result : { kind: 'source_denied' };
    });
    if (verdict.kind === 'unavailable') throw new AccessUnavailableError();
    return verdict.kind === 'allowed';
  }

  /**
   * ownerがいま新規利用できるか（MCPの既存opaque access tokenの要求ごとの解決・OAuth交換/refreshの共通入口）。
   * コードloginの期限付きownerはowner文書の期限で判定する。期限属性の無いownerは、サーバーが保存した封緘UIDを（transactionの外で、
   * 既存の封緘portで）開封し、code UID形なら期限の無い旧コード接続として拒否する（新しいコードで接続し直す）。Apple/Googleの既存ownerは維持する。
   * 開封できない・判別不能は非成功（false）。結果のcacheは持たない。
   */
  async isOwnerActive(ownerId: string): Promise<boolean> {
    if (typeof ownerId !== 'string' || ownerId.length === 0) return false;
    return this.#ownerDataActive(ownerId, (await this.#ownerRef(ownerId).get()).data());
  }

  /** 読んだowner文書のdataでのisOwnerActiveの判定（期限・kind・旧コード接続の判別）。 */
  async #ownerDataActive(ownerId: string, data: Record<string, unknown> | undefined): Promise<boolean> {
    if (!this.#activeOwner(data, this.#d.clock.now())) return false;
    if (Object.hasOwn(data!, 'codeLoginExpiresAt') || data!.loginKind === 'normal' || data!.loginKind === 'reviewer') return true;
    // 期限もkindも無い（この版より前に作られた）ownerだけ、保存UIDで旧コード接続かを判別する。
    return !(await this.#legacyCodeOwner(ownerId, data!));
  }

  /** 期限属性の無いowner文書が旧コード接続か（封緘UIDを開封してcode UID形か）。開封できない・形不正は判別不能としてtrue（拒否側）。 */
  async #legacyCodeOwner(ownerId: string, data: Record<string, unknown>): Promise<boolean> {
    if (typeof data.sealedUid !== 'string') return true;
    let uid: string;
    try {
      uid = await this.#unseal(this.#ownerUidPurpose(ownerId), data.sealedUid, { kind: 'owner-uid', ownerId });
    } catch {
      return true;
    }
    return typeof uid !== 'string' || uid.length === 0 || isLegacyCodeUid(uid);
  }

  /** 審査・テスト専用ログインのownerか（owner文書の種別だけ。無い・読めない種別は審査専用ではない＝他の判定が拒否する）。 */
  async isReviewerOwner(ownerId: string): Promise<boolean> {
    if (typeof ownerId !== 'string' || ownerId.length === 0) return false;
    return (await this.#ownerRef(ownerId).get()).data()?.loginKind === 'reviewer';
  }

  async touchOwner(ownerId: string): Promise<void> {
    await this.#ownerRef(ownerId).update({ lastActiveAt: this.#d.clock.now() });
  }

  async uidOf(ownerId: string): Promise<string | undefined> {
    const data = (await this.#ownerRef(ownerId).get()).data() as { sealedUid?: unknown } | undefined;
    if (typeof data?.sealedUid !== 'string') return undefined;
    return this.#unseal(this.#ownerUidPurpose(ownerId), data.sealedUid, { kind: 'owner-uid', ownerId });
  }

  // ---- 要求内配送のtransactionが同じ文書を読むための参照と判定（書込み・開封はしない。awaitしない） ----

  /** owner文書の参照。 */
  ownerDocRef(ownerId: string): DocumentReference {
    return this.#ownerRef(ownerId);
  }

  /** Grant文書の参照（providerが書くものと同じ位置）。 */
  grantDocRef(grantId: string): DocumentReference {
    return this.#oidcRef('Grant', grantId);
  }

  /** owner文書のdataが、nowで有効（失効なし・無活動期限内）か。 */
  ownerDocActive(data: Record<string, unknown> | undefined, now: number): boolean {
    return this.#activeOwner(data, now);
  }

  /**
   * Grant文書のdataが、nowで期限内の同じGrantで、同じownerのものか。封緘payloadは開かない（開封は保存時暗号化の鍵を使うため、
   * 再実行され得るtransactionの関数へ入れない）。取消・reuse検知・接続解除は文書の削除なので、無ければ無効。
   */
  grantDocLive(data: Record<string, unknown> | undefined, ownerId: string, grantId: string, now: number): boolean {
    const doc = data as OidcDoc | undefined;
    return (
      doc !== undefined &&
      doc.model === 'Grant' &&
      (doc.expiresAt === null || (typeof doc.expiresAt === 'number' && now < doc.expiresAt)) &&
      typeof doc.grantHash === 'string' &&
      hashesEqual(doc.grantHash, this.#hash('grant', grantId)) &&
      typeof doc.ownerHash === 'string' &&
      hashesEqual(doc.ownerHash, this.#hash('owner', ownerId))
    );
  }

  /** owner文書のdataから、その本人の許可recordの参照（identityHashが無い・形違いはnull）。 */
  accessDocRefForOwner(data: Record<string, unknown> | undefined): DocumentReference | null {
    const identityHash = ownerIdentityHash(data);
    return identityHash === null ? null : this.#accessRef(identityHash);
  }

  /** Grantの同意記録（grantMeta）文書の参照。 */
  grantMetaDocRef(grantId: string): DocumentReference {
    return this.#grantMetaRef(grantId);
  }

  /**
   * transactionで読んだ許可recordとgrantMetaのdata（欠落はundefined）から、このowner・Grantの新規利用の可否。I/O・開封0。
   * 不正・不明はunavailable（allowedへ読み替えない）。
   */
  grantUseDecision(
    access: { readonly exists: boolean; readonly data: unknown },
    meta: { readonly exists: boolean; readonly data: unknown },
    ownerId: string,
  ): 'allowed' | 'denied' | 'unavailable' {
    try {
      // コードloginの許可・審査専用ログインのGrantは判定時刻でも期限を確かめる（期限後の照会・送出・購読開始を防ぐ）。
      const now = this.#d.clock.now();
      return grantUseVerdict(accessVerdictOf(access.exists, access.data, now), grantGenerationOf(meta.exists, meta.data), ownerId, now).kind;
    } catch {
      return 'unavailable';
    }
  }

  /** transactionで読んだ許可recordのdataだけからの利用許可（Grantを伴わない判定）。不正はunavailable。 */
  accessUseDecision(access: { readonly exists: boolean; readonly data: unknown }): 'allowed' | 'denied' | 'unavailable' {
    try {
      return accessVerdictOf(access.exists, access.data, this.#d.clock.now()).kind;
    } catch {
      return 'unavailable';
    }
  }

  // ---- 接続interaction（元OAuth要求への束縛・CSRF・単回の同意） ----

  #interactionRef(uid: string): DocumentReference {
    return this.#root.collection('interactions').doc(this.#hash('interaction', uid));
  }

  /** 画面の表示ごとにCSRFを新しくする。期限は最初の表示から延ばさない。消費済み・期限切れはundefined。 */
  async openInteraction(uid: string): Promise<{ readonly csrf: string; readonly ownerId: string | null; readonly reviewer?: true } | undefined> {
    const ref = this.#interactionRef(uid);
    const csrf = newOpaqueValue();
    const csrfHash = this.#hash('csrf', csrf);
    const now = this.#d.clock.now();
    return this.#d.db.runTransaction(async (tx) => {
      const data = (await tx.get(ref)).data() as Record<string, unknown> | undefined;
      if (data === undefined) {
        tx.create(ref, { csrfHash, ownerId: null, authTimeSec: null, state: 'open', expiresAt: now + this.#d.interactionTtlMs });
        return { csrf, ownerId: null };
      }
      if (data.state === 'done' || typeof data.expiresAt !== 'number' || now >= data.expiresAt) return undefined;
      tx.update(ref, { csrfHash });
      return {
        csrf,
        ownerId: typeof data.ownerId === 'string' ? data.ownerId : null,
        ...(data.state === 'authenticated' && data.loginMethod === 'reviewer' ? { reviewer: true as const } : {}),
      };
    });
  }

  #csrfMatches(data: Record<string, unknown>, csrf: string): boolean {
    return typeof data.csrfHash === 'string' && hashesEqual(data.csrfHash, this.#hash('csrf', csrf));
  }

  /** 本人確認へ進む前の読取りだけの確認。CSRFが現行で、未消費・期限内か。 */
  async interactionAccepts(uid: string, csrf: string): Promise<boolean> {
    const data = (await this.#interactionRef(uid).get()).data() as Record<string, unknown> | undefined;
    return (
      data !== undefined &&
      data.state !== 'done' &&
      typeof data.expiresAt === 'number' &&
      this.#d.clock.now() < data.expiresAt &&
      this.#csrfMatches(data, csrf)
    );
  }

  /**
   * ログイン結果をこのinteractionへ束縛する。別ownerへの切替は拒否し、元のownerのまま残す。同じtransactionで利用許可を再確認し、
   * login時の世代と一致する時だけ世代も束縛する（停止・再登録を跨いだら'denied'。不正・障害はAccessUnavailableError）。
   */
  async bindInteraction(uid: string, csrf: string, ownerId: string, authTimeSec: number, accessGeneration: string, loginMethod?: InteractionLoginMethod): Promise<BindOutcome | 'denied'> {
    const ref = this.#interactionRef(uid);
    const ownerRef = this.#ownerRef(ownerId);
    const now = this.#d.clock.now();
    return this.#d.db.runTransaction(async (tx): Promise<BindOutcome | 'denied'> => {
      const data = (await tx.get(ref)).data() as Record<string, unknown> | undefined;
      const access = await this.#accessForOwner(tx, (await tx.get(ownerRef)).data());
      if (data === undefined || data.state === 'done' || typeof data.expiresAt !== 'number' || now >= data.expiresAt) {
        return 'rejected';
      }
      if (!this.#csrfMatches(data, csrf)) return 'rejected';
      if (typeof data.ownerId === 'string' && data.ownerId !== ownerId) return 'other_owner';
      if (access.kind === 'unavailable') throw new AccessUnavailableError();
      if (access.kind === 'denied' || access.generation !== accessGeneration) return 'denied';
      // login方法は審査専用ownerの同意を通常の同意と取り違えないために記録する。
      const method = loginMethod === 'apple' || loginMethod === 'developer_code' || loginMethod === 'google' || loginMethod === 'reviewer' ? { loginMethod } : {};
      tx.update(ref, { ownerId, authTimeSec, accessGeneration, state: 'authenticated', ...method });
      return 'ok';
    });
  }

  /** 本人の明示操作。ログイン済み・CSRF一致・期限内の時だけ1回だけ通し、以後は使えない。 */
  async consumeInteraction(uid: string, csrf: string): Promise<ConsentRecord | 'denied' | undefined> {
    const ref = this.#interactionRef(uid);
    const now = this.#d.clock.now();
    return this.#d.db.runTransaction(async (tx): Promise<ConsentRecord | 'denied' | undefined> => {
      const data = (await tx.get(ref)).data() as Record<string, unknown> | undefined;
      const owner = data !== undefined && typeof data.ownerId === 'string' ? (await tx.get(this.#ownerRef(data.ownerId))).data() : undefined;
      if (data === undefined || data.state !== 'authenticated' || typeof data.expiresAt !== 'number' || now >= data.expiresAt) {
        return undefined;
      }
      if (!this.#csrfMatches(data, csrf) || typeof data.ownerId !== 'string' || typeof data.authTimeSec !== 'number') {
        return undefined;
      }
      // 世代を束縛していない（この版より前にloginした）interactionは同意に使わない（やり直し）。
      if (typeof data.accessGeneration !== 'string') return undefined;
      // 同じtransactionで利用許可を再確認する。停止・再登録を跨いだ同意はこのinteractionを閉じてやり直させる（Grantを作らない）。
      const access = await this.#accessForOwner(tx, owner);
      if (access.kind === 'unavailable') throw new AccessUnavailableError();
      if (access.kind === 'denied' || access.generation !== data.accessGeneration) {
        tx.update(ref, { state: 'done', csrfHash: null });
        return 'denied';
      }
      const receiverGeneration = receiverGenerationOrUnavailable(owner);
      tx.update(ref, { state: 'done', csrfHash: null });
      // 受信reset世代は1以上の時だけ記録へ入れる（欠落は既存の0。従来の同意記録の形を変えない）。
      return { ownerId: data.ownerId, authTimeSec: data.authTimeSec, accessGeneration: data.accessGeneration, ...(receiverGeneration > 0 ? { receiverGeneration } : {}) };
    });
  }

  /**
   * login後の同意画面のsnapshot（読取りだけ）。interactionがlogin済み・期限内で、ownerが現在activeの時だけ、
   * interaction・CSRF・owner・購読文書の版と設定の有無・取消世代・受信reset世代へ束縛した不透明tokenを返す（設定が無くても出す）。それ以外はnull。
   */
  async receiverSnapshot(uid: string): Promise<ReceiverSnapshot | null> {
    const receiver = this.#d.receiverSubscriptions;
    if (receiver === undefined) return null;
    const data = (await this.#interactionRef(uid).get()).data() as Record<string, unknown> | undefined;
    if (data === undefined || data.state !== 'authenticated' || typeof data.ownerId !== 'string' || typeof data.csrfHash !== 'string') return null;
    const ownerId = data.ownerId;
    const owner = (await this.#ownerRef(ownerId).get()).data();
    const subscription = await receiver.refFor(ownerId).get();
    const at = this.#d.clock.now();
    if (typeof data.expiresAt !== 'number' || at >= data.expiresAt || !this.#activeOwner(owner, at)) return null;
    try {
      const present = receiverSettingsPresent(subscription, ownerId, receiver.policy);
      return { token: this.#hash('receiver-reset', receiverSnapshotMaterial({ interactionUid: uid, csrfHash: data.csrfHash, ownerId, subscription, present, ownerData: owner })), present };
    } catch (error) {
      if (error instanceof ReceiverResetUnavailableError) throw new AccessUnavailableError();
      throw error;
    }
  }

  /**
   * 同意の消費（本人の明示操作）を1つのtransactionで行う。破壊的な書込みを含み得るので、SDKの自動再試行はしない（maxAttempts 1）。
   * 全ての読取りの後に、その時の時刻で照合する: interaction（login済み・期限・CSRF・owner・世代）・ownerが現在active・利用許可の現在の世代。
   * 表示したsnapshotが現在の受信先設定と一致した時、既存の設定があれば同意と同じtransactionで消去する。
   * owner文書の取消世代と受信reset世代を進め、以前の受信先とGrantでの再登録を失効させる。
   */
  async consumeInteractionChecked(uid: string, csrf: string, token: string): Promise<CheckedConsent> {
    const receiver = this.#d.receiverSubscriptions;
    const ref = this.#interactionRef(uid);
    return this.#d.db.runTransaction(
      async (tx): Promise<CheckedConsent> => {
        const data = (await tx.get(ref)).data() as Record<string, unknown> | undefined;
        const ownerId = data !== undefined && typeof data.ownerId === 'string' ? data.ownerId : null;
        const ownerRef = ownerId === null ? null : this.#ownerRef(ownerId);
        const owner = ownerRef === null ? undefined : (await tx.get(ownerRef)).data();
        const subscriptionRef = receiver !== undefined && ownerId !== null ? receiver.refFor(ownerId) : null;
        const subscription = subscriptionRef === null ? null : await tx.get(subscriptionRef);
        const access = await this.#accessForOwner(tx, owner);
        // 時刻は全ての読取りの後に読む（期限・無活動の判定を古い時刻で通さない）。
        const at = this.#d.clock.now();
        if (data === undefined || data.state !== 'authenticated' || typeof data.expiresAt !== 'number' || at >= data.expiresAt) return undefined;
        if (!this.#csrfMatches(data, csrf) || ownerId === null || ownerRef === null || typeof data.authTimeSec !== 'number') return undefined;
        if (typeof data.accessGeneration !== 'string') return undefined;
        if (!this.#activeOwner(owner, at)) return undefined;
        if (access.kind === 'unavailable') throw new AccessUnavailableError();
        if (access.kind === 'denied' || access.generation !== data.accessGeneration) {
          tx.update(ref, { state: 'done', csrfHash: null });
          return 'denied';
        }
        if ((data.loginMethod === 'reviewer') !== (owner?.loginKind === 'reviewer')) return undefined;
        const consent = { ownerId, authTimeSec: data.authTimeSec, accessGeneration: data.accessGeneration };
        if (receiver === undefined || subscription === null || subscriptionRef === null) {
          const receiverGeneration = receiverGenerationOrUnavailable(owner);
          tx.update(ref, { state: 'done', csrfHash: null });
          return { ...consent, ...(receiverGeneration > 0 ? { receiverGeneration } : {}) };
        }
        if (typeof data.csrfHash !== 'string') return undefined;
        let present: boolean;
        let expected: string;
        try {
          present = receiverSettingsPresent(subscription, ownerId, receiver.policy);
          expected = this.#hash('receiver-reset', receiverSnapshotMaterial({ interactionUid: uid, csrfHash: data.csrfHash, ownerId, subscription, present, ownerData: owner }));
        } catch (error) {
          if (error instanceof ReceiverResetUnavailableError) throw new AccessUnavailableError();
          throw error;
        }
        if (typeof token !== 'string' || token.length === 0 || !hashesEqual(expected, token)) return 'changed';
        if (!present) {
          const receiverGeneration = receiverGenerationOrUnavailable(owner);
          tx.update(ref, { state: 'done', csrfHash: null });
          return { ...consent, ...(receiverGeneration > 0 ? { receiverGeneration } : {}) };
        }
        const previousGrant = this.#d.connectedApps && subscription.exists
          ? parseKmsState(subscription.data(), ownerId, receiver.policy).active?.grantId
          : undefined;
        const previous = previousGrant ? await this.#sources?.grantStateIn(tx, this.#hash('grant', previousGrant)) : undefined;
        const previousSource = previous?.kind === 'bound' ? previous.binding : undefined;
        if (this.#d.clock.now() >= data.expiresAt || !this.#activeOwner(owner, this.#d.clock.now())) return undefined;
        let writes: ReturnType<typeof receiverResetWrites>;
        try {
          writes = receiverResetWrites(ownerId, owner);
        } catch (error) {
          if (error instanceof ReceiverResetUnavailableError) throw new AccessUnavailableError();
          throw error;
        }
        tx.update(ref, { state: 'done', csrfHash: null });
        tx.update(ownerRef, writes.ownerUpdate);
        tx.set(subscriptionRef, writes.subscriptionDoc);
        return { ...consent, receiverGeneration: writes.receiverGeneration, receiverReset: true, ...(previousSource === undefined ? {} : { previousSource }) };
      },
      { maxAttempts: 1 },
    );
  }

  /** 拒否の操作。CSRFが一致する時だけ閉じる。 */
  async closeInteraction(uid: string, csrf: string): Promise<boolean> {
    const ref = this.#interactionRef(uid);
    return this.#d.db.runTransaction(async (tx) => {
      const data = (await tx.get(ref)).data() as Record<string, unknown> | undefined;
      if (data === undefined || data.state === 'done' || !this.#csrfMatches(data, csrf)) return false;
      tx.update(ref, { state: 'done', csrfHash: null });
      return true;
    });
  }

  async authorizeConnectedAppsIn(tx: Transaction, ownerId: string, grantId: string, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }) {
    const bindingRef = this.grantSourceDocRef(grantId);
    if (!this.#d.connectedApps || bindingRef === null) return null;
    const [owner, grant, meta, binding] = await tx.getAll(
      this.ownerDocRef(ownerId), this.grantDocRef(grantId), this.grantMetaDocRef(grantId), bindingRef,
    );
    const data = owner!.data();
    const access = await this.#accessForOwner(tx, data);
    const at = this.#d.clock.now();
    const identityHash = ownerIdentityHash(data);
    if (operation.signal.aborted || at >= operation.deadlineAt || identityHash === null ||
        !this.#activeOwner(data, at) || !this.grantDocLive(grant!.data(), ownerId, grantId, at) ||
        !isAccountGrant(binding!.data()) || grantUseVerdict(access, grantGenerationOfSnapshot(meta!), ownerId, at).kind !== 'allowed') return null;
    const receiverGeneration = receiverGenerationOrUnavailable(data);
    if (receiverGeneration !== grantReceiverGenerationOf(meta!.data())) return null;
    return { identityHash, receiverGeneration };
  }

  async pairingOwnerIn(tx: Transaction, identity: VerifiedIdentity, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }) {
    const ref = this.#identityRef(identity);
    const mapped = (await tx.get(ref)).data();
    if (typeof mapped?.ownerId !== 'string') return null;
    const owner = (await tx.get(this.#ownerRef(mapped.ownerId))).data();
    const access = await this.#accessForOwner(tx, owner);
    const at = this.#d.clock.now();
    if (operation.signal.aborted || at >= operation.deadlineAt || ownerIdentityHash(owner) !== ref.id ||
        !this.#activeOwner(owner, at) || access.kind !== 'allowed') return null;
    return { identityHash: ref.id, receiverGeneration: receiverGenerationOrUnavailable(owner) };
  }

  // ---- Grantの同意記録 ----

  /**
   * 同意したGrantの記録を作る。同じtransactionでownerの許可recordを読み、activeかつ同意（login）時と同じ世代の時だけ作る。
   * 停止・再登録を跨いだら作らず'denied'（そのGrantはmetadataなしで新規利用に使えない）。不正・障害はAccessUnavailableError。
   */
  async putGrantMeta(grantId: string, record: ConsentRecord, approval?: SourceApprovalRequest): Promise<'created' | 'denied'> {
    const metaRef = this.#grantMetaRef(grantId);
    const ownerRef = this.#ownerRef(record.ownerId);
    const sources = this.#sources;
    const account = this.#d.connectedApps === true;
    if (sources !== undefined && !account && approval === undefined) return 'denied';
    return this.#d.db.runTransaction(async (tx): Promise<'created' | 'denied'> => {
      const owner = (await tx.get(ownerRef)).data();
      const access = await this.#accessForOwner(tx, owner);
      // strict: 同じ本人（owner文書のidentityHash）・client・resourceの承認とsourceを同じtransactionで読み、全readの後の時刻で判定する。
      const identityHash = ownerIdentityHash(owner);
      const judgeApproval =
        sources !== undefined && !account && approval !== undefined && identityHash !== null
          ? await sources.readApprovalIn(tx, { approvalId: approval.approvalId, identityHash, clientHash: approval.clientHash, resourceHash: approval.resourceHash })
          : undefined;
      const accountWrites = account && sources !== undefined && identityHash !== null
        ? await sources.accountGrantWritesIn(tx, identityHash, this.#hash('grant', grantId), record.previousSource)
        : undefined;
      const now = this.#d.clock.now();
      if (access.kind === 'unavailable') throw new AccessUnavailableError();
      if (access.kind === 'denied' || access.generation !== record.accessGeneration) return 'denied';
      // 同意の時に捕捉した受信reset世代が、ownerの現在の値と同じ時だけ作る（後の別のresetを跨いだ同意を、現在の値で救済しない）。
      const captured = record.receiverGeneration ?? 0;
      if (!Number.isSafeInteger(captured) || captured < 0) return 'denied';
      if (receiverGenerationOrUnavailable(owner) !== captured) return 'denied';
      if (account) {
        if (accountWrites === undefined) return 'denied';
        accountWrites();
      } else if (sources !== undefined) {
        const approved = judgeApproval?.(now);
        if (approved === undefined || approved.kind !== 'usable') return 'denied';
        // 承認の単回消費とGrantへのbindingを、grantMetaの作成と同じtransactionで書く。
        approved.apply();
        sources.bindGrantIn(tx, this.#hash('grant', grantId), approved.binding);
      }
      tx.create(metaRef, {
        ownerId: record.ownerId,
        authTimeSec: record.authTimeSec,
        createdAt: this.#d.clock.now(),
        accessGeneration: record.accessGeneration,
        // 既存の0は書かない（従来の形のまま）。
        ...(captured > 0 ? { [RECEIVER_GENERATION_FIELD]: captured } : {}),
      });
      return 'created';
    });
  }

  /** 同意記録のowner・認証時刻。新規利用の世代の判定はgrantUsableで行う。 */
  async grantMeta(grantId: string): Promise<{ readonly ownerId: string; readonly authTimeSec: number } | undefined> {
    const data = (await this.#grantMetaRef(grantId).get()).data() as { ownerId?: unknown; authTimeSec?: unknown } | undefined;
    if (typeof data?.ownerId !== 'string' || typeof data.authTimeSec !== 'number') return undefined;
    return { ownerId: data.ownerId, authTimeSec: data.authTimeSec };
  }

  // ---- client assertionの単回予約 ----

  readonly assertionReplay: AssertionReplayStore = {
    reserve: (key, expiresAt, now) => {
      const ref = this.#root.collection('replay').doc(this.#hash('assertion', key));
      return this.#d.db.runTransaction(async (tx) => {
        const data = (await tx.get(ref)).data() as { expiresAt?: unknown } | undefined;
        if (data !== undefined && typeof data.expiresAt === 'number' && now < data.expiresAt) return false;
        tx.set(ref, { expiresAt });
        return true;
      });
    },
  };
}
