// 保存portの共有の形（購読状態の読取り形と、client assertionの単回予約）。

/** 購読の期限。明示`ttlMs:null`の無期限購読は`null`で保存する。 */
export type SubscriptionExpiry = number | null;

/** 有効な購読。callback URLとsecretは封緘済みの値だけを持ち、平文は渡さない。 */
export interface SubscriptionRecordOf<E extends SubscriptionExpiry> {
  readonly id: string;
  readonly ownerId: string;
  /**
   * この購読を検証したOAuth grantの内部参照。identity（id）には含めず、外部の入力・応答にも出さない。
   * 再検証を通した付け替えでだけ変わる。
   */
  grantId: string;
  readonly sealedUrl: string;
  sealedSecret: string;
  /** 現行secretの鍵付きhash。同じsecretでの更新か、鍵の更新かを復号せずに判定する。 */
  secretHash: string;
  /** 鍵更新の直前のsecret。untilを過ぎたら破棄する。 */
  previousSecret: { readonly sealed: string; readonly until: number } | null;
  /** nullは無期限。owner/grant/tokenの失効・本人解除は別に効く。 */
  expiresAt: E;
}

export interface OwnerSubscriptionStateOf<E extends SubscriptionExpiry> {
  /** 期限内の購読だけ。期限切れはloadの時点で破棄済み。 */
  readonly active: SubscriptionRecordOf<E> | null;
  /**
   * 最後に検証を通した送信先のidentity（id）。期限切れ・取消の後も残し、別の送信先が端末承認なしで
   * 有効になる抜け道を塞ぐ。URLとsecretは含まない。
   */
  readonly knownDestinationId: string | null;
  /** 端末承認待ちの別の送信先。id・要求元grantの内部参照・要求時刻だけで、URLとsecretは保存しない。 */
  readonly pending: { readonly id: string; readonly grantId: string; readonly requestedAt: number } | null;
  /** 直前の購読の終わり方。grant_endedは束縛したgrantの失効による取り下げ。更新（再有効化）でnullへ戻る。 */
  readonly lastEnded: 'expired' | 'cancelled' | 'grant_ended' | null;
}

/**
 * private_key_jwtのclient assertion（client_idとjtiの組）の単回性。固定oidc-providerの標準のreplay記録は
 * 検索の後に保存するため、同時要求の単回性はここで担保する。
 */
export interface AssertionReplayStore {
  /**
   * 原子的。keyが未予約（または期限切れ）のときだけexpiresAtまで予約してtrueを返す。予約済みならfalseで、何も変えない。
   * 同じkeyの同時予約は1つだけ成功する。容量上限に達して予約できないときもfalse（受け付けない側へ倒す）。
   */
  reserve(key: string, expiresAt: number, now: number): Promise<boolean>;
}
