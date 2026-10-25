// OAuth access tokenから解決した要求元と、接続Web（GET /v1/web/connection）の状態判定。

import type { SubscriptionView } from '../events/subscriptions.js';

export interface ResolvedOAuthOwner {
  readonly ownerId: string;
  /** このtokenを発行したgrantの内部参照。購読の束縛に使い、外部の入力・応答には出さない。 */
  readonly grantId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** access tokenの期限（epoch秒）。 */
  readonly expiresAt: number;
}

export type ConnectionState = 'unlinked' | 'linked' | 'subscribed' | 'expired' | 'change_pending';

export interface ConnectionServiceDeps {
  /** ownerの購読の見え方。束縛したgrantが失効した購読・保留は、ここで取り下げられて見えなくなる。 */
  readonly subscriptions: { viewFor(ownerId: string): Promise<SubscriptionView> };
  /** access token発行済みの有効Grantがあるか（保存側がGrantと発行済みの印を同じ読取りで確かめる）。失敗は例外のまま伝える。 */
  readonly issuedGrantSource: (ownerId: string) => Promise<boolean>;
}

/**
 * 接続状態。優先順位は docs/API.md §3: 有効grantなし→unlinked、承認待ちの送信先置換→change_pending、有効な購読→subscribed、
 * 直前の購読が期限切れ→expired、それ以外（未作成・明示取消）→linked。「有効grant」は「clientへaccess tokenを発行済みで、そのGrantが
 * 有効」。元browserの完了だけ（コード未交換）では数えない。grantが無効なら購読の状態に関係なくunlinkedで、購読の期限切れをgrantの失効と
 * 混ぜない。購読と保留は、それぞれを束縛したgrantが有効なものだけを数える。
 */
export class ConnectionService {
  readonly #deps: ConnectionServiceDeps;

  constructor(deps: ConnectionServiceDeps) {
    this.#deps = deps;
  }

  async stateFor(ownerId: string): Promise<ConnectionState> {
    const linked = await this.#deps.issuedGrantSource(ownerId);
    // 有効grantがなくても購読側を通し、失効したgrantに束縛された購読・保留を取り下げさせる。
    const view = await this.#deps.subscriptions.viewFor(ownerId);
    if (!linked) return 'unlinked';
    return view === 'none' ? 'linked' : view;
  }
}
