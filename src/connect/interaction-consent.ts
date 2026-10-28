// OAuth interactionの同意（POST）の手順を、純粋なport（保存・Grant・redirect・応答状態・ログ）だけで行う。HTTP・cookie・HTMLはserver側。
//   1. 同意の消費（保存の1つのtransaction。受信先設定の削除の確認と同時）。未確認・表示後の変化は消費・削除0で再表示。
//   2. 段階A: ownerの現在のactive → Grantの保存 → grantMeta（利用許可の世代と受信reset世代を同じtransactionで再確認）。
//   3. 段階B: redirect（interactionFinished）。
// 受信先設定を消した（確定した）後の失敗は、段階で分けて固定の結果にする: 段階Aは「削除済み・接続未完了」（incomplete）、段階Bは
// 「削除済み・結果未確認」（unknown）、応答の後は二重に書かない（none）。確認付きの消費そのものが例外で終わった時は、削除の成否も断定しない
// （reset_unknown）。削除の無い同意の失敗は、従来どおり（例外はそのまま、metadataの不成立はaccess_denied）。秘密・ID・例外の原文を返さない。

import type { CheckedConsent, ConsentRecord } from './firestore.js';

export interface ConsentPorts {
  /** 同意の消費（CSRF・snapshot token・確認の有無）。 */
  consume(input: { readonly csrf: string; readonly token: string; readonly confirm: boolean }): Promise<CheckedConsent>;
  isOwnerActive(ownerId: string): Promise<boolean>;
  /** 同意したownerのGrantを保存してIDを返す。 */
  saveGrant(ownerId: string): Promise<string>;
  putGrantMeta(grantId: string, consent: ConsentRecord): Promise<'created' | 'denied'>;
  /** redirect（interactionFinished）。 */
  finish(ownerId: string, grantId: string): Promise<void>;
  /** 応答のheaderを既に送ったか。 */
  headersSent(): boolean;
  log(entry: { readonly event: string; readonly category?: string }): void;
}

export type ConsentResult =
  | { readonly kind: 'finished' }
  | { readonly kind: 'link_unavailable' }
  | { readonly kind: 'access_denied' }
  | { readonly kind: 'reshow' }
  | { readonly kind: 'receiver_reset'; readonly outcome: 'incomplete' | 'unknown' | 'reset_unknown' }
  | { readonly kind: 'none' };

export async function runConsent(ports: ConsentPorts, input: { readonly csrf: string; readonly token: string; readonly confirm: boolean }): Promise<ConsentResult> {
  let consent: CheckedConsent;
  try {
    consent = await ports.consume(input);
  } catch (error) {
    // 確認付きの消費（削除を含み得るtransaction）の結果が不明。削除済みとも未削除とも断定しない。
    if (input.confirm) {
      ports.log({ event: 'interaction.receiver_reset_incomplete', category: 'reset_unknown' });
      return { kind: 'receiver_reset', outcome: 'reset_unknown' };
    }
    throw error;
  }
  if (consent === undefined) return { kind: 'link_unavailable' };
  if (consent === 'denied') return { kind: 'access_denied' };
  if (consent === 'changed' || consent === 'confirm_required') return { kind: 'reshow' };
  const reset = consent.receiverReset === true;
  if (reset) ports.log({ event: 'interaction.receiver_reset' });
  const incomplete = (): ConsentResult => {
    ports.log({ event: 'interaction.receiver_reset_incomplete', category: 'incomplete' });
    return { kind: 'receiver_reset', outcome: 'incomplete' };
  };
  // 段階A: owner・Grant・grantMeta。
  let grantId: string;
  try {
    if (!(await ports.isOwnerActive(consent.ownerId))) return reset ? incomplete() : { kind: 'link_unavailable' };
    grantId = await ports.saveGrant(consent.ownerId);
    if ((await ports.putGrantMeta(grantId, consent)) !== 'created') return reset ? incomplete() : { kind: 'access_denied' };
  } catch (error) {
    if (!reset) throw error;
    return incomplete();
  }
  ports.log({ event: 'interaction.consented' });
  // 段階B: redirect。
  try {
    await ports.finish(consent.ownerId, grantId);
    return { kind: 'finished' };
  } catch (error) {
    if (!reset) throw error;
    if (ports.headersSent()) return { kind: 'none' };
    ports.log({ event: 'interaction.receiver_reset_incomplete', category: 'unknown' });
    return { kind: 'receiver_reset', outcome: 'unknown' };
  }
}
