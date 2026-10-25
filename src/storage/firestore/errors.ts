/** 保存・状態の形の検査が外へ出す固定のエラー。文書の内容・SDKのメッセージ・比較した値を持たない。 */
export class StoreError extends Error {
  constructor(readonly code: 'store_error') {
    super(code);
    this.name = 'StoreError';
  }
}
