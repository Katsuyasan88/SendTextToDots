/** 通常ログ。イベント名と分類だけを渡し、token・コード・nonce・本文・URLのqueryを渡さない。 */
export type LogSink = (entry: { readonly event: string; readonly [field: string]: string | number }) => void;
