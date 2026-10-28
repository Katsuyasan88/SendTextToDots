/** 通常ログ。イベント名と分類だけを渡し、token・コード・nonce・本文・URLのqueryを渡さない。 */
export type LogSink = (entry: { readonly event: string; readonly [field: string]: string | number }) => void;

/** 接続serverの期限付き診断ログを有効にする環境変数（既定off）。値はRFC3339 UTCの終了時刻。 */
export const CONNECT_DIAGNOSTICS_ENV = 'STTD_CONNECT_DIAGNOSTICS_UNTIL';
/** 診断ログを有効にできる最長の期間（起動時刻からの終了時刻）。 */
export const CONNECT_DIAGNOSTICS_MAX_WINDOW_MS = 30 * 60_000;
/** 1 processで出す診断ログの最大件数。 */
export const CONNECT_DIAGNOSTICS_MAX_EVENTS = 64;

/**
 * 出してよいevent（固定）と、各eventで出してよいcategory（固定）。categoryを持たないeventは空配列。
 * 一覧に無いeventは捨て、一覧に無いcategoryは`other`にする（入力の文字列をそのまま出さない）。
 */
const DIAGNOSTIC_EVENTS: ReadonlyMap<string, readonly string[]> = new Map([
  ['interaction.login', []],
  ['interaction.consented', []],
  ['interaction.access_denied', []],
  ['interaction.denied', []],
  ['web.disconnected', []],
  ['interaction.receiver_reset', []],
  ['interaction.receiver_reset_incomplete', ['incomplete', 'unknown', 'reset_unknown']],
  ['oauth.server_error', ['authorization_code', 'refresh_token']],
  ['oauth.request_error', ['authorization_code', 'refresh_token']],
  ['oauth.grant_revoked', ['Grant', 'AccessToken', 'AuthorizationCode', 'RefreshToken']],
  ['events.subscribed', []],
  [
    'events.subscribe_failed',
    [
      'invalid_request',
      'unknown_event',
      'cursor_unsupported',
      'destination_change_pending',
      'grant_inactive',
      'conflict',
      'callback_endpoint.connection_refused',
      'callback_endpoint.timeout',
      'callback_endpoint.tls_error',
      'callback_endpoint.http_4xx',
      'callback_endpoint.http_5xx',
      'callback_endpoint.challenge_failed',
      'context_unavailable',
      'request_rejected',
    ],
  ],
]);

const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;

/** 終了時刻の文字列を検査する。RFC3339 UTCで、起動時刻より未来かつ30分以内の時だけepoch ms。それ以外はundefined（＝off）。 */
export function parseDiagnosticsUntil(value: unknown, nowMs: number): number | undefined {
  if (typeof value !== 'string' || !RFC3339_UTC.test(value) || !Number.isSafeInteger(nowMs)) return undefined;
  const until = Date.parse(value);
  if (!Number.isFinite(until) || until <= nowMs || until - nowMs > CONNECT_DIAGNOSTICS_MAX_WINDOW_MS) return undefined;
  return until;
}

export interface DiagnosticSinkOptions {
  /** 環境変数の値（未設定はundefined）。 */
  readonly until: unknown;
  /** 時計（epoch ms）。起動時と各記録時に読む。 */
  readonly now: () => number;
  /** 1行の書き出し（例: stdout）。失敗は呼出し元へ返さない。 */
  readonly write: (line: string) => void;
}

/**
 * 期限付きの診断ログsink。無効（未設定・不正・過去・30分超）ならundefined。
 * 出すのは `{"event": <固定>, "category": <固定>}` だけで、入力のほかのfield（UID・owner・Grant・token・本文・URL・error等）は出さない。
 * 期限を過ぎた後と、64件を出した後は何も出さない。書き出しの失敗は握りつぶし、呼出し元の処理を変えない。
 */
export function createDiagnosticLogSink(options: DiagnosticSinkOptions): LogSink | undefined {
  const { now, write } = options;
  let start: number;
  try {
    start = now();
  } catch {
    return undefined;
  }
  const until = parseDiagnosticsUntil(options.until, start);
  if (until === undefined) return undefined;
  let emitted = 0;
  return (entry) => {
    try {
      if (emitted >= CONNECT_DIAGNOSTICS_MAX_EVENTS) return;
      const at = now();
      if (!Number.isSafeInteger(at) || at >= until) return;
      const event = typeof entry?.event === 'string' ? entry.event : '';
      const categories = DIAGNOSTIC_EVENTS.get(event);
      if (categories === undefined) return;
      const raw = (entry as { readonly category?: unknown }).category;
      const line =
        categories.length === 0 || raw === undefined
          ? JSON.stringify({ event })
          : JSON.stringify({ event, category: typeof raw === 'string' && categories.includes(raw) ? raw : 'other' });
      emitted += 1;
      write(line);
    } catch {
      // 診断ログの失敗で、認証・取消・応答を変えない。
    }
  };
}
