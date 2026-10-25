/** 独自APIのエラー。応答は `{"error":{"code","retryable"}}` だけで、入力値や理由の詳細を載せない。 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly retryable = false,
  ) {
    super(code);
    this.name = 'ApiError';
  }
}

export const apiErrors = {
  invalidRequest: () => new ApiError(400, 'invalid_request'),
  authenticationRequired: () => new ApiError(401, 'authentication_required'),
  forbidden: () => new ApiError(403, 'forbidden'),
  notFound: () => new ApiError(404, 'not_found'),
  /** 接続画面のinteractionが無い・期限切れ・別browser・CSRF不一致を区別しない。 */
  linkUnavailable: () => new ApiError(404, 'link_unavailable'),
  methodNotAllowed: () => new ApiError(405, 'method_not_allowed'),
  /** 一時的に処理できない（期限・中止・閉鎖・依存先の障害）。 */
  temporarilyUnavailable: () => new ApiError(503, 'temporarily_unavailable', true),
};
