// 指示入力の検証が返す固定エラー（送信APIのserviceが受付時刻・期限の失敗を区別する）。

export type CommandInputErrorCode = 'invalid_request' | 'clock_skew' | 'command_expired';

/** 入力検証の失敗。codeだけを持ち、message・入力の値・causeは応答にもログにも出さない。 */
export class CommandApiError extends Error {
  constructor(readonly code: CommandInputErrorCode) {
    super(code);
    this.name = 'CommandApiError';
  }
}
