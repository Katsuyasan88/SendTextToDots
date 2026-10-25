// callback検証（events/subscriptions.tsのVerificationSender）を安全な送出へつなぐadapter。
// 送出の固定分類を、購読runtimeが返すcallback reasonへ対応させる。URL・IP・元例外は運ばない。

import { VerificationSendError, type VerificationFailure, type VerificationSender } from '../events/subscriptions.js';
import type { SafeEgress } from './safe-egress.js';
import { EgressError, type EgressFailure } from './transport.js';

const REASONS: Readonly<Record<EgressFailure, VerificationFailure>> = Object.freeze({
  dns_failed: 'connection_refused',
  connect_failed: 'connection_refused',
  timeout: 'timeout',
  tls_failed: 'tls_error',
  // 宛先ポリシーの拒否・redirect・圧縮/巨大応答・その他は、検証不成立として閉じる。
  invalid_request: 'challenge_failed',
  invalid_url: 'challenge_failed',
  destination_forbidden: 'challenge_failed',
  aborted: 'challenge_failed',
  redirect: 'challenge_failed',
  compressed_response: 'challenge_failed',
  response_too_large: 'challenge_failed',
  protocol_error: 'challenge_failed',
});

export function createEgressVerificationSender(egress: SafeEgress): VerificationSender {
  return async (request, signal) => {
    try {
      return await egress.postCallback(request.url, { headers: request.headers, body: request.body }, { signal });
    } catch (error) {
      throw new VerificationSendError(error instanceof EgressError ? REASONS[error.kind] : 'challenge_failed');
    }
  };
}
