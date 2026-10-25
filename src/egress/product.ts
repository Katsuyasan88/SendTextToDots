// 製品の送出構成（送信APIのcallback送出・MCPのCIMD取得とcallback検証）。引数も環境変数も受け取らず、宛先ポリシー・port・
// 信頼するCAを外から変えられない。

import { lookup } from 'node:dns/promises';

import { isPublicAddress } from './ip-policy.js';
import { createSafeEgress, type SafeEgress } from './safe-egress.js';

export function createProductEgress(): SafeEgress {
  return createSafeEgress({
    // IPv4/IPv6の全回答を、OSの返した順のまま受け取る。
    resolve: (hostname) => lookup(hostname, { all: true, verbatim: true }),
    isAllowedAddress: isPublicAddress,
    port: 443,
  });
}
