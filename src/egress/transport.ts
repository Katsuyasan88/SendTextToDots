// 検証済みの1つのIPへ固定したHTTPS送出。Node 22.20.0の公開API（https.request、netのcustom lookup、tlsの検証）だけを使う。
// 宛先の検証と選択は呼び出し側（safe-egress.ts）の責務で、ここは渡されたpinへ接続することと、TLS・redirect・圧縮・
// 応答上限を守ることだけを行う。期限は持たず、signalの中断でsocketを破棄する。呼び出し側の期限が過ぎたかは
// expiredで尋ね、TLSの成立が期限後なら要求を流さない。

import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';
import type { TLSSocket } from 'node:tls';

import { sameAddress } from './ip-policy.js';

/**
 * 送出の固定分類。URL・IP・本文・元例外は含めない。
 * invalid_request: 許可していない見出しや形の要求（呼び出し側の誤り）。
 */
export type EgressFailure =
  | 'invalid_request'
  | 'invalid_url'
  | 'destination_forbidden'
  | 'dns_failed'
  | 'connect_failed'
  | 'tls_failed'
  | 'timeout'
  | 'aborted'
  | 'redirect'
  | 'compressed_response'
  | 'response_too_large'
  | 'protocol_error';

/** messageは分類名だけで、causeを持たない。 */
export class EgressError extends Error {
  constructor(readonly kind: EgressFailure) {
    super(kind);
    this.name = 'EgressError';
  }
}

export interface PinnedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export interface EgressResponse {
  readonly status: number;
  /** 2xxの本文（上限内）。それ以外のstatusでは読まずに空。 */
  readonly body: string;
}

export interface PinnedRequest {
  readonly method: 'GET' | 'POST';
  /** canonical hostname、またはIP literal（IPv6は角括弧なし）。 */
  readonly hostname: string;
  readonly hostHeader: string;
  readonly ipLiteral: boolean;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string | undefined;
  readonly pin: PinnedAddress;
  /** pinだけを返す名前解決。接続時に別の解決をさせない。 */
  readonly lookup: LookupFunction;
  readonly port: number;
  readonly ca?: string | Buffer | undefined;
  readonly maxResponseBytes: number;
}

/** 名前解決をせず、検証済みの1つのIPだけを返すlookup。 */
export function pinnedLookup(pin: PinnedAddress): LookupFunction {
  return (_hostname, options, callback) => {
    if (options.all) callback(null, [{ address: pin.address, family: pin.family }]);
    else callback(null, pin.address, pin.family);
  };
}

function isCompressed(headers: NodeJS.Dict<string | string[]>): boolean {
  const values = (name: string) => [headers[name] ?? []].flat().flatMap((value) => value.split(','));
  const tokens = (name: string) => values(name).map((value) => value.trim().toLowerCase()).filter(Boolean);
  return (
    tokens('content-encoding').some((token) => token !== 'identity') ||
    tokens('transfer-encoding').some((token) => token !== 'chunked' && token !== 'identity')
  );
}

export function sendPinned(
  request: PinnedRequest,
  signal: AbortSignal,
  expired: () => boolean = () => false,
): Promise<EgressResponse> {
  return new Promise((resolve, reject) => {
    const { pin, maxResponseBytes } = request;
    let settled = false;
    let tcpConnected = false;
    let secured = false;

    const settle = (complete: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      // 完了・失敗のどちらでもsocketを残さない（接続を使い回さない）。
      req.destroy();
      complete();
    };
    const fail = (kind: EgressFailure) => settle(() => reject(new EgressError(kind)));
    const onAbort = () => fail('aborted');

    const body = request.body === undefined ? undefined : Buffer.from(request.body, 'utf8');
    let req: ReturnType<typeof httpsRequest>;
    try {
      req = httpsRequest({
        host: request.hostname,
        port: request.port,
        method: request.method,
        path: request.path,
        headers: {
          ...request.headers,
          host: request.hostHeader,
          connection: 'close',
          // 圧縮を要求しない。圧縮された応答は下で拒否する。
          'accept-encoding': 'identity',
          ...(body === undefined ? {} : { 'content-length': String(body.length) }),
        },
        // 接続を使い回さない。proxy用のagentも使わない。
        agent: false,
        lookup: request.lookup,
        family: pin.family,
        rejectUnauthorized: true,
        // DNS名は元hostnameのSNIと標準のcheckServerIdentity。IP literalはSNIなしでIPの証明書照合。
        ...(request.ipLiteral ? {} : { servername: request.hostname }),
        ...(request.ca === undefined ? {} : { ca: request.ca }),
      });
    } catch {
      reject(new EgressError('invalid_request'));
      return;
    }

    const peerIsPinned = (socket: TLSSocket) =>
      typeof socket.remoteAddress === 'string' && sameAddress(socket.remoteAddress, pin.address);

    req.on('socket', (socket) => {
      const tlsSocket = socket as TLSSocket;
      tlsSocket.once('connect', () => {
        tcpConnected = true;
        // 接続先が選択したIPでなければ、要求を流す前に破棄する。
        if (!peerIsPinned(tlsSocket)) fail('connect_failed');
      });
      tlsSocket.once('secureConnect', () => {
        if (!peerIsPinned(tlsSocket)) fail('connect_failed');
        else if (!tlsSocket.authorized) fail('tls_failed');
        // 期限のタイマーが遅れていても、期限後に成立したTLSへは要求を流さない。
        else if (expired()) fail('timeout');
        else secured = true;
      });
    });

    req.on('error', () => {
      if (!tcpConnected) fail('connect_failed');
      else if (!secured) fail('tls_failed');
      else fail('protocol_error');
    });
    req.on('upgrade', () => fail('protocol_error'));

    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      // redirectは追わない。Locationも読まない。
      if (status >= 300 && status <= 399) return fail('redirect');
      if (status < 200 || status > 299) return settle(() => resolve({ status, body: '' }));
      if (isCompressed(res.headers)) return fail('compressed_response');
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxResponseBytes) return fail('response_too_large');

      // Content-Lengthに頼らず、受け取ったバイト数で上限を見る。
      const chunks: Buffer[] = [];
      let received = 0;
      res.on('data', (chunk: Buffer) => {
        received += chunk.length;
        if (received > maxResponseBytes) fail('response_too_large');
        else chunks.push(chunk);
      });
      res.on('end', () => settle(() => resolve({ status, body: Buffer.concat(chunks).toString('utf8') })));
      res.on('error', () => fail('protocol_error'));
      res.on('close', () => fail('protocol_error'));
    });

    if (signal.aborted) return fail('aborted');
    signal.addEventListener('abort', onAbort, { once: true });
    req.end(body);
  });
}

/** 指示の配送（sendPinnedCommand）の応答。statusだけで、本文・見出しは運ばない。 */
export interface CommandEgressResponse {
  readonly status: number;
}

export interface PinnedCommandRequest {
  /** canonical hostname、またはIP literal（IPv6は角括弧なし）。 */
  readonly hostname: string;
  readonly hostHeader: string;
  readonly ipLiteral: boolean;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  /** 送る本文のbytes。借りるだけで、ここで作る写しだけを送出へ渡す。 */
  readonly body: Buffer;
  readonly pin: PinnedAddress;
  /** pinだけを返す名前解決。接続時に別の解決をさせない。 */
  readonly lookup: LookupFunction;
  readonly port: number;
  readonly ca?: string | Buffer | undefined;
}

/**
 * 指示の配送用のPOST。sendPinnedとは別の入口で、本文はBufferのまま送り、応答はstatusだけを返す。
 * 本文は、ここで作る写し（owned）だけをreq.endへ渡す。結果（status・失敗の分類）が決まったら応答と要求を破棄し、
 * 実際のClientRequestのcloseを待って、写しを0で上書きしてから返す。closeより前に写しを消さない（送出の途中のbytesを壊さない）。
 * 2xxの本文は読まずに捨てる（溜めない・解釈しない）。巨大・圧縮・終わらない本文は、statusの判定を変えない。
 * 3xxはredirect、200〜599以外のstatusはprotocol_error。beforeSendは、TLSの成立の直後・要求を流す前に1回だけ尋ね、
 * 分類が返れば要求を流さずに止める。
 */
export function sendPinnedCommand(
  request: PinnedCommandRequest,
  signal: AbortSignal,
  beforeSend: () => EgressFailure | null = () => null,
): Promise<CommandEgressResponse> {
  return new Promise((resolve, reject) => {
    const { pin } = request;
    if (!Buffer.isBuffer(request.body)) {
      reject(new EgressError('invalid_request'));
      return;
    }
    const owned = Buffer.allocUnsafeSlow(request.body.length);
    request.body.copy(owned);

    let decided = false;
    let finish: () => void = () => {};
    let tcpConnected = false;
    let secured = false;

    let req: ReturnType<typeof httpsRequest>;
    try {
      req = httpsRequest({
        host: request.hostname,
        port: request.port,
        method: 'POST',
        path: request.path,
        headers: {
          ...request.headers,
          host: request.hostHeader,
          connection: 'close',
          'accept-encoding': 'identity',
          'content-length': String(owned.length),
        },
        // 接続を使い回さない。proxy用のagentも使わない。
        agent: false,
        lookup: request.lookup,
        family: pin.family,
        rejectUnauthorized: true,
        ...(request.ipLiteral ? {} : { servername: request.hostname }),
        ...(request.ca === undefined ? {} : { ca: request.ca }),
      });
    } catch {
      // 要求を組み立てられなかった。送出は始まっていないので、すぐに消す。
      owned.fill(0);
      reject(new EgressError('invalid_request'));
      return;
    }

    let response: { destroy(): unknown } | null = null;
    /** 最初の結果だけを採る。応答と要求を破棄し、返すのはcloseの後。 */
    const decide = (complete: () => void) => {
      if (decided) return;
      decided = true;
      finish = complete;
      signal.removeEventListener('abort', onAbort);
      response?.destroy();
      req.destroy();
    };
    const fail = (kind: EgressFailure) => decide(() => reject(new EgressError(kind)));
    const onAbort = () => fail('aborted');

    // 実際の要求のclose。ここより後に、送出が写しを読むことはない。
    req.once('close', () => {
      owned.fill(0);
      // 結果が決まる前に閉じた（応答なしの切断）。
      if (!decided) {
        decided = true;
        signal.removeEventListener('abort', onAbort);
        finish = () => reject(new EgressError(!tcpConnected ? 'connect_failed' : !secured ? 'tls_failed' : 'protocol_error'));
      }
      finish();
    });

    const peerIsPinned = (socket: TLSSocket) =>
      typeof socket.remoteAddress === 'string' && sameAddress(socket.remoteAddress, pin.address);

    req.on('socket', (socket) => {
      const tlsSocket = socket as TLSSocket;
      tlsSocket.once('connect', () => {
        tcpConnected = true;
        if (!peerIsPinned(tlsSocket)) fail('connect_failed');
      });
      tlsSocket.once('secureConnect', () => {
        if (!peerIsPinned(tlsSocket)) return fail('connect_failed');
        if (!tlsSocket.authorized) return fail('tls_failed');
        let blocked: EgressFailure | null;
        try {
          blocked = beforeSend();
        } catch {
          blocked = 'aborted';
        }
        if (blocked !== null) fail(blocked);
        else secured = true;
      });
    });

    // 破棄の後のerror（socket hang up等）は、決まった結果を変えない。
    req.on('error', () => {
      if (!tcpConnected) fail('connect_failed');
      else if (!secured) fail('tls_failed');
      else fail('protocol_error');
    });
    req.on('upgrade', () => fail('protocol_error'));

    req.on('response', (res) => {
      response = res;
      res.on('error', () => {});
      const status = res.statusCode ?? 0;
      // redirectは追わない。Locationも読まない。
      if (status >= 300 && status <= 399) return fail('redirect');
      if (!Number.isInteger(status) || status < 200 || status > 599) return fail('protocol_error');
      // statusが決まった時点で受領の判定は終わり。本文は読まずに、応答ごと破棄する。
      decide(() => resolve({ status }));
    });

    if (signal.aborted) return fail('aborted');
    signal.addEventListener('abort', onAbort, { once: true });
    req.end(owned);
  });
}
