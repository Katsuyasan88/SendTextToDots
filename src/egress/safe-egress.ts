// 安全なHTTPS送出の境界（docs/SECURITY.md「安全なHTTPS送出」）。
// URLの検証、DNSの全回答の検証、1つのIPへの固定、絶対期限、見出しの制限をここで行い、接続はtransport.tsへ渡す。
// connectorは名前解決・宛先ポリシー・port・信頼するCAの差し替え口。製品の値はproduct.tsだけが組み立て、
// 試験はloopbackのTLS受信機へ向けるconnectorを試験側で組み立てる。ここに「private宛先を許可する」設定はない。

import { performance } from 'node:perf_hooks';

import {
  EgressError,
  pinnedLookup,
  sendPinned,
  sendPinnedCommand,
  type CommandEgressResponse,
  type EgressFailure,
  type EgressResponse,
  type PinnedAddress,
} from './transport.js';
import { parseIp } from './ip-policy.js';

/** DNS・接続・TLS・本文読取りを通した絶対期限の上限。 */
export const EGRESS_MAX_DEADLINE_MS = 10_000;
/** 応答本文の上限（バイト）。 */
export const EGRESS_MAX_RESPONSE_BYTES = 8192;
const MAX_URL_LENGTH = 2048;
/** 指示の配送の本文（eventのUTF-8）の上限（バイト）。 */
const MAX_COMMAND_BODY_BYTES = 8704;

/** callbackのPOSTで外へ出してよい見出し。これ以外は送らず、要求を拒否する。 */
const CALLBACK_HEADERS: ReadonlySet<string> = new Set([
  'content-type',
  'webhook-id',
  'webhook-timestamp',
  'webhook-signature',
  'x-mcp-subscription-id',
]);

export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}

export interface EgressConnector {
  /** hostnameのIPv4/IPv6の全回答。試行のたびに呼ばれ、結果は使い回さない。 */
  readonly resolve: (hostname: string) => Promise<readonly ResolvedAddress[]>;
  /** 接続してよいIPか。全回答とIP literalへ適用する。 */
  readonly isAllowedAddress: (address: string) => boolean;
  /** 接続先のport。URLが許すのは443だけで、製品もここは443。 */
  readonly port: number;
  /** 信頼するCA。製品は指定しない（Nodeの既定）。 */
  readonly ca?: string | Buffer | undefined;
}

export interface EgressOptions {
  /** 呼び出し元の中断。期限より先に来れば、そこで打ち切る。 */
  readonly signal?: AbortSignal | undefined;
  /** 呼び出し元の短い期限。上限（10秒）より長い値は上限で切る。 */
  readonly timeoutMs?: number | undefined;
}

export interface CallbackPost {
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** 指示の配送（postCommandCallback）だけの設定。 */
export interface CommandEgressOptions extends EgressOptions {
  /**
   * 呼び出し元の同期の確認（時刻・dispose）。名前解決の前、名前解決の後で接続の直前、TLSの成立の後で要求を流す直前に呼ぶ。
   * true以外・例外は、固定のabortedで送出を止める。認可の確認ではない。
   */
  readonly beforeConnect?: (() => boolean) | undefined;
}

export interface CommandCallbackPost {
  readonly headers: Readonly<Record<string, string>>;
  /** 送る本文のbytes（1〜8704）。借りるだけで、書き換えない。 */
  readonly body: Buffer;
}

export interface SafeEgress {
  /** CIMD/JWKS用。公開JSONを求める見出しだけでGETする。呼び出し元の見出しは受け取らない。 */
  getJson(url: string, options?: EgressOptions): Promise<EgressResponse>;
  /** callback用。本文と署名の見出しだけでPOSTする。 */
  postCallback(url: string, post: CallbackPost, options?: EgressOptions): Promise<EgressResponse>;
  /**
   * 指示の配送用。本文はBufferのまま、署名の見出しだけでPOSTし、応答のstatusだけを返す（本文は読まない）。
   * 本文は最初のawaitより前に写し、送出の実際のcloseの後に0で上書きしてから返す。
   */
  postCommandCallback(url: string, post: CommandCallbackPost, options?: CommandEgressOptions): Promise<CommandEgressResponse>;
}

export interface EgressTarget {
  /** canonical hostname、またはIP literal（IPv6は角括弧なし）。TLS照合とHostに使う。 */
  readonly hostname: string;
  readonly hostHeader: string;
  readonly ipLiteral: boolean;
  readonly path: string;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function hasForbiddenCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    // 制御文字・空白・DEL、URLが黙って読み替えるbackslash、fragment。
    if (code <= 0x20 || code === 0x7f || code === 0x5c || code === 0x23) return true;
  }
  return false;
}

/**
 * HTTPS・443（省略も443）だけを受け付け、canonical hostname/IPを返す。userinfo、fragment、制御文字、
 * 末尾dotのhostname、zone付きliteralは拒否する。整数・8進・16進等のIPv4表記はURLの正規化後のIPとして扱う
 * （別の接続先として解釈しない）。失敗はすべてinvalid_url。
 */
export function parseEgressUrl(raw: string): EgressTarget {
  const invalid = () => new EgressError('invalid_url');
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH || hasForbiddenCharacter(raw)) {
    throw invalid();
  }
  if (!/^https:\/\//i.test(raw)) throw invalid();
  const authority = /^[^/?]*/.exec(raw.slice('https://'.length))?.[0] ?? '';
  // 空のauthority（https:///host）は、URLがpathをhostへ読み替えるため受け付けない。
  if (authority === '' || authority.includes('@')) throw invalid();

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid();
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') throw invalid();
  // 既定の443はURLが空へ正規化する。
  if (url.port !== '') throw invalid();

  const bracketed = url.hostname.startsWith('[') && url.hostname.endsWith(']');
  const hostname = bracketed ? url.hostname.slice(1, -1) : url.hostname;
  if (hostname === '' || hostname.endsWith('.') || hostname.includes('%')) throw invalid();
  const parsed = parseIp(hostname);
  if (bracketed !== (parsed?.family === 6)) throw invalid();

  return { hostname, hostHeader: url.hostname, ipLiteral: parsed !== null, path: `${url.pathname}${url.search}` };
}

async function selectAddress(connector: EgressConnector, target: EgressTarget): Promise<PinnedAddress> {
  const forbidden = () => new EgressError('destination_forbidden');
  if (target.ipLiteral) {
    const parsed = parseIp(target.hostname);
    if (!parsed || !connector.isAllowedAddress(target.hostname)) throw forbidden();
    return { address: target.hostname, family: parsed.family };
  }

  let answers: readonly ResolvedAddress[];
  try {
    answers = await connector.resolve(target.hostname);
  } catch {
    throw new EgressError('dns_failed');
  }
  if (!Array.isArray(answers) || answers.length === 0) throw new EgressError('dns_failed');

  // 全回答を検証する。一つでも不正・禁止なら、残りが公開IPでも接続しない。
  const candidates: PinnedAddress[] = [];
  for (const answer of answers) {
    const parsed = typeof answer?.address === 'string' ? parseIp(answer.address) : null;
    if (!parsed || !connector.isAllowedAddress(answer.address)) throw forbidden();
    candidates.push({ address: answer.address, family: parsed.family });
  }
  // 接続するのは1つだけ。IPv4の回答があれば最初のIPv4、なければ最初のIPv6。別の回答へは切り替えない。
  const selected = candidates.find((candidate) => candidate.family === 4) ?? candidates[0];
  if (!selected) throw new EgressError('dns_failed');
  return selected;
}

interface Outbound {
  readonly method: 'GET' | 'POST';
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string | undefined;
}

function run(connector: EgressConnector, outbound: Outbound, options: EgressOptions): Promise<EgressResponse> {
  return new Promise((resolve, reject) => {
    const { signal, timeoutMs } = options;
    const deadlineMs =
      typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs >= 0
        ? Math.min(timeoutMs, EGRESS_MAX_DEADLINE_MS)
        : EGRESS_MAX_DEADLINE_MS;
    // タイマーのcallbackはイベントループが塞がると遅れる。期限は開始からの単調経過時間でも判定する（壁時計は使わない）。
    const startedAt = performance.now();
    const expired = () => performance.now() - startedAt >= deadlineMs;
    // 期限・呼び出し元の中断・完了のどれでも、進行中の接続を破棄する。
    const stop = new AbortController();
    let settled = false;
    const settle = (complete: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      stop.abort();
      complete();
    };
    const fail = (kind: EgressError['kind']) => settle(() => reject(new EgressError(kind)));
    const onAbort = () => fail('aborted');
    // inactivityではなく、開始からの絶対期限。
    const timer = setTimeout(() => fail('timeout'), deadlineMs);
    if (signal?.aborted) return fail('aborted');
    signal?.addEventListener('abort', onAbort, { once: true });

    void (async () => {
      const target = parseEgressUrl(outbound.url);
      // 0期限では、名前解決も接続も始めない。
      if (expired()) return fail('timeout');
      const pin = await selectAddress(connector, target);
      // 期限・中断の後に名前解決が終わっても、接続を始めない。タイマーがまだ実行されていなくても同じ。
      if (settled) return;
      if (expired()) return fail('timeout');
      const response = await sendPinned(
        {
          method: outbound.method,
          hostname: target.hostname,
          hostHeader: target.hostHeader,
          ipLiteral: target.ipLiteral,
          path: target.path,
          headers: outbound.headers,
          body: outbound.body,
          pin,
          lookup: pinnedLookup(pin),
          port: connector.port,
          ca: connector.ca,
          maxResponseBytes: EGRESS_MAX_RESPONSE_BYTES,
        },
        stop.signal,
        expired,
      );
      // 期限後に完了した応答は、成功にしない。
      if (expired()) return fail('timeout');
      settle(() => resolve(response));
    })().catch((error: unknown) => {
      // 未知の例外は内容を運ばず、固定分類へ閉じる。
      fail(error instanceof EgressError ? error.kind : 'protocol_error');
    });
  });
}

/**
 * 指示の配送の送出。期限・中断・宛先の防御はrunと同じで、違いは次の3つ。beforeConnectの確認を3か所で行う。応答はstatusだけ。
 * ownedは、結果が決まっても、始めた送出の実際のcloseを待ってから0で上書きし、その後で返す（期限のタイマーで先に消さない）。
 */
function runCommand(
  connector: EgressConnector,
  url: string,
  headers: Readonly<Record<string, string>>,
  owned: Buffer,
  options: CommandEgressOptions,
): Promise<CommandEgressResponse> {
  return new Promise((resolve, reject) => {
    const { signal, timeoutMs, beforeConnect } = options;
    const deadlineMs =
      typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs >= 0
        ? Math.min(timeoutMs, EGRESS_MAX_DEADLINE_MS)
        : EGRESS_MAX_DEADLINE_MS;
    const startedAt = performance.now();
    const expired = () => performance.now() - startedAt >= deadlineMs;
    /** 期限と呼び出し元の確認。止める時は、その固定の分類。 */
    const blocked = (): EgressFailure | null => {
      if (expired()) return 'timeout';
      if (beforeConnect === undefined) return null;
      try {
        return beforeConnect() === true ? null : 'aborted';
      } catch {
        return 'aborted';
      }
    };
    const stop = new AbortController();
    /** 始めた送出が閉じた時に解決する。始めていなければ、解決済み。 */
    let closed: Promise<void> = Promise.resolve();
    let settled = false;
    const settle = (complete: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      stop.abort();
      void closed.then(() => {
        owned.fill(0);
        complete();
      });
    };
    const fail = (kind: EgressFailure) => settle(() => reject(new EgressError(kind)));
    const onAbort = () => fail('aborted');
    const timer = setTimeout(() => fail('timeout'), deadlineMs);
    if (signal?.aborted) return fail('aborted');
    signal?.addEventListener('abort', onAbort, { once: true });

    void (async () => {
      const target = parseEgressUrl(url);
      // 0期限・確認の不成立では、名前解決も接続も始めない。
      const beforeDns = blocked();
      if (beforeDns !== null) return fail(beforeDns);
      const pin = await selectAddress(connector, target);
      // 期限・中断・確認の不成立の後に名前解決が終わっても、接続を始めない。
      if (settled) return;
      const beforeSocket = blocked();
      if (beforeSocket !== null) return fail(beforeSocket);
      const sending = sendPinnedCommand(
        {
          hostname: target.hostname,
          hostHeader: target.hostHeader,
          ipLiteral: target.ipLiteral,
          path: target.path,
          headers,
          body: owned,
          pin,
          lookup: pinnedLookup(pin),
          port: connector.port,
          ca: connector.ca,
        },
        stop.signal,
        blocked,
      );
      closed = sending.then(
        () => undefined,
        () => undefined,
      );
      const response = await sending;
      // 期限後に完了した応答は、成功にしない。
      if (expired()) return fail('timeout');
      settle(() => resolve(response));
    })().catch((error: unknown) => {
      // 未知の例外は内容を運ばず、固定分類へ閉じる。
      fail(error instanceof EgressError ? error.kind : 'protocol_error');
    });
  });
}

export function createSafeEgress(connector: EgressConnector): SafeEgress {
  return {
    getJson(url, options = {}) {
      return run(connector, { method: 'GET', url, headers: { accept: 'application/json' } }, options);
    },
    async postCallback(url, post, options = {}) {
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(post.headers)) {
        const lower = name.toLowerCase();
        if (!CALLBACK_HEADERS.has(lower) || typeof value !== 'string' || hasControlCharacter(value)) {
          throw new EgressError('invalid_request');
        }
        headers[lower] = value;
      }
      if (typeof post.body !== 'string') throw new EgressError('invalid_request');
      return run(connector, { method: 'POST', url, headers, body: post.body }, options);
    },
    async postCommandCallback(url, post, options = {}) {
      const invalid = () => new EgressError('invalid_request');
      if (typeof post !== 'object' || post === null || typeof options !== 'object' || options === null) throw invalid();
      const names = Object.keys(post);
      if (names.length !== 2 || !names.includes('headers') || !names.includes('body')) throw invalid();
      const { headers: given, body } = post;
      if (typeof given !== 'object' || given === null) throw invalid();
      if (!Buffer.isBuffer(body) || body.length < 1 || body.length > MAX_COMMAND_BODY_BYTES) throw invalid();
      if (options.beforeConnect !== undefined && typeof options.beforeConnect !== 'function') throw invalid();
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(given)) {
        const lower = name.toLowerCase();
        if (!CALLBACK_HEADERS.has(lower) || typeof value !== 'string' || hasControlCharacter(value)) throw invalid();
        headers[lower] = value;
      }
      // ここまでawaitは無い。呼び出し元のBufferは、この写しを作った後は読まない。
      const owned = Buffer.allocUnsafeSlow(body.length);
      body.copy(owned);
      return runCommand(connector, url, headers, owned, options);
    },
  };
}
