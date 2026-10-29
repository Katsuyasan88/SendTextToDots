// ローカル送信画面の配信helper（Node標準だけ。新依存0）。127.0.0.1だけで待ち受け、入口は http://localhost:<port>/console。
//   - 配信: GET /console（HTML、表示言語は?lang/cookie/Accept-Language。?langの明示選択だけSet-Cookie、httpなのでSecureなし）・/console/app.js・
//     /console/app.css。他のpathは固定404。表示・言語切替・固定プロンプトのコピーでは上流へ何も送らない。
//   - 中継: browserの明示操作に対応する限定route/methodだけを、固定のhttps DNS origin（config）へBearer tokenを添えて中継する。
//     GET /v1/web/connection・POST /v1/web/disconnect → mcpOrigin、POST /v2/commands・GET /v2/commands/:uuid・POST /v2/commands/:uuid/cancel → apiOrigin。
//     任意URL・redirect追従・汎用proxyは無い。
//   - 保護: Host（localhost:<実port>の完全一致・1件）、request-target（origin-form）、Origin（有れば http://localhost:<port> の完全一致）、起動ごとの
//     local nonce header（1件・完全一致。HTMLへescapeして渡す）、Authorization（Bearer 1件）、Content-Type/Idempotency-Key（POST /v2/commandsだけ）、
//     本文上限（8192 byte。他のrouteは本文なし）を上流呼出しの前に検査する。CORS header・Set-Cookie転送・Origin/Cookie/Forwarded/nonceの上流転送は無い。
//   - 上流を呼ぶ前のhelper自身の拒否（Host・未知route/method・nonce/Origin・認証header・本文）には固定header X-Sttd-Local-Refusal: 1 を付け、
//     画面が「未送信」と判定できるようにする（nonce/Origin不一致は古い画面として固定code local_reload_required）。上流応答の同名headerは
//     転送しない（転送はContent-Type/Retry-Afterだけ）。上流呼出し後の失敗（502・500）には付けない（結果不明のまま）。
//   - 有限: 上流の期限（route別）、応答本文の上限、browser切断/中止の上流への伝播。正常終了のcloseを中止と誤認しない。token・本文・秘密を保存/記録しない。
//   - CLI: node dist/console/local-server.js --config <public-client-config.json> [--port 8765]。設定の読取りはconfig.ts。本番配置設定は読まない。

import { OPERATOR_PATH_PREFIX, OPERATOR_SCRIPT_PATH, renderOperatorCodePanel, renderOperatorSection, type OperatorRoutes } from './operator-config.js';
import { createPrivateKey, randomBytes, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFileSync, realpathSync } from 'node:fs';

import { SIGNATURE_HEADER, signSourceRequest, SOURCE_HEADER } from '../source/proof.js';
import { fileURLToPath } from 'node:url';

import { consoleAsset, CONSOLE_PATH, CONSOLE_SCRIPT_PATH, CONSOLE_SDK_BASE, CONSOLE_STYLE_PATH, LOCAL_NONCE_HEADER, LOCAL_REFUSAL_HEADER } from '../connect/console.js';
import { isLanguage, LANGUAGE_QUERY, languageCookie, selectLanguage } from '../connect/i18n.js';
import { ConsoleConfigFileError, loadLocalConsoleConfig, validateLocalConsoleConfig, type LocalConsoleConfig } from './config.js';

export const DEFAULT_LOCAL_PORT = 8765;
const BIND_HOST = '127.0.0.1';
/** POST /v2/commandsの本文上限。本文textは最大4096 UTF-8 byteだがJSON escapeで最大6倍（制御文字）になり、5項目のmetadataも付くので、正規のpayload全体が収まる有限値（32 KiB）。APIの本文上限4096 byte自体は変えない。 */
const MAX_COMMAND_BODY_BYTES = 32768;
const MAX_UPSTREAM_BODY_BYTES = 65536;
const BEARER = /^Bearer [A-Za-z0-9._-]{1,4096}$/;
const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const COMMAND_PATH = new RegExp(`^/v2/commands/(${UUID})(/cancel)?$`);
const ORIGIN_FORM_TARGET = /^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/;
const JSON_TYPE = 'application/json; charset=utf-8';
const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };

/** 中継してよいroute（method・上流・期限・本文の許可・許可元の署名）。 */
interface RelayRoute {
  readonly method: 'GET' | 'POST';
  readonly upstream: 'api' | 'mcp';
  readonly timeoutMs: number;
  readonly body: 'json' | 'none' | 'approve';
  /** 登録開発者環境の設定がある時だけ署名する（照会/取消・接続状態/解除は署名しない最小回復）。 */
  readonly sign?: true | undefined;
}

/** 接続承認の参照（元interaction ID）。 */
const APPROVAL_PATH = /^\/v1\/source\/approvals\/([A-Za-z0-9_-]{1,128})$/;
/** 接続承認のPOST本文（明示承認だけ）。 */
const APPROVE_BODY = '{"approve":true}';/** 許可元の承認画面のscript（同origin。CSPのscript-src 'self'）。 */
export const SOURCE_SCRIPT_PATH = '/console/source.js';

function relayRouteFor(method: string, path: string, sourceEnabled = false): RelayRoute | 'method' | null {
  const table: Array<{ test: (p: string) => boolean; method: 'GET' | 'POST'; route: RelayRoute }> = [
    // 登録開発者環境の設定がある時だけ: 固定MCP originの接続承認（内容の照会・明示承認）。
    ...(sourceEnabled
      ? [
          { test: (p: string) => APPROVAL_PATH.test(p), method: 'GET' as const, route: { method: 'GET' as const, upstream: 'mcp' as const, timeoutMs: 11_000, body: 'none' as const, sign: true as const } },
          { test: (p: string) => APPROVAL_PATH.test(p), method: 'POST' as const, route: { method: 'POST' as const, upstream: 'mcp' as const, timeoutMs: 11_000, body: 'approve' as const, sign: true as const } },
        ]
      : []),
    { test: (p) => p === '/v1/web/connection', method: 'GET', route: { method: 'GET', upstream: 'mcp', timeoutMs: 11_000, body: 'none' } },
    { test: (p) => p === '/v1/web/disconnect', method: 'POST', route: { method: 'POST', upstream: 'mcp', timeoutMs: 11_000, body: 'none' } },
    { test: (p) => p === '/v2/commands', method: 'POST', route: { method: 'POST', upstream: 'api', timeoutMs: 26_000, body: 'json', ...(sourceEnabled ? { sign: true as const } : {}) } },
    { test: (p) => COMMAND_PATH.test(p) && !p.endsWith('/cancel'), method: 'GET', route: { method: 'GET', upstream: 'api', timeoutMs: 11_000, body: 'none' } },
    { test: (p) => COMMAND_PATH.test(p) && p.endsWith('/cancel'), method: 'POST', route: { method: 'POST', upstream: 'api', timeoutMs: 6_000, body: 'none' } },
  ];
  const matches = table.filter((entry) => entry.test(path));
  if (matches.length === 0) return null;
  const exact = matches.find((entry) => entry.method === method);
  return exact ? exact.route : 'method';
}

/** 登録開発者環境の署名に使う鍵（memoryだけ。browser・応答・ログへ出さない）。 */
interface SourceSigner {
  readonly sourceId: string;
  readonly key: KeyObject;
}

function loadSourceSigner(source: { readonly sourceId: string; readonly keyFile: string }): SourceSigner {
  let pem: Buffer;
  try {
    pem = readFileSync(source.keyFile);
  } catch {
    throw new ConsoleConfigFileError('unreadable');
  }
  try {
    const key = createPrivateKey({ key: pem, format: 'pem' });
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new ConsoleConfigFileError('invalid');
    return Object.freeze({ sourceId: source.sourceId, key });
  } catch {
    throw new ConsoleConfigFileError('invalid');
  } finally {
    pem.fill(0);
  }
}

const SOURCE_TEXT = {
  en: {
    title: 'Approve a connection (registered developer environment)',
    label: 'Connection request reference shown on the plugin connection screen',
    check: 'Check',
    approve: 'Approve',
    login: 'Sign in on this screen first.',
    checked: 'Request for {client}. Approve only if you started this connection.',
    approved: 'Approved. Continue on the original connection screen.',
    failed: 'Could not check or approve this request.',
  },
  ja: {
    title: '接続の承認（登録済み開発者環境）',
    label: 'プラグイン接続画面に表示された接続要求の参照',
    check: '確認',
    approve: '承認',
    login: '先にこの画面でログインしてください。',
    checked: '{client} の接続要求です。自分で始めた接続の時だけ承認してください。',
    approved: '承認しました。元の接続画面で続けてください。',
    failed: 'この接続要求を確認・承認できませんでした。',
  },
} as const;

function escapeAttribute(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** 許可元の承認欄（登録開発者環境の設定がある時だけ）。参照の入力→確認→明示承認。元画面の同意はbrowserで続ける。 */
function renderSourceApprovalSection(language: 'en' | 'ja', nonce: string): string {
  const t = SOURCE_TEXT[language];
  const data = Object.entries(t)
    .map(([key, value]) => ` data-sttd-source-${key}="${escapeAttribute(value)}"`)
    .join('');
  return `<section id="sttd-source"${data} data-sttd-source-nonce="${escapeAttribute(nonce)}"><h3>${escapeAttribute(t.title)}</h3>
<label for="sttd-source-ref">${escapeAttribute(t.label)}</label> <input id="sttd-source-ref" maxlength="128" autocomplete="off" spellcheck="false">
<div class="sttd-actions"><button type="button" id="sttd-source-check">${escapeAttribute(t.check)}</button> <button type="button" id="sttd-source-approve" disabled>${escapeAttribute(t.approve)}</button></div>
<p id="sttd-source-message" role="status"></p></section>
<script type="module" src="${SOURCE_SCRIPT_PATH}"></script>`;
}

/**
 * 承認欄のscript。初期表示では何もimport・通信しない（Firebase SDKは「確認」の明示操作の時に、画面と同じ固定URLから遅延importし、
 * 既存のApp（getApps()[0]）だけを使う。新しいApp・別projectは作らない）。確認したGETの結果を参照・本人（user object）・操作世代へ束縛し、
 * 入力・本人の変更で確認と承認可能状態を破棄する。待機中に変わった遅い結果は採用しない。確認中/承認中の多重clickは1操作だけ。
 * 承認は確認済みの参照だけへ1回送り、成功/失敗の後は再確認を要求する。token・UID・鍵はDOM・ログへ保存しない。自動pollはしない。
 */
const SOURCE_SCRIPT = `const loadSdk = (url) => import(url);
const SDK = '${CONSOLE_SDK_BASE}';
const REF = /^[A-Za-z0-9_-]{1,128}$/;
const root = document.getElementById('sttd-source');
const text = (key) => root.dataset['sttdSource' + key.charAt(0).toUpperCase() + key.slice(1)] || '';
const input = document.getElementById('sttd-source-ref');
const check = document.getElementById('sttd-source-check');
const approve = document.getElementById('sttd-source-approve');
const message = document.getElementById('sttd-source-message');
let generation = 0;
let confirmed = null;
let busy = false;
let auth = null;
let lastUser;
const show = (value) => { message.textContent = value; };
const invalidate = () => { generation += 1; confirmed = null; approve.disabled = true; };
input.addEventListener('input', () => { invalidate(); show(''); });
async function currentAuth() {
  if (auth !== null) return auth;
  const [appModule, authModule] = await Promise.all([loadSdk(SDK + 'firebase-app.js'), loadSdk(SDK + 'firebase-auth.js')]);
  const app = appModule.getApps()[0];
  if (!app) return null;
  if (auth !== null) return auth;
  auth = authModule.getAuth(app);
  lastUser = auth.currentUser;
  authModule.onAuthStateChanged(auth, (user) => {
    if (user !== lastUser) { lastUser = user; invalidate(); }
  });
  return auth;
}
check.addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  invalidate();
  const mine = generation;
  const ref = input.value.trim();
  try {
    if (!REF.test(ref)) { show(text('failed')); return; }
    const current = await currentAuth();
    const user = current === null ? null : current.currentUser;
    if (mine !== generation) return;
    if (!user) { show(text('login')); return; }
    const token = await user.getIdToken();
    if (mine !== generation || current.currentUser !== user) return;
    const response = await fetch('/v1/source/approvals/' + ref, { method: 'GET', headers: { Authorization: 'Bearer ' + token, '${LOCAL_NONCE_HEADER}': root.dataset.sttdSourceNonce }, credentials: 'omit', cache: 'no-store' });
    const body = response.ok ? await response.json() : null;
    if (mine !== generation || current.currentUser !== user || input.value.trim() !== ref) return;
    if (!body || typeof body.client !== 'string') { show(text('failed')); return; }
    confirmed = { ref, user, generation: mine };
    show(text('checked').replace('{client}', body.client));
    approve.disabled = false;
  } catch {
    if (mine === generation) show(text('failed'));
  } finally {
    busy = false;
  }
});
approve.addEventListener('click', async () => {
  if (busy || confirmed === null || auth === null) return;
  const target = confirmed;
  // 確認後に参照・本人が変わっていれば送らない（未確認の参照を承認しない）。
  if (target.generation !== generation || input.value.trim() !== target.ref || auth.currentUser !== target.user) { invalidate(); show(text('failed')); return; }
  busy = true;
  confirmed = null;
  approve.disabled = true;
  try {
    const token = await target.user.getIdToken();
    if (target.generation !== generation || auth.currentUser !== target.user || input.value.trim() !== target.ref) { show(text('failed')); return; }
    const response = await fetch('/v1/source/approvals/' + target.ref, { method: 'POST', headers: { Authorization: 'Bearer ' + token, '${LOCAL_NONCE_HEADER}': root.dataset.sttdSourceNonce, 'Content-Type': 'application/json' }, body: '${APPROVE_BODY}', credentials: 'omit', cache: 'no-store' });
    const body = response.ok ? await response.json() : null;
    show(body && body.state === 'approved' ? text('approved') : text('failed'));
  } catch {
    show(text('failed'));
  } finally {
    busy = false;
  }
});
`;

/** 固定の非成功（値を持たない）。 */
class RelayRefusal extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
    this.name = 'RelayRefusal';
  }
}

function refuse(status: number, code: string): never {
  throw new RelayRefusal(status, code);
}

/** rawHeadersから名前（大小無視）の値を全て取り出す。 */
function headerValues(raw: readonly string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index + 1 < raw.length; index += 2) if ((raw[index] ?? '').toLowerCase() === name) values.push(raw[index + 1] ?? '');
  return values;
}

function single(raw: readonly string[], name: string): string | undefined {
  const values = headerValues(raw, name);
  if (values.length > 1) refuse(400, 'invalid_request');
  return values[0];
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const declared = req.headers['content-length'];
  if (declared !== undefined && !(Number(declared) <= maxBytes)) refuse(413, 'payload_too_large');
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > maxBytes) refuse(413, 'payload_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/** 上流応答のstreamを累積上限まで読む。超過・中止はreaderをcancelして失敗（読み込んだbytesは上限を超えて保持しない）。 */
async function readUpstreamBody(body: UpstreamResponseBody, maxBytes: number, controller: AbortController): Promise<Buffer> {
  if (body === null) return Buffer.alloc(0);
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      if (controller.signal.aborted) throw new Error('aborted');
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        controller.abort();
        throw new Error('too_large');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  return Buffer.concat(chunks);
}

type UpstreamResponseBody = { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array | undefined }>; cancel(reason?: unknown): Promise<void> } } | null;

/** 上流fetchの最小の形（試験は合成fetchを注入する）。 */
export type UpstreamFetch = (url: string, init: { method: string; headers: Record<string, string>; body?: Uint8Array | undefined; redirect: 'error'; signal: AbortSignal; cache: 'no-store'; credentials: 'omit' }) => Promise<{
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  /** 応答本文のstream（null可）。accumulated上限で止めるため全体を一度に読まない。 */
  readonly body: { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array | undefined }>; cancel(reason?: unknown): Promise<void> } } | null;
}>;

export interface LocalConsoleOptions {
  readonly config: LocalConsoleConfig;
  /** 127.0.0.1で待ち受けるport（既定8765、試験は0）。 */
  readonly port?: number | undefined;
  /** 上流fetch（既定globalThis.fetch）。 */
  readonly fetch?: UpstreamFetch | undefined;
  /** 固定のevent/route/statusだけを受け取る記録口（任意）。 */
  readonly log?: ((entry: { readonly event: string; readonly route?: string; readonly status?: number }) => void) | undefined;
  /** 明示operator mode（開発者向けコードの発行。operator-server.tsのCLIだけが渡す）。省略時は通常の配信modeで、操作口は404。 */
  readonly operator?: OperatorRoutes | undefined;
}

export interface LocalConsole {
  readonly port: number;
  /** browserの入口origin。 */
  readonly origin: string;
  /** 起動ごとのlocal nonce（HTMLへ渡したもの）。 */
  readonly nonce: string;
  close(): Promise<void>;
}

/** helperを起動する（listen完了後に返る）。 */
export async function startLocalConsole(options: LocalConsoleOptions): Promise<LocalConsole> {
  const config = validateLocalConsoleConfig(options.config);
  const requestedPort = options.port ?? DEFAULT_LOCAL_PORT;
  if (!Number.isSafeInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) throw new ConsoleConfigFileError('invalid');
  const upstreamFetch: UpstreamFetch = options.fetch ?? (globalThis.fetch as unknown as UpstreamFetch);
  if (typeof upstreamFetch !== 'function') throw new ConsoleConfigFileError('invalid');
  const log = options.log ?? (() => {});
  const nonce = randomBytes(32).toString('hex');
  const web = config.firebase;
  // 登録開発者環境の鍵（設定がある時だけ、起動時に1回だけ読む。Ed25519以外・読めない鍵は起動しない）。
  const signer = config.source === undefined ? null : loadSourceSigner(config.source);

  let port = requestedPort;
  let authority = '';
  let origin = '';

  function send(res: ServerResponse, status: number, type: string, body: string | Buffer, headers: Record<string, string> = {}): void {
    const payload = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
    res.writeHead(status, { ...BASE_HEADERS, ...headers, 'Content-Type': type, 'Content-Length': payload.length });
    res.end(payload);
  }

  function sendError(res: ServerResponse, status: number, code: string, retryable = false): void {
    if (res.writableEnded) return;
    if (res.headersSent) {
      res.destroy();
      return;
    }
    send(res, status, JSON_TYPE, JSON.stringify({ error: { code, retryable } }), { Connection: 'close' });
  }

  /** 上流を呼ぶ前のhelper自身の拒否（固定header付き。上流へは何も送っていない）。 */
  function sendLocalRefusal(res: ServerResponse, status: number, code: string): void {
    if (res.writableEnded) return;
    if (res.headersSent) {
      res.destroy();
      return;
    }
    send(res, status, JSON_TYPE, JSON.stringify({ error: { code, retryable: false } }), { Connection: 'close', [LOCAL_REFUSAL_HEADER]: '1' });
  }

  async function relay(req: IncomingMessage, res: ServerResponse, path: string, route: RelayRoute): Promise<void> {
    const raw = req.rawHeaders;
    // local nonce（1件・完全一致）とOrigin（有れば同origin）。CORSは無いので他originのscriptは応答を読めず、nonceも知らない。
    const presented = single(raw, LOCAL_NONCE_HEADER.toLowerCase());
    if (presented !== nonce) refuse(403, 'local_reload_required');
    const originHeader = single(raw, 'origin');
    if (originHeader !== undefined && originHeader !== origin) refuse(403, 'local_reload_required');
    const authorization = single(raw, 'authorization');
    if (authorization === undefined) refuse(401, 'authentication_required');
    if (!BEARER.test(authorization)) refuse(401, 'authentication_required');
    const headers: Record<string, string> = { Authorization: authorization };
    let body: Uint8Array | undefined;
    if (route.body === 'json') {
      const contentType = single(raw, 'content-type');
      if (contentType === undefined || contentType.split(';')[0]!.trim().toLowerCase() !== 'application/json') refuse(400, 'invalid_request');
      const idempotency = single(raw, 'idempotency-key');
      if (idempotency === undefined || !new RegExp(`^${UUID}$`).test(idempotency)) refuse(400, 'invalid_request');
      headers['Content-Type'] = 'application/json';
      headers['Idempotency-Key'] = idempotency;
      body = await readBody(req, MAX_COMMAND_BODY_BYTES);
      if (body.length === 0) refuse(400, 'invalid_request');
    } else if (route.body === 'approve') {
      // 接続承認: 明示承認の固定本文だけ（他の本文・fieldは上流へ送らない）。
      const contentType = single(raw, 'content-type');
      if (contentType === undefined || contentType.split(';')[0]!.trim().toLowerCase() !== 'application/json') refuse(400, 'invalid_request');
      const approval = await readBody(req, APPROVE_BODY.length);
      if (approval.toString('utf8') !== APPROVE_BODY) refuse(400, 'invalid_request');
      body = approval;
      headers['Content-Type'] = 'application/json';
    } else {
      // 本文を持たないroute: 本文を示すheaderがあれば読む前に拒否し、無くても届いた本文は拒否する。
      const declared = single(raw, 'content-length');
      if ((declared !== undefined && declared !== '0') || single(raw, 'transfer-encoding') !== undefined || single(raw, 'content-type') !== undefined) refuse(400, 'invalid_request');
      if ((await readBody(req, MAX_COMMAND_BODY_BYTES)).length !== 0) refuse(400, 'invalid_request');
    }
    const upstreamOrigin = route.upstream === 'api' ? config.apiOrigin : config.mcpOrigin;
    const target = upstreamOrigin + path;
    // 登録開発者環境: 固定上流のこのroute/method/path/本文/本人token/Idempotency-Keyだけに署名する（任意宛先・任意headerの署名はしない）。
    if (route.sign === true && signer !== null) {
      const bearer = authorization.slice('Bearer '.length);
      const nowSec = Math.floor(Date.now() / 1000);
      const claims = { issuedAt: nowSec, expiresAt: nowSec + 30, nonce: randomBytes(16).toString('base64url') };
      headers[SOURCE_HEADER] = signer.sourceId;
      headers[SIGNATURE_HEADER] = signSourceRequest(
        { audience: upstreamOrigin, method: route.method, path, search: '', sourceId: signer.sourceId, body: body ?? new Uint8Array(0), bearer, idempotencyKey: headers['Idempotency-Key'] },
        claims,
        signer.key,
      );
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), route.timeoutMs);
    // browser側の切断/中止は上流へ伝える（正常に書き終えた後のcloseは中止にしない）。
    const onClose = (): void => {
      if (!res.writableFinished) controller.abort();
    };
    req.once('aborted', onClose);
    res.once('close', onClose);
    try {
      let response;
      try {
        response = await upstreamFetch(target, { method: route.method, headers, body, redirect: 'error', signal: controller.signal, cache: 'no-store', credentials: 'omit' });
      } catch {
        if (controller.signal.aborted && res.destroyed) return;
        return sendError(res, 502, 'upstream_unavailable', true);
      }
      // Content-Lengthは信用せず、streamを累積上限まで読む。超過・期限・中止ではreaderをcancelして固定502（本文は捨てる）。
      const declaredLength = response.headers.get('content-length');
      if (typeof declaredLength === 'string' && !(Number(declaredLength) <= MAX_UPSTREAM_BODY_BYTES)) {
        controller.abort();
        return sendError(res, 502, 'upstream_unavailable', true);
      }
      let payload: Buffer;
      try {
        payload = await readUpstreamBody(response.body, MAX_UPSTREAM_BODY_BYTES, controller);
      } catch {
        if (controller.signal.aborted && res.destroyed) return;
        return sendError(res, 502, 'upstream_unavailable', true);
      }
      const forwarded: Record<string, string> = {};
      const contentType = response.headers.get('content-type');
      if (typeof contentType === 'string' && /^[\x21-\x7e][\x20-\x7e]{0,126}$/.test(contentType)) forwarded['Content-Type'] = contentType;
      const retryAfter = response.headers.get('retry-after');
      if (typeof retryAfter === 'string' && /^[0-9]{1,6}$/.test(retryAfter)) forwarded['Retry-After'] = retryAfter;
      if (res.destroyed) return;
      const status = Number.isInteger(response.status) && response.status >= 200 && response.status <= 599 ? response.status : 502;
      res.writeHead(status, { ...BASE_HEADERS, ...forwarded, 'Content-Length': payload.length, ...(forwarded['Content-Type'] === undefined ? { 'Content-Type': 'application/octet-stream' } : {}) });
      res.end(payload);
    } finally {
      clearTimeout(timer);
      req.off('aborted', onClose);
      res.off('close', onClose);
    }
  }

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = req.rawHeaders;
    const target = req.url;
    const hosts = headerValues(raw, 'host');
    if (hosts.length !== 1 || hosts[0] !== authority || typeof target !== 'string' || !ORIGIN_FORM_TARGET.test(target)) {
      log({ event: 'local.rejected' });
      return sendLocalRefusal(res, 400, 'invalid_request');
    }
    const url = new URL(target, origin);
    const path = url.pathname;
    const method = req.method ?? '';
    if (path === CONSOLE_PATH || path === CONSOLE_SCRIPT_PATH || path === CONSOLE_STYLE_PATH) {
      if (method !== 'GET' && method !== 'HEAD') return sendError(res, 405, 'method_not_allowed');
      if ((await readBody(req, 0)).length !== 0) return sendError(res, 400, 'invalid_request');
      const query = url.searchParams.get(LANGUAGE_QUERY);
      const language = selectLanguage({ query, cookie: req.headers.cookie, acceptLanguage: req.headers['accept-language'] });
      const extra: Record<string, string> = path === CONSOLE_PATH && isLanguage(query) ? { 'Set-Cookie': languageCookie(language, false) } : {};
      const operatorSection =
        renderOperatorSection({ language, enabled: options.operator !== undefined, nonce, web }) + (signer === null ? '' : renderSourceApprovalSection(language === 'ja' ? 'ja' : 'en', nonce));
      const operatorCodePanel = renderOperatorCodePanel({ language, enabled: options.operator !== undefined });
  const asset = consoleAsset(path, web, { language, nonce, secure: false, mcpOrigin: config.mcpOrigin, operatorSection, operatorFirst: options.operator !== undefined, operatorCodePanel })!;
      log({ event: 'local.asset', route: path });
      return send(res, 200, asset.type, asset.body, { ...asset.headers, ...extra });
    }
    if (path === OPERATOR_SCRIPT_PATH || path.startsWith(OPERATOR_PATH_PREFIX)) {
      if (options.operator === undefined) return sendLocalRefusal(res, 404, 'not_found');
      log({ event: 'local.operator', route: path });
      return options.operator.handle(req, res, { path, method, nonce, origin });
    }
    if (path === SOURCE_SCRIPT_PATH) {
      if (signer === null) return sendLocalRefusal(res, 404, 'not_found');
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed');
      if ((await readBody(req, 0)).length !== 0) return sendError(res, 400, 'invalid_request');
      return send(res, 200, 'text/javascript; charset=utf-8', SOURCE_SCRIPT);
    }
    const route = relayRouteFor(method, path, signer !== null);
    if (route === null) return sendLocalRefusal(res, 404, 'not_found');
    if (route === 'method') return sendLocalRefusal(res, 405, 'method_not_allowed');
    try {
      await relay(req, res, path, route);
      log({ event: 'local.relay', route: path, status: res.statusCode });
    } catch (error) {
      if (error instanceof RelayRefusal) {
        log({ event: 'local.refused', route: path, status: error.status });
        return sendLocalRefusal(res, error.status, error.code);
      }
      log({ event: 'local.failure', route: path });
      return sendError(res, 500, 'internal_error');
    }
  }

  const server: Server = createServer((req, res) => {
    void serve(req, res).catch(() => {
      if (!res.writableEnded) res.destroy();
    });
  });
  server.on('error', () => log({ event: 'local.server_error' }));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(requestedPort, BIND_HOST, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new ConsoleConfigFileError('invalid');
  }
  port = address.port;
  authority = `localhost:${port}`;
  origin = `http://${authority}`;
  log({ event: 'local.started' });

  let closing: Promise<void> | undefined;
  return Object.freeze({
    port,
    origin,
    nonce,
    close: () => {
      if (closing === undefined) {
        closing = new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
          server.closeAllConnections();
        });
      }
      return closing;
    },
  });
}

/** CLI引数（--config <path> [--port <n>]）。未知の引数・欠落は不正。 */
export function parseLocalConsoleArgs(argv: readonly string[]): { readonly configPath: string; readonly port: number } {
  let configPath: string | undefined;
  let port = DEFAULT_LOCAL_PORT;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = argv[index + 1];
    if (arg === '--config' && typeof value === 'string' && value !== '') {
      configPath = value;
      index += 1;
    } else if (arg === '--port' && typeof value === 'string' && /^[0-9]{1,5}$/.test(value) && Number(value) >= 1024 && Number(value) <= 65535) {
      port = Number(value);
      index += 1;
    } else {
      throw new ConsoleConfigFileError('invalid');
    }
  }
  if (configPath === undefined) throw new ConsoleConfigFileError('invalid');
  return { configPath, port };
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (typeof entry !== 'string') return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  const usage = 'usage: npm run console -- --config <public-client-config.json> [--port 8765]\n';
  let started: LocalConsole | undefined;
  try {
    const args = parseLocalConsoleArgs(process.argv.slice(2));
    const config = loadLocalConsoleConfig(args.configPath);
    started = await startLocalConsole({ config, port: args.port });
    process.stdout.write(`SendTextToDots local console: ${started.origin}${CONSOLE_PATH}\n(Ctrl+C to stop. Nothing is sent until you press a button in the page.)\n`);
  } catch (error) {
    process.stderr.write(error instanceof ConsoleConfigFileError ? `${error.message}\n${usage}` : 'local_console_start_failed\n');
    process.exitCode = 1;
  }
  if (started !== undefined) {
    const stop = (): void => {
      void started!.close().finally(() => process.exit(0));
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  }
}
