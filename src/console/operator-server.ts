// ローカル送信画面の明示operator mode（開発者向け6桁コードの発行helper）。
//   - 起動: `node dist/console/operator-server.js --config <console.local.json> --operator <operator.local.json> [--port <n>]`。通常の
//     `npm run console`（public client設定だけの配信mode）は変えない。管理SDK（firebase-admin・Firestore・Secret Manager）はこのCLIの起動時だけ
//     動的に読み、既定のADCと固定の配置設定で準備する。資格・dedupeKeyをブラウザへ返さない。API/MCPの包装はこのmoduleをimportしない。
//   - 口は発行/再発行/照会/取消の4つだけ（汎用DB書込みなし）。Host（helperが検査済み）・Origin完全一致・起動nonce・JSON小本文を検査する。
//     起動nonceは同じ端末のブラウザの証明で、遠隔管理権限ではない（helperは127.0.0.1だけで待ち受ける）。
//   - 発行元の照会secret（32byte）と最新operationIdはこのprocessのRAMだけ。DBにはHMACだけ。helperを失えば6桁だけで回復しない（新規発行）。
//   - 二重クリック・並行操作は1件ずつに直列化する。各操作は元期限15秒（store側）＋外側の応答期限で無限待ちにしない。

import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';

import { LOCAL_NONCE_HEADER } from '../connect/console.js';
import { consoleToken, type CodeAuthAdmin } from '../identity/developer-code-identity.js';
import {
  DEVELOPER_LOGIN_PURPOSE,
  DeveloperLoginError,
  ISSUE_BUDGET_MS,
  defaultRandom,
  developerLoginKeys,
  newOpaque,
  type Clock,
  type RandomPort,
} from '../identity/developer-login.js';
import { Firestore } from '@google-cloud/firestore';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { applicationDefault, initializeApp, type App } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

import { DeveloperLoginStore } from '../identity/developer-login-store.js';
import { startLocalConsole } from './local-server.js';
import { OPERATOR_ACTIONS, OPERATOR_PATH_PREFIX, OPERATOR_SCRIPT_PATH, operatorScript, parseOperatorConfig, type OperatorAction, type OperatorRoutes } from './operator-config.js';

const JSON_TYPE = 'application/json; charset=utf-8';
const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
const MAX_BODY_BYTES = 64;
/** store側の元期限15秒に加えた外側の応答期限。 */
const RESPONSE_BUDGET_MS = ISSUE_BUDGET_MS + 2_000;

export interface OperatorRoutesDeps {
  readonly store: Pick<DeveloperLoginStore, 'issue' | 'claim' | 'cancel'>;
  readonly auth: Pick<CodeAuthAdmin, 'createCustomToken'>;
  readonly clock: Clock;
  readonly random?: RandomPort | undefined;
  readonly log?: ((entry: { readonly event: string; readonly status?: number }) => void) | undefined;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  if (res.writableEnded || res.destroyed) return;
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, { ...BASE_HEADERS, 'Content-Type': JSON_TYPE, 'Content-Length': payload.length });
  res.end(payload);
}

async function readSmallBody(req: IncomingMessage): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function statusOf(error: unknown): { status: number; code: string } {
  if (error instanceof DeveloperLoginError) {
    switch (error.code) {
      case 'rate_limited':
        return { status: 429, code: 'rate_limited' };
      case 'issue_exhausted':
        return { status: 503, code: 'issue_exhausted' };
      case 'key_rotation_blocked':
        return { status: 503, code: 'key_rotation_blocked' };
      case 'not_owner':
        return { status: 403, code: 'not_owner' };
      default:
        return { status: 503, code: 'unavailable' };
    }
  }
  return { status: 503, code: 'unavailable' };
}

/** 外側の応答期限（storeが返らない場合も待ち続けない）。 */
async function bounded<T>(task: () => Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const running = task();
  running.catch(() => undefined);
  try {
    return await Promise.race([
      running,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new DeveloperLoginError('unavailable')), RESPONSE_BUDGET_MS);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** operator modeの限定口（ローカルhelperが`/console/operator.js`と`/v1/operator/code/*`を渡す）。 */
export function createOperatorRoutes(deps: OperatorRoutesDeps): OperatorRoutes {
  const { store, auth, clock } = deps;
  const random = deps.random ?? defaultRandom;
  const log = deps.log ?? (() => undefined);
  // 発行元の照会secret（このprocessのRAMだけ）。
  const claimSecret = newOpaque(random);
  let current: { operationId: string; code: string; authExpiresAt: number } | null = null;
  let busy = false;

  async function act(action: OperatorAction): Promise<{ status: number; body: unknown }> {
    switch (action) {
      case 'issue': {
        if (current !== null) return { status: 409, body: { error: { code: 'use_reissue' } } };
        const issued = await bounded(() => store.issue({ claimSecret }));
        current = { operationId: issued.operationId, code: issued.code, authExpiresAt: issued.authExpiresAt };
        return { status: 200, body: { code: issued.code, authExpiresAt: issued.authExpiresAt } };
      }
      case 'reissue': {
        if (current === null) return { status: 409, body: { error: { code: 'nothing_to_reissue' } } };
        // 新候補の確保と旧family/予約の失効は同じtransaction。失敗なら旧コード・旧接続は変わらない（currentも変えない）。
        const issued = await bounded(() => store.issue({ claimSecret, previousOperationId: current!.operationId }));
        current = { operationId: issued.operationId, code: issued.code, authExpiresAt: issued.authExpiresAt };
        return { status: 200, body: { code: issued.code, authExpiresAt: issued.authExpiresAt } };
      }
      case 'status': {
        if (current === null) return { status: 200, body: { state: 'ended' } };
        const operationId = current.operationId;
        const result = await bounded(() => consoleToken(store, auth, { claimSecret, operationId }, clock));
        if (result.kind === 'active') return { status: 200, body: { state: 'active', customToken: result.customToken } };
        // 未使用・期限内なら発行結果（コードと期限）を照会できる（通信断の回復。二重発行しない）。
        const reshow = result.kind === 'pending' && clock.now() < current.authExpiresAt ? { code: current.code, authExpiresAt: current.authExpiresAt } : {};
        return { status: 200, body: { state: result.kind, ...reshow } };
      }
      case 'cancel': {
        if (current === null) return { status: 200, body: { state: 'ended' } };
        const operationId = current.operationId;
        await bounded(() => store.cancel({ claimSecret, operationId }));
        current = null;
        return { status: 200, body: { state: 'ended' } };
      }
    }
  }

  return Object.freeze({
    async handle(req: IncomingMessage, res: ServerResponse, context: { readonly path: string; readonly method: string; readonly nonce: string; readonly origin: string }): Promise<void> {
      const { path, method, nonce, origin } = context;
      if (path === OPERATOR_SCRIPT_PATH) {
        if (method !== 'GET') return send(res, 405, { error: { code: 'method_not_allowed' } });
        const payload = Buffer.from(operatorScript(LOCAL_NONCE_HEADER), 'utf8');
        res.writeHead(200, { ...BASE_HEADERS, 'Content-Type': 'text/javascript; charset=utf-8', 'Content-Length': payload.length });
        res.end(payload);
        return;
      }
      const action = path.startsWith(OPERATOR_PATH_PREFIX) ? path.slice(OPERATOR_PATH_PREFIX.length) : '';
      if (!(OPERATOR_ACTIONS as readonly string[]).includes(action)) return send(res, 404, { error: { code: 'not_found' } });
      if (method !== 'POST') return send(res, 405, { error: { code: 'method_not_allowed' } });
      // 同originのブラウザ操作だけ（Origin必須・完全一致、起動nonce、JSON）。認証headerは受けない。
      if (req.headers.origin !== origin || req.headers[LOCAL_NONCE_HEADER.toLowerCase()] !== nonce || req.headers.authorization !== undefined) {
        log({ event: 'operator.refused', status: 403 });
        return send(res, 403, { error: { code: 'forbidden' } });
      }
      if ((req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase() !== 'application/json') return send(res, 415, { error: { code: 'invalid_request' } });
      const raw = await readSmallBody(req);
      if (raw === null || (raw !== '' && raw !== '{}')) return send(res, 400, { error: { code: 'invalid_request' } });
      if (busy) return send(res, 409, { error: { code: 'busy' } });
      busy = true;
      try {
        const { status, body } = await act(action as OperatorAction);
        log({ event: `operator.${action}`, status });
        return send(res, status, body);
      } catch (error) {
        const { status, code } = statusOf(error);
        log({ event: `operator.${action}`, status });
        return send(res, status, { error: { code } });
      } finally {
        busy = false;
      }
    },
  });
}

// ---------- CLI（実SDKはここだけ。試験はcreateOperatorRoutesへ合成portを渡す） ----------

export function parseOperatorArgs(argv: readonly string[]): { readonly configPath: string; readonly operatorPath: string; readonly port: number | undefined } {
  let configPath: string | undefined;
  let operatorPath: string | undefined;
  let port: number | undefined;
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.length > 4096) throw new Error('operator: invalid arguments');
    if (flag === '--config' && configPath === undefined) configPath = value;
    else if (flag === '--operator' && operatorPath === undefined) operatorPath = value;
    else if (flag === '--port' && port === undefined && /^[1-9][0-9]{3,4}$/.test(value) && Number(value) <= 65535) port = Number(value);
    else throw new Error('operator: invalid arguments');
  }
  if (configPath === undefined || operatorPath === undefined) throw new Error('operator: invalid arguments');
  return { configPath, operatorPath, port };
}

/** CLIが使う資格・SDKの生成口（試験は合成を渡し、実SDK・資格・networkに触れずに結線と順序を確かめる）。 */
export interface OperatorSdk {
  readonly readFile: (path: string) => string;
  readonly secretManager: () => Pick<SecretManagerServiceClient, 'accessSecretVersion'>;
  readonly applicationDefault: typeof applicationDefault;
  readonly initializeApp: typeof initializeApp;
  readonly getAuth: (app: App) => Pick<CodeAuthAdmin, 'createCustomToken'>;
  readonly firestore: (settings: { readonly projectId: string; readonly databaseId: string }) => Firestore;
  readonly startLocalConsole: typeof startLocalConsole;
}

const REAL_SDK: OperatorSdk = Object.freeze({
  readFile: (path: string) => readFileSync(path, 'utf8'),
  secretManager: () => new SecretManagerServiceClient(),
  applicationDefault,
  initializeApp,
  getAuth,
  firestore: (settings: { readonly projectId: string; readonly databaseId: string }) => new Firestore({ ...settings }),
  startLocalConsole,
});

export async function startOperatorConsole(argv: readonly string[], sdk: OperatorSdk = REAL_SDK): Promise<{ readonly origin: string }> {
  const args = parseOperatorArgs(argv);
  // 設定の検証（署名SAを含む）は資格・SDK生成・秘密読取りより前。不正なら固定errorで止まり、値を出さない。
  const operator = parseOperatorConfig(JSON.parse(sdk.readFile(args.operatorPath)) as unknown);
  const consoleConfig = JSON.parse(sdk.readFile(args.configPath)) as unknown;
  // 管理SDKの呼出しはoperator modeのCLI起動時だけ（通常の配信modeはこのmoduleをimportしない。API/MCP包装の閉包にも入らない）。
  const secrets = sdk.secretManager();
  // 接続server・送信APIと同じidentifierKey（32byte）。値はこのprocessのRAMだけで、鍵を導いた後に消す。
  const [version] = await secrets.accessSecretVersion({ name: operator.identifierKeySecretVersion });
  const data = version.payload?.data;
  const secret = data instanceof Uint8Array ? Buffer.from(data) : null;
  if (secret === null || secret.length !== 32) throw new Error('operator: identifier key unavailable');
  const keys = developerLoginKeys(secret);
  secret.fill(0);
  // custom tokenの署名先は設定で明示したSAだけ（ADCのclient_emailやmetadata serverへのfallbackに頼らない）。
  const app = sdk.initializeApp(
    { credential: sdk.applicationDefault(), projectId: operator.projectId, serviceAccountId: operator.signingServiceAccount },
    `sttd-operator-${process.pid}`,
  );
  const auth = sdk.getAuth(app);
  const db = sdk.firestore({ projectId: operator.projectId, databaseId: operator.databaseId });
  const clock: Clock = { now: () => Date.now() };
  const store = new DeveloperLoginStore({
    db,
    scope: { projectId: operator.projectId, databaseId: operator.databaseId, namespace: operator.namespace, purpose: DEVELOPER_LOGIN_PURPOSE },
    hasher: keys.hasher,
    sealer: keys.sealer,
    clock,
    random: defaultRandom,
  });
  const routes = createOperatorRoutes({ store, auth: { createCustomToken: (uid, claims) => auth.createCustomToken(uid, claims) }, clock });
  return sdk.startLocalConsole({ config: consoleConfig as never, port: args.port, operator: routes });
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startOperatorConsole(process.argv.slice(2)).then((started) => {
    process.stdout.write(`SendTextToDots operator console: ${started.origin}/console\n`);
  }).catch(() => {
    process.stderr.write('operator console: failed to start\n');
    process.exitCode = 1;
  });
}
