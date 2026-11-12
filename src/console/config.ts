// ローカル送信画面（src/console/local-server.ts）のclient設定。公開してよい値だけ（API/MCPの固定https origin、Firebase Webの公開設定）を
// JSON fileから1回読み、形を検査する。秘密・資格・ID token・本文・Cloudの配置設定は含めない。未知keyは拒否し、runtime originを
// Web入力やqueryで変える口は無い。値はerrorへ載せない。

import { readFileSync } from 'node:fs';

import { isDevelopmentPublicOrigin } from '../http/origin.js';

/** 設定の不正（固定codeだけ。値・pathを持たない）。 */
export class ConsoleConfigFileError extends Error {
  override readonly name = 'ConsoleConfigFileError';
  constructor(readonly code: 'unreadable' | 'invalid_json' | 'invalid') {
    super(`console_config_${code}`);
  }
}

export interface LocalConsoleConfig {
  /** 送信API（Functions）の固定https origin。 */
  readonly apiOrigin: string;
  /** MCP/OAuth serviceの固定https origin（/v1/web/*）。 */
  readonly mcpOrigin: string;
  readonly firebase: {
    readonly apiKey: string;
    readonly authDomain: string;
    readonly projectId: string;
  };
  /**
   * 任意: 管理者が登録した開発者環境（許可元strictの配置）。source IDと、このPCだけに置くEd25519秘密鍵（PKCS#8 PEM）のfile path。
   * helperは起動時に鍵を1回読んでmemoryだけに持ち、固定上流（apiOriginの送信・mcpOriginの送信アプリ登録または旧接続承認）向けの要求だけに署名する。
   * 鍵の本文はbrowser・URL・CLI引数・ログへ出さない。
   */
  readonly connectedApps?: true | undefined;
  readonly source?: { readonly sourceId: string; readonly keyFile: string } | undefined;
}

const TOP_KEYS = ['apiOrigin', 'mcpOrigin', 'firebase'] as const;
const SOURCE_KEYS = ['sourceId', 'keyFile'] as const;
const SOURCE_ID = /^src_[a-z2-7]{26}$/;
const FIREBASE_KEYS = ['apiKey', 'authDomain', 'projectId'] as const;
const DNS_HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
/** 公開client設定の文字列（制御文字・引用符・空白・HTML/JS区切りを含まない）。 */
const PLAIN = /^[A-Za-z0-9._:-]{1,256}$/;

function fail(): never {
  throw new ConsoleConfigFileError('invalid');
}

function plainObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>;
  const own = Object.keys(record);
  if (own.length !== keys.length || !keys.every((key) => own.includes(key))) fail();
  return record;
}

/** 解析済みの値を検査して凍結した設定を返す（file読取りと分離。試験は合成objectを渡せる）。 */
export function validateLocalConsoleConfig(value: unknown): LocalConsoleConfig {
  const hasSource = typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).includes('source');
  const hasConnectedApps = typeof value === 'object' && value !== null && Object.hasOwn(value, 'connectedApps');
  const top = plainObject(value, [...TOP_KEYS, ...(hasSource ? ['source'] : []), ...(hasConnectedApps ? ['connectedApps'] : [])]);
  if (hasConnectedApps && (top.connectedApps !== true || !hasSource)) fail();
  let source: LocalConsoleConfig['source'];
  if (hasSource) {
    const entry = plainObject(top.source, SOURCE_KEYS);
    if (typeof entry.sourceId !== 'string' || !SOURCE_ID.test(entry.sourceId)) fail();
    if (typeof entry.keyFile !== 'string' || entry.keyFile.length < 1 || entry.keyFile.length > 1024 || /[\0\r\n]/.test(entry.keyFile)) fail();
    source = Object.freeze({ sourceId: entry.sourceId, keyFile: entry.keyFile });
  }
  const apiOrigin = top.apiOrigin;
  const mcpOrigin = top.mcpOrigin;
  if (!isDevelopmentPublicOrigin(apiOrigin) || !isDevelopmentPublicOrigin(mcpOrigin) || apiOrigin === mcpOrigin) fail();
  const firebase = plainObject(top.firebase, FIREBASE_KEYS);
  for (const key of FIREBASE_KEYS) if (typeof firebase[key] !== 'string' || !PLAIN.test(firebase[key] as string)) fail();
  if (!DNS_HOST.test(firebase.authDomain as string)) fail();
  return Object.freeze({
    apiOrigin,
    mcpOrigin,
    firebase: Object.freeze({ apiKey: firebase.apiKey as string, authDomain: firebase.authDomain as string, projectId: firebase.projectId as string }),
    ...(source !== undefined ? { source } : {}),
    ...(hasConnectedApps ? { connectedApps: true as const } : {}),
  });
}

/** JSON fileを1回読んで検査する。読取り失敗・不正JSON・不正な形は固定codeのerror（pathや内容を含まない）。 */
export function loadLocalConsoleConfig(path: string): LocalConsoleConfig {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw new ConsoleConfigFileError('unreadable');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ConsoleConfigFileError('invalid_json');
  }
  return validateLocalConsoleConfig(parsed);
}
