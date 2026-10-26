// 運営者だけが使う利用許可の管理（status・grant・revoke）。明示実行のCLI（scripts/manage-access.mjs）からだけ呼ばれ、API/MCP/consoleの
// runtimeはこのmoduleをimportしない（配布archiveの静的依存閉包に入らない）。import時のI/O・SDK生成0。
//   - 対象は編集・build済みの配置設定（src/config/deployment.ts）のproject・database・connectNamespaceだけ。CLIが渡す期待対象と完全一致し、
//     配置設定が有効（configured・accessPolicy）でなければSDK生成の前に固定codeで止める。任意URL・資格file・raw秘密・汎用DB操作は受けない。
//   - UIDは標準入力の1行1件だけ（argv・file・出力・ログへ出さない）。運営者が正規のFirebase利用者管理で確認したUIDを入力する。
//   - identityHashは接続保存の既存identity用HMAC（identifierKeyの固定数値版を既存secret readerと同じ形/CRC/期限検査で読み、RAMだけで使い0埋め）。
//     KMS封緘・OAuth鍵・cookie鍵・本文digest鍵は取得しない。
//   - statusは状態・世代の有無を出さず、state（absent/active/disabled）とFirestore updateTimeの版だけ。grant/revokeは読んだ版（初回はabsent）を
//     期待版として要求し、1 transaction（SDK maxAttempts 5以下）で同じ文書を読み、一致した時だけ1件書く。版違いはconflictで書かない。
//     結果不明（期限・障害）なら再書込みせず、statusで照合する。世代の乱数は閉包の外で1回だけ作る。
//   - 全体30秒（標準入力と処理25秒＋後始末5秒。呼出し元が待つ論理的な上限で、開始済みSDK処理の物理取消・RAMの物理消去は保証しない）。
//     出力は固定codeと非秘密の状態/版、後始末の失敗・未確定の固定field（cleanup）だけ（64KiB以下）。UID・鍵・identityHash・文書path・SDK例外は出さない。
//   - 実SDK（運営者のADC）は別factory openAdminSdkだけが作る。serverのmetadata資格gate・SDK factoryは使わず、変えない。試験は合成SDKを
//     runAccessAdminへ直接注入する（製品CLIから任意module/SDK/接続先を指定する口は無い）。

import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

import type { Firestore } from '@google-cloud/firestore';
import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import { loadDeploymentConfig, type DeploymentConfig } from '../config/validate.js';
import { createGoogleSecretReader } from '../keys/google-secret-reader.js';
import { createHmacHasher } from '../secrets.js';
import { accessDocRef, accessStatusOf, AccessUnavailableError, changeAccess, isAccessVersion, type AccessVersion } from './firestore.js';
import { AccessRecordError, isAccessGeneration, type AccessState } from './policy.js';

/** 1操作の全体の上限（入力・処理25秒＋後始末5秒）。どれも呼出し元が待つ論理的な上限で、開始済みSDK処理の物理取消ではない。 */
export const ADMIN_LIMIT_MS = 30_000;
/** 標準入力の読取りと管理処理（SDK生成・鍵・transaction）の上限（開始から）。 */
export const ADMIN_WORK_MS = 25_000;
/** SDKのclose等の後始末の上限（全体の元期限は延ばさない）。 */
export const ADMIN_CLEANUP_MS = 5_000;
/** 出力の上限（固定code・状態・版だけなので常に小さい）。 */
export const ADMIN_OUTPUT_LIMIT = 65_536;
/** 標準入力の上限（UID 1件と改行）。 */
export const ADMIN_STDIN_LIMIT = 1024;
/** SDKのtransactionの最大実行回数（外側で再試行しない）。 */
const MAX_TRANSACTION_ATTEMPTS = 5;
const KEY_BYTES = 32;
/** 現行の検証済みidentityと同じUIDの長さ（JS文字列の1〜128）。 */
const MAX_UID_LENGTH = 128;
/** 1行1件の入力で別の行・別の値に化け得る文字（C0/C1制御・行/段落区切り・BOM）。それ以外のUnicodeは変換せずそのまま使う。 */
const UID_REFUSED = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff]/;
const LONE_SURROGATE = /\p{Cs}/u;
const CONNECT_ROOT = 'sttdConnect';

export type AccessCommand = 'status' | 'grant' | 'revoke';

/** 固定の結果code。 */
export type AdminCode =
  | 'status'
  | 'changed'
  | 'unchanged'
  | 'conflict'
  | 'usage'
  | 'invalid_input'
  | 'unconfigured'
  | 'target_mismatch'
  | 'environment_rejected'
  | 'invalid_record'
  | 'unavailable'
  | 'timed_out';

export interface AdminResult {
  readonly code: AdminCode;
  /** status・changed・unchangedだけ。 */
  readonly state?: 'absent' | AccessState;
  /** status・unchangedだけ（changedの新しい版はstatusで確かめる）。 */
  readonly version?: AccessVersion;
  /** SDKの後始末が失敗（failed）・上限内に確定しなかった（unconfirmed）時だけ。codeのDB結果は書き換えない。 */
  readonly cleanup?: 'failed' | 'unconfirmed';
}

/** CLI引数を解析した要求（UIDを含まない）。 */
export interface AdminRequest {
  readonly command: AccessCommand;
  readonly target: { readonly projectId: string; readonly databaseId: string; readonly connectNamespace: string };
  /** grant/revokeだけ必須。 */
  readonly expected?: AccessVersion;
}

/** 管理操作が使うSDK（合成SDKの注入は試験だけ）。closeは成功・失敗とも呼ぶ。 */
export interface AdminSdk {
  readonly db: Pick<Firestore, 'collection' | 'runTransaction'>;
  /** identifierKeyの固定数値版を1回だけ読む（返却Bufferの所有は呼出し元）。 */
  readIdentifierKey(operation: { readonly deadlineAt: number; readonly signal: AbortSignal }): Promise<Buffer>;
  close(): Promise<void>;
}

export interface AdminDeps {
  /** 検証済みの配置設定を返す（既定はloadDeploymentConfig）。 */
  readonly config?: () => DeploymentConfig;
  /** 期待対象と配置設定が一致した後にだけ呼ぶSDK factory。 */
  readonly openSdk: (config: DeploymentConfig, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }) => Promise<AdminSdk>;
  readonly clock?: { now(): number };
  readonly newGeneration?: () => string;
  /** 操作の開始時刻（CLIが標準入力を読み始めた時刻。同じclock）。省略時は呼出し時。全体の元期限はここから数える。 */
  readonly startedAt?: number;
}

class AdminFailure extends Error {
  constructor(readonly code: AdminCode) {
    super(code);
    this.name = 'AdminFailure';
  }
}

/** CLI引数（`<status|grant|revoke> --project <id> --database <id> --namespace <t256_…> [--expect <version>]`）。不正はnull。 */
export function parseAdminArgs(argv: readonly string[]): AdminRequest | null {
  const [command, ...rest] = argv;
  if (command !== 'status' && command !== 'grant' && command !== 'revoke') return null;
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index];
    const value = rest[index + 1];
    if (!['--project', '--database', '--namespace', '--expect'].includes(name ?? '') || typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
    if (values.has(name!)) return null;
    values.set(name!, value);
  }
  const projectId = values.get('--project');
  const databaseId = values.get('--database');
  const connectNamespace = values.get('--namespace');
  if (projectId === undefined || databaseId === undefined || connectNamespace === undefined) return null;
  const expected = values.get('--expect');
  if (command === 'status' ? expected !== undefined : expected === undefined || !isAccessVersion(expected)) return null;
  return Object.freeze({
    command,
    target: Object.freeze({ projectId, databaseId, connectNamespace }),
    ...(expected === undefined ? {} : { expected }),
  });
}

/** 管理入力のUIDとして受け付けるか（現行の検証済みidentityと同じ1〜128文字。制御・行区切り・BOMは拒否。trim・正規化しない）。 */
export function isAdminUid(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= MAX_UID_LENGTH && !UID_REFUSED.test(value) && !LONE_SURROGATE.test(value);
}

/**
 * 標準入力の1行1件のUID（末尾の改行1つ（LFかCRLF）だけ許す）。不正UTF-8・空・余分な行・長すぎる値・制御文字はnull。
 * trim・置換・Unicode正規化をせず、入力のbytesどおりの文字列だけを返す。値は呼出し元のRAMだけで使う。
 */
export function parseUidInput(input: Buffer | string): string | null {
  // 文字列の入力は、UTF-8へ変換する前に孤立surrogateを拒否する（変換でU+FFFDへ置き換えて別のUIDにしない）。
  if (typeof input === 'string' && LONE_SURROGATE.test(input)) return null;
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  if (bytes.length === 0 || bytes.length > ADMIN_STDIN_LIMIT) return null;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  if (text.endsWith('\r\n')) text = text.slice(0, -2);
  else if (text.endsWith('\n')) text = text.slice(0, -1);
  return isAdminUid(text) ? text : null;
}

/** 固定の出力（1行JSON）。64KiBを超える形は作らない。 */
export function formatAdminResult(result: AdminResult): string {
  const line = `${JSON.stringify({
    code: result.code,
    ...(result.state === undefined ? {} : { state: result.state }),
    ...(result.version === undefined ? {} : { version: result.version }),
    ...(result.cleanup === undefined ? {} : { cleanup: result.cleanup }),
  })}\n`;
  return Buffer.byteLength(line) <= ADMIN_OUTPUT_LIMIT ? line : '{"code":"unavailable"}\n';
}

/**
 * 上限（limitAt）までにstartの結果が決まらなければ待つのをやめる。startは元期限・中止を検査してから呼び、過ぎていれば始めない。
 * 待つのをやめた後に届いた値はonLateへ渡す（遅いSDK handleを閉じる・遅い鍵を0埋めする）。始めたSDK処理の物理取消とは扱わない。
 */
function bounded<T>(start: () => Promise<T>, limitAt: number, now: () => number, signal: AbortSignal, onLate?: (value: T) => void): Promise<T> {
  const remaining = limitAt - now();
  if (signal.aborted || !(remaining > 0)) return Promise.reject(new AdminFailure('timed_out'));
  let work: Promise<T>;
  try {
    work = Promise.resolve(start());
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const giveUp = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', giveUp);
      reject(new AdminFailure('timed_out'));
    };
    const timer = setTimeout(giveUp, Math.ceil(remaining));
    signal.addEventListener('abort', giveUp, { once: true });
    work.then(
      (value) => {
        if (settled) {
          onLate?.(value);
          return;
        }
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', giveUp);
        if (signal.aborted || !(now() < limitAt)) {
          onLate?.(value);
          reject(new AdminFailure('timed_out'));
        } else {
          resolve(value);
        }
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', giveUp);
        reject(error);
      },
    );
  });
}

/** 遅れて届いた鍵Bufferを0埋めする。 */
function zeroLate(value: unknown): void {
  if (Buffer.isBuffer(value)) value.fill(0);
}

/** 遅れて開いたSDKを閉じることを試みる（待たない。物理的な終了は保証しない）。 */
function closeLate(value: unknown): void {
  try {
    void Promise.resolve((value as AdminSdk).close()).catch(() => {});
  } catch {
    // 閉じられない遅いhandleはprocessの終了に任せる。
  }
}

/**
 * 1操作を実行する（入力1件・1 transaction）。UIDはparseUidInput済みの値。戻り値は固定code（例外を外へ出さない）。
 * 開始（startedAt）から処理25秒・全体30秒を元期限とし、延長しない。期待対象の不一致・未設定はSDK生成の前に止める。
 * 元期限・中止の後は新しいSDK呼出し・transaction・書込みを始めない。期限前に始めたcommitが確定したかは不明（timed_out）として、
 * 再書込みせずstatusで照合する。SDKは成功・失敗ともcloseを後始末の上限内で試み、失敗・未確定はcleanup fieldで示す。
 */
export async function runAccessAdmin(request: AdminRequest, uid: string, deps: AdminDeps): Promise<AdminResult> {
  const clock = deps.clock ?? { now: () => Date.now() };
  const now = (): number => {
    try {
      const value = clock.now();
      return typeof value === 'number' && Number.isFinite(value) ? value : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  if (!isAdminUid(uid)) return { code: 'invalid_input' };
  let config: DeploymentConfig;
  try {
    config = (deps.config ?? loadDeploymentConfig)();
  } catch {
    return { code: 'unconfigured' };
  }
  const { target } = request;
  if (target.projectId !== config.projectId || target.databaseId !== config.databaseId || target.connectNamespace !== config.connectNamespace) {
    return { code: 'target_mismatch' };
  }
  const startedAt = Math.floor(deps.startedAt ?? now());
  if (!Number.isSafeInteger(startedAt)) return { code: 'unavailable' };
  const workDeadline = startedAt + ADMIN_WORK_MS;
  const deadlineAt = startedAt + ADMIN_LIMIT_MS;
  const remaining = workDeadline - now();
  if (!(remaining > 0)) return { code: 'timed_out' };
  const controller = new AbortController();
  const operation = Object.freeze({ deadlineAt: workDeadline, signal: controller.signal });
  const watchdog = setTimeout(() => controller.abort(), Math.ceil(remaining));
  /** 元期限・中止の検査（SDKの開始前・transactionの各実行・各await後・書込み直前）。 */
  const live = (): void => {
    if (controller.signal.aborted || !(now() < workDeadline)) throw new AdminFailure('timed_out');
  };
  let sdk: AdminSdk | undefined;
  let result: AdminResult;
  try {
    try {
      sdk = await bounded(() => deps.openSdk(config, operation), workDeadline, now, controller.signal, closeLate);
    } catch (error) {
      throw error instanceof AdminFailure ? error : new AdminFailure(error instanceof AdminEnvironmentError ? 'environment_rejected' : 'unavailable');
    }
    const opened = sdk;
    const key = await bounded(() => opened.readIdentifierKey(operation), workDeadline, now, controller.signal, zeroLate);
    let identityHash: string;
    try {
      if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw new AdminFailure('unavailable');
      identityHash = createHmacHasher(key).hash(`t256:${config.connectNamespace}:identity`, `${config.projectId}\0${uid}`);
    } finally {
      zeroLate(key);
    }
    const root = opened.db.collection(CONNECT_ROOT).doc(config.connectNamespace);
    const ref = accessDocRef(root, identityHash);
    if (request.command === 'status') {
      const status = await bounded(
        () => {
          live();
          return opened.db.runTransaction(
            async (tx) => {
              live();
              const snapshot = await tx.get(ref);
              live();
              return accessStatusOf(snapshot);
            },
            { readOnly: true },
          );
        },
        workDeadline,
        now,
        controller.signal,
      );
      result = { code: 'status', state: status.record?.state ?? 'absent', version: status.version };
    } else {
      // 世代と時刻は閉包の外で1回だけ決める（SDKが閉包を再実行しても同じ値）。
      const newGeneration = (deps.newGeneration ?? randomUUID)();
      const changedAt = Math.floor(now());
      if (!isAccessGeneration(newGeneration) || !Number.isSafeInteger(changedAt)) throw new AdminFailure('unavailable');
      const outcome = await bounded(
        () =>
          changeAccess(opened.db as Firestore, ref, {
            expected: request.expected!,
            desired: request.command === 'grant' ? 'active' : 'disabled',
            now: changedAt,
            newGeneration,
            maxAttempts: MAX_TRANSACTION_ATTEMPTS,
            live,
          }),
        workDeadline,
        now,
        controller.signal,
      );
      if (outcome.kind === 'conflict') result = { code: 'conflict' };
      else if (outcome.kind === 'changed') result = { code: 'changed', state: outcome.record.state };
      else result = { code: 'unchanged', state: outcome.record?.state ?? 'absent', version: request.expected! };
    }
  } catch (error) {
    if (error instanceof AdminFailure) result = { code: error.code };
    else if (error instanceof AccessRecordError) result = { code: 'invalid_record' };
    else result = { code: 'unavailable' };
  } finally {
    clearTimeout(watchdog);
  }
  if (sdk === undefined) return result;
  // 後始末: 元の全体期限（開始+30秒）と後始末開始+5秒の短い方まで待つ。確定したDB結果（code）は書き換えない。
  const closing = sdk;
  const cleanupDeadline = Math.min(deadlineAt, Math.floor(now()) + ADMIN_CLEANUP_MS);
  const cleanupController = new AbortController();
  if (!(cleanupDeadline > now())) {
    closeLate(closing);
    return { ...result, cleanup: 'unconfirmed' };
  }
  try {
    await bounded(() => closing.close(), cleanupDeadline, now, cleanupController.signal);
    return result;
  } catch (error) {
    return { ...result, cleanup: error instanceof AdminFailure ? 'unconfirmed' : 'failed' };
  }
}

// ---- 運営者のADCを使う実SDK factory（CLIだけ。試験では呼ばない） ----

/** 資格・宛先・TLS・proxy・emulatorを別経路へ変え得る環境名（存在すれば値を読まずに拒否）。 */
const REFUSED_ENV = new Set([
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_OAUTH_ACCESS_TOKEN',
  'CLOUDSDK_AUTH_ACCESS_TOKEN',
  'GOOGLE_API_KEY',
  'GOOGLE_CLOUD_UNIVERSE_DOMAIN',
  'GOOGLE_API_USE_MTLS_ENDPOINT',
  'GOOGLE_API_USE_CLIENT_CERTIFICATE',
  'FIRESTORE_EMULATOR_HOST',
  'FIREBASE_AUTH_EMULATOR_HOST',
  'FIRESTORE_PREFER_REST',
  'GCE_METADATA_HOST',
  'GCE_METADATA_IP',
  'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
  'NODE_EXTRA_CA_CERTS',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'OPENSSL_CONF',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'GRPC_PROXY_EXP',
]);

/** 環境の拒否（固定message）。 */
export class AdminEnvironmentError extends Error {
  override readonly name = 'AdminEnvironmentError';
  constructor() {
    super('admin environment rejected');
  }
}

/** SDK生成の前の環境gate（値は読まない）。 */
export function checkAdminEnvironment(env: NodeJS.ProcessEnv, projectId: string): void {
  for (const name of Object.keys(env)) if (REFUSED_ENV.has(name.toUpperCase())) throw new AdminEnvironmentError();
  for (const name of ['GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']) if (env[name] !== undefined && env[name] !== projectId) throw new AdminEnvironmentError();
}

/**
 * 運営者のADC（gcloudのapplication-default login等）でFirestore（配置設定のproject/database）とSecret Manager（identifierKeyの固定版だけ）を
 * 所有して開く。CLIからだけ呼ぶ。SDK moduleはここで初めて読む（import時0）。
 */
export async function openAdminSdk(config: DeploymentConfig, operation: { readonly deadlineAt: number; readonly signal: AbortSignal }): Promise<AdminSdk> {
  checkAdminEnvironment(process.env, config.projectId);
  const requireCjs = createRequire(import.meta.url);
  const firestoreModule = requireCjs('@google-cloud/firestore') as typeof import('@google-cloud/firestore');
  const secretModule = requireCjs('@google-cloud/secret-manager') as typeof import('@google-cloud/secret-manager');
  const db = new firestoreModule.Firestore({ projectId: config.projectId, databaseId: config.databaseId });
  let client: SecretManagerServiceClient | undefined;
  const close = async (): Promise<void> => {
    const results = await Promise.allSettled([db.terminate(), client?.close() ?? Promise.resolve()]);
    if (results.some((entry) => entry.status === 'rejected')) throw new Error('close failed');
  };
  try {
    client = new secretModule.SecretManagerServiceClient({ projectId: config.projectId });
    await client.initialize();
    if (operation.signal.aborted) throw new Error('aborted');
    const reader = createGoogleSecretReader({ client, projectNumber: config.projectNumber, versions: config.secretVersions, clock: { now: () => Date.now() } });
    return Object.freeze({
      db,
      readIdentifierKey: async (readOperation: { readonly deadlineAt: number; readonly signal: AbortSignal }) => {
        try {
          return await reader.read('identifierKey', { deadlineAt: readOperation.deadlineAt, signal: readOperation.signal });
        } finally {
          reader.dispose();
        }
      },
      close,
    });
  } catch (error) {
    await close().catch(() => {});
    throw error;
  }
}
