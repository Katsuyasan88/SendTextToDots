// 初期化済みの借用Google SDK client（KMS・Secret Manager）から実port（KMS transport・secret reader・connect secret source）を内部で組み立て、
// startDevelopmentKmsConnectServerへ渡す起動口。server.publicOriginは必須、kms.environmentはdevelopmentだけ。
// SDKの生成・initialize・ADC・metadata・任意factory/start注入をしない。秘密は先に読まず、serverの元20秒の中のsecrets.load callbackで1回だけ
// 読む（digest用途は取得0）。loadがcallerへ移したcookieKeys/identifierKeyのBufferは、このwrapperのledgerへ記録し、server startの成功/失敗が
// 確定したfinallyで0埋めする（serverは先に内部copyを作るので、稼働に要るcopyは消さない。JWKの文字列の完全消去は保証しない）。終了の後に
// 届いたloadの結果は採用せず即時0埋めして固定の起動失敗にする。reader/sourceはstartのfinallyでdispose、transportはserverの稼働中だけ
// 生かしてclose・起動失敗でdisposeする。SDK client・db・identity・egress・senderは借用でclose/terminate/dispose0、DB削除0。
// 失敗は固定の3 error（cause・元のSDK error・秘密・値なし）だけ。このwrapper自身はログを出さない（serverへ渡すlogは固定fieldだけ）。
// 任意のserver.startupOperation（起動親）を捕捉し、既中断・期限到達を副作用の前に起動失敗にする。serverへは同じ親deadlineとbridge専有scopeの
// signalの写しを渡す。sourceへは起動専用reader wrapperを渡し、各readを元のoperationと親の短いdeadline・両signalへ結合する。親の中断・親deadlineの
// 実timerで起動scopeを止めてreader/sourceをdisposeし、成功・失敗とも親のlistener・timerを外す。

import type { KeyManagementServiceClient } from '@google-cloud/kms';
import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import { createGoogleConnectSecretSource, type GoogleConnectSecretSource } from '../keys/google-connect-secrets.js';
import {
  createGoogleSecretReader,
  type GoogleSecretPurpose,
  type GoogleSecretReader,
  type GoogleSecretReadOperation,
  type GoogleSecretVersions,
} from '../keys/google-secret-reader.js';
import {
  arrayItems,
  captureClock,
  dataFields,
  GoogleSdkPortError,
  isEpochMs,
  isRealSignal,
  type GoogleSdkPortErrorCode,
} from '../protection/google-sdk-call.js';
import { createGoogleKmsTransport, type GoogleKmsTransport } from '../protection/google-kms-transport.js';
import {
  KmsConnectServerConfigError,
  startDevelopmentKmsConnectServer,
  type KmsConnectKeys,
  type KmsConnectKmsConfig,
  type KmsConnectServer,
  type KmsConnectServerOptions,
} from './kms-server.js';

/** 入力の不正（serverの設定不正・port factoryの入力不正を含む）。副作用（秘密RPC・DB・listen）の前に返す。 */
export class GoogleKmsConnectConfigError extends Error {
  override readonly name = 'GoogleKmsConnectConfigError';
  readonly code = 'google_kms_connect_config_invalid';
  constructor() {
    super('google_kms_connect_config_invalid');
  }
}

/** 起動の失敗（serverの起動失敗・秘密の読込み・内部障害）。所有port/source/readerと元Bufferは片付け済み。 */
export class GoogleKmsConnectStartupError extends Error {
  override readonly name = 'GoogleKmsConnectStartupError';
  readonly code = 'google_kms_connect_startup_failed';
  constructor() {
    super('google_kms_connect_startup_failed');
  }
}

/** closeが成功しなかった（server closeの上限・失敗）。完了と偽らない。 */
export class GoogleKmsConnectCloseError extends Error {
  override readonly name = 'GoogleKmsConnectCloseError';
  readonly code = 'google_kms_connect_close_failed';
  constructor() {
    super('google_kms_connect_close_failed');
  }
}

/** KmsConnectServerOptionsからkms・secretsを除いたもの（publicOriginは必須）。 */
export type GoogleKmsConnectServerOptions = Omit<KmsConnectServerOptions, 'kms' | 'secrets'>;

/** KmsConnectKmsConfigからtransportを除いたもの（environmentはdevelopmentだけ）。 */
export type GoogleKmsConnectKmsOptions = Omit<KmsConnectKmsConfig, 'transport'>;

export interface GoogleKmsConnectGoogleOptions {
  /** callerが生成・`initialize()`した借用KMS client（grpc.enable_retries:0はcallerの前提）。close0。 */
  readonly kmsClient: KeyManagementServiceClient;
  /** callerが生成・`initialize()`した借用Secret Manager client。close0。 */
  readonly secretClient: SecretManagerServiceClient;
  /** 正規10進のproject number。 */
  readonly projectNumber: string;
  /** 4用途の固定数値版（このstartはjwks・cookieKeys・identifierKeyだけを読む）。 */
  readonly secretVersions: GoogleSecretVersions;
}

export interface GoogleKmsConnectOptions {
  readonly server: GoogleKmsConnectServerOptions;
  readonly kms: GoogleKmsConnectKmsOptions;
  readonly google: GoogleKmsConnectGoogleOptions;
}

/** `{issuer, resource, close}`（frozen）。closeは同じPromiseで冪等、失敗はGoogleKmsConnectCloseError。 */
export type GoogleKmsConnectServer = KmsConnectServer;

const TOP_KEYS = ['server', 'kms', 'google'] as const;
const SERVER_KEYS = ['bindPort', 'db', 'namespace', 'identity', 'web', 'clientEgress', 'verificationSender', 'clock', 'publicOrigin'] as const;
const SERVER_OPTIONAL = ['log', 'startupOperation', 'developerCode'] as const;
const STARTUP_OPERATION_KEYS = ['deadlineAt', 'signal'] as const;
/** setTimeoutの遅延の上限（これを越える値はNodeが1msへ置き換える）。 */
const MAX_TIMER_MS = 2_147_483_647;
const KMS_KEYS = ['environment', 'projectId', 'databaseId', 'namespace', 'cryptoKey', 'writeVersion', 'readVersions'] as const;
const GOOGLE_KEYS = ['kmsClient', 'secretClient', 'projectNumber', 'secretVersions'] as const;

/** 入力から1回だけ読んだ値（以後は入力objectを読み直さない）。 */
interface Captured {
  readonly server: Map<string, unknown>;
  readonly kms: Map<string, unknown>;
  readonly readVersions: unknown[];
  readonly google: Map<string, unknown>;
  readonly clock: unknown;
  /** 任意の起動親（捕捉した写し）。省略はnull。 */
  readonly parent: Readonly<{ deadlineAt: number; signal: AbortSignal }> | null;
}

/** exact own data（Proxy・accessor・symbol・未知/欠落の名前を拒否、getterを呼ばない）。不正は固定invalid_input。 */
function capture(options: unknown): Captured {
  const top = dataFields(options, TOP_KEYS);
  const server = dataFields(top.get('server'), SERVER_KEYS, SERVER_OPTIONAL);
  const kms = dataFields(top.get('kms'), KMS_KEYS);
  // environment=developmentだけ（port・sourceを作る前に拒否。publicOriginの正規形はserver startが副作用の前に検査）。
  if (kms.get('environment') !== 'development') throw new GoogleKmsConnectConfigError();
  const readVersions = arrayItems(kms.get('readVersions'));
  const google = dataFields(top.get('google'), GOOGLE_KEYS);
  // 起動親は正確なown dataの2key・epoch ms・genuine AbortSignalだけを1回捕捉する（以後callerの改変を読まない）。
  let parent: Captured['parent'] = null;
  const parentInput = server.get('startupOperation');
  if (parentInput !== undefined) {
    const fields = dataFields(parentInput, STARTUP_OPERATION_KEYS);
    const deadlineAt = fields.get('deadlineAt');
    const signal = fields.get('signal');
    if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) throw new GoogleKmsConnectConfigError();
    parent = Object.freeze({ deadlineAt, signal });
  }
  return { server, kms, readVersions, google, clock: server.get('clock'), parent };
}

/** 起動の間だけ使うreaderの形（GoogleConnectSecretSourceへ渡す）。 */
type StartupReader = Pick<GoogleSecretReader, 'read'>;

/**
 * 起動専用のreader wrapper（bridge内部だけ）。各readの元operation（sourceの元5秒）と起動親の短いdeadlineを固定し、
 * 元のsignalと起動scopeのsignalを所有childへ結合して実readerへ渡す。開始前・await後（Bufferをsourceへ移す前）に同じclock・両signal・
 * 固定deadlineを確かめ、移せないBufferは0埋めして固定失敗にする。時計が親期限を越えていれば起動scopeも止める。joinのlistenerは
 * 成功・失敗・中断のどれでも外す。後着SDK応答の消去は実readerの契約のまま。
 */
function startupReader(
  reader: GoogleSecretReader,
  parentDeadline: number,
  scope: AbortSignal,
  now: () => number | null,
  stopScope: () => void,
): StartupReader {
  const liveCode = (signal: AbortSignal, deadline: number): GoogleSdkPortErrorCode | null => {
    if (scope.aborted || signal.aborted) return 'aborted';
    const at = now();
    if (scope.aborted || signal.aborted) return 'aborted';
    if (at === null) return 'unavailable';
    if (!(at < parentDeadline)) {
      stopScope();
      return 'timed_out';
    }
    return at < deadline ? null : 'timed_out';
  };
  const read = async (purpose: GoogleSecretPurpose, operation: GoogleSecretReadOperation): Promise<Buffer> => {
    let deadlineAt: unknown;
    let signal: unknown;
    try {
      const fields = dataFields(operation, STARTUP_OPERATION_KEYS);
      deadlineAt = fields.get('deadlineAt');
      signal = fields.get('signal');
    } catch {
      throw new GoogleSdkPortError('invalid_input');
    }
    if (!isEpochMs(deadlineAt) || !isRealSignal(signal)) throw new GoogleSdkPortError('invalid_input');
    const deadline = Math.min(deadlineAt, parentDeadline);
    const child = new AbortController();
    const join = (): void => child.abort();
    signal.addEventListener('abort', join, { once: true });
    scope.addEventListener('abort', join, { once: true });
    try {
      const before = liveCode(signal, deadline);
      if (before !== null) throw new GoogleSdkPortError(before);
      let value: Buffer;
      try {
        value = await reader.read(purpose, Object.freeze({ deadlineAt: deadline, signal: child.signal }));
      } catch (error) {
        throw new GoogleSdkPortError(error instanceof GoogleSdkPortError ? error.code : 'unavailable');
      }
      const after = liveCode(signal, deadline);
      if (after !== null) {
        value.fill(0);
        throw new GoogleSdkPortError(after);
      }
      return value;
    } finally {
      signal.removeEventListener('abort', join);
      scope.removeEventListener('abort', join);
    }
  };
  return Object.freeze({ read });
}

interface OwnedPorts {
  readonly transport: GoogleKmsTransport;
  readonly reader: GoogleSecretReader;
  readonly source: GoogleConnectSecretSource;
}

/**
 * port（RPC・鍵取得・初期化0の構成だけ、時計はserver.clockと同じobject）。不正は作ったものだけをdisposeして設定エラー。
 * wrapがあれば、sourceへは実readerの代わりに起動専用wrapperを渡す（reader/source本体は同じ）。
 */
function buildPorts(captured: Captured, wrap?: (reader: GoogleSecretReader) => StartupReader): OwnedPorts {
  const { kms, readVersions, google } = captured;
  const clock = captured.clock as { now(): number };
  let transport: GoogleKmsTransport | undefined;
  let reader: GoogleSecretReader | undefined;
  try {
    transport = createGoogleKmsTransport({
      client: google.get('kmsClient') as KeyManagementServiceClient,
      projectId: kms.get('projectId') as string,
      cryptoKey: kms.get('cryptoKey') as string,
      writeVersion: kms.get('writeVersion') as number,
      readVersions: [...readVersions] as number[],
      clock,
    });
    reader = createGoogleSecretReader({
      client: google.get('secretClient') as SecretManagerServiceClient,
      projectNumber: google.get('projectNumber') as string,
      versions: google.get('secretVersions') as GoogleSecretVersions,
      clock,
    });
    const source = createGoogleConnectSecretSource({ reader: wrap === undefined ? reader : wrap(reader), clock });
    return { transport, reader, source };
  } catch {
    reader?.dispose();
    transport?.dispose();
    throw new GoogleKmsConnectConfigError();
  }
}

/**
 * 初期化済みの借用Google SDKからportを組み立て、startDevelopmentKmsConnectServerで起動する（先読み0・元20秒の中のload 1回・callerへ移された
 * Bufferの成功/失敗/後着の0埋め・close共有Promise・借用SDK/dbのclose0）。入力不正（publicOrigin・environment=development以外を含む）は
 * 副作用の前にGoogleKmsConnectConfigError、起動の失敗はGoogleKmsConnectStartupError。
 */
export async function startDevelopmentGoogleKmsConnectServer(options: GoogleKmsConnectOptions): Promise<GoogleKmsConnectServer> {
  let captured: Captured;
  try {
    captured = capture(options);
  } catch {
    throw new GoogleKmsConnectConfigError();
  }
  const { server, kms, readVersions, parent } = captured;

  // 起動親があれば、既中断・期限到達をport生成・秘密RPC・DB・listenの前に固定の起動失敗にする。
  let now: () => number | null = () => null;
  let parentStartedAt = 0;
  if (parent !== null) {
    try {
      now = captureClock(captured.clock);
    } catch {
      throw new GoogleKmsConnectConfigError();
    }
    if (parent.signal.aborted) throw new GoogleKmsConnectStartupError();
    const at = now();
    if (parent.signal.aborted || at === null || !(at < parent.deadlineAt)) throw new GoogleKmsConnectStartupError();
    parentStartedAt = at;
  }
  /**
   * 起動scope（bridge専有）。親の中断・親deadlineの実timer・時計の親期限越えで止まり、起動専用reader/sourceもdisposeする
   * （新read0）。callerのsignalはabortしない。KMS transportは起動後の通常要求にも使うので、このscopeへ束縛しない。
   */
  const startup = new AbortController();
  let ports: OwnedPorts | undefined;
  const stopStartup = (): void => {
    if (startup.signal.aborted) return;
    startup.abort();
    ports?.source.dispose();
    ports?.reader.dispose();
  };
  ports = buildPorts(
    captured,
    parent === null ? undefined : (reader) => startupReader(reader, parent.deadlineAt, startup.signal, now, stopStartup),
  );
  const { transport: ownedTransport, reader: ownedReader, source } = ports;
  let parentTimer: ReturnType<typeof setTimeout> | undefined;
  if (parent !== null) {
    parent.signal.addEventListener('abort', stopStartup, { once: true });
    // 開始時の同じ親deadlineからの残り（延長しない）。setTimeoutの上限（2^31-1ms）を越える遠い親は上限で切り詰める（越えるとNodeは
    // 1msで発火させるため）。起動自体はserverの元20秒で必ず終わるので、切り詰めた時刻には到達しない。
    parentTimer = setTimeout(stopStartup, Math.min(Math.max(0, parent.deadlineAt - parentStartedAt), MAX_TIMER_MS));
    if (parent.signal.aborted) stopStartup();
  }

  /** loadがcallerへ移したcookieKeys/identifierKeyのBuffer（server startの確定後に0埋めする）。 */
  const ledger = new Set<Buffer>();
  let ended = false;
  let loadUsed = false;
  const wipe = (keys: KmsConnectKeys): void => {
    for (const key of keys.cookieKeys) key.fill(0);
    keys.identifierKey.fill(0);
  };
  /** serverの元20秒の中で1回だけ呼ばれるload。終了後・2回目は新しいRPCを始めない。終了後に届いた成功は即時0埋めして固定失敗。 */
  const load = async (): Promise<KmsConnectKeys> => {
    if (ended || loadUsed) throw new GoogleKmsConnectStartupError();
    loadUsed = true;
    let keys: KmsConnectKeys;
    try {
      keys = await source.load();
    } catch {
      throw new GoogleKmsConnectStartupError();
    }
    if (ended) {
      wipe(keys);
      throw new GoogleKmsConnectStartupError();
    }
    for (const key of keys.cookieKeys) ledger.add(key);
    ledger.add(keys.identifierKey);
    return keys;
  };

  const serverOptions: Record<string, unknown> = {};
  for (const [key, value] of server) if (value !== undefined && key !== 'startupOperation') serverOptions[key] = value;
  // serverへは安全な写し（同じ親deadline・bridge専有scopeのsignal）だけを渡す。
  if (parent !== null) serverOptions.startupOperation = Object.freeze({ deadlineAt: parent.deadlineAt, signal: startup.signal });
  serverOptions.kms = {
    environment: kms.get('environment'),
    projectId: kms.get('projectId'),
    databaseId: kms.get('databaseId'),
    namespace: kms.get('namespace'),
    cryptoKey: kms.get('cryptoKey'),
    writeVersion: kms.get('writeVersion'),
    readVersions: [...readVersions],
    transport: ownedTransport,
  };
  serverOptions.secrets = { load };

  let started: KmsConnectServer | undefined;
  let configFailed = false;
  try {
    started = await startDevelopmentKmsConnectServer(serverOptions as unknown as KmsConnectServerOptions);
  } catch (error) {
    configFailed = error instanceof KmsConnectServerConfigError;
  } finally {
    // 成功・失敗とも起動親のlistenerと親deadlineのtimerを外す（成功後は起動親の期限・中断でserverを止めない）。
    clearTimeout(parentTimer);
    parent?.signal.removeEventListener('abort', stopStartup);
    // 終了の印を先に立て、source/readerを止めてから、callerへ移されたBufferを0埋めして手放す。
    ended = true;
    source.dispose();
    ownedReader.dispose();
    for (const key of ledger) key.fill(0);
    ledger.clear();
    if (started === undefined) ownedTransport.dispose();
  }
  if (started === undefined) throw configFailed ? new GoogleKmsConnectConfigError() : new GoogleKmsConnectStartupError();

  const inner = started;
  let closePromise: Promise<void> | undefined;
  /** 共有Promiseを副作用より先に確定し（abort・disposeからの再入も同じPromise）、server closeが同期にHTTPを止めた後でtransportをdisposeする。 */
  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    let settle: { resolve: () => void; reject: () => void } | undefined;
    closePromise = new Promise<void>((resolve, reject) => {
      settle = { resolve, reject: () => reject(new GoogleKmsConnectCloseError()) };
    });
    let innerClosed: Promise<void>;
    try {
      innerClosed = Promise.resolve(inner.close());
    } catch {
      innerClosed = Promise.reject(new GoogleKmsConnectCloseError());
    }
    ownedTransport.dispose();
    innerClosed.then(
      () => settle?.resolve(),
      () => settle?.reject(),
    );
    return closePromise;
  };

  return Object.freeze({ issuer: inner.issuer, resource: inner.resource, close });
}
