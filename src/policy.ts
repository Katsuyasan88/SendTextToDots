// 認証・接続の期限と本文上限の製品値。値の正本は docs/API.md と docs/SECURITY.md。

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const DAY = 24 * 60 * MINUTE;

export interface AuthPolicy {
  /** ownerの最終認証利用からの無活動失効。 */
  readonly ownerInactivityMs: number;
  /** 接続画面のinteraction（login/consent）とprovider sessionの寿命。 */
  readonly interactionTtlMs: number;
  readonly accessTokenTtlSec: number;
  readonly authorizationCodeTtlSec: number;
  /** refresh tokenの無活動窓とGrantの上限。 */
  readonly refreshFamilyMaxSec: number;
}

export const PRODUCT_POLICY: AuthPolicy = Object.freeze({
  ownerInactivityMs: 90 * DAY,
  interactionTtlMs: 5 * MINUTE,
  accessTokenTtlSec: 15 * 60,
  authorizationCodeTtlSec: 60,
  refreshFamilyMaxSec: 90 * 24 * 60 * 60,
});

/** 接続Web・interactionの本文上限（バイト）。 */
export const MAX_BODY_BYTES = 4096;
/** POST /v2/commandsだけの本文上限（バイト）。値の正本は docs/API.md §2。 */
export const MAX_COMMAND_BODY_BYTES = 8192;
/**
 * 内部で組み立てて送る署名event（指示の配送の本文）の上限（バイト）。受信の上限（平文8192・暗号文12288）とは別。
 * 本文4096バイトの全文字がJSONの`\u00XX`（6バイト）へ展開されても収まるよう、4096×6＋固定envelope 512 = 25088。
 */
export const MAX_SIGNED_EVENT_BYTES = 4096 * 6 + 512;
/** /mcpの本文上限（バイト）。callback URLとsecretを含む購読要求が収まる値。 */
export const MAX_MCP_BODY_BYTES = 16 * 1024;

export interface Clock {
  /** 現在時刻（epochミリ秒）。 */
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

/** 接続保存の名前空間（`t256_<小文字UUID、版1〜8>`）。SDK非依存（配置設定の検証・gatewayからも使う）。 */
const CONNECT_NAMESPACE_PATTERN = /^t256_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isConnectNamespace(value: unknown): value is string {
  return typeof value === 'string' && CONNECT_NAMESPACE_PATTERN.test(value);
}

/** Google実行環境で、存在すれば（値を読まず）拒否する環境名（大文字で比較。SDK factory・gatewayが共有）。NO_PROXY・FIREBASE_CONFIGは含めない。 */
export const RUNTIME_REFUSED_ENV: ReadonlySet<string> = new Set([
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_OAUTH_ACCESS_TOKEN',
  'CLOUDSDK_AUTH_ACCESS_TOKEN',
  'FIREBASE_TOKEN',
  'GOOGLE_API_KEY',
  'GOOGLE_CLOUD_QUOTA_PROJECT',
  'GOOGLE_CLOUD_UNIVERSE_DOMAIN',
  'GOOGLE_API_USE_MTLS_ENDPOINT',
  'GOOGLE_API_USE_CLIENT_CERTIFICATE',
  'GOOGLE_SDK_NODE_LOGGING',
  'FIRESTORE_EMULATOR_HOST',
  'FIREBASE_AUTH_EMULATOR_HOST',
  'FIREBASE_DATABASE_EMULATOR_HOST',
  'STORAGE_EMULATOR_HOST',
  'FIRESTORE_PREFER_REST',
  'FIRESTORE_ENABLE_TRACING',
  'GCE_METADATA_HOST',
  'GCE_METADATA_IP',
  'METADATA_SERVER_DETECTION',
  'DETECT_GCP_RETRIES',
  'GRPC_TRACE',
  'GRPC_VERBOSITY',
  'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',
  'NODE_OPTIONS',
  'NODE_DEBUG',
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

/**
 * bounded-memory-hint-v1の文法（正規名NODE_OPTIONSの文字列・40文字以下）。(1) ASCII spaceだけ0〜8個、又は(2) 前後それぞれASCII space 0〜8個＋
 * 単一の`--max-old-space-size=N`（Nは先頭ゼロなし3桁128〜960）。trim・shell parser・coerce・他flagは無い（文字列全体をそのまま照合する）。
 */
const BOUNDED_MEMORY_HINT = /^ {0,8}(?:--max-old-space-size=(?:12[89]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-5][0-9]|960) {0,8})?$/;
const BOUNDED_MEMORY_HINT_MAX_LENGTH = 40;
/** 正規名NODE_OPTIONSの値がbounded-memory-hint-v1の文法を満たすか（値は改変しない）。 */
export function boundedMemoryHintAccepted(value: string | undefined): boolean {
  return typeof value === 'string' && value.length <= BOUNDED_MEMORY_HINT_MAX_LENGTH && BOUNDED_MEMORY_HINT.test(value);
}
