// gateway-v1配置のrole別組立て（API Functions入口・MCP Run入口が共有する）。副作用の前に次を確かめ、不成立は固定errorにする
// （IAM token取得・SDK module読込み・listen・転送の前。direct配置や匿名転送へ降格しない）:
//   - 配置設定がgateway-v1のtopologyを持つこと。
//   - 実行環境が設定の公開service（API: api.serviceName、MCP: connect.serviceName）であり、資格・metadata・proxy・TLSの宛先を差し替える
//     環境変数が無いこと（値は読まない）。
// 業務SDK（Firestore・KMS・Secret Manager・Firebase Admin）・DB・秘密はimportも初期化もしない。IAM tokenは固定backendのaudienceだけ。

import type { DeploymentConfig } from '../config/validate.js';
import { authorityOf, type GatewayClock, type GatewayRole, type GatewayTopology } from './contract.js';
import { createIdTokenSource, googleComputeIdTokenFetcher, type IdTokenFetcher } from './google-iam.js';
import { createGatewayHandler, type GatewayHandler, type GatewayTransport } from './http.js';

export type GatewayRuntimeErrorCode = 'gateway_config_invalid' | 'gateway_environment_rejected';

/** 固定codeだけの失敗（元の例外・環境の値を持たない）。 */
export class GatewayRuntimeError extends Error {
  override readonly name = 'GatewayRuntimeError';
  readonly code: GatewayRuntimeErrorCode;
  constructor(code: GatewayRuntimeErrorCode) {
    super(code);
    this.code = code;
  }
}

/** gatewayで拒否する環境変数（大小文字を区別しない。値は読まない）。 */
const REFUSED_GATEWAY_ENV: ReadonlySet<string> = new Set([
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_CLOUD_UNIVERSE_DOMAIN',
  'GCE_METADATA_HOST',
  'GCE_METADATA_IP',
  'GCE_METADATA_ROOT',
  'METADATA_SERVER_DETECTION',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'NODE_EXTRA_CA_CERTS',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
]);

/** gateway-v1のtopology（無ければ固定の設定error）。 */
export function requireGatewayTopology(config: DeploymentConfig): GatewayTopology {
  const topology = config.topology;
  if (topology === undefined) throw new GatewayRuntimeError('gateway_config_invalid');
  return topology;
}

/** 実行環境のgate（K_SERVICEの一致と拒否名の不在）。 */
export function checkGatewayEnvironment(env: NodeJS.ProcessEnv, expectedServiceName: string): void {
  for (const name of Object.keys(env)) {
    if (REFUSED_GATEWAY_ENV.has(name.toUpperCase())) throw new GatewayRuntimeError('gateway_environment_rejected');
  }
  if (env['K_SERVICE'] !== expectedServiceName) throw new GatewayRuntimeError('gateway_environment_rejected');
}

export interface GatewayRuntimeOptions {
  readonly role: GatewayRole;
  readonly config: DeploymentConfig;
  readonly env: NodeJS.ProcessEnv;
  readonly clock: GatewayClock;
  /** 試験の合成IAMだけ（既定はpinned google-gaxのCompute）。 */
  readonly fetcher?: IdTokenFetcher | undefined;
  /** 試験の合成loopbackだけ。 */
  readonly transport?: GatewayTransport | undefined;
  readonly connectTo?: { readonly host: string; readonly port: number } | undefined;
}

/** roleのgateway handlerを組み立てる（gateの後だけ。token取得は最初の転送要求まで行わない）。 */
export function createGatewayRuntime(options: GatewayRuntimeOptions): GatewayHandler {
  const { role, config } = options;
  const topology = requireGatewayTopology(config);
  checkGatewayEnvironment(options.env, role === 'api' ? config.api.serviceName : config.connect.serviceName);
  const backendOrigin = topology[role].backendOrigin;
  const tokens = createIdTokenSource({ audience: backendOrigin, fetcher: options.fetcher ?? googleComputeIdTokenFetcher(), clock: options.clock });
  return createGatewayHandler({
    role,
    backendOrigin,
    publicAuthority: role === 'connect' ? authorityOf(config.connect.publicOrigin) : undefined,
    limits: topology.limits,
    tokens,
    clock: options.clock,
    transport: options.transport,
    connectTo: options.connectTo,
  });
}
