// gateway-v1配置のrole別組立て（API Functions入口・MCP Run入口が共有する）。副作用の前に次を確かめ、不成立は固定errorにする
// （IAM token取得・SDK module読込み・listen・転送の前。direct配置や匿名転送へ降格しない）:
//   - 配置設定がgateway-v1のtopologyを持つこと。
//   - 実行環境が既存SDK factoryと同じ条件を満たすこと: 資格・endpoint・emulator・metadata・proxy・TLS・注入/診断・retryを差し替える
//     環境名（../policy.jsのRUNTIME_REFUSED_ENV。値は読まない）が無く、K_SERVICEが設定の公開service（API: api.serviceName、MCP:
//     connect.serviceName）、K_REVISION/K_CONFIGURATIONが正規名、GOOGLE_CLOUD_PROJECT/GCLOUD_PROJECTがあれば設定のproject。例外は
//     API Functionsの正規名NODE_OPTIONSのbounded-memory-hint-v1だけ（既存のAPI gateと同じ文法）。
// 業務SDK（Firestore・KMS・Secret Manager・Firebase Admin）・DB・秘密はimportも初期化もしない。IAM tokenは固定backendのaudienceだけを
// 公式metadata identity endpointへの固定HTTPで取得する（src/gateway/google-iam.ts）。

import type { DeploymentConfig } from '../config/validate.js';
import { authorityOf, type GatewayClock, type GatewayRole, type GatewayTopology } from './contract.js';
import { boundedMemoryHintAccepted, RUNTIME_REFUSED_ENV } from '../policy.js';
import { createIdTokenSource, metadataIdTokenFetcher, type IdTokenFetcher } from './google-iam.js';
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

const CLOUD_RUN_NAME = /^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/;

/** gateway-v1のtopology（無ければ固定の設定error）。 */
export function requireGatewayTopology(config: DeploymentConfig): GatewayTopology {
  const topology = config.topology;
  if (topology === undefined) throw new GatewayRuntimeError('gateway_config_invalid');
  return topology;
}

/** 実行環境のgate（既存SDK factoryと同じ拒否名・identity条件。APIだけ正規名NODE_OPTIONSのbounded memory hintを許す）。 */
export function checkGatewayEnvironment(env: NodeJS.ProcessEnv, role: GatewayRole, config: DeploymentConfig): void {
  const reject = (): never => {
    throw new GatewayRuntimeError('gateway_environment_rejected');
  };
  for (const name of Object.keys(env)) {
    const upper = name.toUpperCase();
    if (!RUNTIME_REFUSED_ENV.has(upper)) continue;
    if (role === 'api' && upper === 'NODE_OPTIONS' && name === 'NODE_OPTIONS' && boundedMemoryHintAccepted(env[name])) continue;
    reject();
  }
  if (env['K_SERVICE'] !== (role === 'api' ? config.api.serviceName : config.connect.serviceName)) reject();
  for (const name of ['K_REVISION', 'K_CONFIGURATION']) {
    const value = env[name];
    if (typeof value !== 'string' || !CLOUD_RUN_NAME.test(value)) reject();
  }
  for (const name of ['GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']) {
    const value = env[name];
    if (value !== undefined && value !== config.projectId) reject();
  }
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
  checkGatewayEnvironment(options.env, role, config);
  const backendOrigin = topology[role].backendOrigin;
  const tokens = createIdTokenSource({ audience: backendOrigin, fetcher: options.fetcher ?? metadataIdTokenFetcher(), clock: options.clock });
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
