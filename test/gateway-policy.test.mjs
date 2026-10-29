// gateway-v1配置の設定・route・backend adapterの合成回帰（pure。network・SDK・資格 0）。
//   - 配置設定: topology省略/'direct'は従来どおり（結果にkey自体が無い）。gateway-v1は全fieldの明示だけで、欠落・未知key・同名/同主体/
//     同origin・http・範囲外の上限は固定の設定error（directへ降格しない）。
//   - route表: 既存の公開routeだけを許可し、未知path・method・不正なrequest-target・encodeやdot segmentでの迂回を拒否する。
//   - backend adapter: transport authorityの一致・Host1件・残時間1件（1〜20000）だけを受け、Hostを公開authorityへ結び内部headerを除く。

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DeploymentConfigError, validateDeploymentConfig } from '../dist/config/validate.js';
import { matchGatewayRoute } from '../dist/gateway/contract.js';
import { admitBackendRequest } from '../dist/gateway/backend.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { BACKEND, topologyConfig, topologyOf } from './fixtures/gateway-runtime.mjs';

const invalid = (config) => assert.throws(() => validateDeploymentConfig(config), (error) => error instanceof DeploymentConfigError && error.code === 'deployment_config_invalid');

test('配置設定: 省略と"direct"は従来のdirect配置（topology keyなし）、gateway-v1は凍結した検証済み値', () => {
  const direct = validateDeploymentConfig(structuredClone(SYNTHETIC));
  assert.equal('topology' in direct, false);
  assert.equal('topology' in validateDeploymentConfig({ ...structuredClone(SYNTHETIC), topology: 'direct' }), false);
  const gateway = validateDeploymentConfig(topologyConfig());
  assert.equal(gateway.topology.mode, 'gateway-v1');
  assert.equal(gateway.topology.api.backendOrigin, BACKEND.api);
  assert.equal(gateway.topology.connect.backendServiceName, 'sendtexttodots-connect-backend');
  assert.ok(Object.isFrozen(gateway.topology) && Object.isFrozen(gateway.topology.limits));
  // 既存fieldは不変（API名・公開URL・許可元の既定）。
  assert.equal(gateway.api.functionName, 'sendtexttodotsapi');
  assert.equal(gateway.api.publicOrigin, direct.api.publicOrigin);
  assert.equal(gateway.sourceAuthorization, 'compatible');
});

test('配置設定: 不正なgateway-v1はdirectへ降格せず設定error', () => {
  const base = topologyOf();
  const cases = [
    'gateway',
    {},
    { ...base, mode: 'gateway-v2' },
    { ...base, extra: true },
    { ...base, limits: undefined },
    { ...base, api: { ...base.api, backendServiceName: 'sendtexttodotsapi' } },
    { ...base, connect: { ...base.connect, backendServiceName: base.api.backendServiceName } },
    { ...base, api: { ...base.api, backendOrigin: SYNTHETIC.api.publicOrigin } },
    { ...base, connect: { ...base.connect, backendOrigin: base.api.backendOrigin } },
    { ...base, api: { ...base.api, backendOrigin: 'http://sendtexttodots-api-backend.example.com' } },
    { ...base, api: { ...base.api, backendOrigin: `${BACKEND.api}/path` } },
    { ...base, api: { ...base.api, gatewayServiceAccount: SYNTHETIC.api.serviceAccount } },
    { ...base, connect: { ...base.connect, gatewayServiceAccount: base.api.gatewayServiceAccount } },
    { ...base, api: { ...base.api, gatewayServiceAccount: 'gw@other-project.iam.gserviceaccount.com' } },
    { ...base, limits: { ...base.limits, maxBodyBytes: 0 } },
    { ...base, limits: { ...base.limits, maxBodyBytes: 1_048_577 } },
    { ...base, limits: { ...base.limits, maxConcurrent: 1.5 } },
    { ...base, limits: { ...base.limits, burst: '10' } },
    { ...base, limits: { maxBodyBytes: 1, maxConcurrent: 1, ratePerSecond: 1 } },
  ];
  for (const topology of cases) invalid({ ...structuredClone(SYNTHETIC), topology });
});

test('route表: API/MCPの既存routeだけ。未知path・method・不正target・encode/dot segmentは拒否', () => {
  const allowed = [
    ['api', 'POST', '/v2/commands'],
    ['api', 'OPTIONS', '/v2/commands'],
    ['api', 'GET', '/v2/commands/0b0c2f9e-1d2a-4c3b-9a8f-7e6d5c4b3a21'],
    ['api', 'POST', '/v2/commands/0b0c2f9e-1d2a-4c3b-9a8f-7e6d5c4b3a21/cancel'],
    ['api', 'GET', '/v2/encryption-key?x=1'],
    ['api', 'POST', '/v2/encryption-key/reissue'],
    ['api', 'POST', '/v2/encrypted-commands'],
    ['connect', 'POST', '/mcp'],
    ['connect', 'GET', '/.well-known/oauth-protected-resource/mcp'],
    ['connect', 'GET', '/.well-known/oauth-authorization-server'],
    ['connect', 'GET', '/oauth/authorize?response_type=code'],
    ['connect', 'GET', '/oauth/authorize/abc_DEF-123'],
    ['connect', 'POST', '/oauth/token'],
    ['connect', 'GET', '/interaction/abc123'],
    ['connect', 'POST', '/interaction/abc123/consent'],
    ['connect', 'POST', '/v1/source/approvals/abc123'],
    ['connect', 'GET', '/v1/web/connection'],
    ['connect', 'POST', '/v1/web/disconnect'],
  ];
  for (const [role, method, target] of allowed) assert.equal(matchGatewayRoute(role, method, target), 'allowed', `${role} ${method} ${target}`);
  const refused = [
    ['api', 'GET', '/', 'not_found'],
    ['api', 'POST', '/mcp', 'not_found'],
    ['api', 'GET', '/v2/commands', 'method_not_allowed'],
    ['api', 'PUT', '/v2/encrypted-commands', 'method_not_allowed'],
    ['api', 'POST', '/v2/commands/', 'not_found'],
    ['api', 'POST', '/v2/commands/../encryption-key', 'not_found'],
    ['api', 'POST', '/v2/commands%2F..%2Fx', 'not_found'],
    ['api', 'GET', '/v2/encryption-key/', 'not_found'],
    ['api', 'GET', '/health', 'not_found'],
    ['api', 'GET', '//evil.example/v2/commands', 'invalid_target'],
    ['api', 'GET', 'https://evil.example/v2/commands', 'invalid_target'],
    ['api', 'GET', '*', 'invalid_target'],
    ['api', 'GET', '/v2/commands#x', 'invalid_target'],
    ['api', 'GET', '/v2/commands x', 'invalid_target'],
    ['connect', 'POST', '/v2/commands', 'not_found'],
    ['connect', 'GET', '/admin', 'not_found'],
    ['connect', 'GET', '/oauth/unknown', 'not_found'],
    ['connect', 'GET', '/.well-known/other', 'not_found'],
    ['connect', 'PUT', '/mcp', 'method_not_allowed'],
    ['connect', 'GET', '/interaction/a/b/c', 'not_found'],
    ['connect', 'GET', '/v1/source/approvals/a/b', 'not_found'],
  ];
  for (const [role, method, target, expected] of refused) assert.equal(matchGatewayRoute(role, method, target), expected, `${role} ${method} ${target}`);
});

function message(rawHeaders) {
  const headers = {};
  for (let index = 0; index < rawHeaders.length; index += 2) headers[rawHeaders[index].toLowerCase()] = rawHeaders[index + 1];
  return { rawHeaders: [...rawHeaders], headers };
}

test('backend adapter: transport authority・Host1件・残時間1件だけ受け、公開authorityへ結んで内部headerを除く', () => {
  const authorities = { transportAuthority: new URL(BACKEND.connect).host, logicalAuthority: 'connect.example.com' };
  const ok = message(['Host', authorities.transportAuthority, 'Authorization', 'Bearer user', 'X-Serverless-Authorization', 'Bearer iam', 'X-STTD-Gateway-Budget-Ms', '19000', 'Cookie', 'a=1']);
  assert.equal(admitBackendRequest(ok, authorities), 19_000);
  assert.deepEqual(ok.rawHeaders, ['Host', 'connect.example.com', 'Authorization', 'Bearer user', 'Cookie', 'a=1']);
  assert.equal(ok.headers.host, 'connect.example.com');
  assert.equal(ok.headers['x-serverless-authorization'], undefined);
  assert.equal(ok.headers['x-sttd-gateway-budget-ms'], undefined);
  const refused = [
    ['Host', 'connect.example.com', 'X-STTD-Gateway-Budget-Ms', '100'],
    ['Host', authorities.transportAuthority, 'Host', authorities.transportAuthority, 'X-STTD-Gateway-Budget-Ms', '100'],
    ['Host', authorities.transportAuthority],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Budget-Ms', '0'],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Budget-Ms', '20001'],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Budget-Ms', '0100'],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Budget-Ms', '100', 'x-sttd-gateway-budget-ms', '100'],
  ];
  for (const raw of refused) {
    const req = message(raw);
    assert.equal(admitBackendRequest(req, authorities), null, raw.join(' '));
    assert.deepEqual(req.rawHeaders, raw, 'refused requests are not rewritten');
  }
});
