// gateway-v1配置の設定・route・backend adapterの合成回帰（pure。network・SDK・資格 0）。
//   - 配置設定: topology省略/'direct'は従来どおり（結果にkey自体が無い）。gateway-v1は全fieldの明示だけで、欠落・未知key・同名/同主体/
//     同origin・http・範囲外の上限は固定の設定error（directへ降格しない）。
//   - route表: 既存の公開routeだけを許可し、未知path・method・不正なrequest-target・encodeやdot segmentでの迂回を拒否する。
//   - backend adapter: transport authorityの一致・Host1件・絶対期限1件（未来）だけを受け、期限はmin(gateway期限, 受付+20秒)。
//     Hostを公開authorityへ結び内部headerを除く。

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DeploymentConfigError, validateDeploymentConfig } from '../dist/config/validate.js';
import { matchGatewayRoute } from '../dist/gateway/contract.js';
import { REISSUE_BODY_MAX_BYTES } from '../dist/encryption/api.js';
import { ENCRYPTED_WIRE_MAX_BYTES } from '../dist/encryption/commands.js';
import { MAX_BODY_BYTES, MAX_COMMAND_BODY_BYTES, MAX_MCP_BODY_BYTES } from '../dist/policy.js';
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

const CMD = '0b0c2f9e-1d2a-4c3b-9a8f-7e6d5c4b3a21';

test('route表: 元handler・pinned Providerのpath/methodだけ。未知path・兄弟action・method・不正target・encode/dot segmentは拒否', () => {
  const allowed = [
    ['api', 'POST', '/v2/commands', MAX_COMMAND_BODY_BYTES],
    ['api', 'OPTIONS', '/v2/commands', 0],
    ['api', 'GET', `/v2/commands/${CMD}`, 0],
    ['api', 'POST', `/v2/commands/${CMD}/cancel`, MAX_COMMAND_BODY_BYTES],
    ['api', 'GET', '/v2/encryption-key?x=1', 0],
    ['api', 'POST', '/v2/encryption-key/reissue', REISSUE_BODY_MAX_BYTES],
    ['api', 'POST', '/v2/encrypted-commands', ENCRYPTED_WIRE_MAX_BYTES],
    ['connect', 'GET', '/interaction/app.js', 0],
    ['connect', 'POST', '/mcp', MAX_MCP_BODY_BYTES],
    ['connect', 'GET', '/.well-known/oauth-protected-resource/mcp', 0],
    ['connect', 'GET', '/.well-known/oauth-authorization-server', 0],
    ['connect', 'GET', '/.well-known/openid-configuration', 0],
    ['connect', 'GET', '/oauth/authorize?response_type=code', 0],
    ['connect', 'GET', '/oauth/authorize/abc_DEF-123', 0],
    ['connect', 'POST', '/oauth/token', 56 * 1024],
    ['connect', 'POST', '/oauth/revoke', 56 * 1024],
    ['connect', 'GET', '/oauth/jwks', 0],
    ['connect', 'POST', '/oauth/session/end/confirm', 56 * 1024],
    ['connect', 'GET', '/interaction/abc123', 0],
    ['connect', 'POST', '/interaction/abc123/login', MAX_BODY_BYTES],
    ['connect', 'POST', '/interaction/abc123/consent', MAX_BODY_BYTES],
    ['connect', 'POST', '/interaction/abc123/deny', MAX_BODY_BYTES],
    ['connect', 'POST', '/interaction/abc123/code', MAX_BODY_BYTES],
    ['connect', 'GET', '/v1/source/approvals/abc123', 0],
    ['connect', 'POST', '/v1/source/approvals/abc123', 64],
    ['connect', 'GET', '/v1/web/connection', 0],
    ['connect', 'POST', '/v1/web/disconnect', 0],
  ];
  for (const [role, method, target, max] of allowed) assert.deepEqual(matchGatewayRoute(role, method, target), { kind: 'allowed', maxBodyBytes: max }, `${role} ${method} ${target}`);
  // 配置上限はroute上限を下げるだけ（拡大しない）。
  assert.deepEqual(matchGatewayRoute('api', 'POST', '/v2/commands', 100), { kind: 'allowed', maxBodyBytes: 100 });
  assert.deepEqual(matchGatewayRoute('connect', 'POST', '/v1/source/approvals/a', 1_048_576), { kind: 'allowed', maxBodyBytes: 64 });
  const refused = [
    ['api', 'GET', '/', 'not_found'],
    ['api', 'POST', '/mcp', 'not_found'],
    ['api', 'GET', '/v2/commands', 'method_not_allowed'],
    ['api', 'POST', `/v2/commands/${CMD}`, 'method_not_allowed'],
    ['api', 'DELETE', `/v2/commands/${CMD}`, 'method_not_allowed'],
    ['api', 'GET', `/v2/commands/${CMD}/cancel`, 'method_not_allowed'],
    ['api', 'GET', '/v2/commands/not-a-uuid', 'not_found'],
    ['api', 'OPTIONS', '/v2/encryption-key', 'method_not_allowed'],
    ['api', 'PUT', '/v2/encrypted-commands', 'method_not_allowed'],
    ['connect', 'POST', '/oauth/authorize', 'method_not_allowed'],
    ['connect', 'GET', '/oauth/userinfo', 'not_found'],
    ['connect', 'POST', '/oauth/reg', 'not_found'],
    ['connect', 'POST', '/oauth/token/introspection', 'not_found'],
    ['connect', 'POST', '/oauth/request', 'not_found'],
    ['connect', 'POST', '/oauth/device/auth', 'not_found'],
    ['connect', 'GET', '/oauth/session/end', 'not_found'],
    ['connect', 'GET', '/oauth/session/end/success', 'not_found'],
    ['connect', 'GET', '/interaction/app.css', 'not_found'],
    ['connect', 'GET', '/interaction/abc123/abort', 'not_found'],
    ['connect', 'POST', '/interaction/abc123/submit', 'not_found'],
    ['connect', 'GET', '/interaction/abc123/login', 'method_not_allowed'],
    ['connect', 'POST', '/interaction/abc123', 'method_not_allowed'],
    ['connect', 'GET', '/assets/app.js', 'not_found'],
    ['connect', 'GET', '/static/app.js', 'not_found'],
    ['connect', 'GET', '/.well-known/oauth-protected-resource', 'not_found'],
    ['connect', 'GET', '/v1/web/disconnect', 'method_not_allowed'],
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
  for (const [role, method, target, expected] of refused) assert.equal(matchGatewayRoute(role, method, target).kind, expected, `${role} ${method} ${target}`);
});

function message(rawHeaders) {
  const headers = {};
  for (let index = 0; index < rawHeaders.length; index += 2) headers[rawHeaders[index].toLowerCase()] = rawHeaders[index + 1];
  return { rawHeaders: [...rawHeaders], headers };
}

test('backend adapter: transport authority・Host1件・絶対期限1件だけ受け、中継遅延で期限を延長せず内部headerを除く', () => {
  const NOW = 1_900_000_000_000;
  const authorities = { transportAuthority: new URL(BACKEND.connect).host, logicalAuthority: 'connect.example.com' };
  const ok = message(['Host', authorities.transportAuthority, 'Authorization', 'Bearer user', 'X-Serverless-Authorization', 'Bearer iam', 'X-STTD-Gateway-Deadline', String(NOW + 19_000), 'Cookie', 'a=1']);
  // gatewayの絶対期限をそのまま使う（backend受付が遅れても延びない）。
  assert.equal(admitBackendRequest(ok, authorities, NOW), NOW + 19_000);
  // 期限がbackend受付+20秒より先なら+20秒へ短縮する（外部値で延長しない）。
  assert.equal(admitBackendRequest(message(['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', String(NOW + 60_000)]), authorities, NOW), NOW + 20_000);
  assert.deepEqual(ok.rawHeaders, ['Host', 'connect.example.com', 'Authorization', 'Bearer user', 'Cookie', 'a=1']);
  assert.equal(ok.headers.host, 'connect.example.com');
  assert.equal(ok.headers['x-serverless-authorization'], undefined);
  assert.equal(ok.headers['x-sttd-gateway-deadline'], undefined);
  const refused = [
    ['Host', 'connect.example.com', 'X-STTD-Gateway-Deadline', String(NOW + 100)],
    ['Host', authorities.transportAuthority, 'Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', String(NOW + 100)],
    ['Host', authorities.transportAuthority],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', String(NOW)],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', String(NOW - 1)],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', `0${NOW + 100}`],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', '19000'],
    ['Host', authorities.transportAuthority, 'X-STTD-Gateway-Deadline', String(NOW + 100), 'x-sttd-gateway-deadline', String(NOW + 100)],
  ];
  for (const raw of refused) {
    const req = message(raw);
    assert.equal(admitBackendRequest(req, authorities, NOW), null, raw.join(' '));
    assert.deepEqual(req.rawHeaders, raw, 'refused requests are not rewritten');
  }
});
