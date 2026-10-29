// gateway-v1の役割別起動口・組立て・包装の合成回帰。
//   - 組立て（createGatewayRuntime）: topologyなし・K_SERVICE不一致・資格/metadata/proxyの差替え名は、IAM取得・転送の前に固定error。
//     IAM取得の失敗は固定503でfallback 0。metadata identity取得（合成transport）の固定GET1回・検査・上限・中止・close・共有。
//   - 期限: 受付の絶対期限を共有し中継遅延で延長しない。route別本文上限（Content-Length・stream・rawBody）は転送前。
//   - 実entry（build済みdistの.jsを所有一時directoryへ写し、配置設定だけ合成のgateway-v1にしたcopy）: MCP gatewayの待受と転送前拒否、
//     API gatewayのexport名・実行主体と転送前拒否・環境不一致の503、backend 2つの設定不正/環境不一致での起動拒否（listen 0）、
//     gateway-v1配置でのdirect entry（API・MCP）の拒否。外部への接続・fetchは拒否して数え、0であることを確かめる。
//   - 包装: 既存2成果物（direct）は不変、gateway-v1の4成果物はrole別main/Dockerfile、入口2つの閉包に業務SDK・bootstrapが無い。
// 実Cloud・IAM・資格・SDK通信・外部network 0。env・listen・connect・fetchの差替えはfinallyで必ず戻す。

import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { validateDeploymentConfig } from '../dist/config/validate.js';
import { createIdTokenSource, METADATA_IDENTITY_HOST, METADATA_IDENTITY_PATH, metadataIdTokenFetcher } from '../dist/gateway/google-iam.js';
import { createGatewayRuntime, GatewayRuntimeError } from '../dist/gateway/runtime.js';
import { RUNTIME_REFUSED_ENV } from '../dist/policy.js';
import { ARTIFACTS, buildArtifacts, buildGatewayArtifacts, GATEWAY_FORBIDDEN_PACKAGES, parseTarGz, parseZip, readServerInputs } from '../scripts/package-artifacts.mjs';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { closeAll, countListener, iamFetcher, isolatedDist, listen, listenerCount, request, syntheticIdToken, topologyConfig } from './fixtures/gateway-runtime.mjs';

const GATEWAY_CONFIG = topologyConfig();
/** 既存SDK gateと同じidentity条件を満たす合成のCloud実行環境（role別）。 */
const GATEWAY_ENV = Object.freeze({
  api: { K_SERVICE: GATEWAY_CONFIG.api.serviceName, K_REVISION: 'sendtexttodotsapi-00001-abc', K_CONFIGURATION: 'sendtexttodotsapi' },
  connect: { K_SERVICE: GATEWAY_CONFIG.connect.serviceName, K_REVISION: 'sendtexttodots-connect-00001-abc', K_CONFIGURATION: 'sendtexttodots-connect' },
});
const copy = isolatedDist(GATEWAY_CONFIG);

after(async () => {
  copy.cleanup();
  await closeAll();
  assert.ok(listenerCount() <= 20);
});

/** 外部への接続・fetchを拒否して数え、listenを127.0.0.1/ephemeralへ寄せる（finallyで必ず戻す）。 */
async function guarded(env, fn) {
  const saved = new Map();
  // 試験hostの資格/proxy/TLS系の環境変数はgateの対象なので、この呼出しの間だけ外す（finallyで戻す）。
  env = { K_REVISION: 'synthetic-00001-abc', K_CONFIGURATION: 'synthetic', GOOGLE_CLOUD_PROJECT: undefined, GCLOUD_PROJECT: undefined, ...env };
  for (const name of Object.keys(process.env)) {
    if (!RUNTIME_REFUSED_ENV.has(name.toUpperCase()) || name in env) continue;
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
  for (const [name, value] of Object.entries(env)) {
    saved.set(name, process.env[name]);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  const originals = { connect: net.Socket.prototype.connect, listen: net.Server.prototype.listen, fetch: globalThis.fetch };
  const counts = { external: 0, listened: [] };
  net.Socket.prototype.connect = function guardedConnect(...args) {
    // net.connectは正規化した[options, callback]の配列を渡す。
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const options = typeof first === 'object' && first !== null ? first : { port: first, host: args[1] };
    if (options.host !== '127.0.0.1' && options.path === undefined) {
      counts.external += 1;
      throw new Error('gateway-runtime: external connection refused');
    }
    return originals.connect.apply(this, args);
  };
  globalThis.fetch = async () => {
    counts.external += 1;
    throw new Error('gateway-runtime: fetch refused');
  };
  net.Server.prototype.listen = function guardedListen(...args) {
    countListener();
    counts.listened.push(this);
    const callback = args.find((item) => typeof item === 'function');
    return originals.listen.call(this, 0, '127.0.0.1', callback);
  };
  try {
    return await fn(counts);
  } finally {
    net.Socket.prototype.connect = originals.connect;
    net.Server.prototype.listen = originals.listen;
    globalThis.fetch = originals.fetch;
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test('組立て: topologyなし・K_SERVICE不一致・差替え名はIAM取得の前に固定error、IAM失敗は503でfallback 0', async () => {
  const config = validateDeploymentConfig(GATEWAY_CONFIG);
  const iam = iamFetcher();
  const make = (overrides) => createGatewayRuntime({ role: 'connect', config, env: GATEWAY_ENV.connect, clock: { now: () => Date.now() }, fetcher: iam.fetcher, ...overrides });
  const rejected = (fn, code) => assert.throws(fn, (error) => error instanceof GatewayRuntimeError && error.code === code);
  rejected(() => make({ config: validateDeploymentConfig(structuredClone(SYNTHETIC)) }), 'gateway_config_invalid');
  rejected(() => make({ env: { ...GATEWAY_ENV.connect, K_SERVICE: config.topology.connect.backendServiceName } }), 'gateway_environment_rejected');
  rejected(() => make({ env: { ...GATEWAY_ENV.connect, K_REVISION: undefined } }), 'gateway_environment_rejected');
  rejected(() => make({ env: { ...GATEWAY_ENV.connect, K_CONFIGURATION: 'Bad_Name' } }), 'gateway_environment_rejected');
  rejected(() => make({ env: { ...GATEWAY_ENV.connect, GOOGLE_CLOUD_PROJECT: 'other-project' } }), 'gateway_environment_rejected');
  // NODE_OPTIONSはMCPでは拒否、APIだけ既存と同じbounded memory hintを許す（他flag・大小文字違いは拒否）。
  rejected(() => make({ env: { ...GATEWAY_ENV.connect, NODE_OPTIONS: '--max-old-space-size=512' } }), 'gateway_environment_rejected');
  make({ role: 'api', env: { ...GATEWAY_ENV.api, NODE_OPTIONS: '--max-old-space-size=512' } }).close();
  rejected(() => make({ role: 'api', env: { ...GATEWAY_ENV.api, NODE_OPTIONS: '--require=/tmp/x.js' } }), 'gateway_environment_rejected');
  rejected(() => make({ role: 'api', env: { ...GATEWAY_ENV.api, node_options: '--max-old-space-size=512' } }), 'gateway_environment_rejected');
  rejected(() => make({ role: 'api' }), 'gateway_environment_rejected');
  for (const name of ['GOOGLE_APPLICATION_CREDENTIALS', 'gce_metadata_host', 'https_proxy', 'NODE_EXTRA_CA_CERTS', 'METADATA_SERVER_DETECTION', 'GRPC_TRACE', 'NODE_DEBUG', 'GOOGLE_API_KEY', 'FIRESTORE_EMULATOR_HOST']) {
    rejected(() => make({ env: { ...GATEWAY_ENV.connect, [name]: 'x' } }), 'gateway_environment_rejected');
  }
  assert.equal(iam.calls.count, 0);
  const failing = iamFetcher(async () => {
    throw new Error('metadata unavailable');
  });
  const handler = make({ fetcher: failing.fetcher, connectTo: { host: '127.0.0.1', port: 9 } });
  const { port } = await listen((req, res) => void handler.handle(req, res));
  const res = await request(port, { path: '/mcp', headers: { Host: new URL(config.connect.publicOrigin).host } });
  assert.equal(res.status, 503);
  assert.deepEqual(JSON.parse(res.body), { error: { code: 'temporarily_unavailable', retryable: true } });
  assert.equal(failing.calls.count, 1);
});

test('metadata ID token: 公式identity endpointへ固定GET1回、検査・上限・中止・close・共有・再送0（合成transport）', async () => {
  const AUD = GATEWAY_CONFIG.topology.connect.backendOrigin;
  const seen = [];
  let mode = 'ok';
  const { port } = await listen((req, res) => {
    seen.push({ url: req.url, flavor: req.headers['metadata-flavor'], host: req.headers.host });
    if (mode === 'hang') return;
    if (mode === 'status') return void res.writeHead(500, { 'Metadata-Flavor': 'Google' }).end('x');
    if (mode === 'flavor') return void res.writeHead(200).end(syntheticIdToken(AUD, Math.floor(Date.now() / 1000) + 3600));
    if (mode === 'big') return void res.writeHead(200, { 'Metadata-Flavor': 'Google' }).end('a'.repeat(9000));
    if (mode === 'late') return void setTimeout(() => res.writeHead(200, { 'Metadata-Flavor': 'Google' }).end(syntheticIdToken(AUD, Math.floor(Date.now() / 1000) + 3600)), 150);
    res.writeHead(200, { 'Metadata-Flavor': 'Google', 'Content-Type': 'text/html' });
    res.end(syntheticIdToken(AUD, Math.floor(Date.now() / 1000) + 3600));
  });
  const requested = [];
  const transport = (options, onResponse) => {
    requested.push({ host: options.host, port: options.port, path: options.path, headers: options.headers, agent: options.agent });
    return http.request({ ...options, host: '127.0.0.1', port }, onResponse);
  };
  const fetcher = metadataIdTokenFetcher(transport);
  const clock = { now: () => Date.now() };
  const live = () => new AbortController().signal;
  const source = createIdTokenSource({ audience: AUD, fetcher, clock });
  // 複数の呼出しは1回の取得を共有し、2回目以降はRAMのtoken。
  const [a, b] = await Promise.all([source.get(Date.now() + 5000, live()), source.get(Date.now() + 5000, live())]);
  assert.equal(a, b);
  assert.equal(await source.get(Date.now() + 5000, live()), a);
  assert.equal(seen.length, 1);
  assert.deepEqual(requested[0], { host: METADATA_IDENTITY_HOST, port: 80, path: `${METADATA_IDENTITY_PATH}?audience=${encodeURIComponent(AUD)}`, headers: { 'Metadata-Flavor': 'Google' }, agent: false });
  assert.equal(seen[0].flavor, 'Google');
  // status・Metadata-Flavor・本文上限の不一致はunavailable、再送0。
  for (const bad of ['status', 'flavor', 'big']) {
    mode = bad;
    const fresh = createIdTokenSource({ audience: AUD, fetcher, clock });
    const before = seen.length;
    await assert.rejects(fresh.get(Date.now() + 5000, live()), (error) => error.code === 'unavailable');
    assert.equal(seen.length, before + 1, `${bad}: one request, no retry`);
  }
  // 取得上限: 応答しないmetadataは上限で中止し、socketを閉じる。
  mode = 'hang';
  const limited = createIdTokenSource({ audience: AUD, fetcher, clock, fetchLimitMs: 60 });
  await assert.rejects(limited.get(Date.now() + 5000, live()), (error) => error.code === 'unavailable');
  assert.equal(limited.stats.inflight, false);
  // 呼出し側の期限・中止は共有の取得を延長しない。
  const short = createIdTokenSource({ audience: AUD, fetcher, clock, fetchLimitMs: 5000 });
  await assert.rejects(short.get(Date.now() + 40, live()), (error) => error.code === 'timed_out');
  const controller = new AbortController();
  const pending = short.get(Date.now() + 5000, controller.signal);
  controller.abort();
  await assert.rejects(pending, (error) => error.code === 'aborted');
  short.close();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(short.stats.inflight, false);
  // closeの後に届いたtokenは採用しない。
  mode = 'late';
  const closing = createIdTokenSource({ audience: AUD, fetcher, clock });
  const late = closing.get(Date.now() + 5000, live());
  closing.close();
  await assert.rejects(late, (error) => error.code === 'aborted' || error.code === 'unavailable');
  await new Promise((resolve) => setTimeout(resolve, 200));
  await assert.rejects(closing.get(Date.now() + 5000, live()), (error) => error.code === 'aborted');
});

test('期限: gateway受付の絶対期限を共有し、中継の遅延で延長しない。期限後のtoken成功・切断後のIAM成功では転送0', async () => {
  const config = validateDeploymentConfig(GATEWAY_CONFIG);
  let now = 1_900_000_000_000;
  const clock = { now: () => now };
  let release;
  const iam = iamFetcher(() => new Promise((resolve) => (release = () => resolve(syntheticIdToken(config.topology.api.backendOrigin, Math.floor(now / 1000) + 3600)))));
  const forwarded = [];
  const handler = createGatewayRuntime({
    role: 'api',
    config,
    env: GATEWAY_ENV.api,
    clock,
    fetcher: iam.fetcher,
    transport: (options) => {
      forwarded.push(options.headers);
      throw new Error('synthetic transport: not connected');
    },
  });
  const { port } = await listen((req, res) => void handler.handle(req, res));
  // IAM待機の間に時計が進んでも、転送する期限は受付+20秒のまま。
  const first = request(port, { path: '/v2/encryption-key' });
  while (iam.calls.count === 0) await new Promise((resolve) => setTimeout(resolve, 5));
  const receivedAt = now;
  now += 7_000;
  release();
  await first;
  assert.equal(forwarded.length, 1);
  const headers = forwarded[0];
  assert.equal(headers[headers.findIndex((value) => String(value).toLowerCase() === 'x-sttd-gateway-deadline') + 1], String(receivedAt + 20_000));
  // tokenが期限の後に届いた要求は転送しない（cacheを捨てて新しい取得にする）。
  handler.close();
  release = undefined;
  const second = createGatewayRuntime({ role: 'api', config, env: GATEWAY_ENV.api, clock, fetcher: iamFetcher(() => new Promise((resolve) => (release = () => resolve(syntheticIdToken(config.topology.api.backendOrigin, Math.floor(now / 1000) + 3600))))).fetcher, transport: (options) => (forwarded.push(options.headers), assert.fail('no forward after deadline')) });
  const { port: port2 } = await listen((req, res) => void second.handle(req, res));
  const expired = request(port2, { path: '/v2/encryption-key' });
  while (release === undefined) await new Promise((resolve) => setTimeout(resolve, 5));
  await new Promise((resolve) => setTimeout(resolve, 20));
  now += 25_000;
  release();
  assert.equal((await expired).status, 503);
  assert.equal(forwarded.length, 1);
  second.close();
});

test('route別上限: 元handlerの上限をContent-Length・stream・Functions rawBodyの全てで転送前に適用（IAM・backend 0）', async () => {
  const config = validateDeploymentConfig(GATEWAY_CONFIG);
  const iam = iamFetcher();
  const forwarded = [];
  const handler = createGatewayRuntime({ role: 'connect', config, env: GATEWAY_ENV.connect, clock: { now: () => Date.now() }, fetcher: iam.fetcher, transport: (options) => (forwarded.push(options), assert.fail('no forward')) });
  const host = new URL(config.connect.publicOrigin).host;
  const { port } = await listen((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = req.headers['x-test-raw'] === '1';
      // Functionsの写し: frameworkが読んだrawBodyだけを渡す（Content-Lengthなし）。
      if (raw) {
        delete req.headers['content-length'];
        for (let index = req.rawHeaders.length - 2; index >= 0; index -= 2) if (req.rawHeaders[index].toLowerCase() === 'content-length') req.rawHeaders.splice(index, 2);
      }
      void handler.handle(req, res, raw ? Buffer.concat(chunks) : undefined);
    });
  });
  const over = [
    { method: 'POST', path: '/v1/source/approvals/abc', body: 'x'.repeat(65) },
    { method: 'GET', path: '/interaction/app.js', body: 'x' },
    { method: 'POST', path: '/v1/web/disconnect', body: 'x' },
    { method: 'POST', path: '/interaction/abc/login', body: 'x'.repeat(4097) },
  ];
  for (const item of over) {
    assert.equal((await request(port, { ...item, headers: { Host: host } })).status, 413, `${item.method} ${item.path}`);
    assert.equal((await request(port, { ...item, headers: { Host: host, 'X-Test-Raw': '1' } })).status, 413, `rawBody ${item.method} ${item.path}`);
  }
  assert.equal(iam.calls.count, 0);
  assert.equal(forwarded.length, 0);
  handler.close();
});

test('MCP gateway entry: 実runで待受し、未知route・Host偽装は転送前に拒否。K_SERVICE不一致は起動拒否（listen 0）', async () => {
  await guarded({ PORT: '18081', K_SERVICE: GATEWAY_CONFIG.connect.serviceName }, async (counts) => {
    const { runGatewayConnect } = await import(copy.url('deployment/gateway-connect.js'));
    const handle = await runGatewayConnect();
    assert.equal(await runGatewayConnect(), handle, 'second run shares the same start');
    const port = counts.listened[0].address().port;
    assert.equal((await request(port, { path: '/admin', headers: { Host: new URL(GATEWAY_CONFIG.connect.publicOrigin).host } })).status, 404);
    assert.equal((await request(port, { path: '/mcp', headers: { Host: 'evil.example' } })).status, 400);
    await handle.close();
    assert.equal(counts.external, 0);
  });
  await guarded({ PORT: '18081', K_SERVICE: 'other-service' }, async (counts) => {
    const { runGatewayConnect } = await import(copy.url('deployment/gateway-connect.js', '?env'));
    await assert.rejects(runGatewayConnect(), (error) => error.code === 'gateway_connect_config_invalid');
    assert.equal(counts.listened.length, 0);
    assert.equal(counts.external, 0);
  });
});

/** Functionsの要求を模した最小の写し（rawBody・header()）で、実exportを呼ぶ所有listener。 */
async function functionsHost(fn) {
  return listen((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      req.rawBody = Buffer.concat(chunks);
      req.header = req.get = (name) => req.headers[String(name).toLowerCase()];
      void Promise.resolve(fn(req, res)).catch(() => res.destroy());
    });
  });
}

test('API gateway entry: 既存export名・gateway主体、転送前の拒否、環境不一致は固定503（token取得・転送0）', async () => {
  await guarded({ K_SERVICE: 'sendtexttodotsapi' }, async (counts) => {
    const module = await import(copy.url('deployment/gateway-api.js'));
    assert.deepEqual(Object.keys(module), ['sendtexttodotsapi']);
    const endpoint = JSON.stringify(module.sendtexttodotsapi.__endpoint ?? {});
    assert.ok(endpoint.includes(GATEWAY_CONFIG.topology.api.gatewayServiceAccount), 'gateway runs as its own principal');
    assert.ok(!endpoint.includes(GATEWAY_CONFIG.api.serviceAccount), 'business principal is not used by the gateway');
    const { port } = await functionsHost(module.sendtexttodotsapi);
    assert.equal((await request(port, { path: '/health' })).status, 404);
    assert.equal((await request(port, { method: 'PUT', path: '/v2/commands' })).status, 405);
    assert.equal(counts.external, 0);
  });
  await guarded({ K_SERVICE: 'other-service' }, async (counts) => {
    const module = await import(copy.url('deployment/gateway-api.js', '?env'));
    const { port } = await functionsHost(module.sendtexttodotsapi);
    assert.equal((await request(port, { path: '/v2/encryption-key' })).status, 503);
    assert.equal(counts.external, 0);
  });
});

test('backend entry: topologyなし・API key欠落・K_SERVICE不一致は起動拒否（listen・外部接続0）', async () => {
  await guarded({ PORT: '18082', K_SERVICE: 'sendtexttodots-api-backend' }, async (counts) => {
    const direct = await import('../dist/deployment/backend-api.js');
    await assert.rejects(direct.runBackendApi(), (error) => error.code === 'backend_api_config_invalid');
    const directConnect = await import('../dist/deployment/backend-connect.js');
    await assert.rejects(directConnect.runBackendConnect(), (error) => error.code === 'backend_connect_config_invalid');
    assert.equal(counts.listened.length, 0);
    assert.equal(counts.external, 0);
  });
  await guarded({ PORT: '18082', K_SERVICE: 'sendtexttodotsapi' }, async (counts) => {
    const { runBackendApi } = await import(copy.url('deployment/backend-api.js'));
    await assert.rejects(runBackendApi(), (error) => ['backend_api_config_invalid', 'backend_api_startup_failed'].includes(error.code));
    assert.equal(counts.listened.length, 0);
    assert.equal(counts.external, 0);
  });
  await guarded({ PORT: '18083', K_SERVICE: 'sendtexttodots-connect-backend', [GATEWAY_CONFIG.web.apiKeyEnv]: undefined }, async (counts) => {
    const { runBackendConnect } = await import(copy.url('deployment/backend-connect.js'));
    await assert.rejects(runBackendConnect(), (error) => error.code === 'backend_connect_config_invalid');
    assert.equal(counts.listened.length, 0);
  });
  await guarded({ PORT: '18083', K_SERVICE: GATEWAY_CONFIG.connect.serviceName, [GATEWAY_CONFIG.web.apiKeyEnv]: 'synthetic-web-key' }, async (counts) => {
    const { runBackendConnect } = await import(copy.url('deployment/backend-connect.js', '?env'));
    await assert.rejects(runBackendConnect(), (error) => ['backend_connect_config_invalid', 'backend_connect_startup_failed'].includes(error.code));
    assert.equal(counts.listened.length, 0);
    assert.equal(counts.external, 0);
  });
});

test('gateway-v1配置ではdirect entry（API・MCP）が業務SDKの前に拒否し、directへ戻らない', async () => {
  await guarded({ PORT: '18084', K_SERVICE: GATEWAY_CONFIG.connect.serviceName, [GATEWAY_CONFIG.web.apiKeyEnv]: 'synthetic-web-key' }, async (counts) => {
    const { runDevelopmentConnect } = await import(copy.url('deployment/connect.js'));
    await assert.rejects(runDevelopmentConnect(), (error) => error.code === 'development_connect_config_invalid');
    assert.equal(counts.listened.length, 0);
    assert.equal(counts.external, 0);
  });
  await guarded({ K_SERVICE: 'sendtexttodotsapi' }, async (counts) => {
    const { sendtexttodotsapi } = await import(copy.url('deployment/functions.js'));
    const { port } = await functionsHost(sendtexttodotsapi);
    assert.equal((await request(port, { method: 'POST', path: '/v2/commands', headers: { Authorization: 'Bearer x', 'Content-Type': 'application/json' }, body: '{}' })).status, 503);
    assert.equal(counts.external, 0);
  });
});

test('包装: 既存2成果物は不変、gateway-v1の4成果物はrole別main、入口2つの閉包に業務SDK・bootstrapが無い', () => {
  const inputs = readServerInputs(process.cwd());
  const direct = buildArtifacts(inputs);
  assert.equal(direct.receipt.api.main, ARTIFACTS.api.main);
  assert.equal(direct.receipt.mcp.main, ARTIFACTS.mcp.main);
  assert.ok(direct.receipt.api.files.every((file) => !file.name.startsWith('dist/deployment/gateway-') && !file.name.startsWith('dist/deployment/backend-')));
  const gateway = buildGatewayArtifacts(inputs);
  const roles = Object.fromEntries(gateway.receipt.roles.map((item) => [item.role, item]));
  assert.deepEqual(Object.keys(roles), ['gateway-api', 'gateway-connect', 'backend-api', 'backend-connect']);
  assert.equal(roles['gateway-api'].format, 'zip32-store');
  for (const role of ['gateway-api', 'gateway-connect']) {
    assert.ok(roles[role].dependencies.every((item) => !GATEWAY_FORBIDDEN_PACKAGES.includes(item)), `${role}: ${roles[role].dependencies.join(',')}`);
    assert.ok(roles[role].files.every((file) => !file.name.startsWith('dist/google-runtime/') && !file.name.startsWith('dist/keys/') && file.name !== 'dist/connect/kms-server.js'));
  }
  assert.ok(roles['backend-api'].dependencies.includes('firebase-admin'));
  assert.ok(roles['backend-connect'].dependencies.includes('oidc-provider'));
  for (const archive of gateway.archives) {
    const role = gateway.receipt.roles.find((item) => item.name === archive.name);
    const entries = archive.name.endsWith('.zip') ? parseZip(archive.bytes) : parseTarGz(archive.bytes);
    assert.equal(JSON.parse(entries.find((entry) => entry.name === 'package.json').bytes.toString('utf8')).main, role.main);
    if (!archive.name.endsWith('.zip')) assert.ok(entries.find((entry) => entry.name === 'Dockerfile').bytes.toString('utf8').includes(`CMD ["node","${role.main}"]`));
  }
});
