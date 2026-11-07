// 送信APIのdirect Cloud Run entry（dist/deployment/api.js）の合成試験。実Cloud・資格・SDK通信・外部network 0。
//   - 設定: api.runtimeの省略互換・明示cloud-run-v1・未知値/名前共用/gateway-v1との不整合の拒否。
//   - entry: importだけでは副作用0、runtime/PORT/K_SERVICEの不成立はSDKより前の固定config error、
//     実owned bootstrap（公開SDK境界だけ合成）での起動・Host検査・既存handlerの401・並行要求・二重run・close・listen失敗の回収。
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { after, test } from 'node:test';

import { validateDeploymentConfig } from '../dist/config/validate.js';
import { RUNTIME_REFUSED_ENV } from '../dist/policy.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { closeAll, countListener, installGoogleSdkSubstitutes, isolatedDist, request, useCrc32c } from './fixtures/gateway-runtime.mjs';

const RUN_NAME = 'sendtexttodots-api-run';
const RUN_ORIGIN = 'https://sendtexttodots-api-run-123456789012.europe-west1.run.app';
const runConfig = (api = {}) => ({ ...structuredClone(SYNTHETIC), api: { ...structuredClone(SYNTHETIC.api), runtime: 'cloud-run-v1', serviceName: RUN_NAME, publicOrigin: RUN_ORIGIN, ...api } });
const CONFIG = runConfig();
const copy = isolatedDist(CONFIG);
const legacy = isolatedDist(structuredClone(SYNTHETIC));
// 設定拒否の試験は別copy（SDK factoryを代替の前に読み込ませない: 実bootstrapのcopyとmodule cacheを分ける）。
const probe = isolatedDist(CONFIG);
let sdk;
const sdkDocs = new Map();

after(async () => {
  sdk?.restore();
  copy.cleanup();
  legacy.cleanup();
  probe.cleanup();
  await closeAll();
});

/** 環境変数・待受・外部接続をこの呼出しの間だけ固定する（listenは127.0.0.1/ephemeralへ・外部接続は拒否して数える）。 */
async function guarded(env, fn, { listenFails = false } = {}) {
  const saved = new Map();
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
  const counts = { external: 0, listened: [], hosts: [] };
  net.Socket.prototype.connect = function guardedConnect(...args) {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const options = typeof first === 'object' && first !== null ? first : { port: first, host: args[1] };
    if (options.host !== '127.0.0.1' && options.path === undefined) {
      counts.external += 1;
      throw new Error('api-entry: external connection refused');
    }
    return originals.connect.apply(this, args);
  };
  globalThis.fetch = async () => {
    counts.external += 1;
    throw new Error('api-entry: fetch refused');
  };
  net.Server.prototype.listen = function guardedListen(...args) {
    counts.hosts.push([args[0], args[1]]);
    if (listenFails) {
      setImmediate(() => this.emit('error', Object.assign(new Error('EADDRINUSE'), { code: 'EADDRINUSE' })));
      return this;
    }
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

test('A1 api.runtime: omitted stays the existing Functions deployment; cloud-run-v1 needs its own safe service name; unknown / shared names / gateway-v1 are refused', () => {
  const plain = validateDeploymentConfig(structuredClone(SYNTHETIC));
  assert.equal(plain.api.runtime, undefined, 'omitted is unchanged');
  assert.equal(plain.api.serviceName, 'sendtexttodotsapi');
  assert.equal(validateDeploymentConfig({ ...structuredClone(SYNTHETIC), api: { ...SYNTHETIC.api, runtime: 'functions-v1' } }).api.runtime, 'functions-v1');
  const run = validateDeploymentConfig(CONFIG);
  assert.deepEqual([run.api.runtime, run.api.functionName, run.api.serviceName], ['cloud-run-v1', 'sendtexttodotsapi', RUN_NAME]);
  const refused = (config, why) => assert.throws(() => validateDeploymentConfig(config), (error) => error.name === 'DeploymentConfigError', why);
  refused({ ...structuredClone(SYNTHETIC), api: { ...SYNTHETIC.api, runtime: 'cloud-run-v2' } }, 'unknown runtime');
  refused({ ...structuredClone(SYNTHETIC), api: { ...SYNTHETIC.api, runtime: null } }, 'null runtime');
  refused({ ...structuredClone(SYNTHETIC), api: { ...SYNTHETIC.api, serviceName: RUN_NAME } }, 'functions deployment keeps the fixed name');
  refused(runConfig({ serviceName: 'sendtexttodotsapi' }), 'cloud run does not reuse the Functions name');
  refused(runConfig({ serviceName: SYNTHETIC.connect.serviceName }), 'not the connect service');
  refused(runConfig({ serviceName: 'Bad_Name' }), 'unsafe name');
  refused(runConfig({ functionName: RUN_NAME }), 'function name stays fixed');
  const gateway = { ...runConfig(), topology: { mode: 'gateway-v1', api: { backendServiceName: 'a-backend', backendOrigin: 'https://a-backend-123456789012.europe-west1.run.app', gatewayServiceAccount: 'api-gateway@sendtexttodots-test.iam.gserviceaccount.com' }, connect: { backendServiceName: 'c-backend', backendOrigin: 'https://c-backend-123456789012.europe-west1.run.app', gatewayServiceAccount: 'connect-gateway@sendtexttodots-test.iam.gserviceaccount.com' }, limits: { maxBodyBytes: 65_536, maxConcurrent: 8, ratePerSecond: 100, burst: 100 } } };
  refused(gateway, 'direct cloud run API and gateway-v1 are exclusive');
});

test('A2 importing the entry does nothing; missing runtime / bad PORT / wrong K_SERVICE fail before any SDK, listen or signal', async () => {
  const sigterm = process.listenerCount('SIGTERM');
  await guarded({ PORT: '8080', K_SERVICE: RUN_NAME }, async (counts) => {
    const legacyEntry = await import(legacy.url('deployment/api.js', '?legacy'));
    assert.equal(counts.listened.length, 0, 'import alone listens nothing');
    await assert.rejects(legacyEntry.runApi(), (error) => error.code === 'api_config_invalid', 'Functions config cannot start the Cloud Run entry');
  });
  for (const [env, why] of [[{ PORT: undefined, K_SERVICE: RUN_NAME }, 'no PORT'], [{ PORT: '0', K_SERVICE: RUN_NAME }, 'PORT 0'], [{ PORT: '70000', K_SERVICE: RUN_NAME }, 'PORT range'], [{ PORT: '08080', K_SERVICE: RUN_NAME }, 'PORT form'], [{ PORT: '8080', K_SERVICE: 'sendtexttodotsapi' }, 'K_SERVICE']]) {
    await guarded(env, async (counts) => {
      const entry = await import(probe.url('deployment/api.js', `?bad-${encodeURIComponent(why)}`));
      await assert.rejects(entry.runApi(), (error) => error.code === 'api_config_invalid', why);
      assert.deepEqual([counts.listened.length, counts.external], [0, 0], why);
    });
  }
  assert.equal(process.listenerCount('SIGTERM'), sigterm, 'no signal handler left behind');
});

async function realBootstrap() {
  const config = validateDeploymentConfig(CONFIG);
  const { kmsMarkerDocument, createKmsSubscriptionPolicy } = await import(copy.url('storage/firestore/kms-subscription-format.js'));
  const { crc32c } = await import(copy.url('protection/kms-sealing.js'));
  useCrc32c(crc32c);
  sdkDocs.set(`sttdAuth/${config.kms.namespace}/config/kms-subscription`, kmsMarkerDocument(createKmsSubscriptionPolicy({ ...config.kms, readVersions: [...config.kms.readVersions] })));
  // 実moduleを先に読み込み（実SDKへ束縛）→ 公開SDK境界だけを代替（test/gateway-runtime.test.mjsと同じ順）。
  for (const name of ['connect/firestore.js', 'connect/kms-port.js', 'connect/kms-server.js', 'connect/google-kms-server.js', 'delivery/kms-functions.js', 'delivery/kms-store.js', 'egress/product.js', 'keys/google-secret-reader.js', 'oauth/request-auth-runtime.js', 'protection/google-kms-transport.js', 'identity/firebase.js']) {
    await import(copy.url(name));
  }
  sdk ??= installGoogleSdkSubstitutes({ resolveFrom: copy.url('google-runtime/development.js'), secretVersions: config.secretVersions, docs: sdkDocs });
  return config;
}

test('A3 real owned bootstrap on synthetic SDK boundaries: 0.0.0.0:PORT, Host check, existing 401, concurrent requests, double run shares one start, close releases the SDK once', async () => {
  const config = await realBootstrap();
  const entry = await import(copy.url('deployment/api.js', '?ok'));
  await guarded({ PORT: '8080', K_SERVICE: RUN_NAME, K_CONFIGURATION: RUN_NAME, K_REVISION: `${RUN_NAME}-00001-abc` }, async (counts) => {
    const [a, b] = await Promise.all([entry.runApi(), entry.runApi()]);
    assert.equal(a, b, 'double run is one shared start');
    assert.deepEqual(counts.hosts[0], [8080, '0.0.0.0']);
    assert.equal(counts.listened.length, 1);
    const port = counts.listened[0].address().port;
    const host = new URL(config.api.publicOrigin).host;
    assert.equal((await request(port, { method: 'POST', path: '/v2/commands', headers: { Host: 'evil.example' }, body: '{}' })).status, 400, 'foreign Host');
    const unauth = () => request(port, { method: 'POST', path: '/v2/commands', headers: { Host: host, 'Content-Type': 'application/json' }, body: '{}' });
    const results = await Promise.all([unauth(), unauth(), unauth()]);
    assert.deepEqual(results.map((r) => r.status), [401, 401, 401], 'existing auth on every concurrent request');
    assert.deepEqual([...sdk.reads].sort(), ['commandDigestKey', 'identifierKey']);
    await a.close();
    await a.close();
    for (const event of ['sdk.terminate', 'sdk.kms.close', 'sdk.secrets.close', 'sdk.deleteApp']) assert.equal(sdk.events.filter((e) => e === event).length >= 1, true, event);
    assert.equal(sdk.events.filter((e) => e === 'sdk.deleteApp').length, 1, 'released once');
    assert.equal(counts.listened[0].listening, false);
    assert.equal(counts.external, 0);
    await assert.rejects(request(port, { method: 'GET', path: '/v2/commands/x', headers: { Host: host } }));
  });
});

test('A4 listen failure releases the owned SDK and fails with the fixed startup code (no retry on the next run)', async () => {
  await realBootstrap();
  const entry = await import(copy.url('deployment/api.js', '?listen-fail'));
  const before = sdk.events.filter((e) => e === 'sdk.deleteApp').length;
  await guarded({ PORT: '8080', K_SERVICE: RUN_NAME, K_CONFIGURATION: RUN_NAME, K_REVISION: `${RUN_NAME}-00001-abc` }, async (counts) => {
    await assert.rejects(entry.runApi(), (error) => error.code === 'api_startup_failed');
    assert.equal(sdk.events.filter((e) => e === 'sdk.deleteApp').length, before + 1, 'owned SDK released');
    await assert.rejects(entry.runApi(), (error) => error.code === 'api_startup_failed', 'the failed start is not retried');
    assert.equal(counts.external, 0);
  }, { listenFails: true });
});

// ---------- 実entry（createApiEntry）を合成clock・timer・bootstrap・127.0.0.1待受へ結ぶ ----------
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, label) {
  for (let i = 0; i < 300; i += 1) {
    if (fn()) return;
    await sleep(5);
  }
  assert.fail(`timeout: ${label}`);
}

/** 合成の依存: clock・timer（手動発火）・bootstrap（要求ごとのingressを記録して保留）・signal（数えるだけ）。 */
async function syntheticEntry({ holdBootstrap = false, appCloseFails = false, bootstrapError = null } = {}) {
  const { createApiEntry } = await import(probe.url('deployment/api.js', '?synthetic'));
  const config = validateDeploymentConfig(CONFIG);
  const clock = { t: 1_000_000, now() { return this.t; } };
  const timers = [];
  const gates = new Map();
  const seen = [];
  const stats = { appClose: 0, signalsOn: 0, signalsOff: 0, servers: [], bootstrapSignal: null };
  let releaseBootstrap;
  const bootstrapHeld = new Promise((resolve) => (releaseBootstrap = resolve));
  const appOf = (options) => ({
    async handler(req, res) {
      const first = options.ingress();
      const entry = { path: req.url, first, after: null, abortedAtEnd: null };
      seen.push(entry);
      if (req.url === '/reenter') first.signal.addEventListener('abort', () => { entry.reentered = stats.entry.close(); });
      await (gates.get(req.url) ?? Promise.resolve());
      entry.after = options.ingress(); // await後も同じ要求のingress（取り直し・混在0）
      entry.abortedAtEnd = first.signal.aborted;
      if (!res.writableEnded && !res.destroyed) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ receivedAt: first.receivedAt, deadlineAt: first.deadlineAt }));
      }
    },
    async close() {
      stats.appClose += 1;
      if (appCloseFails) throw new Error('synthetic close failure');
    },
  });
  const entry = createApiEntry({
    loadConfig: () => config,
    env: { PORT: '8080', K_SERVICE: RUN_NAME },
    clock,
    bootstrap: async (options) => {
      stats.bootstrapSignal = options.operation.signal;
      if (bootstrapError) throw bootstrapError;
      if (holdBootstrap) await bootstrapHeld;
      return appOf(options);
    },
    createServer: (listener) => {
      const server = http.createServer(listener);
      const listen = server.listen.bind(server);
      server.listen = (_port, _host, callback) => listen(0, '127.0.0.1', callback);
      stats.servers.push(server);
      return server;
    },
    setTimer: (fn, ms) => {
      const timer = { fn, ms, cleared: false };
      timers.push(timer);
      return timer;
    },
    clearTimer: (timer) => { timer.cleared = true; },
    signals: { on: (fn) => { stats.signalsOn += 1; stats.onSignal = fn; }, off: () => { stats.signalsOff += 1; } },
    onSignalCloseFailed: () => { stats.signalFailures = (stats.signalFailures ?? 0) + 1; },
    cors: () => false,
  });
  stats.entry = entry;
  const hold = (path) => {
    let release;
    gates.set(path, new Promise((resolve) => (release = resolve)));
    return () => release();
  };
  return { entry, clock, timers, seen, stats, hold, releaseBootstrap, config };
}
const HOST = new URL(RUN_ORIGIN).host;

test('B1 concurrent successful requests keep their own receivedAt / deadline / signal across awaits (no re-read of time, no mixing)', async () => {
  const s = await syntheticEntry();
  const handle = await s.entry.run();
  const port = s.stats.servers[0].address().port;
  const releaseA = s.hold('/a');
  const releaseB = s.hold('/b');
  s.clock.t = 1_000;
  const a = request(port, { method: 'GET', path: '/a', headers: { Host: HOST } });
  await until(() => s.seen.length === 1, 'a arrived');
  s.clock.t = 5_000;
  const b = request(port, { method: 'GET', path: '/b', headers: { Host: HOST } });
  await until(() => s.seen.length === 2, 'b arrived');
  s.clock.t = 9_000; // 後で時計が進んでも、各要求の期限は受信時のまま
  releaseB();
  releaseA();
  const [ra, rb] = await Promise.all([a, b]);
  assert.deepEqual(JSON.parse(ra.body), { receivedAt: 1_000, deadlineAt: 21_000 });
  assert.deepEqual(JSON.parse(rb.body), { receivedAt: 5_000, deadlineAt: 25_000 });
  const [sa, sb] = s.seen;
  assert.equal(sa.first, sa.after, 'same ingress after await (a)');
  assert.equal(sb.first, sb.after, 'same ingress after await (b)');
  assert.notEqual(sa.first.signal, sb.first.signal);
  assert.deepEqual(s.timers.slice(0, 2).map((t) => t.ms), [20_000, 20_000]);
  assert.ok(s.timers.every((t) => t.cleared), 'timers cleared');
  await handle.close();
});

test('B2 a deadline or an HTTP disconnect aborts only that request; the other one completes normally', async () => {
  const s = await syntheticEntry();
  const handle = await s.entry.run();
  const port = s.stats.servers[0].address().port;
  const releaseA = s.hold('/a');
  const releaseB = s.hold('/b');
  s.hold('/c'); // 切断される要求（解放しない）
  const a = request(port, { method: 'GET', path: '/a', headers: { Host: HOST } });
  const b = request(port, { method: 'GET', path: '/b', headers: { Host: HOST } });
  await until(() => s.seen.length === 2, 'a and b');
  const timerA = s.timers[s.seen.findIndex((x) => x.path === '/a')];
  timerA.fn(); // 合成timerでaの元期限だけ到達
  const sa = s.seen.find((x) => x.path === '/a');
  const sb = s.seen.find((x) => x.path === '/b');
  assert.deepEqual([sa.first.signal.aborted, sb.first.signal.aborted], [true, false]);
  // c: HTTP切断
  const c = http.request({ host: '127.0.0.1', port, path: '/c', method: 'GET', headers: { Host: HOST } });
  c.on('error', () => undefined);
  c.end();
  await until(() => s.seen.some((x) => x.path === '/c'), 'c arrived');
  c.destroy();
  const sc = s.seen.find((x) => x.path === '/c');
  await until(() => sc.first.signal.aborted, 'c aborted by disconnect');
  assert.equal(sb.first.signal.aborted, false, 'b untouched by c');
  releaseA();
  releaseB();
  const rb = await b;
  assert.equal(rb.status, 200);
  await a;
  assert.equal(sb.abortedAtEnd, false);
  await handle.close();
});

test('B3 close latches before aborting: re-entry from an abort listener gets the same promise; the app closes once; nothing keeps listening', async () => {
  const s = await syntheticEntry();
  const handle = await s.entry.run();
  const port = s.stats.servers[0].address().port;
  s.hold('/reenter');
  const pending = request(port, { method: 'GET', path: '/reenter', headers: { Host: HOST } }).catch(() => null);
  await until(() => s.seen.length === 1, 'arrived');
  const closing = handle.close();
  assert.equal(s.seen[0].first.signal.aborted, true, 'close aborted the in-flight request');
  assert.equal(s.seen[0].reentered, closing, 'synchronous re-entry returns the same latched promise');
  assert.equal(s.entry.close(), closing);
  await closing;
  await pending;
  assert.equal(s.stats.appClose, 1, 'owned app closed once');
  assert.equal(s.stats.servers[0].listening, false);
  assert.equal(s.stats.signalsOn, s.stats.signalsOff, 'signal handler removed');
});

test('B4 close during startup: bootstrap sees the abort, the late app is closed once, no listener is created, run fails with the fixed code', async () => {
  const s = await syntheticEntry({ holdBootstrap: true });
  const run = s.entry.run();
  await until(() => s.stats.bootstrapSignal !== null, 'bootstrap started');
  const closing = s.entry.close();
  assert.equal(s.stats.bootstrapSignal.aborted, true);
  s.releaseBootstrap();
  await assert.rejects(run, (error) => error.code === 'api_startup_failed');
  await closing;
  assert.deepEqual([s.stats.appClose, s.stats.servers.length], [1, 0]);
  assert.equal(s.stats.signalsOn, s.stats.signalsOff);
  await assert.rejects(s.entry.run(), (error) => error.code === 'api_startup_failed', 'no restart after close');
});

test('B5 close during startup where the late app close rejects: run and the shared close both report the fixed api_close_failed; one close attempt, no listener, signals removed, no retry', async () => {
  const s = await syntheticEntry({ holdBootstrap: true, appCloseFails: true });
  const run = s.entry.run();
  await until(() => s.stats.bootstrapSignal !== null, 'bootstrap started');
  const closing = s.entry.close();
  s.releaseBootstrap();
  await assert.rejects(run, (error) => error.code === 'api_close_failed', 'run reports the unfinished cleanup');
  await assert.rejects(closing, (error) => error.code === 'api_close_failed', 'close does not turn it into success');
  assert.equal(s.entry.close(), closing, 'second close is the same settled promise');
  await assert.rejects(s.entry.close(), (error) => error.code === 'api_close_failed');
  assert.deepEqual([s.stats.appClose, s.stats.servers.length], [1, 0], 'one close attempt, no listener');
  assert.equal(s.stats.signalsOn, s.stats.signalsOff);
  await assert.rejects(s.entry.run(), (error) => error.code === 'api_close_failed', 'no new start after the failure');
  assert.equal(s.stats.servers.length, 0);
});

test('B6 signal-driven close whose cleanup fails is reported exactly once even with repeated signals; the app is closed once', async () => {
  const s = await syntheticEntry({ appCloseFails: true });
  await s.entry.run();
  s.stats.onSignal();
  s.stats.onSignal();
  await assert.rejects(s.entry.close(), (error) => error.code === 'api_close_failed');
  s.stats.onSignal();
  await sleep(20);
  assert.deepEqual([s.stats.signalFailures, s.stats.appClose], [1, 1]);
  assert.equal(s.stats.servers[0].listening, false);
});

test('M1 real direct main in a child process (synthetic SDK boundaries preloaded): after ready, SIGTERM handling whose cleanup fails ends with exit code 1 and one fixed close_failed event', async () => {
  const { spawn } = await import('node:child_process');
  const { writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { pathToFileURL } = await import('node:url');
  const main = isolatedDist(CONFIG);
  try {
    const fixtures = pathToFileURL(join(process.cwd(), 'test', 'fixtures', 'gateway-runtime.mjs')).href;
    const dist = (name) => main.url(name);
    // child内で実moduleを先に読み込み→公開SDK境界だけを合成へ（firebase-admin/appのdeleteAppは失敗）→stdinの'T'でSIGTERMの登録handlerを起動。
    // 実OSのsignal配送ではなく、processへ登録されたSIGTERM handlerをprocess.emitで呼ぶ（Windowsは子へSIGTERMを配送できないため）。
    const preload = `
import Module, { createRequire } from 'node:module';
import { installGoogleSdkSubstitutes, useCrc32c } from ${JSON.stringify(fixtures)};
const { validateDeploymentConfig } = await import(${JSON.stringify(dist('config/validate.js'))});
const config = validateDeploymentConfig(${JSON.stringify(CONFIG)});
const { kmsMarkerDocument, createKmsSubscriptionPolicy } = await import(${JSON.stringify(dist('storage/firestore/kms-subscription-format.js'))});
const { crc32c } = await import(${JSON.stringify(dist('protection/kms-sealing.js'))});
useCrc32c(crc32c);
const docs = new Map([[\`sttdAuth/\${config.kms.namespace}/config/kms-subscription\`, kmsMarkerDocument(createKmsSubscriptionPolicy({ ...config.kms, readVersions: [...config.kms.readVersions] }))]]);
for (const href of ${JSON.stringify(['connect/firestore.js', 'connect/kms-port.js', 'connect/kms-server.js', 'connect/google-kms-server.js', 'delivery/kms-functions.js', 'delivery/kms-store.js', 'egress/product.js', 'keys/google-secret-reader.js', 'oauth/request-auth-runtime.js', 'protection/google-kms-transport.js', 'identity/firebase.js'].map((name) => main.url(name)))}) await import(href);
installGoogleSdkSubstitutes({ resolveFrom: ${JSON.stringify(dist('google-runtime/development.js'))}, secretVersions: config.secretVersions, docs });
const req = createRequire(new URL(${JSON.stringify(dist('google-runtime/development.js'))}));
Module._cache[req.resolve('firebase-admin/app')].exports.deleteApp = () => Promise.reject(new Error('synthetic close failure'));
process.stdin.on('data', (b) => { for (const ch of String(b)) if (ch === 'T') process.emit('SIGTERM', 'SIGTERM'); });
process.stdin.on('end', () => process.stdin.unref?.());
`;
    const preloadPath = join(main.root, 'preload.mjs');
    writeFileSync(preloadPath, preload);
    const probePort = await new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
    const env = {};
    for (const [k, v] of Object.entries(process.env)) if (!RUNTIME_REFUSED_ENV.has(k.toUpperCase())) env[k] = v;
    Object.assign(env, { PORT: String(probePort), K_SERVICE: RUN_NAME, K_CONFIGURATION: RUN_NAME, K_REVISION: `${RUN_NAME}-00001-abc` });
    delete env.GOOGLE_CLOUD_PROJECT;
    delete env.GCLOUD_PROJECT;
    const child = spawn(process.execPath, ['--import', pathToFileURL(preloadPath).href, join(main.root, 'dist', 'deployment', 'api.js')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
    const killer = setTimeout(() => child.kill(), 30_000);
    try {
      await until(() => stdout.includes('"event":"sttd_api.ready"') || child.exitCode !== null, 'child ready');
      assert.ok(stdout.includes('"event":"sttd_api.ready"'), `ready (stderr: ${stderr.slice(0, 200)})`);
      child.stdin.write('TT'); // 多重signal
      child.stdin.end();
      const code = await exited;
      assert.equal(code, 1, 'exit code 1 after a failed signal cleanup');
      const events = stderr.split('\n').filter((l) => l.trim() !== '');
      assert.deepEqual(events, ['{"event":"sttd_api.close_failed"}'], 'exactly one fixed event and nothing else (no raw error)');
    } finally {
      clearTimeout(killer);
      if (child.exitCode === null) child.kill();
    }
  } finally {
    main.cleanup();
  }
  assert.equal(process.exitCode, undefined, 'importing the entry in the test process never set an exit code');
});

test('F1 the Functions entry keeps its export / options, but a cloud-run-v1 config fails as a fixed config error before any SDK or secret (every request 503)', async () => {
  const writes = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => (writes.push(String(chunk)), original(chunk, ...rest));
  try {
    await guarded({ K_SERVICE: RUN_NAME }, async (counts) => {
      const { sendtexttodotsapi } = await import(probe.url('deployment/functions.js', '?mismatch'));
      assert.equal(typeof sendtexttodotsapi, 'function', 'export kept');
      const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          req.rawBody = Buffer.concat(chunks);
          req.header = req.get = (name) => req.headers[String(name).toLowerCase()];
          void Promise.resolve(sendtexttodotsapi(req, res)).catch(() => res.destroy());
        });
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      try {
        const port = server.address().port;
        const r = await request(port, { method: 'POST', path: '/v2/commands', headers: { Authorization: 'Bearer x', 'Content-Type': 'application/json' }, body: '{}' });
        assert.equal(r.status, 503);
        assert.equal(counts.external, 0);
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    });
  } finally {
    process.stderr.write = original;
  }
  assert.ok(writes.some((w) => w.includes('"stage":"config","code":"config_invalid"')), 'fixed config failure recorded');
  assert.equal(writes.some((w) => /sdk|secret/i.test(w)), false);
});

// ---------- direct entryの起動診断（所有bootstrapの固定diagnosticだけを許可表で保持） ----------
test('S1 direct entry keeps the owned typed diagnostic (allowlisted stage/code, verified mask) and nothing else; other errors are entry/unclassified', async () => {
  const dd = await import(probe.url('google-runtime/delivery-development.js'));
  const api = await import(probe.url('deployment/api.js', '?synthetic'));
  const failWith = async (error) => {
    const s = await syntheticEntry({ bootstrapError: error });
    let caught;
    await s.entry.run().catch((e) => { caught = e; });
    assert.equal(s.stats.servers.length, 0, 'no listener after a startup failure');
    assert.equal(s.stats.signalsOn, s.stats.signalsOff, 'signals cleaned');
    return caught;
  };
  const e1 = await failWith(new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'identifier_secret', code: 'read_failed' }));
  assert.deepEqual([e1.code, { ...e1.diagnostic }], ['api_startup_failed', { stage: 'identifier_secret', code: 'read_failed' }]);
  const e2 = await failWith(new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'environment_rejected', environmentGateMask: 5 }));
  assert.deepEqual({ ...e2.diagnostic }, { stage: 'sdk', code: 'environment_rejected', environmentGateMask: 5 });
  const e3 = await failWith(new dd.OwnedDevelopmentDeliveryCloseError({ stage: 'assembly', code: 'cleanup_failed' }));
  assert.deepEqual([e3.code, { ...e3.diagnostic }], ['api_close_failed', { stage: 'assembly', code: 'cleanup_failed' }]);
  const canary = 'CANARY-secret-projects/x/secrets/y-uid-123';
  const e4 = await failWith(Object.assign(new Error(canary), { diagnostic: { stage: 'sdk', code: 'read_failed' }, cause: canary }));
  assert.deepEqual({ ...e4.diagnostic }, { stage: 'entry', code: 'unclassified' }, 'arbitrary errors do not pass their own diagnostic');
  assert.equal(JSON.stringify({ ...e4, message: e4.message, d: e4.diagnostic }).includes('CANARY'), false);
  // 不正な診断・mask・getter・Proxy は安全にfallback（読取り例外も無害）
  const forged = new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'identifier_secret', code: 'read_failed' });
  Object.defineProperty(forged, 'diagnostic', { value: { stage: 'evil', code: 'read_failed' } });
  assert.deepEqual({ ...api.startDiagnosticOf(forged) }, { stage: 'entry', code: 'unclassified' });
  const getter = new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'aborted' });
  Object.defineProperty(getter, 'diagnostic', { get() { throw new Error(canary); } });
  assert.deepEqual({ ...api.startDiagnosticOf(getter) }, { stage: 'entry', code: 'unclassified' });
  const proxied = new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'aborted' });
  Object.defineProperty(proxied, 'diagnostic', { value: new Proxy({ stage: 'sdk', code: 'aborted' }, {}) });
  assert.deepEqual({ ...api.startDiagnosticOf(proxied) }, { stage: 'entry', code: 'unclassified' });
  const badMask = new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'environment_rejected' });
  Object.defineProperty(badMask, 'diagnostic', { value: { stage: 'sdk', code: 'environment_rejected', environmentGateMask: 64 } });
  assert.deepEqual({ ...api.startDiagnosticOf(badMask) }, { stage: 'sdk', code: 'environment_rejected' }, 'out-of-range mask is dropped');
  const otherMask = new dd.OwnedDevelopmentDeliveryStartupError({ stage: 'sdk', code: 'environment_rejected' });
  Object.defineProperty(otherMask, 'diagnostic', { value: { stage: 'marker', code: 'read_failed', environmentGateMask: 3 } });
  assert.deepEqual({ ...api.startDiagnosticOf(otherMask) }, { stage: 'marker', code: 'read_failed' }, 'mask only for sdk/environment_rejected');
  // configの不正は固定 config/config_invalid
  const c = await (await import(probe.url('deployment/api.js', '?cfg'))).createApiEntry({ loadConfig: () => { throw new Error(canary); }, env: {}, clock: { now: () => 0 }, bootstrap: async () => { throw new Error('unused'); }, createServer: () => { throw new Error('unused'); }, setTimer: () => 0, clearTimer: () => {}, signals: { on: () => {}, off: () => {} }, cors: () => false }).run().catch((e) => e);
  assert.deepEqual([c.code, { ...c.diagnostic }], ['api_config_invalid', { stage: 'config', code: 'config_invalid' }]);
  assert.equal(api.startFailureLine(e2), '{"event":"sttd_api.start_failed","stage":"sdk","code":"environment_rejected","environmentGateMask":5}\n');
  assert.equal(api.startFailureLine(new Error(canary)), '{"event":"sttd_api.start_failed","stage":"entry","code":"unclassified"}\n');
});

test('S2 direct main writes exactly one fixed start_failed line with the diagnostic and exits 1; importing writes nothing', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const file = fileURLToPath(probe.url('deployment/api.js'));
  const env = { ...process.env, PORT: 'bad', K_SERVICE: RUN_NAME };
  for (const n of Object.keys(env)) if (RUNTIME_REFUSED_ENV.has(n.toUpperCase()) && n !== 'PORT' && n !== 'K_SERVICE') delete env[n];
  const r = spawnSync(process.execPath, [file], { encoding: 'utf8', env, timeout: 30_000 });
  assert.equal(r.status, 1);
  assert.deepEqual(r.stderr.split('\n').filter(Boolean), ['{"event":"sttd_api.start_failed","stage":"config","code":"config_invalid"}']);
  assert.equal(r.stdout, '');
  const imp = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(probe.url('deployment/api.js'))});`], { encoding: 'utf8', env, timeout: 30_000 });
  assert.deepEqual([imp.status, imp.stdout, imp.stderr], [0, '', '']);
});
