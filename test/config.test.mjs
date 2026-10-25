// 配置設定（src/config/deployment.ts → dist/config/deployment.js）の検証と、未設定時の副作用前拒否。
//   - G1: 合成の未設定値（test/fixtures/unconfigured-deployment.mjs。配布時と同じ形のplaceholder）はunconfigured。configuredだけをtrueにしても
//     placeholderが形式で落ちる（有効化値だけで検査を迂回できない）。導入者の実際の設定・source・distは読まない（配布sourceが未設定である
//     ことは公開fileの点検で別に確かめる）。
//   - G2: 合成の設定済み値は通り、deep frozenな写しを返す。loadDeploymentConfigは同じ値を返す。
//   - G3: 未知のkey（endpoint・credential・emulator等のoverride）・accessor・Proxy・型違い・各項目の形式違い・相互不整合を全て拒否する。
//   - G4: 合成の未設定値へ差し替えたdistの一時copyを評価し、Functions entryのimport・MCP entry・API/MCP起動口・SDK factory・CORSが、socket・DNS・HTTP(S)・TLS・
//     fetch・listen・signal登録の前に固定の設定errorで止まることを確かめる。
//   - G5: Functionsのexport名と設定の照合値（API_FUNCTION_EXPORT）が一致する（compile後のdistの静的読取り）。
// 実Cloud・資格・外部network 0。fixtureは全て合成値。

import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net, { Server } from 'node:net';
import { join } from 'node:path';
import { after, test } from 'node:test';
import tls from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { API_FUNCTION_EXPORT, DeploymentConfigError, loadDeploymentConfig, validateDeploymentConfig } from '../dist/config/validate.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';
import { DEPLOYMENT_CONFIG as UNCONFIGURED } from './fixtures/unconfigured-deployment.mjs';

const WORK = fileURLToPath(new URL('..', import.meta.url));
const UNCONFIGURED_FILE = fileURLToPath(new URL('./fixtures/unconfigured-deployment.mjs', import.meta.url));
const clone = () => structuredClone(SYNTHETIC);
const codeOf = (fn) => {
  try {
    fn();
    return 'ok';
  } catch (error) {
    return error instanceof DeploymentConfigError ? error.code : `unexpected:${error?.name}`;
  }
};
const results = {};
let unhandled = 0;
process.on('unhandledRejection', () => {
  unhandled += 1;
});
after(() => {
  process.stdout.write(`# CONFIG_COUNTS ${JSON.stringify({ unhandled, results })}\n`);
  assert.equal(unhandled, 0);
});

test('G1 unconfigured placeholders: unconfigured, and switching only configured to true still fails on the placeholders', () => {
  const distributed = structuredClone(UNCONFIGURED);
  assert.equal(distributed.configured, false);
  assert.equal(codeOf(() => validateDeploymentConfig(distributed)), 'deployment_config_unconfigured');
  const enabled = { ...structuredClone(distributed), configured: true };
  assert.equal(codeOf(() => validateDeploymentConfig(enabled)), 'deployment_config_invalid');
  // placeholderのどれか1つだけを直しても通らない（各項目を個別に検査している）。
  const partial = { ...enabled, projectId: SYNTHETIC.projectId };
  assert.equal(codeOf(() => validateDeploymentConfig(partial)), 'deployment_config_invalid');
  results.G1 = { distributedKeys: Object.keys(distributed).length };
});

test('G2 synthetic configured values pass, the result is a deep frozen copy, and the build under test loads the same values', () => {
  const input = clone();
  const config = validateDeploymentConfig(input);
  assert.equal(Object.isFrozen(config) && Object.isFrozen(config.api) && Object.isFrozen(config.kms) && Object.isFrozen(config.kms.readVersions), true);
  assert.notEqual(config.kms.readVersions, input.kms.readVersions, 'arrays are copied');
  input.projectId = 'changed-after-validation';
  assert.equal(config.projectId, SYNTHETIC.projectId, 'later caller mutation is not read');
  assert.equal('configured' in config, false);
  const loaded = loadDeploymentConfig();
  assert.equal(loadDeploymentConfig(), loaded, 'memoized');
  assert.deepEqual(JSON.parse(JSON.stringify(loaded)), JSON.parse(JSON.stringify(config)));
  assert.equal(config.api.functionName, API_FUNCTION_EXPORT);
  results.G2 = { location: config.location };
});

test('G3 every unknown key, accessor, proxy, wrong type, malformed value and inconsistency is rejected as deployment_config_invalid', () => {
  const cases = {
    extraTopKey: (c) => Object.assign(c, { firestoreEmulatorHost: '127.0.0.1:8080' }),
    extraApiKey: (c) => Object.assign(c.api, { servicePath: 'evil.example.com' }),
    extraKmsKey: (c) => Object.assign(c.kms, { credentials: 'x' }),
    missingWeb: (c) => delete c.web,
    projectIdUpper: (c) => Object.assign(c, { projectId: 'Bad-Project' }),
    projectNumberZero: (c) => Object.assign(c, { projectNumber: '0123456789' }),
    databaseBad: (c) => Object.assign(c, { databaseId: 'DB!' }),
    locationGlobal: (c) => Object.assign(c, { location: 'global' }),
    functionNameOther: (c) => Object.assign(c.api, { functionName: 'otherapi', serviceName: 'otherapi' }),
    serviceNameMismatch: (c) => Object.assign(c.api, { serviceName: 'otherapi' }),
    invokerPublic: (c) => Object.assign(c.api, { invoker: 'public' }),
    apiSaOtherProject: (c) => Object.assign(c.api, { serviceAccount: 'api-runtime@other-project.iam.gserviceaccount.com' }),
    connectSameSa: (c) => Object.assign(c.connect, { serviceAccount: c.api.serviceAccount }),
    connectSameService: (c) => Object.assign(c.connect, { serviceName: c.api.serviceName }),
    connectSameOrigin: (c) => Object.assign(c.connect, { publicOrigin: c.api.publicOrigin }),
    connectServiceUpper: (c) => Object.assign(c.connect, { serviceName: 'Connect' }),
    originHttp: (c) => Object.assign(c.api, { publicOrigin: 'http://api.sendtexttodots.example.org' }),
    originLocalhost: (c) => Object.assign(c.connect, { publicOrigin: 'https://localhost' }),
    originIp: (c) => Object.assign(c.connect, { publicOrigin: 'https://203.0.113.10' }),
    originPath: (c) => Object.assign(c.connect, { publicOrigin: 'https://connect.sendtexttodots.example.org/' }),
    originInvalidTld: (c) => Object.assign(c.connect, { publicOrigin: 'https://connect.example.invalid' }),
    connectNamespaceBad: (c) => Object.assign(c, { connectNamespace: 't256_00000000-0000-0000-0000-000000000000' }),
    deliveryNamespaceSwapped: (c) => Object.assign(c, { deliveryNamespace: c.connectNamespace }),
    kmsNamespaceBad: (c) => Object.assign(c.kms, { namespace: c.connectNamespace }),
    kmsEnvironment: (c) => Object.assign(c.kms, { environment: 'production' }),
    kmsProjectMismatch: (c) => Object.assign(c.kms, { projectId: 'other-project-x' }),
    kmsDatabaseMismatch: (c) => Object.assign(c.kms, { databaseId: 'other-db' }),
    kmsLocationMismatch: (c) => Object.assign(c.kms, { cryptoKey: c.kms.cryptoKey.replace('/europe-west1/', '/us-central1/') }),
    kmsKeyOtherProject: (c) => Object.assign(c.kms, { cryptoKey: c.kms.cryptoKey.replace(`projects/${c.projectId}/`, 'projects/other-project-x/') }),
    kmsWriteNotRead: (c) => Object.assign(c.kms, { writeVersion: 2 }),
    kmsReadDuplicate: (c) => Object.assign(c.kms, { readVersions: [1, 1] }),
    secretOtherProject: (c) => Object.assign(c.secretVersions, { jwks: 'projects/999999999999/secrets/stt-jwks/versions/1' }),
    secretLatest: (c) => Object.assign(c.secretVersions, { jwks: `projects/${c.projectNumber}/secrets/stt-jwks/versions/latest` }),
    secretSameId: (c) => Object.assign(c.secretVersions, { cookieKeys: c.secretVersions.jwks }),
    webProjectMismatch: (c) => Object.assign(c.web, { projectId: 'other-project-x' }),
    webAuthDomainBad: (c) => Object.assign(c.web, { authDomain: 'https://x.firebaseapp.com' }),
    apiKeyEnvCredential: (c) => Object.assign(c.web, { apiKeyEnv: 'GOOGLE_APPLICATION_CREDENTIALS' }),
    apiKeyEnvNodeOptions: (c) => Object.assign(c.web, { apiKeyEnv: 'NODE_OPTIONS' }),
    apiKeyEnvPort: (c) => Object.assign(c.web, { apiKeyEnv: 'PORT' }),
    apiKeyEnvLower: (c) => Object.assign(c.web, { apiKeyEnv: 'web_api_key' }),
  };
  const outcomes = {};
  for (const [name, mutate] of Object.entries(cases)) {
    const config = clone();
    mutate(config);
    outcomes[name] = codeOf(() => validateDeploymentConfig(config));
  }
  const accessor = clone();
  Object.defineProperty(accessor, 'projectId', { get: () => SYNTHETIC.projectId, enumerable: true });
  outcomes.accessor = codeOf(() => validateDeploymentConfig(accessor));
  outcomes.proxy = codeOf(() => validateDeploymentConfig(new Proxy(clone(), {})));
  outcomes.nestedProxy = codeOf(() => validateDeploymentConfig({ ...clone(), api: new Proxy(clone().api, {}) }));
  outcomes.notObject = codeOf(() => validateDeploymentConfig('configured'));
  // configuredはboolean trueだけ（文字列等は未設定と同じ扱い）。
  assert.equal(codeOf(() => validateDeploymentConfig({ ...clone(), configured: 'true' })), 'deployment_config_unconfigured');
  outcomes.nullValue = codeOf(() => validateDeploymentConfig(null));
  for (const [name, outcome] of Object.entries(outcomes)) assert.equal(outcome, 'deployment_config_invalid', name);
  assert.equal(codeOf(() => validateDeploymentConfig(clone())), 'ok', 'the untouched synthetic value still passes');
  results.G3 = { rejected: Object.keys(outcomes).length };
});

test('G4 with an unconfigured build, every entry and start function stops with a fixed config error before any network, listen or signal side effect', async () => {
  const dir = mkdtempSync(join(WORK, '.unconfigured-'));
  cpSync(join(WORK, 'dist'), join(dir, 'dist'), { recursive: true });
  cpSync(UNCONFIGURED_FILE, join(dir, 'dist', 'config', 'deployment.js'));
  const url = (path) => pathToFileURL(join(dir, 'dist', ...path.split('/'))).href;
  const attempts = { count: 0 };
  const refuse = () => {
    attempts.count += 1;
    throw new Error('config test: network refused');
  };
  const originals = { connect: net.Socket.prototype.connect, lookup: dns.lookup, httpRequest: http.request, httpsRequest: https.request, tlsConnect: tls.connect, fetch: globalThis.fetch, listen: Server.prototype.listen };
  const signals = { term: process.listenerCount('SIGTERM'), int: process.listenerCount('SIGINT') };
  net.Socket.prototype.connect = refuse;
  dns.lookup = refuse;
  http.request = refuse;
  https.request = refuse;
  tls.connect = refuse;
  globalThis.fetch = async () => refuse();
  Server.prototype.listen = refuse;
  const outcomes = {};
  try {
    const validate = await import(url('config/validate.js'));
    try {
      validate.loadDeploymentConfig();
      outcomes.load = 'ok';
    } catch (error) {
      outcomes.load = error.code;
    }
    try {
      await import(`${url('deployment/functions.js')}?config-test`);
      outcomes.functionsImport = 'ok';
    } catch (error) {
      outcomes.functionsImport = `${error.name}:${error.code}`;
    }
    const connectEntry = await import(`${url('deployment/connect.js')}?config-test`);
    outcomes.connectEntry = await connectEntry.runDevelopmentConnect().then(
      () => 'ok',
      (error) => error.code,
    );
    const operation = () => ({ deadlineAt: Date.now() + 20_000, signal: new AbortController().signal });
    const sdk = await import(url('google-runtime/development.js'));
    outcomes.sdk = await sdk
      .openDevelopmentGoogleSdk({ projectId: SYNTHETIC.projectId, databaseId: SYNTHETIC.databaseId, expectedServiceName: SYNTHETIC.api.serviceName, clock: { now: () => Date.now() }, operation: operation() })
      .then(
        () => 'ok',
        (error) => error.code,
      );
    const delivery = await import(url('google-runtime/delivery-development.js'));
    outcomes.delivery = await delivery
      .startOwnedIngressDevelopmentDeliveryFunction({
        projectId: SYNTHETIC.projectId,
        projectNumber: SYNTHETIC.projectNumber,
        databaseId: SYNTHETIC.databaseId,
        expectedServiceName: SYNTHETIC.api.serviceName,
        connectNamespace: SYNTHETIC.connectNamespace,
        deliveryNamespace: SYNTHETIC.deliveryNamespace,
        kms: clone().kms,
        secretVersions: clone().secretVersions,
        clock: { now: () => Date.now() },
        operation: operation(),
        ingress: () => {
          throw new Error('not called');
        },
      })
      .then(
        () => 'ok',
        (error) => `${error.code}:${error.diagnostic?.stage}`,
      );
    const connect = await import(url('google-runtime/connect-development.js'));
    outcomes.connect = await connect
      .startOwnedDevelopmentConnectServer({
        projectId: SYNTHETIC.projectId,
        projectNumber: SYNTHETIC.projectNumber,
        databaseId: SYNTHETIC.databaseId,
        expectedServiceName: SYNTHETIC.connect.serviceName,
        bindPort: 8080,
        publicOrigin: SYNTHETIC.connect.publicOrigin,
        connectNamespace: SYNTHETIC.connectNamespace,
        kms: clone().kms,
        secretVersions: clone().secretVersions,
        web: { apiKey: 'synthetic-web-api-key', authDomain: SYNTHETIC.web.authDomain, projectId: SYNTHETIC.web.projectId },
        clock: { now: () => Date.now() },
        operation: operation(),
      })
      .then(
        () => 'ok',
        (error) => error.code,
      );
    const cors = await import(url('deployment/console-cors.js'));
    try {
      cors.decideConsoleCors('POST', '/v2/commands', ['Origin', SYNTHETIC.connect.publicOrigin]);
      outcomes.cors = 'ok';
    } catch (error) {
      outcomes.cors = error.code;
    }
    // Originの無いnative要求は設定に触れない（従来どおりCORS headerなし）。
    outcomes.corsNoOrigin = cors.decideConsoleCors('POST', '/v2/commands', []).kind;
  } finally {
    Object.assign(net.Socket.prototype, { connect: originals.connect });
    dns.lookup = originals.lookup;
    http.request = originals.httpRequest;
    https.request = originals.httpsRequest;
    tls.connect = originals.tlsConnect;
    globalThis.fetch = originals.fetch;
    Server.prototype.listen = originals.listen;
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  }
  assert.deepEqual(outcomes, {
    load: 'deployment_config_unconfigured',
    functionsImport: 'DeploymentConfigError:deployment_config_unconfigured',
    connectEntry: 'development_connect_config_invalid',
    sdk: 'invalid_config',
    delivery: 'owned_development_delivery_config_invalid:config',
    connect: 'owned_development_connect_config_invalid',
    cors: 'deployment_config_unconfigured',
    corsNoOrigin: 'none',
  });
  assert.equal(attempts.count, 0, 'no socket/DNS/HTTP/TLS/fetch/listen attempt');
  assert.deepEqual([process.listenerCount('SIGTERM'), process.listenerCount('SIGINT')], [signals.term, signals.int], 'no signal listener registered');
  results.G4 = outcomes;
});

test('G5 the Functions export name equals the value the config validator accepts', () => {
  const functions = readFileSync(join(WORK, 'dist', 'deployment', 'functions.js'), 'utf8');
  const exported = [...functions.matchAll(/^export const ([A-Za-z0-9_$]+) =/gm)].map((match) => match[1]);
  assert.deepEqual(exported, [API_FUNCTION_EXPORT]);
});
