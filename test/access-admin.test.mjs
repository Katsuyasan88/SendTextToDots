// 利用許可の管理（dist/access/admin.js と scripts/manage-access.mjs）を、注入した合成SDK（in-memory Firestore・合成identifierKey）だけで確かめる。
//   - M1: 引数・標準入力のUIDの形（argvにUIDを取らない・1行1件）、固定出力（UID・hash・pathを出さない、64KiB以下）。
//   - M2: 期待対象の不一致・未設定はSDK生成の前に止める（openSdk 0）。
//   - M3: status→grant（期待absent）→同状態の再実行（書込み・世代変更0）→古い期待版の競合（書込み0）→revoke→grant（毎回新世代）。
//     書いたrecordは接続保存（ConnectStorage）の同じidentityHashで読める（runtimeのloginが許可として扱う）。
//   - M4: 不正なrecordは修復せずinvalid_record、DB障害はunavailable、期限超過はtimed_out。鍵は使用後に0埋め、SDKは成否ともclose。
//   - M5: CLIのimportは副作用0。API/MCPの配布entryの静的依存閉包に管理module・CLIが入らない。
// 実ADC探索・Secret Manager・Firestore・Cloud・network・子process 0（openAdminSdkは呼ばない）。UIDは合成値。

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, normalize } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { formatAdminResult, parseAdminArgs, parseUidInput, runAccessAdmin } from '../dist/access/admin.js';
import { validateDeploymentConfig } from '../dist/config/validate.js';
import { ConnectStorage } from '../dist/connect/firestore.js';
import { createHmacHasher } from '../dist/secrets.js';
import { moduleSpecifiers } from '../scripts/module-specifiers.mjs';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';

const CONFIG = validateDeploymentConfig(structuredClone(SYNTHETIC));
const TARGET = { projectId: CONFIG.projectId, databaseId: CONFIG.databaseId, connectNamespace: CONFIG.connectNamespace };
const UID = 'synthetic-uid-0001';
const BASE = 1_900_000_000_000;
const WORK = fileURLToPath(new URL('..', import.meta.url));

/** 合成Firestore（transactionは読取り→書込み。updateTimeは書込みごとに進む）。 */
function fakeDb() {
  const docs = new Map();
  let tick = 0;
  const control = { fail: false, writes: 0, transactions: 0, options: [] };
  const snapshot = (path) => {
    const entry = docs.get(path);
    return { exists: entry !== undefined, updateTime: entry?.updateTime, data: () => (entry === undefined ? undefined : structuredClone(entry.data)) };
  };
  const collectionOf = (path) => ({ doc: (id) => refOf(`${path}/${id}`) });
  function refOf(path) {
    return { firestore: db, path, id: path.split('/').pop(), collection: (name) => collectionOf(`${path}/${name}`), get: async () => snapshot(path) };
  }
  const write = (path, data) => {
    tick += 1;
    control.writes += 1;
    docs.set(path, { data: structuredClone(data), updateTime: { seconds: 1_900_000_000 + tick, nanoseconds: tick } });
  };
  const db = {
    docs,
    control,
    collection: (name) => collectionOf(name),
    async runTransaction(fn, options) {
      control.transactions += 1;
      control.options.push(options);
      if (control.fail) throw new Error('synthetic transaction failure');
      const pending = [];
      const result = await fn({
        get: async (ref) => snapshot(ref.path),
        create: (ref, data) => void pending.push(() => {
          if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
          write(ref.path, data);
        }),
        set: (ref, data) => void pending.push(() => write(ref.path, data)),
      });
      for (const apply of pending) apply();
      return result;
    },
  };
  return db;
}

function harness({ key = randomBytes(32) } = {}) {
  const db = fakeDb();
  const calls = { open: 0, close: 0, keys: [], closeFails: false };
  const deps = {
    config: () => CONFIG,
    clock: { now: () => BASE },
    openSdk: async (config, operation) => {
      calls.open += 1;
      assert.equal(config, CONFIG);
      assert.ok(operation.deadlineAt === BASE + 30_000 && operation.signal instanceof AbortSignal);
      return {
        db,
        readIdentifierKey: async () => {
          const copy = Buffer.from(key);
          calls.keys.push(copy);
          return copy;
        },
        close: async () => {
          calls.close += 1;
          if (calls.closeFails) throw new Error('synthetic close failure');
        },
      };
    },
  };
  const run = (command, expected, overrides = {}) =>
    runAccessAdmin({ command, target: TARGET, ...(expected === undefined ? {} : { expected }) }, overrides.uid ?? UID, { ...deps, ...overrides.deps });
  const accessPath = (uid = UID) => `sttdConnect/${CONFIG.connectNamespace}/access/${createHmacHasher(key).hash(`t256:${CONFIG.connectNamespace}:identity`, `${CONFIG.projectId}\0${uid}`)}`;
  return { db, calls, deps, run, key, accessPath };
}

test('M1 arguments, stdin UID and fixed output', () => {
  const args = ['--project', TARGET.projectId, '--database', TARGET.databaseId, '--namespace', TARGET.connectNamespace];
  assert.deepEqual(parseAdminArgs(['status', ...args]), { command: 'status', target: TARGET });
  assert.deepEqual(parseAdminArgs(['grant', ...args, '--expect', 'absent']), { command: 'grant', target: TARGET, expected: 'absent' });
  assert.equal(parseAdminArgs(['revoke', ...args, '--expect', '1900000001.000000001']).expected, '1900000001.000000001');
  for (const bad of [
    [],
    ['delete', ...args],
    ['status', ...args, '--expect', 'absent'],
    ['grant', ...args],
    ['grant', ...args, '--expect', 'latest'],
    ['status', ...args, '--uid', UID],
    ['status', ...args, '--project', 'x'],
    ['status', '--project', TARGET.projectId],
    ['status', ...args.slice(0, -1)],
  ]) {
    assert.equal(parseAdminArgs(bad), null, bad.join(' '));
  }
  assert.equal(parseUidInput(`${UID}\n`), UID);
  assert.equal(parseUidInput(`${UID}\r\n`), UID);
  assert.equal(parseUidInput(UID), UID);
  for (const bad of ['', '\n', `${UID}\n${UID}\n`, `${UID} x`, ' uid', 'u'.repeat(129), `${UID}\n\n`, Buffer.alloc(2000, 0x61)]) {
    assert.equal(parseUidInput(bad), null, String(bad).slice(0, 20));
  }
  const line = formatAdminResult({ code: 'status', state: 'active', version: '1900000001.000000001' });
  assert.equal(line, '{"code":"status","state":"active","version":"1900000001.000000001"}\n');
  assert.ok(Buffer.byteLength(line) <= 65_536);
});

test('M2 target mismatch or an unconfigured deployment stops before the SDK factory', async () => {
  const h = harness();
  for (const target of [{ ...TARGET, projectId: 'other-project-1' }, { ...TARGET, databaseId: 'other-db' }, { ...TARGET, connectNamespace: `t256_${randomUUID()}` }]) {
    assert.deepEqual(await runAccessAdmin({ command: 'status', target }, UID, h.deps), { code: 'target_mismatch' });
  }
  const unconfigured = () => {
    throw new Error('deployment_config_unconfigured');
  };
  assert.deepEqual(await h.run('status', undefined, { deps: { config: unconfigured } }), { code: 'unconfigured' });
  assert.deepEqual(await h.run('status', undefined, { uid: 'bad uid' }), { code: 'invalid_input' });
  assert.equal(h.calls.open, 0);
});

test('M3 status / grant / revoke with expected versions: one record, a new generation per transition, no write for the same state or a stale expectation; runtime login sees the record', async () => {
  const h = harness();
  assert.deepEqual(await h.run('status'), { code: 'status', state: 'absent', version: 'absent' });
  assert.deepEqual(await h.run('grant', 'absent'), { code: 'changed', state: 'active' });
  const first = h.db.docs.get(h.accessPath()).data;
  assert.deepEqual(Object.keys(first).sort(), ['generation', 'state', 'updatedAt', 'version']);
  assert.deepEqual([first.version, first.state, first.updatedAt], [1, 'active', BASE]);
  const status = await h.run('status');
  assert.equal(status.state, 'active');
  assert.match(status.version, /^\d+\.\d{9}$/);
  const writes = h.db.control.writes;
  assert.deepEqual(await h.run('grant', status.version), { code: 'unchanged', state: 'active', version: status.version });
  assert.deepEqual(await h.run('revoke', 'absent'), { code: 'conflict' }, 'a stale expectation is not applied to the latest state');
  assert.equal(h.db.control.writes, writes, 'no write for the same state or a conflict');
  assert.deepEqual(await h.run('revoke', status.version), { code: 'changed', state: 'disabled' });
  const stopped = h.db.docs.get(h.accessPath()).data;
  assert.notEqual(stopped.generation, first.generation);
  assert.deepEqual(await h.run('grant', status.version), { code: 'conflict' });
  const again = await h.run('status');
  assert.deepEqual(await h.run('grant', again.version), { code: 'changed', state: 'active' });
  const reenabled = h.db.docs.get(h.accessPath()).data;
  assert.ok(reenabled.generation !== first.generation && reenabled.generation !== stopped.generation);
  assert.equal([...h.db.docs.keys()].length, 1, 'exactly one record');
  // 不存在のrevokeは書込みなし。
  assert.deepEqual(await h.run('revoke', 'absent', { uid: 'synthetic-uid-0002' }), { code: 'unchanged', state: 'absent', version: 'absent' });
  assert.equal([...h.db.docs.keys()].length, 1);
  // 1操作1transaction・SDK maxAttemptsは5以下、鍵は0埋め、SDKは毎回close。
  assert.ok(h.db.control.options.every((options) => options?.readOnly === true || options?.maxAttempts <= 5));
  assert.ok(h.calls.keys.every((buffer) => buffer.every((byte) => byte === 0)), 'keys zeroed');
  assert.equal(h.calls.close, h.calls.open);

  // 同じ鍵・同じnamespaceの接続保存はこのrecordを許可として読む（identityHashが一致する）。
  const storage = new ConnectStorage({
    db: h.db,
    namespace: CONFIG.connectNamespace,
    hasher: createHmacHasher(h.key),
    box: { seal: () => 'sealed', open: () => '' },
    clock: { now: () => BASE },
    ownerInactivityMs: 1,
    interactionTtlMs: 1,
    grantInactivityMs: 1,
  });
  assert.equal(await storage.accessDisplay({ projectId: CONFIG.projectId, uid: UID, authTimeSec: 1 }), 'allowed');
  assert.equal(await storage.accessDisplay({ projectId: CONFIG.projectId, uid: 'synthetic-uid-0002', authTimeSec: 1 }), 'denied');
});

test('M4 invalid record / DB failure / deadline / close failure are fixed codes; no repair and no automatic retry', async () => {
  const h = harness();
  h.db.docs.set(h.accessPath(), { data: { version: 1, state: 'enabled' }, updateTime: { seconds: 1, nanoseconds: 1 } });
  const writes = h.db.control.writes;
  assert.deepEqual(await h.run('status'), { code: 'invalid_record' });
  assert.deepEqual(await h.run('grant', '1.000000001'), { code: 'invalid_record' });
  assert.equal(h.db.control.writes, writes, 'no repair');
  h.db.control.fail = true;
  const transactions = h.db.control.transactions;
  assert.deepEqual(await h.run('status'), { code: 'unavailable' });
  assert.equal(h.db.control.transactions, transactions + 1, 'one transaction, no outer retry');
  h.db.control.fail = false;
  // 元期限を過ぎた後の結果は採用しない。
  let calls = 0;
  const late = { now: () => (calls++ === 0 ? BASE : BASE + 30_001) };
  assert.deepEqual(await h.run('status', undefined, { deps: { clock: late } }), { code: 'timed_out' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.calls.close, h.calls.open, 'an SDK opened after the deadline is closed, not adopted');
  // 鍵の形が違えば使わない。
  assert.deepEqual(await harness({ key: randomBytes(16) }).run('status'), { code: 'unavailable' });
  // closeの失敗: 失敗した操作はclose_failed、確定した結果は変えない。
  h.calls.closeFails = true;
  h.db.control.fail = true;
  assert.deepEqual(await h.run('status'), { code: 'close_failed' });
  h.db.control.fail = false;
  assert.deepEqual(await h.run('status'), { code: 'close_failed' }, 'an invalid record with a failed close');
  assert.equal(h.calls.close, h.calls.open);
});

test('M5 the CLI import has no side effect; the admin module is not in the API/MCP runtime closure', async () => {
  const before = { exitCode: process.exitCode, listeners: process.listenerCount('SIGINT') };
  const cli = await import('../scripts/manage-access.mjs');
  assert.equal(typeof cli.main, 'function');
  assert.deepEqual({ exitCode: process.exitCode, listeners: process.listenerCount('SIGINT') }, before);

  // 配布entry（API・MCP）の静的import閉包を辿る（相対specifierだけ。bareは外部依存）。
  const closure = (entry) => {
    const seen = new Set();
    const queue = [join(WORK, entry)];
    while (queue.length > 0) {
      const file = normalize(queue.pop());
      if (seen.has(file)) continue;
      seen.add(file);
      const { imports } = moduleSpecifiers(readFileSync(file, 'utf8'));
      for (const specifier of imports) {
        if (!specifier.startsWith('.')) continue;
        const next = join(dirname(file), specifier);
        assert.ok(existsSync(next), specifier);
        queue.push(next);
      }
    }
    return [...seen].map((file) => file.slice(WORK.length).replaceAll('\\', '/'));
  };
  for (const entry of ['dist/deployment/functions.js', 'dist/deployment/connect.js']) {
    const files = closure(entry);
    assert.ok(files.some((file) => file.endsWith('access/policy.js')), `${entry} uses the access policy`);
    assert.equal(files.some((file) => file.endsWith('access/admin.js') || file.includes('manage-access')), false, `${entry} does not include the admin module`);
  }
});
