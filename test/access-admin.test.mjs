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
  // onGet: tx.getの後に呼ぶ（時計を進める等）。retryOnce: 1回目の実行を捨ててSDKのように閉包を再実行する（beforeRetryを呼ぶ）。
  const control = { fail: false, writes: 0, transactions: 0, options: [], onGet: null, retryOnce: false, beforeRetry: null, attempts: 0 };
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
      for (;;) {
        control.attempts += 1;
        const pending = [];
        const result = await fn({
          get: async (ref) => {
            const value = snapshot(ref.path);
            control.onGet?.();
            return value;
          },
          create: (ref, data) => void pending.push(() => {
            if (docs.has(ref.path)) throw new Error('ALREADY_EXISTS');
            write(ref.path, data);
          }),
          set: (ref, data) => void pending.push(() => write(ref.path, data)),
        });
        if (control.retryOnce) {
          // 競合でcommitできなかった1回目（書込みを捨てる）→ SDKが閉包を再実行する。
          control.retryOnce = false;
          control.beforeRetry?.();
          continue;
        }
        for (const apply of pending) apply();
        return result;
      }
    },
  };
  return db;
}

function harness({ key = randomBytes(32) } = {}) {
  const db = fakeDb();
  // keyDelayMs: 鍵を遅れて返す。closeMode: 'ok' | 'fail' | 'hang'。
  const calls = { open: 0, close: 0, keys: [], closeFails: false, closeMode: 'ok', keyDelayMs: 0, openGate: null };
  const time = { value: BASE };
  const deps = {
    config: () => CONFIG,
    clock: { now: () => time.value },
    openSdk: async (config, operation) => {
      calls.open += 1;
      assert.equal(config, CONFIG);
      assert.ok(operation.signal instanceof AbortSignal && operation.deadlineAt <= time.value + 25_000, 'the work deadline is passed to the SDK');
      const sdk = {
        db,
        readIdentifierKey: async () => {
          if (calls.keyDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, calls.keyDelayMs));
          const copy = Buffer.from(key);
          calls.keys.push(copy);
          return copy;
        },
        close: async () => {
          calls.close += 1;
          if (calls.closeFails || calls.closeMode === 'fail') throw new Error('synthetic close failure');
          if (calls.closeMode === 'hang') await new Promise(() => {});
        },
      };
      if (calls.openGate) await calls.openGate;
      return sdk;
    },
  };
  const run = (command, expected, overrides = {}) =>
    runAccessAdmin({ command, target: TARGET, ...(expected === undefined ? {} : { expected }) }, overrides.uid ?? UID, { ...deps, ...overrides.deps });
  const accessPath = (uid = UID) => `sttdConnect/${CONFIG.connectNamespace}/access/${createHmacHasher(key).hash(`t256:${CONFIG.connectNamespace}:identity`, `${CONFIG.projectId}\0${uid}`)}`;
  return { db, calls, deps, run, key, accessPath, time };
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
  // 現行の検証済みidentityと同じく、有効なUnicodeのUIDも1〜128文字ならそのまま受ける（trim・置換・正規化しない）。
  for (const unicode of ['利用者ユーザー', 'uid-😀-x', ' spaced uid ', 'e\u0301', 'u'.repeat(128), '😀'.repeat(64), `a${String.fromCharCode(0xd83d, 0xde00)}b`]) {
    assert.equal(parseUidInput(`${unicode}\n`), unicode, JSON.stringify(unicode));
  }
  assert.notEqual(parseUidInput('e\u0301'), parseUidInput('\u00e9'), 'not normalized into another UID');
  for (const bad of [
    '',
    '\n',
    `${UID}\n${UID}\n`,
    `${UID}\n\n`,
    `${UID}\r`,
    `a\rb`,
    `a\tb`,
    `a\u2028b`,
    `\ufeff${UID}`,
    'u'.repeat(129),
    '😀'.repeat(65),
    Buffer.from([0x61, 0xff, 0x62]),
    Buffer.from([0xed, 0xa0, 0x80]),
    // 文字列入力の孤立surrogate（UTF-8変換でU+FFFDへ置き換わる前に拒否する）。
    String.fromCharCode(0xd800),
    String.fromCharCode(0xdc00),
    `a${String.fromCharCode(0xd800)}b`,
    `a${String.fromCharCode(0xdc00)}b\n`,
    `${String.fromCharCode(0xdc00, 0xd800)}`,
    Buffer.alloc(2000, 0x61),
  ]) {
    assert.equal(parseUidInput(bad), null, JSON.stringify(String(bad).slice(0, 20)));
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
  assert.deepEqual(await h.run('status', undefined, { uid: 'bad' + String.fromCharCode(10) + 'uid' }), { code: 'invalid_input' });
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
  // 開始の時点で処理の元期限を過ぎていれば、SDKを作らない。
  const opened = h.calls.open;
  let calls = 0;
  const late = { now: () => (calls++ === 0 ? BASE : BASE + 30_001) };
  assert.deepEqual(await h.run('status', undefined, { deps: { clock: late } }), { code: 'timed_out' });
  assert.deepEqual(await h.run('status', undefined, { deps: { startedAt: BASE - 25_000 } }), { code: 'timed_out' });
  assert.equal(h.calls.open, opened, 'no SDK is started after the deadline');
  // 鍵の形が違えば使わない。
  assert.deepEqual(await harness({ key: randomBytes(16) }).run('status'), { code: 'unavailable' });
  // closeの失敗は固定のcleanup fieldで示し、codeは書き換えない。
  h.calls.closeFails = true;
  h.db.control.fail = true;
  assert.deepEqual(await h.run('status'), { code: 'unavailable', cleanup: 'failed' });
  h.db.control.fail = false;
  assert.deepEqual(await h.run('status'), { code: 'invalid_record', cleanup: 'failed' });
  assert.equal(h.calls.close, h.calls.open);
});

test('M6 deadline inside the transaction: a clock past the work deadline after tx.get or before an SDK retry gives timed_out with no write; the expected version and generation are not re-read', async () => {
  // tx.getの後に時計が開始+30001へ進む（PMの反例）→ timed_out・書込み0。
  {
    const h = harness();
    h.db.control.onGet = () => {
      h.time.value = BASE + 30_001;
    };
    const transactions = h.db.control.transactions;
    // 全体の元期限（開始+30秒）も過ぎているので、後始末は待たずにcloseを試みてunconfirmedと示す。
    assert.deepEqual(await h.run('grant', 'absent'), { code: 'timed_out', cleanup: 'unconfirmed' });
    assert.deepEqual([h.db.control.writes, h.db.docs.size, h.db.control.transactions - transactions], [0, 0, 1]);
    assert.equal(h.calls.close, h.calls.open, 'the SDK is still closed');
  }
  // 処理の元期限（開始+25秒）ちょうどを過ぎた時点でも同じ（全体の30秒を待たない）。
  {
    const h = harness();
    h.db.control.onGet = () => {
      h.time.value = BASE + 25_000;
    };
    assert.deepEqual(await h.run('grant', 'absent'), { code: 'timed_out' });
    assert.equal(h.db.control.writes, 0);
  }
  // SDKが閉包を再実行する前に期限を過ぎる → 再実行の開始で止まり、書込み0（期待版・世代を取り直して書かない）。
  {
    const h = harness();
    h.db.control.retryOnce = true;
    h.db.control.beforeRetry = () => {
      h.time.value = BASE + 26_000;
    };
    assert.deepEqual(await h.run('revoke', 'absent'), { code: 'timed_out' });
    assert.deepEqual([h.db.control.writes, h.db.control.attempts], [0, 2]);
  }
  // 期限内の再実行は同じ期待版・同じ世代で1件だけ書く。
  {
    const h = harness();
    h.db.control.retryOnce = true;
    const generation = randomUUID();
    assert.deepEqual(await h.run('grant', 'absent', { deps: { newGeneration: () => generation } }), { code: 'changed', state: 'active' });
    assert.deepEqual([h.db.control.writes, h.db.docs.get(h.accessPath()).data.generation], [1, generation]);
  }
  // status（読取り）も同じ検査。
  {
    const h = harness();
    h.db.control.onGet = () => {
      h.time.value = BASE + 30_001;
    };
    assert.deepEqual(await h.run('status'), { code: 'timed_out', cleanup: 'unconfirmed' });
  }
});

test('M7 bounded waits and cleanup: a slow SDK open or key is abandoned at the work deadline, the late handle is closed and the late key zeroed; a hanging close is reported as unconfirmed within the cleanup bound; a failed close keeps the confirmed DB result', async () => {
  // 遅いopen（処理の元期限まで残り20ms）→ timed_out、後から開いたSDKは採用せず閉じる。
  {
    const h = harness();
    let release;
    h.calls.openGate = new Promise((resolve) => (release = resolve));
    assert.deepEqual(await h.run('status', undefined, { deps: { startedAt: BASE - 24_980 } }), { code: 'timed_out' });
    assert.equal(h.calls.close, 0);
    release();
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(h.calls.close, 1, 'the late SDK handle is closed');
  }
  // 遅い鍵 → timed_out、後から届いた鍵Bufferは0埋め。SDKは閉じる。
  {
    const h = harness();
    h.calls.keyDelayMs = 80;
    assert.deepEqual(await h.run('status', undefined, { deps: { startedAt: BASE - 24_960 } }), { code: 'timed_out' });
    await new Promise((resolve) => setTimeout(resolve, 120));
    assert.equal(h.calls.keys.length, 1);
    assert.ok(h.calls.keys[0].every((byte) => byte === 0), 'the late key is zeroed');
    assert.equal(h.calls.close, h.calls.open);
    assert.equal(h.db.control.transactions, 0, 'no transaction after the deadline');
  }
  // 確定したchangedの後のclose失敗: changedのまま、cleanup failed（未実行へ書き換えない・再書込みしない）。
  {
    const h = harness();
    h.calls.closeMode = 'fail';
    assert.deepEqual(await h.run('grant', 'absent'), { code: 'changed', state: 'active', cleanup: 'failed' });
    assert.equal(h.db.control.writes, 1);
  }
  // 閉じ終わらないclose: 後始末の上限（最大5秒）で待つのをやめ、cleanup unconfirmed。
  {
    const h = harness();
    h.calls.closeMode = 'hang';
    const started = Date.now();
    assert.deepEqual(await h.run('status'), { code: 'status', state: 'absent', version: 'absent', cleanup: 'unconfirmed' });
    const waited = Date.now() - started;
    assert.ok(waited >= 4_900 && waited < 7_000, `bounded cleanup wait (${waited} ms)`);
  }
  // 全体の元期限を過ぎてから後始末に入る場合は待たずに閉じることを試み、unconfirmed。
  assert.match(formatAdminResult({ code: 'changed', state: 'active', cleanup: 'unconfirmed' }), /^\{"code":"changed","state":"active","cleanup":"unconfirmed"\}\n$/);
});

test('M8 CLI stdin is bounded: EOF within the limit gives the bytes, more than 1 KiB or no EOF before the deadline stops reading without waiting further and zeroes what was read', async () => {
  const { readStdin } = await import('../scripts/manage-access.mjs');
  const { PassThrough } = await import('node:stream');
  const ok = new PassThrough();
  const reading = readStdin(ok, Date.now() + 1_000);
  ok.end(`${UID}\n`);
  const got = await reading;
  assert.equal(got.kind, 'ok');
  assert.equal(parseUidInput(got.bytes), UID);
  const big = new PassThrough();
  const tooLarge = readStdin(big, Date.now() + 1_000);
  big.write(Buffer.alloc(1025, 0x61));
  assert.deepEqual(await tooLarge, { kind: 'too_large' });
  const open = new PassThrough();
  const started = Date.now();
  const chunk = Buffer.from('partial-uid');
  const waiting = readStdin(open, Date.now() + 50);
  open.write(chunk);
  assert.deepEqual(await waiting, { kind: 'timed_out' });
  assert.ok(Date.now() - started < 1_000, 'no wait for EOF beyond the deadline');
  assert.ok(open.destroyed, 'the stream is stopped');
  assert.deepEqual(await readStdin(new PassThrough(), Date.now() - 1), { kind: 'timed_out' });
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
