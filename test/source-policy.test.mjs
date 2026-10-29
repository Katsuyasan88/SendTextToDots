// 許可元の共通契約（source/contract.ts）と配置設定のsourceAuthorization。
//   - 省略は既存互換、strictは明示objectだけ。空・未知・重複の方式・未知key・文字列の'strict-v1'は設定error（互換へ降格しない）。
//   - 登録recordのexact schema（不正は自動修復せず拒否）、要求・bindingの判定（不存在/墓標/停止/期限/操作/方式/本人/世代）。
// 合成値だけ。実Cloud・資格・network 0。

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { validateDeploymentConfig } from '../dist/config/validate.js';
import {
  parseSourceAuthorization,
  parseSourceRecord,
  SourceContractError,
  sourceBindingVerdict,
  sourceRequestVerdict,
} from '../dist/source/contract.js';
import { DEPLOYMENT_CONFIG as SYNTHETIC } from './fixtures/synthetic-deployment.mjs';

const ID = 'src_abcdefghijklmnopqrstuvwxyz';
const GEN = 'AAAAAAAAAAAAAAAAAAAAAA';
const HASH = 'a'.repeat(64);
const OTHER_HASH = 'b'.repeat(64);
const KEY = 'A'.repeat(43);

const withSource = (value) => ({ ...SYNTHETIC, sourceAuthorization: value });

test('配置設定: 省略/compatibleは既存互換、strictは明示した方式だけ', () => {
  assert.equal(validateDeploymentConfig(SYNTHETIC).sourceAuthorization, 'compatible');
  assert.equal(validateDeploymentConfig(withSource('compatible')).sourceAuthorization, 'compatible');
  const strict = validateDeploymentConfig(withSource({ mode: 'strict-v1', methods: ['developer-key-v1', 'app-check-v1'] })).sourceAuthorization;
  assert.deepEqual(strict, { mode: 'strict-v1', methods: ['developer-key-v1', 'app-check-v1'] });
  assert.ok(Object.isFrozen(strict) && Object.isFrozen(strict.methods));
});

test('配置設定: strictの不備は設定errorで、互換へ降格しない', () => {
  const invalid = [
    'strict-v1',
    'off',
    null,
    { mode: 'strict-v1', methods: [] },
    { mode: 'strict-v1', methods: ['debug'] },
    { mode: 'strict-v1', methods: ['app-check-v1', 'app-check-v1'] },
    { mode: 'strict-v1' },
    { mode: 'strict-v2', methods: ['app-check-v1'] },
    { mode: 'strict-v1', methods: ['app-check-v1'], appIds: [] },
  ];
  for (const value of invalid) {
    assert.throws(() => validateDeploymentConfig(withSource(value)), { code: 'deployment_config_invalid' });
  }
  assert.throws(() => parseSourceAuthorization({ mode: 'strict-v1', methods: ['developer-key-v1', 'app-check-v1', 'developer-key-v1'] }), SourceContractError);
});

const developer = (overrides = {}) => ({
  schemaVersion: 1,
  sourceId: ID,
  kind: 'developer',
  state: 'active',
  generation: GEN,
  operations: ['send'],
  publicKey: KEY,
  identityHash: HASH,
  expiresAt: 2_000,
  createdAt: 1_000,
  updatedAt: 1_000,
  ...overrides,
});
const app = (overrides = {}) => ({
  schemaVersion: 1,
  sourceId: ID,
  kind: 'app',
  state: 'active',
  generation: GEN,
  operations: ['send', 'keys', 'connect'],
  appId: '1:123456789012:ios:0123abcd',
  createdAt: 1_000,
  updatedAt: 1_000,
  ...overrides,
});

test('登録record: exact schemaだけを受け、不正は修復せず拒否する', () => {
  assert.equal(parseSourceRecord(developer(), ID).kind, 'developer');
  assert.equal(parseSourceRecord(developer({ expiresAt: null }), ID).expiresAt, null);
  assert.equal(parseSourceRecord(app(), ID).kind, 'app');
  // 削除は物理削除で、墓標の形は保存されない（あれば不正として拒否）。
  assert.throws(() => parseSourceRecord({ schemaVersion: 1, sourceId: ID, kind: 'deleted', deletedAt: 5 }, ID), SourceContractError);
  const bad = [
    developer({ sourceId: 'src_bbbbbbbbbbbbbbbbbbbbbbbbbb' }),
    developer({ extra: 1 }),
    developer({ expiresAt: undefined }),
    developer({ expiresAt: 500 }),
    developer({ operations: [] }),
    developer({ operations: ['send', 'send'] }),
    developer({ operations: ['admin'] }),
    developer({ publicKey: 'short' }),
    developer({ identityHash: 'uid-plain' }),
    developer({ state: 'deleted' }),
    developer({ updatedAt: 999 }),
    app({ appId: 'my-app' }),
    app({ kind: 'debug' }),
    { schemaVersion: 1, sourceId: ID, kind: 'deleted', deletedAt: 5, state: 'active' },
  ];
  for (const value of bad) assert.throws(() => parseSourceRecord(value, ID), SourceContractError);
});

test('要求の判定: 不存在・墓標・停止・期限・操作外・方式違い・別本人を区別して拒否する', () => {
  const need = { method: 'developer-key-v1', operation: 'send', identityHash: HASH, now: 1_500 };
  const reason = (record, overrides = {}) => {
    const verdict = sourceRequestVerdict(record === null ? null : parseSourceRecord(record, ID), { ...need, ...overrides });
    return verdict.kind === 'usable' ? 'usable' : verdict.reason;
  };
  assert.equal(reason(developer()), 'usable');
  assert.equal(reason(null), 'missing');
  assert.equal(reason(developer({ state: 'disabled' })), 'disabled');
  assert.equal(reason(developer(), { now: 2_000 }), 'expired');
  assert.equal(reason(developer({ expiresAt: null }), { now: 9_999_999 }), 'usable');
  assert.equal(reason(developer(), { operation: 'keys' }), 'operation');
  assert.equal(reason(developer(), { method: 'app-check-v1' }), 'method');
  assert.equal(reason(app(), {}), 'method');
  assert.equal(reason(developer(), { identityHash: OTHER_HASH }), 'subject');
  assert.equal(reason(app(), { method: 'app-check-v1', identityHash: OTHER_HASH }), 'usable');
});

test('bindingの判定: 世代違い（停止後の再有効化）と墓標の旧Grantを拒否する', () => {
  const binding = { sourceId: ID, generation: GEN };
  assert.equal(sourceBindingVerdict(parseSourceRecord(app(), ID), binding, 1_500).kind, 'usable');
  const renewed = sourceBindingVerdict(parseSourceRecord(app({ generation: 'BBBBBBBBBBBBBBBBBBBBBB' }), ID), binding, 1_500);
  assert.deepEqual(renewed, { kind: 'rejected', reason: 'generation' });
  assert.deepEqual(sourceBindingVerdict(parseSourceRecord(app({ operations: ['send'] }), ID), binding, 1_500), { kind: 'rejected', reason: 'operation' });
  assert.deepEqual(sourceBindingVerdict(null, binding, 1_500), { kind: 'rejected', reason: 'missing' });
});
