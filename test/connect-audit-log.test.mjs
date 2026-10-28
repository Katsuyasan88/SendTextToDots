// 接続serverの期限付き診断ログ: 既定off・期限・上限・固定のevent/categoryだけ・失敗の非干渉。合成の値だけを使う（資格・実値なし）。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const log = await import('../dist/http/log.js');
const server = await import('../dist/connect/kms-server.js');

const T0 = Date.parse('2026-01-01T00:00:00Z');
const iso = (ms) => new Date(ms).toISOString();
function sink(until, clock = { t: T0 }) {
  const lines = [];
  const s = log.createDiagnosticLogSink({ until, now: () => clock.t, write: (line) => lines.push(line) });
  return { s, lines, clock };
}

test('diagnostics are off by default and for invalid, past, or too-long end times', () => {
  for (const until of [undefined, '', 'not-a-time', '2026-01-01T00:10:00+09:00', iso(T0 - 1000), iso(T0), iso(T0 + 30 * 60_000 + 1000), 12345]) {
    assert.equal(sink(until).s, undefined, `until=${String(until)}`);
  }
  assert.equal(log.CONNECT_DIAGNOSTICS_ENV, 'STTD_CONNECT_DIAGNOSTICS_UNTIL');
});

test('a valid end time within 30 minutes enables the sink and writes only event (and fixed category)', () => {
  const { s, lines } = sink(iso(T0 + 30 * 60_000));
  assert.equal(typeof s, 'function');
  s({ event: 'interaction.consented' });
  s({ event: 'interaction.login', category: 'anything' });
  assert.deepEqual(lines.map((l) => JSON.parse(l)), [{ event: 'interaction.consented' }, { event: 'interaction.login' }]);
});

test('the existing login, consent, refusal, deny, and disconnect events pass through', () => {
  const { s, lines } = sink(iso(T0 + 60_000));
  for (const event of ['interaction.login', 'interaction.consented', 'interaction.access_denied', 'interaction.denied', 'web.disconnected']) s({ event });
  assert.deepEqual(lines.map((l) => JSON.parse(l).event), ['interaction.login', 'interaction.consented', 'interaction.access_denied', 'interaction.denied', 'web.disconnected']);
});

test('unknown events are dropped, unknown categories become other, and no other field is written', () => {
  const { s, lines } = sink(iso(T0 + 60_000));
  s({ event: 'interaction.code', category: 'exchanged' });
  s({ event: 'http.request', route: 'x', status: 200 });
  s({ event: 'oauth.grant_revoked', category: 'Grant', uid: 'synthetic-uid', grantId: 'synthetic-grant', token: 'synthetic-token', url: 'https://example.invalid/?code=x' });
  s({ event: 'oauth.request_error', category: 'client_credentials', error: 'synthetic error text' });
  assert.deepEqual(lines.map((l) => JSON.parse(l)), [{ event: 'oauth.grant_revoked', category: 'Grant' }, { event: 'oauth.request_error', category: 'other' }]);
  assert.ok(!lines.join('\n').match(/synthetic|example\.invalid|"uid"|"grantId"|"token"|"url"|"error"|"route"|"status"/));
});

test('nothing is written after the end time, and the cap is 64 events per process', () => {
  const clock = { t: T0 };
  const { s, lines } = sink(iso(T0 + 60_000), clock);
  for (let i = 0; i < 70; i += 1) s({ event: 'interaction.login' });
  assert.equal(lines.length, log.CONNECT_DIAGNOSTICS_MAX_EVENTS);
  const late = sink(iso(T0 + 60_000), { t: T0 });
  late.clock.t = T0 + 60_000;
  late.s({ event: 'interaction.login' });
  assert.equal(late.lines.length, 0);
});

test('a failing writer or clock never throws into the caller', () => {
  let calls = 0;
  const s = log.createDiagnosticLogSink({ until: iso(T0 + 60_000), now: () => (calls++ === 0 ? T0 : (() => { throw new Error('clock'); })()), write: () => {} });
  assert.doesNotThrow(() => s({ event: 'interaction.login' }));
  const w = log.createDiagnosticLogSink({ until: iso(T0 + 60_000), now: () => T0, write: () => { throw new Error('stdout'); } });
  assert.doesNotThrow(() => w({ event: 'interaction.login' }));
  assert.equal(log.createDiagnosticLogSink({ until: iso(T0 + 60_000), now: () => { throw new Error('x'); }, write: () => {} }), undefined);
});

test('grant revocation is recorded only after a successful adapter revoke, with a fixed model category', async () => {
  const events = [];
  const order = [];
  await server.auditedRevoke('Grant', async () => { order.push('revoke'); }, (e) => { order.push('log'); events.push(e); });
  await server.auditedRevoke('Session', async () => {}, (e) => events.push(e));
  assert.deepEqual(order, ['revoke', 'log']);
  assert.deepEqual(events, [{ event: 'oauth.grant_revoked', category: 'Grant' }, { event: 'oauth.grant_revoked', category: 'other' }]);
});

test('a failed revoke propagates unchanged and records nothing; a failing log does not change a successful revoke', async () => {
  const events = [];
  const failure = new Error('synthetic revoke failure');
  await assert.rejects(server.auditedRevoke('Grant', async () => { throw failure; }, (e) => events.push(e)), (e) => e === failure);
  assert.equal(events.length, 0);
  await assert.doesNotReject(server.auditedRevoke('Grant', async () => {}, () => { throw new Error('log'); }));
});

test('token error events carry only the fixed grant_type category', () => {
  assert.equal(server.grantTypeCategory({ oidc: { params: { grant_type: 'authorization_code' } } }), 'authorization_code');
  assert.equal(server.grantTypeCategory({ oidc: { params: { grant_type: 'refresh_token' } } }), 'refresh_token');
  assert.equal(server.grantTypeCategory({ oidc: { params: { grant_type: 'urn:x' } } }), 'other');
  assert.equal(server.grantTypeCategory(undefined), 'other');
  assert.equal(server.grantTypeCategory({ get oidc() { throw new Error('x'); } }), 'other');
});

test('the connect entry reads only the diagnostics end time and passes the sink only when enabled', () => {
  const entry = readFileSync(new URL('../dist/deployment/connect.js', import.meta.url), 'utf8');
  assert.match(entry, /createDiagnosticLogSink\(/);
  assert.match(entry, /CONNECT_DIAGNOSTICS_ENV/);
  assert.match(entry, /log !== undefined \? \{ log \} : \{\}/);
  const envReads = entry.match(/process\.env\[[^\]]+\]/g) ?? [];
  assert.deepEqual(envReads.sort(), ["process.env['PORT']", 'process.env[CONNECT_DIAGNOSTICS_ENV]', 'process.env[M.web.apiKeyEnv]'].sort());
});
