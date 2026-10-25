// 安全なHTTPS送出。Nodeのhttps/tls/netの実経路を、loopbackのTLS受信機と試験専用のCA・connectorで通す。
// 実インターネットへは接続しない（製品構成の試験は、接続を始める前に拒否されるIP literalとloopbackだけを使う）。

import assert from 'node:assert/strict';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';

import { isPublicAddress } from '../dist/egress/ip-policy.js';
import { createProductEgress } from '../dist/egress/product.js';
import {
  createSafeEgress,
  EGRESS_MAX_DEADLINE_MS,
  EGRESS_MAX_RESPONSE_BYTES,
  parseEgressUrl,
} from '../dist/egress/safe-egress.js';
import { pinnedLookup, sendPinned } from '../dist/egress/transport.js';
import {
  assertEgressFailure,
  CALLBACK_HOST,
  closedPort,
  createTlsFixture,
  delay,
  fixtureConnector,
  OTHER_HOST,
  startPlainReceiver,
  startReceiver,
} from './egress-helpers.mjs';

const tls = createTlsFixture();
const URL_ = `https://${CALLBACK_HOST}/hook/abc?x=1`;
const POST = { headers: { 'content-type': 'application/json', 'webhook-id': 'msg_fixture' }, body: '{"challenge":"c-1"}' };

/** CALLBACK_HOSTを1つのloopback受信機へ向けたegress。 */
async function setup(t, { credentials = tls.good, host = '127.0.0.1', ca = tls.ca, dns, tlsOptions } = {}) {
  const receiver = await startReceiver(t, credentials, { host, tlsOptions });
  const connector = fixtureConnector({
    dns: dns ?? { [CALLBACK_HOST]: [host], [OTHER_HOST]: [host] },
    allowed: [host],
    port: receiver.port,
    // nullは「CAを指定しない」（製品と同じ、Nodeの既定の信頼）。
    ca: ca ?? undefined,
  });
  return { receiver, connector, egress: createSafeEgress(connector) };
}

const reply = (status, headers, body) => (_req, res) => {
  res.writeHead(status, headers);
  res.end(body);
};

// 試験がsetTimeoutを差し替えても動く実タイマーと、イベントループを塞ぐ同期処理。
const realSetTimeout = globalThis.setTimeout;
const realDelay = (ms) => new Promise((resolve) => realSetTimeout(resolve, ms));
const block = (ms) => {
  const until = performance.now() + ms;
  while (performance.now() < until);
};

/** 送出がhttps.requestを呼んだ回数（接続処理の開始）。呼び出しはそのまま実経路へ通す。 */
function countNetworkAttempts(t) {
  const original = https.request;
  const counter = { attempts: 0 };
  https.request = function counted(...args) {
    counter.attempts += 1;
    return original.apply(this, args);
  };
  syncBuiltinESMExports();
  t.after(() => {
    https.request = original;
    syncBuiltinESMExports();
  });
  return counter;
}

test('正: DNS名のcallbackへ、固定したIP・元hostnameのSNI/Host・許可した見出しだけでPOSTし、2xxの本文を受け取る', async (t) => {
  const { receiver, connector, egress } = await setup(t, { host: '127.0.0.2' });
  const response = await egress.postCallback(URL_, {
    headers: { 'Content-Type': 'application/json', 'webhook-id': 'msg_1', 'webhook-timestamp': '1', 'webhook-signature': 'v1,sig', 'x-mcp-subscription-id': 'sub_1' },
    body: POST.body,
  });
  assert.deepEqual(response, { status: 200, body: '{"challenge":"c-1"}' });

  assert.equal(receiver.requests.length, 1);
  const [seen] = receiver.requests;
  assert.equal(seen.method, 'POST');
  assert.equal(seen.url, '/hook/abc?x=1');
  assert.equal(seen.body, POST.body);
  assert.equal(seen.servername, CALLBACK_HOST, 'SNIは元hostname');
  assert.equal(seen.headers.host, CALLBACK_HOST, 'Hostはcanonical hostname（試験用portを含めない）');
  assert.equal(seen.localAddress, '127.0.0.2', 'fixtureのDNSが返したIPへ接続した');
  // 外へ出た見出しは、許可した5つと送出が自分で付ける4つだけ。
  assert.deepEqual(Object.keys(seen.headers).sort(), [
    'accept-encoding', 'connection', 'content-length', 'content-type', 'host',
    'webhook-id', 'webhook-signature', 'webhook-timestamp', 'x-mcp-subscription-id',
  ]);
  assert.equal(seen.headers['accept-encoding'], 'identity');
  assert.equal(seen.headers.connection, 'close');
  // 名前解決は1回だけ。.testのhostnameはOSでは解決できないので、接続時に別の解決はしていない。
  assert.deepEqual(connector.calls, [CALLBACK_HOST]);

  // GET（CIMD/JWKS用）は公開JSON用の見出しだけ。
  receiver.handle = reply(200, { 'content-type': 'application/json' }, '{"keys":[]}');
  assert.deepEqual(await egress.getJson(`https://${CALLBACK_HOST}/oauth/jwks.json`), { status: 200, body: '{"keys":[]}' });
  const got = receiver.requests[1];
  assert.equal(got.method, 'GET');
  assert.deepEqual(Object.keys(got.headers).sort(), ['accept', 'accept-encoding', 'connection', 'host']);
  assert.equal(got.headers.accept, 'application/json');
  // 接続は使い回さない。
  assert.equal(receiver.connections, 2);
});

test('対照: 同じloopback宛先は、製品の宛先ポリシーでは接続を始める前に拒否される', async (t) => {
  const { receiver, connector, egress } = await setup(t);
  assert.equal((await egress.postCallback(URL_, POST)).status, 200, '試験用ポリシーでは届く');

  // DNS・port・CAは同じまま、宛先ポリシーだけを製品のものにする。
  const guarded = createSafeEgress({ ...connector, isAllowedAddress: isPublicAddress });
  await assertEgressFailure(guarded.postCallback(URL_, POST), 'destination_forbidden');
  await assertEgressFailure(guarded.getJson(URL_), 'destination_forbidden');
  assert.equal(receiver.connections, 1, '製品ポリシーでは1本も接続しない');

  // 製品構成（引数なし）。IP literalと表記の変形は、名前解決も接続もせずに拒否される。
  const product = createProductEgress();
  assert.equal(createProductEgress.length, 0, '製品構成に差し替え口がない');
  const literals = [
    '127.0.0.1', '127.0.0.2', '127.1', '2130706433', '0x7f.0.0.1', '0177.0.0.1', '0x7f000001', '127.0.0.1.',
    '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '192.0.0.9', '192.88.99.1', '198.18.0.1', '203.0.113.5',
    '[::1]', '[::]', '[::ffff:127.0.0.1]', '[::ffff:7f00:1]', '[::127.0.0.1]', '[fe80::1]', '[fc00::1]', '[fd00::1]',
    '[64:ff9b::7f00:1]', '[2002:7f00:1::1]', '[2001:db8::1]', '[2001::1]', '[ff02::1]', '[4000::1]', '[::ffff:8.8.8.8]',
  ];
  for (const host of literals) {
    await assertEgressFailure(product.postCallback(`https://${host}/hook`, POST), 'destination_forbidden', host);
    await assertEgressFailure(product.getJson(`https://${host}:443/doc.json`), 'destination_forbidden', host);
  }
  // OSが解決するloopback名（外部への問い合わせにならない）も、全回答の検証で拒否される。
  await assertEgressFailure(product.postCallback('https://localhost/hook', POST), 'destination_forbidden');
  assert.equal(receiver.connections, 1);
});

test('URL: HTTPS・443以外、userinfo、fragment、制御文字、非正規の形は接続前にinvalid_urlで拒否する', async (t) => {
  const { receiver, connector, egress } = await setup(t);
  const invalid = [
    `http://${CALLBACK_HOST}/hook`, `ftp://${CALLBACK_HOST}/hook`, `//${CALLBACK_HOST}/hook`, `${CALLBACK_HOST}/hook`,
    `https://${CALLBACK_HOST}:8443/hook`, `https://${CALLBACK_HOST}:80/hook`, `https://${CALLBACK_HOST}:0/hook`,
    `https://${CALLBACK_HOST}:${receiver.port}/hook`,
    `https://user:pass@${CALLBACK_HOST}/hook`, `https://user@${CALLBACK_HOST}/hook`, `https://@${CALLBACK_HOST}/hook`, `https://:@${CALLBACK_HOST}/hook`,
    `https://evil.example@${CALLBACK_HOST}/hook`,
    `https://${CALLBACK_HOST}/hook#frag`, `https://${CALLBACK_HOST}/hook#`, `https://${CALLBACK_HOST}#`,
    `https://${CALLBACK_HOST}/ho ok`, ` https://${CALLBACK_HOST}/hook`, `https://${CALLBACK_HOST}/hook\n`, `https://${CALLBACK_HOST}/ho\tok`,
    `https://call\tback.sttd-fixture.test/hook`, `https://${CALLBACK_HOST}/hook\r\nx-injected: 1`, `https://${CALLBACK_HOST}/hook\u0000`, `https://${CALLBACK_HOST}/\u007f`,
    `https://${CALLBACK_HOST}\\@evil.example/hook`, `https:\\\\${CALLBACK_HOST}/hook`, `https:/${CALLBACK_HOST}/hook`, `https:${CALLBACK_HOST}/hook`,
    `https://${CALLBACK_HOST}./hook`, 'https:///hook', 'https://', 'https://[fe80::1%25eth0]/hook', 'https://[::1/hook', 'https://exa mple.test/',
    `https://${CALLBACK_HOST}/${'a'.repeat(2048)}`, '', 'not a url',
  ];
  for (const url of invalid) {
    await assertEgressFailure(egress.postCallback(url, POST), 'invalid_url', JSON.stringify(url).slice(0, 60));
    await assertEgressFailure(egress.getJson(url), 'invalid_url', JSON.stringify(url).slice(0, 60));
  }
  for (const url of [undefined, null, 42, {}, new URL(URL_)]) await assertEgressFailure(egress.getJson(url), 'invalid_url');
  assert.deepEqual(connector.calls, [], '名前解決もしていない');
  assert.equal(receiver.connections, 0);

  // 受理する形は、canonical hostnameへ正規化して使う。
  assert.deepEqual(parseEgressUrl('HTTPS://CallBack.STTD-fixture.TEST:443/a/../b?q=1'), {
    hostname: CALLBACK_HOST, hostHeader: CALLBACK_HOST, ipLiteral: false, path: '/b?q=1',
  });
  assert.deepEqual(parseEgressUrl('https://[2606:4700:0:0::1111]/x'), {
    hostname: '2606:4700::1111', hostHeader: '[2606:4700::1111]', ipLiteral: true, path: '/x',
  });
  // 整数・16進・短縮のIPv4表記は、正規化後のIPとして扱う（hostnameとして名前解決へ回さない）。
  for (const host of ['2130706433', '0x7f.0.0.1', '0177.0.0.1', '127.1']) {
    assert.deepEqual(parseEgressUrl(`https://${host}/`), { hostname: '127.0.0.1', hostHeader: '127.0.0.1', ipLiteral: true, path: '/' });
  }
  assert.equal((await egress.postCallback(`HTTPS://${CALLBACK_HOST.toUpperCase()}:443/hook`, POST)).status, 200);
  assert.equal(receiver.requests[0].headers.host, CALLBACK_HOST);
  assert.equal(receiver.requests[0].servername, CALLBACK_HOST);
});

test('DNS: 空・失敗・不正IP・混合回答を拒否し、試行ごとに再解決して、検証した1つのIPだけへ接続する', async (t) => {
  const a = await startReceiver(t, tls.good, { host: '127.0.0.2' });
  const b = await startReceiver(t, tls.good, { host: '127.0.0.3', port: a.port });
  let answers = [];
  const connector = fixtureConnector({
    dns: (hostname) => (hostname === CALLBACK_HOST ? answers : undefined),
    allowed: ['127.0.0.2', '127.0.0.3'],
    port: a.port,
    ca: tls.ca,
  });
  const egress = createSafeEgress(connector);
  const send = () => egress.postCallback(URL_, POST);

  answers = [];
  await assertEgressFailure(send(), 'dns_failed', '空回答');
  await assertEgressFailure(egress.postCallback(`https://${OTHER_HOST}/hook`, POST), 'dns_failed', '解決の失敗');
  for (const bad of [
    ['127.0.0.2', '10.0.0.5'],
    ['10.0.0.5', '127.0.0.2'],
    ['127.0.0.2', '8.8.8.8'],
    ['127.0.0.2', '::1'],
    ['127.0.0.2', '::ffff:127.0.0.2'],
    ['127.0.0.2', 'fe80::1%eth0'],
    ['127.0.0.2', 'not-an-ip'],
    ['127.0.0.2', ''],
    ['127.0.0.2', '127.0.0.3.'],
    ['127.0.0.2', { address: undefined, family: 4 }],
    ['127.0.0.2', null],
    ['0x7f.0.0.2'],
    ['2130706434'],
  ]) {
    answers = bad;
    await assertEgressFailure(send(), 'destination_forbidden', `混合・不正な回答 ${JSON.stringify(bad)}`);
  }
  assert.equal(a.connections + b.connections, 0, '許可IPを含む回答でも、一つでも禁止・不正なら接続しない');

  // 選択: 全回答が許可IPなら、最初のIPv4だけへ接続する（別の回答へは接続しない）。
  answers = ['127.0.0.3', '127.0.0.2'];
  assert.equal((await send()).status, 200);
  assert.deepEqual([a.connections, b.connections], [0, 1]);
  assert.equal(b.requests[0].localAddress, '127.0.0.3');

  // rebinding: 試行ごとに解決し直し、前回の許可を持ち越さない。接続中に解決し直すこともしない。
  const before = connector.calls.length;
  answers = ['127.0.0.2'];
  assert.equal((await send()).status, 200);
  assert.deepEqual([a.connections, b.connections], [1, 1]);
  answers = ['169.254.169.254'];
  await assertEgressFailure(send(), 'destination_forbidden', '2回目の解決が禁止IP');
  answers = ['127.0.0.2', '192.168.0.10'];
  await assertEgressFailure(send(), 'destination_forbidden', '2回目の解決が混合');
  assert.deepEqual([a.connections, b.connections], [1, 1]);
  assert.equal(connector.calls.length - before, 3, '1試行につき解決は1回');

  // 解決の例外の内容（hostnameを含む）は、エラーへ出ない。
  const failure = await assertEgressFailure(egress.getJson(`https://secret-host.sttd-fixture.test/doc`), 'dns_failed');
  assert.ok(!`${failure.stack}`.includes('secret-host'));
});

test('接続先の照合: 接続したIPが選択したIPと違えば、要求を流さずに破棄する', async (t) => {
  const pinned = await startReceiver(t, tls.good, { host: '127.0.0.2' });
  const elsewhere = await startReceiver(t, tls.good, { host: '127.0.0.3', port: pinned.port });
  const pin = { address: '127.0.0.2', family: 4 };
  const request = (lookup) => ({
    method: 'POST', hostname: CALLBACK_HOST, hostHeader: CALLBACK_HOST, ipLiteral: false, path: '/hook',
    headers: POST.headers, body: POST.body, pin, lookup, port: pinned.port, ca: tls.ca, maxResponseBytes: EGRESS_MAX_RESPONSE_BYTES,
  });
  const never = new AbortController().signal;

  // 正: pinどおりのlookupなら届く。
  assert.equal((await sendPinned(request(pinnedLookup(pin)), never)).status, 200);
  assert.equal(pinned.requests.length, 1);

  // 負: lookupが別のIP（証明書もhostnameも正しい受信機）を返した場合。TLSは成立し得るが、要求は届かない。
  await assertEgressFailure(sendPinned(request(pinnedLookup({ address: '127.0.0.3', family: 4 })), never), 'connect_failed');
  await delay(50);
  assert.equal(elsewhere.connections, 1, '別のIPへ実際に接続が起きた');
  assert.equal(elsewhere.requests.length, 0, 'HTTP要求は流れていない');
  assert.equal(elsewhere.closed, 1, 'socketは破棄された');

  // pinnedLookupは、単一・all指定のどちらでもpinだけを返す。
  const single = await new Promise((resolve) => pinnedLookup(pin)('ignored.example', {}, (...args) => resolve(args)));
  assert.deepEqual(single, [null, '127.0.0.2', 4]);
  const all = await new Promise((resolve) => pinnedLookup(pin)('ignored.example', { all: true }, (...args) => resolve(args)));
  assert.deepEqual(all, [null, [{ address: '127.0.0.2', family: 4 }]]);
});

test('TLS: hostname不一致・未信頼CA・期限切れ・IP証明書の不一致・平文の相手はtls_failedで、HTTP要求を流さない', async (t) => {
  // 正: IP literalは、IPのSANを持つ証明書と照合する（SNIなし）。
  const ipSite = await setup(t, { credentials: tls.ip });
  assert.equal((await ipSite.egress.postCallback('https://127.0.0.1/hook', POST)).status, 200);
  assert.equal(ipSite.receiver.requests[0].servername, false, 'IP literalではSNIを送らない');
  assert.equal(ipSite.receiver.requests[0].headers.host, '127.0.0.1');
  assert.deepEqual(ipSite.connector.calls, [], 'IP literalは名前解決しない');
  // 同じ証明書でも、DNS名としては照合に通らない。
  await assertEgressFailure(ipSite.egress.postCallback(URL_, POST), 'tls_failed', 'DNS名に対するIPだけの証明書');

  const cases = [
    { label: 'SANにないhostname', site: await setup(t), url: `https://${OTHER_HOST}/hook` },
    { label: 'IP literalに対するDNS名だけの証明書', site: await setup(t), url: 'https://127.0.0.1/hook' },
    { label: '信頼していないCA', site: await setup(t, { credentials: tls.untrusted }), url: URL_ },
    { label: '期限切れ', site: await setup(t, { credentials: tls.expired }), url: URL_ },
    // 製品と同じくCAを指定しない（Nodeの既定の信頼）と、試験専用CAの証明書は通らない。
    { label: '既定の信頼では試験CAを信頼しない', site: await setup(t, { ca: null }), url: URL_ },
  ];
  for (const { label, site, url } of cases) {
    await assertEgressFailure(site.egress.postCallback(url, POST), 'tls_failed', label);
    await assertEgressFailure(site.egress.getJson(url), 'tls_failed', label);
    assert.equal(site.receiver.connections, 2, `${label}: 接続は起きた`);
    assert.equal(site.receiver.requests.length, 0, `${label}: HTTP要求は流れていない`);
    await delay(50);
    assert.equal(site.receiver.closed, 2, `${label}: 送出側がsocketを破棄した`);
  }

  const plain = await startPlainReceiver(t);
  const toPlain = createSafeEgress(fixtureConnector({ dns: { [CALLBACK_HOST]: ['127.0.0.1'] }, port: plain.port, ca: tls.ca }));
  await assertEgressFailure(toPlain.postCallback(URL_, POST), 'tls_failed', 'TLSを話さない相手');
  assert.equal(plain.connections, 1);

  // 誰もlistenしていないportは、接続の失敗。
  const nowhere = createSafeEgress(fixtureConnector({ dns: { [CALLBACK_HOST]: ['127.0.0.1'] }, port: await closedPort(), ca: tls.ca }));
  await assertEgressFailure(nowhere.postCallback(URL_, POST), 'connect_failed', '接続拒否');
});

test('絶対期限: DNS・接続・応答待ち・本文読取りの合計で打ち切り、期限後のDNS完了では接続を始めない', async (t) => {
  let dnsDelay = 0;
  const { receiver, egress } = await setup(t, {
    dns: async () => {
      await delay(dnsDelay);
      return ['127.0.0.1'];
    },
  });
  const timed = async (promise, kind, label) => {
    const started = performance.now();
    await assertEgressFailure(promise, kind, label);
    return performance.now() - started;
  };

  // 期限の後に名前解決が終わっても、接続を始めない。
  dnsDelay = 250;
  const dnsOnly = await timed(egress.postCallback(URL_, POST, { timeoutMs: 80 }), 'timeout', 'DNSが期限を超える');
  assert.ok(dnsOnly >= 70 && dnsOnly < 220, `期限で返る: ${dnsOnly}`);
  await delay(300);
  assert.equal(receiver.connections, 0, '期限後のDNS完了で接続していない');

  // 各段階は期限より短いが、合計が期限を超える（段階ごとのtimeoutではない）。
  dnsDelay = 120;
  receiver.handle = (_req, res) => setTimeout(() => reply(200, {}, '{}')(null, res), 120);
  const sum = await timed(egress.postCallback(URL_, POST, { timeoutMs: 200 }), 'timeout', 'DNS＋応答待ちの合計');
  assert.ok(sum >= 190 && sum < 400, `合計の期限で返る: ${sum}`);
  // 正の対照: 同じ遅延でも、期限が合計より長ければ届く。
  assert.equal((await egress.postCallback(URL_, POST, { timeoutMs: 2000 })).status, 200);

  // 本文が途切れずに少しずつ届き続ける相手（inactivity timeoutでは止まらない）も、絶対期限で打ち切る。
  dnsDelay = 0;
  let dripping;
  receiver.handle = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    dripping = setInterval(() => res.write(' '), 20);
    res.on('close', () => clearInterval(dripping));
  };
  await delay(50);
  const closedBefore = receiver.closed;
  const drip = await timed(egress.postCallback(URL_, POST, { timeoutMs: 200 }), 'timeout', '本文が届き続ける');
  assert.ok(drip >= 190 && drip < 400, `絶対期限で返る: ${drip}`);
  await delay(50);
  assert.equal(receiver.closed, closedBefore + 1, '期限でsocketを破棄した');

  // 応答しない相手。
  receiver.handle = () => {};
  await timed(egress.getJson(URL_, { timeoutMs: 100 }), 'timeout', '応答なし');
  await delay(50);
  assert.equal(receiver.closed, receiver.connections, '残っている接続はない');
});

test('絶対期限の上限は10秒: 省略・長い指定・不正な指定のどれでも10秒で打ち切る', async (t) => {
  const { egress } = await setup(t, { dns: () => new Promise(() => {}) });
  assert.equal(EGRESS_MAX_DEADLINE_MS, 10_000);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const timeoutMs of [undefined, 60_000, Number.MAX_SAFE_INTEGER, Infinity, Number.NaN, -1, '5']) {
    let outcome = 'pending';
    const pending = egress.postCallback(URL_, POST, { timeoutMs }).catch((error) => (outcome = error.kind));
    await Promise.resolve();
    t.mock.timers.tick(9_999);
    await Promise.resolve();
    assert.equal(outcome, 'pending', `${timeoutMs}: 10秒の直前はまだ打ち切らない`);
    t.mock.timers.tick(1);
    await pending;
    assert.equal(outcome, 'timeout', `${timeoutMs}: 10秒で打ち切る`);
  }
  // 呼び出し元の短い期限は、そのまま使う。
  let outcome = 'pending';
  const pending = egress.postCallback(URL_, POST, { timeoutMs: 1_000 }).catch((error) => (outcome = error.kind));
  t.mock.timers.tick(999);
  await Promise.resolve();
  assert.equal(outcome, 'pending');
  t.mock.timers.tick(1);
  await pending;
  assert.equal(outcome, 'timeout');
});

test('絶対期限: 同期処理・イベントループ遅延でタイマーが遅れても、期限後のDNS完了と0期限では接続処理を呼ばない', async (t) => {
  const network = countNetworkAttempts(t);
  let dns = async () => ['127.0.0.1'];
  const { receiver, connector, egress } = await setup(t, { dns: () => dns() });

  // 正の対照: 短い正の期限内なら、同じ経路で届く。
  assert.equal((await egress.postCallback(URL_, POST, { timeoutMs: 1_000 })).status, 200);
  assert.deepEqual([network.attempts, receiver.connections], [1, 1]);

  // 名前解決の中の同期処理が期限を超える。タイマーのcallbackはまだ実行されていない。
  dns = async () => {
    block(80);
    return ['127.0.0.1'];
  };
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 20 }), 'timeout', '同期処理で期限を超えたDNS');
  await assertEgressFailure(egress.getJson(URL_, { timeoutMs: 20 }), 'timeout', '同期処理で期限を超えたDNS（GET）');
  assert.equal(network.attempts, 1, '期限後のDNS完了で接続処理を呼んでいない');

  // イベントループが塞がり、名前解決の完了（5ms）が期限（30ms）のタイマーより先に、期限後にまとめて処理される。
  dns = async () => {
    await realDelay(5);
    return ['127.0.0.1'];
  };
  const delayed = egress.postCallback(URL_, POST, { timeoutMs: 30 });
  setImmediate(() => block(120));
  await assertEgressFailure(delayed, 'timeout', 'イベントループ遅延で期限を超えたDNS');
  assert.equal(network.attempts, 1);

  // 0期限: 名前解決も接続も始めない。IP literal（名前解決なし）でも同じ。
  dns = async () => ['127.0.0.1'];
  const resolved = connector.calls.length;
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 0 }), 'timeout', '0期限');
  await assertEgressFailure(egress.getJson(URL_, { timeoutMs: 0 }), 'timeout', '0期限（GET）');
  await assertEgressFailure(egress.postCallback('https://127.0.0.1/hook', POST, { timeoutMs: 0 }), 'timeout', '0期限のIP literal');
  assert.equal(connector.calls.length, resolved, '0期限では名前解決を呼ばない');
  assert.equal(network.attempts, 1, '0期限では接続処理を呼ばない');
  // 経過時間が0のまま（時計が進まない間）でも、0期限は開始時点で期限切れ。
  const frozen = t.mock.method(performance, 'now', () => 1_000);
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 0 }), 'timeout', '経過0の0期限');
  frozen.mock.restore();
  assert.equal(connector.calls.length, resolved, '経過0の0期限でも名前解決を呼ばない');
  assert.equal(network.attempts, 1);
  // 0期限でも、URLの拒否と開始前の中断の分類は変わらない。
  await assertEgressFailure(egress.postCallback(`http://${CALLBACK_HOST}/hook`, POST, { timeoutMs: 0 }), 'invalid_url');
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 0, signal: AbortSignal.abort() }), 'aborted');

  // 応答を返す側の同期処理で期限を超えた場合も、成功にしない。
  receiver.handle = (_req, res) => {
    block(150);
    reply(200, {}, '{}')(null, res);
  };
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 60 }), 'timeout', '同期処理で期限を超えた応答');
  receiver.handle = null;

  await delay(100);
  assert.deepEqual([network.attempts, receiver.connections], [2, 2], '期限切れの要求のうち接続したのは、応答待ちの1件だけ');
  assert.equal(receiver.closed, receiver.connections, '残っている接続はない');

  // 通常の要求は、期限切れの後も接続できる。
  assert.equal((await egress.postCallback(URL_, POST, { timeoutMs: 1_000 })).status, 200);
  assert.deepEqual([network.attempts, receiver.connections], [3, 3]);
});

test('絶対期限: 期限のタイマーが一度も実行されなくても、期限後のDNS・TLS・応答の完了を成功にしない', async (t) => {
  const network = countNetworkAttempts(t);
  let dnsDelay = 0;
  let sniDelay = 0;
  const { receiver, egress } = await setup(t, {
    dns: async () => {
      await realDelay(dnsDelay);
      return ['127.0.0.1'];
    },
    // 受信機側でTLS handshakeの完了を遅らせる（ctxなしは受信機の既定の証明書）。
    tlsOptions: { SNICallback: (_servername, done) => realSetTimeout(() => done(null), sniDelay) },
  });
  // 期限のsetTimeoutを止める。以降、送出が期限を知る手段は経過時間の判定だけになる。
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const send = (timeoutMs) => egress.postCallback(URL_, POST, { timeoutMs });

  // 正の対照: 期限内なら、同じ遅延の入った経路で届く。
  dnsDelay = 20;
  sniDelay = 20;
  receiver.handle = (_req, res) => realSetTimeout(() => reply(200, {}, '{"challenge":"c-1"}')(null, res), 20);
  assert.deepEqual(await send(3_000), { status: 200, body: '{"challenge":"c-1"}' });
  assert.deepEqual([network.attempts, receiver.requests.length], [1, 1]);

  // 期限後のDNS完了: 接続処理を呼ばない。
  dnsDelay = 400;
  await assertEgressFailure(send(100), 'timeout', '期限後のDNS完了');
  assert.deepEqual([network.attempts, receiver.connections], [1, 1]);
  // 壁時計が開始より前へ戻っても、期限は延びない。
  const rewound = Date.now() - 3_600_000;
  const wallClock = t.mock.method(Date, 'now', () => rewound);
  await assertEgressFailure(send(100), 'timeout', '壁時計を戻した期限後のDNS完了');
  wallClock.mock.restore();
  assert.deepEqual([network.attempts, receiver.connections], [1, 1]);

  // 期限後のTLS成立: 接続は始まっているが、HTTP要求を流さずに破棄する。
  dnsDelay = 0;
  sniDelay = 500;
  await assertEgressFailure(send(150), 'timeout', '期限後のTLS成立');
  await realDelay(100);
  assert.deepEqual([network.attempts, receiver.connections], [2, 2]);
  assert.equal(receiver.requests.length, 1, '期限後に成立したTLSへ要求を流していない');
  assert.equal(receiver.closed, receiver.connections, '期限後のTLSでsocketを破棄した');

  // 期限後の応答完了: 2xx、本文の末尾だけが期限後、4xx/5xxのどれも成功として返さない。
  sniDelay = 0;
  const late = [
    ['2xx', (_req, res) => realSetTimeout(() => reply(200, {}, '{"challenge":"c-1"}')(null, res), 500)],
    ['本文の末尾', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.write('{"challenge":');
      realSetTimeout(() => res.end('"c-1"}'), 500);
    }],
    ['5xx', (_req, res) => realSetTimeout(() => reply(503, {}, '')(null, res), 500)],
  ];
  for (const [label, handle] of late) {
    receiver.handle = handle;
    const seen = receiver.requests.length;
    await assertEgressFailure(send(200), 'timeout', `期限後の応答完了（${label}）`);
    assert.equal(receiver.requests.length, seen + 1, `${label}: 要求は期限内に届いていた`);
  }
  await realDelay(100);
  assert.equal(receiver.closed, receiver.connections, '残っている接続はない');
  assert.equal(network.attempts, receiver.connections);
});

test('中断: 呼び出し元のAbortSignalで、開始前は何もせず、名前解決中・応答待ち中はsocketを破棄して打ち切る', async (t) => {
  let dnsDelay = 0;
  const { receiver, connector, egress } = await setup(t, {
    dns: async () => {
      await delay(dnsDelay);
      return ['127.0.0.1'];
    },
  });

  await assertEgressFailure(egress.postCallback(URL_, POST, { signal: AbortSignal.abort() }), 'aborted', '開始前に中断済み');
  assert.deepEqual(connector.calls, [], '名前解決もしない');

  dnsDelay = 150;
  const duringDns = new AbortController();
  setTimeout(() => duringDns.abort(), 30);
  await assertEgressFailure(egress.postCallback(URL_, POST, { signal: duringDns.signal }), 'aborted', '名前解決中');
  await delay(250);
  assert.equal(receiver.connections, 0, '中断後のDNS完了で接続していない');

  dnsDelay = 0;
  receiver.handle = () => {};
  const duringWait = new AbortController();
  const started = performance.now();
  const pending = egress.postCallback(URL_, POST, { signal: duringWait.signal, timeoutMs: 5_000 });
  for (let waited = 0; receiver.requests.length === 0 && waited < 400; waited += 1) await delay(5);
  assert.equal(receiver.requests.length, 1, '要求は受信機へ届いている');
  duringWait.abort();
  await assertEgressFailure(pending, 'aborted', '応答待ち中');
  assert.ok(performance.now() - started < 2_000, '期限を待たずに返る');
  await delay(50);
  assert.equal(receiver.closed, receiver.connections, 'socketを破棄した');
});

test('応答: redirectは追わず、圧縮と8192バイト超を拒否し、4xx/5xxはstatusだけを返す', async (t) => {
  const { receiver, egress } = await setup(t);
  const elsewhere = await startReceiver(t, tls.good, { host: '127.0.0.2' });
  const send = () => egress.postCallback(URL_, POST);
  assert.equal(EGRESS_MAX_RESPONSE_BYTES, 8192);

  for (const status of [300, 301, 302, 303, 307, 308, 399]) {
    for (const location of [`https://${CALLBACK_HOST}/next`, `https://127.0.0.2:${elsewhere.port}/next`, '/next', 'http://169.254.169.254/latest']) {
      receiver.handle = reply(status, { location }, '{"challenge":"c-1"}');
      await assertEgressFailure(send(), 'redirect', `${status} → ${location}`);
    }
    receiver.handle = reply(status, {}, '');
    await assertEgressFailure(egress.getJson(URL_), 'redirect', `${status}（GET）`);
  }
  assert.equal(elsewhere.connections, 0, 'Locationの先へ接続していない');
  assert.equal(receiver.requests.length, receiver.connections, '1要求1接続で、追加の要求をしていない');
  assert.ok(receiver.requests.every((seen) => seen.url === '/hook/abc?x=1'), '同じ受信機の/nextも追っていない');

  // 4xx/5xxは、本文を読まずにstatusだけを返す（分類は呼び出し側）。
  for (const status of [400, 401, 403, 404, 410, 429, 499, 500, 502, 503, 599]) {
    receiver.handle = reply(status, { 'content-type': 'application/json' }, '{"challenge":"c-1","detail":"x"}');
    assert.deepEqual(await send(), { status, body: '' }, String(status));
  }

  // 上限ちょうどは受け取る。1バイト超は、Content-Lengthの有無・正否に関わらず拒否する。
  const exact = 'x'.repeat(8192);
  receiver.handle = reply(200, { 'content-length': '8192' }, exact);
  assert.equal((await send()).body, exact);
  receiver.handle = reply(200, {}, exact);
  assert.equal((await send()).body.length, 8192, 'chunkedで上限ちょうど');
  const over = 'x'.repeat(8193);
  receiver.handle = reply(200, { 'content-length': '8193' }, over);
  await assertEgressFailure(send(), 'response_too_large', 'Content-Lengthで上限超');
  receiver.handle = reply(200, {}, over);
  await assertEgressFailure(send(), 'response_too_large', 'chunkedで上限超');
  // 終わらない本文は、上限で読むのをやめて破棄する（期限を待たない）。
  let pump;
  receiver.handle = (_req, res) => {
    res.writeHead(200, {});
    pump = setInterval(() => res.write('y'.repeat(4096)), 1);
    res.on('close', () => clearInterval(pump));
  };
  const started = performance.now();
  await assertEgressFailure(egress.postCallback(URL_, POST, { timeoutMs: 5_000 }), 'response_too_large', '終わらない本文');
  assert.ok(performance.now() - started < 2_000);

  // 圧縮: 展開すれば小さく正しい本文でも受け取らない。
  const small = gzipSync('{"challenge":"c-1"}');
  const bomb = gzipSync(Buffer.alloc(1024 * 1024));
  assert.ok(bomb.length < 8192, '圧縮後は上限内に収まる');
  for (const [encoding, payload] of [['gzip', small], ['gzip', bomb], ['br', small], ['deflate', small], ['zstd', small], ['identity, gzip', small], ['GZIP', small]]) {
    receiver.handle = reply(200, { 'content-encoding': encoding, 'content-length': String(payload.length) }, payload);
    await assertEgressFailure(send(), 'compressed_response', `content-encoding: ${encoding}`);
  }
  receiver.handle = reply(200, { 'content-encoding': 'identity' }, '{"challenge":"c-1"}');
  assert.equal((await send()).body, '{"challenge":"c-1"}', 'identityは圧縮ではない');
  assert.ok(receiver.requests.every((seen) => seen.headers['accept-encoding'] === 'identity'), '圧縮を要求していない');

  // 本文の途中で切れた応答は、成功にしない。
  receiver.handle = (_req, res) => {
    res.writeHead(200, { 'content-length': '100' });
    res.write('{"challenge":');
    setTimeout(() => res.destroy(), 20);
  };
  await assertEgressFailure(send(), 'protocol_error', '途中で切れた本文');
  await delay(50);
  assert.equal(receiver.closed, receiver.connections, '接続を残していない');
});

test('非転送と非露出: 許可していない見出しは送らずに拒否し、エラーにURL・IP・本文・元例外を含めない', async (t) => {
  const { receiver, connector, egress } = await setup(t);
  const secret = 'whsec_c2VjcmV0LXZhbHVlLWZvci10ZXN0LW9ubHk=';
  for (const name of ['authorization', 'Authorization', 'cookie', 'set-cookie', 'x-forwarded-for', 'x-api-key', 'host', 'accept-encoding', 'content-length', 'transfer-encoding', 'proxy-authorization', 'x-sttd-installation-token']) {
    await assertEgressFailure(
      egress.postCallback(URL_, { headers: { ...POST.headers, [name]: `Bearer ${secret}` }, body: POST.body }),
      'invalid_request',
      name,
    );
  }
  await assertEgressFailure(egress.postCallback(URL_, { headers: { 'webhook-id': 42 }, body: POST.body }), 'invalid_request');
  await assertEgressFailure(egress.postCallback(URL_, { headers: POST.headers, body: { challenge: 'x' } }), 'invalid_request');
  await assertEgressFailure(egress.postCallback(URL_, { headers: { 'webhook-id': 'a\r\nx-injected: 1' }, body: POST.body }), 'invalid_request', '見出しの改行');
  assert.deepEqual(connector.calls, []);
  assert.equal(receiver.connections, 0);
  // getJsonは見出しを受け取る引数を持たない。optionsへ紛れ込ませても送らない。
  await egress.getJson(URL_, { headers: { authorization: `Bearer ${secret}` }, timeoutMs: 2_000 }).catch(() => {});
  assert.equal(receiver.requests[0].headers.authorization, undefined);
  assert.ok(!receiver.requests[0].rawHeaders.join('\n').includes(secret));

  // どの失敗でも、エラーの内容は固定の分類名だけ。
  const marker = 'marker-7f3a9c';
  const sensitiveUrl = `https://${CALLBACK_HOST}/hook/${marker}?token=${marker}`;
  const failures = [];
  receiver.handle = reply(302, { location: `https://${marker}.example/` }, marker);
  failures.push(await assertEgressFailure(egress.postCallback(sensitiveUrl, { headers: { 'webhook-signature': `v1,${marker}` }, body: marker }), 'redirect'));
  receiver.handle = reply(200, {}, marker.repeat(1000));
  failures.push(await assertEgressFailure(egress.postCallback(sensitiveUrl, POST), 'response_too_large'));
  failures.push(await assertEgressFailure(egress.postCallback(`https://${OTHER_HOST}/${marker}`, POST), 'tls_failed'));
  failures.push(await assertEgressFailure(egress.postCallback(`https://user:${marker}@${CALLBACK_HOST}/`, POST), 'invalid_url'));
  const throwing = createSafeEgress({
    ...connector,
    resolve: async () => {
      throw new Error(`resolver failed for ${marker} at 10.1.2.3`);
    },
  });
  failures.push(await assertEgressFailure(throwing.postCallback(sensitiveUrl, POST), 'dns_failed'));
  const broken = createSafeEgress({
    ...connector,
    isAllowedAddress: () => {
      throw new Error(`policy crashed on ${marker}`);
    },
  });
  failures.push(await assertEgressFailure(broken.postCallback(sensitiveUrl, POST), 'protocol_error', '未知の例外は固定分類へ閉じる'));
  for (const failure of failures) {
    const rendered = [failure.message, failure.stack, JSON.stringify(failure), String(failure), Object.getOwnPropertyNames(failure).join()].join('\n');
    for (const leaked of [marker, CALLBACK_HOST, OTHER_HOST, '127.0.0.1', '10.1.2.3', String(receiver.port)]) {
      assert.ok(!rendered.includes(leaked), `${failure.kind}: エラーに${leaked}が現れた`);
    }
  }
});

test('fixtureの後始末: 証明書と秘密鍵の一時ディレクトリは生成直後に削除されている', () => {
  assert.equal(tls.tempDirGone(), true);
  for (const name of ['good', 'ip', 'untrusted', 'expired']) assert.match(tls[name].key, /PRIVATE KEY/);
});
