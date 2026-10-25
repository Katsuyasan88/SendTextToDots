// 宛先IPの固定分類表。references/に保存したIANAの3表と実装の表を照合し、全登録範囲の
// 両端とその外側を、表から独立に計算した期待値（BigInt）と比べる。実行中に表を取得しない。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  IPV4_MULTICAST,
  IPV4_SPECIAL_PURPOSE,
  IPV6_GLOBAL_UNICAST,
  IPV6_SPECIAL_PURPOSE,
  isPublicAddress,
  parseIp,
  sameAddress,
} from '../dist/egress/ip-policy.js';

// references/README.md に記録された、LF正規化後のSHA256（取得日2026-10-06）。
const REFERENCES = {
  ipv4Special: { file: 'iana_ipv4_special_20261006.csv', sha256: 'E4A1C06ECF8E934ED5AE30977A1477A78957DA1A5FB602FC855E3F74BF01C8AC' },
  ipv6Special: { file: 'iana_ipv6_special_20261006.csv', sha256: '8B0E181A4EF0C71FCB25403C40702F2050C2F6DC198156B6EC1A5FB746C9A73E' },
  ipv6Space: { file: 'iana_ipv6_space_20261006.csv', sha256: '1FA475923CE071391AB47484DE4184A0D0ABEEF376822A4711BAF75C9FE23A3B' },
};

function readReference({ file }) {
  return readFileSync(new URL(`../references/${file}`, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
}

/** 引用符内の改行とカンマを保つ最小のCSV読み取り。 */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') {
      row.push(cell);
      cell = '';
    } else if (char === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else cell += char;
  }
  if (cell !== '' || row.length > 0) rows.push([...row, cell]);
  return rows;
}

/** 1セルに複数の範囲や脚注（[2]等）があっても、CIDRをすべて取り出す。 */
const cidrsIn = (cell) => cell.match(/[0-9a-fA-F:.]+\/\d+/g) ?? [];

function table(reference) {
  const [header, ...rows] = parseCsv(readReference(reference));
  return rows.map((row) => Object.fromEntries(header.map((name, index) => [name, row[index]])));
}

// 実装のparseIpを使わない、独立したアドレス計算。
function toBigInt(address) {
  if (!address.includes(':')) {
    return { bits: 32, value: address.split('.').reduce((sum, part) => (sum << 8n) | BigInt(part), 0n) };
  }
  const [head, tail] = address.split('::');
  const groups = (part) => (part ? part.split(':') : []);
  const left = groups(head);
  const right = tail === undefined ? [] : groups(tail);
  const middle = tail === undefined ? [] : new Array(8 - left.length - right.length).fill('0');
  const value = [...left, ...middle, ...right].reduce((sum, group) => (sum << 16n) | BigInt(`0x${group}`), 0n);
  return { bits: 128, value };
}

function fromBigInt(value, bits) {
  if (bits === 32) return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 0xffn)).join('.');
  const groups = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(((value >> shift) & 0xffffn).toString(16));
  return groups.join(':');
}

function rangeOf(cidr) {
  const [address, length] = cidr.split('/');
  const { bits, value } = toBigInt(address);
  const size = 1n << BigInt(bits - Number(length));
  const first = (value / size) * size;
  return { bits, first, last: first + size - 1n, max: (1n << BigInt(bits)) - 1n };
}

const inAny = (value, ranges) => ranges.some((range) => value >= range.first && value <= range.last);

/** 範囲の最初・最後と、その1つ外側（アドレス空間の端を除く）。 */
function boundaries(range) {
  const points = [range.first, range.last];
  if (range.first > 0n) points.push(range.first - 1n);
  if (range.last < range.max) points.push(range.last + 1n);
  return points;
}

test('保存したIANA表は記録されたSHA256と一致し、実装の固定表は表の全範囲と一致する', () => {
  for (const reference of Object.values(REFERENCES)) {
    const digest = createHash('sha256').update(readReference(reference), 'utf8').digest('hex').toUpperCase();
    assert.equal(digest, reference.sha256, reference.file);
  }
  const v4 = table(REFERENCES.ipv4Special).flatMap((row) => cidrsIn(row['Address Block']));
  const v6 = table(REFERENCES.ipv6Special).flatMap((row) => cidrsIn(row['Address Block']));
  // 1セルに2範囲ある行（192.0.0.170/32, 192.0.0.171/32）と脚注付きの行を取りこぼしていない。
  assert.equal(v4.length, 26);
  assert.equal(v6.length, 25);
  assert.ok(v4.includes('192.0.0.171/32') && v4.includes('192.0.0.0/24') && v6.includes('2002::/16'));
  assert.deepEqual([...IPV4_SPECIAL_PURPOSE].sort(), [...v4].sort());
  assert.deepEqual([...IPV6_SPECIAL_PURPOSE].sort(), [...v6].sort());

  // IPv6割当空間でGlobal Unicastは2000::/3だけ。
  const space = table(REFERENCES.ipv6Space);
  assert.equal(space.length, 20);
  assert.deepEqual(space.filter((row) => row.Allocation === 'Global Unicast').map((row) => row['IPv6 Prefix']), [IPV6_GLOBAL_UNICAST]);
  assert.equal(IPV4_MULTICAST, '224.0.0.0/4');
});

test('IPv4: 特殊用途の全範囲とmulticastの両端を拒否し、範囲のすぐ外側は表から独立に計算した期待値どおり', () => {
  const cidrs = [...table(REFERENCES.ipv4Special).flatMap((row) => cidrsIn(row['Address Block'])), '224.0.0.0/4'];
  const ranges = cidrs.map(rangeOf);
  let allowed = 0;
  let refused = 0;
  for (const [index, range] of ranges.entries()) {
    assert.equal(isPublicAddress(fromBigInt(range.first, 32)), false, `${cidrs[index]} の先頭`);
    assert.equal(isPublicAddress(fromBigInt(range.last, 32)), false, `${cidrs[index]} の末尾`);
    for (const point of boundaries(range)) {
      const address = fromBigInt(point, 32);
      const expected = !inAny(point, ranges);
      assert.equal(isPublicAddress(address), expected, `${cidrs[index]} の境界 ${address}`);
      if (expected) allowed += 1;
      else refused += 1;
    }
  }
  // 外側が公開IPになる境界（例: 9.255.255.255、11.0.0.0）と、別の範囲に入る境界の両方を通っている。
  assert.ok(allowed >= 25 && refused >= 52, `allowed=${allowed} refused=${refused}`);

  const explicit = {
    '9.255.255.255': true, '10.0.0.0': false, '10.255.255.255': false, '11.0.0.0': true,
    '100.63.255.255': true, '100.64.0.0': false, '100.127.255.255': false, '100.128.0.0': true,
    '126.255.255.255': true, '127.0.0.1': false, '127.255.255.255': false, '128.0.0.0': true,
    '169.253.255.255': true, '169.254.169.254': false, '169.255.0.0': true,
    '172.15.255.255': true, '172.16.0.0': false, '172.31.255.255': false, '172.32.0.0': true,
    '191.255.255.255': true, '192.0.0.0': false, '192.0.0.255': false, '192.0.1.0': true,
    '192.0.2.0': false, '192.0.3.0': true, '192.88.98.255': true, '192.88.99.0': false, '192.88.100.0': true,
    '192.167.255.255': true, '192.168.0.0': false, '192.168.255.255': false, '192.169.0.0': true,
    '198.17.255.255': true, '198.18.0.0': false, '198.19.255.255': false, '198.20.0.0': true,
    '198.51.100.0': false, '203.0.113.255': false, '203.0.114.0': true,
    '223.255.255.255': true, '224.0.0.0': false, '239.255.255.255': false, '240.0.0.0': false,
    '255.255.255.254': false, '255.255.255.255': false, '0.0.0.0': false, '0.255.255.255': false, '1.0.0.0': true,
    '8.8.8.8': true, '1.1.1.1': true,
  };
  for (const [address, expected] of Object.entries(explicit)) assert.equal(isPublicAddress(address), expected, address);
});

test('IPv6: 2000::/3の外はすべて拒否し、内側でも特殊用途の全範囲を拒否する（両端・外側・割当空間の全prefix）', () => {
  const cidrs = table(REFERENCES.ipv6Special).flatMap((row) => cidrsIn(row['Address Block']));
  const special = cidrs.map(rangeOf);
  const global = rangeOf('2000::/3');
  const expectedFor = (point) => point >= global.first && point <= global.last && !inAny(point, special);
  let allowed = 0;
  for (const [index, range] of special.entries()) {
    assert.equal(isPublicAddress(fromBigInt(range.first, 128)), false, `${cidrs[index]} の先頭`);
    assert.equal(isPublicAddress(fromBigInt(range.last, 128)), false, `${cidrs[index]} の末尾`);
    for (const point of boundaries(range)) {
      const address = fromBigInt(point, 128);
      assert.equal(isPublicAddress(address), expectedFor(point), `${cidrs[index]} の境界 ${address}`);
      if (expectedFor(point)) allowed += 1;
    }
  }
  assert.ok(allowed >= 10, `公開IPになる境界を通っている: ${allowed}`);

  // 割当空間の全prefix: Global Unicast以外は両端とも拒否。2000::/3の両端の外側も拒否。
  for (const row of table(REFERENCES.ipv6Space)) {
    const range = rangeOf(row['IPv6 Prefix']);
    for (const point of [range.first, range.last, ...boundaries(range)]) {
      assert.equal(isPublicAddress(fromBigInt(point, 128)), expectedFor(point), `${row['IPv6 Prefix']} ${fromBigInt(point, 128)}`);
    }
    if (row.Allocation !== 'Global Unicast') {
      assert.equal(isPublicAddress(fromBigInt(range.first, 128)), false, row['IPv6 Prefix']);
      assert.equal(isPublicAddress(fromBigInt(range.last, 128)), false, row['IPv6 Prefix']);
    }
  }

  const explicit = {
    '::': false, '::1': false, '::2': false, '1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff': false,
    '2000::': true, '2000::1': true, '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff': false, '2001:200::': true,
    '2001:db7:ffff:ffff:ffff:ffff:ffff:ffff': true, '2001:db8::': false, '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff': false, '2001:db9::': true,
    '2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff': true, '2002::': false, '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff': false, '2003::': true,
    '2620:4f:7fff:ffff:ffff:ffff:ffff:ffff': true, '2620:4f:8000::': false, '2620:4f:8001::': true,
    '3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff': true, '3fff::': false, '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff': false, '3fff:1000::': true,
    '3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff': true, '4000::': false, '5f00::1': false,
    'fc00::1': false, 'fd12:3456::1': false, 'fe80::1': false, 'fec0::1': false, 'ff02::1': false,
    '2606:4700:4700::1111': true, '2a00:1450:4001::1': true,
  };
  for (const [address, expected] of Object.entries(explicit)) assert.equal(isPublicAddress(address), expected, address);
});

test('特殊用途表でGlobally Reachableが真の範囲も、保守的に拒否する', () => {
  const globals = [REFERENCES.ipv4Special, REFERENCES.ipv6Special].flatMap((reference) =>
    table(reference)
      .filter((row) => row['Globally Reachable'].startsWith('True'))
      .flatMap((row) => cidrsIn(row['Address Block'])),
  );
  // 192.0.0.9、192.0.0.10、AS112、AMT、64:ff9b::/96、2001:1::1〜3、2001:3::/32、2001:4:112::/48、ORCHIDv2、DETs 等。
  assert.equal(globals.length, 14);
  for (const cidr of globals) {
    const range = rangeOf(cidr);
    for (const point of [range.first, range.last]) {
      assert.equal(isPublicAddress(fromBigInt(point, range.bits)), false, cidr);
    }
  }
  for (const address of ['192.0.0.9', '192.0.0.10', '192.31.196.1', '192.52.193.1', '192.175.48.1']) {
    assert.equal(isPublicAddress(address), false, address);
  }
  for (const address of ['64:ff9b::808:808', '2001:1::1', '2001:3::1', '2001:4:112::1', '2001:20::1', '2001:30::1', '2620:4f:8000::1']) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('表記の変形: mapped・変換・トンネル・zone・非正規のIPv4表記は、公開IPを包んでいても拒否する', () => {
  const refused = [
    // IPv4-mapped / 互換 / 変換 / 6to4 / Teredo。
    '::ffff:8.8.8.8', '::ffff:808:808', '::FFFF:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:0a00:0001',
    '::8.8.8.8', '::127.0.0.1', '64:ff9b::8.8.8.8', '64:ff9b:1::8.8.8.8', '2002:0808:0808::1', '2002:7f00:1::', '2001:0:808:808::1',
    // zone付き。
    'fe80::1%eth0', 'fe80::1%25eth0', '2606:4700::1111%1',
    // dotted decimal以外のIPv4、範囲外、余分な文字。
    '8.8.8', '8.8', '134744072', '0x8.0x8.0x8.0x8', '010.8.8.8', '08.8.8.8', '8.8.8.256', '8.8.8.8.', ' 8.8.8.8', '8.8.8.8 ',
    '8.8.8.8/32', '8.8.8.8:443', '[2606:4700::1111]', '2606:4700::1111::', 'example.com', 'localhost', '',
  ];
  for (const address of refused) assert.equal(isPublicAddress(address), false, JSON.stringify(address));
  for (const value of [undefined, null, 134744072, {}, ['8.8.8.8']]) assert.equal(isPublicAddress(value), false);

  // 同じ公開IPv6は、表記が違っても同じ判定になる。
  for (const address of ['2606:4700:4700::1111', '2606:4700:4700:0:0:0:0:1111', '2606:4700:4700:0000:0000:0000:0000:1111', '2606:4700:4700::0.0.17.17', '2606:4700:4700::1111'.toUpperCase()]) {
    assert.equal(isPublicAddress(address), true, address);
    assert.ok(sameAddress(address, '2606:4700:4700::1111'), address);
  }
  assert.deepEqual([...parseIp('::ffff:1.2.3.4').bytes.slice(10)], [0xff, 0xff, 1, 2, 3, 4]);
  assert.equal(parseIp('1.2.3.4').family, 4);
  assert.equal(parseIp('fe80::1%eth0'), null);
});

test('接続先の照合: 同じfamilyの同じアドレスだけが一致する', () => {
  assert.ok(sameAddress('127.0.0.2', '127.0.0.2'));
  assert.ok(sameAddress('2001:DB8::1', '2001:db8:0:0:0:0:0:1'));
  for (const [left, right] of [
    ['127.0.0.2', '127.0.0.3'],
    ['127.0.0.2', '::ffff:127.0.0.2'],
    ['::ffff:127.0.0.2', '127.0.0.2'],
    ['2001:db8::1', '2001:db8::2'],
    ['127.0.0.2', ''],
    ['127.0.0.2', undefined],
    ['not-an-ip', 'not-an-ip'],
  ]) {
    assert.equal(sameAddress(left, right), false, `${left} / ${right}`);
  }
});
