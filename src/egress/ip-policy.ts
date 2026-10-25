// 外向き送出の宛先IP分類。契約の正本は docs/SECURITY.md「安全なHTTPS送出」。
// 範囲の根拠は references/ に保存したIANAの3表（取得日2026-10-06、IPv4/IPv6特殊用途 2025-10-09、
// IPv6割当空間 2025-10-23）。実行中に表を取得しない。範囲の更新はレビューを通す（試験が保存した表と照合する）。
// 特殊用途表でGlobally Reachableが真の範囲も拒否する。IANAの到達性の判定ではなく、SendTextToDotsの採用制限。

import { isIPv4, isIPv6 } from 'node:net';

/** IANA IPv4 Special-Purpose Address Registryの全範囲。 */
export const IPV4_SPECIAL_PURPOSE: readonly string[] = Object.freeze([
  '0.0.0.0/8',
  '0.0.0.0/32',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.0.0/29',
  '192.0.0.8/32',
  '192.0.0.9/32',
  '192.0.0.10/32',
  '192.0.0.170/32',
  '192.0.0.171/32',
  '192.0.2.0/24',
  '192.31.196.0/24',
  '192.52.193.0/24',
  '192.88.99.0/24',
  '192.88.99.2/32',
  '192.168.0.0/16',
  '192.175.48.0/24',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '240.0.0.0/4',
  '255.255.255.255/32',
]);

/** 特殊用途表にないが拒否するIPv4 multicast。 */
export const IPV4_MULTICAST = '224.0.0.0/4';

/** IANA IPv6 Address Spaceで唯一のGlobal Unicast。この外のIPv6はすべて拒否する。 */
export const IPV6_GLOBAL_UNICAST = '2000::/3';

/** IANA IPv6 Special-Purpose Address Registryの全範囲。2000::/3の内側にあるものも拒否する。 */
export const IPV6_SPECIAL_PURPOSE: readonly string[] = Object.freeze([
  '::1/128',
  '::/128',
  '::ffff:0:0/96',
  '64:ff9b::/96',
  '64:ff9b:1::/48',
  '100::/64',
  '100:0:0:1::/64',
  '2001::/23',
  '2001::/32',
  '2001:1::1/128',
  '2001:1::2/128',
  '2001:1::3/128',
  '2001:2::/48',
  '2001:3::/32',
  '2001:4:112::/48',
  '2001:10::/28',
  '2001:20::/28',
  '2001:30::/28',
  '2001:db8::/32',
  '2002::/16',
  '2620:4f:8000::/48',
  '3fff::/20',
  '5f00::/16',
  'fc00::/7',
  'fe80::/10',
]);

export interface ParsedIp {
  readonly family: 4 | 6;
  readonly bytes: Uint8Array;
}

function parseIPv4Bytes(address: string): Uint8Array {
  return Uint8Array.from(address.split('.'), (part) => Number(part));
}

function parseIPv6Bytes(address: string): Uint8Array {
  let text = address;
  // 末尾のdotted IPv4（::ffff:192.0.2.1 等）は2つの16bit群へ直す。
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.')) {
    const v4 = parseIPv4Bytes(text.slice(lastColon + 1));
    const group = (high: number, low: number) => (((v4[high] ?? 0) << 8) | (v4[low] ?? 0)).toString(16);
    text = `${text.slice(0, lastColon + 1)}${group(0, 1)}:${group(2, 3)}`;
  }
  const [head = '', tail] = text.split('::');
  const groupsOf = (part: string) => (part === '' ? [] : part.split(':'));
  const headGroups = groupsOf(head);
  const tailGroups = tail === undefined ? [] : groupsOf(tail);
  const fill = tail === undefined ? 0 : 8 - headGroups.length - tailGroups.length;
  const groups = [...headGroups, ...new Array<string>(fill).fill('0'), ...tailGroups];
  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    const value = Number.parseInt(group, 16);
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
}

/**
 * dotted decimalのIPv4と、zoneのないIPv6だけを読む。短縮形・8進/16進・整数表記のIPv4、zone付きIPv6、
 * それ以外の文字列はnull。
 */
export function parseIp(address: string): ParsedIp | null {
  if (typeof address !== 'string') return null;
  if (isIPv4(address)) return { family: 4, bytes: parseIPv4Bytes(address) };
  if (isIPv6(address) && !address.includes('%')) return { family: 6, bytes: parseIPv6Bytes(address) };
  return null;
}

interface Prefix {
  readonly bytes: Uint8Array;
  readonly bits: number;
}

function prefixOf(cidr: string): Prefix {
  const slash = cidr.lastIndexOf('/');
  const parsed = parseIp(cidr.slice(0, slash));
  if (!parsed) throw new Error('invalid address range in the fixed table');
  return { bytes: parsed.bytes, bits: Number(cidr.slice(slash + 1)) };
}

function within(bytes: Uint8Array, prefix: Prefix): boolean {
  const whole = prefix.bits >> 3;
  for (let index = 0; index < whole; index += 1) {
    if (bytes[index] !== prefix.bytes[index]) return false;
  }
  const rest = prefix.bits & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return ((bytes[whole] ?? 0) & mask) === ((prefix.bytes[whole] ?? 0) & mask);
}

const V4_FORBIDDEN = [...IPV4_SPECIAL_PURPOSE, IPV4_MULTICAST].map(prefixOf);
const V6_GLOBAL = prefixOf(IPV6_GLOBAL_UNICAST);
const V6_FORBIDDEN = IPV6_SPECIAL_PURPOSE.map(prefixOf);

/**
 * 製品の宛先ポリシー。公開宛先として接続してよいIPだけtrue。読めない表記はfalse。
 * IPv4は特殊用途とmulticastの外、IPv6は2000::/3の内側かつ特殊用途の外。
 */
export function isPublicAddress(address: string): boolean {
  const parsed = parseIp(address);
  if (!parsed) return false;
  if (parsed.family === 4) return !V4_FORBIDDEN.some((prefix) => within(parsed.bytes, prefix));
  return within(parsed.bytes, V6_GLOBAL) && !V6_FORBIDDEN.some((prefix) => within(parsed.bytes, prefix));
}

/** 同じfamilyの同じアドレスか（IPv6は表記の違いを吸収して比べる）。読めない値は一致しない。 */
export function sameAddress(left: string, right: string): boolean {
  const a = parseIp(left);
  const b = parseIp(right);
  if (!a || !b || a.family !== b.family) return false;
  return a.bytes.every((byte, index) => byte === b.bytes[index]);
}
