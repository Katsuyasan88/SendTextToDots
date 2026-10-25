// 候補rootの現在の`dist`と固定package（package.json・package-lock.json）から、送信APIのFunctions source ZIPとMCPのCloud Build source archiveを
// offlineで作る包装tool。標準Node（fs・path・url・crypto・zlib・child_process）だけで、新依存・外部zip/tar・install・Cloud・資格・送信0。
// import時は定義だけでI/O 0。CLIは`package`の1引数だけで、root・path・entry・output・base imageを差し替える口は無い。
//   - entry: API `dist/deployment/functions.js`（Functions名・SA・options・HTTP契約はentry内の固定値）、MCP `dist/deployment/connect.js`。
//     各entryから静的import/export from（両quote。相対はdist内の実file、bareはnode:組込みかpackage.jsonのdependencies）と、固定形
//     `requireCjs('<依存>')`だけを字句解析（module-specifiers.mjs。comment・文字列・template本文は依存にせず、template式の中は検査）で
//     抽出して閉包を作る。動的import・それ以外のrequire・解析不能形・dist外への相対・未解決・依存外のbareは拒否する（評価しない）。
//   - dist全体を走査し、link・junction・realpath逸脱・regular file/directory以外・.js/.d.ts/.js.map/.d.ts.map以外のfile、対応する
//     `src/**/*.ts`が無い生成物（削除sourceの残り）を拒否する。閉包の各JSは`node --check`で構文だけを確かめる（実行しない）。
//   - 独自コードのMIT許諾表示と第三者noticeを保持するため、root の`LICENSE`・`THIRD_PARTY_NOTICES.md`を必須入力として両archiveへそのまま入れ
//     （MCPはimageへもCOPY）、読戻しで同じbytesを確かめる。無ければlicense_missingで出力0。
//   - package.jsonは名前・版・private・license（必須の非空文字列）・type module・engines node 22・main・dependencies/devDependencies（全て固定版）だけへ派生し、lockは
//     root enginesだけを揃える（版・resolved・integrityは不変）。.npmrcはregistry・omit dev・ignore-scripts・audit/fund 0。
//   - API: ZIP32 store（UTF-8・固定時刻・0644・byte順）。MCP: ustar＋gzip（固定base imageのDockerfile・.dockerignore付き）。
//   - 生成物を同じ厳格parserで読み直し、entry一覧・内容・main・Dockerfileを確かめてから、`<root>/.tmp/sendtexttodots-artifacts-<digest12>`を
//     exclusive作成して3 file（api.zip・mcp.tar.gz・receipt.json）をexclusive作成・読戻す。既存出力は上書き・削除・再試行しない。
//   - receiptは公開metadata（planningOnly true・executionPermitted false）で、upload・Build・配置・認可の証拠ではない。

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { constants as zlibConstants, crc32, gunzipSync, gzipSync } from 'node:zlib';

import { ModuleScanError, moduleSpecifiers } from './module-specifiers.mjs';

const SCRIPTS = dirname(fileURLToPath(import.meta.url));
const SERVER = dirname(SCRIPTS);

export const ARTIFACTS = Object.freeze({
  schema: 'sendtexttodots-artifacts/1',
  api: Object.freeze({ name: 'api.zip', main: 'dist/deployment/functions.js' }),
  mcp: Object.freeze({ name: 'mcp.tar.gz', main: 'dist/deployment/connect.js' }),
  baseImage: 'docker.io/library/node:22.23.3-bookworm-slim@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562',
  node: '22',
  outputPrefix: 'sendtexttodots-artifacts-',
});
const NPMRC_LINES = Object.freeze(['registry=https://registry.npmjs.org/', 'omit=dev', 'ignore-scripts=true', 'audit=false', 'fund=false']);
const DOCKERIGNORE_LINES = Object.freeze(['**', '!package.json', '!package-lock.json', '!.npmrc', '!LICENSE', '!THIRD_PARTY_NOTICES.md', '!dist', '!dist/**']);
/** 包装物へそのまま入れる許諾表示（候補rootの実file）。 */
const LEGAL_FILES = Object.freeze(['LICENSE', 'THIRD_PARTY_NOTICES.md']);
const DIST_SUFFIXES = Object.freeze(['.d.ts.map', '.js.map', '.d.ts', '.js']);
const FILE_LIMIT = 4 * 1024 * 1024;
const TOTAL_LIMIT = 32 * 1024 * 1024;
const MAX_DIST_FILES = 2048;
const EXACT_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** 固定codeだけの失敗（path・値・元例外を転記しない）。 */
export class ArtifactError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ArtifactError';
    this.code = code;
  }
}
const fail = (code) => {
  throw new ArtifactError(code);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const isPlain = (value) => typeof value === 'object' && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const json = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const lines = (items) => Buffer.from(`${items.join('\n')}\n`, 'utf8');
const byteOrder = (left, right) => Buffer.compare(Buffer.from(left, 'latin1'), Buffer.from(right, 'latin1'));

/** 相対ASCII通常path（絶対・drive・空要素・.・..・backslash・制御文字を拒否）。 */
function validName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 255 || !/^[\x21-\x7e]+$/.test(name)) return false;
  if (name.startsWith('/') || name.includes('\\') || name.includes(':')) return false;
  return name.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

// ---------- 入力（固定root以下。link・別名・上限） ----------
function lstatKind(path, kind, code) {
  let stat;
  let real;
  try {
    stat = lstatSync(path);
    real = realpathSync.native(path);
  } catch {
    return fail(code);
  }
  if (stat.isSymbolicLink() || (kind === 'directory' ? !stat.isDirectory() : !stat.isFile()) || real !== path) fail(code);
  return stat;
}
function readFile(path, code) {
  const before = lstatKind(path, 'file', code);
  if (before.size > FILE_LIMIT) fail('input_too_large');
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    return fail(code);
  }
  const after = lstatKind(path, 'file', code);
  if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ino !== before.ino) fail('input_changed');
  return bytes;
}
/** directory以下の実file一覧（regular fileとdirectoryだけ・各段の実pathが一致）。 */
function walk(root, code) {
  const found = [];
  const visit = (relative) => {
    const path = relative === '' ? root : join(root, ...relative.split('/'));
    lstatKind(path, 'directory', code);
    let entries;
    try {
      entries = readdirSync(path, { withFileTypes: true });
    } catch {
      return fail(code);
    }
    for (const entry of entries) {
      const child = relative === '' ? entry.name : `${relative}/${entry.name}`;
      if (!validName(child)) fail(code);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile()) {
        lstatKind(join(root, ...child.split('/')), 'file', code);
        found.push(child);
      } else fail(code);
      if (found.length > MAX_DIST_FILES) fail('dist_too_large');
    }
  };
  visit('');
  return found.sort(byteOrder);
}

/**
 * server root（package.json・package-lock.json・LICENSE・THIRD_PARTY_NOTICES.md・src・dist）を読み、distの残り物・未知fileを拒否してdistのJS（相対path→bytes）を返す。
 * 構文検査はここで実fileに対して行う（`node --check`・実行0）。
 */
export function readServerInputs(serverRoot) {
  lstatKind(serverRoot, 'directory', 'server_invalid');
  const packageJson = readFile(join(serverRoot, 'package.json'), 'package_invalid');
  const packageLock = readFile(join(serverRoot, 'package-lock.json'), 'package_invalid');
  const legal = LEGAL_FILES.map((name) => ({ name, bytes: readFile(join(serverRoot, name), 'license_missing') }));
  if (legal.some((file) => file.bytes.length === 0)) fail('license_missing');
  const sources = new Set(walk(join(serverRoot, 'src'), 'src_invalid').filter((name) => name.endsWith('.ts')).map((name) => name.slice(0, -3)));
  const distRoot = join(serverRoot, 'dist');
  const dist = new Map();
  let total = 0;
  for (const name of walk(distRoot, 'dist_invalid')) {
    const suffix = DIST_SUFFIXES.find((item) => name.endsWith(item));
    if (suffix === undefined) fail('dist_unknown_file');
    if (!sources.has(name.slice(0, -suffix.length))) fail('dist_stale_file');
    if (suffix !== '.js') continue;
    const bytes = readFile(join(distRoot, ...name.split('/')), 'dist_invalid');
    total += bytes.length;
    if (total > TOTAL_LIMIT) fail('input_too_large');
    dist.set(name, bytes);
  }
  return { packageJson, packageLock, legal, dist, checkSyntax: (name) => checkSyntax(join(distRoot, ...name.split('/'))) };
}
/** Nodeの構文検査だけ（`--check`。評価・import解決0）。 */
function checkSyntax(path) {
  const result = spawnSync(process.execPath, ['--check', path], { stdio: 'ignore', timeout: 10_000, windowsHide: true, env: { PATH: process.env.PATH ?? '', ...(process.env.SystemRoot === undefined ? {} : { SystemRoot: process.env.SystemRoot }) } });
  return result.status === 0 && result.error === undefined;
}

// ---------- 閉包 ----------
const packageOf = (specifier) => (specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]);
/** 依存specifier（module-specifiers.mjsの字句解析）。dynamic import・requireは閉包の拒否code、他の解析不能形はclosure_parse_invalid。 */
function specifiersOf(text) {
  try {
    return moduleSpecifiers(text);
  } catch (error) {
    if (!(error instanceof ModuleScanError)) return fail('closure_parse_invalid');
    if (error.code === 'scan_dynamic_import') return fail('closure_dynamic_import');
    if (error.code === 'scan_require') return fail('closure_require_forbidden');
    return fail('closure_parse_invalid');
  }
}/** entryからの閉包（distの相対path集合）と、使ったbare依存の集合。 */
export function closureOf(entry, dist, dependencies) {
  const files = new Set();
  const packages = new Set();
  const pending = [entry];
  while (pending.length > 0) {
    const name = pending.pop();
    if (files.has(name)) continue;
    const bytes = dist.get(name);
    if (bytes === undefined) fail('closure_unresolved');
    files.add(name);
    const found = specifiersOf(bytes.toString('utf8'));
    for (const specifier of [...found.imports, ...found.cjs]) {
      if (specifier.startsWith('node:')) continue;
      if (specifier.startsWith('./') || specifier.startsWith('../')) {
        if (found.cjs.includes(specifier)) fail('closure_relative_require');
        const target = posix.normalize(posix.join(posix.dirname(name), specifier));
        if (!validName(target) || !dist.has(target)) fail('closure_unresolved');
        pending.push(target);
        continue;
      }
      if (!dependencies.includes(packageOf(specifier))) fail('closure_dependency_unknown');
      packages.add(packageOf(specifier));
    }
  }
  return { files: [...files].sort(byteOrder), packages: [...packages].sort() };
}

// ---------- package ----------
function parseJson(bytes, code) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    return JSON.parse(text);
  } catch {
    return fail(code);
  }
}
const exactMap = (value) => isPlain(value) && Object.values(value).every((item) => typeof item === 'string' && EXACT_VERSION.test(item));
const sameMap = (a, b) => isPlain(a) && isPlain(b) && Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([key, item]) => b[key] === item);
/** 派生package.jsonとlock（版・依存は元のまま。固定版以外・lock不一致は拒否）。 */
export function derivePackages(packageJson, packageLock) {
  const original = parseJson(packageJson, 'package_invalid');
  const lock = parseJson(packageLock, 'package_invalid');
  if (!isPlain(original) || typeof original.name !== 'string' || typeof original.version !== 'string' || typeof original.license !== 'string' || original.license === '' || original.type !== 'module' || !exactMap(original.dependencies) || !exactMap(original.devDependencies ?? {})) fail('package_invalid');
  const root = isPlain(lock) && isPlain(lock.packages) ? lock.packages[''] : null;
  const lockOk = lock.lockfileVersion === 3 && lock.requires === true && lock.name === original.name && lock.version === original.version && isPlain(root) && sameMap(root.dependencies, original.dependencies) && sameMap(root.devDependencies ?? {}, original.devDependencies ?? {});
  if (!lockOk) fail('package_lock_mismatch');
  for (const [name, version] of Object.entries(original.dependencies)) if (lock.packages[`node_modules/${name}`]?.version !== version) fail('package_lock_mismatch');
  const pkg = (main) => ({ name: original.name, version: original.version, private: true, license: original.license, type: 'module', engines: { node: ARTIFACTS.node }, main, dependencies: { ...original.dependencies }, devDependencies: { ...(original.devDependencies ?? {}) } });
  const derivedLock = structuredClone(lock);
  derivedLock.packages[''].engines = { node: ARTIFACTS.node };
  return { license: original.license, dependencies: Object.keys(original.dependencies), api: json(pkg(ARTIFACTS.api.main)), mcp: json(pkg(ARTIFACTS.mcp.main)), lock: json(derivedLock) };
}
function dockerfile() {
  return lines([
    `FROM ${ARTIFACTS.baseImage}`,
    'WORKDIR /app',
    'COPY package.json package-lock.json .npmrc ./',
    'RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund',
    'COPY dist ./dist',
    `COPY ${LEGAL_FILES.join(' ')} ./`,
    'ENV NODE_ENV=production',
    'USER node',
    `CMD ${JSON.stringify(['node', ARTIFACTS.mcp.main])}`,
  ]);
}

// ---------- ZIP32（store） ----------
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
const UTF8_FLAG = 0x0800;
const MADE_BY = (3 << 8) | 20;
const UNIX_REGULAR_0644 = (0o100644 << 16) >>> 0;
const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
const END = 0x06054b50;
export function buildZip(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const { name, bytes } of entries) {
    const nameBytes = Buffer.from(name, 'latin1');
    const crc = crc32(bytes) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(UTF8_FLAG, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(bytes.length, 18);
    local.writeUInt32LE(bytes.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(CENTRAL, 0);
    header.writeUInt16LE(MADE_BY, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(UTF8_FLAG, 8);
    header.writeUInt16LE(0, 10);
    header.writeUInt16LE(DOS_TIME, 12);
    header.writeUInt16LE(DOS_DATE, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(bytes.length, 20);
    header.writeUInt32LE(bytes.length, 24);
    header.writeUInt16LE(nameBytes.length, 28);
    header.writeUInt32LE(UNIX_REGULAR_0644, 38);
    header.writeUInt32LE(offset, 42);
    parts.push(local, nameBytes, bytes);
    central.push(header, nameBytes);
    offset += local.length + nameBytes.length + bytes.length;
  }
  const centralBytes = Buffer.concat(central);
  if (offset + centralBytes.length > 0xffffffff || entries.length > 0xffff) fail('archive_too_large');
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, centralBytes, end]);
}
/** 固定形式のZIP32 storeだけを解析する（EOCD comment 0・分割0・store・固定属性・CRC・連続layout・byte順・重複0）。 */
export function parseZip(zip) {
  if (!Buffer.isBuffer(zip) || zip.length < 22 || zip.length > TOTAL_LIMIT) fail('archive_invalid');
  const endAt = zip.length - 22;
  if (zip.readUInt32LE(endAt) !== END) fail('archive_invalid');
  const count = zip.readUInt16LE(endAt + 10);
  const centralSize = zip.readUInt32LE(endAt + 12);
  const centralAt = zip.readUInt32LE(endAt + 16);
  if (zip.readUInt16LE(endAt + 4) !== 0 || zip.readUInt16LE(endAt + 6) !== 0 || zip.readUInt16LE(endAt + 8) !== count || zip.readUInt16LE(endAt + 20) !== 0 || centralAt + centralSize !== endAt) fail('archive_invalid');
  const entries = [];
  let cursor = centralAt;
  let localCursor = 0;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > endAt || zip.readUInt32LE(cursor) !== CENTRAL) fail('archive_invalid');
    const field = (offset, size) => (size === 2 ? zip.readUInt16LE(cursor + offset) : zip.readUInt32LE(cursor + offset));
    const nameLength = field(28, 2);
    const fixed = field(4, 2) === MADE_BY && field(6, 2) === 20 && field(8, 2) === UTF8_FLAG && field(10, 2) === 0 && field(12, 2) === DOS_TIME && field(14, 2) === DOS_DATE && field(20, 4) === field(24, 4) && field(30, 2) === 0 && field(32, 2) === 0 && field(34, 2) === 0 && field(36, 2) === 0 && field(38, 4) === UNIX_REGULAR_0644;
    if (!fixed || cursor + 46 + nameLength > endAt) fail('archive_invalid');
    const crc = field(16, 4);
    const size = field(20, 4);
    const localAt = field(42, 4);
    const nameBytes = zip.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString('latin1');
    if (!validName(name) || (entries.length > 0 && byteOrder(entries.at(-1).name, name) >= 0)) fail('archive_invalid');
    if (localAt !== localCursor || localAt + 30 + nameLength + size > centralAt || zip.readUInt32LE(localAt) !== LOCAL) fail('archive_invalid');
    const local = (offset, width) => (width === 2 ? zip.readUInt16LE(localAt + offset) : zip.readUInt32LE(localAt + offset));
    const localOk = local(4, 2) === 20 && local(6, 2) === UTF8_FLAG && local(8, 2) === 0 && local(10, 2) === DOS_TIME && local(12, 2) === DOS_DATE && local(14, 4) === crc && local(18, 4) === size && local(22, 4) === size && local(26, 2) === nameLength && local(28, 2) === 0 && zip.subarray(localAt + 30, localAt + 30 + nameLength).equals(nameBytes);
    if (!localOk) fail('archive_invalid');
    const bytes = zip.subarray(localAt + 30 + nameLength, localAt + 30 + nameLength + size);
    if (crc32(bytes) >>> 0 !== crc >>> 0) fail('archive_invalid');
    entries.push({ name, bytes: Buffer.from(bytes) });
    localCursor = localAt + 30 + nameLength + size;
    cursor += 46 + nameLength;
  }
  if (cursor !== endAt || localCursor !== centralAt) fail('archive_invalid');
  return entries;
}

// ---------- ustar＋gzip ----------
const octal = (value, width) => `${value.toString(8).padStart(width - 1, '0')}\0`;
function tarHeader(name, size) {
  const nameBytes = Buffer.from(name, 'latin1');
  if (nameBytes.length > 100) fail('archive_name_too_long');
  const header = Buffer.alloc(512);
  nameBytes.copy(header, 0);
  header.write(octal(0o644, 8), 100, 'ascii');
  header.write(octal(0, 8), 108, 'ascii');
  header.write(octal(0, 8), 116, 'ascii');
  header.write(octal(size, 12), 124, 'ascii');
  header.write(octal(0, 12), 136, 'ascii');
  header.fill(0x20, 148, 156);
  header.write('0', 156, 'ascii');
  header.write('ustar\0', 257, 'ascii');
  header.write('00', 263, 'ascii');
  header.write(octal(0, 8), 329, 'ascii');
  header.write(octal(0, 8), 337, 'ascii');
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return header;
}
export function buildTarGz(entries) {
  const parts = [];
  for (const { name, bytes } of entries) {
    if (bytes.length > 0o77777777777) fail('archive_too_large');
    parts.push(tarHeader(name, bytes.length), bytes);
    const pad = (512 - (bytes.length % 512)) % 512;
    if (pad > 0) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts), { level: zlibConstants.Z_BEST_COMPRESSION, memLevel: 8, windowBits: 15, strategy: zlibConstants.Z_DEFAULT_STRATEGY });
}
/** 同じ固定形式のustar＋gzipだけを解析する（regular file・0644・uid/gid/mtime 0・checksum・padding・末尾0 block 2・余剰0）。 */
export function parseTarGz(archive) {
  let tar;
  try {
    tar = gunzipSync(archive, { maxOutputLength: TOTAL_LIMIT });
  } catch {
    return fail('archive_invalid');
  }
  const entries = [];
  let at = 0;
  for (;;) {
    if (at + 512 > tar.length) fail('archive_invalid');
    const header = tar.subarray(at, at + 512);
    if (header.every((byte) => byte === 0)) {
      if (at + 1024 !== tar.length || !tar.subarray(at, at + 1024).every((byte) => byte === 0)) fail('archive_invalid');
      return entries;
    }
    const end = header.indexOf(0);
    const name = header.subarray(0, end === -1 || end > 100 ? 100 : end).toString('latin1');
    const size = Number.parseInt(header.subarray(124, 135).toString('ascii'), 8);
    const expected = tarHeader(name, Number.isSafeInteger(size) ? size : 0);
    if (!validName(name) || !Number.isSafeInteger(size) || !expected.equals(header) || (entries.length > 0 && byteOrder(entries.at(-1).name, name) >= 0)) fail('archive_invalid');
    const bytes = tar.subarray(at + 512, at + 512 + size);
    if (bytes.length !== size) fail('archive_invalid');
    const pad = (512 - (size % 512)) % 512;
    if (!tar.subarray(at + 512 + size, at + 512 + size + pad).every((byte) => byte === 0)) fail('archive_invalid');
    entries.push({ name, bytes: Buffer.from(bytes) });
    at += 512 + size + pad;
  }
}

// ---------- 組立て（pure） ----------
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0x82f63b78 : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();
function crc32c(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = (CRC32C_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8)) >>> 0;
  return (value ^ 0xffffffff) >>> 0;
}
const digestsOf = (bytes) => {
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32c(bytes));
  return { size: bytes.length, sha256: sha256(bytes), md5Base64: createHash('md5').update(bytes).digest('base64'), crc32cBase64: crc.toString('base64') };
};
const sameEntries = (parsed, planned) => parsed.length === planned.length && parsed.every((entry, index) => entry.name === planned[index].name && entry.bytes.equals(planned[index].bytes));

/**
 * 読取り済みの入力から2 archiveとreceiptを作る（pure。書込み0）。inputs: readServerInputsの戻り値。構文検査で落ちたJSは拒否する。
 */
export function buildArtifacts(inputs) {
  const packages = derivePackages(inputs.packageJson, inputs.packageLock);
  const legal = inputs.legal;
  if (!Array.isArray(legal) || legal.length !== LEGAL_FILES.length || !legal.every((file, index) => file?.name === LEGAL_FILES[index] && Buffer.isBuffer(file.bytes) && file.bytes.length > 0)) fail('license_missing');
  const legalEntries = legal.map((file) => ({ name: file.name, bytes: file.bytes }));
  const npmrc = lines(NPMRC_LINES);
  const plan = (graph, extra) => {
    const closure = closureOf(graph.main, new Map([...inputs.dist].map(([name, bytes]) => [`dist/${name}`, bytes])), packages.dependencies);
    for (const name of closure.files) if (inputs.checkSyntax(name.slice('dist/'.length)) !== true) fail('syntax_invalid');
    const entries = [...closure.files.map((name) => ({ name, bytes: inputs.dist.get(name.slice('dist/'.length)) })), ...extra].sort((left, right) => byteOrder(left.name, right.name));
    return { entries, closure };
  };
  const api = plan(ARTIFACTS.api, [
    ...legalEntries,
    { name: '.npmrc', bytes: npmrc },
    { name: 'package-lock.json', bytes: packages.lock },
    { name: 'package.json', bytes: packages.api },
  ]);
  const mcp = plan(ARTIFACTS.mcp, [
    ...legalEntries,
    { name: '.dockerignore', bytes: lines(DOCKERIGNORE_LINES) },
    { name: '.npmrc', bytes: npmrc },
    { name: 'Dockerfile', bytes: dockerfile() },
    { name: 'package-lock.json', bytes: packages.lock },
    { name: 'package.json', bytes: packages.mcp },
  ]);
  const zip = buildZip(api.entries);
  const tarGz = buildTarGz(mcp.entries);
  // 生成物を同じ厳格parserで読み直す（一覧・内容・main・Dockerfile）。
  const zipEntries = parseZip(zip);
  const tarEntries = parseTarGz(tarGz);
  const pkgOf = (entries) => parseJson(entries.find((entry) => entry.name === 'package.json')?.bytes ?? Buffer.alloc(0), 'archive_verify_failed');
  const mainOf = (entries) => pkgOf(entries).main;
  // 許諾表示（LICENSE・第三者notice）が入力と同じbytesで入り、派生package.jsonがlicenseを保つ。
  const legalKept = (entries) => legalEntries.every((file) => entries.find((entry) => entry.name === file.name)?.bytes.equals(file.bytes) === true) && pkgOf(entries).license === packages.license;
  const verified =
    sameEntries(zipEntries, api.entries) &&
    sameEntries(tarEntries, mcp.entries) &&
    mainOf(zipEntries) === ARTIFACTS.api.main &&
    mainOf(tarEntries) === ARTIFACTS.mcp.main &&
    zipEntries.some((entry) => entry.name === ARTIFACTS.api.main) &&
    tarEntries.some((entry) => entry.name === ARTIFACTS.mcp.main) &&
    tarEntries.find((entry) => entry.name === 'Dockerfile')?.bytes.equals(dockerfile()) === true &&
    legalKept(zipEntries) &&
    legalKept(tarEntries);
  if (!verified) fail('archive_verify_failed');
  const describe = (entries) => entries.map((entry) => ({ name: entry.name, size: entry.bytes.length, sha256: sha256(entry.bytes) }));
  const receipt = {
    schema: ARTIFACTS.schema,
    package: { packageJsonSha256: sha256(inputs.packageJson), packageLockSha256: sha256(inputs.packageLock), node: ARTIFACTS.node, license: packages.license, legalFiles: [...LEGAL_FILES] },
    api: { name: ARTIFACTS.api.name, format: 'zip32-store', main: ARTIFACTS.api.main, entries: zipEntries.length, dependencies: api.closure.packages, ...digestsOf(zip), files: describe(zipEntries) },
    mcp: { name: ARTIFACTS.mcp.name, format: 'ustar-gzip', main: ARTIFACTS.mcp.main, baseImage: ARTIFACTS.baseImage, entries: tarEntries.length, dependencies: mcp.closure.packages, ...digestsOf(tarGz), files: describe(tarEntries) },
    planningOnly: true,
    executionPermitted: false,
    notice: 'local archive metadata only; not evidence of Cloud upload, build, deployment, signature or authorization',
  };
  return { zip, tarGz, receipt };
}

// ---------- 出力 ----------
function writeExclusive(path, bytes) {
  try {
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o644 });
  } catch {
    return fail('output_write_failed');
  }
  let readBack;
  try {
    lstatKind(path, 'file', 'output_readback_failed');
    readBack = readFileSync(path);
  } catch {
    return fail('output_readback_failed');
  }
  if (!readBack.equals(bytes)) fail('output_readback_failed');
}
/** server rootから2 archiveを作り、output root（.tmp）直下へ1回だけ書く。戻り値は出力名とreceipt。 */
export function packageArtifacts({ serverRoot, outputRoot }) {
  try {
    const built = buildArtifacts(readServerInputs(serverRoot));
    lstatKind(outputRoot, 'directory', 'output_invalid');
    const name = `${ARTIFACTS.outputPrefix}${sha256(Buffer.from(`${built.receipt.api.sha256}\n${built.receipt.mcp.sha256}\n`, 'utf8')).slice(0, 12)}`;
    const directory = join(outputRoot, name);
    try {
      mkdirSync(directory);
    } catch {
      return fail('output_exists');
    }
    lstatKind(directory, 'directory', 'output_invalid');
    writeExclusive(join(directory, ARTIFACTS.api.name), built.zip);
    writeExclusive(join(directory, ARTIFACTS.mcp.name), built.tarGz);
    writeExclusive(join(directory, 'receipt.json'), json(built.receipt));
    return Object.freeze({ output: name, receipt: built.receipt });
  } catch (error) {
    if (error instanceof ArtifactError) throw error;
    throw new ArtifactError('internal_failed');
  }
}

function isDirectMain() {
  const entry = process.argv[1];
  if (typeof entry !== 'string' || entry === '') return false;
  try {
    return pathToFileURL(resolve(entry)).href === import.meta.url;
  } catch {
    return false;
  }
}

if (isDirectMain()) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] !== 'package') {
    process.stderr.write('usage: node scripts/package-artifacts.mjs package\n');
    process.exitCode = 2;
  } else {
    try {
      // 出力root（<root>/.tmp。gitignore対象）だけを用意する。既存の出力directoryは上書きしない。
      mkdirSync(join(SERVER, '.tmp'), { recursive: true });
      const { output, receipt } = packageArtifacts({ serverRoot: SERVER, outputRoot: join(SERVER, '.tmp') });
      const brief = (item) => ({ name: item.name, entries: item.entries, size: item.size, sha256: item.sha256 });
      process.stdout.write(`${JSON.stringify({ event: 'sendtexttodots_artifacts.ready', output: `.tmp/${output}`, api: brief(receipt.api), mcp: brief(receipt.mcp) })}\n`);
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ event: 'sendtexttodots_artifacts.failed', code: error instanceof ArtifactError ? error.code : 'internal_failed' })}\n`);
      process.exitCode = 1;
    }
  }
}
