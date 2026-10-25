// offline包装tool（scripts/package-artifacts.mjs）を、一時directoryの合成server root（package・lock・LICENSE・第三者notice・src・dist）で確かめる。
//   - 正: API ZIP（entry閉包＋.npmrc・lock・package）とMCP archive（閉包＋固定Dockerfile・.dockerignore）を作り、厳格parserで読み直した
//     一覧・内容・main・base imageが一致、receiptは公開metadata、出力は1回だけ（既存は拒否）。
//   - 許諾表示: LICENSE・THIRD_PARTY_NOTICES.mdが両archiveへ同じbytesで入り、MCP imageへCOPYされ、派生package.jsonがlicenseを保つ。欠落・空・license無しは出力0で拒否。
//   - 負: 削除sourceの生成JS・未知file・junction・動的import・宣言外の依存・dist外/未解決の相対・構文不正・固定版以外・lock不一致は出力0で拒否。
//   - 依存の字句形: double quoteの相対importを含め、template本文のbrowser scriptは依存にせずbytesを保つ。template式内のdynamic importとrequireは拒否。
// 実serverのdist・.tmp・Cloud・install・network 0（構文検査の`node --check`だけが子process）。

import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { ARTIFACTS, ArtifactError, buildArtifacts, packageArtifacts, parseTarGz, parseZip, readServerInputs } from '../scripts/package-artifacts.mjs';

const roots = [];
after(() => {
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
  assert.equal(roots.every((root) => !fs.existsSync(root)), true);
});

const PACKAGE = { name: 'fixture-server', version: '0.0.0', private: true, license: 'MIT', type: 'module', dependencies: { 'dep-a': '1.2.3', '@scope/dep-b': '4.5.6' }, devDependencies: { 'dev-c': '7.8.9' } };
const lockFor = (pkg) => ({
  name: pkg.name,
  version: pkg.version,
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: pkg.name, version: pkg.version, dependencies: pkg.dependencies, devDependencies: pkg.devDependencies },
    'node_modules/dep-a': { version: '1.2.3' },
    'node_modules/@scope/dep-b': { version: '4.5.6' },
    'node_modules/dev-c': { version: '7.8.9', dev: true },
  },
});
const BASE_FILES = {
  'deployment/functions': "import { shared } from '../lib/shared.js';\nimport { a } from 'dep-a';\nexport const sendtexttodotsapi = () => shared + a;\n",
  'deployment/connect': "import { shared } from '../lib/shared.js';\nimport { b } from '@scope/dep-b/sub';\nimport { createRequire } from 'node:module';\nconst requireCjs = createRequire(import.meta.url);\nconst a = requireCjs('dep-a');\nexport { shared, b, a };\n",
  'lib/shared': "export * from './inner.js';\nexport const shared = 1;\n",
  'lib/inner': 'export const inner = 2;\n',
  'lib/unused': 'export const unused = 3;\n',
};
const LEGAL = { LICENSE: 'MIT License\n\nCopyright (c) 2026 Fixture\n', 'THIRD_PARTY_NOTICES.md': '# Third-party notices (fixture)\n' };

/** 合成server root（srcのtsとdistのjs・d.tsを対で作る）。overridesでdistの内容・追加fileを差し替える。 */
function server({ files = BASE_FILES, pkg = PACKAGE, lock = lockFor(PACKAGE), extraDist = {}, extraSrc = [], legal = LEGAL } = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(join(tmpdir(), 'sendtexttodots-pack-')));
  roots.push(root);
  const serverRoot = join(root, 'server');
  for (const [name, text] of Object.entries(files)) {
    for (const [dir, ext, body] of [['src', '.ts', '// source\n'], ['dist', '.js', text], ['dist', '.d.ts', 'export {};\n']]) {
      const path = join(serverRoot, dir, ...`${name}${ext}`.split('/'));
      fs.mkdirSync(join(path, '..'), { recursive: true });
      fs.writeFileSync(path, body);
    }
  }
  for (const name of extraSrc) {
    const path = join(serverRoot, 'src', ...name.split('/'));
    fs.mkdirSync(join(path, '..'), { recursive: true });
    fs.writeFileSync(path, '// source\n');
  }
  for (const [name, text] of Object.entries(extraDist)) {
    const path = join(serverRoot, 'dist', ...name.split('/'));
    fs.mkdirSync(join(path, '..'), { recursive: true });
    fs.writeFileSync(path, text);
  }
  fs.writeFileSync(join(serverRoot, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
  fs.writeFileSync(join(serverRoot, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
  for (const [name, text] of Object.entries(legal)) fs.writeFileSync(join(serverRoot, name), text);
  const outputRoot = join(root, '.tmp');
  fs.mkdirSync(outputRoot);
  return { root, serverRoot, outputRoot };
}
const code = (fn) => {
  try {
    fn();
    return 'ok';
  } catch (error) {
    return error instanceof ArtifactError ? error.code : `unexpected:${error?.message}`;
  }
};

test('P1 build: the API ZIP holds the functions closure (shared, inner; not unused or the MCP entry) with .npmrc, lock and a package whose main is the API entry; the MCP archive holds the connect closure with the fixed Dockerfile and .dockerignore; both re-parse to the same entries', () => {
  const s = server();
  const { zip, tarGz, receipt } = buildArtifacts(readServerInputs(s.serverRoot));
  const zipEntries = parseZip(zip);
  const tarEntries = parseTarGz(tarGz);
  assert.deepEqual(zipEntries.map((entry) => entry.name), ['.npmrc', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'dist/deployment/functions.js', 'dist/lib/inner.js', 'dist/lib/shared.js', 'package-lock.json', 'package.json']);
  assert.deepEqual(tarEntries.map((entry) => entry.name), ['.dockerignore', '.npmrc', 'Dockerfile', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'dist/deployment/connect.js', 'dist/lib/inner.js', 'dist/lib/shared.js', 'package-lock.json', 'package.json']);
  for (const entries of [zipEntries, tarEntries]) {
    for (const [name, text] of Object.entries(LEGAL)) assert.equal(entries.find((entry) => entry.name === name).bytes.toString('utf8'), text, `${name} kept byte-equal`);
  }
  const pkgOf = (entries) => JSON.parse(entries.find((entry) => entry.name === 'package.json').bytes.toString('utf8'));
  assert.deepEqual(pkgOf(zipEntries), { name: 'fixture-server', version: '0.0.0', private: true, license: 'MIT', type: 'module', engines: { node: '22' }, main: ARTIFACTS.api.main, dependencies: PACKAGE.dependencies, devDependencies: PACKAGE.devDependencies });
  assert.deepEqual([pkgOf(tarEntries).main, pkgOf(tarEntries).license], [ARTIFACTS.mcp.main, 'MIT']);
  const lock = JSON.parse(zipEntries.find((entry) => entry.name === 'package-lock.json').bytes.toString('utf8'));
  assert.deepEqual([lock.packages[''].engines, lock.packages['node_modules/dep-a'].version], [{ node: '22' }, '1.2.3']);
  const dockerfile = tarEntries.find((entry) => entry.name === 'Dockerfile').bytes.toString('utf8');
  assert.ok(dockerfile.startsWith(`FROM ${ARTIFACTS.baseImage}\n`) && dockerfile.includes('RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund') && dockerfile.includes('CMD ["node","dist/deployment/connect.js"]') && dockerfile.includes('COPY LICENSE THIRD_PARTY_NOTICES.md ./\n'));
  assert.ok(tarEntries.find((entry) => entry.name === '.dockerignore').bytes.toString('utf8').includes('!LICENSE\n!THIRD_PARTY_NOTICES.md\n'), 'the legal files are in the build context');
  assert.equal(zipEntries.find((entry) => entry.name === '.npmrc').bytes.toString('utf8'), 'registry=https://registry.npmjs.org/\nomit=dev\nignore-scripts=true\naudit=false\nfund=false\n');
  assert.deepEqual([receipt.api.entries, receipt.mcp.entries, receipt.api.dependencies, receipt.mcp.dependencies, receipt.planningOnly, receipt.executionPermitted], [8, 10, ['dep-a'], ['@scope/dep-b', 'dep-a'], true, false]);
  assert.match(receipt.api.md5Base64, /^[A-Za-z0-9+/]{22}==$/);
  assert.match(receipt.mcp.crc32cBase64, /^[A-Za-z0-9+/]{6}==$/);
  // 同じ入力からは同じbytes（固定時刻・固定順・固定圧縮）。
  const again = buildArtifacts(readServerInputs(s.serverRoot));
  assert.deepEqual([again.zip.equals(zip), again.tarGz.equals(tarGz)], [true, true]);
});

test('P2 output: one exclusive directory with exactly api.zip, mcp.tar.gz and receipt.json read back byte-equal; a second run is output_exists and writes nothing', () => {
  const s = server();
  const first = packageArtifacts({ serverRoot: s.serverRoot, outputRoot: s.outputRoot });
  assert.match(first.output, /^sendtexttodots-artifacts-[0-9a-f]{12}$/);
  const dir = join(s.outputRoot, first.output);
  assert.deepEqual(fs.readdirSync(dir).sort(), ['api.zip', 'mcp.tar.gz', 'receipt.json']);
  assert.equal(JSON.parse(fs.readFileSync(join(dir, 'receipt.json'), 'utf8')).api.sha256, first.receipt.api.sha256);
  assert.equal(code(() => packageArtifacts({ serverRoot: s.serverRoot, outputRoot: s.outputRoot })), 'output_exists');
  assert.deepEqual(fs.readdirSync(s.outputRoot), [first.output]);
});

test('P3 refusals before any output: a generated file without its source, an unknown file, a junction, a dynamic import, an undeclared dependency, a relative import outside dist or unresolved, a relative requireCjs and a syntax error', () => {
  const cases = {
    dist_stale_file: server({ extraDist: { 'old/removed.js': 'export const x = 1;\n' } }),
    dist_unknown_file: server({ extraDist: { 'lib/notes.txt': 'x' }, extraSrc: ['lib/notes.ts'] }),
    closure_dynamic_import: server({ files: { ...BASE_FILES, 'lib/inner': "export const inner = () => import('./shared.js');\n" } }),
    closure_dependency_unknown: server({ files: { ...BASE_FILES, 'lib/inner': "import x from 'not-declared';\nexport const inner = x;\n" } }),
    closure_unresolved: server({ files: { ...BASE_FILES, 'lib/inner': "import { y } from '../../outside.js';\nexport const inner = y;\n" } }),
    closure_relative_require: server({ files: { ...BASE_FILES, 'deployment/connect': "import { createRequire } from 'node:module';\nconst requireCjs = createRequire(import.meta.url);\nexport const a = requireCjs('./x.js');\n" } }),
    syntax_invalid: server({ files: { ...BASE_FILES, 'lib/inner': 'export const inner = ;\n' } }),
  };
  const junction = server();
  fs.mkdirSync(join(junction.root, 'elsewhere'));
  fs.symlinkSync(join(junction.root, 'elsewhere'), join(junction.serverRoot, 'dist', 'linked'), 'junction');
  cases.dist_invalid = junction;
  for (const [expected, s] of Object.entries(cases)) {
    assert.equal(code(() => packageArtifacts({ serverRoot: s.serverRoot, outputRoot: s.outputRoot })), expected, expected);
    assert.deepEqual(fs.readdirSync(s.outputRoot), [], `${expected}: no output`);
  }
});

test('P4 package refusals: a range version, a lock whose root or installed version differs, and a non-module package are refused', () => {
  const range = { ...PACKAGE, dependencies: { ...PACKAGE.dependencies, 'dep-a': '^1.2.3' } };
  const lock = lockFor(PACKAGE);
  lock.packages['node_modules/dep-a'].version = '1.2.4';
  const root = lockFor(PACKAGE);
  root.packages[''].dependencies = { 'dep-a': '1.2.3' };
  const cases = [
    ['package_invalid', server({ pkg: range, lock: lockFor(range) })],
    ['package_lock_mismatch', server({ lock })],
    ['package_lock_mismatch', server({ lock: root })],
    ['package_invalid', server({ pkg: { ...PACKAGE, type: 'commonjs' } })],
  ];
  for (const [expected, s] of cases) assert.equal(code(() => buildArtifacts(readServerInputs(s.serverRoot))), expected, expected);
});

test('P5 dependency text forms: a double-quoted relative import is packaged, and a browser module script kept as template text (with a CDN import line) adds no dependency and keeps its bytes', () => {
  const browser = "export const SCRIPT = `import { initializeApp } from 'https://cdn.example/firebase-app.js';\nimport \"./not-server.js\";\n`;\n";
  const s = server({ files: { ...BASE_FILES, 'lib/inner': `import { deep } from "./deep.js";\nexport const inner = deep;\n${browser}`, 'lib/deep': 'export const deep = 1;\n' } });
  const { zip, receipt } = buildArtifacts(readServerInputs(s.serverRoot));
  const entries = parseZip(zip);
  assert.ok(entries.some((entry) => entry.name === 'dist/lib/deep.js'), 'double-quoted import followed');
  assert.equal(entries.find((entry) => entry.name === 'dist/lib/inner.js').bytes.toString('utf8').includes('https://cdn.example/firebase-app.js'), true, 'browser script bytes kept');
  assert.deepEqual(receipt.api.dependencies, ['dep-a']);
  const dynamicInTemplate = server({ files: { ...BASE_FILES, 'lib/inner': 'export const inner = `x ${import("./deep.js")}`;\n', 'lib/deep': 'export const deep = 1;\n' } });
  assert.equal(code(() => buildArtifacts(readServerInputs(dynamicInTemplate.serverRoot))), 'closure_dynamic_import');
  const required = server({ files: { ...BASE_FILES, 'lib/inner': "const x = require('dep-a');\nexport const inner = x;\n" } });
  assert.equal(code(() => buildArtifacts(readServerInputs(required.serverRoot))), 'closure_require_forbidden');
});

test('P6 legal notices: a missing or empty LICENSE or THIRD_PARTY_NOTICES.md and a package without a license are refused before any output', () => {
  const cases = [
    ['license_missing', server({ legal: { 'THIRD_PARTY_NOTICES.md': LEGAL['THIRD_PARTY_NOTICES.md'] } })],
    ['license_missing', server({ legal: { LICENSE: LEGAL.LICENSE } })],
    ['license_missing', server({ legal: { ...LEGAL, LICENSE: '' } })],
    ['package_invalid', server({ pkg: { ...PACKAGE, license: '' } })],
  ];
  for (const [expected, s] of cases) {
    assert.equal(code(() => packageArtifacts({ serverRoot: s.serverRoot, outputRoot: s.outputRoot })), expected, expected);
    assert.deepEqual(fs.readdirSync(s.outputRoot), [], `${expected}: no output`);
  }
});
