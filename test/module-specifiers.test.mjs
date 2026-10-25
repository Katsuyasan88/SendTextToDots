// 包装の依存解析（scripts/module-specifiers.mjs）と、実current-dist（候補rootのdist。試験時はscripts/run-tests.mjsの一時copy）に対する包装の閉包を確かめる。
//   - 字句解析の正負: 両quoteのstatic import/export、side-effect import、`export * (as)`/`{…} from`、固定形requireCjs、
//     comment・文字列・正規表現・template本文の中の `import` は依存にしない、template式の中のdynamic importは拒否、他の拒否形。
//   - 実current-dist: 全JSについて、字句解析のstatic specifierとV8のES module parser（vm.SourceTextModuleのdependencySpecifiers。
//     parseだけで評価・link 0、子process 1つで終了を待つ）が集合として一致すること。
//   - 実current-distの包装（書込み0）: API/MCPの閉包が全ての相対依存を含み（V8の結果で照合）、browser用script（pages/console）のbytesが
//     dist原本と同一で、bare依存は宣言済みだけ。Cloud・install・network・.tmp書込み0。

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { ModuleScanError, moduleSpecifiers } from '../scripts/module-specifiers.mjs';
import { ARTIFACTS, buildArtifacts, parseTarGz, parseZip, readServerInputs } from '../scripts/package-artifacts.mjs';

const SERVER = dirname(dirname(fileURLToPath(import.meta.url)));
const DIST = join(SERVER, 'dist');
const scanCode = (text) => {
  try {
    moduleSpecifiers(text);
    return 'ok';
  } catch (error) {
    return error instanceof ModuleScanError ? error.code : `unexpected:${error?.message}`;
  }
};

test('L1 positives: both quotes, side-effect imports, default/named/namespace imports, export * / * as / { } from and the fixed requireCjs form are extracted in order', () => {
  const text = [
    "import a from './a.js';",
    'import { b, c as d } from "./b.js";',
    "import * as ns from 'node:fs';",
    'import "./side.js";',
    'import def, { x } from "@scope/pkg/sub";',
    "export * from './e.js';",
    'export * as f from "./f.js";',
    "export { g, h as i } from './g.js';",
    'export { local };',
    'export const value = 1;',
    "const requireCjs = createRequire(import.meta.url);",
    "const gax = requireCjs('google-gax');",
    'const kms = requireCjs("@google-cloud/kms");',
    'const n = 1e-5, m = 0x1f / 2;',
  ].join('\n');
  assert.deepEqual(moduleSpecifiers(text), {
    imports: ['./a.js', './b.js', 'node:fs', './side.js', '@scope/pkg/sub', './e.js', './f.js', './g.js'],
    cjs: ['google-gax', '@google-cloud/kms'],
  });
});

test('L2 text that is not code is not a dependency: comments, strings, regular expressions and template text (a browser module script) are ignored while template expressions stay code', () => {
  const browser = [
    'const SDK = "https://www.gstatic.com/firebasejs/x/";',
    'export const SCRIPT = `import { initializeApp } from \'${SDK}firebase-app.js\';',
    'import { getAuth } from "${SDK}firebase-auth.js";',
    "const nested = `inner ${'import x from \"./not.js\";'} text`;",
    '`;',
    "// import a from './comment.js';",
    "/* export * from './block.js'; */",
    "const s = \"import b from './string.js';\";",
    "const r = /import c from '.\\/regex.js'/g;",
    "const q = a / b / c;",
    "import real from './real.js';",
  ].join('\n');
  assert.deepEqual(moduleSpecifiers(browser), { imports: ['./real.js'], cjs: [] });
  assert.deepEqual(moduleSpecifiers('const o = { import: 1, require: 2 }; o.import; o?.require; x.requireCjs;'), { imports: [], cjs: [] });
});

test('L3 fail closed: dynamic import (also inside a template expression), require, other requireCjs forms, malformed import/export, escaped specifiers and unterminated text are refused', () => {
  const cases = {
    "const m = import('./x.js');": 'scan_dynamic_import',
    'const t = `a ${await import("./x.js")} b`;': 'scan_dynamic_import',
    'const t = `a ${`b ${import("./y.js")}`} c`;': 'scan_dynamic_import',
    "const m = require('x');": 'scan_require',
    'const t = `${require("x")}`;': 'scan_require',
    'const g = requireCjs(name);': 'scan_require_cjs_form',
    "const g = requireCjs('a' + 'b');": 'scan_require_cjs_form',
    "import { a } from;": 'scan_import_form',
    "import a from b;": 'scan_import_form',
    "export * from x;": 'scan_export_form',
    "import a from './\\u0061.js';": 'scan_specifier_escape',
    "const s = 'unterminated;": 'scan_unterminated',
    'const t = `open ${x': 'scan_unterminated',
    '/* open': 'scan_unterminated',
    'const r = /open': 'scan_unterminated',
    'const x = \\u0061;': 'scan_invalid',
  };
  for (const [text, code] of Object.entries(cases)) assert.equal(scanCode(text), code, text);
});

/** V8のES module parserでstatic specifierを得る（子process 1つ。parseだけで評価・link 0。終了を待つ）。 */
function v8Specifiers(files) {
  const script = "const vm=require('node:vm');const fs=require('node:fs');const out={};let n=0;for(const f of process.argv.slice(1)){n+=1;out[f]=new vm.SourceTextModule(fs.readFileSync(f,'utf8'),{identifier:'file:///sttd-scan/'+n+'.mjs'}).dependencySpecifiers;}process.stdout.write(JSON.stringify(out));";
  const result = spawnSync(process.execPath, ['--experimental-vm-modules', '--no-warnings', '-e', script, ...files], { encoding: 'utf8', timeout: 60_000, windowsHide: true, maxBuffer: 1024 * 1024 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, 'V8 parse child exited');
  return JSON.parse(result.stdout);
}
const distFiles = () => {
  const found = [];
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.name.endsWith('.js')) found.push(path);
    }
  };
  visit(DIST);
  return found.sort();
};

test('R1 current dist: for every compiled JS the lexer finds exactly the static specifiers that the V8 module parser reports, with no dynamic import or forbidden require, and the browser scripts in pages/console add no dependency', () => {
  const files = distFiles();
  assert.ok(files.length >= 50, `dist JS present (${files.length})`);
  const oracle = v8Specifiers(files);
  const mismatched = [];
  for (const file of files) {
    const mine = [...new Set(moduleSpecifiers(fs.readFileSync(file, 'utf8')).imports)].sort();
    const theirs = [...new Set(oracle[file])].sort();
    if (JSON.stringify(mine) !== JSON.stringify(theirs)) mismatched.push(file.slice(DIST.length + 1));
  }
  assert.deepEqual(mismatched, []);
  const pages = moduleSpecifiers(fs.readFileSync(join(DIST, 'connect', 'pages.js'), 'utf8'));
  const consoleJs = moduleSpecifiers(fs.readFileSync(join(DIST, 'connect', 'console.js'), 'utf8'));
  for (const found of [pages, consoleJs]) assert.equal(found.imports.some((item) => item.includes('firebase') || item.includes('http')), false, 'browser script imports are not server dependencies');
  assert.ok(fs.readFileSync(join(DIST, 'connect', 'pages.js'), 'utf8').includes('firebase-auth.js'), 'the browser script text is present in the compiled file');
});

test('R2 current dist packaging (RAM only): API and MCP closures contain every relative dependency reported by V8, keep the browser script files byte-identical, use only declared bare dependencies and re-parse to the planned entries', () => {
  const inputs = readServerInputs(SERVER);
  const built = buildArtifacts(inputs);
  const pkg = JSON.parse(fs.readFileSync(join(SERVER, 'package.json'), 'utf8'));
  const declared = Object.keys(pkg.dependencies);
  const archives = { api: parseZip(built.zip), mcp: parseTarGz(built.tarGz) };
  const oracleFor = (names) => v8Specifiers(names.map((name) => join(SERVER, ...name.split('/'))));
  for (const [kind, entries] of Object.entries(archives)) {
    const names = new Set(entries.map((entry) => entry.name));
    const js = entries.filter((entry) => entry.name.startsWith('dist/') && entry.name.endsWith('.js'));
    assert.ok(names.has(ARTIFACTS[kind].main), `${kind} main`);
    const oracle = oracleFor(js.map((entry) => entry.name));
    const missing = [];
    const bare = new Set();
    for (const entry of js) {
      assert.ok(entry.bytes.equals(fs.readFileSync(join(SERVER, ...entry.name.split('/')))), `${kind}: ${entry.name} bytes equal dist`);
      for (const specifier of oracle[join(SERVER, ...entry.name.split('/'))]) {
        if (specifier.startsWith('node:')) continue;
        if (specifier.startsWith('.')) {
          const target = posix.normalize(posix.join(posix.dirname(entry.name), specifier));
          if (!names.has(target)) missing.push(`${entry.name} -> ${specifier}`);
        } else bare.add(specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]);
      }
    }
    assert.deepEqual(missing, [], `${kind}: closure complete`);
    assert.deepEqual([...bare].filter((name) => !declared.includes(name)), [], `${kind}: only declared bare dependencies`);
    assert.deepEqual(built.receipt[kind].files.map((file) => file.name), entries.map((entry) => entry.name));
  }
  const mcpNames = archives.mcp.map((entry) => entry.name);
  assert.ok(mcpNames.includes('dist/connect/pages.js') && mcpNames.includes('dist/connect/console.js'), 'MCP carries the browser script modules');
  assert.equal(built.receipt.mcp.baseImage, ARTIFACTS.baseImage);
});
