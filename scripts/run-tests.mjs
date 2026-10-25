// 試験runner。build済みの`dist`を候補root内の一時directory（`.tmp/test-run-<uuid>`、gitignore対象）へ写し、その写しの配置設定module
// （dist/config/deployment.js）だけを合成の設定済み値（test/fixtures/synthetic-deployment.mjs）へ置き換えてから、写しの中で
// `node --test "test/*.test.mjs"`を1回だけ実行する。導入者が編集した実際の設定（src/config/deployment.ts）・`dist`は読み替え・書換えせず、
// 実行の前後でそのbytesが同じことを確かめる（変わっていれば失敗）。未設定の拒否は合成fixture（test/fixtures/unconfigured-deployment.mjs）で
// 確かめるため、試験の結果は導入者の設定内容に依存しない。実Cloud・資格・外部network・install 0。一時directoryは終了時に削除する。

import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const LIMIT_MS = 540_000;
/** 試験が書き換えてはならない実際の設定とbuild結果。 */
const GUARDED = ['src/config/deployment.ts', 'dist/config/deployment.js', 'dist/config/validate.js'];
const digestOf = () => GUARDED.map((name) => `${name}:${createHash('sha256').update(readFileSync(join(ROOT, ...name.split('/')))).digest('hex')}`).join('\n');

if (!existsSync(join(ROOT, 'dist', 'config', 'deployment.js'))) {
  process.stderr.write('run-tests: dist is missing; run `npm run build` first\n');
  process.exit(2);
}

const before = digestOf();
mkdirSync(join(ROOT, '.tmp'), { recursive: true });
const work = join(ROOT, '.tmp', `test-run-${randomUUID()}`);
mkdirSync(work);
let status = 1;
try {
  for (const name of ['package.json', 'package-lock.json', 'LICENSE', 'THIRD_PARTY_NOTICES.md']) copyFileSync(join(ROOT, name), join(work, name));
  for (const name of ['src', 'dist', 'scripts', 'test', 'references']) cpSync(join(ROOT, name), join(work, name), { recursive: true });
  copyFileSync(join(ROOT, 'test', 'fixtures', 'synthetic-deployment.mjs'), join(work, 'dist', 'config', 'deployment.js'));
  const result = spawnSync(process.execPath, ['--test', 'test/*.test.mjs'], { cwd: work, stdio: 'inherit', timeout: LIMIT_MS, windowsHide: true });
  if (result.error !== undefined) process.stderr.write(`run-tests: ${result.error.code ?? 'spawn_failed'}\n`);
  status = typeof result.status === 'number' ? result.status : 1;
} finally {
  rmSync(work, { recursive: true, force: true, maxRetries: 3 });
}
const untouched = digestOf() === before;
process.stdout.write(`# run-tests: deployment config and dist untouched=${untouched}\n`);
if (!untouched) status = 1;
process.exitCode = status;
