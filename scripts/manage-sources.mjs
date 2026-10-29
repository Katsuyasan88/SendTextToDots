// 運営者だけが使う許可元（source）の管理CLI（build済みのdist/source/admin.jsを使う）。import時のI/O 0、明示実行だけで動き、既定動作は無い。
//   node scripts/manage-sources.mjs status             --project <projectId> --database <databaseId> --namespace <connectNamespace> --source <src_…>
//   node scripts/manage-sources.mjs register-app       --project … --database … --namespace …   (stdin: {"appId":"1:<projectNumber>:ios:…","operations":["send","keys","connect"]})
//   node scripts/manage-sources.mjs register-developer --project … --database … --namespace …   (stdin: {"uid":"…","publicKey":"<PEM or raw base64url>","operations":[…],"expiresAt":"<ISO>|never"})
//   node scripts/manage-sources.mjs disable|enable|delete --project … --database … --namespace … --source <src_…> --expect <statusで得た版>
// UID・公開鍵は標準入力の1行JSONだけ（argv・履歴・fileへ書かない）。秘密鍵は受けない・作らない。期限は明示値（無期限も"never"の明示時だけ）。
// 期待対象は編集・build済みの配置設定と完全一致が必要。資格は運営者のADCだけ。出力は固定codeと非秘密の状態/版の1行JSONだけ。
// 結果が不明（timed_out・unavailable）なら再実行で上書きせず、statusで照合する。

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { readStdin } from './manage-access.mjs';

const USAGE =
  'usage: node scripts/manage-sources.mjs <status|register-app|register-developer|disable|enable|delete> --project <id> --database <id> --namespace <t256_…> [--source <src_…>] [--expect <version>]  (registration JSON on stdin)\n';

/** CLIの本体（依存は明示実行の時だけ読む）。戻り値はexit code。 */
export async function main(argv, io) {
  const admin = await import('../dist/source/admin.js');
  const { loadDeploymentConfig } = await import('../dist/config/validate.js');
  const startedAt = Date.now();
  const request = admin.parseSourceAdminArgs(argv);
  if (request === null) {
    io.stderr.write(USAGE);
    io.stdout.write(admin.formatSourceAdminResult({ code: 'usage' }));
    return 2;
  }
  const config = loadDeploymentConfig();
  let input = null;
  if (request.command === 'register-app' || request.command === 'register-developer') {
    const read = await readStdin(io.stdin, startedAt + admin.ADMIN_WORK_MS);
    if (read.kind !== 'ok') {
      io.stdout.write(admin.formatSourceAdminResult({ code: read.kind === 'timed_out' ? 'timed_out' : 'invalid_input' }));
      return 2;
    }
    input = admin.parseRegistrationInput(request.command, read.bytes, config.projectNumber, Date.now());
    read.bytes.fill(0);
    if (input === null) {
      io.stdout.write(admin.formatSourceAdminResult({ code: 'invalid_input' }));
      return 2;
    }
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(0, startedAt + admin.ADMIN_WORK_MS - Date.now()));
  try {
    const opened = await admin.openSourceAdmin(config, request, { deadlineAt: startedAt + admin.ADMIN_WORK_MS, signal: controller.signal });
    if (opened === 'target_mismatch') {
      io.stdout.write(admin.formatSourceAdminResult({ code: 'target_mismatch' }));
      return 2;
    }
    try {
      const result = await admin.runSourceAdmin(request, input, opened.deps);
      io.stdout.write(admin.formatSourceAdminResult(result));
      return ['status', 'created', 'changed'].includes(result.code) ? 0 : result.code === 'conflict' ? 3 : 1;
    } finally {
      await opened.close().catch(() => {});
    }
  } finally {
    clearTimeout(timer);
  }
}

function isMain() {
  const entry = process.argv[1];
  if (typeof entry !== 'string') return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  let code = 1;
  try {
    code = await main(process.argv.slice(2), { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
  } catch {
    process.stdout.write('{"code":"unavailable"}\n');
  }
  process.stdout.write('', () => process.exit(code));
}
