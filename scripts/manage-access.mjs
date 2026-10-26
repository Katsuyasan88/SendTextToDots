// 運営者だけが使う利用許可の管理CLI（build済みのdist/access/admin.jsを使う）。import時のI/O 0、明示実行だけで動き、既定動作は無い。
//   node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
//   node scripts/manage-access.mjs grant  --project … --database … --namespace … --expect <statusで得た版（初回はabsent）>
//   node scripts/manage-access.mjs revoke --project … --database … --namespace … --expect <版>
// 対象のFirebase UIDは標準入力から1行1件だけ（argv・履歴・fileへ書かない）。運営者が正規のFirebase利用者管理で確認したUIDを入れる。
// 期待対象は編集・build済みの配置設定と完全一致が必要。資格は運営者のADCだけで、任意URL・資格file・接続先の指定は無い。
// 出力は固定codeと非秘密の状態/版の1行JSONだけ。結果が不明（timed_out・unavailable）なら再実行で上書きせず、statusで照合する。

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const USAGE = 'usage: node scripts/manage-access.mjs <status|grant|revoke> --project <id> --database <id> --namespace <t256_…> [--expect <version>]  (UID on stdin)\n';
const STDIN_LIMIT = 1024;

/** 標準入力を上限まで読む（超過はnull）。 */
async function readStdin(stream) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.length;
    if (total > STDIN_LIMIT) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

/** CLIの本体（依存は明示実行の時だけ読む）。戻り値はexit code。 */
export async function main(argv, io) {
  const admin = await import('../dist/access/admin.js');
  const request = admin.parseAdminArgs(argv);
  if (request === null) {
    io.stderr.write(USAGE);
    io.stdout.write(admin.formatAdminResult({ code: 'usage' }));
    return 2;
  }
  const input = await readStdin(io.stdin);
  const uid = input === null ? null : admin.parseUidInput(input);
  input?.fill(0);
  if (uid === null) {
    io.stdout.write(admin.formatAdminResult({ code: 'invalid_input' }));
    return 2;
  }
  const result = await admin.runAccessAdmin(request, uid, { openSdk: admin.openAdminSdk });
  io.stdout.write(admin.formatAdminResult(result));
  return ['status', 'changed', 'unchanged'].includes(result.code) ? 0 : result.code === 'conflict' ? 3 : 1;
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
  try {
    process.exitCode = await main(process.argv.slice(2), { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
  } catch {
    process.stdout.write('{"code":"unavailable"}\n');
    process.exitCode = 1;
  }
}
