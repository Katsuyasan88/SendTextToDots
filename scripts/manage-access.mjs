// 運営者だけが使う利用許可の管理CLI（build済みのdist/access/admin.jsを使う）。import時のI/O 0、明示実行だけで動き、既定動作は無い。
//   node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
//   node scripts/manage-access.mjs grant  --project … --database … --namespace … --expect <statusで得た版（初回はabsent）>
//   node scripts/manage-access.mjs revoke --project … --database … --namespace … --expect <版>
// 対象のFirebase UIDは標準入力から1行1件だけ（argv・履歴・fileへ書かない）。運営者が正規のFirebase利用者管理で確認したUIDを入れる。
// 期待対象は編集・build済みの配置設定と完全一致が必要。資格は運営者のADCだけで、任意URL・資格file・接続先の指定は無い。
// 全体30秒: 標準入力の読取りと処理は開始から25秒まで、後始末は残りの5秒まで待ち、その後はprocessを終える（待つのをやめるだけで、
// 開始済みSDK処理の物理取消・RAMの物理消去は保証しない）。出力は固定codeと非秘密の状態/版・後始末の印の1行JSONだけ。
// 結果が不明（timed_out・unavailable）なら再実行で上書きせず、statusで照合する。

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const USAGE = 'usage: node scripts/manage-access.mjs <status|grant|revoke> --project <id> --database <id> --namespace <t256_…> [--expect <version>]  (UID on stdin)\n';
const STDIN_LIMIT = 1024;

/**
 * 標準入力を元期限（deadlineAt、clockと同じ基準のms）まで、上限bytesまで読む。{kind:'ok', bytes} / {kind:'too_large'} / {kind:'timed_out'}。
 * 上限超過・期限ではstreamを止め、読んだchunkは0埋めする（EOFを待ち続けない）。
 */
export function readStdin(stream, deadlineAt, clock = { now: () => Date.now() }) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let done = false;
    const finish = (outcome) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('end', onEnd);
      stream.off('error', onError);
      if (outcome.kind !== 'ok') {
        for (const chunk of chunks) chunk.fill(0);
        stream.pause?.();
        stream.destroy?.();
      }
      resolve(outcome);
    };
    const onData = (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      total += buffer.length;
      chunks.push(buffer);
      if (total > STDIN_LIMIT) finish({ kind: 'too_large' });
    };
    const onEnd = () => {
      const bytes = Buffer.concat(chunks);
      for (const chunk of chunks) chunk.fill(0);
      finish({ kind: 'ok', bytes });
    };
    const onError = () => finish({ kind: 'invalid' });
    const remaining = deadlineAt - clock.now();
    const timer = setTimeout(() => finish({ kind: 'timed_out' }), Math.max(0, Math.ceil(Number.isFinite(remaining) ? remaining : 0)));
    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onError);
    if (!(remaining > 0)) finish({ kind: 'timed_out' });
  });
}

/** CLIの本体（依存は明示実行の時だけ読む）。戻り値はexit code。 */
export async function main(argv, io) {
  const admin = await import('../dist/access/admin.js');
  const startedAt = Date.now();
  const request = admin.parseAdminArgs(argv);
  if (request === null) {
    io.stderr.write(USAGE);
    io.stdout.write(admin.formatAdminResult({ code: 'usage' }));
    return 2;
  }
  const input = await readStdin(io.stdin, startedAt + admin.ADMIN_WORK_MS);
  if (input.kind !== 'ok') {
    io.stdout.write(admin.formatAdminResult({ code: input.kind === 'timed_out' ? 'timed_out' : 'invalid_input' }));
    return 2;
  }
  const uid = admin.parseUidInput(input.bytes);
  input.bytes.fill(0);
  if (uid === null) {
    io.stdout.write(admin.formatAdminResult({ code: 'invalid_input' }));
    return 2;
  }
  const result = await admin.runAccessAdmin(request, uid, { openSdk: admin.openAdminSdk, startedAt });
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
  let code = 1;
  try {
    code = await main(process.argv.slice(2), { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
  } catch {
    process.stdout.write('{"code":"unavailable"}\n');
  }
  // 出力を書き終えたら、後始末が未確定のSDK handleが残っていてもprocessを終える（全体の上限を超えて待たない）。
  process.stdout.write('', () => process.exit(code));
}
