// 許可元の管理（scripts/manage-sources.mjsだけが使う）。runtimeの一般APIには公開しない。
//   status / register-app / register-developer / disable / enable / delete
// 登録は管理CLIが暗号学的乱数で作る新しいID・世代だけ（廃止IDを指定して再登録する操作は無い）。停止→有効化は新しい世代（旧Grantを
// 復活させない）、削除は物理削除（実App ID・公開鍵・identityHash・日時を残さない。旧bindingは不在として拒否され、付け替えない）。
// 開発者の期限は管理者の明示値（ISO時刻、または明示の"never"）。秘密鍵の作成・登録はしない（公開鍵だけを標準入力で受ける）。
// 入力は標準入力の1行JSON（UID・公開鍵をargv・履歴・ログへ出さない）。出力は固定code・source ID・状態/版・世代の有無だけ。

import { randomBytes } from 'node:crypto';

import { checkAdminEnvironment, isAdminUid, openAdminSdk as openAccessAdminSdk, ADMIN_WORK_MS } from '../access/admin.js';
import type { DeploymentConfig } from '../config/validate.js';
import { connectIdentityHash } from '../connect/firestore.js';
import { createHmacHasher, type SecretHasher } from '../secrets.js';
import {
  appIdProjectNumber,
  SOURCE_ID,
  SOURCE_OPERATIONS,
  type AppSourceRecord,
  type DeveloperSourceRecord,
  type SourceOperation,
  type SourceRecord,
} from './contract.js';
import { normalizeSourcePublicKey } from './proof.js';
import { SourceStore } from './firestore.js';

export { ADMIN_WORK_MS };

export type SourceAdminCommand = 'status' | 'register-app' | 'register-developer' | 'disable' | 'enable' | 'delete';
const COMMANDS: readonly SourceAdminCommand[] = ['status', 'register-app', 'register-developer', 'disable', 'enable', 'delete'];

export interface SourceAdminRequest {
  readonly command: SourceAdminCommand;
  readonly project: string;
  readonly database: string;
  readonly namespace: string;
  readonly source?: string | undefined;
  readonly expect?: string | undefined;
}

export type SourceAdminCode = 'usage' | 'invalid_input' | 'target_mismatch' | 'status' | 'created' | 'changed' | 'conflict' | 'missing' | 'deleted' | 'unavailable' | 'timed_out';

export interface SourceAdminResult {
  readonly code: SourceAdminCode;
  readonly source?: string;
  readonly kind?: string;
  readonly state?: string;
  readonly version?: string;
}

const NEEDS_SOURCE: readonly SourceAdminCommand[] = ['status', 'disable', 'enable', 'delete'];
const NEEDS_EXPECT: readonly SourceAdminCommand[] = ['disable', 'enable', 'delete'];
const VERSION = /^(?:absent|[0-9]{1,16})$/;

/** argv（command＋--project/--database/--namespace＋必要な--source/--expect）。不正・重複・未知はnull。 */
export function parseSourceAdminArgs(argv: readonly string[]): SourceAdminRequest | null {
  const [command, ...rest] = argv;
  if (!COMMANDS.includes(command as SourceAdminCommand) || rest.length % 2 !== 0) return null;
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index];
    const value = rest[index + 1];
    if (name === undefined || value === undefined || !['--project', '--database', '--namespace', '--source', '--expect'].includes(name) || values.has(name)) return null;
    values.set(name, value);
  }
  const cmd = command as SourceAdminCommand;
  const source = values.get('--source');
  const expect = values.get('--expect');
  if (NEEDS_SOURCE.includes(cmd) !== (source !== undefined) || NEEDS_EXPECT.includes(cmd) !== (expect !== undefined)) return null;
  if ((source !== undefined && !SOURCE_ID.test(source)) || (expect !== undefined && !VERSION.test(expect))) return null;
  const project = values.get('--project');
  const database = values.get('--database');
  const namespace = values.get('--namespace');
  if (project === undefined || database === undefined || namespace === undefined) return null;
  return Object.freeze({ command: cmd, project, database, namespace, source, expect });
}

export interface RegistrationInput {
  readonly operations: readonly SourceOperation[];
  readonly appId?: string;
  readonly uid?: string;
  readonly publicKey?: string;
  /** epoch ms、またはnull（管理者が明示した無期限）。 */
  readonly expiresAt?: number | null;
}

/** 登録の標準入力（1行JSON、1KiBまで）。appは{appId,operations}、developerは{uid,publicKey,operations,expiresAt}。 */
export function parseRegistrationInput(command: 'register-app' | 'register-developer', input: Buffer, projectNumber: string, now: number): RegistrationInput | null {
  let value: unknown;
  try {
    const text = input.toString('utf8').trim();
    if (text.length === 0 || text.length > 1024 || text.includes('\n')) return null;
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const fields = value as Record<string, unknown>;
  const keys = Object.keys(fields).sort();
  const operations = fields.operations;
  if (!Array.isArray(operations) || operations.length < 1 || new Set(operations).size !== operations.length) return null;
  if (!operations.every((item) => (SOURCE_OPERATIONS as readonly unknown[]).includes(item))) return null;
  if (command === 'register-app') {
    if (keys.join(',') !== 'appId,operations' || appIdProjectNumber(fields.appId) !== projectNumber) return null;
    return { operations: operations as SourceOperation[], appId: fields.appId as string };
  }
  if (keys.join(',') !== 'expiresAt,operations,publicKey,uid' || !isAdminUid(fields.uid) || typeof fields.publicKey !== 'string') return null;
  const publicKey = normalizeSourcePublicKey(fields.publicKey);
  if (publicKey === null) return null;
  let expiresAt: number | null;
  if (fields.expiresAt === 'never') expiresAt = null;
  else if (typeof fields.expiresAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(fields.expiresAt)) {
    expiresAt = Date.parse(fields.expiresAt);
    if (!Number.isSafeInteger(expiresAt) || !(expiresAt > now)) return null;
  } else return null;
  return { operations: operations as SourceOperation[], uid: fields.uid as string, publicKey, expiresAt };
}

export function newSourceId(): string {
  const bytes = randomBytes(17);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < 26) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `src_${out}`;
}

export function newSourceGeneration(): string {
  return randomBytes(16).toString('base64url');
}

function describe(record: SourceRecord | null, version: string): SourceAdminResult {
  if (record === null) return { code: 'status', state: 'absent', version };
  return { code: 'status', source: record.sourceId, kind: record.kind, state: record.state, version };
}

export interface SourceAdminDeps {
  readonly store: Pick<SourceStore, 'status' | 'create' | 'change'>;
  readonly hasher?: SecretHasher | undefined;
  readonly namespace: string;
  readonly projectId: string;
  readonly projectNumber: string;
  readonly now: () => number;
}

/** 1操作（期待版の一致・新ID・新世代はここで1回だけ決める）。 */
export async function runSourceAdmin(request: SourceAdminRequest, input: RegistrationInput | null, deps: SourceAdminDeps): Promise<SourceAdminResult> {
  try {
    const now = deps.now();
    if (request.command === 'status') {
      const { record, version } = await deps.store.status(request.source!);
      return describe(record, version);
    }
    if (request.command === 'register-app' || request.command === 'register-developer') {
      if (input === null) return { code: 'invalid_input' };
      const sourceId = newSourceId();
      const base = { schemaVersion: 1 as const, sourceId, state: 'active' as const, generation: newSourceGeneration(), operations: [...input.operations], createdAt: now, updatedAt: now };
      let record: AppSourceRecord | DeveloperSourceRecord;
      if (request.command === 'register-app') record = { ...base, kind: 'app', appId: input.appId! };
      else {
        if (deps.hasher === undefined) return { code: 'unavailable' };
        const identityHash = connectIdentityHash(deps.hasher, deps.namespace, { projectId: deps.projectId, uid: input.uid! });
        record = { ...base, kind: 'developer', publicKey: input.publicKey!, identityHash, expiresAt: input.expiresAt ?? null };
      }
      const created = await deps.store.create(record);
      return created === 'created' ? { code: 'created', source: sourceId, kind: record.kind, state: 'active', version: String(now) } : { code: 'conflict' };
    }
    const generation = newSourceGeneration();
    const outcome = await deps.store.change(request.source!, request.expect!, (current): SourceRecord | null => {
      // 版は前回より必ず大きくする（同じmsの連続変更でも期待版が変わる）。
      const updatedAt = Math.max(now, current.updatedAt + 1);
      // 削除は物理削除（App ID・公開鍵・identityHash・日時を残さない）。旧Grant・承認は不在として拒否される。
      if (request.command === 'delete') return null;
      if (request.command === 'disable') return { ...current, state: 'disabled', updatedAt };
      // 有効化は常に新しい世代（停止前のGrant・承認は復活しない）。
      return { ...current, state: 'active', generation, updatedAt };
    });
    if (outcome.kind === 'deleted') return { code: 'deleted', source: request.source!, state: 'absent', version: 'absent' };
    if (outcome.kind !== 'changed') return { code: outcome.kind };
    const record = outcome.record;
    return { code: 'changed', source: record.sourceId, kind: record.kind, state: record.state, version: String(record.updatedAt) };
  } catch {
    // SourceUnavailableError・SDKの失敗とも結果不明（再実行で上書きせず、statusで照合する）。
    return { code: 'unavailable' };
  }
}

export function formatSourceAdminResult(result: SourceAdminResult): string {
  return `${JSON.stringify(result)}\n`;
}

/** 実SDKを開く（明示実行の時だけ）。期待対象が編集済みの配置設定と一致しなければtarget_mismatch。 */
export async function openSourceAdmin(
  config: DeploymentConfig,
  request: SourceAdminRequest,
  operation: { readonly deadlineAt: number; readonly signal: AbortSignal },
): Promise<{ readonly deps: SourceAdminDeps; readonly close: () => Promise<void> } | 'target_mismatch'> {
  if (request.project !== config.projectId || request.database !== config.databaseId || request.namespace !== config.connectNamespace) return 'target_mismatch';
  checkAdminEnvironment(process.env, config.projectId);
  const sdk = await openAccessAdminSdk(config, operation);
  let hasher: SecretHasher | undefined;
  if (request.command === 'register-developer') {
    const key = await sdk.readIdentifierKey(operation);
    hasher = createHmacHasher(key);
  }
  const clock = { now: () => Date.now() };
  return {
    deps: { store: new SourceStore({ db: sdk.db, namespace: config.connectNamespace, clock }), hasher, namespace: config.connectNamespace, projectId: config.projectId, projectNumber: config.projectNumber, now: clock.now },
    close: () => sdk.close(),
  };
}
