// Firebase Authentication（Apple providerのみ）のID token検証portと、firebase-adminのAuthを使う実adapter（Appの所有はSDK起動口）。
// 製品の検証は verifyIdToken(token, checkRevoked=true) に任せ、その後にSendTextToDotsの条件（同じproject・apple.com・tenantなし）を足す。
// 未検証のJWT decodeやUIDの自己申告を本人確認に使わない（下のclassifyだけが、SDKが拒否した後の分類にpayloadを読む）。
// 失敗は固定のcodeだけで、元の例外・token・uidを持たせない。

export const APPLE_PROVIDER_ID = 'apple.com';
const ISSUER_PREFIX = 'https://securetoken.google.com/';
const PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

export type IdentityFailure =
  | 'invalid'
  | 'expired'
  | 'revoked'
  | 'disabled'
  | 'deleted'
  | 'wrong_project'
  | 'wrong_provider'
  | 'unavailable';

export class IdentityError extends Error {
  constructor(readonly code: IdentityFailure) {
    super(`identity: ${code}`);
    this.name = 'IdentityError';
  }
}

/** 検証済みの本人。uidはFirebaseのUID（Appleのraw IDではない）。 */
export interface VerifiedIdentity {
  readonly projectId: string;
  readonly uid: string;
  /** Firebaseへの認証時刻（epoch秒）。 */
  readonly authTimeSec: number;
  /** 開発者向けコード由来の利用単位だけ'developer_code'（Appleは省略）。 */
  readonly method?: 'developer_code';
}

/**
 * 開発者向けコードのidentity照合（任意。未設定ならcustom providerは従来どおりwrong_provider）。providerがcustomというだけでは受理せず、
 * 認証marker・専用UID形・保存されたcode identityのstate/familyを確かめる。
 */
export interface CodeIdentityCheck {
  status(uid: string, familyId: string | null): Promise<'active' | 'revoked' | 'missing'>;
  /** 任意。falseの間は機能offと同じ（起動口が秘密の読込み後に照合を結ぶまで）。 */
  enabled?(): boolean;
}

function codeEnabled(check: CodeIdentityCheck | undefined): check is CodeIdentityCheck {
  return check !== undefined && (check.enabled === undefined || check.enabled() === true);
}
const CUSTOM_PROVIDER_ID = 'custom';
const CODE_UID = /^sttdc_[A-Za-z0-9_-]{32}$/;
const CODE_FAMILY = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type AccountStatus = 'active' | 'disabled' | 'revoked' | 'deleted';

export interface IdentityVerifier {
  readonly projectId: string;
  /** 署名・issuer・audience・期限・失効/disabled・apple.comを確かめる。失敗はIdentityError。 */
  verifyIdToken(idToken: string): Promise<VerifiedIdentity>;
  /**
   * MCP認可の交換・refresh時の再確認。sinceSecより後に失効（tokensValidAfterTime）していればrevoked。
   * 確認できない一時障害はIdentityError('unavailable')で、成功にしない。
   */
  accountStatus(uid: string, sinceSec: number): Promise<AccountStatus>;
}

/** 実adapterが使う firebase-admin の Auth の範囲。 */
export interface AdminAuthLike {
  verifyIdToken(idToken: string, checkRevoked?: boolean): Promise<Record<string, unknown>>;
  getUser(uid: string): Promise<{ readonly disabled: boolean; readonly tokensValidAfterTime?: string | undefined }>;
}

function codeOf(error: unknown): string {
  return typeof error === 'object' && error !== null && typeof (error as { code?: unknown }).code === 'string'
    ? (error as { code: string }).code
    : '';
}

/** SDKが拒否した後だけ、分類のためにpayloadのaudを読む。本人確認には使わない。 */
function unverifiedAudience(idToken: string): unknown {
  try {
    const part = idToken.split('.')[1];
    if (part === undefined) return undefined;
    return (JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as { aud?: unknown }).aud;
  } catch {
    return undefined;
  }
}

function classify(error: unknown, idToken: string, projectId: string): IdentityFailure {
  switch (codeOf(error)) {
    case 'auth/id-token-expired':
      return 'expired';
    case 'auth/id-token-revoked':
      return 'revoked';
    case 'auth/user-disabled':
      return 'disabled';
    case 'auth/user-not-found':
      return 'deleted';
    case 'auth/argument-error':
    case 'auth/invalid-argument':
    case 'auth/invalid-id-token': {
      const audience = unverifiedAudience(idToken);
      return typeof audience === 'string' && audience !== projectId ? 'wrong_project' : 'invalid';
    }
    default:
      return 'unavailable';
  }
}

async function codeStatus(codeIdentities: CodeIdentityCheck, uid: string, familyId: string | null): Promise<'active' | 'revoked' | 'missing'> {
  let status: unknown;
  try {
    status = await codeIdentities.status(uid, familyId);
  } catch {
    throw new IdentityError('unavailable');
  }
  if (status !== 'active' && status !== 'revoked' && status !== 'missing') throw new IdentityError('unavailable');
  return status;
}

export function createFirebaseAdminVerifier(deps: {
  readonly auth: AdminAuthLike;
  readonly projectId: string;
  readonly codeIdentities?: CodeIdentityCheck | undefined;
}): IdentityVerifier {
  const { auth, projectId, codeIdentities } = deps;
  if (!PROJECT_ID_PATTERN.test(projectId)) throw new Error('identity: invalid project id');
  return {
    projectId,
    async verifyIdToken(idToken) {
      if (typeof idToken !== 'string' || idToken.length === 0 || idToken.length > 4096) throw new IdentityError('invalid');
      let decoded: Record<string, unknown>;
      try {
        decoded = await auth.verifyIdToken(idToken, true);
      } catch (error) {
        throw new IdentityError(classify(error, idToken, projectId));
      }
      // SDKも確かめる項目だが、SendTextToDotsの条件として重ねて見る。
      if (decoded.aud !== projectId || decoded.iss !== `${ISSUER_PREFIX}${projectId}`) throw new IdentityError('wrong_project');
      const firebase = decoded.firebase as { sign_in_provider?: unknown; tenant?: unknown } | undefined;
      if (firebase?.tenant !== undefined) throw new IdentityError('wrong_project');
      const { sub, auth_time: authTime } = decoded;
      const subjectChecked = () => {
        if (typeof sub !== 'string' || sub.length === 0 || sub.length > 128) throw new IdentityError('invalid');
        if (typeof authTime !== 'number' || !Number.isSafeInteger(authTime) || authTime <= 0) throw new IdentityError('invalid');
        return { sub, authTime };
      };
      if (firebase?.sign_in_provider === CUSTOM_PROVIDER_ID) {
        const { sub, authTime } = subjectChecked();
        // 開発者向けコード: 機能offではcustomを受けない。marker・専用UID・familyと保存identityのactiveが揃った時だけ。
        if (!codeEnabled(codeIdentities)) throw new IdentityError('wrong_provider');
        const family = decoded.sttd_fam;
        if (decoded.sttd_dlc !== 1 || typeof family !== 'string' || !CODE_FAMILY.test(family) || !CODE_UID.test(sub)) {
          throw new IdentityError('wrong_provider');
        }
        const status = await codeStatus(codeIdentities, sub, family);
        if (status === 'missing') throw new IdentityError('deleted');
        if (status !== 'active') throw new IdentityError('revoked');
        return Object.freeze({ projectId, uid: sub, authTimeSec: authTime, method: 'developer_code' as const });
      }
      if (firebase?.sign_in_provider !== APPLE_PROVIDER_ID) throw new IdentityError('wrong_provider');
      const subject = subjectChecked();
      // code専用UIDの形はAppleとして受けない（rollback時に旧code identityをApple相当で通さない）。
      if (CODE_UID.test(subject.sub)) throw new IdentityError('wrong_provider');
      return Object.freeze({ projectId, uid: subject.sub, authTimeSec: subject.authTime });
    },
    async accountStatus(uid, sinceSec) {
      // code専用UIDは保存identityのstateも見る（再発行・取消でrefresh/交換を止める）。機能offではcode UIDを有効にしない。
      if (CODE_UID.test(uid)) {
        if (!codeEnabled(codeIdentities)) return 'revoked';
        const status = await codeStatus(codeIdentities, uid, null);
        if (status === 'missing') return 'deleted';
        if (status !== 'active') return 'revoked';
      }
      let user: Awaited<ReturnType<AdminAuthLike['getUser']>>;
      try {
        user = await auth.getUser(uid);
      } catch (error) {
        if (codeOf(error) === 'auth/user-not-found') return 'deleted';
        throw new IdentityError('unavailable');
      }
      if (user.disabled) return 'disabled';
      if (user.tokensValidAfterTime !== undefined) {
        const validSince = new Date(user.tokensValidAfterTime).getTime();
        if (!Number.isFinite(validSince)) throw new IdentityError('unavailable');
        if (sinceSec * 1000 < validSince) return 'revoked';
      }
      return 'active';
    },
  };
}

