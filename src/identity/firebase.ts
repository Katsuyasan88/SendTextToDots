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
}

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

export function createFirebaseAdminVerifier(deps: { readonly auth: AdminAuthLike; readonly projectId: string }): IdentityVerifier {
  const { auth, projectId } = deps;
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
      if (firebase?.sign_in_provider !== APPLE_PROVIDER_ID) throw new IdentityError('wrong_provider');
      const { sub, auth_time: authTime } = decoded;
      if (typeof sub !== 'string' || sub.length === 0 || sub.length > 128) throw new IdentityError('invalid');
      if (typeof authTime !== 'number' || !Number.isSafeInteger(authTime) || authTime <= 0) throw new IdentityError('invalid');
      return Object.freeze({ projectId, uid: sub, authTimeSec: authTime });
    },
    async accountStatus(uid, sinceSec) {
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

