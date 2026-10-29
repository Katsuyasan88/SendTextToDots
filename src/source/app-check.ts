// Firebase App Check方式のverifier（firebase-admin/app-checkのverifyTokenを`consume: true`で毎回呼ぶ）。実runtimeは
// google-runtime/development.tsが同じ配置のAdmin App（getAppCheck）を渡す。試験だけが同じ形の合成portを渡す。
// 成功は「この配置projectのApp IDが発行し、今回初めて消費したtoken」であることだけを意味する。tokenはbearerで、本文・宛先・本人tokenへ
// 暗号学的に束縛されず、未消費tokenの盗用による先取り・中継は防げない。個々のtokenがnative provider由来かdebug資格由来かも判別しない。
// 欠落・不正・消費済み・消費結果不明・SDK/通信障害は全て通さない（開発者方式・互換へ降格しない）。元の例外・tokenは返さない。

/** 実adapterが使うfirebase-adminのAppCheckの範囲（`getAppCheck(app)`の戻り値）。 */
export interface AppCheckAdminLike {
  verifyToken(
    appCheckToken: string,
    options?: { consume?: boolean },
  ): Promise<{ readonly appId: string; readonly token: Readonly<Record<string, unknown>>; readonly alreadyConsumed?: boolean | undefined }>;
}

export type AppCheckOutcome =
  | { readonly kind: 'verified'; readonly appId: string }
  | { readonly kind: 'rejected'; readonly reason: 'invalid' | 'consumed' | 'wrong_project' }
  | { readonly kind: 'unavailable' };

export interface AppCheckVerifier {
  /** tokenを検証し消費する（同じtokenの2回目以降はconsumed）。 */
  consume(token: string): Promise<AppCheckOutcome>;
}

const ISSUER_PREFIX = 'https://firebaseappcheck.googleapis.com/';

function codeOf(error: unknown): string {
  return typeof error === 'object' && error !== null && typeof (error as { code?: unknown }).code === 'string' ? (error as { code: string }).code : '';
}

/** projectNumber・projectIdは検証済みの配置設定の値（同じ配置projectのapp以外を受けない）。 */
export function createAppCheckVerifier(deps: { readonly appCheck: AppCheckAdminLike; readonly projectNumber: string; readonly projectId: string }): AppCheckVerifier {
  const { appCheck, projectNumber, projectId } = deps;
  if (typeof appCheck !== 'object' || appCheck === null || typeof appCheck.verifyToken !== 'function') throw new Error('app check verifier invalid');
  const audiences = [`projects/${projectNumber}`, `projects/${projectId}`];
  return Object.freeze({
    async consume(token: string): Promise<AppCheckOutcome> {
      let result: Awaited<ReturnType<AppCheckAdminLike['verifyToken']>>;
      try {
        result = await appCheck.verifyToken(token, { consume: true });
      } catch (error) {
        // tokenの形・署名・期限の拒否だけをinvalid。他（権限・通信・未知）は結果不明として通さない。
        const code = codeOf(error);
        return code === 'app-check/invalid-argument' || code === 'app-check/app-check-token-expired' ? { kind: 'rejected', reason: 'invalid' } : { kind: 'unavailable' };
      }
      if (typeof result !== 'object' || result === null) return { kind: 'unavailable' };
      // consumeを要求したのに消費結果が無い応答は、結果不明として通さない。
      if (result.alreadyConsumed === true) return { kind: 'rejected', reason: 'consumed' };
      if (result.alreadyConsumed !== false) return { kind: 'unavailable' };
      const decoded = result.token;
      const aud: unknown = decoded?.aud;
      const audienceOk = Array.isArray(aud) && aud.some((value) => audiences.includes(value as string));
      if (!audienceOk || decoded.iss !== `${ISSUER_PREFIX}${projectNumber}`) return { kind: 'rejected', reason: 'wrong_project' };
      if (typeof result.appId !== 'string' || decoded.sub !== result.appId) return { kind: 'rejected', reason: 'invalid' };
      return { kind: 'verified', appId: result.appId };
    },
  });
}
