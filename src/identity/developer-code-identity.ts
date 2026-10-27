// コード由来の内部利用単位（code identity）の交換・照合・コンソール用token。
//   交換: (1) 消費とinteraction束縛のtransaction → (2) transaction外でFirebase createUser（専用の推測不能UID）→ (3) custom token署名
//         （認証markerと非秘密family参照）→ (4) 同じissuance/発行元世代/非取消を再確認してidentityとUID1件の利用許可を確定。
//         どの段階の失敗・応答消失でも消費をissuedへ戻さず、failedで止める（許可なし）。既存UIDエラーで任意の既存UIDを採用しない。
//   照合: API/MCPが共有するIdentityVerifier（identity/firebase.ts）がcustom providerのtokenをmarker・UID形・保存identityのstate/familyで確かめる。
//   コンソール: 発行元helperの照会secretの証明があるactive operationだけ、同じUIDへのcustom tokenを返す（6桁だけでは取得できない）。
// Appleの既存利用単位へ自動で紐付けない（新しい利用単位ごとに専用UID）。

import {
  CODE_FAMILY_CLAIM,
  CODE_MARKER_CLAIM,
  CODE_MARKER_VALUE,
  DeveloperLoginError,
  EXCHANGE_BODY_MAX_BYTES,
  EXCHANGE_BUDGET_MS,
  isCodeUid,
  parseCodeInput,
  type Clock,
} from './developer-login.js';
import type { CodeIdentityState, DeveloperLoginStore } from './developer-login-store.js';

/** firebase-admin Authのうち、code identityに要る範囲（helper/接続server側だけ）。 */
export interface CodeAuthAdmin {
  createUser(properties: { readonly uid: string; readonly disabled: false }): Promise<unknown>;
  createCustomToken(uid: string, claims: Record<string, unknown>): Promise<string>;
}

/** API/MCPの共通照合が使う参照（読取りだけ）。 */
export interface CodeIdentityLookup {
  status(uid: string, familyId: string | null): Promise<CodeIdentityState>;
}

export function createCodeIdentityLookup(store: Pick<DeveloperLoginStore, 'identityHashOf' | 'identityState'>): CodeIdentityLookup {
  return Object.freeze({
    async status(uid: string, familyId: string | null): Promise<CodeIdentityState> {
      if (!isCodeUid(uid)) return 'missing';
      const found = await store.identityState(store.identityHashOf(uid));
      if (found.state !== 'active') return found.state;
      // familyが違うtokenは旧/偽造（同じUIDに別familyは無い）。
      if (familyId !== null && found.familyId !== familyId) return 'revoked';
      return 'active';
    },
  });
}

/** 元期限までにSDKが返らなければ待つのをやめる（開始済みの副作用は取り消さない。結果不明は失敗として扱う）。 */
export async function within<T>(task: () => Promise<T>, deadline: number, clock: Clock): Promise<T> {
  const remaining = deadline - clock.now();
  if (remaining <= 0) throw new DeveloperLoginError('unavailable');
  let timer: ReturnType<typeof setTimeout> | undefined;
  const running = task();
  running.catch(() => undefined);
  try {
    return await Promise.race([
      running,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new DeveloperLoginError('unavailable')), remaining);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function codeClaims(familyId: string): Record<string, unknown> {
  return { [CODE_MARKER_CLAIM]: CODE_MARKER_VALUE, [CODE_FAMILY_CLAIM]: familyId };
}

export type ExchangeOutcome =
  | { readonly kind: 'token'; readonly customToken: string }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'rate_limited' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'unavailable' };

export interface DeveloperCodeExchangeDeps {
  readonly store: Pick<DeveloperLoginStore, 'consume' | 'fail' | 'activate'>;
  readonly auth: CodeAuthAdmin;
  /** 接続保存の既存identity用HMAC（access/{identityHash}の位置。connect/firestore.tsのconnectIdentityHash）。 */
  readonly accessIdentityHash: (uid: string) => string;
  readonly clock: Clock;
}

export interface DeveloperCodeExchange {
  exchange(input: { readonly code: unknown; readonly interactionKey: string; readonly sourceKey: string }): Promise<ExchangeOutcome>;
}

export function createDeveloperCodeExchange(deps: DeveloperCodeExchangeDeps): DeveloperCodeExchange {
  const { store, auth, accessIdentityHash, clock } = deps;
  return Object.freeze({
    async exchange(input: { readonly code: unknown; readonly interactionKey: string; readonly sourceKey: string }): Promise<ExchangeOutcome> {
      const code = parseCodeInput(input.code);
      if (code === null) return { kind: 'rejected' };
      const deadline = clock.now() + EXCHANGE_BUDGET_MS;
      let consumed;
      try {
        consumed = await store.consume({ code, interactionKey: input.interactionKey, sourceKey: input.sourceKey, deadline });
      } catch (error) {
        if (error instanceof DeveloperLoginError && error.code === 'invalid_request') return { kind: 'rejected' };
        return { kind: 'unavailable' };
      }
      if (consumed.kind !== 'consumed') return consumed;
      const { operationIdHash, issuanceId, uid, familyId } = consumed;
      // ここから先は消費済み。失敗はfailedで止め、コードを未使用へ戻さない。
      const stop = async (): Promise<ExchangeOutcome> => {
        try {
          await store.fail({ operationIdHash, issuanceId });
        } catch {
          // failedの記録ができなくてもprovisioningのまま許可は作られない（activate前）。
        }
        return { kind: 'failed' };
      };
      try {
        await within(() => auth.createUser({ uid, disabled: false }), deadline, clock);
        const customToken = await within(() => auth.createCustomToken(uid, codeClaims(familyId)), deadline, clock);
        if (typeof customToken !== 'string' || customToken.length === 0 || customToken.length > 8192) return await stop();
        const activated = await store.activate({ operationIdHash, issuanceId, uid, accessIdentityHash: accessIdentityHash(uid), deadline });
        if (activated.kind !== 'active') return await stop();
        return { kind: 'token', customToken };
      } catch {
        // UID既存・署名失敗・応答消失を区別せず止める（既存UIDの採用・再試行をしない）。
        return stop();
      }
    },
  });
}

/** プラグイン接続画面のコード入力の判定（kms-serverが既存の固定エラーへ写す）。 */
export type CodeEntryResult =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'invalid_request' }
  | { readonly kind: 'link_unavailable' }
  | { readonly kind: 'exchanged'; readonly outcome: ExchangeOutcome };

export interface CodeEntryPorts {
  /** 機能offはnull（固定404。本文・cookieを読まない）。 */
  readonly exchange: DeveloperCodeExchange | null;
  /** issuerのorigin（Origin headerの完全一致先）。 */
  readonly origin: string;
  /** provider自身のinteraction cookieと元browser・resource/scopeの確認（拒否はthrow）。 */
  checkInteraction(): Promise<void>;
  /** 現行interactionのCSRFか。 */
  csrfAccepts(csrf: string): Promise<boolean>;
  readonly sourceKey: string;
}

const CSRF_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;

/**
 * コード入力（POST /interaction/{uid}/code）。Origin・JSON・1KiB・interaction cookie・CSRFをコード消費の前に確かめる。
 * どれかが不成立ならexchangeを呼ばない（試行件数も消費しない）。
 */
export async function developerCodeEntry(req: AsyncIterable<unknown> & { readonly headers: Record<string, string | string[] | undefined> }, interactionKey: string, ports: CodeEntryPorts): Promise<CodeEntryResult> {
  if (ports.exchange === null) return { kind: 'not_found' };
  if (req.headers.origin !== ports.origin) return { kind: 'forbidden' };
  const type = req.headers['content-type'];
  if (typeof type !== 'string' || type.split(';')[0]?.trim().toLowerCase() !== 'application/json') return { kind: 'invalid_request' };
  const declared = Number(req.headers['content-length']);
  if (!Number.isSafeInteger(declared) || declared <= 0 || declared > EXCHANGE_BODY_MAX_BYTES) return { kind: 'invalid_request' };
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > EXCHANGE_BODY_MAX_BYTES) return { kind: 'invalid_request' };
    chunks.push(buffer);
  }
  let body: unknown;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return { kind: 'invalid_request' };
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return { kind: 'invalid_request' };
  const keys = Object.keys(body);
  const { csrf, code } = body as { csrf?: unknown; code?: unknown };
  if (keys.length !== 2 || typeof csrf !== 'string' || !CSRF_PATTERN.test(csrf) || typeof code !== 'string' || code.length > 16) {
    return { kind: 'invalid_request' };
  }
  await ports.checkInteraction();
  if (!(await ports.csrfAccepts(csrf))) return { kind: 'link_unavailable' };
  return { kind: 'exchanged', outcome: await ports.exchange.exchange({ code, interactionKey, sourceKey: ports.sourceKey }) };
}

/** 後から結ぶcode identity照合（起動口がverifierを先に作り、秘密の読込み後に保存層を結ぶ）。未結合は機能offとして扱う。 */
export interface LateCodeIdentityCheck {
  enabled(): boolean;
  status(uid: string, familyId: string | null): Promise<CodeIdentityState>;
  bind(lookup: CodeIdentityLookup): void;
}

export function createLateCodeIdentityCheck(): LateCodeIdentityCheck {
  let bound: CodeIdentityLookup | null = null;
  return Object.freeze({
    enabled: () => bound !== null,
    async status(uid: string, familyId: string | null): Promise<CodeIdentityState> {
      if (bound === null) throw new DeveloperLoginError('feature_off');
      return bound.status(uid, familyId);
    },
    bind(lookup: CodeIdentityLookup): void {
      // 1回だけ（別の保存層へ付け替えない）。
      if (bound !== null) throw new DeveloperLoginError('conflict');
      bound = lookup;
    },
  });
}

export type ConsoleTokenOutcome =
  | { readonly kind: 'active'; readonly customToken: string }
  | { readonly kind: 'pending' }
  | { readonly kind: 'ended' };

/** 発行元helperだけが呼ぶ: 照会secretの証明があるactive operationへ同じUIDのcustom tokenを署名する。 */
export async function consoleToken(
  store: Pick<DeveloperLoginStore, 'claim'>,
  auth: Pick<CodeAuthAdmin, 'createCustomToken'>,
  input: { readonly claimSecret: string; readonly operationId: string },
  clock: Clock,
): Promise<ConsoleTokenOutcome> {
  const deadline = clock.now() + EXCHANGE_BUDGET_MS;
  const claimed = await store.claim(input);
  if (claimed.kind !== 'active') return claimed;
  let customToken: string;
  try {
    customToken = await within(() => auth.createCustomToken(claimed.uid, codeClaims(claimed.familyId)), deadline, clock);
  } catch {
    throw new DeveloperLoginError('unavailable');
  }
  if (typeof customToken !== 'string' || customToken.length === 0) throw new DeveloperLoginError('unavailable');
  return { kind: 'active', customToken };
}
