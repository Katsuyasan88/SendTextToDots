# API とイベント

[English](API_EN.md) | 日本語

source 0.3.0の契約です。送信APIは `/v2/commands` 系、要求とEventsの `schemaVersion` は整数2、イベント名は `text.submitted` です。入力元が送信ごとに渡した任意の本文（下の上限・期限・認証の条件内）を、本人が購読した送信先へそのまま届けます。方向・定型task・保存したshortcut等のmetadataは契約に含みません。0.2.0以前のv1契約とは互換性がなく、旧route・旧schema・旧イベント名は受け付けません（[INSTALL.md](INSTALL.md#030の互換性)）。値の正本は実装（`src/commands/input.ts`・`src/policy.ts`・`src/delivery/`・`src/events/contract.ts`）です。

## 1. 概要

- 送信API（Functions）: 認証済みの入力元が1件の本文を送り、要求の処理中に本人の有効な購読先へ1回だけ署名付きHTTPSで届けます。キュー・自動再送・本文の保存はありません。
- MCP/OAuth service（Cloud Run）: 本人の接続（OAuth）と、MCP Eventsの購読（callback URL・secretの登録）を受けます。送信用のMCP toolはありません。

## 2. 送信API

`POST /v2/commands`。必須header: `Authorization: Bearer <Firebase ID token>`（Apple provider）、`Content-Type: application/json`、`Idempotency-Key: <commandId>`。

```json
{
  "schemaVersion": 2,
  "commandId": "d8d32ec5-9531-4b12-841a-b809ab45d3ef",
  "text": "今案内している電車の一本後で調べ直して",
  "createdAt": "2026-10-06T04:10:00Z",
  "expiresAt": "2026-10-06T04:11:00Z"
}
```

要求は上の5項目ちょうどで、全て必須です。

| 項目 | 規則 |
| --- | --- |
| schemaVersion | 整数2だけ（1・3等は400） |
| commandId | UUID（36文字のhex-hyphen形。版・variantは見ない）。Idempotency-Keyと大小を無視して一致。内部の照合と応答のcommandIdは小文字、Eventsのdataは送られた表記のまま |
| text | 送られた文字列をそのまま配送します。前後の空白・日本語・絵文字・改行・結合文字を保持し、切詰め・Unicode正規化・定型文への置換をしません。空・空白だけ（trimで判定）・対にならないsurrogateは不可。UTF-8で4096 byte以下 |
| createdAt・expiresAt | UTCのRFC 3339（大文字T/Z、小数秒なしか1〜3桁、1970〜9999年の実在日時）、expiresAt＝createdAt＋60秒 |
| 時計・期限 | createdAtがserver時刻より30秒超未来なら拒否。新規の受付時に残り10秒以上。有効期限はmin(expiresAt, 受信＋60秒) |
| 本文全体 | UTF-8で8192 byte以下（JSONのescapeを含むwireのbyte数）。BOM・不正なUTF-8・不正なJSONは拒否 |
| 件数 | owner当たり10件/分、burst 3件 |
| その他 | 未知field・欠落・誤った型・同名keyの重複（escapeを解いた同名を含む）は400。`direction`・`taskId`・`taskLabel`・`revision`・任意のmetadata objectも未知fieldとして400。ownerId・購読ID・callback URL・secretは受けない（ownerはtoken、送信先は有効な購読から決まる） |

応答と状態:

| 操作 | 応答 |
| --- | --- |
| 新規POST | 要求内で処理しHTTP 200＋`state`（delivered / failed / cancelled / expired / delivery_unknown） |
| 同じIDの再POST | 同じ内容（5項目の値が同じ。key順・JSONの空白・escape表記の違いは同じ内容）なら保存済みの状態だけ（処理中は202 in_flight）。textや日時が違えば409 idempotency_conflict。再配送しない。時刻を更新した新しい内容を同じIDで送り直す救済はありません |
| `GET /v2/commands/{commandId}` | 状態の照会だけ。他ownerと不在は同じ404 |
| `POST /v2/commands/{commandId}/cancel` | 送出前ならcancelled。送出権の確定後はdelivery_unknown（届いたHTTPは撤回できない）。元のPOSTより先に届いた取消は、その後の同じIDのPOSTを本文に関わらずcancelledにします |

状態応答は `commandId`・`state`、存在する場合の `expiresAt`、deliveredの時の `acknowledgedAt` だけで、本文・callback URLは含みません。状態は受信から24時間まで照会できます。

callbackの2xxはdelivered、5xx・送出後の応答不明はdelivery_unknown、429・その他4xx・TLS成立前の失敗はfailed、送出前の期限不足はexpired。410・redirect・不正な宛先はその購読を停止します。

旧v1のroute（`/v1/commands`・`/v1/commands/{commandId}`・`/v1/commands/{commandId}/cancel`）は404 not_foundで、処理を行いません。v2のrouteへの誤ったmethodは405 method_not_allowed、v2へ`schemaVersion` 1や旧項目を送ると400 invalid_requestです。新旧の変換・redirectはありません。

エラーは `{"error":{"code":"…","retryable":<boolean>}}`。主なcode: invalid_request(400)・authentication_required(401)・connection_revoked / access_denied(403)・not_found(404)・method_not_allowed(405)・subscription_required / destination_change_pending / idempotency_conflict(409)・command_expired / clock_skew(422)・rate_limited(429、Retry-After)・temporarily_unavailable(503)。retryableがtrueでも本文の自動再送はせず、同じIDの状態を照会してください。

利用許可: 新規POST（同じIDの再POSTを含む）は、運営者が明示登録した利用許可（[CONFIGURATION](CONFIGURATION.md#access-admin)）がactiveで、配送先の購読が現在の許可の世代で同意したGrantに結ばれている時だけ受け付けます。未登録・停止中・旧世代のGrantは403 `access_denied`（retryable false。接続の失効 `connection_revoked` とは別）、許可を確認できない時は503 `temporarily_unavailable` です。受付後に停止が確定した場合は送出権の確定時に再確認し、送らずに `failed` で終えます（既に送出権を得た1件は既存の契約どおり確定します）。状態の照会と取消は利用許可を条件にしません。

期限: 処理予算は受信から20秒か元の期限の短い方、外部HTTPは最大10秒、Functions timeoutは30秒。

ローカル送信画面 `/console` は、空の入力欄に利用者が入力した本文を同じ5項目の形でローカルhelper経由でAPIへ送ります（方向・定型文の選択はありません）。接続状態の表示と、明示の確認後に既存の `/v1/web/disconnect` で行う接続解除も同じ画面にあります。helperは利用者のBearer tokenを固定のAPI/MCP originへ中継し、ブラウザのOrigin・cookie・local nonceは転送しません。APIのCORSは引き続き設定のMCP originからの上の3 routeだけを許可します（許可header: authorization・content-type・idempotency-key、`Retry-After` を公開、wildcard・credential cookieなし）。localhostをCloud側の許可originへ追加する必要はありません。Originが付いた旧v1 routeや他のoriginは固定の403、Originの無い要求はCORS headerを付けずに通常の処理（v1は404）へ進みます。

## 3. 送信画面と接続状態

送信画面はCloud Runではなく、自分のパソコンで動くローカルhelperが配信します（[LOCAL_CONSOLE.md](LOCAL_CONSOLE.md)）。MCP serviceはOAuth interaction画面だけを配信し、`/console`・`/connect`とそのassetは未知pathと同じ404です。helperは押した操作だけを下のrouteへBearer tokenつきで中継します。

| endpoint | 内容 |
| --- | --- |
| `GET /v1/web/connection` | Bearer Firebase ID token。`{state, access}`（accessは `allowed`・`denied`・`unavailable`。UID・許可一覧・世代は返さない） |
| `POST /v1/web/disconnect` | 同ownerのGrant/購読を失効。`{state}` |
| `/interaction/{uid}`・`…/login`・`…/consent`・`…/deny`・`/interaction/app.js` | OAuth認可のinteraction（同origin・CSRF・毎回の明示同意）とその固定script |
| `/mcp` | MCP（Bearer access token、scope `sttd:events`） |
| `/.well-known/*`・`/oauth/*` | OAuth metadata・token等（`oidc-provider`） |

`/v1/web/*`・OAuthのrouteとscopeは送信APIの版とは別で、0.3.0でも変わりません。

表示言語: HTML画面（`/console`・OAuth interaction・利用者向けOAuthエラー）は英語/日本語で描きます。`?lang=en` / `?lang=ja` の明示選択は表示専用のsession cookie `sttd_language`（Path=/・SameSite=Lax・Secure・期限なし）へ保存し、送信画面での言語切替も同じcookieをbrowserで書くため最後の選択が残ります。無い時は `Accept-Language` の優先順位（日本語選好ならja、それ以外はen）で決めます。このcookieを認証・認可に使わず、machine code・field・scope・route・送信本文は翻訳しません。

状態の優先順位: 有効なGrantが無い→unlinked、承認待ちの送信先置換→change_pending、有効な購読→subscribed、直前の購読が期限切れ→expired、それ以外（未購読・購読取消）→linked。

利用許可（`access`）は購読の`state`と別に返します。許可を読めない時もHTTP 200で`state`と`access: "unavailable"`を返し、新しい利用はできません。OAuth interactionのloginでは、未登録・停止中の本人は403 `access_denied`（画面は「このサービスの利用が許可されていません。運営者へ確認」）でownerを作りません。同意の時点で停止・再登録を跨いだ場合も同じ案内の403画面でGrantを使える状態にしません。code交換・refreshは同じ世代のGrantだけで、そうでなければ既存の`invalid_grant`です。MCPの`events/subscribe`（延長・secret更新を含む）は既存のForbidden（`data.reason` = `access_revoked`）で、challengeの前と最終の保存時の両方で確かめます。`events/unsubscribe`・接続解除・状態照会・取消は利用許可を条件にしません。

## 4. MCP Events

`/mcp` の `server/discover` は `events:{}` と `tools:{}` を宣言し、`tools/list` は常に空です。`events/list` が返す唯一のイベントは `text.submitted`（認証済みの入力元が送った任意の本文を、本人の購読先へ配送する）です。submittedは本文の受付・配送のイベント名で、受信側の処理完了を意味しません。購読・配送は認証ownerに限られます。旧名 `shortcut.triggered` 等の未知のイベント名の購読・解除はNotFound（-32011、`data.kind` = `event`）で、保存・暗号・challengeへ進みません。

| 購読の入力 | 規則 |
| --- | --- |
| callback URL | UTF-8・1〜2048 byte、HTTPS/443、userinfo・fragment・空白・制御文字・backslashなし、安全な送出のIP検査に合格 |
| secret | `whsec_`＋base64（24〜64 byte） |
| ttlMs | 省略＝24時間、null＝無期限、正の整数は24時間まで |
| cursor | 省略かnullだけ（履歴再生なし） |

購読は署名付きchallenge（最大10秒）が一致した時だけ有効になります。別のcallbackへの置換は本人の承認待ちになります。

payload（`data`）は `schemaVersion`(2)・`commandId`・`text`・`expiresAt` の4項目ちょうどで、この順に並び、追加項目はありません（`createdAt` も含みません）。`text` は送信APIが受け付けた本文と同じ文字列です。

```json
{
  "eventId": "7c0f2a8e-1d34-8b6a-9f10-2e4d6c8a0b12",
  "name": "text.submitted",
  "timestamp": "2026-10-06T04:10:00.000Z",
  "data": { "schemaVersion": 2, "commandId": "d8d32ec5-9531-4b12-841a-b809ab45d3ef", "text": "今案内している電車の一本後で調べ直して", "expiresAt": "2026-10-06T04:11:00.000Z" },
  "cursor": null
}
```

`timestamp` はserverの受信時刻、`expiresAt` はserverが決めた有効期限（min(expiresAt, 受信＋60秒)）で、どちらもISO 8601（ミリ秒付きUTC）です。`events/list` の `payloadSchema` はJSON Schemaで上の4項目を `required`、`additionalProperties: false` とします。schemaの `text` の `minLength` 1・`maxLength` 4096は文字数の粗い上限で、4096 UTF-8 byte・空白だけ・対にならないsurrogateの厳密な検査は送信APIの入力検証が行います。

eventIdは識別子鍵＋owner/commandIdのHMACから作るUUIDv8で、同じowner・同じcommandIdでは同じ値、別ownerでは別の値です。署名はStandard Webhooks形式で、送るbytesそのものに署名します。secret回転中の5分は新旧両方で署名します。`expiresAt` を含めても受信側が期限を守る保証にはなりません。


<a id="firebase-sessions"></a>

## Firebaseのsessionと自動送信

現在の認証はFirebase AuthenticationのApple providerだけに対応し、Dotsを接続した本人と同じFirebase project・UIDを使います。このAPI契約を満たすアプリやスクリプトが入力元になり、特定のスマートフォン・時計・入力元アプリは必須ではありません。受信側MCPのOAuth接続と、入力元のFirebase sessionは別です。

Firebase ID tokenは約1時間で期限切れになります。Firebase clientの認証sessionを使うアプリは、送信前にSDKで有効なtokenを取得してください。ローカル送信画面では認証が必要な操作ごとに`user.getIdToken()`を呼び、期限切れまたは期限間近なら更新できます。通常は毎時間Appleへ手動で再ログインする必要はありません。サインアウト・失効・認証上の問題があれば再ログインが必要になることはあります。[Firebaseのsession寿命](https://firebase.google.com/docs/auth/admin/manage-sessions)と[getIdToken](https://firebase.google.com/docs/reference/js/auth.user.md#usergetidtoken)も参照してください。

下のNode.js例は渡されたID tokenを使うだけで、ログインやtoken更新を行いません。長時間・無人で動く入力元は、対応する認証/session管理を自分で用意する必要があります。headlessのAppleログイン、token書出しtool、常駐送信process、長期の送信専用キー、自動再送は同梱していません。ブラウザからrefresh tokenを抽出する代わりに、SDKのsession用APIを使ってください。Firebase Web API keyは設定を識別するもので、本人のID tokenの代わりにはなりません。

<a id="direct-client-example"></a>

## 直接APIを使うclient例

配置・購読後、次を手元の`.mjs`ファイルに保存し、Node.js 22で実行します。`STTD_API_ORIGIN`へ配置済みHTTPS API origin、`STTD_FIREBASE_ID_TOKEN`へApple providerで認証した有効なFirebase ID tokenを設定してください。この環境変数は例のclient用で、server設定ではありません。tokenをGitや共有ログへ残さないでください。実行すると実メッセージ1件を送り、サービス費用が生じる可能性があります。
```js
// Node.js 22; set STTD_API_ORIGIN and STTD_FIREBASE_ID_TOKEN locally.
const origin = process.env.STTD_API_ORIGIN;
const token = process.env.STTD_FIREBASE_ID_TOKEN;
if (!origin || !token) throw new Error('Set the API origin and Firebase ID token');
const commandId = crypto.randomUUID();
console.log('commandId:', commandId); // Keep this ID even if the request fails.
const now = Date.now();
const response = await fetch(new URL('/v2/commands', origin), {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': commandId,
  },
  body: JSON.stringify({
    schemaVersion: 2,
    commandId,
    text: 'Hello Dots',
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
  }),
});
console.log(response.status, await response.json());
```
要求は5項目ちょうどです。`Idempotency-Key`は`commandId`と一致させ、`expiresAt`は`createdAt`のちょうど60秒後、受付時に残り10秒以上とします。本文はUTF-8で4096 byteまで。例は実行ごとに現在時刻とUUIDを作るため、再実行は新しいcommandの送信になります。

応答の一例は`{"commandId":"d8d32ec5-9531-4b12-841a-b809ab45d3ef","state":"delivered","expiresAt":"2026-10-25T00:01:00.000Z","acknowledgedAt":"2026-10-25T00:00:01.000Z"}`です。実際のID・時刻は異なります。新規POSTは通常HTTP 200で`delivered`・`failed`・`cancelled`・`expired`・`delivery_unknown`のいずれかを返します。同一commandの再POSTは処理中なら202 `in_flight`の場合があります。HTTP 2xxだけで配送成功とせず`state`を確認してください。`delivered`はcallback受領で、Dotsの処理完了ではありません。

要求や応答の解析に失敗してもIDを使えるよう、送信前に表示します。結果不明時に自動再送せず、同じ認証で`GET /v2/commands/{commandId}`を照会してください。error・中止・件数枠・冪等性の詳細は[API](API.md)を参照してください。
