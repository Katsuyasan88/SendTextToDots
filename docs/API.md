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

エラーは `{"error":{"code":"…","retryable":<boolean>}}`。主なcode: invalid_request(400)・authentication_required(401)・connection_revoked(403)・not_found(404)・method_not_allowed(405)・subscription_required / destination_change_pending / idempotency_conflict(409)・command_expired / clock_skew(422)・rate_limited(429、Retry-After)・temporarily_unavailable(503)。retryableがtrueでも本文の自動再送はせず、同じIDの状態を照会してください。

期限: 処理予算は受信から20秒か元の期限の短い方、外部HTTPは最大10秒、Functions timeoutは30秒。

送信画面 `/console`（MCP originで配信）は、空の入力欄に利用者が入力した本文を同じ5項目の形でAPIへ直接送ります（方向・定型文の選択はありません）。接続状態の表示と、明示の確認後に既存の `/v1/web/disconnect` で行う接続解除も同じ画面にあります。APIのCORSは設定のMCP originからの上の3 routeだけを許可します（許可header: authorization・content-type・idempotency-key、`Retry-After` を公開、wildcard・credential cookieなし）。Originが付いた旧v1 routeや他のoriginは固定の403、Originの無い要求はCORS headerを付けずに通常の処理（v1は404）へ進みます。

## 3. 送信画面と接続状態

送信画面はCloud Runではなく、自分のパソコンで動くローカルhelperが配信します（[LOCAL_CONSOLE.md](LOCAL_CONSOLE.md)）。MCP serviceはOAuth interaction画面だけを配信し、`/console`・`/connect`とそのassetは未知pathと同じ404です。helperは押した操作だけを下のrouteへBearer tokenつきで中継します。

| endpoint | 内容 |
| --- | --- |
| `GET /v1/web/connection` | Bearer Firebase ID token。`{state}` |
| `POST /v1/web/disconnect` | 同ownerのGrant/購読を失効。`{state}` |
| `/interaction/{uid}`・`…/login`・`…/consent`・`…/deny`・`/interaction/app.js` | OAuth認可のinteraction（同origin・CSRF・毎回の明示同意）とその固定script |
| `/mcp` | MCP（Bearer access token、scope `sttd:events`） |
| `/.well-known/*`・`/oauth/*` | OAuth metadata・token等（`oidc-provider`） |

`/v1/web/*`・OAuthのrouteとscopeは送信APIの版とは別で、0.3.0でも変わりません。

表示言語: HTML画面（`/console`・OAuth interaction・利用者向けOAuthエラー）は英語/日本語で描きます。`?lang=en` / `?lang=ja` の明示選択は表示専用のsession cookie `sttd_language`（Path=/・SameSite=Lax・Secure・期限なし）へ保存し、送信画面での言語切替も同じcookieをbrowserで書くため最後の選択が残ります。無い時は `Accept-Language` の優先順位（日本語選好ならja、それ以外はen）で決めます。このcookieを認証・認可に使わず、machine code・field・scope・route・送信本文は翻訳しません。

状態の優先順位: 有効なGrantが無い→unlinked、承認待ちの送信先置換→change_pending、有効な購読→subscribed、直前の購読が期限切れ→expired、それ以外（未購読・購読取消）→linked。

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
