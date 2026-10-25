# SendTextToDots

[English](README.md) | 日本語

自分のアプリやスクリプトから、ChatGPTのDotsへ、書いたとおりのテキストを1件ずつ送ります。

SendTextToDotsは自分で配置して使う中継サービスです。認証済みのアプリやスクリプトがAPIへ本文を送り、同じ利用者が接続したDotsの購読先へ署名付きイベントを届けます。DotsはChatGPT側で本文を受け取るアシスタントで、どう応答するかはそこで利用者が与えた指示によります。

> **状態: 実験的。** [MCP Eventsの草案](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md)のWebhook配送を使っています。草案や受信側サービスの変更により、更新が必要になったり互換性が失われたりする可能性があります。OpenAI・Apple・Googleの公式製品、または承認された連携ではありません。

ホスト済みのサービスではなく、自分で配置するソースです。詳細ドキュメント（`docs/`）は日本語と英語（`*_EN.md`）があり、Web画面も英語/日本語を切り替えられます。

## 配送の流れ

```mermaid
sequenceDiagram
  participant C as 自分のアプリやスクリプト
  participant A as 送信API (Cloud Functions)
  participant M as MCP/OAuth (Cloud Run)
  participant D as Dots / ChatGPT
  D->>M: OAuth接続とtext.submittedの購読
  C->>A: Firebase ID token付きPOST /v2/commands
  A->>D: 登録callbackへ署名付きイベント
  D-->>A: 2xxでcallback受領
  A-->>C: command状態（Dotsの処理完了ではない）
```

ownerは検証済みFirebase tokenで識別する利用者です。購読はOAuth認可後、その利用者の受信先callbackと署名用secretを登録するものです。SendTextToDotsは本文を解釈せず配送します。方向操作・定型指示の割当・本文生成は入力元アプリ、指示の実行はDots側の役割です。MCPの送信tool、キュー、自動再送はありません。

## 構成

| 部分 | 実行先 | 役割 |
| --- | --- | --- |
| 送信API | Cloud Functions 第2世代（`sendtexttodotsapi`） | 認証済み本文の受付、署名付き配送1回、状態照会、中止 |
| MCP/OAuth・送信画面 | Cloud Run（`dist/deployment/connect.js`） | OAuth認可、`/mcp`でのEvents購読、送信画面`/console`（Appleログイン・接続状態・接続解除・1件送信）。別の接続画面はない |
| 保存 | Firestore | 利用者の接続、OAuth認可、KMS封緘した購読、本文を含まないcommand状態 |
| 鍵 | Cloud KMS・Secret Manager | 封緘鍵と、署名・cookie・識別子・digest用に分離した秘密 |

詳細は[API](docs/API.md)・[配置設定](docs/CONFIGURATION.md)・[安全設計](docs/SECURITY.md)を参照してください。

## 前提条件

- ローカルの確認版はNode.js 22.23.4・npm 10.9.9です。互換性のある新しい22.x patchを使ってください。初期22.xには使用APIがないため、[INSTALL](docs/INSTALL.md)の版の条件を確認してください。
- 請求先が有効な自分のGoogle Cloud projectと、同じprojectのFirebase。[INSTALL](docs/INSTALL.md)記載のFirestore・Cloud KMS・Secret Manager・Cloud Functions・Cloud Build・Cloud Run資源。
- Firebase AuthenticationのApple provider。Sign in with AppleとApple Developer Program側の設定、authorized domainへのMCP originのhostの追加。
- 必要なEvents購読に対応したDots/ChatGPTの利用資格。許可するOAuth clientは`src/oauth/cimd.ts`のChatGPT CIMDに固定され、任意clientにはソース変更なしでは対応しません。

外部サービスの利用資格・契約・権限・費用は導入者の責任です。このリポジトリは全体の費用上限を設定せず、無料枠内での稼働も保証しません。

## 最初の送信まで

1. 固定lockどおりに依存を取得: `npm ci --ignore-scripts --no-audit --no-fund`。`--ignore-scripts`はインストール時のpackage lifecycle scriptを実行しない指定で、依存自体の安全性を保証するものではありません。
2. `npm test`を実行。build1回後、合成設定・合成SDK・loopbackだけで試験します。実Cloud・実資格・外部networkへ接続しません。
3. [導入手順](docs/INSTALL.md)に従い、service URLを決定し、Cloud資源・service account・runtime権限（`firebaseauth.users.get`を含む）・秘密・KMS購読markerを用意。[CONFIGURATION](docs/CONFIGURATION.md)を参照し、唯一の配置設定`src/config/deployment.ts`を編集します。
4. `npm run build`後、`npm run package`でAPI ZIPとMCP Cloud Build source archiveをoffline作成。包装だけでは配置されません。同じ内容での再包装は`output_exists`で停止します。既存archiveの確認方法は[INSTALL](docs/INSTALL.md)を参照してください。
5. [INSTALL](docs/INSTALL.md)のarchive配置例・origin/IAM確認に従い、APIをCloud Functions 第2世代、MCP/OAuthをDockerfile → Cloud Build → Cloud Runの順で配置します。Cloud資源作成・配置・停止のtoolは同梱されません。導入者のCloud権限が必要で、第三者projectでの手順全体の実行検証は未完了です。
6. 配置したMCP originの`/console`でAppleログイン（画面はEnglish/日本語を選べます）。Dots/ChatGPT側からMCP serverへOAuth接続し、`text.submitted`を購読すると画面が「受信中」になります。
7. 同じ`/console`の空欄に本文を入力し、1件送って受信側で確認します。購読後は下のAPI例でも送信できます。同じ画面の「接続を解除」は確認の後に認可と購読を失効させます。

[Dotsの受信テストと応答設定](docs/DOTS_GUIDE.md)に、受信先Dotsへ貼る指示文を用意しています。本文一致の配送確認を行った後、短文は引用・長文は要約・秘密情報は省く通常の応答へ切り替えられます。送信画面の案内でも、選択中の言語で両方の文面を表示・コピーできます。

配布設定は未設定（`configured: false`）です。そのままbuild・配置しても、両serviceはSDK生成・資格取得・DB・外部HTTPの前に固定の設定errorで止まります。

## APIの最小例

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

要求や応答の解析に失敗してもIDを使えるよう、送信前に表示します。結果不明時に自動再送せず、同じ認証で`GET /v2/commands/{commandId}`を照会してください。error・中止・件数枠・冪等性の詳細は[API](docs/API.md)を参照してください。

## 互換性

0.3.0は新規導入専用で、自動移行はありません。API・Eventsは0.2.0と非互換、0.2.0より前とは保存形式・OAuth scope・封緘形式も異なります。配置前に[互換性の詳細](docs/INSTALL.md#030の互換性)を確認してください。

## 制約と免責

- 2026-10-25、作者の環境で実Dotsへの2件の配送（直接APIと`/console`、日本語・改行を含む）と、同じ開発環境の再起動後の単純な計算指示1件を確認しました。限定した確認であり、任意指示の実行保証ではありません。
- 追加の本人提供資料で、MacでGitHubのcommit `ad276fccc504bc367df209edb694809570496c3e` を取得し、配置設定だけを変更してbuildに成功、`/console`からの1件が実Dotsに入力どおり届いた実績を記録しています。Macの自動試験は108/112成功で、4件は`127.0.0.2`へのlisten時の`EADDRNOTAVAIL`で失敗。同じsourceのLinux Cloud Buildでは合成試験112/112成功との報告です。第三者独立検証や長期の本番運用受入とは区別します。環境と残る制約は[LIMITATIONS](docs/LIMITATIONS.md)を参照してください。
- 本番の信頼性・負荷・費用・同UIDの複数入口・1件ごとの即時処理は保証しません。受信側でまとめて処理される場合があります。Events草案の変更も互換性に影響し得ます。
- 本人確認はFirebaseのApple providerだけです。認証省略や任意endpoint・資格・emulator・HTTP経由の設定overrideはありません。
- 本serviceは本文を永続保存しません。期限切れの保存metadataは利用不可になりますが、物理削除とaccount全削除は未実装です。受信後の保持・処理は受信サービスの条件に従います。RAM・SDK・OS内の物理消去も保証しません。
- MITが許諾するのは本sourceで、外部サービスやSDKの利用権を再許諾しません。[SECURITY](docs/SECURITY.md)と[LIMITATIONS](docs/LIMITATIONS.md)を参照してください。

## セキュリティ

[安全設計と報告方法の現状](docs/SECURITY.md)を確認してください。非公開の脆弱性報告窓口は一般公開前に定める予定で、現在利用可能な窓口を示すものではありません。公開issueへtoken・秘密・実データを書かないでください。

## ディレクトリ

| path | 内容 |
| --- | --- |
| `src/config/deployment.ts` | 導入者が編集する唯一の配置設定 |
| `src/config/validate.ts` | 設定の検証（未設定・不整合は副作用の前に拒否） |
| `src/deployment/` | Functions entry・Cloud Run entry・CORS |
| `src/google-runtime/` | Google SDKの所有起動（Cloud実行環境gate・危険な環境変数の拒否） |
| `src/delivery/`・`src/commands/` | 送信APIの入力検証・単回配送・中止・状態 |
| `src/connect/`・`src/oauth/`・`src/mcp/`・`src/events/` | 送信画面・OAuth interaction画面（英日辞書は`i18n.ts`）・OAuth・MCP Events・購読・署名 |
| `src/storage/`・`src/protection/`・`src/keys/` | Firestore保存形式・KMS封緘・Secret読取り |
| `src/egress/` | 安全なHTTPS送出（IP検証・固定接続・TLS・期限・上限） |
| `scripts/` | offline包装（`package-artifacts.mjs`）・試験runner |
| `test/` | 自動試験（合成値だけ） |
| `references/` | 宛先IP分類の根拠にしたIANA表（CC0 1.0）。[references/README.md](references/README.md) |
| `firestore/` | 全拒否のFirestore rulesと索引除外 |

## License

[MIT](LICENSE) © 2026 Katsuyasan88。第三者のpackage・SDK・参照dataは [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（[English](THIRD_PARTY_NOTICES_EN.md)）を参照してください。
