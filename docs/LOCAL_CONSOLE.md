# ローカル送信画面（5段階セットアップ）

[English](LOCAL_CONSOLE_EN.md) | 日本語

送信画面はCloud Runではなく、あなたのパソコンで動く小さな配信helperが `http://localhost:8765/console` に出します。画面を開く・再読み込みする・言語を切り替える・固定の指示文を表示/コピーするだけでは、Cloud Run・送信API・Firebaseへ一切通信しません。通信は画面のボタンを押した時だけで、Firebaseの認証ライブラリも手順1の「Appleでログイン」を押した時に初めて読み込みます。

## 必要なもの

- Node.js 22（[INSTALL](INSTALL.md)の版の条件と同じ）と、このリポジトリのbuild済みsource（`npm ci --ignore-scripts --no-audit --no-fund` と `npm run build`）。新しい依存はありません。
- 配置済みのAPI/MCPサービスのhttps originと、Firebase Webアプリの公開設定（`apiKey`・`authDomain`・`projectId`）。いずれも秘密ではなくブラウザに渡る値ですが、設定fileはcommitしません（`console.local.json` と `*.local.json` は `.gitignore` 済み）。
- Firebase Authenticationのauthorized domainsに `localhost` が入っていること（Appleログインのpopupに必要）。

## 設定fileと起動

`console.config.example.json` をコピーして `console.local.json` を作り、値を自分のものに置き換えます。keyはこの3つだけで、未知のkey・http origin・IPアドレス・path付きoriginは起動時に拒否します。

```json
{
  "apiOrigin": "https://sendtexttodotsapi-<PROJECT_NUMBER>.<REGION>.run.app",
  "mcpOrigin": "https://<MCP_SERVICE>-<PROJECT_NUMBER>.<REGION>.run.app",
  "firebase": { "apiKey": "...", "authDomain": "<project>.firebaseapp.com", "projectId": "<project>" }
}
```

```sh
npm run build
npm run console -- --config console.local.json          # 既定 http://localhost:8765/console
npm run console -- --config console.local.json --port 9000
```

helperは `127.0.0.1` だけで待ち受け、`Host: localhost:<port>` と完全に一致する要求だけを受けます。LAN公開・`0.0.0.0`・`file://` での直開きには対応しません。止めるときは Ctrl+C です。

## 画面でできること（5段階）

5つの手順は常に順に表示され、初めは手順1だけが有効で、2〜5は灰色です。完了した手順は薄く表示され、その枠のどこかをクリック（またはEnter/Space）すると見直しのために再び有効になります（見直すだけでは記録は消えません）。有効でない枠の中のボタンや入力欄は押せません。全5段階を終えると、画面の一番下に完了の文面が表示され、手順4へ戻って送信を続けても表示されたままです。進捗・入力した本文・ID tokenはメモリだけにあり、再読み込みで初期化されます。言語の選択だけが表示用cookie `sttd_language` に残ります。別のタブでログアウトや別アカウントへの切替があった場合も手順2〜5は戻り、再ログインを案内します。

1. **ログイン** — 「Appleでログイン」を押すと認証ライブラリを読み込み、入力元アプリと同じAppleアカウントでログインします。popupは押した時だけ開きます（ブロックされた場合はもう一度押してください）。別アカウントでやり直すと手順2〜5は戻ります。
2. **接続確認** — 「接続を確認」を1回押して、接続と購読の状態を確認します（自動の再確認はありません）。「受信中」なら手順3へ進めます。未接続・受信開始待ち・期限切れ・送信先変更の確認待ちの場合は、ChatGPTで次にすることを英日で案内します。確認中は手順3〜5を一時的に封鎖し、受信中が続いていれば進捗は保持、そうでなければ手順3〜5を戻します。ここで「接続を解除」もできます。
3. **テスト用Dotsプロンプト** — [Dotsガイド](DOTS_GUIDE.md)のテスト用文面を表示/コピーし、受信するDotsへ貼り付けてから「Dotsへ貼り付けて次へ」を押します。コピーできないブラウザでは手動コピーを確認してから進めます。コピーしてもDotsへは送られません。
4. **送信** — 本文欄は空で、placeholderに非機密の例文があります。短い本文を入力して「送信」を押し（1回のPOST。二重クリックで2件にはなりません）、Dotsで受信した本文が一致することを自分で確認してから「Dotsで本文一致を確認して次へ」を押します。「受領」はcallbackの2xxで、一致の証明ではありません。未送信・失敗・中止・期限切れでは進めず、結果不明の場合は実際にDotsで一致を確認したうえで進めます（画面は不明を成功へ書き換えません）。
5. **運用用Dotsプロンプト** — 運用用の文面を表示/コピーして同じDotsへ貼り付け、「Dotsへ貼り付けて完了」を押すと、5段階の完了文面が表示されます。これはあなたの確認操作による進捗で、サーバーがDotsへの適用を検証したわけではありません。

完了後は手順4を選び直して通常の送信を繰り返せます（手順3/5の再コピーは不要です）。再ログイン・受信中でない状態・テスト用文面の再適用があると、それに依存する手順は戻ります。

## helperが中継するもの

helperは、画面のボタン操作に対応する次の要求だけを、設定した固定originへ中継します。ブラウザから本番originへ直接通信せず、Cloud Run側のCORS・権限は変えていません。

| 画面からの要求 | 上流 |
| --- | --- |
| `GET /v1/web/connection`・`POST /v1/web/disconnect` | `mcpOrigin` |
| `POST /v2/commands`・`GET /v2/commands/{id}`・`POST /v2/commands/{id}/cancel` | `apiOrigin` |

要求ごとに `Authorization: Bearer <Firebase ID token>` と、起動時に作る乱数（local nonce）を必須にし、Hostの不一致・Originの不一致・nonceの欠落や重複・許可外のpath/method・本文超過（送信のJSON全体で32 KiB。本文の上限4096 byteはAPI側のまま）は上流を呼ぶ前に拒否します。上流の応答は64 KiBまで読み、超える場合は打ち切って固定のエラーにします。上流へ転送するheaderは `Authorization`（送信時は `Content-Type` と `Idempotency-Key` も）だけで、Cookie・Origin・Forwarded・nonceは送りません。応答は状態・本文・`Content-Type`・`Retry-After` だけを返し、`Set-Cookie` は転送しません。token・本文・秘密は保存もログ出力もしません。任意URLへの中継・redirectの追従はできません。

## 制約

- 第三者の環境・実ブラウザでの動作は合成試験以外で未確認です（[LIMITATIONS](LIMITATIONS.md)）。
- helperはあなたのパソコンで動く開発補助で、認証や秘密を追加で扱いません。Cloud側の設定・サービスの起動停止は行いません。
