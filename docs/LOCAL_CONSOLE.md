# ローカル送信画面（5段階セットアップ）

[English](LOCAL_CONSOLE_EN.md) | 日本語

送信画面はCloud Runではなく、あなたのパソコンで動く小さな配信helperが `http://localhost:8765/console` に出します。画面を開く・再読み込みする・言語を切り替える・固定の指示文を表示/コピーするだけでは、Cloud Run・送信API・Firebaseへ一切通信しません。通信は画面のボタンを押した時だけで、Firebaseの認証ライブラリも手順1の「Appleでログイン」を押した時に初めて読み込みます。

## 必要なもの

- Node.js 22（`>=22.2.0 <23`。実測は22.23.4。[INSTALL](INSTALL.md)の版の条件と同じ）と、このリポジトリのbuild済みsource（`npm ci --ignore-scripts --no-audit --no-fund` と `npm run build`）。新しい依存はありません。
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

5つの手順は常に順に表示され、初めは手順1だけが有効で、2〜5は灰色です。完了した手順は薄く表示され、その枠のどこかをクリック（またはEnter/Space）すると見直しのために再び有効になります（見直すだけでは記録は消えません）。有効でない枠の中のボタンや入力欄は押せません。全5段階を終えると、画面の一番下に完了の文面が表示され、手順4へ戻って送信を続けても表示されたままです。この画面とhelperは、進捗・入力した本文・ID tokenをメモリだけで扱い、cookie・localStorage・fileなどへ追加保存しません（再読み込みで初期化されます）。画面自身が残すのは表示用cookie `sttd_language`（言語の選択）だけです。これとは別に、Firebase SDK自身はログイン状態の復元のために既定の方法で認証sessionをブラウザ内に保存します。この保存はFirebaseの仕様で、本画面は変更していません。別のタブでログアウトや別アカウントへの切替があった場合も手順2〜5は戻り、再ログインを案内します。

1. **ログイン** — 「Appleでログイン」を押すと認証ライブラリを読み込み、入力元アプリと同じAppleアカウントでログインします。popupは押した時だけ開きます（ブロックされた場合はもう一度押してください）。別アカウントでやり直すと手順2〜5は戻ります。
2. **接続確認** — 「接続を確認」を1回押して、接続と購読の状態を確認します（自動の再確認はありません）。「受信中」なら手順3へ進めます。未接続・受信開始待ち・期限切れ・送信先変更の確認待ちの場合は、ChatGPTで次にすることを英日で案内します。確認中は手順3〜5を一時的に封鎖し、受信中が続いていれば進捗は保持、そうでなければ手順3〜5を戻します。ここで「接続を解除」もできます。 利用許可（運営者の明示登録）も同時に表示し、許可されていない・確認できない・サービスが旧版で更新が必要、の3つを区別して案内します。いずれの場合も手順3以降の新しい送信へは進めませんが、接続解除と、前の送信の結果確認・中止はできます。 手順2には「プラグインを追加・接続する」の短い案内と展開できる手順があり、未接続でも接続済みでも見直せます（接続済みなら追加し直す必要はありません）。登録先として、helperの設定`mcpOrigin`の後ろに`/mcp`を付けたこの配置のServer URLを表示します（設定が無い時はURLを推定せず案内だけ）。このローカル画面（localhost）やAPIのoriginは登録しません。手順: ChatGPTのPlugins →「+」→「Add custom MCP server」で、分かる名前とServer URLを入れ、接続はHTTPS・認証はOAuthを選ぶ → 接続先・認証・警告を確認して作成・インストールし、手順1と同じAppleアカウントで同意する → 受け取りたいDotsの会話で追加したプラグインを選び「このDotsで受信を開始」と依頼する → この画面へ戻り「接続を確認」を押す。メニュー名や利用できるかどうかはChatGPTのアカウント・workspaceにより、変わることがあるため、画面の公式リンク（[Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)・[Add custom MCP server](https://developers.openai.com/api/docs/guides/custom-mcp-server)）も確認してください。ガイドを開く・リンクを押す・言語を切り替える操作では、この画面は通信しません。
3. **テスト用Dotsプロンプト** — [Dotsガイド](DOTS_GUIDE.md)のテスト用文面を表示/コピーし、受信するDotsへ貼り付けてから「Dotsへ貼り付けて次へ」を押します。コピーできないブラウザでは手動コピーを確認してから進めます。コピーしてもDotsへは送られません。
4. **送信** — 本文欄は空で、placeholderに非機密の例文があります。短い本文を入力して「送信」を押し（1回のPOST。二重クリックで2件にはなりません）、Dotsで受信した本文が一致することを自分で確認してから「Dotsで本文一致を確認して次へ」を押します。「受領」はcallbackの2xxで、一致の証明ではありません。未送信・失敗・中止・期限切れでは進めず、結果不明の場合は実際にDotsで一致を確認したうえで進めます（画面は不明を成功へ書き換えません）。
5. **運用用Dotsプロンプト** — 運用用の文面を表示/コピーして同じDotsへ貼り付け、「Dotsへ貼り付けて完了」を押すと、5段階の完了文面が表示されます。これはあなたの確認操作による進捗で、サーバーがDotsへの適用を検証したわけではありません。

完了後は手順4を選び直して通常の送信を繰り返せます（手順3/5の再コピーは不要です）。再ログイン・受信中でない状態・テスト用文面の再適用があると、それに依存する手順は戻ります。

## ログインsessionとtoken更新

認証が必要なボタン操作では、helperで中継する前に`user.getIdToken()`で有効なFirebase ID tokenを取得します。SDKは既存のログインsessionから短期tokenを更新できるため、寿命が約1時間でも、毎時間の手動ログインが必要という意味ではありません。サインアウト・sessionの失効や無効化があれば、再ログインが必要になることはあります。画面のメモリ上のセットアップ進捗とFirebaseのブラウザsessionは別です。背景での状態監視や送信を追加するものではありません。[sessionと自動送信の説明](API.md#firebase-sessions)も参照してください。

## helperが中継するもの

helperは、画面のボタン操作に対応する次の要求だけを、設定した固定originへ中継します。ブラウザから本番originへ直接通信せず、Cloud Run側のCORS・権限は変えていません。

| 画面からの要求 | 上流 |
| --- | --- |
| `GET /v1/web/connection`・`POST /v1/web/disconnect` | `mcpOrigin` |
| `POST /v2/commands`・`GET /v2/commands/{id}`・`POST /v2/commands/{id}/cancel` | `apiOrigin` |

要求ごとに `Authorization: Bearer <Firebase ID token>` と、起動時に作る乱数（local nonce）を必須にし、Hostの不一致・Originの不一致・nonceの欠落や重複・許可外のpath/method・本文超過（送信のJSON全体で32 KiB。本文の上限4096 byteはAPI側のまま）は上流を呼ぶ前に拒否します。上流の応答は64 KiBまで読み、超える場合は打ち切って固定のエラーにします。上流へ転送するheaderは `Authorization`（送信時は `Content-Type` と `Idempotency-Key` も）だけで、Cookie・Origin・Forwarded・nonceは送りません。応答は状態・本文・`Content-Type`・`Retry-After` だけを返し、`Set-Cookie` は転送しません。token・本文・秘密は保存もログ出力もしません。任意URLへの中継・redirectの追従はできません。

helperが上流を呼ぶ前に自分で拒否した応答（古い画面のnonce不一致・許可外のpath/method・本文超過など）には固定header `X-Sttd-Local-Refusal: 1` を付け、画面はこれがある時だけ「送信されていない」と表示して再読み込みを案内します（本文一致の確認へは進めません）。上流の応答の同名headerは転送しないため、上流のエラーを未送信に見せかけることはできません。上流を呼んだ後の失敗（502など）は従来どおり結果不明です。結果が確定していない送信がある時に再ログイン・認証の喪失・状態の再確認・テスト用文面の再適用で手順が戻った場合は、重複して届く可能性の注意を表示したままにします（自動の照会・取消・再送はしません）。

## 制約

- 第三者の環境・実ブラウザでの動作は合成試験以外で未確認です（[LIMITATIONS](LIMITATIONS.md)）。
- helperはあなたのパソコンで動く開発補助で、認証や秘密を追加で扱いません。Cloud側の設定・サービスの起動停止は行いません。

## 開発者向け6桁コードで接続する（operator mode）

通常の`npm run console`は従来どおりAppleでログインする配信modeで、コード発行の操作口はありません（ステップ1に「この配置ではコード発行が設定されていません」と表示）。配置設定で`developerLogin: 'operator-code-v1'`にした配置で、自分の配置へ管理権限を持つ端末だけが、明示的にoperator modeを起動します。

```
node dist/console/operator-server.js --config console.local.json --operator operator.local.json
```

1. ステップ1で「コードで接続」を選びます（選ぶだけでは発行しません）。「コードを発行」を押すと6桁のコードと残り時間を表示します。
2. 10分以内に、プラグインを追加した後の接続画面でコードを入力します。コードの使用は1回だけです。続けて通常の同意・購読を行います。
3. コンソールで「接続を確認」を押すと、同じ利用単位でコンソールもログインします。自動での確認（poll）はしません。
4. 「再発行」は現在のコードとそのコードによる接続を終了して作り直します。新しいコードを確保できなかったときは、現在のコードと接続は変わりません。

AppleとコードはStep 1で切り替えられます。切り替えても以前の接続は自動では止まりません。以前のプラグインを削除し、ステップ2から追加し直してください。以前の接続は新しい接続へ引き継がれません。

operatorの照会用secretはhelperのメモリだけにあり、helperを終了すると発行済みコードの照会・再発行はできません（未使用のコードは10分で失効します。新しく発行してください）。
