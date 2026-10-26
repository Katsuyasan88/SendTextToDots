# 配置設定

[English](CONFIGURATION_EN.md) | 日本語

設定の正本は `src/config/deployment.ts` の1 fileだけです。配置前に編集してbuildします。実行時にHTTP・環境変数・引数から設定を選んだり上書きしたりする口はありません（MCPのlisten portと、Firebase Web API keyの値を読む環境変数を除く）。

下の表は配置値の意味と条件をまとめたものです。入力元は汎用のアプリやスクリプトで、入力元のログイン/session管理とserver配置設定は別です（[API](API.md#firebase-sessions)）。本人認証は現在Apple providerのFirebaseだけに対応します。入力元のtokenや実ユーザー識別子を配置設定へ入れないでください。

## 検証

`src/config/validate.ts` が次を全て確かめ、1つでも外れると固定のerror（`deployment_config_unconfigured` / `deployment_config_invalid`）で起動を止めます。値・path・元の例外はerrorに含めません。

- `configured` が boolean の `true`。これだけでは他の検査を省略しません（配布placeholderは形式の検査で落ちます）。
- key は表のものだけ（未知のkey、getter、Proxyは拒否）。endpoint・credential・emulator等を足すkeyはありません。
- 各値の形式と、下表の相互整合。

Functions entryはimport時（discovery時）に、MCP entryと各起動口はenv捕捉・signal登録・SDK生成・Secret取得・DB・listen・外部HTTPの前に検証します。

## 項目

| key | 形式・条件 |
| --- | --- |
| `configured` | `true` |
| `accessPolicy` | `explicit-allow-v1` だけ（運営者が明示登録した利用者だけが使える。欠落・他の値は設定error。全員許可の方式は無い） |
| `projectId` | Google Cloud project ID（英小文字始まり6〜30文字） |
| `projectNumber` | 同じprojectの数値project number |
| `databaseId` | `(default)` 又は名前付きFirestore database ID |
| `location` | 単一region（例 `us-central1`）。Functionsのregion、KMS key ringの地域に使う。`global`・multi-regionは不可 |
| `api.functionName`・`api.serviceName` | どちらも `sendtexttodotsapi`（Functionsのexport名はESMの静的名のため固定。変える場合は `src/deployment/functions.ts` のexport名と `src/config/validate.ts` の `API_FUNCTION_EXPORT` も変える） |
| `api.serviceAccount` | `<name>@<projectId>.iam.gserviceaccount.com`。API専用 |
| `api.invoker`・`connect.invoker` | `private` だけ。外部到達はIAMで別に付与する（アプリ層の本人確認・OAuth・署名は常に必須） |
| `api.publicOrigin` | APIの公開origin `https://<host>`（path・port・末尾slashなし。IP・localhost・予約TLDは不可） |
| `connect.serviceName` | Cloud Runのservice名（APIと別） |
| `connect.serviceAccount` | MCP専用SA（APIと別） |
| `connect.publicOrigin` | MCPの公開origin（OAuth issuer。APIと別） |
| `connectNamespace` | `t256_<小文字UUID>`（version 1〜8・RFC variant）。導入時に1回生成し、以後変えない |
| `deliveryNamespace` | `t270_<小文字UUID>` |
| `kms.environment` | `development`（保存形式の値。既存形式と互換） |
| `kms.projectId`・`kms.databaseId` | top-levelと同じ値 |
| `kms.namespace` | `t268_<小文字UUID>` |
| `kms.cryptoKey` | `projects/<projectId>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>`（locationは上の`location`と同じ） |
| `kms.writeVersion`・`kms.readVersions` | 正の整数。readVersionsは1〜8件・重複なし・writeVersionを含む |
| `secretVersions.jwks`・`cookieKeys`・`identifierKey`・`commandDigestKey` | `projects/<projectNumber>/secrets/<id>/versions/<数値>`。用途ごとに別secret。`latest`・aliasは不可 |
| `web.projectId` | `projectId` と同じ |
| `web.authDomain` | Firebase Web設定のauthDomain（DNS host） |
| `web.apiKeyEnv` | MCP processでFirebase Web API keyの値を読む環境変数名（英大文字・数字・`_`）。`GOOGLE_`・`FIREBASE_`・`NODE_`・`K_` 等の既存の名前空間と `PORT` は不可 |

UUIDは例えば `node -e "console.log(crypto.randomUUID())"` で作れます（Node 22のrandomUUIDはversion 4）。

<a id="access-admin"></a>

## 利用者の明示登録（管理CLI）

本人1名で使う場合も、使う人ごとに運営者が利用許可を登録します。初回ログイン・Apple認証の成功・既存のowner/Grant/購読だけでは使えません。許可は既存DBの `sttdConnect/{connectNamespace}/access/{identityHash}`（UIDの平文は保存しない）に置き、active/disabledと世代を持ちます。停止（disabled）や再登録で世代が変わると、それより前の同意で作ったGrant・購読からは新しい送信・購読・token交換ができず、本人のOAuth再同意と再購読が必要です。状態の照会・取消・購読解除・接続解除は停止中も使えます。

登録・停止は運営者のパソコンやCloud Shellで、buildした同じ配置設定に対して明示的に実行します（`npm run build`の後）。対象のFirebase UIDは正規のFirebase利用者管理（Firebase consoleのAuthentication等）で本人のものを確認し、標準入力から1件だけ渡します（引数・履歴・fileへ書かない）。

```bash
node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
node scripts/manage-access.mjs grant  --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <statusのversion（初回はabsent）>
node scripts/manage-access.mjs revoke --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <statusのversion>
```

- `--project`・`--database`・`--namespace`は配置設定と完全一致が必要です（不一致・未設定ならSDKを作らずに止めます）。資格は運営者のApplication Default Credentialsだけで、資格file・接続先・emulator・proxyを指定する口はありません（それらの環境変数があれば止めます）。必要な権限は対象DBの読書きと`identifierKey`の固定版の読取りだけです。
- 出力は1行JSONの固定codeと状態・版だけ（`status`・`changed`・`unchanged`・`conflict`等）で、UID・鍵・hashは出しません。`grant`/`revoke`はstatusで得た版と一致した時だけ1件を書き、版が違えば`conflict`で何も書きません。結果が不明（`timed_out`・`unavailable`）の時は同じ操作を繰り返さず、`status`で確かめてから判断します。
- 既存の配置から更新する場合、新しい版へ切り替えるまで許可は効きません。更新後は旧Grantを使えないため、許可した本人がOAuth同意と購読をやり直します。

## ローカル送信画面の設定

ローカル送信画面（[LOCAL_CONSOLE.md](LOCAL_CONSOLE.md)）は別の小さなJSON fileを使い、公開client値だけを持ちます（`apiOrigin`・`mcpOrigin`・`firebase.apiKey/authDomain/projectId`。`console.config.example.json`参照）。`src/config/deployment.ts`は読まず変更もせず、秘密を含みません。実fileはGitへ入れません（`console.local.json`はignore済み）。

## 秘密の値

設定fileには秘密の値を書きません。

| 用途 | 置き場所 |
| --- | --- |
| 購読情報の封緘鍵 | Cloud KMS（SOFTWARE、ENCRYPT_DECRYPT） |
| AS署名JWKS・cookie鍵・識別子HMAC鍵（32 byte）・command digest鍵（32 byte） | Secret Manager の各secretの数値版（形式は [INSTALL.md](INSTALL.md)） |
| Firebase Web API key | MCPのCloud Run環境変数（名前は `web.apiKeyEnv`） |

## 実行環境で拒否する環境変数

SDKの生成前に、資格・宛先・TLS・ログを別経路へ変え得る環境変数（例 `GOOGLE_APPLICATION_CREDENTIALS`、`FIRESTORE_EMULATOR_HOST`、`HTTPS_PROXY`、`NODE_TLS_REJECT_UNAUTHORIZED`、`NODE_EXTRA_CA_CERTS` 等）が存在すると起動を拒否します（値は読みません）。`NODE_OPTIONS` はAPI serviceだけ `--max-old-space-size=<128〜960>` 1つ（前後の空白0〜8個）を許し、MCP serviceでは存在自体を拒否します。一覧は `src/google-runtime/development.ts`。

## 初回originと配置時の確認

`api.publicOrigin`と`connect.publicOrigin`はbuild前に確定させます。[INSTALL.md](INSTALL.md)の順序で、service名・数値project number・regionから決定的なCloud Run URLを選ぶか、先にTLS/routingを用意した独自domainを選んでください。MCP issuer、CORS、Firebase authorized domain、Dotsへの`/mcp`登録で同じoriginを使います。配置後にConsoleの別名URLだけを見て書き換えず、選んだURLの利用可否を照合します。

serviceへattachしたruntime SAのmetadata資格だけを使います。ローカルADCや資格fileを設定して起動する開発serverではありません。PORTはCloud Runが付ける値、Web API keyは`web.apiKeyEnv`の名前で初回起動前に設定します。runtimeに`firebaseauth.users.get`がない場合は、正しいtokenでも失効・ユーザー状態照会ができません。runtime/build/配置担当の権限表は[INSTALL.md](INSTALL.md)を参照してください。

`invoker: private`はsourceの許可値です。browser/Dotsがserviceへ到達するためのCloud側の公開到達設定は別に必要で、設定fileのinvokerをpublicへ変更して解決しません。アプリのFirebase ID token/OAuth認証は常に必須です。

実際の設定値や秘密を公開Gitへcommitせず、導入者が管理する環境で保管してください。試験が合格しても実配置値の正しさ・IAM・秘密の登録・URL到達を検証したことにはなりません。