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
| `payloadEncryption`（任意） | 省略または`'off'`（既定）。有効化の形は下の[本文暗号化の鍵保存](#payload-encryption)を参照 |

UUIDは例えば `node -e "console.log(crypto.randomUUID())"` で作れます（Node 22のrandomUUIDはversion 4）。

<a id="access-admin"></a>

## 利用者の明示登録（管理CLI）

本人1名で使う場合も、使う人ごとに運営者が利用許可を登録します。初回ログイン・Apple認証の成功・既存のowner/Grant/購読だけでは使えません。許可は既存DBの `sttdConnect/{connectNamespace}/access/{identityHash}`（UIDの平文は保存しない）に置き、active/disabledと世代を持ちます。停止（disabled）や再登録で世代が変わると、それより前の同意で作ったGrant・購読からは新しい送信・購読・token交換ができず、本人のOAuth再同意と再購読が必要です。状態の照会・取消・購読解除・接続解除は停止中も使えます。

登録・停止は運営者のパソコンやCloud Shellで、buildした同じ配置設定に対して明示的に実行します（`npm run build`の後）。対象のFirebase UIDは正規のFirebase利用者管理（Firebase consoleのAuthentication等）で本人のものを確認し、標準入力から1行1件だけ渡します（引数・履歴・fileへ書かない）。UIDは1〜128文字のUnicodeをそのまま使い、前後の空白の除去・置換・正規化をしません。不正なUTF-8・改行や制御文字・行/段落区切り（U+2028/U+2029）・BOM・孤立surrogate・余分な行・長すぎる値は`invalid_input`です。

```bash
node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
node scripts/manage-access.mjs grant  --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <statusのversion（初回はabsent）>
node scripts/manage-access.mjs revoke --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <statusのversion>
```

- `--project`・`--database`・`--namespace`は配置設定と完全一致が必要です（不一致・未設定ならSDKを作らずに止めます）。資格は運営者のApplication Default Credentialsだけで、資格file・接続先・emulator・proxyを指定する口はありません（それらの環境変数があれば止めます）。必要な権限は対象DBの読書きと`identifierKey`の固定版の読取りだけです。
- 1回の実行は全体30秒です。標準入力の読取りと処理（SDKの準備・鍵・transaction）は開始から25秒まで、SDKを閉じる後始末は残りの5秒までしか待たず、その後はprocessを終えます。これは待つ時間の上限で、既に始めたSDK処理の物理的な取消や、メモリ上の値の物理的な消去を保証するものではありません。期限の後は新しいtransactionや書込みを始めません（期限の前に始めた書込みが確定したかは`timed_out`で不明になり得るので、`status`で確かめます）。
- 出力は1行JSONの固定codeと状態・版だけ（`status`・`changed`・`unchanged`・`conflict`等）で、UID・鍵・hashは出しません。SDKを閉じられなかった・上限内に閉じ終わらなかった時は`cleanup`（`failed`・`unconfirmed`）を加えますが、`code`のDB結果（例: `changed`）は書き換えません。`grant`/`revoke`はstatusで得た版と一致した時だけ1件を書き、版が違えば`conflict`で何も書きません。結果が不明（`timed_out`・`unavailable`）の時は同じ操作を繰り返さず、`status`で確かめてから判断します。
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

<a id="payload-encryption"></a>
## 本文暗号化の鍵保存（既定off、開発中）

現在の版で有効にすると、送信APIに本人の[公開鍵の取得](API.md#encryption-key)（`GET /v2/encryption-key`）が加わります。暗号文の送信と鍵の再発行はまだ提供していません。専用secretは送信API（Functions）の実行時だけが、鍵の作成や保護し直しが必要な要求のときに読みます。起動時には読まず、MCP・運営者用の画面は読みません。読めない時は取得だけが`503`になり、平文の送信は続きます。省略・`'off'`では新しい秘密は不要で、Secret読取り・鍵作成は行わず、取得の入口は`404`です。

有効にする場合の形（全項目必須・余分なkeyは不可）:

| 項目 | 内容 |
| --- | --- |
| `mode` | `jwe-rsa-oaep-256-a256gcm-v1` だけ |
| `namespace` | `t280_<小文字UUID>`。同じFirestore database内の `sttdEncryption/<namespace>` に保存します |
| `secret` | `projects/<projectNumber>/secrets/<id>`（版を含まない）。`secretVersions`の既存4用途とは別の専用secret |
| `writeSecretVersion` | 新しく保護するときに使う正の整数の版 |
| `readSecretVersions` | 開封に使える版。重複なし1〜3件で、`writeSecretVersion`を含む |

専用secretの値は32byteのランダム値をpaddingなしのbase64url（43文字）にしたものです。値を設定ファイルへ書かないでください。版は数値で固定し、`latest`・aliasは使いません。保護鍵の更新は、新しい版を作り`readSecretVersions`に旧版と新版を並べて`writeSecretVersion`を新版にします。旧版で保護された鍵は、その利用者の次の利用時に同じ鍵のまま新版で保護し直されます。利用されていない鍵が旧版に依存している間は、旧版をreadから外したり破棄したりしないでください（旧版が読めないと、その利用者の鍵は一時的に利用できません）。

## 開発者向け6桁コード（既定off）

配置設定（`src/config/deployment.ts`）の`developerLogin`で有効にします。省略・`'off'`は無効（既定）、`'operator-code-v1'`だけが有効値で、他の値は起動前の設定errorです。offの間はコード入力の口が無く（固定404）、custom providerのID tokenも送信API・MCPの両方で受け付けません。onにすると、接続server（MCP）はプラグイン接続画面のコード入力を受け、接続serverと送信APIの共通の本人確認がコード由来の利用単位を照合します。

コードの予約HMACと予定UIDの封緘の鍵は、既存の`secretVersions.identifierKey`（配置ごとの32byteの秘密）からHKDFで用途を分けて導きます。新しい秘密は増えません。identifierKeyを切り替えると同じ番号の予約が別IDになるため、鍵の指紋が違う間は時間に関係なく発行を拒否します。切替は発行を停止し、全予約の削除を確認してから管理者が明示的に行ってください。

operator modeの設定ファイル（例: `operator.local.json`、commitしない）は次のexact schemaだけを受けます。

| key | 内容 |
| --- | --- |
| version | `1` |
| projectId / databaseId | 配置設定と同じFirebase project・Firestore database |
| namespace | 配置設定と同じ接続保存のnamespace（`t256_<UUID>`） |
| identifierKeySecretVersion | 配置設定の`secretVersions.identifierKey`と同じSecret Manager版名（`projects/<projectNumber>/secrets/<id>/versions/<n>`）。値をファイル・ブラウザ・配布物へ書かない |
| signingServiceAccount | custom tokenの署名に使う同projectの専用service account（`<name>@<projectId>.iam.gserviceaccount.com`、nameは小文字6〜30文字。例: `sttd-signer@sample-project.iam.gserviceaccount.com`）。他project・compute既定SA・URL・鍵JSONは受けません。必須で、欠落・不正なら資格・SDK・秘密の読取り前に固定errorで止まります |

helperは既定のADCで動き、custom tokenの署名はFirebase Adminの`serviceAccountId`へ渡した`signingServiceAccount`だけを使います（ADCやmetadata serverから署名先を推測しません。自分のGoogleユーザーのADCにはservice accountのemailが無いためです）。helperを動かす資格に、そのservice accountへの`iam.serviceAccounts.signBlob`（例: Service Account Token Creator）が必要です。service accountの鍵JSONは配布しないでください。

初期値（小規模な自己配置向け）: コード10分・予約は発行から24時間以上、発行候補20個・DB transaction最大5回・全体15秒。同時有効コードはnamespace 5・発行元1、発行は発行元3回/時・namespace 20回/時、入力はinteraction 5回・送信元5回・namespace全体の失敗5回/10分。onにする配置では、接続serverのservice accountにFirebaseユーザー作成とcustom token署名の権限が要ります（送信APIは照合の読取りだけ）。operator helperの資格もユーザー情報の署名・該当collectionの読み書き・identifierKeyの読取りに限ってください。TTLを使う場合は`developerLoginCodeReservations.deleteAfter`等へ配置側で設定します（認証期限の判定にはTTLを使いません）。
