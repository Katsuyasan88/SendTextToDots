# 導入

[English](INSTALL_EN.md) | 日本語

この手順は、自分のGoogle Cloud / Firebaseへ0.3.0を新規導入するための構成と作業順です。第三者projectでこの手順を一通り実行した検証は未完了です。[LIMITATIONS.md](LIMITATIONS.md)の確認範囲を超えて、配置成功・本番運用を保証するものではありません。Cloudコマンドは資源・費用・権限を変更するので、対象projectと予算を確認してから実行してください。

## 1. 用意するもの

- ローカルのNode.jsは**22.23.4を推奨**（作者の確認版）、npmは10.9.9が確認版です。単に22系なら全て対応するという意味ではありません。`node --version`・`npm --version`で確認してください。`zlib.crc32`は22.2.0、`URL.parse`は22.1.0で追加されており、初期22.xは使えません。その他の版の全機能は未検証です。
- このrepositoryのsourceだけでbuild/testできます。開発者の私有folder、Git hook、AI設定は不要です。`node_modules`・`dist`を他環境からコピーせず、lockから取得してください。TypeScriptのプラットフォーム別依存があるため`--omit=optional`は付けません。
- 請求先が有効な、自分のGoogle Cloud projectと同じprojectのFirebase。既存の他アプリのDB・鍵・購読を流用しない新規導入にします。
- Firebase Webアプリ、AuthenticationのApple provider、Apple Developer Program側のSign in with Apple設定。[公式のApple設定手順](https://firebase.google.com/docs/auth/web/apple)に沿いServices ID・Team ID・key等を設定し、認証redirect先をApple側に登録します。Appleの秘密鍵はこのsourceへ入れません。
- 必要なMCP Events購読に対応したDots/ChatGPTの利用資格。許可するOAuth clientは`src/oauth/cimd.ts`のChatGPT CIMD 1件です。別clientや別callback仕様へ自動対応しません。
- 以下のCloudコマンド例は**Bash（Cloud Shell等）とGoogle Cloud CLI**用です。PowerShellへそのまま貼る構文ではありません。CLIは導入者の管理操作用で、serviceのruntime資格としては使いません。

## 2. project・名前・URLを配置前に確定する

1. Google Cloud Consoleでproject IDと数値project number、Firebase Web設定の`projectId`・`authDomain`・Web API keyを確認します。Web API keyの値はserver sourceへ書かず、MCPの環境変数へ後で設定します。
2. 単一region、API用とMCP用の別runtime service account、MCP service名を決めます。APIのfunction/service/export名は`sendtexttodotsapi`固定です。名称衝突がある既存serviceへ上書きしないでください。
3. API/MCPのoriginはbuild前に必要です。[Cloud Runの決定的URL](https://docs.cloud.google.com/run/docs/triggering/https-request#deterministic-url)なら作成前に次の形で予測できます。

   ```text
   API: https://sendtexttodotsapi-<PROJECT_NUMBER>.<REGION>.run.app
   MCP: https://<MCP_SERVICE>-<PROJECT_NUMBER>.<REGION>.run.app
   ```

   service名と`-`とproject numberを合わせたDNS segmentは63文字以内にします。default `run.app` URLが許可された環境で使い、配置後に使用可能であることを管理画面で照合します。Consoleが別名のhash URLや`cloudfunctions.net` URLも表示していても、無断でissuerを切り替えません。独自domainを使う場合はTLSとroutingを先に整え、同じoriginを一貫して使ってください。
4. MCPのhostをFirebase Authenticationのauthorized domainsへ追加します。Apple側のredirect先はFirebaseの`https://<authDomain>/__/auth/handler`で、MCPの`/console`そのものとは別です。
5. [CONFIGURATION.md](CONFIGURATION.md)に従い3つの新しいnamespace UUIDを生成し、以後固定します。これは秘密鍵ではありません。設定のproject/number/database/region/鍵/secret版との対応を台帳で確認します。

## 3. Cloud資源と権限を用意する

Google Cloud Consoleで少なくともCloud Functions、Cloud Run、Cloud Build、Artifact Registry、Firestore、Cloud KMS、Secret Manager、IAM、Firebase Authentication/Identity Toolkit関連のAPIが使える状態にします。APIの有効化やroleの付与は導入者のproject管理者が行います。組織制約・region制約・請求無効がある場合は先に解決してください。

| 資源 | 内容 |
| --- | --- |
| Firestore | Native modeの新しいdatabase（`(default)`又は名前付き）。選んだdatabaseへ`firestore/firestore.rules`の全拒否rulesと`firestore/firestore.indexes.json`の5つのfield索引除外を適用。書込みはserver IAM経由だけ |
| Cloud KMS | 設定regionのkey ringと、SOFTWARE / ENCRYPT_DECRYPTの対称CryptoKey。利用する数値版を固定 |
| Secret Manager | 4用途別secretと各数値版（次節）。`latest`は使わない |
| Runtime service account | API用とMCP用を別に作り、それぞれのserviceへattach。長期SA key fileは作らない |
| Build service account | runtimeとは別に選び、source取得・image書込み・buildログ保存の権限を用意 |
| Artifact Registry / source保存先 | buildと同じproject/使用regionのDocker repositoryと、Functions/Cloud Buildのsource・ログの保存先 |

### runtimeと配置担当の権限を分ける

| 主体 | 必須の権限・用途 | 範囲の目安 |
| --- | --- | --- |
| API/MCP runtime両方 | Firestore読書き（例: `roles/datastore.user`） | 使用databaseに限定。Firestore rulesを公開read/writeへ変えて代用しない |
| API/MCP runtime両方 | **`firebaseauth.users.get`**。ID tokenの失効・無効化とユーザー状態の照会 | 使用project。最小のcustom role又は必要範囲を審査した既定role。Authユーザー一覧/参照能力を伴うことに注意 |
| API runtime | KMS復号（`roles/cloudkms.cryptoKeyDecrypter`） | 使用CryptoKeyだけ |
| MCP runtime | KMS暗号化/復号（`roles/cloudkms.cryptoKeyEncrypterDecrypter`） | 同じCryptoKeyだけ |
| API runtime | Secret読取り（`roles/secretmanager.secretAccessor`） | identifierKey、commandDigestKeyの2 secretだけ |
| MCP runtime | Secret読取り（同上） | jwks、cookieKeys、identifierKeyの3 secretだけ |
| Build SA | source object読取り・必要なstaging書込み、Artifact Registry書込み、buildログ保存 | 選んだbucket/repository/log保存先に限定 |
| 配置する本人/CI | Functions/Runの作成更新、Build起動、選んだbuild/runtime SAの`iam.serviceAccounts.actAs`等 | 配置対象に限定。runtimeへ配置権限を渡さない |

`firebaseauth.users.get`がないとDBや秘密を読めても認証時に止まります。sourceは`verifyIdToken(token, true)`と`getUser`で確認するため、JWTの署名検証だけの構成では足りません。[Auth権限の公式一覧](https://docs.cloud.google.com/iam/docs/roles-permissions/firebaseauth)を参照してください。

Google管理のFunctions/Run/Build service agentにも、それぞれの標準の配置権限が必要です。runtime SAと混同せず、service agent用roleを一般ユーザーへ渡さないでください。Build SAの既定値はprojectで異なります。選んだ主体とsource bucket/Artifact Registry/ログ保存先を[Functions build](https://docs.cloud.google.com/functions/docs/building)・[user-managed Build SA](https://docs.cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts)に沿って確認します。権限エラーをOwner/Editorの一括付与で解決しないでください。

### 秘密を作って数値版へ登録する

| 用途 | 必須の形式 |
| --- | --- |
| `jwks` | UTF-8 JSON `{"keys":[<private ES256 JWK>,<private RS256 JWK>]}`。2鍵ちょうどで各1個。各fieldはstring。ES256は`alg: "ES256"`・`kty: "EC"`・`crv: "P-256"`、RS256は`alg: "RS256"`・`kty: "RSA"`。両方に非空の`d`と完全な秘密鍵パラメータが必要。別々の`kid`と`use: "sig"`を付ける |
| `cookieKeys` | randomな32 byte鍵を1個以上連結した**raw bytes**（32の正の倍数） |
| `identifierKey` | randomな**raw 32 bytes** |
| `commandDigestKey` | identifierKeyとは別に生成した**raw 32 bytes** |

JWK exportには`alg`が自動で付かない場合があります。また、鍵用途以外のarray/boolean fieldをJWKへ追加するとこのsourceの検査で拒否されます。binary secretをhex/base64の文字列として登録しないでください。

次は導入者が自分の保護された環境で行う生成例です。Git作業folder外に権限を制限したdirectoryを用意し、その絶対pathを`STTD_SECRET_DIR`へ設定してから、例を同directoryの`.mjs`へ保存しNode.jsで実行します。鍵は画面へ出さず、既存fileは上書きしません。バックアップ/削除方法は導入者の秘密管理方針に従ってください。

```js
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
const directory = process.env.STTD_SECRET_DIR;
if (!directory || !isAbsolute(directory)) throw new Error('Set an absolute STTD_SECRET_DIR outside the repository');
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
const jwks = { keys: [
  { ...ec, alg: 'ES256', use: 'sig', kid: randomUUID() },
  { ...rsa, alg: 'RS256', use: 'sig', kid: randomUUID() },
] };
const payloads = {
  'jwks.json': Buffer.from(JSON.stringify(jwks)),
  'cookie-keys.bin': randomBytes(32),
  'identifier-key.bin': randomBytes(32),
  'command-digest-key.bin': randomBytes(32),
};
try {
  for (const [name, bytes] of Object.entries(payloads)) {
    writeFileSync(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
} finally {
  for (const bytes of Object.values(payloads)) bytes.fill(0);
}
```

directoryのACLは別途制限してください。`mode: 0o600`だけでWindowsのACLを設定できるわけではありません。ファイル・バックアップ・JWK文字列の物理消去は保証しません。途中で止まった時も既存の鍵を自動で再生成しないでください。

Secret Managerで用途別の4 secretを作成し、それぞれ対応fileを**fileとして**登録します。既に作成済みのsecretへ登録するBash例は次の形です（project/secret名は自分で設定）。

```bash
gcloud secrets versions add "$JWKS_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/jwks.json"
gcloud secrets versions add "$COOKIE_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/cookie-keys.bin"
gcloud secrets versions add "$IDENTIFIER_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/identifier-key.bin"
gcloud secrets versions add "$DIGEST_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/command-digest-key.bin"
```

返された数値版を`projects/<PROJECT_NUMBER>/secrets/<SECRET_ID>/versions/<N>`で配置設定へ記録します。payloadをログ/issue/ソースへ転記せず、各版が有効でruntime SAに必要な読取り権限があることを確認します。

### KMS購読のmarkerを作る

起動時、両serviceは`sttdAuth/<kms.namespace>/config/kms-subscription`が設定と完全一致することを要求します。作成・修復は自動で行いません。選択したFirestore databaseのConsoleでcollection `sttdAuth` → document `<kms.namespace>` → subcollection `config` → document `kms-subscription`の順に進み、次のfieldだけを作ります。

| field | 値・Firestore型 |
| --- | --- |
| `version` | integer `2` |
| `format` | string `sttdkms1` |
| `namespace`・`environment`・`projectId`・`databaseId`・`cryptoKey` | 配置設定の`kms`と同じstring（environmentは`development`固定） |
| `writeVersion` | 配置設定と同じinteger |
| `readVersions` | 配置設定の数値版を昇順にしたintegerのarray |

`writeVersion`/`readVersions`をstringにしないでください。余分なfieldも拒否されます。既存markerがある時は値を照合して止め、別の導入を上書きしません。正しい形の定義は`src/storage/firestore/kms-subscription-format.ts`の`kmsMarkerDocument`です。

### Firestore rulesと索引除外の適用

Firebase ConsoleのFirestoreで**使用databaseを選択**し、Rulesへ`firestore/firestore.rules`の内容を適用します。Indexesのsingle-field exemptionsへ`firestore/firestore.indexes.json`の各`collectionGroup`/`fieldPath`を登録し、ascending・descending・arrayの索引を無効にします。対象は`oidc/sealed`、`owners/sealedUid`、`subscriptions/active.sealedUrl`、`subscriptions/active.sealedSecret`、`subscriptions/active.previousSecret.sealed`の5項目です（slashの左がcollection group、右がfield path）。[公式の索引管理手順](https://firebase.google.com/docs/firestore/query-data/indexing)に沿い完了を確認してください。raw JSONをConsoleのquery欄へ貼る操作ではありません。名前付きDBの場合も対象を間違えて既存DBへ適用しないでください。

## 4. 設定・build・包装

1. source rootで`npm ci --ignore-scripts --no-audit --no-fund`、`npm test`を実行します。試験は合成設定で行い、実Cloud/資格へ接続しません。
2. `src/config/deployment.ts`の全placeholderを自分の資源の参照値へ替え、最後に`configured: true`にします。[CONFIGURATION.md](CONFIGURATION.md)を参照してください。実秘密を書かず、導入者の実配置値を公開Gitへcommitしないでください。
3. `npm run build`の後、`npm run package`を実行します。API ZIP・MCP Cloud Build archive・receiptは`.tmp/sendtexttodots-artifacts-<digest12>/`へ作られます。包装はofflineで、Cloudへ送信・配置しません。

同じ内容で再度包装すると`output_exists`で止まります。上書き・自動削除は仕様上行いません。既存directoryに`api.zip`・`mcp.tar.gz`・`receipt.json`がそろっているか確認し、receiptの各archive SHA256と実fileのSHA256を照合して既存の成果物を使ってください。receiptはローカル包装の記録で、配置・認可の証拠ではありません。途中失敗で不完全な出力がある時は使わず、対象directoryと必要な成果物を確認してから手動で隔離し、同じ名前が空いた状態で包装し直します。`.tmp`全体を消して解決しないでください。

## 5. archiveから配置する

rootの`package.json`はローカルbuild/test用で、`main`や`start`を持つ配置用packageではありません。rootをそのまま`firebase deploy`やCloud Run source deployへ渡す手順ではありません。必ず包装済みarchiveを使います。

### stagingとbuildの準備

以下のBash変数を自分の値へ設定します。`ARTIFACT_DIR`は前節の出力directory、`STAGE`はGit作業folder外の新しい空directoryです。archiveを混ぜたり既存stagingへ重ねて展開しません。

```bash
mkdir "$STAGE/api" "$STAGE/mcp"
unzip "$ARTIFACT_DIR/api.zip" -d "$STAGE/api"
tar -xzf "$ARTIFACT_DIR/mcp.tar.gz" -C "$STAGE/mcp"
```

- `PROJECT_ID`・`PROJECT_NUMBER`・`REGION`は配置設定と同じ値。
- `API_SA`・`MCP_SA`は各runtime SAのメール形式、`MCP_SERVICE`は配置設定のservice名。
- `BUILD_SA`は選んだbuild SAのメール形式、`BUILD_SA_RESOURCE`は`projects/<PROJECT_ID>/serviceAccounts/<BUILD_SA>`。
- `IMAGE_URI`は作成済みDocker repository内の`<REGION>-docker.pkg.dev/<PROJECT_ID>/<REPOSITORY>/connect:<固有tag>`。他の版を上書きしないtagにします。
- `BUILD_LOGS_BUCKET`はbuild SAがログを書ける自分のGCS bucket URI。user-managed Build SAのログ保存条件を満たしてください。
- `WEB_KEY_ENV`は配置設定の`web.apiKeyEnv`と同じ名前。MCPの初回起動前に、Firebase Web API keyの値をこの名前でCloud Runの環境変数へ設定する必要があります。Consoleの変数欄又はGit作業folder外の保護したenv YAMLで設定し、値をコマンド履歴へ直接書きません。

### API（Cloud Functions 第2世代）

[gcloud functions deployの公式仕様](https://docs.cloud.google.com/sdk/gcloud/reference/functions/deploy)に沿った新規配置例です。既存同名functionがある場合は先に止め、更新してよい対象か確認します。

```bash
gcloud functions deploy sendtexttodotsapi \
  --project="$PROJECT_ID" --region="$REGION" --gen2 --runtime=nodejs22 \
  --entry-point=sendtexttodotsapi --source="$STAGE/api" \
  --service-account="$API_SA" --build-service-account="$BUILD_SA_RESOURCE" \
  --trigger-http --no-allow-unauthenticated \
  --memory=1GiB --cpu=1 --timeout=30s \
  --min-instances=0 --max-instances=3 --concurrency=20
```

APIの処理条件（1 CPU/1GiB、30秒、min0/max3、concurrency20）は`src/delivery/functions.ts`と合わせます。runtimeはCloud管理のNode22、ローカルNodeのpatchと同一とは限りません。配布設定のままでは起動しません。

### MCP/OAuth（DockerfileをCloud BuildしてCloud Runへ）

展開したMCP archiveには固定base imageのDockerfileがあります。[Cloud Build submit](https://docs.cloud.google.com/sdk/gcloud/reference/builds/submit)でimageを作り、成功したimageのdigestを確認します。

```bash
gcloud builds submit "$STAGE/mcp" --project="$PROJECT_ID" --region="$REGION" \
  --tag="$IMAGE_URI" --service-account="$BUILD_SA_RESOURCE" \
  --gcs-log-dir="$BUILD_LOGS_BUCKET"
```

`IMAGE_DIGEST_URI`へ、そのbuildで作った`<image>@sha256:<digest>`を設定します。`MCP_ENV_FILE`は前述のWeb API keyの環境変数を含む保護したYAMLのpathです。新規serviceに対する[Cloud Run配置](https://docs.cloud.google.com/run/docs/deploying)の例は次です。

```bash
gcloud run deploy "$MCP_SERVICE" --project="$PROJECT_ID" --region="$REGION" \
  --image="$IMAGE_DIGEST_URI" --service-account="$MCP_SA" \
  --port=8080 --cpu=1 --memory=1Gi --timeout=30s \
  --min-instances=0 --max-instances=3 --concurrency=20 \
  --env-vars-file="$MCP_ENV_FILE" --no-allow-unauthenticated
```

MCPのCPU/memory/instance数は上記の開始例であり、負荷試験済みの推奨値・費用上限ではありません。`PORT`はCloud Runが設定します。SA資格fileや`NODE_OPTIONS`等の拒否される環境変数を足さないでください。

### origin照合と外部到達

1. ConsoleでAPI/MCPのservice名・region・runtime SA・image/source・Web keyの環境変数名を照合します。事前に選んだ決定的URLが使用可能でdefault URLが無効化されていないこと、OAuth issuer/CORS/authorized domainが同じoriginを使うことを確認します。URLが違う場合は設定へ戻り、別URLへの自動置換や重ね配置で救済しません。
2. 上記例はCloud IAMの入口を非公開にしています。通常のbrowserとDotsが使えるようにする段階で、導入者が[Cloud Runの公開到達設定](https://docs.cloud.google.com/run/docs/authenticating/public)を確認し、API/MCPの各対象serviceだけへ必要な公開到達を許可します。組織policyで禁止されていれば、その制約を回避せず管理者へ相談してください。
3. `api.invoker`/`connect.invoker`のsource値は`private`のままです。Cloud IAMの入口と、アプリのFirebase/OAuth認証は別です。Cloud入口の公開到達を許しても、アプリのtoken/owner/署名検査は無効になりません。Firebase ID tokenはCloud IAM用ID tokenの代用品ではありません。
4. 起動失敗時は次節の条件を確認し、鍵・namespace・権限を無差別に作り直さないでください。

## 6. 接続・最初の送信・停止計画

[Dotsの受信テストと応答設定](DOTS_GUIDE.md)の順に、受信先Dotsへテスト用の指示文を貼り、送信した本文の一致を確認した後、運用用の指示文を貼ります。送信画面の接続案内から、選択言語の文面を表示・コピーできます。コピーだけではDotsへ送信されず、本文一致や切替完了を画面が自動判定することもありません。

1. MCP originの`/console`へアクセスしAppleログインします。画面はEnglish/日本語を選べます（ページ上部の言語リンク。初期言語はブラウザの言語設定）。Dots/ChatGPTのMCP server登録先は**MCP originの`/mcp`**です。`/console`やAPI originを登録先にしません。
2. Dots/ChatGPT側からOAuth接続し、同じFirebase利用者として明示同意します。`text.submitted`を購読して「受信中」であることを確認します。送信画面を開くだけでは購読は作られません。
3. MCP originの`/console`の空欄に本文を入力し1件送信。受信側で入力どおりの表示を確認します。指示として実行させたい場合はDots側にその扱いを指示します。STTD自身は本文を実行しません。
4. 直接APIを使う場合はREADMEの例を参照。Apple providerで認証した同じproject/UIDのFirebase ID tokenが必要です。Web画面のtokenを表示する管理toolは同梱しません。最初の確認には`/console`を使えます。
5. `delivered`はcallbackの2xx受領で、受信側の処理完了ではありません。結果不明なら送信前に控えた同じcommandIdで状態照会し、新IDで自動再送しません。
6. このaccountからの送信を止めるには`/console`の「接続を解除」を使います（画面で確認してから実行）。認可と購読が失効し、再開はChatGPTからの再接続です。別の接続画面はありません。

配置前に停止方法と保持費用を決めてください。接続解除は購読/Grantの失効で、Cloud資源の停止・廃棄ではありません。minInstances=0でも外部要求で起動し得ます。不要になったserviceの停止・削除と、DB/Secret/KMS/imageの保持はCloud側で別に判断します。暗号鍵の破棄は保存情報を復号不能にするため、費用だけを理由に一括削除しません。本sourceは自動停止/物理削除toolを含みません。

## 7. 詰まった時の確認

| 症状 | 最初に確認すること |
| --- | --- |
| `deployment_config_unconfigured` / `deployment_config_invalid` | placeholder・configured・origin・project number・namespace・secret数値版・設定後の再build |
| SDKの`environment_rejected` | Cloud Runのservice/revision/configuration、設定service名、拒否環境変数。ローカルserver起動や資格overrideで回避しない |
| 起動時の秘密/marker失敗 | JWKSのalg/完全な秘密鍵、raw bytes長、各secret版の有効性/権限、選択DBのmarkerの型/完全一致 |
| tokenが正しいように見えるのに認証失敗 | Apple provider・同project/UID・期限・失効状態と、**runtime SAのfirebaseauth.users.get** |
| browser/DotsがCloudの401/403でアプリに届かない | Cloud入口の公開到達/IAM。アプリ401と区別し、Firebase tokenをCloud IAM tokenの代わりにしない |
| 接続済みだが送れない | `/mcp`でtext.submitted購読が有効か。別UID・Grant失効・送信先置換待ち・期限を確認 |
| `output_exists` | 既存archive/receiptの完全性とhash。既存の内容を確認せず`.tmp`全体を削除しない |

## 互換性
### 0.3.0の互換性

0.3.0は新規導入専用です。

- 送信API・Eventsの契約が0.2.0から非互換に変わりました。送信は `/v2/commands` 系で、要求は `schemaVersion` 2・`commandId`・`text`・`createdAt`・`expiresAt` の5項目だけ、Eventsは `text.submitted`（dataは `schemaVersion` 2・`commandId`・`text`・`expiresAt` の4項目）です。0.2.0の `/v1/commands` 系route（404）、`schemaVersion` 1や `direction`・`taskId`・`taskLabel`・`revision` を含む要求（400）、旧イベント名 `shortcut.triggered` の購読（NotFound）は受け付けません。新旧の変換・別名・redirectはありません。入力元は[API.md](API.md)の新しい契約で送ってください。
- 保存形式の識別子（上の保存root・`sttdkms1`・markerのversion・command状態の文書形式）とOAuth scope・`/v1/web/*`のrouteは0.2.0から変えていません（旧接続画面`/connect`は0.3.0で廃止）。ただし、これは0.2.0で保存したGrant・購読・command状態をそのまま引き継げる保証ではありません。0.2.0の配置を0.3.0へ置き換える移行手順・自動移行は提供せず、確認もしていません。既存の保存データ・購読を流用せず、新しい導入（別の保存namespace・接続・購読）として0.3.0を配置してください。
- 0.2.0より前の版とは、OAuth scope名・Firestoreの保存root・KMS封緘の形式（prefix・format・AAD）も異なり、互換性がありません。それらの版で保存したGrant・購読・command状態・markerは読まず、旧scopeのtokenも受け付けません。
