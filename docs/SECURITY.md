# セキュリティとデータの扱い

[English](SECURITY_EN.md) | 日本語

公開用のプライバシーポリシーではありません。導入者は自分の配置について、保存場所・ログ・委託先・表示を確認してください。

## データの扱い

- 本文（`text`）・event bytesは送信APIの要求処理中のRAMだけで扱い、DB・キュー・ログ・応答へ保存・出力しません。DBへ書くのは本文を含まないcommand状態と鍵付きdigestだけです。自分で作ったBufferは処理後に0埋めしますが、RAM・SDK・OS内の物理消去は保証しません。
- 本人確認はFirebase Authentication（Apple provider）だけで、検証済みUIDを内部ownerへ結びます。氏名・メール・Apple raw ID・tokenを独自に保存しません（Firebase/Apple自身のaccount情報は別に存在します）。
- 本文は購読先（例: ChatGPT）へ届き、その後の保持・処理は受信側サービスの条件に従います。

| データ | 場所 | 保持の設計 |
| --- | --- | --- |
| owner（UIDとの対応・失効版・最終利用） | Firestore `sttdConnect` | 最終利用から90日無活動で失効 |
| OAuth record（Grant・token等。payloadはKMS封緘） | Firestore `sttdConnect` | 各期限。Grant/refreshは90日無活動で失効、取消で即失効 |
| 接続interaction | Firestore `sttdConnect` | 5分・単回 |
| callback URL・購読secret（KMS封緘） | Firestore `sttdAuth` | 有効な購読中。回転時の旧secretは5分 |
| command状態（ID・鍵付きdigest・購読参照・state・時刻。本文なし） | Firestore `sttdDelivery` | 24時間で利用不可 |
| 本文 | 要求処理中のRAM | 要求の終了・期限まで |

期限切れデータの物理削除処理は含まれていません（[LIMITATIONS.md](LIMITATIONS.md)）。

保存root・KMS封緘の形式（capsule prefix・format・AADのdomain）・OAuth scopeは0.2.0で導入した値を0.3.0でも使い、0.2.0より前の版のデータやtokenを読み替える・受け入れる経路はありません。封緘の開封はformat・domain・保存位置が一致した場合だけ成功し、所有・期限・署名・単回配送・認可の検査は変わりません。0.3.0は送信API・Eventsの契約が0.2.0と非互換で（v2・`schemaVersion` 2・`text.submitted`。旧v1・旧項目・旧イベント名は拒否）、保存形式の識別子が同じでも0.2.0のデータを引き継ぐ移行は提供・確認していないため、新規導入として配置してください（[INSTALL.md](INSTALL.md#030の互換性)）。

## 認可と秘密

- API・購読・照会・取消はtoken由来のownerを強制し、入力のownerIdを信用しません。Firebase ID token・MCPのOAuth token・Webhook secretを相互に流用しません。
- 長期の保護はCloud KMSの直接暗号化で、AADへ用途・recordId・owner等を束縛し、開封ごとに期待AADを作り直します。
- 4用途の固定秘密（署名JWKS・cookie鍵・識別子HMAC鍵・digest鍵）はSecret Managerの数値版を起動時に1回だけ読み、用途間で流用しません。
- 鍵・秘密・tokenの値をログ・応答・例外へ出しません。起動失敗の記録は固定のstage/codeと値を含まない整数maskだけです。
- 利用は運営者が明示登録した利用者だけです（`accessPolicy: explicit-allow-v1`、[CONFIGURATION.md](CONFIGURATION.md#access-admin)）。許可はFirebase project＋検証済みUIDの既存HMACへ結び、平文UIDを保存しません。OAuthのlogin・同意・code交換・refresh、購読（challengeの前と最終保存）、送信（受付と送出権の確定）を同じDBの最新の許可と世代で確かめ、読めない・不正な許可は一時障害として利用を拒否します（許可へ読み替えません）。照会・取消・購読解除・接続解除は許可に依存しません。登録・停止は明示実行の管理CLIだけで、通常のAPI/MCP/画面に管理routeはありません。Firestoreのclient rulesはdeny-allのままで、server SDKは通常runtimeと管理をrulesで区別しません。
- 配置設定は1 moduleに固定し、未設定・不整合ならSDK生成・資格・DB・外部HTTPの前に拒否します。資格・宛先・TLS・proxy・emulatorを変え得る環境変数があれば起動しません（[CONFIGURATION.md](CONFIGURATION.md)）。
- 送信画面は利用者のパソコンで動きます（[LOCAL_CONSOLE.md](LOCAL_CONSOLE.md)）。helperは127.0.0.1だけで待ち受け、Host/Originと起動ごとのnonceを検査し、固定5 routeだけを固定のAPI/MCP originへ利用者のBearer tokenつきで中継し、cookie・nonceを上流へ送らず、token・本文を保持しません。Cloud Runは送信画面を配信せず、CORS・権限は不変。Firebaseの読み込みは画面での明示ログイン時だけです。
- 表示言語cookie `sttd_language`（`en` / `ja`）は画面で言語を選んだ時に置く表示専用のsession cookieで、認証・認可・ownerの判断に使わず、token・個人情報を含みません。

<a id="mcp-oauth"></a>

## MCP/OAuth認証

- `oidc-provider` 9.12.2の固定profile（https issuer、resource `<issuer>/mcp`、scope `sttd:events` だけ）。PKCE S256・redirect・resource・scopeの一致を要求し、認可コードは単回です。
- 新しい認可は毎回、接続Webで本人（Firebase ID token検証済み）が明示同意します。同意は同ownerと元のinteraction・CSRFへ単回で束縛します。
- clientはCIMDで許可した1件だけ（client_id・redirect・JWKS URLの完全一致、`private_key_jwt`）。client assertionはclient_idとjtiの組を単回予約します。
- access tokenは15分のopaque Bearer。refreshは単回回転・再使用検知で同Grantを失効させます。購読はGrantへ束縛し、Grant失効後は配送しません。

<a id="safe-https-egress"></a>

## 安全なHTTPS送出

callbackの検証・配送・CIMD取得は共通の送出部品を使います。

- HTTPSの443だけ。userinfo・fragment・空白・制御文字・backslashを拒否。
- DNSの全回答IPを検証し、localhost・private・link-local・予約・metadata・IANA特殊用途範囲（Globally Reachableでも保守的に拒否、根拠は `references/`）、mapped・変換・zone・非正規表記を拒否します。検証したIPへ固定して接続し、hostnameでTLSを照合します。
- 期限は最大10秒、応答本文は8192 byteまで。redirectを追わず、圧縮応答を拒否し、呼出し元のheader・秘密を転送しません。
- 失敗は固定分類だけを返し、URL・IP・元例外を出しません。

## 主な脅威と対応

| 脅威 | 対応 |
| --- | --- |
| 他ユーザーへの誤配送 | token→owner→唯一の購読を固定し、送出権のtransactionで最新を再検査 |
| 二重配送 | owner当たり有効な購読は1つ、置換は本人承認。owner＋commandIdの単回送出、自動再送なし |
| 古い指示 | 60秒の寿命、送出前の期限確認、キュー・履歴再生なし |
| SSRF / DNS rebinding | 上記の安全な送出 |
| 秘密の漏えい | KMS封緘・Secret Manager・ログ禁止 |
| プロンプト注入 | 本文は利用者のデータとして運び、serverの指示文を混ぜない |
| 大量送信・費用 | ownerの件数枠・本文上限・Functionsのmax instance/concurrency。全体の費用上限・停止は導入者の運用 |

## 脆弱性の報告

英語の[報告方針と受付状態](../SECURITY.md)を参照してください。脆弱性はそこで案内するGitHubの非公開の受付経路から報告してください。公開issueへ脆弱性の詳細・秘密・実データ・tokenを書かないでください。報告ボタンがない場合は、問題の詳細を含めず、非公開の連絡方法だけを問い合わせてください。

## 開発者向け6桁コード

- コードは暗号学的乱数の000000〜999999で、発行から10分未満・1回だけ認証に使えます。使用・取消後も発行から少なくとも24時間（削除遅延中はそれ以上）同じ番号を発行しません。平文コードはDB・記録に保存せず、予約は配置秘密（identifierKey）から用途分離して導いた鍵のHMACで識別します。
- 6桁は総当たりに弱いため、試行は照合前に予約して数え（interaction・送信元・namespace全体）、全体上限はIPやinteractionを変えても回避できません。上限は第三者による一時的な利用妨害も起こし得ます。
- コードごとに新しい内部利用単位（専用UID）を作り、Appleの利用単位へ自動で紐付けません。運営者がその発行で予定したUID1件だけに利用許可を与えます。
- API/MCPは共通の本人確認で、custom providerであることだけでは受理せず、認証marker・専用UID・保存identityのstate/family・利用許可の世代を確かめます。再発行・取消はそのfamilyだけを失効させ、Appleや別コンソールへ波及しません。
- 6桁だけではコンソール用の資格や再発行権を得られません（発行元helperのメモリにある32byteの照会secretが必要）。
- Firebaseの作成/署名の失敗・応答消失・期限超過でコードを未使用へ戻しません。期限後に遅れて確定した接続は失効させます。
