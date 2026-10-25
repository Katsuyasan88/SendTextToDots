# 未確認事項と制約

[English](LIMITATIONS_EN.md) | 日本語

確認した範囲と、残る未確認事項・制約を示します。

## 確認済みの範囲

2026-10-25、作者の開発環境で0.3.0のAppleログインと `text.submitted` の購読を行い、直接API（`/v2/commands`）と開発用 `/console` から異なる任意本文を各1件送信しました。日本語・改行を含む本文が本人の実Dotsへ入力どおり届き、重複なく表示されたことを本人が確認しています。確認はこの2件に限ります。

同日、サービスを停止後に再起動し、同じブラウザで受信中の表示を確認しました。受信側Dotsへ本文を作業依頼として扱うよう伝え、デモから送った単純な計算指示1件の結果と識別子が一致することも確認しています。作業を実行するのはDots側で、SendTextToDots自体は本文を解釈・実行しません。

### MacでのGitHub取得sourceの使用実績（本人報告）

2026-10-25付の作者提供資料で、MacでGitHubのcommit `ad276fccc504bc367df209edb694809570496c3e`（0.3.0）を取得し、製品コード・試験・依存を変更せずに配置できたと報告しています。変更は`src/config/deployment.ts`の配置値と、追加の`.firebaserc`・`firebase.json`という配置設定です。未設定のplaceholderのまま動くという意味ではありません。

MacはNode.js 22.23.2/npm 12.0.2で、`npm ci --ignore-scripts --no-audit --no-fund`とTypeScript buildに成功。`npm test`は108件成功・4件失敗で、失敗はmacOSで`127.0.0.2`へlistenする際の`EADDRNOTAVAIL`と報告されています。TLS試験には一時フォルダに用意したOpenSSL 3.6.4を使用し、sourceや試験を弱める変更はしていません。同じsourceのLinux Cloud Build（`node:22.23.3-trixie`、Node.js 22.23.3、OpenSSL 3.5.7）では合成設定・SDKとloopbackによる112件すべてが成功したとの報告です。

作者がAppleログイン・OAuth接続・Events購読後に`/console`から1件を送信し、日本語・改行を含む2行が本人の実Dotsに入力どおり届いたことを確認しています。該当command IDとAPIの`delivered`状態のログによる突き合わせは資料にありません。

これらは作者の別端末での導入・使用実績で、第三者による独立検証ではありません。MacのOS版/CPUは未記録です。Mac自動試験の全件合格、掲載した全導入コマンドの無修正再現、長期運転・負荷・費用上限を含む本番運用全般の検証済みを意味しません。

## 未確認

| 項目 | 状態 |
| --- | --- |
| 第三者のGoogle Cloud projectでの配置・動作 | 未確認。自動試験は合成SDK・合成設定・loopbackだけで、実Cloud・実資格・実callbackを使っていない |
| 受信側（Dots/ChatGPT）での処理 | 上記2件の表示と単純な計算指示1件以外は未確認。以前の版では短時間に複数送った時にまとめて処理される挙動があり、1件ごとの即時処理（個別応答）や任意の指示の実行完了は保証しない |
| 同じ利用者の複数入口（iOSアプリとWebで同じFirebase UID）の一連動作 | 未確認（0.3.0を含む） |
| service再起動を跨ぐ接続・購読の継続 | 作者の開発環境で、再起動後の同じブラウザの受信中表示と指示1件の配送を確認。長期間の継続や購読更新の全経路は未確認 |
| 負荷・同時実行・費用 | 未確認。費用上限・予算通知・停止手順は導入者の運用 |
| 保持期限後の物理削除 | 期限後は利用不可にするが、期限切れデータを物理削除する処理は含まれていない。Firestore TTL等の設定は導入者の判断 |
| account削除（本人の全データ削除） | 未実装 |
| 購読元clientの変更 | OAuth clientは `src/oauth/cimd.ts` のChatGPTのCIMD 1件に固定。他clientでは未確認 |
| macOS・Linuxでのbuild/test | 上記の作者提供資料ではMac build成功・試験108成功/4失敗、Linux Cloud Buildは112/112成功。Macのloopback試験の移植性は未解決。Windowsの確認版はWindows 11・Node 22.23.4・npm 10.9.9・TypeScript 7.0.2。全OS/版への保証ではない |
| 表示言語 | 英語/日本語の画面と言語cookieは合成試験だけで確認。実ブラウザでの動作と他言語は未確認で、英語・日本語以外は英語になる |
| ローカル送信画面 | helper・5段階セットアップ・中継は合成SDK/DOM/fetchとloopbackだけで確認。実ブラウザでのログイン・clipboard・Apple popup・実配置への中継は未確認。作者の過去の実配送は旧Cloud Run `/console`（現在のsourceには含まれない。配置済み環境に残っているかは配置時期による）で行ったもの |

## 含まれないもの

- iPhone/Apple Watchアプリ（入力元のclient）。方向の操作・定型指示の割当・本文の生成は入力元側の機能で、このsourceには含まれません。
- Cloud資源の作成・配置・停止のtool。包装（`npm run package`）はofflineでarchiveを作るだけです。
- KMS購読markerの作成tool（[INSTALL.md](INSTALL.md) の形式で導入者が作る）。
- 有料購入・利用枠の検証。self-hostの利用者・費用の管理は導入者が行います。

## 保証しないこと

- `delivered` は受信側callbackの2xx受領で、受信側アプリの処理完了・応答ではありません。
- 送出後の取消（届いたHTTPの撤回）。
- RAM・SDK・OS内の秘密・本文の物理消去。
- Cloud Runの終了猶予内の完全な終了、cold startの所要時間。
- OpenAI・Apple・Googleの公式製品ではなく、それらの提供・承認を受けたものではありません。

## 導入手順とNode版の検証範囲

[INSTALL.md](INSTALL.md)の配置コマンド例は、公開sourceの契約とGoogle Cloud公式資料に照らした手順です。第三者projectでのfresh setup全体、掲載した鍵生成・API例の実行、組織policyごとのIAM/公開到達の成立は未確認です。MacでのGitHub取得sourceの使用・実Dots到達は上記の本人報告を記録しましたが、掲載コマンドを全てそのまま実行した証明にはしません。

ローカルの確認版はNode.js 22.23.4/npm 10.9.9です。packageの`engines: >=22`は全ての22.xや上位majorの動作保証ではありません。使用する`URL.parse`は22.1.0、`zlib.crc32`は22.2.0追加のため、初期22.xは対象にできません。最低版の全機能検証やNode23以降の検証はしていません。Cloud管理のNode22 runtimeとMCPの固定base imageのpatchもローカル版と別で、同一環境ではありません。

`npm run package`は同じdigestの出力を上書きせず`output_exists`で停止します。archiveは依存を含まず配置先buildでregistryへ接続します。ローカル包装が成功しても、image取得/依存取得/Cloud Build/IAM/サービス起動を保証しません。
