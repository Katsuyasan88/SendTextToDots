// 送信画面/console・OAuth interaction・利用者向けOAuthエラーの表示言語（en/jaだけ）と固定の英日辞書。
//   - 表示言語の決定: 表示専用cookie `sttd_language=en|ja` の明示選択を優先し、欠落・不正ならAccept-Languageの対応言語の優先順位（q値）で
//     日本語選好ならja、それ以外（header無し・不正・未対応言語だけ）はen。この値を認証・認可・owner・CSRFの判断に使わない。
//   - cookieはsession cookie（Max-Age/Expiresなし）、Path=/、SameSite=Lax、httpsではSecure。DB・localStorage・sessionStorageへ保存しない。
//   - 辞書は固定の文字列だけ。未知の入力を辞書キー・言語として受けず、HTML/JSへ埋め込む値は呼出し側がescape/textContentで扱う。
//   - API機械code・field・scope・route・送信本文は翻訳の対象にしない。

export type Language = 'en' | 'ja';

export const LANGUAGES: readonly Language[] = Object.freeze(['en', 'ja']);
export const DEFAULT_LANGUAGE: Language = 'en';
export const LANGUAGE_COOKIE = 'sttd_language';
/** 言語の明示選択に使うquery名（GETの表示だけ。formの送信・OAuthの状態変更には使わない）。 */
export const LANGUAGE_QUERY = 'lang';

export function isLanguage(value: unknown): value is Language {
  return value === 'en' || value === 'ja';
}

/**
 * Accept-Languageの対応言語（en/ja）の優先順位。RFC 9110の言語範囲とq値（0〜1、小数3桁まで）を読み、`ja`・`ja-*`と`en`・`en-*`・`*`だけを
 * 採用する。日本語のq値が英語より大きければja、同点・英語優先・header無し・不正・対応言語なしはen。q=0の言語は選ばない。
 * qの形が不正（範囲外・桁数超過・数値でない・qの重複・未知のparameter）な項目は、q省略（既定1）と同じにせず、その項目を採用しない。
 */
export function languageFromAcceptLanguage(header: unknown): Language {
  if (typeof header !== 'string' || header.length === 0 || header.length > 1024) return DEFAULT_LANGUAGE;
  let ja = 0;
  let en = 0;
  let wildcard = 0;
  for (const part of header.split(',')) {
    const [rangeRaw, ...params] = part.trim().split(';');
    const range = (rangeRaw ?? '').trim().toLowerCase();
    if (!/^(\*|[a-z]{1,8}(-[a-z0-9]{1,8})*)$/.test(range)) continue;
    let quality = 1;
    let valid = true;
    let seenQ = false;
    for (const param of params) {
      const match = /^\s*q\s*=\s*(0(\.[0-9]{0,3})?|1(\.0{0,3})?)\s*$/i.exec(param);
      if (match === null || seenQ) {
        valid = false;
        break;
      }
      seenQ = true;
      quality = Number(match[1]);
    }
    if (!valid) continue;
    if (range === 'ja' || range.startsWith('ja-')) ja = Math.max(ja, quality);
    else if (range === 'en' || range.startsWith('en-')) en = Math.max(en, quality);
    else if (range === '*') wildcard = Math.max(wildcard, quality);
  }
  if (ja > 0 && ja > en && ja >= wildcard) return 'ja';
  return DEFAULT_LANGUAGE;
}

/** Cookie headerから表示言語cookieの値を読む（同名が複数・不正な値はnull）。他のcookieの値は読まない・返さない。 */
export function languageFromCookieHeader(header: unknown): Language | null {
  if (typeof header !== 'string' || header.length === 0 || header.length > 8192) return null;
  let found: string | null = null;
  for (const pair of header.split(';')) {
    const index = pair.indexOf('=');
    if (index < 0) continue;
    if (pair.slice(0, index).trim() !== LANGUAGE_COOKIE) continue;
    if (found !== null) return null;
    found = pair.slice(index + 1).trim();
  }
  return isLanguage(found) ? found : null;
}

/** 明示選択（query → cookie）を優先し、無ければAccept-Language。 */
export function selectLanguage(input: { readonly query?: unknown; readonly cookie?: unknown; readonly acceptLanguage?: unknown }): Language {
  if (isLanguage(input.query)) return input.query;
  const fromCookie = languageFromCookieHeader(input.cookie);
  if (fromCookie !== null) return fromCookie;
  return languageFromAcceptLanguage(input.acceptLanguage);
}

/** 表示言語cookieの固定属性（Path=/・SameSite=Lax、httpsではSecure。Max-Age/Expires/Domainなし＝session cookie）。browser側の同期設定も同じ値を使う。 */
export function languageCookieAttributes(secure: boolean): string {
  return `Path=/; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** Set-Cookieの値（session cookie・Path=/・SameSite=Lax、httpsではSecure。Max-Age/Expires/Domainなし）。 */
export function languageCookie(language: Language, secure: boolean): string {
  if (!isLanguage(language)) throw new TypeError('unsupported language');
  return `${LANGUAGE_COOKIE}=${language}; ${languageCookieAttributes(secure)}`;
}

/** 言語の明示選択へ使うURL（同じpathへ`?lang=`を付ける。他のquery・fragmentは持ち越さない）。 */
export function languageHref(path: string, language: Language): string {
  return `${path}?${LANGUAGE_QUERY}=${language}`;
}

/** 固定辞書（キーはHTML/JSで共有）。値は表示文だけで、machine code・route・scope・本文を含まない。 */
export const MESSAGES = Object.freeze({
  en: Object.freeze({
    'common.productName': 'SendTextToDots',
    'common.language': 'Language',
    'common.languageEnglish': 'English',
    'common.languageJapanese': '日本語',
    'common.appleLogin': 'Sign in with Apple',
    'common.switchAccount': 'Sign in with a different Apple account',
    'common.continueSignedIn': 'Continue with the signed-in Apple account',
    'common.loginFailed': 'Could not sign in.',
    'common.loginRefresh': 'Could not refresh the sign-in state. Please sign in again.',
    'common.loginUnknown': 'Could not check the sign-in state.',
    'common.state.unlinked': 'Signed in. Dots is not connected yet.',
    'common.state.linked': 'Connection authorized. Waiting for receiving to start.',
    'common.state.subscribed': 'Receiving',
    'common.state.expired': 'Receiving has expired. Resume receiving from ChatGPT.',
    'common.state.change_pending': 'Waiting for confirmation of a destination change.',
    'common.startGuide': 'To start receiving, ask the SendTextToDots connection in ChatGPT to "start receiving on this Dots". After confirmation the state becomes "Receiving".',
    'common.disconnect': 'Disconnect',
    'common.disconnectConfirm': 'Disconnect SendTextToDots from Dots? Authorization and the subscription for this account are revoked. Sending stops until you connect again from ChatGPT.',
    'common.disconnectYes': 'Yes, disconnect',
    'common.disconnectNo': 'Cancel',
    'common.disconnecting': 'Disconnecting…',
    'common.disconnectFailed': 'Could not disconnect. The connection state has been checked again.',
    'common.disconnectDone': 'Disconnected.',
    'console.title': 'SendTextToDots send screen',
    'console.heading': 'SendTextToDots send screen',
    'console.intro': 'Sign in with the same Apple account as your source app, check the connection, and send one text to the connected Dots.',
    'console.account': 'Account',
    'console.accountChecking': 'Checking the sign-in state…',
    'console.accountSignedOut': 'Not signed in.',
    'console.accountSignedIn': 'Signed in with an Apple account.',
    'console.connection': 'Connection and receiving',
    'console.connectionSignedOut': 'Shown after you sign in.',
    'console.connectionChecking': 'Checking the state…',
    'console.connectionUnavailable': 'Could not check the connection state (this does not mean it is disconnected or unsubscribed). Sending is not possible.',
    'console.refresh': 'Check the state again',
    'console.state.subscribed': 'Receiving (you can send)',
    'console.send': 'Send',
    'console.textLabel': 'Text to send (used only on this page and not stored)',
    'console.textPlaceholder': 'Enter the text to send to Dots (up to 4096 bytes)',
    'console.sendOne': 'Send one message',
    'console.cancel': 'Cancel',
    'console.check': 'Check the result for the same ID',
    'console.new': 'New message',
    'console.note': '"Accepted" means the destination received this one message from SendTextToDots. Check the response from Dots in ChatGPT.',
    'console.sendDisabled': 'Sending is disabled after disconnecting. Connect again from ChatGPT to send.',
    'console.sending': 'Sending. You can cancel.',
    'console.inputInvalid': 'Enter text containing non-whitespace characters within 4096 bytes (unpaired surrogate characters cannot be sent). Nothing was sent.',
    'console.notSent': 'Nothing was sent because the sign-in state could not be checked.',
    'console.state.in_flight': 'Processing (the result is not final yet).',
    'console.state.delivered': 'The destination accepted it. Check the response from Dots (the reaction of Dots is not checked automatically).',
    'console.state.failed': 'Could not send.',
    'console.state.cancelled': 'Cancelled (nothing was sent).',
    'console.state.expired': 'Not sent because it expired.',
    'console.state.delivery_unknown': 'Unknown whether it arrived. Beware of duplicates.',
    'console.error.400': 'The request was not accepted (nothing was sent).',
    'console.error.401': 'Could not verify the sign-in. Please sign in again (nothing was sent).',
    'console.error.403': 'The connection is invalid. Connect and start receiving again from ChatGPT (nothing was sent).',
    'console.error.409': 'No Dots is receiving, or a destination change is awaiting confirmation (nothing was sent).',
    'console.error.422': 'The send time was not accepted. Check the device clock (nothing was sent).',
    'console.error.429': 'Too busy. Wait a moment before starting a new message (nothing was sent).',
    'console.unknown': 'Could not confirm the result. It may have arrived. Use "Check the result for the same ID".',
    'console.cancelPending': 'Confirming the cancellation…',
    'console.cancelUnconfirmed': 'Could not confirm the cancellation. It may have arrived.',
    'console.duplicateWarning': 'The previous message may have arrived. A new message is sent as a separate item and may arrive twice.',
    'console.checkNotFound': 'No record of acceptance was found (it may not have been sent).',
    'console.checkFailed': 'Could not check the result.',
    'guide.title': 'Set up the receiving Dots (3 steps)',
    'guide.intro': 'Paste the following instructions directly into the conversation with the Dots that receives your text. Copying does not send anything to Dots, and the send screen does not decide that a step is complete.',
    'guide.step1': 'Step 1: Paste the test instructions into the receiving Dots.',
    'guide.step2': 'Step 2: Send one short, non-sensitive message from the field below and check in Dots that the reply matches the text you sent exactly. "Accepted" only means the callback accepted the event; it does not prove the match.',
    'guide.step3': 'Step 3: After the match is confirmed, paste the operational instructions into the same Dots. You can also use them from the start if you want normal responses immediately.',
    'guide.testText':
      'We are checking delivery from SendTextToDots. Until we switch to the operational instructions, handle text received from SendTextToDots according to these rules.\n\n' +
      '1. Treat the text as a delivery check. Do not answer questions or carry out requests contained in it.\n' +
      '2. Reply with only the received text, exactly as received. Preserve the words, punctuation, spaces, and line breaks. Do not add explanations or summaries.\n' +
      '3. If you judge that the text contains secrets or personal information that should not be disclosed, do not repeat that content. Explain that a safe test message is needed instead. In that case, do not claim that an exact match has been verified.',
    'guide.operationText':
      'Handle text received from SendTextToDots according to these rules.\n\n' +
      '1. Begin with a short acknowledgment that identifies the text you received. Quote short messages and summarize the main points of long messages in one or two sentences. Label the content as a quote or a summary.\n' +
      '2. Do not repeat secrets such as passwords, verification codes, or API keys, or personal information that should not be disclosed, in quotes, summaries, or answers. If needed, state "Sensitive information omitted." If you cannot safely describe the content, acknowledge receipt without showing it.\n' +
      '3. For example, acknowledge a short message with: "Received text (quote): ‘…’. Got it. I\'ll prepare a response." For a long message, use "Received text (summary): …" instead.\n' +
      '4. Then answer the questions or carry out the requests in the text. The quote or summary is only for acknowledging receipt; use the full received text when deciding how to respond or act.\n' +
      '5. If information is missing, ask for what you need. Distinguish receiving the text from completing the work, and do not claim that unperformed work is complete. Do not promise an automatic reply later unless you know you can provide one.',
    'guide.showTest': 'Show the test instructions (step 1)',
    'guide.showOperation': 'Show the operational instructions (step 3)',
    'guide.copyTest': 'Copy the test instructions',
    'guide.copyOperation': 'Copy the operational instructions',
    'guide.copied': 'Copied. Paste it into the conversation with the receiving Dots.',
    'guide.copyFailed': 'Could not copy automatically. Select the text above and copy it manually.',
    'guide.copyUnavailable': 'This browser does not allow automatic copying here. Select the text above and copy it manually.',
    'interaction.title': 'SendTextToDots connection',
    'interaction.loginConfirmFailed': 'Could not verify the sign-in. Please start again.',
    'interaction.client': 'Connecting to: ',
    'interaction.loginGuide': 'Sign in with the same Apple account as your source app.',
    'interaction.consentQuestion': ' is asking to connect to SendTextToDots. If you allow it, text can be sent only to the Dots you subscribe.',
    'interaction.allow': 'Allow the connection to this Dots',
    'interaction.deny': 'Do not allow',
    'oauth.errorTitle': 'SendTextToDots',
    'oauth.error': 'The connection could not be completed.',
  }),
  ja: Object.freeze({
    'common.productName': 'SendTextToDots',
    'common.language': '言語',
    'common.languageEnglish': 'English',
    'common.languageJapanese': '日本語',
    'common.appleLogin': 'Appleでログイン',
    'common.switchAccount': '別のAppleアカウントでログイン',
    'common.continueSignedIn': 'ログイン中のAppleアカウントで続ける',
    'common.loginFailed': 'ログインできませんでした。',
    'common.loginRefresh': 'ログイン状態を更新できませんでした。もう一度ログインしてください。',
    'common.loginUnknown': 'ログイン状態を確認できませんでした。',
    'common.state.unlinked': 'ログイン済み・Dotsとの接続はまだありません',
    'common.state.linked': '接続許可済み・受信開始待ち',
    'common.state.subscribed': '受信中',
    'common.state.expired': '受信の期限が切れました。ChatGPTで受信を再開してください',
    'common.state.change_pending': '送信先の変更確認待ち',
    'common.startGuide': '受信を始めるには、ChatGPTのSendTextToDots接続で「このDotsで受信を開始」と依頼してください。確認が済むと「受信中」になります。',
    'common.disconnect': '接続を解除',
    'common.disconnectConfirm': 'SendTextToDotsとDotsの接続を解除しますか。このアカウントの認可と購読が失効し、ChatGPTから再接続するまで送信できなくなります。',
    'common.disconnectYes': 'はい、解除する',
    'common.disconnectNo': 'やめる',
    'common.disconnecting': '解除しています…',
    'common.disconnectFailed': '接続を解除できませんでした。接続状態を再確認しました。',
    'common.disconnectDone': '接続を解除しました。',
    'console.title': 'SendTextToDots 送信画面',
    'console.heading': 'SendTextToDots 送信画面',
    'console.intro': '入力元アプリと同じAppleアカウントでログインし、接続を確認してから、接続済みのDotsへ本文を1件送ります。',
    'console.account': 'アカウント',
    'console.accountChecking': 'ログイン状態を確認しています…',
    'console.accountSignedOut': 'ログインしていません。',
    'console.accountSignedIn': 'Appleアカウントでログイン中です。',
    'console.connection': '接続と受信の状態',
    'console.connectionSignedOut': 'ログインすると表示します。',
    'console.connectionChecking': '状態を確認しています…',
    'console.connectionUnavailable': '接続状態を確認できませんでした（未接続・未購読とは限りません）。送信はできません。',
    'console.refresh': '状態を再確認',
    'console.state.subscribed': '受信中（送信できます）',
    'console.send': '送信',
    'console.textLabel': '送る文（このページの中だけで使い、保存しません）',
    'console.textPlaceholder': 'Dotsへ送る文を入力してください（4096バイトまで）',
    'console.sendOne': '1件だけ送信',
    'console.cancel': '中止',
    'console.check': '同じIDの結果を確認',
    'console.new': '新しい送信',
    'console.note': '「受領」は送信先がSendTextToDotsからの1件を受け取ったという意味です。Dotsの返答はChatGPTの画面で確認してください。',
    'console.sendDisabled': '接続を解除したため送信できません。送るにはChatGPTから再接続してください。',
    'console.sending': '送信中です。中止できます。',
    'console.inputInvalid': '送る文は空白以外の文字を含め、4096バイト以内で入力してください（対にならない文字は送れません。送信されていません）。',
    'console.notSent': 'ログイン状態を確認できなかったため送信していません。',
    'console.state.in_flight': '処理中です（結果はまだ確定していません）。',
    'console.state.delivered': '送信先が受領しました。Dotsの返答を確認してください（Dotsの反応は自動では確認していません）。',
    'console.state.failed': '送信できませんでした。',
    'console.state.cancelled': '中止しました（送信されていません）。',
    'console.state.expired': '期限切れのため送信されませんでした。',
    'console.state.delivery_unknown': '届いたか分かりません。重複に注意してください。',
    'console.error.400': '送信内容を受け付けられませんでした（送信されていません）。',
    'console.error.401': 'ログインを確認できませんでした。もう一度ログインしてください（送信されていません）。',
    'console.error.403': '接続が無効です。ChatGPTで接続と受信開始をやり直してください（送信されていません）。',
    'console.error.409': '受信中のDotsが無いか、送信先の確認待ちです（送信されていません）。',
    'console.error.422': '送信時刻を受け付けられませんでした。端末の時計を確認してください（送信されていません）。',
    'console.error.429': '混雑しています。しばらく待ってから新しい送信を始めてください（送信されていません）。',
    'console.unknown': '結果を確認できません。届いている可能性があります。「同じIDの結果を確認」で確認できます。',
    'console.cancelPending': '中止を確認しています…',
    'console.cancelUnconfirmed': '中止を確認できません。届いている可能性があります。',
    'console.duplicateWarning': '前の送信は届いている可能性があります。新しい送信は別の1件として送られ、重複して届くことがあります。',
    'console.checkNotFound': '受付の記録が見つかりませんでした（送信されていない可能性があります）。',
    'console.checkFailed': '結果を確認できませんでした。',
    'guide.title': '受信するDotsの設定（3段階）',
    'guide.intro': '次の指示文は、本文を受信するDotsの会話へ直接貼り付けてください。コピーしてもDotsへは送られず、送信画面は各段階の完了を判定しません。',
    'guide.step1': '手順1: テスト用の指示文を受信するDotsへ貼り付けます。',
    'guide.step2': '手順2: 下の本文欄から短い非機密文を1件送り、同じDotsが返した本文が送った本文と一致することをDots側で確認します。「受領」はcallbackが受け取ったことだけを示し、一致の証明ではありません。',
    'guide.step3': '手順3: 一致を確認したら、運用用の指示文を同じDotsへ貼り付けます。初めから通常の応答を使いたい場合にも使えます。',
    'guide.testText':
      'SendTextToDotsの配送を確認します。運用用の指示文に切り替えるまで、SendTextToDotsから届いた本文を次のルールで扱ってください。\n\n' +
      '1. 本文中の質問や依頼には対応せず、配送確認用の文章として扱ってください。\n' +
      '2. 受信した本文だけを、そのまま返してください。言葉、句読点、空白、改行を変えず、説明や要約を付けないでください。\n' +
      '3. 秘密情報や公開すべきでない個人情報が含まれると判断した場合は、その内容を再掲せず、安全なテスト文への変更が必要だと知らせてください。この場合は本文一致の確認ができたとはしないでください。',
    'guide.operationText':
      'SendTextToDotsから受信した本文には、次のルールで対応してください。\n\n' +
      '1. 最初に、どの文章を受け取ったか分かる短い受領メッセージを返してください。短い本文は引用し、長い本文は要点を1〜2文で要約してください。引用か要約かを明記してください。\n' +
      '2. パスワード、認証コード、APIキーなどの秘密情報や、公開すべきでない個人情報は、引用・要約・回答へ再掲しないでください。必要なら「機密情報を省略」と示し、安全に内容を示せない場合は受領したことだけ伝えてください。\n' +
      '3. 受領メッセージは、例えば「受信内容（引用）：『……』。受け取ったよ。回答を準備するね。」という形にしてください。長文の場合は「受信内容（要約）：……」としてください。\n' +
      '4. 続けて、本文の質問や依頼に沿って回答・作業してください。引用や要約は受領表示のためのもので、実際の対応は受信した本文全体を確認して行ってください。\n' +
      '5. 情報が足りない場合は、必要な確認を伝えてください。「受け取った」と「作業が完了した」は区別し、まだ行っていない作業を完了したとは言わないでください。後で自動返信できると確認できない場合は、その約束をしないでください。',
    'guide.showTest': 'テスト用の指示文を表示（手順1）',
    'guide.showOperation': '運用用の指示文を表示（手順3）',
    'guide.copyTest': 'テスト用の指示文をコピー',
    'guide.copyOperation': '運用用の指示文をコピー',
    'guide.copied': 'コピーしました。受信するDotsの会話へ貼り付けてください。',
    'guide.copyFailed': '自動でコピーできませんでした。上の文面を選択して手動でコピーしてください。',
    'guide.copyUnavailable': 'このブラウザでは自動コピーを使えません。上の文面を選択して手動でコピーしてください。',
    'interaction.title': 'SendTextToDots 接続',
    'interaction.loginConfirmFailed': 'ログインを確認できませんでした。最初からやり直してください。',
    'interaction.client': '接続先: ',
    'interaction.loginGuide': '送信元アプリと同じAppleアカウントでログインしてください。',
    'interaction.consentQuestion': ' とSendTextToDotsの接続を許可しますか。許可すると、あなたが購読したDotsだけへ送信できます。',
    'interaction.allow': 'このDotsとの接続を許可',
    'interaction.deny': '許可しない',
    'oauth.errorTitle': 'SendTextToDots',
    'oauth.error': '接続を完了できませんでした。',
  }),
});

export type MessageKey = keyof (typeof MESSAGES)['en'];

/** 固定キーの表示文（未知のキーは型で拒否。実行時に未知の値が来た場合は空文字で、入力を反映しない）。 */
export function text(language: Language, key: MessageKey): string {
  const table: Readonly<Record<string, string>> = MESSAGES[isLanguage(language) ? language : DEFAULT_LANGUAGE];
  return Object.hasOwn(table, key) ? table[key]! : '';
}

/** browser scriptへ埋め込む辞書のJSON（両言語・固定内容。HTMLへは呼出し側がescapeして渡す）。 */
export function messagesJson(): string {
  return JSON.stringify(MESSAGES);
}
