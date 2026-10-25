// 接続Web・/console・OAuth interaction・利用者向けOAuthエラーの表示言語（en/jaだけ）と固定の英日辞書。
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
    for (const param of params) {
      const match = /^\s*q\s*=\s*(0(\.[0-9]{0,3})?|1(\.0{0,3})?)\s*$/i.exec(param);
      if (match) quality = Number(match[1]);
    }
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

/** Set-Cookieの値（session cookie・Path=/・SameSite=Lax、httpsではSecure。Max-Age/Expires/Domainなし）。 */
export function languageCookie(language: Language, secure: boolean): string {
  if (!isLanguage(language)) throw new TypeError('unsupported language');
  return `${LANGUAGE_COOKIE}=${language}; Path=/; SameSite=Lax${secure ? '; Secure' : ''}`;
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
    'common.stateUnavailable': 'Could not check the connection state.',
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
    'console.connectLink': 'Connection page (legacy)',
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
    'connect.title': 'SendTextToDots connection',
    'connect.heading': 'SendTextToDots connection',
    'connect.consoleGuide': 'The usual screen is the send screen, which includes connection management and disconnecting.',
    'connect.consoleLink': 'Open the send screen',
    'connect.consoleUnavailable': 'This page is the connection page. Sign in with Apple, check the state, and disconnect here.',
    'connect.loginConfirmFailed': 'Could not verify the sign-in. Please start again.',
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
    'common.stateUnavailable': '状態を確認できませんでした。',
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
    'console.connectLink': '接続画面（従来）',
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
    'connect.title': 'SendTextToDots 接続',
    'connect.heading': 'SendTextToDots 接続',
    'connect.consoleGuide': '通常は送信画面を使います。接続の管理と解除も送信画面でできます。',
    'connect.consoleLink': '送信画面を開く',
    'connect.consoleUnavailable': 'このページは接続画面です。Appleログイン・状態確認・接続解除はここで行います。',
    'connect.loginConfirmFailed': 'ログインを確認できませんでした。最初からやり直してください。',
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
