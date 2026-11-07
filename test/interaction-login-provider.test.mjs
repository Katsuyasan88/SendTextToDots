// 接続画面のlogin scriptの回帰: 保存済みの認証（Apple・開発者コード・不明）を区別し、Appleの「続ける」はAppleの時だけ、
// コードの続行は機能onの時だけ別の操作、競合・切替で古いtokenを送らない。合成のFirebase/DOM/fetchだけ（通信・資格・実Auth 0）。
import assert from 'node:assert/strict';
import { test } from 'node:test';

const pages = await import('../dist/connect/pages.js');
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
const SOURCE = pages.INTERACTION_SCRIPT.split('\n').filter((line) => !line.startsWith('import ')).join('\n');
const IDS = ['sttd-message', 'sttd-continue', 'sttd-apple-login', 'sttd-switch-account', 'sttd-code-submit', 'sttd-continue-code', 'sttd-code-input'];

const appleUser = (n = 1) => ({ uid: `synthetic-apple-${n}`, isAnonymous: false, providerData: [{ providerId: 'apple.com' }], getIdToken: async () => `apple-token-${n}` });
const codeUser = () => ({ uid: 'sttdc_synthetic', isAnonymous: false, providerData: [], getIdToken: async () => 'code-token' });

async function page({ saved = null, code = 'off', popup = async () => appleUser(2), customUser = codeUser(), google = false, codeResponse = null, lang = 'en' } = {}) {
  const ids = google ? [...IDS, 'sttd-google-login'] : IDS;
  const nodes = Object.fromEntries(ids.map((id) => [id, { hidden: id !== 'sttd-message' && id !== 'sttd-code-input', disabled: false, textContent: '', value: '', onclick: null }]));
  const calls = { popup: [], signOut: 0, posts: [], custom: 0, codePosts: 0 };
  const auth = { currentUser: saved, authStateReady: async () => {} };
  const fake = {
    initializeApp: () => ({}),
    getAuth: () => auth,
    OAuthProvider: function OAuthProvider(id) { this.providerId = id; },
    GoogleAuthProvider: function GoogleAuthProvider() { this.providerId = 'google.com'; },
    signInWithPopup: async (_a, provider) => { calls.popup.push(provider.providerId); const user = await popup(); auth.currentUser = user; return { user }; },
    signInWithCustomToken: async () => { calls.custom += 1; auth.currentUser = customUser; return { user: customUser }; },
    signOut: async () => { calls.signOut += 1; auth.currentUser = null; },
  };
  const document = { body: { dataset: { sttdView: 'interaction-login', sttdFirebase: '{}', sttdLanguage: lang, sttdInteraction: 'synthetic-interaction', sttdCsrf: 'synthetic-csrf', sttdCode: code } }, getElementById: (id) => nodes[id] ?? null };
  const fetch = async (url, init) => {
    if (String(url).endsWith('/login')) { calls.posts.push(JSON.parse(init.body).idToken); return { status: 204 }; }
    if (String(url).endsWith('/code')) { calls.codePosts += 1; return codeResponse ?? { status: 200, json: async () => ({ customToken: 'synthetic-custom-token' }) }; }
    return { status: 500 };
  };
  const location = { reload: () => {} };
  const run = new AsyncFunction('initializeApp', 'getAuth', 'GoogleAuthProvider', 'OAuthProvider', 'signInWithCustomToken', 'signInWithPopup', 'signOut', 'document', 'fetch', 'location', SOURCE);
  await run(fake.initializeApp, fake.getAuth, fake.GoogleAuthProvider, fake.OAuthProvider, fake.signInWithCustomToken, fake.signInWithPopup, fake.signOut, document, fetch, location);
  return { nodes, calls, auth };
}
const visible = (n) => Object.entries(n).filter(([id, v]) => id !== 'sttd-message' && id !== 'sttd-code-input' && !v.hidden).map(([id]) => id).sort();

test('saved Apple session: Apple continue is shown, and continuing posts that Apple token once without a popup', async () => {
  const p = await page({ saved: appleUser(1) });
  assert.deepEqual(visible(p.nodes), ['sttd-continue', 'sttd-switch-account']);
  await p.nodes['sttd-continue'].onclick();
  assert.deepEqual(p.calls.posts, ['apple-token-1']);
  assert.equal(p.calls.popup.length, 0);
});

test('saved code session with code on: no Apple continue; a separate code continue posts the code token only on that action', async () => {
  const p = await page({ saved: codeUser(), code: 'on' });
  assert.deepEqual(visible(p.nodes), ['sttd-apple-login', 'sttd-continue-code']);
  assert.equal(p.calls.posts.length, 0);
  await p.nodes['sttd-continue'].onclick();
  assert.equal(p.calls.posts.length, 0, 'hidden Apple continue must not post a code token');
  await p.nodes['sttd-continue-code'].onclick();
  assert.deepEqual(p.calls.posts, ['code-token']);
  assert.equal(p.calls.custom, 0, 'no new code is issued');
});

test('saved code session with code off, unknown provider, or anonymous: not restored as Apple; only Apple sign-in is offered', async () => {
  for (const saved of [codeUser(), { uid: 'synthetic-pw', isAnonymous: false, providerData: [{ providerId: 'password' }], getIdToken: async () => 'pw-token' }, { uid: 'synthetic-anon', isAnonymous: true, providerData: [], getIdToken: async () => 'anon-token' }]) {
    const p = await page({ saved, code: 'off' });
    assert.deepEqual(visible(p.nodes), ['sttd-apple-login']);
    assert.equal(p.nodes['sttd-message'].textContent, 'The saved sign-in is not an Apple account. To continue, sign in with Apple.');
    assert.equal(p.calls.posts.length + p.calls.popup.length, 0);
  }
});

test('choosing Apple while a code session is saved signs out first, opens only an apple.com popup, and posts the Apple token', async () => {
  const p = await page({ saved: codeUser(), code: 'on' });
  await p.nodes['sttd-apple-login'].onclick();
  assert.equal(p.calls.signOut, 1);
  assert.deepEqual(p.calls.popup, ['apple.com']);
  assert.deepEqual(p.calls.posts, ['apple-token-2']);
});

test('a failed or non-Apple popup posts nothing and never falls back to the saved code token', async () => {
  const failed = await page({ saved: codeUser(), code: 'on', popup: async () => { throw new Error('popup closed'); } });
  await failed.nodes['sttd-apple-login'].onclick();
  assert.equal(failed.calls.posts.length, 0);
  assert.deepEqual(visible(failed.nodes), ['sttd-apple-login']);
  const notApple = await page({ popup: async () => codeUser() });
  await notApple.nodes['sttd-apple-login'].onclick();
  assert.equal(notApple.calls.posts.length, 0);
});

test('the user changing while the token is fetched means the old token is not posted', async () => {
  const user = appleUser(1);
  let p;
  user.getIdToken = async () => { p.auth.currentUser = appleUser(9); return 'apple-token-1'; };
  p = await page({ saved: user });
  await p.nodes['sttd-continue'].onclick();
  assert.equal(p.calls.posts.length, 0);
});

test('double clicks and a competing method while busy send only one login', async () => {
  let release;
  const user = appleUser(1);
  user.getIdToken = () => new Promise((resolve) => { release = () => resolve('apple-token-1'); });
  const p = await page({ saved: user, code: 'on' });
  const first = p.nodes['sttd-continue'].onclick();
  await p.nodes['sttd-continue'].onclick();
  await p.nodes['sttd-switch-account'].onclick();
  await p.nodes['sttd-code-submit'].onclick();
  assert.equal(p.nodes['sttd-apple-login'].disabled, true);
  release();
  await first;
  assert.deepEqual(p.calls.posts, ['apple-token-1']);
  assert.equal(p.calls.popup.length, 0);
  assert.equal(p.nodes['sttd-continue'].disabled, false);
});

test('no automatic popup or login at start for any saved kind', async () => {
  for (const [saved, code] of [[null, 'off'], [appleUser(1), 'off'], [codeUser(), 'on'], [codeUser(), 'off']]) {
    const p = await page({ saved, code });
    assert.equal(p.calls.popup.length + p.calls.posts.length + p.calls.signOut + p.calls.custom, 0);
  }
});

test('code login still works, posts only the token of the user it signed in, and shows no UID or token', async () => {
  const p = await page({ code: 'on' });
  p.nodes['sttd-code-input'].value = '123456';
  await p.nodes['sttd-code-submit'].onclick();
  assert.deepEqual(p.calls.posts, ['code-token']);
  const shown = Object.values(p.nodes).map((n) => n.textContent).join('|');
  assert.ok(!/sttdc_|synthetic|token/.test(shown));
});

test('the page has a hidden, separately labelled saved-code button, disabled when the code feature is off', () => {
  const web = { apiKey: 'synthetic-api-key', authDomain: 'synthetic-project.firebaseapp.com', projectId: 'synthetic-project' };
  const on = pages.renderInteractionLogin(web, 'synthetic-uid', 'Client', 'csrf', 'en', true);
  const off = pages.renderInteractionLogin(web, 'synthetic-uid', 'Client', 'csrf', 'en', false);
  assert.match(on, /<button type="button" id="sttd-continue-code" hidden>Continue with the saved code sign-in<\/button>/);
  assert.match(off, /<button type="button" id="sttd-continue-code" hidden disabled>/);
  // T232: 保存済みApple/Googleの両方を続けるため、続けるボタンの文言はprovider中立（意味は同じ「ログイン中のアカウントで続ける」）。
  assert.match(on, /id="sttd-continue" hidden>Continue with the signed-in account</);
});

// ---------- T232: Google・コード入力ロック（Google nodeを持つ版の合成DOMだけ） ----------
const googleUser = (n = 1) => ({ uid: `synthetic-google-${n}`, isAnonymous: false, providerData: [{ providerId: 'google.com' }], getIdToken: async () => `google-token-${n}` });

test('T232-G1 saved Google session: continue is shown (no Apple switch), continuing posts that Google token once without a popup', async () => {
  const p = await page({ saved: googleUser(1), google: true });
  assert.deepEqual(visible(p.nodes), ['sttd-apple-login', 'sttd-continue']);
  await p.nodes['sttd-continue'].onclick();
  assert.deepEqual([p.calls.posts, p.calls.popup], [['google-token-1'], []]);
});

test('T234-G4 saved Google names Google on continue in both languages; saved Apple keeps the neutral label; unchanged login paths', async () => {
  const en = await page({ saved: googleUser(1), google: true });
  assert.equal(en.nodes['sttd-continue'].textContent, 'Continue with the account signed in with Google');
  const ja = await page({ saved: googleUser(1), google: true, lang: 'ja' });
  assert.equal(ja.nodes['sttd-continue'].textContent, 'Googleでログイン中のアカウントで続ける');
  await ja.nodes['sttd-continue'].onclick();
  assert.deepEqual([ja.calls.posts, ja.calls.popup], [['google-token-1'], []]);
  const apple = await page({ saved: appleUser(1), google: true, lang: 'ja' });
  assert.equal(apple.nodes['sttd-continue'].textContent, 'ログイン中のアカウントで続ける');
  assert.deepEqual(visible(apple.nodes), ['sttd-continue', 'sttd-google-login', 'sttd-switch-account']);
  // 案内は方式を限定しない（Apple/Googleどちらでも、送信元と同じ方式・同じ本人）
  const web = { apiKey: 'synthetic-api-key', authDomain: 'synthetic-project.firebaseapp.com', projectId: 'synthetic-project' };
  assert.match(pages.renderInteractionLogin(web, 'synthetic-uid', 'Client', 'csrf', 'ja', false), /同じ方法（AppleまたはGoogle）・同じアカウント/);
  assert.match(pages.renderInteractionLogin(web, 'synthetic-uid', 'Client', 'csrf', 'en', false), /same method \(Apple or Google\) and the same account/);
  const none = await page({ google: true, lang: 'ja' });
  assert.equal(none.nodes['sttd-continue'].hidden, true);
  assert.ok(visible(none.nodes).includes('sttd-google-login'));
});

test('T232-G2 Google button opens only the google.com popup and posts the Google token; a non-Google result is not used', async () => {
  const p = await page({ google: true, popup: async () => googleUser(3) });
  assert.ok(visible(p.nodes).includes('sttd-google-login'));
  await p.nodes['sttd-google-login'].onclick();
  assert.deepEqual([p.calls.popup, p.calls.posts], [['google.com'], ['google-token-3']]);
  const q = await page({ google: true, popup: async () => appleUser(4) });
  await q.nodes['sttd-google-login'].onclick();
  assert.deepEqual(q.calls.posts, []);
});

test('T232-G3 account-exists-with-different-credential shows the fixed guidance (no link, no lookup, no post)', async () => {
  const p = await page({ google: true, popup: async () => { throw Object.assign(new Error('x'), { code: 'auth/account-exists-with-different-credential' }); } });
  await p.nodes['sttd-google-login'].onclick();
  assert.equal(p.calls.posts.length, 0);
  assert.match(p.nodes['sttd-message'].textContent, /already registered with a different sign-in method/);
});

test('T232-L1 code lock: a 403 session_locked locks code entry (message, submit/input disabled, no more code POSTs); Apple stays available', async () => {
  const p = await page({ code: 'on', google: true, codeResponse: { status: 403, json: async () => ({ error: { code: 'session_locked' } }) } });
  p.nodes['sttd-code-input'].value = '123456';
  await p.nodes['sttd-code-submit'].onclick();
  assert.match(p.nodes['sttd-message'].textContent, /locked/);
  assert.equal(p.nodes['sttd-code-submit'].disabled, true);
  assert.equal(p.nodes['sttd-code-input'].disabled, true);
  const before = p.calls.codePosts;
  p.nodes['sttd-code-input'].value = '654321';
  await p.nodes['sttd-code-submit'].onclick();
  assert.equal(p.calls.codePosts, before);
  assert.equal(p.nodes['sttd-apple-login'].disabled, false);
  // 他の403（session_locked以外）はロックにしない
  const q = await page({ code: 'on', codeResponse: { status: 403, json: async () => ({ error: { code: 'forbidden' } }) } });
  q.nodes['sttd-code-input'].value = '123456';
  await q.nodes['sttd-code-submit'].onclick();
  assert.equal(q.nodes['sttd-code-submit'].disabled, false);
});
