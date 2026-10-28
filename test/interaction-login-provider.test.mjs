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

async function page({ saved = null, code = 'off', popup = async () => appleUser(2), customUser = codeUser() } = {}) {
  const nodes = Object.fromEntries(IDS.map((id) => [id, { hidden: id !== 'sttd-message' && id !== 'sttd-code-input', disabled: false, textContent: '', value: '', onclick: null }]));
  const calls = { popup: [], signOut: 0, posts: [], custom: 0 };
  const auth = { currentUser: saved, authStateReady: async () => {} };
  const fake = {
    initializeApp: () => ({}),
    getAuth: () => auth,
    OAuthProvider: function OAuthProvider(id) { this.providerId = id; },
    signInWithPopup: async (_a, provider) => { calls.popup.push(provider.providerId); const user = await popup(); auth.currentUser = user; return { user }; },
    signInWithCustomToken: async () => { calls.custom += 1; auth.currentUser = customUser; return { user: customUser }; },
    signOut: async () => { calls.signOut += 1; auth.currentUser = null; },
  };
  const document = { body: { dataset: { sttdView: 'interaction-login', sttdFirebase: '{}', sttdLanguage: 'en', sttdInteraction: 'synthetic-interaction', sttdCsrf: 'synthetic-csrf', sttdCode: code } }, getElementById: (id) => nodes[id] ?? null };
  const fetch = async (url, init) => {
    if (String(url).endsWith('/login')) { calls.posts.push(JSON.parse(init.body).idToken); return { status: 204 }; }
    if (String(url).endsWith('/code')) return { status: 200, json: async () => ({ customToken: 'synthetic-custom-token' }) };
    return { status: 500 };
  };
  const location = { reload: () => {} };
  const run = new AsyncFunction('initializeApp', 'getAuth', 'OAuthProvider', 'signInWithCustomToken', 'signInWithPopup', 'signOut', 'document', 'fetch', 'location', SOURCE);
  await run(fake.initializeApp, fake.getAuth, fake.OAuthProvider, fake.signInWithCustomToken, fake.signInWithPopup, fake.signOut, document, fetch, location);
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
  assert.match(on, /id="sttd-continue" hidden>Continue with the signed-in Apple account</);
});
