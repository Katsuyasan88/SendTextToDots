// ローカル送信画面の実CONSOLE_SCRIPTを、Node標準のvmで動かすための合成browser fixture（browser・network・実SDK 0）。
//   - domFromHtml: 実HTMLの id/hidden/disabled/textarea/data属性/placeholder/初期textContent から合成DOM（setAttribute・querySelectorAll・cookie jar）を作る。
//   - runConsole: scriptの固定1行（Firebase SDKの動的import）だけを合成loaderへ差し替えて実行する。SDK読込回数・fetch・clipboard・cookieを観測できる。
// 全ての値は合成値。ID token/本文は固定の合成文字列。

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import vm from 'node:vm';

import { CONSOLE_SCRIPT, CONSOLE_SDK_BASE } from '../../dist/connect/console.js';

export const SDK_LOADER_LINE = `const loadSdkModules = () => Promise.all([import(SDK_BASE + 'firebase-app.js'), import(SDK_BASE + 'firebase-auth.js')]);`;

export const unescapeHtml = (value) => value.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));

export const settle = async () => {
  for (let i = 0; i < 25; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

export function gate() {
  let release;
  let fail;
  const promise = new Promise((resolve, reject) => {
    release = resolve;
    fail = reject;
  });
  return { promise, release: (value) => release(value), fail: (error) => fail(error) };
}

/**
 * 実browserのイベント経路（capture: 祖先→target、target、bubble: target→祖先）を最小限に再現する。
 * 祖先は、要素を含む`<section id="sttd-panel-N">`と、summary/preを含む`<details>`だけ（それ以外の入れ子は不要）。
 */
function dispatch(elements, target, type, init = {}) {
  const path = [];
  for (let node = target.parent; node; node = node.parent) path.unshift(node);
  const event = {
    type,
    target,
    key: init.key,
    defaultPrevented: false,
    propagationStopped: false,
    preventDefault() {
      this.defaultPrevented = true;
    },
    stopPropagation() {
      this.propagationStopped = true;
    },
  };
  const run = (node, phase) => {
    for (const listener of node.listeners[type]?.[phase] ?? []) {
      if (event.propagationStopped) return;
      listener(event);
    }
  };
  for (const node of path) {
    if (event.propagationStopped) break;
    run(node, 'capture');
  }
  if (!event.propagationStopped) {
    run(target, 'capture');
    if (type === 'click' && typeof target.onclick === 'function' && !event.propagationStopped) target.onclick(event);
    if (type === 'keydown' && typeof target.onkeydown === 'function' && !event.propagationStopped) target.onkeydown(event);
    run(target, 'bubble');
  }
  for (const node of [...path].reverse()) {
    if (event.propagationStopped) break;
    run(node, 'bubble');
  }
  // summaryの既定動作: 親detailsの開閉（preventDefaultされなければ）。
  if (type === 'click' && target.tag === 'summary' && !event.defaultPrevented && target.parent?.tag === 'details') target.parent.open = !target.parent.open;
  return event;
}

export function domFromHtml(html) {
  const elements = new Map();
  const writes = [];
  /** 要素の位置から包含するpanel/detailsを決めるための範囲表。 */
  const ranges = [];
  for (const match of html.matchAll(/<(section|details)\b[^>]*\sid="(sttd-[^"]+)"[^>]*>/g)) {
    const close = html.indexOf(`</${match[1]}>`, match.index);
    ranges.push({ id: match[2], tag: match[1], start: match.index, end: close });
  }
  for (const match of html.matchAll(/<(\w+)\b([^>]*\sid="(sttd-[^"]+)"[^>]*)>/g)) {
    const [, tag, attrs, id] = match;
    const after = match.index + match[0].length;
    let initial = '';
    if (tag === 'textarea') initial = unescapeHtml(html.slice(after, html.indexOf('</textarea>', match.index)));
    let textContent = tag === 'textarea' ? '' : unescapeHtml(html.slice(after, html.indexOf('<', after)));
    const attributes = {};
    for (const [, name, value] of attrs.matchAll(/\s([a-z0-9-]+)="([^"]*)"/g)) attributes[name] = unescapeHtml(value);
    const dataset = {};
    for (const [name, value] of Object.entries(attributes)) if (name.startsWith('data-')) dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
    const element = {
      id,
      tag,
      hidden: /\shidden(\s|$)/.test(attrs),
      disabled: /\sdisabled(\s|$)/.test(attrs),
      open: /\sopen(\s|$)/.test(attrs),
      value: initial,
      placeholder: attributes.placeholder ?? '',
      dataset,
      onclick: null,
      onkeydown: null,
      parent: null,
      position: match.index,
      listeners: {},
      addEventListener(type, listener, options) {
        const capture = options === true || (typeof options === 'object' && options !== null && options.capture === true);
        this.listeners[type] ??= { capture: [], bubble: [] };
        this.listeners[type][capture ? 'capture' : 'bubble'].push(listener);
      },
      get textContent() {
        return textContent;
      },
      set textContent(value) {
        textContent = String(value);
        writes.push(textContent);
      },
      setAttribute(name, value) {
        attributes[name] = String(value);
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
      /**
       * browserと同じく、disabled・hiddenの要素はclickイベントを起こさない。起こす場合は実際の経路（祖先のcapture→target→bubble）で配送する。
       * 戻り値: リンクはpreventDefaultの有無、それ以外はイベントが配送されたか。
       */
      click() {
        if (this.disabled || this.hidden) return false;
        const event = dispatch(elements, this, 'click');
        return tag === 'a' ? event.defaultPrevented : true;
      },
      /** keydownを実際の経路で配送する。戻り値はdefaultPrevented。 */
      keydown(key) {
        if (this.hidden) return false;
        return dispatch(elements, this, 'keydown', { key }).defaultPrevented;
      },
    };
    elements.set(id, element);
  }
  // 包含関係（panel/details）を親として結ぶ。最も内側の範囲を親にする。
  for (const element of elements.values()) {
    let parent = null;
    for (const range of ranges) {
      if (range.id === element.id || element.position <= range.start || element.position >= range.end) continue;
      if (parent === null || range.start > parent.start) parent = range;
    }
    element.parent = parent === null ? null : elements.get(parent.id);
  }
  const bodyAttrs = /<body([^>]*)>/.exec(html)[1];
  const dataset = {};
  for (const [, name, value] of bodyAttrs.matchAll(/\sdata-([a-z0-9-]+)="([^"]*)"/g)) dataset[name.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = unescapeHtml(value);
  const cookies = { writes: [], reads: 0, jar: new Map() };
  const document = {
    body: { dataset },
    documentElement: { lang: /<html lang="([a-z]+)">/.exec(html)[1] },
    title: /<title>([^<]*)<\/title>/.exec(html)[1],
    getElementById: (id) => elements.get(id) ?? null,
    querySelectorAll: (selector) => {
      assert.equal(selector, '[data-sttd-i18n]');
      return [...elements.values()].filter((element) => Object.hasOwn(element.dataset, 'sttdI18n'));
    },
    get cookie() {
      cookies.reads += 1;
      return [...cookies.jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    },
    set cookie(value) {
      const text = String(value);
      cookies.writes.push(text);
      const [pair] = text.split(';');
      const index = pair.indexOf('=');
      cookies.jar.set(pair.slice(0, index), pair.slice(index + 1));
    },
  };
  return { document, elements, writes, cookies };
}

/**
 * 合成Firebase SDK。load()がscriptの動的importの代わりに呼ばれる（回数を数える。modeで失敗を合成）。
 * auth.currentUserはsignIn後に合成userになる。popupはmodeに従う（ok / blocked / fail）。
 */
export function syntheticSdk({ restoredUser = false, token = 'synthetic-id-token', uid = 'uid-a' } = {}) {
  const calls = { loads: 0, loadMode: 'ok', popups: 0, popupMode: 'ok', signOuts: 0, tokens: 0, tokenMode: 'ok', providers: [], initialized: [], listeners: [], tokenGate: null };
  const makeUser = (id, value) => ({
    uid: id,
    async getIdToken() {
      calls.tokens += 1;
      if (calls.tokenMode === 'fail') throw new Error('synthetic token failure');
      if (calls.tokenGate) await calls.tokenGate.promise;
      return value;
    },
  });
  const user = makeUser(uid, token);
  const auth = {
    currentUser: restoredUser ? user : null,
    async authStateReady() {},
    onAuthStateChanged(listener) {
      calls.listeners.push(listener);
      return () => {};
    },
  };
  /** 別tab等での認証変化を合成する（別ownerへ切替 / null = ログアウト）。observerへ通知する。 */
  const changeUser = (id, value = 'synthetic-id-token-' + id) => {
    auth.currentUser = id === null ? null : makeUser(id, value);
    for (const listener of calls.listeners) listener(auth.currentUser);
  };
  const authModule = {
    getAuth: () => auth,
    OAuthProvider: class {
      constructor(id) {
        calls.providers.push(id);
      }
    },
    signInWithPopup: async () => {
      calls.popups += 1;
      if (calls.popupMode === 'blocked') throw Object.assign(new Error('popup blocked'), { code: 'auth/popup-blocked' });
      if (calls.popupMode === 'fail') throw new Error('synthetic sign-in failure');
      auth.currentUser = user;
      return { user };
    },
    signOut: async () => {
      calls.signOuts += 1;
      auth.currentUser = null;
    },
  };
  const appModule = { initializeApp: (config) => (calls.initialized.push(config), {}) };
  return {
    calls,
    auth,
    user,
    changeUser,
    load: async () => {
      calls.loads += 1;
      if (calls.loadMode === 'fail') throw new TypeError('synthetic import failure');
      return [appModule, authModule];
    },
  };
}

/**
 * CONSOLE_SCRIPTを合成DOM/fetch/SDKで実行する。fetchは同origin（localhost helper）への要求だけを受け、onFetch(entry)が応答
 * （{status, json}かthrowするPromise）を返す。navigatorは任意（無ければclipboard未対応）。
 */
export async function runConsole({ html, onFetch, sdk, navigator }) {
  const dom = domFromHtml(html);
  assert.ok(CONSOLE_SCRIPT.includes(`${SDK_LOADER_LINE}\n`), 'the fixed SDK loader line is present');
  const source = CONSOLE_SCRIPT.replace(SDK_LOADER_LINE, 'const loadSdkModules = () => __sdk.load();');
  assert.equal(/^\s*import\s/m.test(source), false, 'no static import in the browser script');
  assert.equal(source.includes('import('), false, 'no other dynamic import');
  assert.ok(CONSOLE_SCRIPT.includes(`'${CONSOLE_SDK_BASE}'`), 'the SDK base is the fixed CDN');
  const fetches = [];
  const fetch = async (url, init = {}) => {
    const entry = { url, method: init.method ?? 'GET', headers: { ...(init.headers ?? {}) }, body: init.body, credentials: init.credentials, redirect: init.redirect, cache: init.cache, signal: init.signal };
    fetches.push(entry);
    assert.ok(url.startsWith('/'), 'only same-origin relative requests');
    const { status, json } = await onFetch(entry);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (json === undefined) throw new SyntaxError('not json');
        return json;
      },
    };
  };
  const globals = { document: dom.document, fetch, crypto: { randomUUID }, TextEncoder, setTimeout, clearTimeout, AbortController, __sdk: sdk };
  if (navigator !== undefined) globals.navigator = navigator;
  const context = vm.createContext(globals);
  vm.runInContext(source, context, { filename: 'console-app.js' });
  await settle();
  const api = () => fetches.filter((entry) => entry.url.startsWith('/v2/'));
  const web = (path) => fetches.filter((entry) => entry.url === path);
  const stepState = (n) => dom.elements.get(`sttd-step-${n}`).getAttribute('data-sttd-state');
  const panelState = (n) => dom.elements.get(`sttd-panel-${n}`).getAttribute('data-sttd-state');
  /** panelの余白のクリック（targetはpanel自身）。非active内のcontrolはpointer-events:noneなので、その上のクリックもpanelがtargetになる。 */
  const clickPanel = (n) => dom.elements.get(`sttd-panel-${n}`).click();
  /** panelへのkeydown（戻り値はdefaultPrevented）。 */
  const keyPanel = (n, key) => dom.elements.get(`sttd-panel-${n}`).keydown(key);
  return { ...dom, fetches, api, web, stepState, panelState, clickPanel, keyPanel, el: (id) => dom.elements.get(id) };
}
