// 開発者向けコード（T-065）のプラグイン接続画面のコード入力（POST /interaction/{uid}/code の判定 developerCodeEntry）をHTTPで合成検証する。
//   - 機能offは固定404（本文・cookie・CSRFを読まない）。Origin欠落/違いは403。Content-Type/長さ1KiB/JSON exact/CSRF形の違反は400。
//   - interaction cookieの確認失敗とCSRF不一致ではコード交換を呼ばない（試行件数も消費しない）。成功時だけcustom tokenを同originへ返す。
//   - 交換の固定結果（rejected/rate_limited/failed/unavailable）をkms-serverと同じ固定statusへ写す。
//   - 別々の起動（別のexchange）は互いの機能on/offを参照しない。
// 127.0.0.1のlocal serverと合成portだけ。実oidc-provider/Firebase/ブラウザ/Cloud 0（実providerのcookie検査はkms-serverの既存経路で、ここでは合成）。

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';

import { developerCodeEntry } from '../dist/identity/developer-code-identity.js';

const CSRF = 'a'.repeat(43);
const STATUS = { not_found: 404, forbidden: 403, invalid_request: 400, link_unavailable: 400 };
const OUTCOME_STATUS = { token: 200, rejected: 400, rate_limited: 429, failed: 503, unavailable: 503 };

function fakeExchange(outcome = { kind: 'token', customToken: 'synthetic-custom-token' }) {
  const calls = [];
  return {
    calls,
    async exchange(input) {
      calls.push(input);
      return typeof outcome === 'function' ? outcome(input) : outcome;
    },
  };
}

/** 1つの起動相当（自分のexchange・interaction確認・CSRFだけを持つ）。 */
async function startEntry(exchange, options = {}) {
  const seen = { interaction: 0, csrf: 0 };
  let origin = '';
  const server = createServer(async (req, res) => {
    try {
      const uid = /^\/interaction\/([A-Za-z0-9_-]{1,128})\/code$/.exec(req.url ?? '')?.[1];
      if (uid === undefined || req.method !== 'POST') {
        res.writeHead(404).end();
        return;
      }
      const result = await developerCodeEntry(req, uid, {
        exchange,
        origin,
        checkInteraction: async () => {
          seen.interaction += 1;
          if (options.cookieRejected) throw new Error('link unavailable');
        },
        csrfAccepts: async (csrf) => {
          seen.csrf += 1;
          return csrf === CSRF;
        },
        sourceKey: req.socket.remoteAddress ?? 'unknown',
      });
      if (result.kind !== 'exchanged') {
        res.writeHead(STATUS[result.kind], { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: { code: result.kind } }));
        return;
      }
      const status = OUTCOME_STATUS[result.outcome.kind];
      const body = result.outcome.kind === 'token' ? { customToken: result.outcome.customToken } : { error: { code: result.outcome.kind } };
      res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: { code: 'link_unavailable' } }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const post = (body, headers = {}) =>
    fetch(`${origin}/interaction/interaction1/code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin, ...headers },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  return { post, seen, origin, close: () => new Promise((resolve) => server.close(resolve)) };
}

test('R1 feature off is a fixed 404 and reads neither cookie nor CSRF', async () => {
  const entry = await startEntry(null);
  try {
    const response = await entry.post({ csrf: CSRF, code: '012345' });
    assert.equal(response.status, 404);
    assert.deepEqual(entry.seen, { interaction: 0, csrf: 0 });
  } finally {
    await entry.close();
  }
});

test('R2 Origin, type, size and exact JSON are checked before cookie/CSRF and before consuming a code', async () => {
  const exchange = fakeExchange();
  const entry = await startEntry(exchange);
  try {
    assert.equal((await entry.post({ csrf: CSRF, code: '012345' }, { Origin: 'https://attacker.example' })).status, 403);
    assert.equal((await entry.post({ csrf: CSRF, code: '012345' }, { 'Content-Type': 'text/plain' })).status, 400);
    assert.equal((await entry.post({ csrf: CSRF, code: '012345', pad: 'x'.repeat(1100) })).status, 400);
    assert.equal((await entry.post('{"csrf":')).status, 400);
    assert.equal((await entry.post({ csrf: CSRF, code: '012345', extra: 1 })).status, 400);
    assert.equal((await entry.post({ csrf: 'short', code: '012345' })).status, 400);
    assert.equal((await entry.post({ csrf: CSRF, code: '1'.repeat(17) })).status, 400);
    assert.deepEqual(entry.seen, { interaction: 0, csrf: 0 });
    assert.equal(exchange.calls.length, 0);
    // Originなし（fetchは同originでもPOSTにOriginを付けるため、明示に空へは出来ない）→ 別のheaderなし送信で確認。
    const bare = await new Promise((resolve, reject) => {
      const url = new URL(`${entry.origin}/interaction/interaction1/code`);
      const body = JSON.stringify({ csrf: CSRF, code: '012345' });
      import('node:http').then(({ request }) => {
        const req = request({ host: url.hostname, port: url.port, path: url.pathname, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, (res) => {
          res.resume();
          resolve(res.statusCode);
        });
        req.on('error', reject);
        req.end(body);
      });
    });
    assert.equal(bare, 403);
    assert.equal(exchange.calls.length, 0);
  } finally {
    await entry.close();
  }
});

test('R3 interaction cookie failure and CSRF mismatch never call the exchange', async () => {
  const exchange = fakeExchange();
  const rejected = await startEntry(exchange, { cookieRejected: true });
  try {
    assert.equal((await rejected.post({ csrf: CSRF, code: '012345' })).status, 400);
    assert.equal(rejected.seen.csrf, 0);
  } finally {
    await rejected.close();
  }
  const entry = await startEntry(exchange);
  try {
    const response = await entry.post({ csrf: 'b'.repeat(43), code: '012345' });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, 'link_unavailable');
    assert.equal(exchange.calls.length, 0);
  } finally {
    await entry.close();
  }
});

test('R4 success returns a custom token only to the same-origin response; fixed outcome statuses', async () => {
  const outcomes = [
    [{ kind: 'token', customToken: 'synthetic-custom-token' }, 200],
    [{ kind: 'rejected' }, 400],
    [{ kind: 'rate_limited' }, 429],
    [{ kind: 'failed' }, 503],
    [{ kind: 'unavailable' }, 503],
  ];
  for (const [outcome, status] of outcomes) {
    const exchange = fakeExchange(outcome);
    const entry = await startEntry(exchange);
    try {
      const response = await entry.post({ csrf: CSRF, code: ' 012345 ' });
      assert.equal(response.status, status, outcome.kind);
      const body = await response.json();
      if (outcome.kind === 'token') assert.deepEqual(body, { customToken: 'synthetic-custom-token' });
      else assert.equal(JSON.stringify(body).includes('012345'), false);
      assert.equal(exchange.calls.length, 1);
      assert.equal(exchange.calls[0].interactionKey, 'interaction1');
      assert.equal(exchange.calls[0].code, ' 012345 ');
    } finally {
      await entry.close();
    }
  }
});

test('R5 two starts with their own parts do not leak enablement to each other', async () => {
  const exchange = fakeExchange();
  const enabled = await startEntry(exchange);
  const disabled = await startEntry(null);
  try {
    assert.equal((await disabled.post({ csrf: CSRF, code: '012345' })).status, 404);
    assert.equal((await enabled.post({ csrf: CSRF, code: '012345' })).status, 200);
    assert.equal((await disabled.post({ csrf: CSRF, code: '012345' })).status, 404);
    assert.equal(exchange.calls.length, 1);
  } finally {
    await enabled.close();
    await disabled.close();
  }
});
