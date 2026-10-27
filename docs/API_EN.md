# API and events

English | [日本語](API.md)

This is the contract of source 0.3.0. The send API is the `/v2/commands` family, `schemaVersion` of requests and Events is the integer 2, and the event name is `text.submitted`. Arbitrary text passed by the source for each send (within the limits, lifetime and authentication conditions below) is delivered as is to the destination the user has subscribed. Direction, preset tasks, saved shortcuts and similar metadata are not part of the contract. The v1 contract of 0.2.0 and earlier is incompatible; old routes, old schemas and old event names are rejected ([INSTALL_EN.md](INSTALL_EN.md#compatibility-of-030)). The implementation (`src/commands/input.ts`, `src/policy.ts`, `src/delivery/`, `src/events/contract.ts`) is the source of truth for the values.

## 1. Overview

- Send API (Functions): an authenticated source sends one text, and during the processing of that request the service delivers it once over signed HTTPS to the user's valid subscription. There is no queue, automatic resend or storage of the text.
- MCP/OAuth service (Cloud Run): accepts the user's connection (OAuth) and MCP Events subscriptions (registration of the callback URL and secret). There is no MCP tool for sending.

## 2. Send API

`POST /v2/commands`. Required headers: `Authorization: Bearer <Firebase ID token>` (Apple provider), `Content-Type: application/json`, `Idempotency-Key: <commandId>`.

```json
{
  "schemaVersion": 2,
  "commandId": "d8d32ec5-9531-4b12-841a-b809ab45d3ef",
  "text": "今案内している電車の一本後で調べ直して",
  "createdAt": "2026-10-06T04:10:00Z",
  "expiresAt": "2026-10-06T04:11:00Z"
}
```

The request has exactly the five fields above, all required.

| Field | Rule |
| --- | --- |
| schemaVersion | The integer 2 only (1, 3 and others are 400) |
| commandId | UUID (36-character hex-hyphen form; version and variant are not checked). Must match Idempotency-Key case-insensitively. Internal matching and the commandId in responses are lower-case; the Events data keeps the form as sent |
| text | The string is delivered as sent. Leading/trailing whitespace, Japanese, emoji, line breaks and combining characters are preserved; there is no truncation, Unicode normalization or replacement by preset text. Empty, whitespace-only (judged by trim) and unpaired surrogates are rejected. At most 4096 UTF-8 bytes |
| createdAt, expiresAt | RFC 3339 in UTC (upper-case T/Z, no fractional seconds or 1 to 3 digits, an existing date-time between 1970 and 9999), expiresAt = createdAt + 60 seconds |
| Clock and lifetime | Rejected if createdAt is more than 30 seconds in the future of the server clock. At least 10 seconds must remain when a new command is accepted. The effective lifetime is min(expiresAt, receipt + 60 seconds) |
| Whole body | At most 8192 UTF-8 bytes (wire bytes including JSON escapes). A BOM, invalid UTF-8 or invalid JSON is rejected |
| Rate | 10 per minute per owner, burst 3 |
| Other | Unknown fields, missing fields, wrong types and duplicated keys (including duplicates after unescaping) are 400. `direction`, `taskId`, `taskLabel`, `revision` and any metadata object are unknown fields (400). ownerId, subscription ID, callback URL and secret are not accepted (the owner comes from the token and the destination from the valid subscription) |

Responses and states:

| Operation | Response |
| --- | --- |
| New POST | Processed within the request; HTTP 200 plus `state` (delivered / failed / cancelled / expired / delivery_unknown) |
| Repeated POST with the same ID | If the content is the same (the same five values; key order, JSON whitespace and escape forms do not matter) only the stored state is returned (202 in_flight while processing). A different text or timestamp is 409 idempotency_conflict. No redelivery. There is no remedy that resends new content with updated times under the same ID |
| `GET /v2/commands/{commandId}` | State lookup only. Another owner's command and a missing command are the same 404 |
| `POST /v2/commands/{commandId}/cancel` | cancelled if before dispatch. After the dispatch right is fixed it is delivery_unknown (an HTTP request that has been delivered cannot be withdrawn). A cancel that arrives before the original POST makes the later POST with the same ID cancelled regardless of its text |

A state response contains only `commandId`, `state`, `expiresAt` when present and `acknowledgedAt` for delivered; it never contains the text or the callback URL. States can be looked up for 24 hours after receipt.

A callback 2xx is delivered; 5xx and an unknown response after dispatch are delivery_unknown; 429, other 4xx and failures before TLS is established are failed; insufficient time before dispatch is expired. 410, redirects and invalid destinations stop that subscription.

The old v1 routes (`/v1/commands`, `/v1/commands/{commandId}`, `/v1/commands/{commandId}/cancel`) are 404 not_found and perform no processing. A wrong method on a v2 route is 405 method_not_allowed; sending `schemaVersion` 1 or old fields to v2 is 400 invalid_request. There is no conversion or redirect between old and new.

Errors are `{"error":{"code":"…","retryable":<boolean>}}`. Main codes: invalid_request(400), authentication_required(401), connection_revoked / access_denied(403), not_found(404), method_not_allowed(405), subscription_required / destination_change_pending / idempotency_conflict(409), command_expired / clock_skew(422), rate_limited(429, Retry-After), temporarily_unavailable(503). Even when retryable is true, do not resend the text automatically; look up the state of the same ID instead.

Access permission: a new POST (including a repeated POST of the same ID) is accepted only while the operator's explicit access record ([CONFIGURATION](CONFIGURATION_EN.md#access-admin)) is active and the destination subscription is bound to a Grant consented under the current access generation. Not registered, stopped, or an older-generation Grant gives 403 `access_denied` (retryable false; distinct from `connection_revoked`); when the permission cannot be checked the response is 503 `temporarily_unavailable`. If a stop is confirmed after acceptance, the send right is re-checked and the command ends as `failed` without sending (a command that already holds its send right settles under the existing contract). Looking up and cancelling commands does not require the permission.

Deadlines: the processing budget is the shorter of 20 seconds from receipt and the original lifetime, external HTTP takes at most 10 seconds, and the Functions timeout is 30 seconds.

The local send screen `/console` sends the text the user typed into its empty input to the API through the local helper in the same five-field form (there is no direction or preset selection). It also shows the connection state and disconnects through the existing `/v1/web/disconnect` after an explicit confirmation. The helper forwards the user's Bearer token to the fixed API/MCP origins, without forwarding the browser's Origin, cookies, or local nonce. The API CORS still allows only the three routes above from the configured MCP origin (allowed headers: authorization, content-type, idempotency-key; `Retry-After` exposed; no wildcard or credential cookies). There is no need to add localhost to the Cloud service's allowed origins. Old v1 routes with an Origin and other origins get a fixed 403; requests without an Origin proceed to normal processing without CORS headers (v1 is 404).

<a id="encryption-key"></a>
### Fetching your own public key (payload encryption, off by default)

Available only on deployments that enable payload encryption in the [deployment configuration](CONFIGURATION_EN.md#payload-encryption). On deployments where it is off, the response is `404 not_found`. Besides this fetch, [reissuing the key](#encryption-key-reissue) and [sending encrypted text](#encrypted-commands) below are provided.

`GET /v2/encryption-key` (`Authorization: Bearer <Firebase ID token>`, no body or query)

- There is one key per authenticated user unit (UID). Multiple devices of the same UID receive the same key, and a different UID gets a different key. The first fetch creates the key; later fetches return the same key. Repeated fetches never recreate the key.
- You cannot select anyone else's key. Specifying a user or key in the query or body returns `400 invalid_request`.
- Success is `200` and returns only the following public information (`Cache-Control: no-store`). Keep it in client memory for at most 5 minutes, and fetch again after receiving a 409 below.

```json
{
  "version": 1,
  "kid": "<lower-case UUID>",
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "scope": "<43-character base64url>",
  "publicJwk": { "kty": "RSA", "n": "<base64url>", "e": "AQAB", "kid": "<kid>", "alg": "RSA-OAEP-256", "use": "enc" },
  "publicKeySpki": "<base64url of the SPKI DER>",
  "createdAt": "<ISO 8601>"
}
```

| status | `error.code` | Meaning |
| --- | --- | --- |
| 401 | `authentication_required` | No Bearer token, or identity could not be verified |
| 403 | `access_denied` | The operator has not granted access, or access is suspended |
| 409 | `connection_required` | If there is no connection (owner) yet, connect through the normal connection steps and fetch again (fetching a key never creates a connection). If the connection was revoked or has not been used for 90 days, repeating the fetch or signing in does not revive it automatically (this API has no recovery operation) |
| 409 | `encryption_key_unavailable` | The key has not been used for 90 days and is unavailable. It is not recreated automatically |
| 429 | `rate_limited` | Too many fetch attempts (60 per minute and 1000 per UTC day; first creation 3 per minute and 10 per day). Wait for the `Retry-After` seconds |
| 503 | `temporarily_unavailable` | Temporary failure of storage, the protection key or the processing deadline. A failure of the dedicated protection key does not stop plaintext sending. Failures of components shared with existing sending, such as the shared database, can affect plaintext sending as before |

<a id="encryption-key-reissue"></a>
### Reissuing the key (payload encryption, off by default)

`POST /v2/encryption-key/reissue` (`Authorization: Bearer <Firebase ID token>`, `Content-Type: application/json`, `Idempotency-Key: <requestId>`). The body is exactly `{"requestId":"<UUID>","mode":"normal"}` or `"mode":"compromised"`, 1024 bytes or less. `requestId` must match `Idempotency-Key`. A query or other items return `400 invalid_request`. Only your own key is recreated; you cannot select anyone else's key. On deployments where encryption is off, the response is `404`.

- Success is `200` with the public information of the new key (the same shape as fetching the public key; the private key is never returned, including its protected form).
- `normal`: the previous key can still decrypt for 120 seconds and then cannot. Older keys stop being usable immediately. `compromised` (suspected leak): all previous keys stop being usable immediately. In both cases, a send whose key became unusable before the right to send was confirmed is not sent. A send after that confirmation cannot be withdrawn.
- Resending the same `requestId` and `mode` returns the original result as is (even if a later reissue happened, it is the result of that time; check the current key with the fetch). While processing, the response is `202` (`{"requestId":…,"state":"in_flight"}`, `Retry-After: 1`) and no extra key is created. The same `requestId` with a different `mode` returns `409 idempotency_conflict`.
- If processing does not finish within its deadline (at most 20 seconds from receipt) or generation/storage fails, that `requestId` returns `409 key_reissue_failed` and is not recreated automatically. The old key stays usable. To reissue again, send explicitly with a new `requestId`. When the response is unknown (such as `503`), first resend the same `requestId` to confirm the result.
- If a reissue with another `requestId` is in progress, the response is `409 key_reissue_in_progress`; if there is no key yet, `409 key_not_initialized`.
- Limits: at most 4 reissues per 24 hours (failures and in-progress ones count), and at least 60 seconds after the previous reissue. Attempts with different `requestId`s are limited to 3 per minute and 10 per UTC day. Resending the same `requestId` does not use these, but as an HTTP request it shares the fetch limit (60 per minute and 1000 per UTC day). Exceeding a limit returns `429` with `Retry-After`.
- Other devices follow by fetching the public key again after keeping it for at most 5 minutes, or when they receive `409 encryption_key_unavailable`.
- Retention: past keys that became unusable are removed 24 hours after the switch, and reissue records after 24 hours, at the next normal update of that user's keys. The physical deletion time is not guaranteed.

401, 403, `409 connection_required`, `409 encryption_key_unavailable` (a key unused for 90 days) and `503` are the same as fetching the public key.

<a id="encrypted-commands"></a>
### Sending encrypted text (payload encryption, off by default)

`POST /v2/encrypted-commands` (`Authorization: Bearer <Firebase ID token>`, `Content-Type: application/jose`, `Idempotency-Key: <commandId>`). On deployments where it is off, the response is `404`.

- The body is only the ASCII of a five-segment JWE Compact Serialization (RFC 7516), 12288 bytes or less in total. Only `alg` `RSA-OAEP-256` and `enc` `A256GCM` are accepted. The CEK is 32 random bytes per request and the IV is 12 bytes. RSA-OAEP uses SHA-256 for both the hash and MGF1 with an empty label. base64url is unpadded.
- The protected header has exactly these nine items: `{"alg":"RSA-OAEP-256","enc":"A256GCM","typ":"sttd-command+jwe","kid":"<fetched kid>","sttdVersion":1,"scope":"<fetched scope>","commandId":"<UUID>","createdAt":"<time>","expiresAt":"<time>"}`. Duplicate or unknown items, compression (`zip`) and other algorithms are rejected. The AAD is the ASCII bytes of the protected header segment, so all nine items are authenticated.
- The encrypted plaintext is only the UTF-8 of the `text` to send (4096 bytes or less; empty or whitespace-only is not allowed). The conditions on `commandId`, `createdAt` and `expiresAt` and the match with `Idempotency-Key` are the same as plaintext sending. Line breaks, whitespace and Unicode representation arrive unchanged.
- For checking implementations, fixed vectors made with a synthetic test-only key (positive cases and negative cases for tag, AAD, nonce, kid, UTF-8 and maximum length) are in `test/fixtures/encrypted-payload-vectors.json`. The key is for tests only and must never be used in a deployment.
- The body of the signed event sent to Dots is at most 25088 bytes, separate from the receive limits (including the case where every character of a 4096-byte text expands to a JSON `\u00XX` escape). This API does not guarantee that the receiver (Dots) accepts this size.
- The response is the same status response as plaintext sending (`commandId`/`state` etc.). With the same `commandId` and the same content, sending as plaintext, encrypted, re-encrypted or with another key converges to the same state and is not delivered twice. Different content returns `409 idempotency_conflict`. Use `/v2/commands/{commandId}` for status and cancellation.

| status | `error.code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_encrypted_request` | Shape, limits, cryptographic authentication or the content checks failed, or the key belongs to someone else or is unknown. The reason is not distinguished |
| 409 | `encryption_key_unavailable` | Your key was revoked or is unavailable. It is refused without opening. For a request you already sent, first query its status with `GET /v2/commands/{commandId}`. When the result is unknown, do not automatically resend with a new ID or an extended expiry. Fetch the public key again separately when needed |
| 429 | `rate_limited` | Too many decryption attempts (30 per minute and 1000 per UTC day; malformed requests, key mismatches and failures also count). Separate from the delivery count limit |
| 503 | `temporarily_unavailable` | Temporary failure of storage, the protection key or the processing deadline. A failure of the dedicated protection key does not stop plaintext sending |

401, 403 and `409 connection_required` are the same as fetching the public key. A body larger than 12288 bytes returns `400 invalid_encrypted_request` before identity verification or attempt counting. Other existing responses (`422` for time and expiry, `429` for the delivery count) are the same as plaintext sending.

## 3. Send screen and connection state

The send screen is served by the local helper on your computer ([LOCAL_CONSOLE_EN.md](LOCAL_CONSOLE_EN.md)), not by Cloud Run. The MCP service serves only the OAuth interaction pages; `/console`, `/connect` and their assets are 404 there like any unknown path. The helper relays the pressed actions to the routes below with your Bearer token.

| Endpoint | Content |
| --- | --- |
| `GET /v1/web/connection` | Bearer Firebase ID token. `{state, access}` (access is `allowed`, `denied` or `unavailable`; no UID, list or generation is returned) |
| `POST /v1/web/disconnect` | Revokes the same owner's Grant and subscription. `{state}` |
| `/interaction/{uid}`, `…/login`, `…/consent`, `…/deny`, `/interaction/app.js` | OAuth authorization interaction (same origin, CSRF, explicit consent every time) and its fixed script |
| `/mcp` | MCP (Bearer access token, scope `sttd:events`) |
| `/.well-known/*`, `/oauth/*` | OAuth metadata, token and other endpoints (`oidc-provider`) |

The `/v1/web/*` routes, the OAuth routes and the scope are separate from the send API version and do not change in 0.3.0.

Display language: the HTML pages (`/console`, the OAuth interaction and the user-facing OAuth error page) are rendered in English or Japanese. An explicit choice through `?lang=en` or `?lang=ja` is stored in the display-only session cookie `sttd_language` (Path=/, SameSite=Lax, Secure, no expiry); the send screen writes the same cookie in the browser when you switch its language, so the last choice is kept; without it the `Accept-Language` preference decides (Japanese when preferred, otherwise English). The cookie is never used for authentication or authorization, and machine codes, fields, scopes, routes and the text being sent are never translated.

State priority: no valid Grant → unlinked, a destination replacement awaiting approval → change_pending, a valid subscription → subscribed, the most recent subscription expired → expired, otherwise (no subscription or subscription cancelled) → linked.

The access permission (`access`) is returned separately from the subscription `state`. When it cannot be read, the response is still HTTP 200 with `state` and `access: "unavailable"`, and new use is not possible. At the OAuth interaction login, a person who is not registered or is stopped gets 403 `access_denied` (the page says "This account is not permitted to use this service. Please check with the operator.") and no owner is created. If a stop or re-registration happens before consent completes, the same notice is shown with 403 and the Grant is not made usable. Code exchange and refresh accept only a Grant of the same generation; otherwise the existing `invalid_grant` applies. MCP `events/subscribe` (including extension and secret rotation) returns the existing Forbidden (`data.reason` = `access_revoked`), checked both before the challenge and at the final save. `events/unsubscribe`, disconnect, status lookups and cancellation do not require the permission.

## 4. MCP Events

`server/discover` on `/mcp` declares `events:{}` and `tools:{}`, and `tools/list` is always empty. The only event returned by `events/list` is `text.submitted` (delivery of arbitrary text sent by an authenticated source to the user's subscription). "submitted" is the event name for acceptance and delivery of the text; it does not mean the receiver finished processing. Subscriptions and delivery are limited to the authenticated owner. Subscribing to or unsubscribing from unknown event names such as the old `shortcut.triggered` is NotFound (-32011, `data.kind` = `event`) and does not reach storage, cryptography or the challenge.

| Subscription input | Rule |
| --- | --- |
| callback URL | UTF-8, 1 to 2048 bytes, HTTPS/443, no userinfo, fragment, whitespace, control characters or backslash, and it passes the IP checks of the safe egress |
| secret | `whsec_` + base64 (24 to 64 bytes) |
| ttlMs | omitted = 24 hours, null = no expiry, a positive integer up to 24 hours |
| cursor | omitted or null only (no history replay) |

A subscription becomes valid only when the signed challenge (at most 10 seconds) matches. Replacing the callback with another one waits for the user's approval.

The payload (`data`) is exactly the four fields `schemaVersion`(2), `commandId`, `text` and `expiresAt` in this order, with no additional fields (`createdAt` is not included). `text` is the same string the send API accepted.

```json
{
  "eventId": "7c0f2a8e-1d34-8b6a-9f10-2e4d6c8a0b12",
  "name": "text.submitted",
  "timestamp": "2026-10-06T04:10:00.000Z",
  "data": { "schemaVersion": 2, "commandId": "d8d32ec5-9531-4b12-841a-b809ab45d3ef", "text": "今案内している電車の一本後で調べ直して", "expiresAt": "2026-10-06T04:11:00.000Z" },
  "cursor": null
}
```

`timestamp` is the server's receipt time and `expiresAt` is the lifetime the server decided (min(expiresAt, receipt + 60 seconds)); both are ISO 8601 in UTC with milliseconds. The `payloadSchema` of `events/list` is a JSON Schema that marks the four fields above as `required` with `additionalProperties: false`. The `minLength` 1 and `maxLength` 4096 of `text` in the schema are a rough character-count bound; the strict checks for 4096 UTF-8 bytes, whitespace-only text and unpaired surrogates are done by the send API's input validation.

The eventId is a UUIDv8 derived from the identifier key and an HMAC of owner/commandId, so it is the same for the same owner and commandId and different for a different owner. Signatures use the Standard Webhooks format over the exact bytes sent. During the 5 minutes of a secret rotation both the old and the new secret sign. Including `expiresAt` does not guarantee that the receiver honours the lifetime.


<a id="firebase-sessions"></a>

## Firebase sessions and automated senders

Authentication currently accepts Firebase Authentication with the Apple provider (and, only on deployments that set `developerLogin: 'operator-code-v1'`, developer 6-digit code accounts), for the same Firebase project and UID as the user's Dots connection. Any app or script can be the input source if it meets this API contract; a particular phone, watch or source app is not required. The receiving MCP OAuth connection is separate from the sender's Firebase session.

Firebase ID tokens expire after about one hour. An app using a Firebase client session should obtain a current token with the SDK before sending. In the local send screen, each authenticated action calls `user.getIdToken()`, which can refresh an expired or soon-to-expire token. This does not normally require manual Apple sign-in every hour. Signing out, revocation or another authentication problem can still require signing in again. See [Firebase session lifetimes](https://firebase.google.com/docs/auth/admin/manage-sessions) and [getIdToken](https://firebase.google.com/docs/reference/js/auth.user.md#usergetidtoken).

The Node.js example below uses the supplied ID token only; it performs no sign-in or token refresh. A long-running or unattended sender must provide its own supported authentication/session handling. This repository does not bundle a headless Apple sign-in flow, a token-export tool, a sender daemon, a long-lived send-only key or automatic resend. Use SDK session APIs instead of extracting a refresh token from the browser. A Firebase Web API key identifies the Firebase configuration and cannot replace a user's ID token.

<a id="direct-client-example"></a>

## Direct client example

After deployment and subscription, save this example as a local `.mjs` file and run it with Node.js 22. Set `STTD_API_ORIGIN` to your deployed HTTPS API origin and `STTD_FIREBASE_ID_TOKEN` to a current Firebase ID token authenticated with the Apple provider. These variables are for this client example, not server configuration. Keep tokens out of source control and shared logs. Running it sends one real message and may incur service costs.
```js
// Node.js 22; set STTD_API_ORIGIN and STTD_FIREBASE_ID_TOKEN locally.
const origin = process.env.STTD_API_ORIGIN;
const token = process.env.STTD_FIREBASE_ID_TOKEN;
if (!origin || !token) throw new Error('Set the API origin and Firebase ID token');
const commandId = crypto.randomUUID();
console.log('commandId:', commandId); // Keep this ID even if the request fails.
const now = Date.now();
const response = await fetch(new URL('/v2/commands', origin), {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': commandId,
  },
  body: JSON.stringify({
    schemaVersion: 2,
    commandId,
    text: 'Hello Dots',
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
  }),
});
console.log(response.status, await response.json());
```
The request has exactly five fields. `Idempotency-Key` must match `commandId`; `expiresAt` must be exactly 60 seconds after `createdAt`, with at least 10 seconds remaining at acceptance. Text is limited to 4096 UTF-8 bytes. The example generates fresh timestamps and a UUID for each run, so rerunning it sends a new command.

An illustrative response is `{"commandId":"d8d32ec5-9531-4b12-841a-b809ab45d3ef","state":"delivered","expiresAt":"2026-10-25T00:01:00.000Z","acknowledgedAt":"2026-10-25T00:00:01.000Z"}`; actual identifiers and times vary. A new POST normally returns HTTP 200 with `delivered`, `failed`, `cancelled`, `expired`, or `delivery_unknown`. A repeated identical command may return 202 `in_flight` while processing. HTTP 2xx alone does not prove delivery: inspect `state`. `delivered` means callback acceptance, not completion of Dots processing.

The ID is printed before sending so it remains available if the request or response parsing fails. Do not resend automatically after an uncertain result. Query `GET /v2/commands/{commandId}` with the same authentication instead. See [API](API_EN.md) for errors, cancellation, rate limits, and idempotency rules.

## Code entry on the plugin connection screen (developer 6-digit code)

Only on deployments where the feature is enabled, the OAuth interaction login screen shows "Connect with a code". `POST /interaction/{uid}/code` (same origin, interaction cookie and CSRF required, JSON `{"csrf","code"}` up to 1 KiB) returns a custom token in the same-origin response only on success; the page signs in with the Firebase SDK and sends the ID token to the existing `/login` (consent and subscription as usual). Unknown, expired, used, and cancelled codes all return the same `400 code_rejected`; attempt limits return `429`; a create/sign failure returns `503 code_failed` (generate a new code in the console); other failures return `503`. With the feature off it is `404`. API/MCP Bearer credentials remain Firebase ID tokens, and the code does not limit how many texts you send.
