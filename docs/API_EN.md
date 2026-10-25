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

Errors are `{"error":{"code":"…","retryable":<boolean>}}`. Main codes: invalid_request(400), authentication_required(401), connection_revoked(403), not_found(404), method_not_allowed(405), subscription_required / destination_change_pending / idempotency_conflict(409), command_expired / clock_skew(422), rate_limited(429, Retry-After), temporarily_unavailable(503). Even when retryable is true, do not resend the text automatically; look up the state of the same ID instead.

Deadlines: the processing budget is the shorter of 20 seconds from receipt and the original lifetime, external HTTP takes at most 10 seconds, and the Functions timeout is 30 seconds.

The send screen `/console` (served on the MCP origin) sends the text the user typed into its empty input directly to the API in the same five-field form (there is no direction or preset selection). It also shows the connection state and disconnects through the existing `/v1/web/disconnect` after an explicit confirmation. The API CORS allows only the three routes above from the configured MCP origin (allowed headers: authorization, content-type, idempotency-key; `Retry-After` exposed; no wildcard or credential cookies). Old v1 routes with an Origin and other origins get a fixed 403; requests without an Origin proceed to normal processing without CORS headers (v1 is 404).

## 3. Send screen and connection state

The send screen is the only web entry. There is no separate connection page; `/connect` and `/connect/app.js` are not served (404 like any unknown path).

| Endpoint | Content |
| --- | --- |
| `GET /console` | Send screen (Apple sign-in, state, disconnect, one send, cancel, same-ID lookup). Served only when the deployment configuration provides the API origin |
| `GET /v1/web/connection` | Bearer Firebase ID token. `{state}` |
| `POST /v1/web/disconnect` | Revokes the same owner's Grant and subscription. `{state}` |
| `/interaction/{uid}`, `…/login`, `…/consent`, `…/deny`, `/interaction/app.js` | OAuth authorization interaction (same origin, CSRF, explicit consent every time) and its fixed script |
| `/mcp` | MCP (Bearer access token, scope `sttd:events`) |
| `/.well-known/*`, `/oauth/*` | OAuth metadata, token and other endpoints (`oidc-provider`) |

The `/v1/web/*` routes, the OAuth routes and the scope are separate from the send API version and do not change in 0.3.0.

Display language: the HTML pages (`/console`, the OAuth interaction and the user-facing OAuth error page) are rendered in English or Japanese. An explicit choice through `?lang=en` or `?lang=ja` is stored in the display-only session cookie `sttd_language` (Path=/, SameSite=Lax, Secure, no expiry); the send screen writes the same cookie in the browser when you switch its language, so the last choice is kept; without it the `Accept-Language` preference decides (Japanese when preferred, otherwise English). The cookie is never used for authentication or authorization, and machine codes, fields, scopes, routes and the text being sent are never translated.

State priority: no valid Grant → unlinked, a destination replacement awaiting approval → change_pending, a valid subscription → subscribed, the most recent subscription expired → expired, otherwise (no subscription or subscription cancelled) → linked.

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
