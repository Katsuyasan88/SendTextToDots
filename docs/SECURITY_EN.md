# Security and data handling

English | [日本語](SECURITY.md)

This is not a public privacy policy. Installers must check storage locations, logs, processors and disclosures for their own deployment.

## Data handling

- The text (`text`) and event bytes are handled only in RAM while the send API processes the request; they are not stored in or written to the DB, queues, logs or responses. Only the command state without the text and a keyed digest are written to the DB. Buffers created by the service are zero-filled after processing, but physical erasure from RAM, SDKs and the OS is not guaranteed.
- Identity verification uses Firebase Authentication (Apple provider) only, and the verified UID is bound to an internal owner. Names, e-mail addresses, Apple raw IDs and tokens are not stored by this service (Firebase/Apple keep their own account information separately).
- The text is delivered to the subscription destination (for example ChatGPT); retention and processing after that follow the terms of the receiving service.

| Data | Location | Retention design |
| --- | --- | --- |
| owner (UID mapping, revocation version, last use) | Firestore `sttdConnect` | Expires after 90 days without activity |
| OAuth records (Grant, tokens and so on; payload sealed with KMS) | Firestore `sttdConnect` | Each lifetime. Grant/refresh expire after 90 days without activity and immediately on revocation |
| Connection interaction | Firestore `sttdConnect` | 5 minutes, single use |
| Callback URL and subscription secret (sealed with KMS) | Firestore `sttdAuth` | While the subscription is valid. The previous secret during rotation for 5 minutes |
| Command state (ID, keyed digest, subscription reference, state, times; no text) | Firestore `sttdDelivery` | Unusable after 24 hours |
| Text | RAM while the request is processed | Until the request ends or expires |

Physical deletion of expired data is not included ([LIMITATIONS_EN.md](LIMITATIONS_EN.md)).

The storage roots, the KMS sealing format (capsule prefix, format and AAD domain) and the OAuth scope keep the values introduced in 0.2.0, and there is no path that reinterprets or accepts data or tokens from versions before 0.2.0. Unsealing succeeds only when format, domain and storage position match, and the checks of ownership, lifetime, signature, single delivery and authorization do not change. 0.3.0 is incompatible with 0.2.0 in the send API and Events contract (v2, `schemaVersion` 2, `text.submitted`; old v1, old fields and old event names are rejected), and even though the storage identifiers are the same, no migration that carries 0.2.0 data over is provided or verified, so deploy it as a new installation ([INSTALL_EN.md](INSTALL_EN.md#compatibility-of-030)).

## Authorization and secrets

- The API, subscriptions, lookups and cancellations enforce the owner derived from the token and do not trust an ownerId in the input. Firebase ID tokens, MCP OAuth tokens and webhook secrets are not interchangeable.
- Long-term protection uses direct encryption with Cloud KMS, binding the purpose, recordId, owner and so on into the AAD and rebuilding the expected AAD for every unsealing.
- The four fixed secrets (signing JWKS, cookie keys, identifier HMAC key, digest key) are read once at startup from numbered Secret Manager versions and are not reused across purposes.
- Key, secret and token values are never written to logs, responses or exceptions. Startup failure records contain only a fixed stage/code and an integer mask without values.
- Only users the operator has explicitly registered can use the service (`accessPolicy: explicit-allow-v1`, [CONFIGURATION_EN.md](CONFIGURATION_EN.md#access-admin)). The permission is bound to the existing HMAC of the Firebase project and the verified UID; no plaintext UID is stored. OAuth login, consent, code exchange and refresh, subscriptions (before the challenge and at the final save) and sends (acceptance and the send right) check the latest permission and generation in the same database; an unreadable or invalid permission refuses use as a temporary failure (it is never treated as allowed). Lookups, cancellation, unsubscribing and disconnecting do not depend on it. Registration and stops are done only by the explicitly run admin CLI; the regular API/MCP/screens have no admin route. Firestore client rules stay deny-all, and server SDKs are not told apart from the admin by rules.
- The deployment configuration is fixed to one module; if it is unset or inconsistent the service refuses before SDK creation, credentials, DB and external HTTP. The service does not start when an environment variable that could change credentials, destinations, TLS, proxies or emulators exists ([CONFIGURATION_EN.md](CONFIGURATION_EN.md)).
- The send screen runs on the user's computer ([LOCAL_CONSOLE_EN.md](LOCAL_CONSOLE_EN.md)). Its helper listens on 127.0.0.1 only, checks Host/Origin and a per-start nonce, relays only five fixed routes to the fixed API/MCP origins with the user's Bearer token, forwards no cookies or nonce upstream, and keeps no token or text. The Cloud Run service serves no send screen; its CORS and permissions are unchanged, and Firebase is loaded by the page only on an explicit sign-in.
- The display language cookie `sttd_language` (`en` or `ja`) is a display-only session cookie set when the user chooses a language on a page; it is never used for authentication, authorization or ownership decisions, and it does not carry tokens or personal data.

<a id="mcp-oauth"></a>

## MCP/OAuth authentication

- A fixed profile of `oidc-provider` 9.12.2 (https issuer, resource `<issuer>/mcp`, scope `sttd:events` only). PKCE S256, redirect, resource and scope must match, and authorization codes are single use.
- Every new authorization requires explicit consent from the user (verified by Firebase ID token) on the connection web. Consent is bound once to the same owner and the original interaction/CSRF.
- The client is the single CIMD-allowed client (exact match of client_id, redirect and JWKS URL, `private_key_jwt`). Client assertions reserve the pair of client_id and jti once.
- Access tokens are opaque Bearer tokens valid for 15 minutes. Refresh rotates once and reuse detection revokes the same Grant. Subscriptions are bound to the Grant, and nothing is delivered after the Grant is revoked.

<a id="safe-https-egress"></a>

## Safe HTTPS egress

Callback verification, delivery and CIMD retrieval share the same egress component.

- HTTPS on 443 only. userinfo, fragments, whitespace, control characters and backslashes are rejected.
- All DNS answer IPs are verified; localhost, private, link-local, reserved, metadata and IANA special-purpose ranges (rejected conservatively even when Globally Reachable; the basis is in `references/`), mapped, translated, zoned and non-canonical forms are rejected. Connections are pinned to the verified IP and TLS is checked against the hostname.
- Deadlines are at most 10 seconds and response bodies at most 8192 bytes. Redirects are not followed, compressed responses are rejected, and the caller's headers and secrets are not forwarded.
- Failures return fixed categories only, without URLs, IPs or original exceptions.

## Main threats and responses

| Threat | Response |
| --- | --- |
| Misdelivery to another user | Fix token → owner → the single subscription, and re-check the latest state in the dispatch-right transaction |
| Double delivery | One valid subscription per owner, replacement approved by the user. Single dispatch per owner + commandId, no automatic resend |
| Stale instructions | 60-second lifetime, lifetime check before dispatch, no queue or history replay |
| SSRF / DNS rebinding | The safe egress above |
| Secret leakage | KMS sealing, Secret Manager, no logging |
| Prompt injection | The text is carried as user data and the server mixes no instructions into it |
| Mass sending and cost | Per-owner rate limit, text limit, Functions max instances/concurrency. Overall cost caps and shutdown are the installer's operation |

## Reporting vulnerabilities

See the English [security policy and reporting channel status](../SECURITY.md). Report vulnerabilities through the GitHub private reporting channel described there. Do not put vulnerability details, secrets, real data or tokens in public issues. If the reporting button is unavailable, ask only for a private security contact without disclosing the issue.

## Developer 6-digit code

- Codes are cryptographically random 000000–999999 and authenticate once, within 10 minutes of issue. After use or cancellation the same number is not issued for at least 24 hours from issue (longer while deletion is delayed). Plain codes are never stored in the database or logs; reservations are identified by an HMAC under a key derived, per purpose, from the deployment secret (identifierKey).
- Six digits are weak against guessing, so attempts are reserved and counted before comparison (per interaction, per source, and namespace-wide); the namespace limit cannot be bypassed by changing IP or interaction. The limit can also let a third party temporarily block use.
- Each code creates a new internal account (dedicated UID) and is never linked to an Apple account automatically. Access is granted only to the one UID planned by the operator for that issuance.
- API and MCP share one identity check that never accepts a token merely because the provider is custom: it checks the marker, the dedicated UID, the stored identity state/family, and the access generation. Reissue or cancel revokes only that family and never affects Apple or other consoles.
- The 6 digits alone never yield console credentials or the right to reissue (the 32-byte claim secret held in the issuing helper's memory is required).
- A Firebase create/sign failure, lost response, or deadline never returns a code to unused. A connection that commits late, after the deadline, is revoked.
