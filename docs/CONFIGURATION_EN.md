# Deployment configuration

English | [日本語](CONFIGURATION.md)

The single source of configuration is the file `src/config/deployment.ts`. Edit it before deployment and build. There is no way to choose or override configuration at run time through HTTP, environment variables or arguments (except the MCP listen port and the environment variable that holds the Firebase Web API key value).

The English table below covers the deployment values independently of the source comments. This is a self-hosted relay for a generic app or script; sender sign-in/session handling is separate from these server settings ([API](API_EN.md#firebase-sessions)). Only Apple-backed Firebase user authentication is currently accepted. Do not put sender tokens or real user identifiers into this configuration.

## Validation

`src/config/validate.ts` checks all of the following and stops startup with a fixed error (`deployment_config_unconfigured` / `deployment_config_invalid`) if any one fails. Values, paths and the original exception are not included in the error.

- `configured` is the boolean `true`. This alone does not skip the other checks (the distributed placeholders fail the format checks).
- Only the keys in the table (unknown keys, getters and Proxies are rejected). There are no keys that add endpoints, credentials, emulators and so on.
- The format of each value and the mutual consistency in the table below.

The Functions entry validates at import (discovery) time; the MCP entry and each startup path validate before environment capture, signal registration, SDK creation, Secret retrieval, DB access, listen and external HTTP.

## Items

| key | Format and conditions |
| --- | --- |
| `configured` | `true` |
| `accessPolicy` | `explicit-allow-v1` only (only users the operator has explicitly registered can use the service; missing or any other value is a configuration error; there is no allow-everyone mode) |
| `projectId` | Google Cloud project ID (6 to 30 characters starting with a lower-case letter) |
| `projectNumber` | The numeric project number of the same project |
| `databaseId` | `(default)` or a named Firestore database ID |
| `location` | A single region (for example `us-central1`). Used for the Functions region and the KMS key ring location. `global` and multi-region are not allowed |
| `api.functionName`, `api.serviceName` | Both `sendtexttodotsapi` (the Functions export name is a static ESM name, so it is fixed. To change it, also change the export name in `src/deployment/functions.ts` and `API_FUNCTION_EXPORT` in `src/config/validate.ts`) |
| `api.serviceAccount` | `<name>@<projectId>.iam.gserviceaccount.com`. Dedicated to the API |
| `api.invoker`, `connect.invoker` | `private` only. External reachability is granted separately through IAM (application-level identity verification, OAuth and signatures are always required) |
| `api.publicOrigin` | The public origin of the API, `https://<host>` (no path, port or trailing slash. IP addresses, localhost and reserved TLDs are not allowed) |
| `connect.serviceName` | The Cloud Run service name (separate from the API) |
| `connect.serviceAccount` | The MCP-only SA (separate from the API) |
| `connect.publicOrigin` | The public origin of the MCP service (OAuth issuer, separate from the API) |
| `connectNamespace` | `t256_<lower-case UUID>` (version 1 to 8, RFC variant). Generate once at installation and never change it |
| `deliveryNamespace` | `t270_<lower-case UUID>` |
| `kms.environment` | `development` (a value of the storage format, compatible with the existing format) |
| `kms.projectId`, `kms.databaseId` | The same values as the top level |
| `kms.namespace` | `t268_<lower-case UUID>` |
| `kms.cryptoKey` | `projects/<projectId>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>` (the location is the same as `location` above) |
| `kms.writeVersion`, `kms.readVersions` | Positive integers. readVersions has 1 to 8 entries without duplicates and includes writeVersion |
| `secretVersions.jwks`, `cookieKeys`, `identifierKey`, `commandDigestKey` | `projects/<projectNumber>/secrets/<id>/versions/<number>`. A separate secret per purpose. `latest` and aliases are not allowed |
| `web.projectId` | The same as `projectId` |
| `web.authDomain` | The authDomain of the Firebase Web configuration (a DNS host) |
| `web.apiKeyEnv` | The name of the environment variable from which the MCP process reads the Firebase Web API key value (upper-case letters, digits and `_`). Existing namespaces such as `GOOGLE_`, `FIREBASE_`, `NODE_`, `K_` and `PORT` are not allowed |
| `payloadEncryption` (optional) | Omitted or `'off'` (default). For the enabled form, see [Key storage for payload encryption](#payload-encryption) below |

A UUID can be generated with, for example, `node -e "console.log(crypto.randomUUID())"` (randomUUID in Node 22 is version 4).

<a id="access-admin"></a>

## Explicit user registration (admin CLI)

Even for a single self-hosting user, the operator registers each person who may use the service. A first sign-in, a successful Apple sign-in, or an existing owner/Grant/subscription alone does not grant use. The permission lives in the existing database at `sttdConnect/{connectNamespace}/access/{identityHash}` (no plaintext UID) with an active/disabled state and a generation. A stop (disabled) or a re-registration changes the generation; Grants and subscriptions consented before that can no longer be used for new sends, subscriptions or token exchanges, and the person must consent through OAuth again and subscribe again. Looking up and cancelling commands, unsubscribing and disconnecting keep working while stopped.

Run registration and stops explicitly from the operator's computer or Cloud Shell against the same built deployment configuration (after `npm run build`). Confirm the person's Firebase UID in the regular Firebase user management (for example Authentication in the Firebase console) and pass exactly one UID on one line of standard input (never as an argument, in history or in a file). The UID is used exactly as given, 1 to 128 Unicode characters, with no trimming, replacement or normalization. Invalid UTF-8, line breaks or control characters, line/paragraph separators (U+2028/U+2029), a BOM, lone surrogates, extra lines or an overlong value give `invalid_input`.

```bash
node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
node scripts/manage-access.mjs grant  --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <version from status (absent the first time)>
node scripts/manage-access.mjs revoke --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <version from status>
```

- `--project`, `--database` and `--namespace` must exactly match the deployment configuration (a mismatch or an unconfigured build stops before any SDK is created). Credentials are the operator's Application Default Credentials only; there is no way to pass a credential file, endpoint, emulator or proxy (such environment variables stop the command). The only permissions needed are read/write on the target database and reading the fixed `identifierKey` version.
- One run takes at most 30 seconds overall. Reading standard input and the work (preparing the SDK, the key and the transaction) wait until 25 seconds after the start, and closing the SDK waits only for the remaining 5 seconds; then the process exits. These are limits on how long the command waits; they do not guarantee that SDK work already started is physically cancelled or that values in memory are physically erased. After the deadline no new transaction or write is started (whether a write started before the deadline was committed can be unknown as `timed_out`, so check with `status`).
- The output is one line of JSON with a fixed code and state/version only (`status`, `changed`, `unchanged`, `conflict` and so on); no UID, key or hash is printed. `grant`/`revoke` write the single record only when the version from status still matches; otherwise they print `conflict` and write nothing. If the SDK could not be closed, or did not finish closing within the limit, a `cleanup` field (`failed` or `unconfirmed`) is added without changing the database result in `code` (for example `changed`). If the result is unknown (`timed_out`, `unavailable`), do not repeat the operation; check with `status` first.
- When updating an existing deployment, the permission takes effect only after switching to the new version. Old Grants cannot be used after the update, so each permitted person consents through OAuth and subscribes again.

## Local send screen configuration

The local send screen ([LOCAL_CONSOLE_EN.md](LOCAL_CONSOLE_EN.md)) uses a separate small JSON file with public client values only (`apiOrigin`, `mcpOrigin`, `firebase.apiKey/authDomain/projectId`; see `console.config.example.json`). It does not read or change `src/config/deployment.ts`, and it contains no secrets. Keep your real file out of Git (`console.local.json` is ignored).

## Secret values

Secret values are not written in the configuration file.

| Purpose | Location |
| --- | --- |
| Sealing key for subscription data | Cloud KMS (SOFTWARE, ENCRYPT_DECRYPT) |
| AS signing JWKS, cookie keys, identifier HMAC key (32 bytes), command digest key (32 bytes) | Numbered versions of each Secret Manager secret (format in [INSTALL_EN.md](INSTALL_EN.md)) |
| Firebase Web API key | The MCP Cloud Run environment variable (named by `web.apiKeyEnv`) |

## Environment variables rejected at run time

Before SDK creation, startup is refused if an environment variable that could redirect credentials, destinations, TLS or logging exists (for example `GOOGLE_APPLICATION_CREDENTIALS`, `FIRESTORE_EMULATOR_HOST`, `HTTPS_PROXY`, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_EXTRA_CA_CERTS`); the values are not read. `NODE_OPTIONS` is allowed only for the API service as a single `--max-old-space-size=<128 to 960>` (with 0 to 8 surrounding spaces); the MCP service rejects its presence. The list is in `src/google-runtime/development.ts`.

## Time-limited diagnostic logging for the connection server (off by default)

Only the MCP service (connection server) reads the environment variable `STTD_CONNECT_DIAGNOSTICS_UNTIL`. Its value is an end time (RFC 3339 in UTC, for example `2026-01-01T00:20:00Z`) and it takes effect only when it is later than the start time and no more than 30 minutes ahead. A missing, malformed, past, or more-than-30-minutes value is ignored (nothing is written), and startup and authentication behave the same.

While enabled, only these fixed events are written to standard output as one-line JSON (just `event` and a fixed `category`): `interaction.login`, `interaction.consented`, `interaction.access_denied`, `interaction.denied`, `web.disconnected`, `interaction.receiver_reset` (a confirmed deletion of the receiver settings was committed), `interaction.receiver_reset_incomplete` (after that deletion the connection did not complete or its result is unknown, or the result of the confirmed consent itself is unknown; category is `incomplete`, `unknown`, `reset_unknown`, or `other`), `oauth.server_error` / `oauth.request_error` (category is the token request's `authorization_code`, `refresh_token`, or `other`), and `oauth.grant_revoked` (only after a stored revocation succeeds; category is `Grant`, `AccessToken`, `AuthorizationCode`, `RefreshToken`, or `other`), `events.subscribed` (a subscription registration succeeded), and `events.subscribe_failed` (a subscription registration failed; one event per registration; category is `invalid_request`, `unknown_event`, `cursor_unsupported`, `destination_change_pending`, `grant_inactive`, `conflict`, `callback_endpoint.` followed by `connection_refused`, `timeout`, `tls_error`, `http_4xx`, `http_5xx`, or `challenge_failed`, `context_unavailable` (deadline, abort, or shutdown), `request_rejected` (a request with `Mcp-Method: events/subscribe` was rejected before reaching registration, for example by parameter validation or authentication), or `other`). No UID, owner, Grant, code, token, cookie, body, URL, query, IP address, User-Agent, error text, stack, or hash is written. Nothing is written after the end time or after 64 events in one process. A write failure does not change authentication, revocation, subscriptions, or responses. Use it temporarily for investigation and remove the value afterwards.

## Initial origins and checks at deployment

Fix `api.publicOrigin` and `connect.publicOrigin` before the build. In the order of [INSTALL_EN.md](INSTALL_EN.md), either choose the deterministic Cloud Run URL from the service name, numeric project number and region, or choose your own domain with TLS/routing prepared first. The same origin is used for the MCP issuer, CORS, the Firebase authorized domain and the `/mcp` registration in Dots. After deployment, verify that the chosen URL is usable instead of rewriting it from an alias URL shown in the Console.

Only the metadata credentials of the runtime SA attached to the service are used. This is not a development server that starts with local ADC or a credentials file. PORT is set by Cloud Run; set the Web API key under the name `web.apiKeyEnv` before the first start. Without `firebaseauth.users.get` on the runtime, revocation and user-state lookups fail even for a correct token. See [INSTALL_EN.md](INSTALL_EN.md) for the permission table of the runtime, build and deploying principals.

`invoker: private` is the allowed value in the source. The Cloud-side public reachability that lets browsers and Dots reach the service is configured separately; changing invoker to public in the configuration file does not solve it. The application's Firebase ID token / OAuth authentication is always required.

Do not commit real configuration values or secrets to public Git; keep them in an environment the installer controls. Passing tests does not verify the correctness of real deployment values, IAM, secret registration or URL reachability.

<a id="payload-encryption"></a>
## Key storage for payload encryption (off by default, in development)

In the current version, enabling it adds [fetching your own public key](API_EN.md#encryption-key) (`GET /v2/encryption-key`), [reissuing the key](API_EN.md#encryption-key-reissue) (`POST /v2/encryption-key/reissue`) and [sending encrypted text](API_EN.md#encrypted-commands) (`POST /v2/encrypted-commands`) to the send API. The dedicated secret is read only by the send API (Functions) runtime, and only for requests that need to create or reissue a key, protect it again or decrypt encrypted text. Reissuing the key and updating the protection key (dedicated secret) version are separate operations. It is not read at startup, and the MCP service and operator screens never read it. If it cannot be read, only the fetch returns `503` and plaintext sending continues. When omitted or `'off'`, no new secret is needed, no secret is read, no key is created, and the fetch entry returns `404`.

The enabled form (all items required, no extra keys):

| Item | Content |
| --- | --- |
| `mode` | Only `jwe-rsa-oaep-256-a256gcm-v1` |
| `namespace` | `t280_<lower-case UUID>`. Stored under `sttdEncryption/<namespace>` in the same Firestore database |
| `secret` | `projects/<projectNumber>/secrets/<id>` (without a version). A dedicated secret, different from the four existing purposes in `secretVersions` |
| `writeSecretVersion` | The positive integer version used when protecting a key |
| `readSecretVersions` | Versions allowed for opening. 1 to 3 without duplicates, including `writeSecretVersion` |

The value of the dedicated secret is 32 random bytes encoded as unpadded base64url (43 characters). Never write the value in the configuration file. Versions are fixed numbers; `latest` and aliases are not used. To rotate the protection key, create a new version, list the old and new versions in `readSecretVersions`, and set `writeSecretVersion` to the new one. A key protected with the old version is protected again with the new version, keeping the same key, the next time that user uses it. While an unused key still depends on the old version, do not remove the old version from read or destroy it (if the old version cannot be read, that user's key is temporarily unavailable).

## Developer 6-digit code (off by default)

Enable it with `developerLogin` in the deployment configuration (`src/config/deployment.ts`). Omitted or `'off'` is disabled (the default); `'operator-code-v1'` is the only enabling value, and any other value is a configuration error before startup. While off there is no code entry endpoint (fixed 404), and neither the send API nor MCP accepts ID tokens from the custom provider. When on, the connect server (MCP) accepts code entry on the plugin connection screen, and the identity check shared by the connect server and the send API verifies code-based accounts.

The keys for the reservation HMAC and for sealing planned UIDs are derived with HKDF, per purpose, from the existing `secretVersions.identifierKey` (a 32-byte per-deployment secret). No new secret is added. Rotating the identifierKey would give the same number a different ID, so issuance is refused, regardless of time, while the key fingerprint differs. Rotate only after stopping issuance and confirming that all reservations were deleted, as an explicit administrator step.

The operator mode file (for example `operator.local.json`, never committed) accepts only this exact schema:

| key | meaning |
| --- | --- |
| version | `1` |
| projectId / databaseId | The same Firebase project and Firestore database as the deployment configuration |
| namespace | The same connect storage namespace as the deployment configuration (`t256_<UUID>`) |
| identifierKeySecretVersion | The same Secret Manager version name as `secretVersions.identifierKey` (`projects/<projectNumber>/secrets/<id>/versions/<n>`). Never put the value in files, the browser, or distributed artifacts |
| signingServiceAccount | The dedicated service account in the same project that signs custom tokens (`<name>@<projectId>.iam.gserviceaccount.com`, name 6–30 lowercase characters; for example `sttd-signer@sample-project.iam.gserviceaccount.com`). Other projects, the Compute default service account, URLs and key JSON are refused. Required; if missing or invalid the helper stops with a fixed error before reading credentials, SDKs or secrets |

The helper runs with Application Default Credentials and signs custom tokens only as the `signingServiceAccount`, passed to Firebase Admin as `serviceAccountId` (it never guesses the signer from ADC or the metadata server; user ADC has no service account email). The credentials running the helper need `iam.serviceAccounts.signBlob` on that service account (for example Service Account Token Creator). Do not distribute service account key JSON.

Initial values (small self-hosted deployments): code 10 minutes, reservation kept at least 24 hours from issue, 20 candidates, at most 5 DB transaction attempts, 15 seconds overall. Active codes: 5 per namespace and 1 per console; issuance 3 per hour per console and 20 per hour per namespace; entry 5 per interaction, 5 per source and 5 namespace-wide failures per 10 minutes. On deployments that enable it, the connect server's service account needs permission to create Firebase users and sign custom tokens (the send API only reads for verification). Limit the operator helper's credentials to signing, read/write of the related collections, and reading the identifierKey. If you use TTL, configure it on fields such as `developerLoginCodeReservations.deleteAfter` yourself (TTL is never used to decide authentication expiry).
