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

A UUID can be generated with, for example, `node -e "console.log(crypto.randomUUID())"` (randomUUID in Node 22 is version 4).

<a id="access-admin"></a>

## Explicit user registration (admin CLI)

Even for a single self-hosting user, the operator registers each person who may use the service. A first sign-in, a successful Apple sign-in, or an existing owner/Grant/subscription alone does not grant use. The permission lives in the existing database at `sttdConnect/{connectNamespace}/access/{identityHash}` (no plaintext UID) with an active/disabled state and a generation. A stop (disabled) or a re-registration changes the generation; Grants and subscriptions consented before that can no longer be used for new sends, subscriptions or token exchanges, and the person must consent through OAuth again and subscribe again. Looking up and cancelling commands, unsubscribing and disconnecting keep working while stopped.

Run registration and stops explicitly from the operator's computer or Cloud Shell against the same built deployment configuration (after `npm run build`). Confirm the person's Firebase UID in the regular Firebase user management (for example Authentication in the Firebase console) and pass exactly one UID on standard input (never as an argument, in history or in a file).

```bash
node scripts/manage-access.mjs status --project <projectId> --database <databaseId> --namespace <connectNamespace>
node scripts/manage-access.mjs grant  --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <version from status (absent the first time)>
node scripts/manage-access.mjs revoke --project <projectId> --database <databaseId> --namespace <connectNamespace> --expect <version from status>
```

- `--project`, `--database` and `--namespace` must exactly match the deployment configuration (a mismatch or an unconfigured build stops before any SDK is created). Credentials are the operator's Application Default Credentials only; there is no way to pass a credential file, endpoint, emulator or proxy (such environment variables stop the command). The only permissions needed are read/write on the target database and reading the fixed `identifierKey` version.
- The output is one line of JSON with a fixed code and state/version only (`status`, `changed`, `unchanged`, `conflict` and so on); no UID, key or hash is printed. `grant`/`revoke` write the single record only when the version from status still matches; otherwise they print `conflict` and write nothing. If the result is unknown (`timed_out`, `unavailable`), do not repeat the operation; check with `status` first.
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

## Initial origins and checks at deployment

Fix `api.publicOrigin` and `connect.publicOrigin` before the build. In the order of [INSTALL_EN.md](INSTALL_EN.md), either choose the deterministic Cloud Run URL from the service name, numeric project number and region, or choose your own domain with TLS/routing prepared first. The same origin is used for the MCP issuer, CORS, the Firebase authorized domain and the `/mcp` registration in Dots. After deployment, verify that the chosen URL is usable instead of rewriting it from an alias URL shown in the Console.

Only the metadata credentials of the runtime SA attached to the service are used. This is not a development server that starts with local ADC or a credentials file. PORT is set by Cloud Run; set the Web API key under the name `web.apiKeyEnv` before the first start. Without `firebaseauth.users.get` on the runtime, revocation and user-state lookups fail even for a correct token. See [INSTALL_EN.md](INSTALL_EN.md) for the permission table of the runtime, build and deploying principals.

`invoker: private` is the allowed value in the source. The Cloud-side public reachability that lets browsers and Dots reach the service is configured separately; changing invoker to public in the configuration file does not solve it. The application's Firebase ID token / OAuth authentication is always required.

Do not commit real configuration values or secrets to public Git; keep them in an environment the installer controls. Passing tests does not verify the correctness of real deployment values, IAM, secret registration or URL reachability.
