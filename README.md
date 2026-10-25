# SendTextToDots

English | [日本語](README_JP.md)

Send text from your own app or script to Dots in ChatGPT, one message at a time, exactly as written.

SendTextToDots is a self-hosted relay. Your authenticated app or script posts text to the API. The service delivers a signed event to the Dots subscription connected by the same user. Dots is the receiving assistant in ChatGPT; its response to the text depends on the instructions you give it there.

> **Status: experimental.** This project uses webhook delivery from the [draft MCP Events proposal](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md). Changes to the proposal or the receiving service may require updates or break compatibility. This is not an official OpenAI, Apple, or Google product or an endorsed integration.

This is source you deploy yourself, not a hosted service. Detailed documentation in `docs/` is currently in Japanese.

## How it works

```mermaid
sequenceDiagram
  participant C as Your app or script
  participant A as Send API (Cloud Functions)
  participant M as MCP/OAuth (Cloud Run)
  participant D as Dots / ChatGPT
  D->>M: OAuth connection and text.submitted subscription
  C->>A: POST /v2/commands with Firebase ID token
  A->>D: Signed event to the registered callback
  D-->>A: 2xx callback acceptance
  A-->>C: Command status (not Dots processing completion)
```

The owner is the user identified by the verified Firebase token. A subscription registers that user's receiving callback and signing secret after OAuth authorization. SendTextToDots delivers text without interpreting it. Direction controls, preset mappings, and text generation belong to the source app; instruction execution belongs to Dots. There is no MCP send tool, message queue, or automatic retry.

## Components

| Component | Runtime | Role |
| --- | --- | --- |
| Send API | Cloud Functions 2nd gen (`sendtexttodotsapi`) | Authenticated text submission, one signed delivery attempt, status lookup, and cancellation |
| MCP/OAuth and web UI | Cloud Run (`dist/deployment/connect.js`) | OAuth authorization, Events subscriptions at `/mcp`, Apple login at `/connect`, and development send UI at `/console` |
| Storage | Firestore | User connections, OAuth authorizations, subscriptions sealed with KMS, and command status without message text |
| Keys | Cloud KMS and Secret Manager | Sealing keys and separate signing, cookie, identifier, and digest secrets |

See [API](docs/API.md), [configuration](docs/CONFIGURATION.md), and [security design](docs/SECURITY.md) (Japanese) for details.

## Prerequisites

- Node.js 22.23.4 and npm 10.9.9 are the tested local versions. Use a current compatible 22.x patch; early 22.x releases lack APIs this project uses. See [INSTALL](docs/INSTALL.md) for version limits.
- Your own Google Cloud project with billing enabled and Firebase in the same project, plus Firestore, Cloud KMS, Secret Manager, Cloud Functions, Cloud Build, and Cloud Run resources described in [INSTALL](docs/INSTALL.md).
- Firebase Authentication with the Apple provider, configured through Sign in with Apple and the Apple Developer Program; add the MCP origin's host to authorized domains.
- Access to a receiving Dots/ChatGPT client that supports the required Events subscription. The allowed OAuth client is fixed to the ChatGPT CIMD in `src/oauth/cimd.ts`; arbitrary clients are not supported without source changes.

External service eligibility, agreements, permissions, and costs are your responsibility. This repository does not set an overall spending cap or guarantee operation within a free tier.

## Quick start

1. Install locked dependencies: `npm ci --ignore-scripts --no-audit --no-fund`. `--ignore-scripts` skips package lifecycle scripts during installation; it does not establish that dependencies are safe.
2. Run `npm test`: one build followed by tests using synthetic configuration, synthetic SDKs, and loopback only. Tests do not access real Cloud resources, credentials, or external networks.
3. Follow the ordered [installation guide](docs/INSTALL.md) to choose service URLs, prepare Cloud resources, assign runtime permissions (including `firebaseauth.users.get`), register secrets, and create the KMS subscription marker. Edit the single deployment configuration, `src/config/deployment.ts`, using [CONFIGURATION](docs/CONFIGURATION.md).
4. Run `npm run build`, then `npm run package` to create API ZIP and MCP Cloud Build source archives offline. Packaging does not deploy anything. Repeating unchanged packaging stops with `output_exists`; see [INSTALL](docs/INSTALL.md) for verifying existing archives.
5. Deploy the API to Cloud Functions 2nd gen and the MCP/OAuth service to Cloud Run using the archive deployment examples and origin/IAM checks in [INSTALL](docs/INSTALL.md). These include Functions entry settings and the MCP Dockerfile → Cloud Build → Cloud Run sequence. No provisioning, deployment, or shutdown tool is bundled; the procedure still requires your Cloud permissions and has not been verified end-to-end in a third-party project.
6. Open `/connect` on your deployed MCP origin and sign in with Apple. Connect the MCP server from Dots/ChatGPT through OAuth and subscribe to `text.submitted`.
7. Open `/console` on the MCP origin and send one text from its empty input. Confirm the text on the receiving side. Alternatively, use the API example below after establishing a subscription.

The distributed configuration is unset (`configured: false`). If built and deployed unchanged, both services stop with a fixed configuration error before SDK creation, credential acquisition, database access, or external HTTP.

## API at a glance

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

The ID is printed before sending so it remains available if the request or response parsing fails. Do not resend automatically after an uncertain result. Query `GET /v2/commands/{commandId}` with the same authentication instead. See [API](docs/API.md) for errors, cancellation, rate limits, and idempotency rules.

## Compatibility

Version 0.3.0 is for new installations only; there is no automatic migration. The API and Events contract is incompatible with 0.2.0, and versions before 0.2.0 also use different storage, OAuth scopes, and sealing formats. See [compatibility details](docs/INSTALL.md#030の互換性) (Japanese) before deployment.

## Limitations and disclaimer

- The author verified two real Dots deliveries on 2026-10-25 (direct API and `/console`, including Japanese and line breaks), and one simple calculation instruction after restarting the same development environment. These are limited observations, not a guarantee of arbitrary instruction execution. The author also reported successful real Dots delivery after obtaining the GitHub source on a Mac and configuring an author-managed server. The tested commit, Mac environment, changes beyond deployment configuration, and exact build/test results have not yet been recorded. Third-party Cloud environments and Linux remain unverified. See [LIMITATIONS](docs/LIMITATIONS.md).
- Production reliability, load, cost, multiple entry points sharing one UID, and immediate processing of each message are not guaranteed. The receiver may batch messages. Draft Events changes may affect compatibility.
- Authentication supports only Firebase's Apple provider. There is no authentication bypass or arbitrary endpoint, credential, emulator, or HTTP configuration override.
- Message text is not persisted by this service. Expired stored metadata is made unusable, but physical deletion and full account deletion are not implemented. Receiver retention and processing follow that service's terms. Physical erasure from RAM, SDKs, and the OS is not guaranteed.
- MIT licenses this source; it does not sublicense external services or SDKs. See [SECURITY](docs/SECURITY.md) and [LIMITATIONS](docs/LIMITATIONS.md) (Japanese).

## Security

Read the [security design and reporting status](docs/SECURITY.md). A private vulnerability reporting channel will be specified before public release; no active channel is claimed here. Do not put tokens, secrets, or real user data in public issues.

## Directory layout

| Path | Contents |
| --- | --- |
| `src/config/deployment.ts` | The single deployment configuration file for installers to edit |
| `src/config/validate.ts` | Configuration validation; rejects unset or inconsistent values before side effects |
| `src/deployment/` | Functions entry, Cloud Run entry, and CORS |
| `src/google-runtime/` | Owned Google SDK initialization, Cloud runtime gate, and rejection of unsafe environment variables |
| `src/delivery/`, `src/commands/` | Send API validation, single delivery attempt, cancellation, and status |
| `src/connect/`, `src/oauth/`, `src/mcp/`, `src/events/` | Connection web UI, OAuth, MCP Events, subscriptions, and signatures |
| `src/storage/`, `src/protection/`, `src/keys/` | Firestore storage formats, KMS sealing, and secret reads |
| `src/egress/` | Safe outbound HTTPS with IP validation, pinned connections, TLS, deadlines, and limits |
| `scripts/` | Offline packaging (`package-artifacts.mjs`) and test runner |
| `test/` | Automated tests using synthetic values only |
| `references/` | IANA tables used for destination IP classification (CC0 1.0) |
| `firestore/` | Deny-all Firestore rules and index exemptions |

## License

[MIT](LICENSE) © 2026 Katsuyasan88. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (Japanese) for third-party packages, SDKs, and reference data.
