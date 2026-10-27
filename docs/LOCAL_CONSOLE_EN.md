# Local send screen (5-step setup)

English | [日本語](LOCAL_CONSOLE.md)

The send screen is not served by Cloud Run. A small helper running on your own computer serves it at `http://localhost:8765/console`. Opening the page, reloading it, switching the language, and showing or copying the fixed instructions never contact Cloud Run, the send API or Firebase. Requests leave the page only when you press a button, and the Firebase authentication library is loaded only when you press "Sign in with Apple" in step 1.

## What you need

- Node.js 22 (`>=22.2.0 <23`; measured with 22.23.4; the same version conditions as in [INSTALL](INSTALL_EN.md)) and the built source of this repository (`npm ci --ignore-scripts --no-audit --no-fund` and `npm run build`). No new dependency.
- The https origins of your deployed API and MCP services and the public Firebase Web configuration (`apiKey`, `authDomain`, `projectId`). These values reach the browser and are not secrets, but the configuration file is not committed (`console.local.json` and `*.local.json` are ignored by Git).
- `localhost` in the authorized domains of Firebase Authentication (required for the Apple sign-in popup).

## Configuration file and start

Copy `console.config.example.json` to `console.local.json` and replace the values with yours. Only these three keys exist; unknown keys, http origins, IP addresses and origins with a path are refused at start.

```json
{
  "apiOrigin": "https://sendtexttodotsapi-<PROJECT_NUMBER>.<REGION>.run.app",
  "mcpOrigin": "https://<MCP_SERVICE>-<PROJECT_NUMBER>.<REGION>.run.app",
  "firebase": { "apiKey": "...", "authDomain": "<project>.firebaseapp.com", "projectId": "<project>" }
}
```

```sh
npm run build
npm run console -- --config console.local.json          # default http://localhost:8765/console
npm run console -- --config console.local.json --port 9000
```

The helper listens on `127.0.0.1` only and accepts requests whose `Host` is exactly `localhost:<port>`. LAN exposure, `0.0.0.0` and opening the file directly (`file://`) are not supported. Stop it with Ctrl+C.

## What the screen does (5 steps)

All five steps are always shown in order; at first only step 1 is active and steps 2 to 5 are gray. Completed steps are shown faded, and clicking anywhere in such a step (or pressing Enter/Space on it) re-activates it for review (reviewing does not erase anything). Buttons and fields inside inactive steps cannot be used. After all five steps the completion text appears at the bottom of the page and stays there even when you return to step 4 to keep sending. This page and the helper keep progress, the typed text and the ID token in memory only and add no storage of their own (cookie, localStorage or file); a reload resets them. The only thing the page itself keeps is the display cookie `sttd_language` (your language choice). Separately, the Firebase SDK itself stores the authentication session in the browser in its default way so that the sign-in can be restored; that storage is Firebase's behaviour and is not changed by this page. If another tab signs out or switches to another account, steps 2 to 5 are reset and you are asked to sign in again.

1. **Sign in** — "Sign in with Apple" loads the authentication library and signs in with the same Apple account as your source app. The popup opens only when you press the button (press again if it was blocked). Signing in again with another account resets steps 2 to 5.
2. **Check the connection** — Press "Check the connection" once to check the connection and subscription (nothing is polled). "Receiving" unlocks step 3. For not connected, waiting to start receiving, expired, or a pending destination change, the screen tells you in English or Japanese what to do next in ChatGPT. While checking, steps 3 to 5 are locked; if receiving continues the progress is kept, otherwise steps 3 to 5 are reset. "Disconnect" is also here. It also shows the access permission (the operator's explicit registration) and tells apart three cases: not permitted, could not be checked, and an old service version that needs an update. In all of them no new send is possible from step 3 on, but you can still disconnect, and check or cancel an earlier send. Step 2 also has a short "Add and connect the plugin" note with expandable steps that you can read whether or not you are connected (an existing connection does not need to be added again). As the registration target it shows this deployment's server URL, the helper's `mcpOrigin` followed by `/mcp` (without that setting it shows guidance only and never guesses a URL). Do not register this local page (localhost) or the API origin. The steps: in ChatGPT open Plugins, press "+", choose "Add custom MCP server", enter a name you will recognize and the server URL, and choose an HTTPS connection with OAuth authentication; check the destination, authentication and any warning, create and install it, and allow the connection with the same Apple account as in step 1; in the conversation of the Dots that should receive, select the added plugin and ask it to "start receiving on this Dots"; then come back and press "Check the connection". Menu names and availability depend on your ChatGPT account or workspace and may change, so also see the official links on the page ([Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt), [Add custom MCP server](https://developers.openai.com/api/docs/guides/custom-mcp-server)). Opening the guide, following a link or switching the language sends nothing from this page.
3. **Test instructions for Dots** — Show or copy the test text from the [Dots guide](DOTS_GUIDE_EN.md), paste it into the receiving Dots, then press "I pasted it into Dots. Next". If the browser cannot copy, confirm a manual copy before continuing. Copying sends nothing to Dots.
4. **Send** — The text field is empty with a non-sensitive example as placeholder. Type a short message and press "Send" (one POST; a double click does not create a second one), confirm yourself in Dots that the received text matches, then press "I confirmed in Dots that the text matches. Next". "Accepted" is the callback's 2xx, not proof of a match. Nothing sent, failed, cancelled or expired cannot be confirmed; an unknown result can be confirmed after you actually checked the match in Dots (the screen never rewrites unknown to success).
5. **Operational instructions for Dots** — Show or copy the operational text, paste it into the same Dots, and press "I pasted it into Dots. Finish". The screen then shows the 5-step completion text. This is progress by your own confirmations, not a server-side verification that Dots applied the instructions.

After completion, re-select step 4 to send ordinary messages (no re-copy of steps 3/5 is required). Signing in again, losing the receiving state, or re-applying the test instructions resets the steps that depend on it.

## Sign-in session and token refresh

Each authenticated button action obtains a current Firebase ID token through `user.getIdToken()` before the helper relays it. The SDK can refresh the short-lived token using its existing sign-in session, so the one-hour token lifetime does not mean you must manually sign in every hour. Signing out or a revoked/invalid session can require signing in again. This page's in-memory setup progress remains separate from Firebase's browser session. It adds no background polling or sending. See [session and automated-sender details](API_EN.md#firebase-sessions).

## What the helper relays

The helper relays only the requests behind the buttons, to the fixed origins in the configuration. The browser never talks to the production origins directly, and the CORS and permissions of the Cloud Run side are unchanged.

| Request from the page | Upstream |
| --- | --- |
| `GET /v1/web/connection`, `POST /v1/web/disconnect` | `mcpOrigin` |
| `POST /v2/commands`, `GET /v2/commands/{id}`, `POST /v2/commands/{id}/cancel` | `apiOrigin` |

Every request must carry `Authorization: Bearer <Firebase ID token>` and a random value created at start (local nonce). A mismatched Host or Origin, a missing or duplicated nonce, a path or method outside the list, and an oversized body (32 KiB for the whole send JSON; the 4096-byte text limit stays with the API) are refused before any upstream call. Upstream responses are read up to 64 KiB and cut off with a fixed error beyond that. Only `Authorization` (plus `Content-Type` and `Idempotency-Key` when sending) is forwarded; Cookie, Origin, Forwarded headers and the nonce are not. Responses return only the status, body, `Content-Type` and `Retry-After`; `Set-Cookie` is not forwarded. Tokens, text and secrets are neither stored nor logged. Arbitrary URLs cannot be relayed and redirects are not followed.

When the helper itself refuses a request before calling upstream (a nonce mismatch from an old page, a path/method outside the list, an oversized body and so on), its response carries the fixed header `X-Sttd-Local-Refusal: 1`; only then does the page say that nothing was sent and suggest reloading (the match confirmation stays locked). The helper never forwards an upstream header of the same name, so an upstream error cannot be made to look unsent. Failures after the upstream call (such as 502) stay "unknown" as before. If a send whose result is not settled is dropped from the page by signing in again, losing the sign-in, re-checking the state or re-applying the test instructions, the warning that it may arrive twice stays visible (nothing is checked, cancelled or resent automatically).

## Limits

- Behaviour in third-party environments and real browsers is unverified beyond the synthetic tests ([LIMITATIONS](LIMITATIONS_EN.md)).
- The helper is a development aid on your own computer; it adds no authentication or secret handling and does not change Cloud settings or start or stop services.

## Connecting with a developer 6-digit code (operator mode)

The regular `npm run console` keeps the Sign in with Apple delivery mode and has no code issuance endpoints (step 1 shows "Code issuance is not configured for this deployment."). On a deployment configured with `developerLogin: 'operator-code-v1'`, start operator mode explicitly, only on a machine that holds management access to your own deployment.

```
node dist/console/operator-server.js --config console.local.json --operator operator.local.json
```

`operator.local.json` requires `signingServiceAccount`, the service account that signs custom tokens ([configuration](CONFIGURATION_EN.md)). The helper runs with Application Default Credentials, which need `iam.serviceAccounts.signBlob` on that service account.

1. At the top of step 1, under "Choose how to connect", choose "Code" (choosing does not issue a code). Only the chosen method's controls are shown: "Apple" shows the Apple guidance and "Sign in with Apple" only, and "Code" shows the code controls only. "Generate a code" shows a 6-digit code and the time left.
2. Within 10 minutes, enter the code in the plugin connection screen after adding the plugin. A code works once. Then complete the normal consent and subscription.
3. Press "Check connection" in the console to sign the console in to the same account. There is no automatic polling.
4. "Generate a new code" ends the current code and its connection and creates a new one. If a new code cannot be secured, the current code and connection stay unchanged.

Switching between Apple and a code happens in step 1. Switching does not stop the previous connection. Remove the previous plugin and add it again from step 2. The previous connection will not carry over.

The operator claim secret lives only in the helper's memory. If the helper exits, issued codes can no longer be checked or reissued (an unused code expires in 10 minutes; issue a new one).
