# Local send screen (7-step setup)

English | [日本語](LOCAL_CONSOLE.md)

This screen sends plaintext only, through `POST /v2/commands`; it has no screen for sending encrypted text, fetching the public key or reissuing the key. Those are separate [APIs](API_EN.md#encryption-key): the client on your own device encrypts the text, and SendTextToDots decrypts it for delivery (this is not end-to-end encryption). Stopping the helper with Ctrl+C stops only this screen on your computer; the Cloud services remain available and the Dots subscription stays. Use "Disconnect" in step 2 and confirm to delete the authorization, subscription, and receiving settings. Stopping the Cloud services is your own operation.

The send screen is not served by Cloud Run. A small helper running on your own computer serves it at `http://localhost:8765/console`. Opening the page, reloading it, switching the language, and showing or copying the fixed instructions never contact Cloud Run, the send API or Firebase. Requests leave the page only when you press a button, and the Firebase authentication library is loaded only when you press "Sign in with Apple" or "Sign in with Google" in step 1.

## What you need

- Node.js 22 (`>=22.2.0 <23`; measured with 22.23.4; the same version conditions as in [INSTALL](INSTALL_EN.md)) and the built source of this repository (`npm ci --ignore-scripts --no-audit --no-fund` and `npm run build`). No new dependency.
- The https origins of your deployed API and MCP services and the public Firebase Web configuration (`apiKey`, `authDomain`, `projectId`). These values reach the browser and are not secrets, but the configuration file is not committed (`console.local.json` and `*.local.json` are ignored by Git).
- `localhost` in the authorized domains of Firebase Authentication (required for the Apple or Google sign-in popup).

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

## What the screen does (7 steps)

All seven steps are always shown in order; at first only step 1 is active and steps 2 to 7 are gray. Completed steps are shown faded, and clicking anywhere in such a step (or pressing Enter/Space on it) re-activates it for review (reviewing does not erase anything). Buttons and fields inside inactive steps cannot be used. After the setup (steps 1 to 6) the completion text appears at the bottom of the page and stays there while you keep sending in step 7 (the results in step 7 are not a condition of the setup). This page and the helper keep progress, the typed text and the ID token in memory only and add no storage of their own (cookie, localStorage or file); a reload resets them. The only thing the page itself keeps is the display cookie `sttd_language` (your language choice). Separately, the Firebase SDK itself stores the authentication session in the browser in its default way so that the sign-in can be restored; that storage is Firebase's behaviour and is not changed by this page. If another tab signs out or switches to another account, steps 2 to 7 are reset and you are asked to sign in again.

1. **Sign in** — "Sign in with Apple" (or "Sign in with Google", if enabled; see below) loads the authentication library and signs in with the same method and account as your source app. The popup opens only when you press the button (press again if it was blocked). Signing in again with another account resets steps 2 to 7.
2. **Add the plugin and confirm the connection** — After adding the plugin and allowing the connection, press "Check the connection" once (nothing is polled). When the connection is allowed ("Connection authorized. Waiting for receiving to start." or "Receiving") and access is allowed, the screen moves to step 3 by itself (step 4 is not skipped even when already receiving). Not connected, expired, a pending destination change, or a state that could not be checked does not advance; the screen tells you in English or Japanese what to do next. A pending destination change (receiver settings for a different destination remain) is resolved by reconnecting the plugin with the original Apple or Google account and confirming the deletion of the previous receiver settings on the final permission page (code sign-in never deletes them; the deletion stops the old destination for new deliveries and does not cancel deliveries already started). While checking, steps 3 to 7 are locked; if the connection stays allowed the progress is kept, otherwise steps 3 to 7 are reset. "Disconnect" deletes this account’s connection and receiving settings after confirmation. It also shows the access permission (the operator's explicit registration) and tells apart three cases: not permitted, could not be checked, and an old service version that needs an update. In all of them no new send is possible, but you can still disconnect, and check or cancel an earlier send. Step 2 also has a short "Add and connect the plugin" note with expandable steps that you can read whether or not you are connected (an existing connection does not need to be added again). As the registration target it shows this deployment's server URL, the helper's `mcpOrigin` followed by `/mcp` (without that setting it shows guidance only and never guesses a URL). Do not register this local page (localhost) or the API origin. The steps: in ChatGPT open Plugins, press "+", choose "Add custom MCP server", enter a name you will recognize and the server URL, and choose an HTTPS connection with OAuth authentication; check the destination, authentication and any warning, create and install it, and allow the connection with the same Apple account as in step 1; then come back and press "Check the connection" (receiving is started in step 3). Menu names and availability depend on your ChatGPT account or workspace and may change, so also see the official links on the page ([Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt), [Add custom MCP server](https://developers.openai.com/api/docs/guides/custom-mcp-server)). Opening the guide, following a link or switching the language sends nothing from this page.
3. **Test instructions for Dots (start receiving)** — Show or copy the test text from the [Dots guide](DOTS_GUIDE_EN.md), paste it into the receiving Dots, select the added plugin in the same conversation and ask it to "start receiving on this Dots", then press "I pasted it into Dots. Next" to move to step 4. If the browser cannot copy, confirm a manual copy before continuing. Copying sends nothing to Dots.
4. **Check receiving** — After asking to start receiving, press "Check receiving" once. Only receiving with access allowed opens step 5. Waiting for receiving stays in this step; an unknown result is never treated as success.
5. **Send the fixed test message** — There is no text field; the fixed message (English "This is a SendTextToDots delivery test.", Japanese "SendTextToDotsの送信テストです。") is shown. The sent text is this fixed message, not any value typed on the page. Press "Send the fixed message" (one POST; a double click does not create a second one), confirm yourself in Dots that the received text matches it, then press "I confirmed in Dots that the text matches. Next". "Accepted" is the callback's 2xx, not proof of a match. Nothing sent, failed, cancelled or expired cannot be confirmed; an unknown result can be confirmed after you actually checked the match in Dots (the screen never rewrites unknown to success).
6. **Operational instructions for Dots** — Show or copy the operational text, paste it into the same Dots, and press "I pasted it into Dots. Finish". The screen then shows the setup completion text and opens step 7 (it scrolls there). This is progress by your own confirmations, not a server-side verification that Dots applied the instructions.

7. **Send your own text** — After completing step 6, type a message and press "Send". Use "New send" for another message. Whitespace-only text and text over 4096 UTF-8 bytes are rejected before sending. These results are separate from the fixed test match, and do not determine whether setup is complete.

After completion, send ordinary messages in step 7 (no re-copy of steps 3/6 is required). Signing in again, switching the sign-in method, losing the connection or the access permission, losing the receiving state, or re-applying the test instructions resets the steps that depend on it (re-applying the test instructions restarts from the receiving check in step 4 and locks step 7 again).

**Skipping steps (the "Skip" at the top right)** — Steps 1, 2, 3, 5, 6 and 7 have a gray "Skip" at the top right of their heading; step 4 is marked "Required" and cannot be skipped. A skip is recorded separately from "done": an unconfirmed step is never shown as completed, matched or pasted. "Skip (resume the saved sign-in)" in step 1 loads the authentication library only when pressed and checks the sign-in that Firebase saved in this browser for the chosen method. It refreshes the ID token and moves to step 2 only when the project, no tenant, and the sign-in method (Apple, or for a code the dedicated UID and code marker) match this deployment. With no saved sign-in, an expired one, another deployment or another method, you stay in step 1 with guidance to sign in normally (no popup, no sign-out, no code issued). For a resumed code sign-in, reissue, cancel and the code check are not shown unless this page issued the code. Skipping steps 2 and 3 still requires the explicit check in step 4 (receiving with access allowed) before anything can be sent. If steps 5 or 6 were skipped, the completion text says that some steps are unconfirmed, and you can go back and do them. "Skip" in step 7 only ends the guidance without sending, and is unavailable while a send is unsettled. Signing in again, switching the method, or losing the connection or receiving resets the related steps, including skips.

**Sign in with Google** — In step 1 you can choose "Sign in with Google" next to "Sign in with Apple" (the official Firebase Google popup). The server accepts only verified ID tokens for this deployment's project, without a tenant, from the `google.com` provider. Apple and Google are separate accounts even with the same email address; they are not merged or linked automatically by email. If the email is already registered with a different method, the screen asks you to sign in with the method you used before. A saved Google sign-in can be resumed with "Skip (resume with the saved sign-in)" and with "Continue with the signed-in account" on the connection screen. When reconnecting with the same Google account, you can confirm deletion of the previous receiver settings on the permission page. To use Google on a deployment, the operator must enable the Google provider in Firebase Authentication and set the authorized domains (otherwise the popup fails and the screen shows "Could not sign in.").

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

1. In step 1, under "Choose how to sign in", select "Sign in with a code" and press "Continue" (selecting alone issues nothing and sends nothing). Selecting "Sign in with Apple (recommended)" and pressing "Continue" starts the Apple sign-in. There is a single "Continue" button, and only the chosen method's description and controls are shown. A successful issue moves you to step 2 (the add-on steps open) and shows a 6-digit code and the time left. Issuing a code alone does not open step 3 or later.
2. Within 10 minutes, enter the code in the plugin connection screen after adding the plugin. A code works once. Then complete the normal consent (receiving is started in step 3 and checked in step 4).
3. Press "Check connection" in the console to sign the console in to the same account. There is no automatic polling.
4. "Generate a new code" ends the current code and its connection and creates a new one. If a new code cannot be secured, the current code and connection stay unchanged.

Switching between Apple and a code happens in step 1. Switching does not stop the previous connection. Remove the previous plugin and add it again from step 2. The previous connection will not carry over.

The operator claim secret lives only in the helper's memory. If the helper exits, issued codes can no longer be checked or reissued (an unused code expires in 10 minutes; issue a new one).

**Code sign-in lifetime (10 minutes after sign-in)** — A code sign-in stops working 10 minutes after the sign-in with the code succeeded on the connection screen. Even if the plugin was added and connected normally, after 10 minutes new sends, subscriptions, connection checks, token refreshes, new requests with an existing access token, and restoring the state in the issuing console are all refused. Reloading or refreshing tokens does not extend it (exactly 10 minutes is already refused). To keep using it, issue a new code in the console and start a new connection from the plugin. This lifetime does not apply to Apple or Google sign-in. Requests that were already in progress are not cut off, and the Firebase account is not deleted automatically (only new operations after the deadline are stopped). Code connections from earlier versions that lack this deadline cannot be used, because their deadline cannot be checked (no new 10 minutes is added); connect again with a new code. Existing Apple and Google connections keep working. Earlier code connections are detected at the common entry for MCP access tokens and OAuth exchange/refresh (the owner check) and at sign-in admission. The final delivery/subscription checks judge only connections that carry the deadline themselves; an earlier connection does not reach them without passing that common entry.

**Code entry lock (3 wrong codes per connection)** — If a wrong code is entered 3 times in the same connection (one connection attempt started from the plugin), code entry is locked for that connection, and from the 4th try even the correct code cannot connect. Reloading the page, reissuing the code, another tab, or waiting does not unlock it. To try a code again, start a new connection from the plugin (Sign in with Apple still works while locked). Posts from an invalid page (Origin or check value mismatch) and temporary failures do not count as wrong codes. Removing and re-adding the plugin can be used to recover, but STTD does not detect or require plugin removal (the lock is per connection attempt).

## Registered developer environment (strict trusted-source deployments)

Only if the operator registered this PC's public key with `manage-sources.mjs register-developer`, add `"source": {"sourceId": "src_…", "keyFile": "<path to the Ed25519 private key (PKCS#8 PEM)>"}` to the helper's configuration JSON. The helper reads the key once at start and keeps it only in memory (never in the browser, URLs, CLI arguments or logs). Make the key file readable only by you on this PC.

### Deployments with sending-app registration

When sending-app registration is enabled on the MCP server, add `"connectedApps": true` at the top level of the helper's JSON configuration. This setting requires the `source` configuration above.

1. Sign in in step 1, then connect SendTextToDots in ChatGPT using the same account.
2. Ask SendTextToDots in ChatGPT for a registration code for the local console. Enter it in “App registration code” in step 2 and select “Register console.” The code expires after 10 minutes and works once.
3. Select “Check the connection” and continue to set up receiving. If the console's registration is removed, return to step 2 to register again. Use `list_connected_apps` in ChatGPT to check registrations or `remove_connected_app` to revoke one. The “Disconnect” action in step 2 deletes the account connection, receiving settings, and sending-app registrations together.

The helper signs `GET /v1/source/pair` and `POST /v1/source/pair` for the configured MCP origin using the registered key. The code is sent in the POST body.

### Deployments with connection approval

With `connectedApps` omitted, the helper uses the existing approval flow. When `source` is set, the helper signs `POST /v2/commands` to the fixed apiOrigin and the connection approval `GET/POST /v1/source/approvals/{interactionId}` to the fixed mcpOrigin. Status/cancel and connection state/disconnect are not signed. There is no way to sign for arbitrary destinations or headers. The send screen shows an "Approve a connection" section: enter the connection request reference shown on the plugin connection screen, press "Check", confirm the content, press "Approve", then continue consenting on the original connection screen. This section loads no Firebase SDK and makes no request until you press "Check". The approval is sent only for the reference you checked and the account signed in at that time; changing the reference or account after checking requires checking again (and so does each approval). There is no automatic polling. The helper does not start if the key is not Ed25519, cannot be read, or the setting is malformed.
