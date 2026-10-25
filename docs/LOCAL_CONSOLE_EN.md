# Local send screen (5-step setup)

English | [日本語](LOCAL_CONSOLE.md)

The send screen is not served by Cloud Run. A small helper running on your own computer serves it at `http://localhost:8765/console`. Opening the page, reloading it, switching the language, and showing or copying the fixed instructions never contact Cloud Run, the send API or Firebase. Requests leave the page only when you press a button, and the Firebase authentication library is loaded only when you press "Sign in with Apple" in step 1.

## What you need

- Node.js 22 (the same version conditions as in [INSTALL](INSTALL_EN.md)) and the built source of this repository (`npm ci --ignore-scripts --no-audit --no-fund` and `npm run build`). No new dependency.
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

All five steps are always shown in order; at first only step 1 is active and steps 2 to 5 are gray. Completed steps are shown faded, and clicking anywhere in such a step (or pressing Enter/Space on it) re-activates it for review (reviewing does not erase anything). Buttons and fields inside inactive steps cannot be used. After all five steps the completion text appears at the bottom of the page and stays there even when you return to step 4 to keep sending. Progress, the typed text and the ID token live only in memory and are reset by a reload. Only the language choice is kept, in the display cookie `sttd_language`. If another tab signs out or switches to another account, steps 2 to 5 are reset and you are asked to sign in again.

1. **Sign in** — "Sign in with Apple" loads the authentication library and signs in with the same Apple account as your source app. The popup opens only when you press the button (press again if it was blocked). Signing in again with another account resets steps 2 to 5.
2. **Check the connection** — Press "Check the connection" once to check the connection and subscription (nothing is polled). "Receiving" unlocks step 3. For not connected, waiting to start receiving, expired, or a pending destination change, the screen tells you in English or Japanese what to do next in ChatGPT. While checking, steps 3 to 5 are locked; if receiving continues the progress is kept, otherwise steps 3 to 5 are reset. "Disconnect" is also here.
3. **Test instructions for Dots** — Show or copy the test text from the [Dots guide](DOTS_GUIDE_EN.md), paste it into the receiving Dots, then press "I pasted it into Dots. Next". If the browser cannot copy, confirm a manual copy before continuing. Copying sends nothing to Dots.
4. **Send** — The text field is empty with a non-sensitive example as placeholder. Type a short message and press "Send" (one POST; a double click does not create a second one), confirm yourself in Dots that the received text matches, then press "I confirmed in Dots that the text matches. Next". "Accepted" is the callback's 2xx, not proof of a match. Nothing sent, failed, cancelled or expired cannot be confirmed; an unknown result can be confirmed after you actually checked the match in Dots (the screen never rewrites unknown to success).
5. **Operational instructions for Dots** — Show or copy the operational text, paste it into the same Dots, and press "I pasted it into Dots. Finish". The screen then shows the 5-step completion text. This is progress by your own confirmations, not a server-side verification that Dots applied the instructions.

After completion, re-select step 4 to send ordinary messages (no re-copy of steps 3/5 is required). Signing in again, losing the receiving state, or re-applying the test instructions resets the steps that depend on it.

## What the helper relays

The helper relays only the requests behind the buttons, to the fixed origins in the configuration. The browser never talks to the production origins directly, and the CORS and permissions of the Cloud Run side are unchanged.

| Request from the page | Upstream |
| --- | --- |
| `GET /v1/web/connection`, `POST /v1/web/disconnect` | `mcpOrigin` |
| `POST /v2/commands`, `GET /v2/commands/{id}`, `POST /v2/commands/{id}/cancel` | `apiOrigin` |

Every request must carry `Authorization: Bearer <Firebase ID token>` and a random value created at start (local nonce). A mismatched Host or Origin, a missing or duplicated nonce, a path or method outside the list, and an oversized body (32 KiB for the whole send JSON; the 4096-byte text limit stays with the API) are refused before any upstream call. Upstream responses are read up to 64 KiB and cut off with a fixed error beyond that. Only `Authorization` (plus `Content-Type` and `Idempotency-Key` when sending) is forwarded; Cookie, Origin, Forwarded headers and the nonce are not. Responses return only the status, body, `Content-Type` and `Retry-After`; `Set-Cookie` is not forwarded. Tokens, text and secrets are neither stored nor logged. Arbitrary URLs cannot be relayed and redirects are not followed.

## Limits

- Behaviour in third-party environments and real browsers is unverified beyond the synthetic tests ([LIMITATIONS](LIMITATIONS_EN.md)).
- The helper is a development aid on your own computer; it adds no authentication or secret handling and does not change Cloud settings or start or stop services.
