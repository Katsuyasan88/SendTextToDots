# Unverified items and limitations

English | [日本語](LIMITATIONS.md)

This page states what has been verified and the remaining unverified items and limitations.

## Verified scope

On 2026-10-25, in the author's development environment, 0.3.0 was used for Apple sign-in and a `text.submitted` subscription, and one arbitrary text each was sent from the direct API (`/v2/commands`) and from `/console`. The author confirmed that texts containing Japanese and line breaks arrived in the author's real Dots exactly as typed and were shown without duplicates. The verification is limited to these two messages.

On the same day the service was stopped and restarted, and the receiving state was confirmed in the same browser. The receiving Dots was told to treat the text as a work request, and the result and identifier of one simple calculation instruction sent from the demo matched. Dots performs the work; SendTextToDots itself does not interpret or execute the text.

### Use of the GitHub source on a Mac (author's report)

Material provided by the author dated 2026-10-25 reports that GitHub commit `ad276fccc504bc367df209edb694809570496c3e` (0.3.0) was obtained on a Mac and deployed without changing product code, tests or dependencies. The changes were the deployment values in `src/config/deployment.ts` and the additional deployment configuration files `.firebaserc` and `firebase.json`. This does not mean the service works with the unset placeholders.

The Mac ran Node.js 22.23.2/npm 12.0.2, and `npm ci --ignore-scripts --no-audit --no-fund` and the TypeScript build succeeded. `npm test` had 108 successes and 4 failures; the failures are reported as `EADDRNOTAVAIL` when listening on `127.0.0.2` on macOS. The TLS tests used OpenSSL 3.6.4 prepared in a temporary folder, and no change weakened the source or the tests. The same source in Linux Cloud Build (`node:22.23.3-trixie`, Node.js 22.23.3, OpenSSL 3.5.7) is reported to have passed all 112 tests with synthetic configuration, synthetic SDKs and loopback.

After Apple sign-in, the OAuth connection and the Events subscription, the author sent one message from `/console` and confirmed that two lines containing Japanese and a line break arrived in the author's real Dots exactly as typed. The material contains no reconciliation of that command ID with the API's `delivered` state log.

These are the author's installation and usage results on another device, not independent third-party verification. The macOS version and CPU are not recorded. They do not mean that all Mac automated tests pass, that every listed installation command was reproduced unchanged, or that production operation including long-running operation, load and cost caps has been verified.

## Unverified

| Item | State |
| --- | --- |
| Deployment and operation in a third party's Google Cloud project | Unverified. Automated tests use only synthetic SDKs, synthetic configuration and loopback, not real Cloud, real credentials or real callbacks |
| Processing on the receiving side (Dots/ChatGPT) | Unverified beyond the two messages above and one simple calculation instruction. An earlier version showed batching when several messages were sent in a short time; immediate per-message processing (individual responses) and completion of arbitrary instructions are not guaranteed |
| A sequence with several entry points for the same user (the same Firebase UID in an iOS app and the web) | Unverified (including 0.3.0) |
| Continuity of connections and subscriptions across service restarts | In the author's development environment, the receiving state in the same browser and the delivery of one instruction were confirmed after a restart. Long-term continuity and all subscription renewal paths are unverified |
| Load, concurrency and cost | Unverified. Cost caps, budget alerts and shutdown procedures are the installer's operation |
| Physical deletion after the retention period | Data becomes unusable after expiry, but no process physically deletes expired data. Firestore TTL and similar settings are the installer's decision |
| Account deletion (deletion of all of a user's data) | Not implemented |
| Changing the subscribing client | The OAuth client is fixed to the single ChatGPT CIMD in `src/oauth/cimd.ts`. Other clients are unverified |
| Build/test on macOS and Linux | In the author's material above, the Mac build succeeded with 108 passed / 4 failed tests, and Linux Cloud Build passed 112/112. The portability of the Mac loopback tests is unresolved. The Windows verified versions are Windows 11, Node 22.23.4, npm 10.9.9 and TypeScript 7.0.2. This is not a guarantee for every OS or version |
| Display language | The English/Japanese pages and the language cookie are verified only by synthetic tests. Real browser behaviour and other languages are unverified; languages other than English and Japanese fall back to English |
| Local send screen | The helper, the 5-step setup and the relay are verified only with synthetic SDK/DOM/fetch and loopback. Real browser sign-in, clipboard, Apple popup, and relaying to a real deployment are unverified. The author's earlier real deliveries were made with the former Cloud Run `/console`, which no longer exists |

## Not included

- The iPhone/Apple Watch app (the source client). Direction controls, preset instruction mappings and text generation are features of the source and are not part of this source.
- Tools to create, deploy or stop Cloud resources. Packaging (`npm run package`) only creates archives offline.
- A tool to create the KMS subscription marker (installers create it in the format of [INSTALL_EN.md](INSTALL_EN.md)).
- Verification of paid purchases or quotas. Self-hosting users and costs are managed by the installer.

## Not guaranteed

- `delivered` means the receiving callback accepted with 2xx; it is not the completion of processing or a response by the receiving app.
- Cancellation after dispatch (withdrawing an HTTP request that has arrived).
- Physical erasure of secrets and text from RAM, SDKs and the OS.
- Complete termination within the Cloud Run shutdown grace period, or cold start duration.
- This is not an official OpenAI, Apple or Google product and is not provided or endorsed by them.

## Verification scope of the installation steps and Node versions

The deployment command examples in [INSTALL_EN.md](INSTALL_EN.md) follow the public source contract and Google Cloud's official documentation. A complete fresh setup in a third party's project, running the listed key-generation and API examples, and IAM/public reachability under each organization policy are unverified. The author's report of using the GitHub source on a Mac and reaching real Dots is recorded above, but it is not proof that every listed command was run as written.

The locally verified versions are Node.js 22.23.4/npm 10.9.9. The package's `engines: >=22` is not a guarantee for every 22.x or a later major version. `URL.parse` was added in 22.1.0 and `zlib.crc32` in 22.2.0, so early 22.x cannot be targeted. Full verification at the minimum version and verification on Node 23 or later have not been done. The Cloud-managed Node 22 runtime and the MCP's fixed base image have different patch versions from the local one and are not the same environment.

`npm run package` does not overwrite output with the same digest and stops with `output_exists`. The archives contain no dependencies and the deployment-side build connects to the registry. A successful local packaging does not guarantee image retrieval, dependency retrieval, Cloud Build, IAM or service startup.
