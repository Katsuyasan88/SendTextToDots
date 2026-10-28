# Installation

English | [日本語](INSTALL.md)

This guide describes the structure and the order of work for a new installation of 0.3.0 into your own Google Cloud / Firebase. Running this procedure end to end in a third party's project has not been verified. It does not guarantee successful deployment or production operation beyond the verified scope in [LIMITATIONS_EN.md](LIMITATIONS_EN.md). Cloud commands change resources, costs and permissions, so confirm the target project and budget before running them.

## 1. What you need

- Local Node.js **22.23.4 is recommended** (the author's verified version); npm 10.9.9 is the verified version. This does not mean every 22.x release works. Check with `node --version` and `npm --version`. `zlib.crc32` was added in 22.2.0 and `URL.parse` in 22.1.0, so early 22.x cannot be used. The package `engines` declares `>=22.2.0 <23` (the 22 line only) as the requirement of these APIs; this does not mean every test passes on 22.2.0 or that every 22.x works. The measured version is 22.23.4 above, and full functionality on other 22.x patches is unverified. The Cloud Functions managed Node.js 22 runtime, the engines of the packaged archives (`22`) and the MCP's fixed base image (Node.js 22.23.3) have separate roles from the local version and are not the same environment.
- The source of this repository alone can be built and tested. The developer's private folders, Git hooks and AI settings are not needed. Do not copy `node_modules` or `dist` from another environment; obtain them from the lock file. Do not add `--omit=optional`, because TypeScript has platform-specific dependencies.
- Your own Google Cloud project with billing enabled and Firebase in the same project. Make it a new installation that does not reuse another app's DB, keys or subscriptions.
- A Firebase Web app, the Apple provider in Authentication, and the Sign in with Apple configuration on the Apple Developer Program side. Follow the [official Apple setup guide](https://firebase.google.com/docs/auth/web/apple) to configure the Services ID, Team ID, key and so on, and register the authentication redirect on the Apple side. Apple's private key is never put into this source.
- Access to a Dots/ChatGPT client that supports the required MCP Events subscription. The allowed OAuth client is the single ChatGPT CIMD in `src/oauth/cimd.ts`. Other clients or other callback specifications are not supported automatically.
- The Cloud command examples below are for **Bash (Cloud Shell and so on) and the Google Cloud CLI**. They are not syntax to paste into PowerShell as is. The CLI is for the installer's administrative operations and is not used as the service's runtime credentials.

## 2. Fix the project, names and URLs before deployment

1. In the Google Cloud Console, check the project ID, the numeric project number, and the `projectId`, `authDomain` and Web API key of the Firebase Web configuration. Do not write the Web API key value into the server source; set it later in the MCP environment variable.
2. Decide a single region, separate runtime service accounts for the API and the MCP service, and the MCP service name. The API function/service/export name is fixed to `sendtexttodotsapi`. Do not overwrite an existing service with a conflicting name.
3. The API/MCP origins are needed before the build. With [Cloud Run deterministic URLs](https://docs.cloud.google.com/run/docs/triggering/https-request#deterministic-url) they can be predicted before creation in this form:

   ```text
   API: https://sendtexttodotsapi-<PROJECT_NUMBER>.<REGION>.run.app
   MCP: https://<MCP_SERVICE>-<PROJECT_NUMBER>.<REGION>.run.app
   ```

   Keep the DNS segment made of the service name, `-` and the project number within 63 characters. Use this in an environment where the default `run.app` URL is allowed, and verify in the management console after deployment that it is usable. Even if the Console also shows an aliased hash URL or a `cloudfunctions.net` URL, do not switch the issuer without a decision. If you use your own domain, prepare TLS and routing first and use the same origin consistently.
4. Add the MCP host to the authorized domains of Firebase Authentication. The redirect on the Apple side is Firebase's `https://<authDomain>/__/auth/handler`, which is separate from the MCP origin itself. Also add `localhost` for the local send screen.
5. Following [CONFIGURATION_EN.md](CONFIGURATION_EN.md), generate three new namespace UUIDs and keep them fixed. They are not secret keys. Check the mapping of project/number/database/region/keys/secret versions in the configuration against your records.

## 3. Prepare Cloud resources and permissions

In the Google Cloud Console, make at least the APIs for Cloud Functions, Cloud Run, Cloud Build, Artifact Registry, Firestore, Cloud KMS, Secret Manager, IAM and Firebase Authentication/Identity Toolkit usable. Enabling APIs and granting roles is done by the installer's project administrator. Resolve organization constraints, region constraints and disabled billing first.

| Resource | Content |
| --- | --- |
| Firestore | A new database in Native mode (`(default)` or named). Apply the deny-all rules of `firestore/firestore.rules` and the five single-field index exemptions of `firestore/firestore.indexes.json` to the chosen database. Writes go through the server IAM only |
| Cloud KMS | A key ring in the configured region and a symmetric SOFTWARE / ENCRYPT_DECRYPT CryptoKey. Fix the numeric version in use |
| Secret Manager | Four purpose-specific secrets with numbered versions (next section). Do not use `latest` |
| Runtime service accounts | Create separate ones for the API and the MCP service and attach each to its service. Do not create long-lived SA key files |
| Build service account | Choose one separate from the runtime, with permissions to read the source, write images and store build logs |
| Artifact Registry / source storage | A Docker repository in the same project/region as the build, plus the storage for Functions/Cloud Build sources and logs |

### Separate runtime and deployment permissions

| Principal | Required permissions and purpose | Scope guideline |
| --- | --- | --- |
| Both API and MCP runtime | Firestore read/write (for example `roles/datastore.user`) | Limited to the database in use. Do not substitute by changing the Firestore rules to public read/write |
| Both API and MCP runtime | **`firebaseauth.users.get`**. Checking ID token revocation/disabling and user state | The project in use. A minimal custom role or a reviewed predefined role. Note that it comes with the ability to list/view Auth users |
| API runtime | KMS decryption (`roles/cloudkms.cryptoKeyDecrypter`) | The CryptoKey in use only |
| MCP runtime | KMS encryption/decryption (`roles/cloudkms.cryptoKeyEncrypterDecrypter`) | The same CryptoKey only |
| API runtime | Secret read (`roles/secretmanager.secretAccessor`) | The two secrets identifierKey and commandDigestKey only |
| MCP runtime | Secret read (same) | The three secrets jwks, cookieKeys and identifierKey only |
| Build SA | Reading source objects and any required staging writes, Artifact Registry writes, build log storage | Limited to the chosen bucket/repository/log destination |
| The deploying person/CI | Create/update Functions/Run, start Builds, `iam.serviceAccounts.actAs` on the chosen build/runtime SAs and so on | Limited to the deployment targets. Do not give deployment permissions to the runtime |

Without `firebaseauth.users.get`, authentication stops even if the DB and secrets can be read. The source verifies with `verifyIdToken(token, true)` and `getUser`, so a setup with only JWT signature verification is not enough. See the [official list of Auth permissions](https://docs.cloud.google.com/iam/docs/roles-permissions/firebaseauth).

The Google-managed Functions/Run/Build service agents also need their standard deployment permissions. Do not confuse them with the runtime SA, and do not give service-agent roles to ordinary users. The default Build SA differs per project. Check the chosen principal and the source bucket/Artifact Registry/log destination against [Functions build](https://docs.cloud.google.com/functions/docs/building) and [user-managed Build SA](https://docs.cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts). Do not solve permission errors by granting Owner/Editor wholesale.

### Create the secrets and register numbered versions

| Purpose | Required format |
| --- | --- |
| `jwks` | UTF-8 JSON `{"keys":[<private ES256 JWK>,<private RS256 JWK>]}`. Exactly two keys, one of each. Every field is a string. ES256 has `alg: "ES256"`, `kty: "EC"`, `crv: "P-256"`; RS256 has `alg: "RS256"`, `kty: "RSA"`. Both need a non-empty `d` and the complete private-key parameters. Give them separate `kid` values and `use: "sig"` |
| `cookieKeys` | **Raw bytes** of one or more random 32-byte keys concatenated (a positive multiple of 32) |
| `identifierKey` | **Raw 32 bytes**, random |
| `commandDigestKey` | **Raw 32 bytes** generated separately from identifierKey |

A JWK export may not include `alg` automatically. Adding array/boolean fields other than key-usage fields to a JWK is rejected by this source's checks. Do not register binary secrets as hex/base64 strings.

The following is a generation example that the installer runs in their own protected environment. Prepare a directory with restricted permissions outside the Git working folder, set its absolute path in `STTD_SECRET_DIR`, save the example as a `.mjs` file in the same directory and run it with Node.js. Keys are not printed, and existing files are not overwritten. Follow your own secret management policy for backup/deletion.

```js
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
const directory = process.env.STTD_SECRET_DIR;
if (!directory || !isAbsolute(directory)) throw new Error('Set an absolute STTD_SECRET_DIR outside the repository');
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
const jwks = { keys: [
  { ...ec, alg: 'ES256', use: 'sig', kid: randomUUID() },
  { ...rsa, alg: 'RS256', use: 'sig', kid: randomUUID() },
] };
const payloads = {
  'jwks.json': Buffer.from(JSON.stringify(jwks)),
  'cookie-keys.bin': randomBytes(32),
  'identifier-key.bin': randomBytes(32),
  'command-digest-key.bin': randomBytes(32),
};
try {
  for (const [name, bytes] of Object.entries(payloads)) {
    writeFileSync(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
} finally {
  for (const bytes of Object.values(payloads)) bytes.fill(0);
}
```

Restrict the directory ACL separately. `mode: 0o600` alone does not set Windows ACLs. Physical erasure of files, backups and JWK strings is not guaranteed. If the process stops midway, do not regenerate existing keys automatically.

Create the four purpose-specific secrets in Secret Manager and register each corresponding file **as a file**. A Bash example for secrets that already exist is as follows (set the project/secret names yourself).

```bash
gcloud secrets versions add "$JWKS_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/jwks.json"
gcloud secrets versions add "$COOKIE_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/cookie-keys.bin"
gcloud secrets versions add "$IDENTIFIER_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/identifier-key.bin"
gcloud secrets versions add "$DIGEST_SECRET" --project="$PROJECT_ID" --data-file="$STTD_SECRET_DIR/command-digest-key.bin"
```

Record the returned numbered versions in the deployment configuration as `projects/<PROJECT_NUMBER>/secrets/<SECRET_ID>/versions/<N>`. Do not copy the payloads into logs, issues or the source, and confirm that each version is enabled and that the runtime SA has the required read permission.

Only if you use payload encryption (off by default), create one more dedicated secret, separate from the four above. Its value is 32 random bytes as unpadded base64url (43 characters). Grant read permission on that secret only to the send API runtime SA (not to the MCP runtime SA). For the configuration, see [Key storage for payload encryption](CONFIGURATION_EN.md#payload-encryption). If you keep it off, this step is not needed.

### Create the KMS subscription marker

At startup both services require that `sttdAuth/<kms.namespace>/config/kms-subscription` matches the configuration exactly. It is not created or repaired automatically. In the Console of the chosen Firestore database, go to collection `sttdAuth` → document `<kms.namespace>` → subcollection `config` → document `kms-subscription`, and create only the following fields.

| Field | Value and Firestore type |
| --- | --- |
| `version` | integer `2` |
| `format` | string `sttdkms1` |
| `namespace`, `environment`, `projectId`, `databaseId`, `cryptoKey` | The same strings as `kms` in the deployment configuration (environment is fixed to `development`) |
| `writeVersion` | The same integer as the deployment configuration |
| `readVersions` | An array of integers, the numbered versions of the deployment configuration in ascending order |

Do not make `writeVersion`/`readVersions` strings. Extra fields are also rejected. If a marker already exists, compare the values and stop; do not overwrite another installation. The correct form is defined by `kmsMarkerDocument` in `src/storage/firestore/kms-subscription-format.ts`.

### Apply the Firestore rules and index exemptions

In the Firestore section of the Firebase Console, **select the database in use** and apply the content of `firestore/firestore.rules` to Rules. In the single-field exemptions under Indexes, register each `collectionGroup`/`fieldPath` of `firestore/firestore.indexes.json` and disable the ascending, descending and array indexes. The targets are the five items `oidc/sealed`, `owners/sealedUid`, `subscriptions/active.sealedUrl`, `subscriptions/active.sealedSecret` and `subscriptions/active.previousSecret.sealed` (left of the slash is the collection group, right is the field path). Confirm completion following the [official index management guide](https://firebase.google.com/docs/firestore/query-data/indexing). This is not an operation of pasting raw JSON into the Console query field. With a named DB, do not apply to the wrong existing DB.

## 4. Configure, build and package

1. In the source root run `npm ci --ignore-scripts --no-audit --no-fund` and `npm test`. Tests run with synthetic configuration and do not connect to real Cloud or credentials.
2. Replace every placeholder in `src/config/deployment.ts` with the reference values of your resources and finally set `configured: true`. See [CONFIGURATION_EN.md](CONFIGURATION_EN.md). Do not write real secrets, and do not commit your real deployment values to public Git.
3. After `npm run build`, run `npm run package`. The API ZIP, the MCP Cloud Build archive and the receipt are created under `.tmp/sendtexttodots-artifacts-<digest12>/`. Packaging is offline and does not send to or deploy to Cloud.

Packaging the same content again stops with `output_exists`. Overwriting and automatic deletion are not done by design. Check that the existing directory contains `api.zip`, `mcp.tar.gz` and `receipt.json`, compare each archive SHA256 in the receipt with the actual file's SHA256, and use the existing artifacts. The receipt is a record of local packaging, not evidence of deployment or authorization. If an incomplete output remains after a failure, do not use it; check the target directory and the required artifacts, quarantine them manually, and package again with the same name free. Do not solve it by deleting the whole `.tmp`.

## 5. Deploy from the archives

The root `package.json` is for local build/test and is not a deployment package with `main` or `start`. This is not a procedure that passes the root to `firebase deploy` or a Cloud Run source deploy as is. Always use the packaged archives.

### Prepare staging and the build

Set the following Bash variables to your values. `ARTIFACT_DIR` is the output directory of the previous section and `STAGE` is a new empty directory outside the Git working folder. Do not mix archives or extract over an existing staging directory.

```bash
mkdir "$STAGE/api" "$STAGE/mcp"
unzip "$ARTIFACT_DIR/api.zip" -d "$STAGE/api"
tar -xzf "$ARTIFACT_DIR/mcp.tar.gz" -C "$STAGE/mcp"
```

- `PROJECT_ID`, `PROJECT_NUMBER` and `REGION` are the same values as the deployment configuration.
- `API_SA` and `MCP_SA` are the e-mail forms of the runtime SAs, and `MCP_SERVICE` is the service name of the deployment configuration.
- `BUILD_SA` is the e-mail form of the chosen build SA, and `BUILD_SA_RESOURCE` is `projects/<PROJECT_ID>/serviceAccounts/<BUILD_SA>`.
- `IMAGE_URI` is `<REGION>-docker.pkg.dev/<PROJECT_ID>/<REPOSITORY>/connect:<unique tag>` inside the created Docker repository. Use a tag that does not overwrite another version.
- `BUILD_LOGS_BUCKET` is your own GCS bucket URI where the build SA can write logs. Satisfy the log storage conditions of a user-managed Build SA.
- `WEB_KEY_ENV` is the same name as `web.apiKeyEnv` in the deployment configuration. Before the first start of the MCP service, the Firebase Web API key value must be set under this name in the Cloud Run environment variables. Set it in the Console variable field or in a protected env YAML outside the Git working folder, and do not write the value directly into the command history.

### API (Cloud Functions 2nd gen)

A new deployment example following the [official gcloud functions deploy reference](https://docs.cloud.google.com/sdk/gcloud/reference/functions/deploy). If a function with the same name exists, stop first and confirm that it may be updated.

```bash
gcloud functions deploy sendtexttodotsapi \
  --project="$PROJECT_ID" --region="$REGION" --gen2 --runtime=nodejs22 \
  --entry-point=sendtexttodotsapi --source="$STAGE/api" \
  --service-account="$API_SA" --build-service-account="$BUILD_SA_RESOURCE" \
  --trigger-http --no-allow-unauthenticated \
  --memory=1GiB --cpu=1 --timeout=30s \
  --min-instances=0 --max-instances=3 --concurrency=20
```

The API processing conditions (1 CPU/1GiB, 30 seconds, min 0/max 3, concurrency 20) match `src/delivery/functions.ts`. The runtime is Cloud-managed Node 22, not necessarily the same patch as the local Node. The service does not start with the distributed configuration.

### MCP/OAuth (build the Dockerfile with Cloud Build and deploy to Cloud Run)

The extracted MCP archive contains a Dockerfile with a fixed base image. Build the image with [Cloud Build submit](https://docs.cloud.google.com/sdk/gcloud/reference/builds/submit) and check the digest of the successful image.

```bash
gcloud builds submit "$STAGE/mcp" --project="$PROJECT_ID" --region="$REGION" \
  --tag="$IMAGE_URI" --service-account="$BUILD_SA_RESOURCE" \
  --gcs-log-dir="$BUILD_LOGS_BUCKET"
```

Set `IMAGE_DIGEST_URI` to the `<image>@sha256:<digest>` created by that build. `MCP_ENV_FILE` is the path of the protected YAML containing the Web API key environment variable mentioned above. A [Cloud Run deployment](https://docs.cloud.google.com/run/docs/deploying) example for a new service follows.

```bash
gcloud run deploy "$MCP_SERVICE" --project="$PROJECT_ID" --region="$REGION" \
  --image="$IMAGE_DIGEST_URI" --service-account="$MCP_SA" \
  --port=8080 --cpu=1 --memory=1Gi --timeout=30s \
  --min-instances=0 --max-instances=3 --concurrency=20 \
  --env-vars-file="$MCP_ENV_FILE" --no-allow-unauthenticated
```

The MCP CPU/memory/instance counts are starting examples, not load-tested recommendations or cost caps. `PORT` is set by Cloud Run. Do not add rejected environment variables such as SA credential files or `NODE_OPTIONS`.

### Origin verification and external reachability

1. In the Console, compare the API/MCP service names, region, runtime SA, image/source and the name of the Web key environment variable. Confirm that the deterministic URL chosen in advance is usable and the default URL is not disabled, and that the OAuth issuer/CORS/authorized domain use the same origin. If the URL differs, go back to the configuration; do not rescue it by automatic substitution to another URL or by deploying on top.
2. The examples above keep the Cloud IAM entry private. At the stage where ordinary browsers and Dots must be able to use it, the installer checks the [Cloud Run public access settings](https://docs.cloud.google.com/run/docs/authenticating/public) and allows the required public reachability only for the API/MCP target services. If an organization policy forbids it, consult the administrator instead of bypassing the constraint.
3. The source values of `api.invoker`/`connect.invoker` stay `private`. The Cloud IAM entry and the application's Firebase/OAuth authentication are separate. Allowing public reachability at the Cloud entry does not disable the application's token/owner/signature checks. A Firebase ID token is not a substitute for a Cloud IAM ID token.
4. On startup failure, check the conditions in the next section and do not recreate keys, namespaces or permissions indiscriminately.

## 6. Connect, send the first message, and plan the shutdown

Follow the [Dots receiving and response guide](DOTS_GUIDE_EN.md): paste the test instructions into the receiving Dots, verify that the received text matches your sent message, and then paste the operational instructions. Steps 3 and 6 of the local send screen show and copy these instructions in its selected language. Copying does not send them to Dots, and the screen does not automatically verify a text match or a completed switch.

1. Start the local send screen on your computer ([LOCAL_CONSOLE_EN.md](LOCAL_CONSOLE_EN.md)): copy `console.config.example.json` to `console.local.json`, fill in the API/MCP origins and the public Firebase Web configuration, run `npm run console -- --config console.local.json`, and open `http://localhost:8765/console` (English and Japanese; nothing is loaded or sent until you press a button). Add `localhost` to the Firebase authorized domains. In step 1 sign in with Apple. The MCP server registration target for Dots/ChatGPT is **`/mcp` on the MCP origin**. Do not register the local screen or the API origin.
2. Before connecting, the operator explicitly registers each person who will use the service, including yourself, with the admin CLI ([CONFIGURATION](CONFIGURATION_EN.md#access-admin)). The Apple sign-in in step 1 creates the Firebase user, so confirm that person's UID in Authentication in the Firebase console (or equivalent) and register it. Someone not registered or stopped sees "This account is not permitted to use this service" at the OAuth login and cannot send. Then, from Dots/ChatGPT, connect through OAuth and give explicit consent as the same Firebase user. In step 2 press "Check the connection"; once the connection is allowed, step 3 opens (the screen tells you what to do next for the other states). Subscribing to `text.submitted` (starting to receive) happens in step 3, and step 4 checks that it shows "Receiving". Opening the send screen alone does not create a subscription. The steps to add the service to Dots/ChatGPT and the server URL to register are shown under "Add and connect the plugin" in step 2 of the local screen ([LOCAL_CONSOLE](LOCAL_CONSOLE_EN.md)).
3. In step 3 paste the test instructions into the receiving Dots and start receiving. In step 4 press "Check receiving" and confirm it shows "Receiving". In step 5 send the fixed test message. Confirm on the receiving side that it is shown exactly as the fixed message, then confirm the match in the screen. In step 6 paste the operational instructions; step 7 then sends your own text. STTD itself does not execute the text.
4. To use the API directly, see the [one-message client example](API_EN.md#direct-client-example) and [session requirements](API_EN.md#firebase-sessions). A Firebase ID token of the same project/UID authenticated with the Apple provider is required. No management tool that shows the web screen's token is bundled. The local screen can be used for the first check and for ordinary sends afterwards (step 7).
5. `delivered` means the callback accepted with 2xx, not completion of processing on the receiving side. If the result is unknown, look up the state with the same commandId you noted before sending, and do not resend automatically with a new ID.
6. To stop sending from this account, use "Disconnect" in step 2 of the local screen (confirm it there). It revokes the authorization and the subscription; connect again from ChatGPT to resume. Disconnecting keeps the record of the previous receiving destination, so to receive at a different destination, connect the plugin again with Apple and confirm "delete the previous receiver settings" on the final permission page (code sign-in never deletes them; your account, permission and key are kept). Cloud Run serves no send screen and no separate connection page.

Decide the shutdown method and retention costs before deployment. Disconnecting revokes the subscription/Grant; it does not stop or dispose of Cloud resources. Even with minInstances=0, external requests can start the service. Stopping/deleting unneeded services and retaining the DB/Secret/KMS/images are separate decisions on the Cloud side. Destroying the encryption key makes the stored information undecryptable, so do not delete everything at once just for cost reasons. This source contains no automatic shutdown/physical deletion tool.

## 7. Checks when stuck

| Symptom | What to check first |
| --- | --- |
| `deployment_config_unconfigured` / `deployment_config_invalid` | Placeholders, configured, origins, project number, namespaces, numbered secret versions, rebuild after configuring |
| `environment_rejected` from the SDK | Cloud Run service/revision/configuration, the configured service name, rejected environment variables. Do not bypass with a local server start or credential override |
| Secret/marker failure at startup | JWKS alg/complete private key, raw byte lengths, validity/permission of each secret version, type/exact match of the marker in the selected DB |
| Authentication fails although the token looks correct | Apple provider, same project/UID, expiry, revocation state, and **firebaseauth.users.get on the runtime SA** |
| The browser/Dots gets Cloud 401/403 and does not reach the app | Public reachability/IAM at the Cloud entry. Distinguish from the app's 401, and do not use a Firebase token in place of a Cloud IAM token |
| Connected but cannot send | Whether the text.submitted subscription on `/mcp` is valid. Check a different UID, Grant revocation, pending destination replacement and expiry |
| `output_exists` | Integrity and hash of the existing archive/receipt. Do not delete the whole `.tmp` without checking the existing content |

## Compatibility
### Compatibility of 0.3.0

0.3.0 is for new installations only.

- The send API and Events contract changed incompatibly from 0.2.0. Sending uses the `/v2/commands` family, a request has only the five fields `schemaVersion` 2, `commandId`, `text`, `createdAt` and `expiresAt`, and Events is `text.submitted` (data has the four fields `schemaVersion` 2, `commandId`, `text` and `expiresAt`). The 0.2.0 `/v1/commands` routes (404), requests with `schemaVersion` 1 or `direction`, `taskId`, `taskLabel`, `revision` (400), and subscriptions to the old event name `shortcut.triggered` (NotFound) are not accepted. There is no conversion, alias or redirect between old and new. Sources must send with the new contract in [API_EN.md](API_EN.md).
- The storage format identifiers (the storage roots above, `sttdkms1`, the marker version and the command state document format), the OAuth scope and the `/v1/web/*` routes are unchanged from 0.2.0 (the old connection page `/connect` is removed in 0.3.0). However, this is not a guarantee that Grants, subscriptions and command states stored by 0.2.0 can be carried over as is. No migration procedure or automatic migration from a 0.2.0 deployment to 0.3.0 is provided or verified. Do not reuse existing stored data or subscriptions; deploy 0.3.0 as a new installation (a different storage namespace, connection and subscription).
- This source includes the access permission (`accessPolicy: explicit-allow-v1`): nobody can use it until users are registered with the admin CLI. When an earlier 0.3.0 deployment without the permission is updated to this source, Grants and subscriptions consented before cannot be used for new sends or subscriptions, so each permitted person consents through OAuth and subscribes again. Going back to a version without the permission also removes the restriction, so do not roll back automatically ([CONFIGURATION](CONFIGURATION_EN.md#access-admin)).
- Versions before 0.2.0 also differ in the OAuth scope name, the Firestore storage roots and the KMS sealing format (prefix, format, AAD) and are incompatible. Grants, subscriptions, command states and markers stored by those versions are not read, and tokens with the old scope are not accepted.
