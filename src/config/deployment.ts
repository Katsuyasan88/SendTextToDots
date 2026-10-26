// SendTextToDots deployment configuration: the single source an installer edits before building and deploying.
// As distributed it is unconfigured (configured: false) and every value is a synthetic placeholder that fails validation. After
// editing, both the API and the MCP service refuse to start with a fixed error, before any SDK, credential, database or external
// HTTP use, unless every field passes src/config/validate.ts. Setting only configured to true is not enough.
// Never write secret values (keys, tokens, the Web API key value) here; write only Secret Manager version names and the name of
// the environment variable that holds the Web API key. Field details: docs/CONFIGURATION_EN.md (Japanese: docs/CONFIGURATION.md).
// This module is data only and has no imports.

export const DEPLOYMENT_CONFIG = {
  /** Set to true only after replacing every value below with your own. */
  configured: false,
  /** Access policy. Only `explicit-allow-v1` is accepted: only users the operator registers with the admin CLI can use the service (there is no allow-everyone mode). */
  accessPolicy: 'explicit-allow-v1',
  /** Google Cloud / Firebase project ID (6 to 30 characters). */
  projectId: 'your-project-id',
  /** Numeric project number of the same project. */
  projectNumber: '0',
  /** Firestore database ID (usually `(default)`). */
  databaseId: '(default)',
  /** Single region for Functions, Cloud Run and the KMS key ring (for example `us-central1`). */
  location: 'your-region',
  api: {
    /** Functions export name. Only `sendtexttodotsapi`, the export name in src/deployment/functions.ts, is accepted. */
    functionName: 'sendtexttodotsapi',
    /** Cloud Run service name of the API (the same as functionName for 2nd gen Functions). */
    serviceName: 'sendtexttodotsapi',
    /** Runtime service account used only by the API. */
    serviceAccount: 'your-api-sa@your-project-id.iam.gserviceaccount.com',
    /** `private` only (public reachability is granted separately through IAM at deployment). */
    invoker: 'private',
    /** Fixed public API origin (`https://<host>`, no trailing slash) that the local send screen helper relays to. */
    publicOrigin: 'https://api.example.invalid',
  },
  connect: {
    /** Cloud Run service name of the MCP/OAuth service (MCP, OAuth interaction and the connection status/disconnect API). */
    serviceName: 'your-connect-service',
    /** Runtime service account used only by the MCP service (different from the API's). */
    serviceAccount: 'your-connect-sa@your-project-id.iam.gserviceaccount.com',
    /** Public MCP origin (the OAuth issuer). Register `<this origin>/mcp` in Dots/ChatGPT. */
    publicOrigin: 'https://connect.example.invalid',
    invoker: 'private',
  },
  /** Namespace of the connection storage (`t256_<lower-case UUID, version 1 to 8>`). Generate once at installation and never change it. */
  connectNamespace: 't256_00000000-0000-0000-0000-000000000000',
  /** Namespace of the delivery storage (`t270_<lower-case UUID>`). */
  deliveryNamespace: 't270_00000000-0000-0000-0000-000000000000',
  kms: {
    /** Storage format environment name. Only `development` (compatible with the existing storage format). */
    environment: 'development',
    /** The same value as projectId. */
    projectId: 'your-project-id',
    /** The same value as databaseId. */
    databaseId: '(default)',
    /** Namespace of the KMS subscription storage (`t268_<lower-case UUID>`). */
    namespace: 't268_00000000-0000-0000-0000-000000000000',
    /** `projects/<projectId>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>` */
    cryptoKey: 'projects/your-project-id/locations/your-region/keyRings/your-ring/cryptoKeys/your-key',
    /** Numeric key version used for sealing. */
    writeVersion: 1,
    /** Numeric key versions allowed for opening (must include writeVersion). */
    readVersions: [1],
  },
  /** Fixed numeric versions of a separate Secret Manager secret per purpose (`projects/<projectNumber>/secrets/<id>/versions/<N>`). */
  secretVersions: {
    jwks: 'projects/0/secrets/your-jwks/versions/1',
    cookieKeys: 'projects/0/secrets/your-cookie-keys/versions/1',
    identifierKey: 'projects/0/secrets/your-identifier-key/versions/1',
    commandDigestKey: 'projects/0/secrets/your-command-digest-key/versions/1',
  },
  web: {
    /** projectId of the Firebase Web configuration (the same value as projectId). */
    projectId: 'your-project-id',
    /** authDomain of the Firebase Web configuration (for example `<projectId>.firebaseapp.com`). */
    authDomain: 'your-project-id.firebaseapp.invalid',
    /** Name of the environment variable from which the MCP process reads the Firebase Web API key (never write the value here). */
    apiKeyEnv: 'SENDTEXTTODOTS_FIREBASE_WEB_API_KEY',
  },
} as const;
