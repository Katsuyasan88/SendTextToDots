// 試験専用の合成配置設定（scripts/run-tests.mjsが一時copyのdist/config/deployment.jsへ置く）。実在のproject・資源・秘密ではない。
// 形式は src/config/deployment.ts と同じ（validateDeploymentConfigを通る値）。

export const DEPLOYMENT_CONFIG = {
  configured: true,
  accessPolicy: 'explicit-allow-v1',
  projectId: 'sendtexttodots-test',
  projectNumber: '123456789012',
  databaseId: '(default)',
  location: 'europe-west1',
  api: {
    functionName: 'sendtexttodotsapi',
    serviceName: 'sendtexttodotsapi',
    serviceAccount: 'api-runtime@sendtexttodots-test.iam.gserviceaccount.com',
    invoker: 'private',
    publicOrigin: 'https://sendtexttodotsapi-123456789012.europe-west1.run.app',
  },
  connect: {
    serviceName: 'sendtexttodots-connect',
    serviceAccount: 'connect-runtime@sendtexttodots-test.iam.gserviceaccount.com',
    publicOrigin: 'https://sendtexttodots-connect-123456789012.europe-west1.run.app',
    invoker: 'private',
  },
  connectNamespace: 't256_3f6c2a1e-8d4b-4c7a-9e2f-1b5d7c9a0e34',
  deliveryNamespace: 't270_7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d',
  kms: {
    environment: 'development',
    projectId: 'sendtexttodots-test',
    databaseId: '(default)',
    namespace: 't268_c4d5e6f7-a8b9-4c0d-9e1f-2a3b4c5d6e7f',
    cryptoKey: 'projects/sendtexttodots-test/locations/europe-west1/keyRings/sendtexttodots/cryptoKeys/connect-seal',
    writeVersion: 1,
    readVersions: [1],
  },
  secretVersions: {
    jwks: 'projects/123456789012/secrets/stt-jwks/versions/1',
    cookieKeys: 'projects/123456789012/secrets/stt-cookie-keys/versions/1',
    identifierKey: 'projects/123456789012/secrets/stt-identifier-key/versions/1',
    commandDigestKey: 'projects/123456789012/secrets/stt-command-digest-key/versions/1',
  },
  web: {
    projectId: 'sendtexttodots-test',
    authDomain: 'sendtexttodots-test.firebaseapp.com',
    apiKeyEnv: 'SENDTEXTTODOTS_FIREBASE_WEB_API_KEY',
  },
};
