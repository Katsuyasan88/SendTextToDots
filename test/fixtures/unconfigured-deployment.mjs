// 試験専用の合成「未設定」配置設定。配布時のsrc/config/deployment.tsと同じ形・同じ種類のplaceholder（configured: false）で、
// 導入者が実際に編集した設定とは独立に「未設定は拒否」を確かめるために使う（試験は実際の設定・source・distを読まない・書き換えない）。

export const DEPLOYMENT_CONFIG = {
  configured: false,
  projectId: 'your-project-id',
  projectNumber: '0',
  databaseId: '(default)',
  location: 'your-region',
  api: {
    functionName: 'sendtexttodotsapi',
    serviceName: 'sendtexttodotsapi',
    serviceAccount: 'your-api-sa@your-project-id.iam.gserviceaccount.com',
    invoker: 'private',
    publicOrigin: 'https://api.example.invalid',
  },
  connect: {
    serviceName: 'your-connect-service',
    serviceAccount: 'your-connect-sa@your-project-id.iam.gserviceaccount.com',
    publicOrigin: 'https://connect.example.invalid',
    invoker: 'private',
  },
  connectNamespace: 't256_00000000-0000-0000-0000-000000000000',
  deliveryNamespace: 't270_00000000-0000-0000-0000-000000000000',
  kms: {
    environment: 'development',
    projectId: 'your-project-id',
    databaseId: '(default)',
    namespace: 't268_00000000-0000-0000-0000-000000000000',
    cryptoKey: 'projects/your-project-id/locations/your-region/keyRings/your-ring/cryptoKeys/your-key',
    writeVersion: 1,
    readVersions: [1],
  },
  secretVersions: {
    jwks: 'projects/0/secrets/your-jwks/versions/1',
    cookieKeys: 'projects/0/secrets/your-cookie-keys/versions/1',
    identifierKey: 'projects/0/secrets/your-identifier-key/versions/1',
    commandDigestKey: 'projects/0/secrets/your-command-digest-key/versions/1',
  },
  web: {
    projectId: 'your-project-id',
    authDomain: 'your-project-id.firebaseapp.invalid',
    apiKeyEnv: 'SENDTEXTTODOTS_FIREBASE_WEB_API_KEY',
  },
};
