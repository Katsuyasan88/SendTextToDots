// SendTextToDotsの配置設定（導入者が配置前にこのfileだけを編集してbuildする唯一の正本）。
// 配布時は未設定（configured: false）で、値は検証を通らない合成placeholder。編集後は全項目が src/config/validate.ts の検証を
// 通らない限り、API・MCPともSDK生成・資格取得・DB・外部HTTPの前に固定errorで起動を拒否する。configuredだけをtrueにしても通らない。
// 実秘密の値（鍵・token・Web API keyの値）はここへ書かない。Secret Managerの版名と、Web API keyを読む環境変数名だけを書く。
// 項目の説明は docs/CONFIGURATION.md。このmoduleはimport・型以外の依存を持たない（data only）。

export const DEPLOYMENT_CONFIG = {
  /** 全項目を自分の値へ置き換えた後にだけtrueにする。 */
  configured: false,
  /** Google Cloud / Firebaseのproject ID（6〜30文字）。 */
  projectId: 'your-project-id',
  /** 同じprojectの数値project number。 */
  projectNumber: '0',
  /** Firestore database ID（通常は`(default)`）。 */
  databaseId: '(default)',
  /** Functions・Cloud Run・KMS key ringの地域（例: `us-central1`）。 */
  location: 'your-region',
  api: {
    /** Functionsのexport名。src/deployment/functions.tsのexport名（`sendtexttodotsapi`）と同じ値だけを受け付ける。 */
    functionName: 'sendtexttodotsapi',
    /** 配置先Cloud Runのservice名（Functions第2世代ではfunctionNameと同じ）。 */
    serviceName: 'sendtexttodotsapi',
    /** API専用のruntime service account。 */
    serviceAccount: 'your-api-sa@your-project-id.iam.gserviceaccount.com',
    /** `private`だけ（公開の入口は配置側のIAMで別に付与する）。 */
    invoker: 'private',
    /** /consoleのbrowserが直接送るAPIの公開origin（`https://<host>`、末尾slashなし）。 */
    publicOrigin: 'https://api.example.invalid',
  },
  connect: {
    /** MCP/OAuth・接続WebのCloud Run service名。 */
    serviceName: 'your-connect-service',
    /** MCP専用のruntime service account（APIと別）。 */
    serviceAccount: 'your-connect-sa@your-project-id.iam.gserviceaccount.com',
    /** MCPの公開origin（OAuth issuer）。 */
    publicOrigin: 'https://connect.example.invalid',
    invoker: 'private',
  },
  /** 接続保存のnamespace（`t256_<小文字UUID v1〜v8>`）。導入時に一度だけ生成し、以後変えない。 */
  connectNamespace: 't256_00000000-0000-0000-0000-000000000000',
  /** 配送保存のnamespace（`t270_<小文字UUID>`）。 */
  deliveryNamespace: 't270_00000000-0000-0000-0000-000000000000',
  kms: {
    /** 保存形式の環境名。`development`だけ（既存の保存形式と互換）。 */
    environment: 'development',
    /** projectIdと同じ値。 */
    projectId: 'your-project-id',
    /** databaseIdと同じ値。 */
    databaseId: '(default)',
    /** KMS購読のnamespace（`t268_<小文字UUID>`）。 */
    namespace: 't268_00000000-0000-0000-0000-000000000000',
    /** `projects/<projectId>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>` */
    cryptoKey: 'projects/your-project-id/locations/your-region/keyRings/your-ring/cryptoKeys/your-key',
    /** 封緘に使う数値版。 */
    writeVersion: 1,
    /** 開封を許す数値版（writeVersionを含む）。 */
    readVersions: [1],
  },
  /** 用途ごとに別のSecret Manager secretの固定数値版（`projects/<projectNumber>/secrets/<id>/versions/<N>`）。 */
  secretVersions: {
    jwks: 'projects/0/secrets/your-jwks/versions/1',
    cookieKeys: 'projects/0/secrets/your-cookie-keys/versions/1',
    identifierKey: 'projects/0/secrets/your-identifier-key/versions/1',
    commandDigestKey: 'projects/0/secrets/your-command-digest-key/versions/1',
  },
  web: {
    /** Firebase Web設定のprojectId（projectIdと同じ値）。 */
    projectId: 'your-project-id',
    /** Firebase Web設定のauthDomain（例: `<projectId>.firebaseapp.com`）。 */
    authDomain: 'your-project-id.firebaseapp.invalid',
    /** MCP processでFirebase Web API keyを読む環境変数名（値はここへ書かない）。 */
    apiKeyEnv: 'SENDTEXTTODOTS_FIREBASE_WEB_API_KEY',
  },
} as const;
