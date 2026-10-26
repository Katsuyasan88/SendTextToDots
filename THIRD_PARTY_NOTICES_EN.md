# Third-party notices

English | [日本語](THIRD_PARTY_NOTICES.md)

Apart from SendTextToDots' own source (MIT in `LICENSE`), the following third-party material is used. The copyrights and licenses of third parties belong to their respective holders and are not replaced by MIT.

## 1. npm packages (fixed lock)

This repository does not include `node_modules`. `npm ci` obtains the fixed versions and integrity values of `package-lock.json` from the npm registry, and the license text, copyright notices and NOTICE files of each package are inside the obtained packages. The output of `npm run package` (`api.zip`, `mcp.tar.gz`) also contains no `node_modules`; the deployment-side build obtains them from the same lock.

License breakdown of all 333 packages in the lock (runtime, dev and optional; optional packages may not be obtained depending on the environment): MIT 219, Apache-2.0 76, ISC 18, BSD-3-Clause 12, BlueOak-1.0.0 6, 0BSD 1, Unlicense 1. All are permissive licenses that allow use, modification and redistribution.

- `limiter` 1.1.5 (a dependency of `jwks-rsa`) has no license field in the lock; it was confirmed from the legacy `licenses` field (MIT) in the package and `LICENSE.txt` (MIT, Copyright (C) 2011 by John Hurliman).
- Among the obtained packages, the ones with an Apache-2.0 NOTICE file were `typescript` and `@typescript/typescript-<platform>` (all dev dependencies for the build).
- Checked: 2026-10-23 (lock metadata and the `package.json` of each package in `node_modules` obtained on Windows x64).

## 2. Scripts loaded by the browser (not bundled)

| Material | Loaded from | License and conditions |
| --- | --- | --- |
| Firebase JavaScript SDK 13.0.0 (`firebase-app.js`, `firebase-auth.js`) | `https://www.gstatic.com/firebasejs/13.0.0/` | Apache-2.0 (Firebase JS SDK). Distribution and use follow the Google/Firebase terms |
| Google API loader (`api.js`, loaded by the popup path of Firebase Auth) | `https://apis.google.com/js/api.js` | A script distributed by Google. Use follows the Google terms |

## 3. Reference data

| Material | Source | License |
| --- | --- | --- |
| `references/iana_*_20261006.csv` (IPv4/IPv6 special-purpose, IPv6 address space) | IANA Protocol Registries (retrieved 2026-10-06; details in `references/README_EN.md`) | CC0 1.0 (no attribution requirement). Basis: https://www.iana.org/help/licensing-terms (checked 2026-10-23) |

## 4. External services

Google Cloud (Functions, Cloud Run, Firestore, Cloud KMS, Secret Manager, Cloud Build), Firebase Authentication, Sign in with Apple and the receiving side (for example the ChatGPT connector) follow the terms and prices of their respective providers. The MIT license of this source does not grant the right to use them.

## 5. Package list

The columns are package, version, license, kind (runtime / dev / optional) and the source of confirmation (the lock file, or the package.json of the package for the legacy `licenses` field). The rows are identical to the Japanese notice.

| package | version | license | kind | confirmed from |
| --- | --- | --- | --- | --- |
| @fastify/busboy | 3.2.3 | MIT | runtime | lock |
| @firebase/app-check-interop-types | 0.3.5 | Apache-2.0 | runtime | lock |
| @firebase/app-types | 0.9.6 | Apache-2.0 | runtime | lock |
| @firebase/auth-interop-types | 0.2.6 | Apache-2.0 | runtime | lock |
| @firebase/component | 0.7.5 | Apache-2.0 | runtime | lock |
| @firebase/database | 1.1.5 | Apache-2.0 | runtime | lock |
| @firebase/database-compat | 2.1.7 | Apache-2.0 | runtime | lock |
| @firebase/database-types | 1.0.22 | Apache-2.0 | runtime | lock |
| @firebase/logger | 0.5.2 | Apache-2.0 | runtime | lock |
| @firebase/util | 1.15.3 | Apache-2.0 | runtime | lock |
| @google-cloud/firestore | 8.3.0 | Apache-2.0 | runtime | lock |
| @google-cloud/firestore | 9.3.1 | Apache-2.0 | optional | lock |
| @google-cloud/firestore-api | 0.2.0 | Apache-2.0 | optional | lock |
| @google-cloud/kms | 6.3.0 | Apache-2.0 | runtime | lock |
| @google-cloud/paginator | 7.2.0 | Apache-2.0 | optional | lock |
| @google-cloud/projectify | 6.2.0 | Apache-2.0 | optional | lock |
| @google-cloud/promisify | 6.2.0 | Apache-2.0 | optional | lock |
| @google-cloud/secret-manager | 7.2.0 | Apache-2.0 | runtime | lock |
| @google-cloud/storage | 8.4.0 | Apache-2.0 | optional | lock |
| @grpc/grpc-js | 1.14.5 | Apache-2.0 | runtime | lock |
| @grpc/proto-loader | 0.8.1 | Apache-2.0 | runtime | lock |
| @hono/node-server | 1.19.17 | MIT | runtime | lock |
| @isaacs/cliui | 8.0.2 | ISC | runtime | lock |
| @js-sdsl/ordered-map | 4.4.2 | MIT | runtime | lock |
| @modelcontextprotocol/core | 2.3.1 | Apache-2.0 | runtime | lock |
| @modelcontextprotocol/node | 2.1.1 | Apache-2.0 | runtime | lock |
| @modelcontextprotocol/server | 2.3.1 | Apache-2.0 | runtime | lock |
| @nodable/entities | 3.1.0 | MIT | optional | lock |
| @opentelemetry/api | 1.9.1 | Apache-2.0 | runtime | lock |
| @pkgjs/parseargs | 0.11.0 | MIT | optional | lock |
| @protobufjs/aspromise | 1.1.2 | BSD-3-Clause | runtime | lock |
| @protobufjs/base64 | 1.1.2 | BSD-3-Clause | runtime | lock |
| @protobufjs/codegen | 2.0.5 | BSD-3-Clause | runtime | lock |
| @protobufjs/eventemitter | 1.1.1 | BSD-3-Clause | runtime | lock |
| @protobufjs/fetch | 1.1.1 | BSD-3-Clause | runtime | lock |
| @protobufjs/float | 1.0.2 | BSD-3-Clause | runtime | lock |
| @protobufjs/path | 1.1.2 | BSD-3-Clause | runtime | lock |
| @protobufjs/pool | 1.1.0 | BSD-3-Clause | runtime | lock |
| @protobufjs/utf8 | 1.1.2 | BSD-3-Clause | runtime | lock |
| @stablelib/base64 | 1.0.1 | MIT | runtime | lock |
| @types/accepts | 1.3.7 | MIT | dev | lock |
| @types/body-parser | 1.19.6 | MIT | runtime | lock |
| @types/connect | 3.4.38 | MIT | runtime | lock |
| @types/content-disposition | 0.5.9 | MIT | dev | lock |
| @types/cookies | 0.9.2 | MIT | dev | lock |
| @types/cors | 2.8.19 | MIT | runtime | lock |
| @types/express | 5.0.6 | MIT | runtime | lock |
| @types/express-serve-static-core | 5.1.3 | MIT | runtime | lock |
| @types/http-assert | 1.5.6 | MIT | dev | lock |
| @types/http-errors | 2.0.5 | MIT | runtime | lock |
| @types/jsonwebtoken | 9.0.10 | MIT | runtime | lock |
| @types/keygrip | 1.0.6 | MIT | dev | lock |
| @types/koa | 3.0.3 | MIT | dev | lock |
| @types/koa-compose | 3.2.9 | MIT | dev | lock |
| @types/ms | 2.1.0 | MIT | runtime | lock |
| @types/node | 22.18.6 | MIT | runtime | lock |
| @types/oidc-provider | 9.12.1 | MIT | dev | lock |
| @types/qs | 6.15.1 | MIT | runtime | lock |
| @types/range-parser | 1.2.7 | MIT | runtime | lock |
| @types/send | 1.2.1 | MIT | runtime | lock |
| @types/serve-static | 2.2.0 | MIT | runtime | lock |
| @typescript/typescript-aix-ppc64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-darwin-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-darwin-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-freebsd-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-freebsd-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-arm | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-loong64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-mips64el | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-ppc64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-riscv64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-s390x | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-linux-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-netbsd-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-netbsd-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-openbsd-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-openbsd-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-sunos-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-win32-arm64 | 7.0.2 | Apache-2.0 | dev | lock |
| @typescript/typescript-win32-x64 | 7.0.2 | Apache-2.0 | dev | lock |
| abort-controller | 3.0.0 | MIT | optional | lock |
| accepts | 1.3.8 | MIT | runtime | lock |
| accepts | 2.0.0 | MIT | runtime | lock |
| agent-base | 7.1.4 | MIT | runtime | lock |
| ansi-regex | 5.0.1 | MIT | runtime | lock |
| ansi-regex | 5.0.1 | MIT | runtime | lock |
| ansi-regex | 5.0.1 | MIT | runtime | lock |
| ansi-regex | 5.0.1 | MIT | runtime | lock |
| ansi-regex | 5.0.1 | MIT | runtime | lock |
| ansi-regex | 6.4.0 | MIT | runtime | lock |
| ansi-styles | 4.3.0 | MIT | runtime | lock |
| ansi-styles | 4.3.0 | MIT | runtime | lock |
| ansi-styles | 6.2.3 | MIT | runtime | lock |
| anynum | 1.0.1 | MIT | optional | lock |
| async-retry | 1.3.3 | MIT | optional | lock |
| balanced-match | 1.0.2 | MIT | runtime | lock |
| base64-js | 1.5.1 | MIT | runtime | lock |
| bignumber.js | 9.3.1 | MIT | runtime | lock |
| body-parser | 2.4.0 | MIT | runtime | lock |
| brace-expansion | 2.1.7 | MIT | runtime | lock |
| buffer-equal-constant-time | 1.0.1 | BSD-3-Clause | runtime | lock |
| bytes | 3.1.2 | MIT | runtime | lock |
| call-bind-apply-helpers | 1.0.2 | MIT | runtime | lock |
| call-bound | 1.0.4 | MIT | runtime | lock |
| cliui | 8.0.1 | ISC | runtime | lock |
| color-convert | 2.0.1 | MIT | runtime | lock |
| color-name | 1.1.4 | MIT | runtime | lock |
| content-disposition | 1.0.1 | MIT | runtime | lock |
| content-disposition | 2.0.1 | MIT | runtime | lock |
| content-type | 1.0.5 | MIT | runtime | lock |
| content-type | 2.1.0 | MIT | runtime | lock |
| content-type | 2.1.0 | MIT | runtime | lock |
| content-type | 2.1.0 | MIT | runtime | lock |
| cookie | 0.7.2 | MIT | runtime | lock |
| cookie-signature | 1.2.2 | MIT | runtime | lock |
| cookies | 0.9.2 | MIT | runtime | lock |
| cors | 2.8.6 | MIT | runtime | lock |
| cross-spawn | 7.0.6 | MIT | runtime | lock |
| data-uri-to-buffer | 4.0.1 | MIT | runtime | lock |
| debug | 4.4.3 | MIT | runtime | lock |
| deep-equal | 1.0.1 | MIT | runtime | lock |
| delegates | 1.0.0 | MIT | runtime | lock |
| depd | 1.1.2 | MIT | runtime | lock |
| depd | 2.0.0 | MIT | runtime | lock |
| destroy | 1.2.0 | MIT | runtime | lock |
| dunder-proto | 1.0.1 | MIT | runtime | lock |
| duplexify | 4.1.3 | MIT | runtime | lock |
| eastasianwidth | 0.2.0 | MIT | runtime | lock |
| ecdsa-sig-formatter | 1.0.11 | Apache-2.0 | runtime | lock |
| ee-first | 1.1.1 | MIT | runtime | lock |
| emoji-regex | 8.0.0 | MIT | runtime | lock |
| emoji-regex | 8.0.0 | MIT | runtime | lock |
| emoji-regex | 8.0.0 | MIT | runtime | lock |
| emoji-regex | 8.0.0 | MIT | runtime | lock |
| emoji-regex | 9.2.2 | MIT | runtime | lock |
| encodeurl | 2.0.0 | MIT | runtime | lock |
| end-of-stream | 1.4.5 | MIT | runtime | lock |
| es-define-property | 1.0.1 | MIT | runtime | lock |
| es-errors | 1.3.0 | MIT | runtime | lock |
| es-object-atoms | 1.1.2 | MIT | runtime | lock |
| escalade | 3.2.0 | MIT | runtime | lock |
| escape-html | 1.0.3 | MIT | runtime | lock |
| etag | 1.8.1 | MIT | runtime | lock |
| event-target-shim | 5.0.1 | MIT | optional | lock |
| express | 5.3.0 | MIT | runtime | lock |
| extend | 3.0.2 | MIT | runtime | lock |
| fast-deep-equal | 3.1.3 | MIT | runtime | lock |
| fast-sha256 | 1.3.0 | Unlicense | runtime | lock |
| fast-xml-builder | 1.3.1 | MIT | optional | lock |
| fast-xml-parser | 5.11.2 | MIT | optional | lock |
| faye-websocket | 0.11.4 | Apache-2.0 | runtime | lock |
| fetch-blob | 3.2.0 | MIT | runtime | lock |
| finalhandler | 2.1.1 | MIT | runtime | lock |
| firebase-admin | 14.5.0 | Apache-2.0 | runtime | lock |
| firebase-functions | 7.4.0 | MIT | runtime | lock |
| foreground-child | 3.3.1 | ISC | runtime | lock |
| formdata-polyfill | 4.0.10 | MIT | runtime | lock |
| forwarded | 0.2.0 | MIT | runtime | lock |
| fresh | 0.5.2 | MIT | runtime | lock |
| fresh | 2.0.0 | MIT | runtime | lock |
| fresh | 2.0.0 | MIT | runtime | lock |
| function-bind | 1.1.2 | MIT | runtime | lock |
| functional-red-black-tree | 1.0.1 | MIT | runtime | lock |
| gaxios | 7.1.3 | Apache-2.0 | optional | lock |
| gaxios | 7.1.3 | Apache-2.0 | runtime | lock |
| gaxios | 7.3.1 | Apache-2.0 | optional | lock |
| gaxios | 7.3.1 | Apache-2.0 | runtime | lock |
| gaxios | 7.3.1 | Apache-2.0 | runtime | lock |
| gaxios | 8.3.1 | Apache-2.0 | runtime | lock |
| gaxios | 8.3.1 | Apache-2.0 | runtime | lock |
| gcp-metadata | 8.1.4 | Apache-2.0 | optional | lock |
| gcp-metadata | 8.1.4 | Apache-2.0 | runtime | lock |
| gcp-metadata | 9.2.1 | Apache-2.0 | runtime | lock |
| get-caller-file | 2.0.5 | ISC | runtime | lock |
| get-intrinsic | 1.3.0 | MIT | runtime | lock |
| get-proto | 1.0.1 | MIT | runtime | lock |
| glob | 10.5.0 | ISC | runtime | lock |
| google-auth-library | 10.5.0 | Apache-2.0 | optional | lock |
| google-auth-library | 10.5.0 | Apache-2.0 | runtime | lock |
| google-auth-library | 11.3.1 | Apache-2.0 | runtime | lock |
| google-gax | 5.0.8 | Apache-2.0 | optional | lock |
| google-gax | 5.0.8 | Apache-2.0 | runtime | lock |
| google-gax | 6.12.1 | Apache-2.0 | optional | lock |
| google-gax | 6.5.0 | Apache-2.0 | runtime | lock |
| google-logging-utils | 1.1.3 | Apache-2.0 | optional | lock |
| google-logging-utils | 1.1.3 | Apache-2.0 | runtime | lock |
| google-logging-utils | 2.1.0 | Apache-2.0 | runtime | lock |
| gopd | 1.2.0 | MIT | runtime | lock |
| gtoken | 8.0.0 | MIT | runtime | lock |
| has-symbols | 1.1.0 | MIT | runtime | lock |
| hasown | 2.0.4 | MIT | runtime | lock |
| hono | 4.13.13 | MIT | runtime | lock |
| html-entities | 2.6.0 | MIT | optional | lock |
| http-assert | 1.5.0 | MIT | runtime | lock |
| http-errors | 1.8.1 | MIT | runtime | lock |
| http-errors | 2.0.1 | MIT | runtime | lock |
| http-parser-js | 0.5.10 | MIT | runtime | lock |
| http-proxy-agent | 7.0.2 | MIT | runtime | lock |
| https-proxy-agent | 7.0.6 | MIT | runtime | lock |
| iconv-lite | 0.7.3 | MIT | runtime | lock |
| inherits | 2.0.4 | ISC | runtime | lock |
| ipaddr.js | 1.9.1 | MIT | runtime | lock |
| is-fullwidth-code-point | 3.0.0 | MIT | runtime | lock |
| is-promise | 4.0.0 | MIT | runtime | lock |
| is-unsafe | 2.0.2 | MIT | optional | lock |
| isexe | 2.0.0 | ISC | runtime | lock |
| jackspeak | 3.4.3 | BlueOak-1.0.0 | runtime | lock |
| jose | 6.2.12 | MIT | runtime | lock |
| json-bigint | 1.0.0 | MIT | runtime | lock |
| jsonwebtoken | 9.0.3 | MIT | runtime | lock |
| jwa | 2.0.1 | MIT | runtime | lock |
| jwks-rsa | 4.1.0 | MIT | runtime | lock |
| jws | 4.0.1 | MIT | runtime | lock |
| keygrip | 1.1.0 | MIT | runtime | lock |
| koa | 3.2.1 | MIT | runtime | lock |
| koa-compose | 4.1.0 | MIT | runtime | lock |
| limiter | 1.1.5 | MIT | runtime | package.json (legacy "licenses") |
| lodash.camelcase | 4.3.0 | MIT | runtime | lock |
| lodash.clonedeep | 4.5.0 | MIT | runtime | lock |
| lodash.includes | 4.3.0 | MIT | runtime | lock |
| lodash.isboolean | 3.0.3 | MIT | runtime | lock |
| lodash.isinteger | 4.0.4 | MIT | runtime | lock |
| lodash.isnumber | 3.0.3 | MIT | runtime | lock |
| lodash.isplainobject | 4.0.6 | MIT | runtime | lock |
| lodash.isstring | 4.0.1 | MIT | runtime | lock |
| lodash.once | 4.1.1 | MIT | runtime | lock |
| long | 5.3.2 | Apache-2.0 | runtime | lock |
| lru-cache | 10.4.3 | ISC | runtime | lock |
| lru-cache | 11.5.3 | BlueOak-1.0.0 | runtime | lock |
| lru-cache | 11.5.3 | BlueOak-1.0.0 | runtime | lock |
| lru-memoizer | 3.0.0 | MIT | runtime | lock |
| math-intrinsics | 1.1.0 | MIT | runtime | lock |
| media-typer | 1.1.1 | MIT | runtime | lock |
| merge-descriptors | 2.0.0 | MIT | runtime | lock |
| mime | 3.0.0 | MIT | optional | lock |
| mime-db | 1.52.0 | MIT | runtime | lock |
| mime-db | 1.54.0 | MIT | runtime | lock |
| mime-types | 2.1.35 | MIT | runtime | lock |
| mime-types | 3.0.2 | MIT | runtime | lock |
| minimatch | 9.0.9 | ISC | runtime | lock |
| minipass | 7.1.3 | BlueOak-1.0.0 | runtime | lock |
| ms | 2.1.3 | MIT | runtime | lock |
| negotiator | 0.6.3 | MIT | runtime | lock |
| negotiator | 1.1.0 | MIT | runtime | lock |
| node-domexception | 1.0.0 | MIT | runtime | lock |
| node-fetch | 3.3.2 | MIT | runtime | lock |
| object-assign | 4.1.1 | MIT | runtime | lock |
| object-hash | 3.0.0 | MIT | runtime | lock |
| object-inspect | 1.13.4 | MIT | runtime | lock |
| oidc-provider | 9.12.2 | MIT | runtime | lock |
| on-finished | 2.4.1 | MIT | runtime | lock |
| once | 1.4.0 | ISC | runtime | lock |
| p-limit | 3.1.0 | MIT | optional | lock |
| package-json-from-dist | 1.0.1 | BlueOak-1.0.0 | runtime | lock |
| parseurl | 1.3.3 | MIT | runtime | lock |
| path-expression-matcher | 1.6.2 | MIT | optional | lock |
| path-key | 3.1.1 | MIT | runtime | lock |
| path-scurry | 1.11.1 | BlueOak-1.0.0 | runtime | lock |
| path-to-regexp | 8.4.2 | MIT | runtime | lock |
| proto3-json-serializer | 3.0.4 | Apache-2.0 | optional | lock |
| proto3-json-serializer | 3.0.4 | Apache-2.0 | runtime | lock |
| proto3-json-serializer | 4.1.0 | Apache-2.0 | runtime | lock |
| protobufjs | 7.6.6 | BSD-3-Clause | runtime | lock |
| proxy-addr | 2.0.8 | MIT | runtime | lock |
| qs | 6.16.1 | BSD-3-Clause | runtime | lock |
| range-parser | 1.3.0 | MIT | runtime | lock |
| raw-body | 3.0.2 | MIT | runtime | lock |
| readable-stream | 3.6.2 | MIT | runtime | lock |
| require-directory | 2.1.1 | MIT | runtime | lock |
| retry | 0.13.1 | MIT | optional | lock |
| retry-request | 8.0.4 | MIT | optional | lock |
| retry-request | 8.0.4 | MIT | runtime | lock |
| retry-request | 9.1.0 | MIT | runtime | lock |
| rimraf | 5.0.10 | ISC | runtime | lock |
| router | 2.2.0 | MIT | runtime | lock |
| safe-buffer | 5.2.1 | MIT | runtime | lock |
| safer-buffer | 2.1.2 | MIT | runtime | lock |
| semver | 7.8.5 | ISC | runtime | lock |
| send | 1.2.1 | MIT | runtime | lock |
| serve-static | 2.2.1 | MIT | runtime | lock |
| setprototypeof | 1.2.0 | ISC | runtime | lock |
| shebang-command | 2.0.0 | MIT | runtime | lock |
| shebang-regex | 3.0.0 | MIT | runtime | lock |
| side-channel | 1.1.1 | MIT | runtime | lock |
| side-channel-list | 1.0.1 | MIT | runtime | lock |
| side-channel-map | 1.0.1 | MIT | runtime | lock |
| side-channel-weakmap | 1.0.2 | MIT | runtime | lock |
| signal-exit | 4.1.0 | ISC | runtime | lock |
| standardwebhooks | 1.1.1 | MIT | runtime | lock |
| statuses | 1.5.0 | MIT | runtime | lock |
| statuses | 2.0.2 | MIT | runtime | lock |
| stream-events | 1.0.5 | MIT | runtime | lock |
| stream-shift | 1.0.3 | MIT | runtime | lock |
| string-width | 4.2.3 | MIT | runtime | lock |
| string-width | 4.2.3 | MIT | runtime | lock |
| string-width | 4.2.3 | MIT | runtime | lock |
| string-width | 5.1.2 | MIT | runtime | lock |
| string-width-cjs | 4.2.3 | MIT | runtime | lock |
| string_decoder | 1.3.0 | MIT | runtime | lock |
| strip-ansi | 6.0.1 | MIT | runtime | lock |
| strip-ansi | 6.0.1 | MIT | runtime | lock |
| strip-ansi | 6.0.1 | MIT | runtime | lock |
| strip-ansi | 6.0.1 | MIT | runtime | lock |
| strip-ansi | 7.2.0 | MIT | runtime | lock |
| strip-ansi-cjs | 6.0.1 | MIT | runtime | lock |
| strnum | 2.5.1 | MIT | optional | lock |
| stubs | 3.0.0 | MIT | runtime | lock |
| teeny-request | 10.1.4 | Apache-2.0 | runtime | lock |
| teeny-request | 11.1.1 | Apache-2.0 | optional | lock |
| toidentifier | 1.0.1 | MIT | runtime | lock |
| tslib | 2.8.1 | 0BSD | runtime | lock |
| tsscmp | 1.0.6 | MIT | runtime | lock |
| type-is | 2.1.0 | MIT | runtime | lock |
| typescript | 7.0.2 | Apache-2.0 | dev | lock |
| undici-types | 6.21.0 | MIT | runtime | lock |
| unpipe | 1.0.0 | MIT | runtime | lock |
| util-deprecate | 1.0.2 | MIT | runtime | lock |
| vary | 1.1.2 | MIT | runtime | lock |
| web-streams-polyfill | 3.3.3 | MIT | runtime | lock |
| websocket-driver | 0.7.5 | Apache-2.0 | runtime | lock |
| websocket-extensions | 0.1.4 | Apache-2.0 | runtime | lock |
| which | 2.0.2 | ISC | runtime | lock |
| wrap-ansi | 7.0.0 | MIT | runtime | lock |
| wrap-ansi | 8.1.0 | MIT | runtime | lock |
| wrap-ansi-cjs | 7.0.0 | MIT | runtime | lock |
| wrappy | 1.0.2 | ISC | runtime | lock |
| xml-naming | 0.3.0 | MIT | optional | lock |
| y18n | 5.0.8 | ISC | runtime | lock |
| yargs | 17.7.3 | MIT | runtime | lock |
| yargs-parser | 21.1.1 | ISC | runtime | lock |
| yocto-queue | 0.1.0 | MIT | optional | lock |
| zod | 4.6.7 | MIT | runtime | lock |
