# @cauthyhq/node

Cauthy for Node.js backends: sign-in, cookie sessions, organizations, Pact contract mode and token verification, served as the [auth-bff protocol](https://github.com/vennet-developers/cauthy-sdk-spec) version 1, level `strict`.

The browser never holds a token. Your server mounts one route, keeps the session in an encrypted HttpOnly cookie, and every security setting (sign-in methods, second factors, session length) is a switch in Cauthy's dashboard, not code.

```bash
npm install @cauthyhq/node
```

Node 20 or later. ESM and CommonJS. One dependency: `jose`.

## Five lines

```ts
// auth.ts — reads CAUTHY_ISSUER, CAUTHY_CLIENT_ID, CAUTHY_SECRET, CAUTHY_TENANT, CAUTHY_BASE_URL
import { createCauthy } from '@cauthyhq/node'
export const auth = createCauthy()
```

| Framework | Mount | Check the mount at startup |
| --- | --- | --- |
| Express, plain Node | `app.use(cauthyExpress(auth))` from `@cauthyhq/node/express`, before your body parser | `await auth.checkMount('http://localhost:3000')` after `listen` |
| Hono | `app.use(cauthyHono(auth))` from `@cauthyhq/node/hono` | `await auth.checkMount(app.fetch)` |
| Fastify | `await app.register(cauthyFastify, { auth })` from `@cauthyhq/node/fastify` | Done by the plugin itself when Fastify is ready (`checkMount: false` turns it off); `checkFastifyMount(app, auth)` runs it by hand |
| Next.js | `export const { GET, POST } = cauthyNext(auth)` in `app/api/auth/[...cauthy]/route.ts` | Next refuses two route files for one path at build time |
| Anything with `Request`/`Response` (TanStack Start, Bun, Deno) | `auth.handler(request)` for `/api/auth/*` | `await auth.checkMount(yourFetch)` |

`checkMount` sends three requests that never reach Cauthy and throws when another route answers under `/api/auth` (another auth library's catch-all, a proxy rule).

```ts
const session = await auth.getSession(request, responseHeaders)   // null when nobody is signed in
session?.user.id                                                   // key your rows by this, never by email
await auth.organizations(session)                                  // the person's organizations and roles
```

See [`examples/acme-crm`](examples/acme-crm) for a whole application.

## Verifying a token

```ts
const who = await verifyToken(request, { audience: 'acme-api', tenantId: '<the workspace id>' })   // reads CAUTHY_ISSUER too
```

`verifyToken(request)` checks a Cauthy access token against Cauthy's published keys, by the rules of the spec's [`verification/rules.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/verification/rules.md) (every vector of the spec passes in CI). The error carries a `reason` from the spec's closed list (`expired`, `wrong_audience`, `system_token`, …).

- **The audience and the workspace are required** (`audience` or `CAUTHY_AUDIENCE`, `tenantId` or `CAUTHY_TENANT_ID`, the id as a lowercase UUID). Without them a token issued for another application or workspace would be accepted, so the verifier refuses to be built (`CauthyConfigError`). `createTokenVerifier(options)` builds it once, at startup.
- A system's own token (`sys` claim, whatever its value) and a guest's token (`anon: true`) are refused where a person is expected. Pass `allowSystem` or `allowAnonymous` for an endpoint that takes them.
- Clock tolerance is 30 seconds (`leeway`, 0 to 60). A token over 8192 bytes, with a repeated JSON name, a fractional date or a wrongly typed claim is refused.

## Moving from cauthy-auth

`@cauthyhq/node` 1.0 is the server half of `cauthy-auth` 0.42 with the same options, variables and names. Change the import:

| cauthy-auth 0.42 | @cauthyhq/node 1.0 |
| --- | --- |
| `cauthy-auth` | `@cauthyhq/node` |
| `cauthy-auth/express`, `/fastify`, `/hono`, `/next`, `/mcp`, `/keys`, `/theme` | `@cauthyhq/node/express`, … (same names) |
| `cauthy-auth/react`, `/client`, `/vue`, `/svelte`, `/styles.css` | Keep `cauthy-auth` 0.43 in the browser until `@cauthyhq/js` and `@cauthyhq/react` ship |
| `npx cauthy-auth …` | The `cauthy` CLI |

Five things change:

1. **Every `POST` but `/logout` needs `X-Cauthy-Request: 1`** (`403 csrf_required` otherwise). `cauthy-auth` 0.43's browser client sends it; 0.42's does not. Upgrade the browser package in the same deploy, or pass `requestHeader: 'warn'` for that one deploy. `'warn'` is a migration aid and leaves in 2.0.
2. **Answers carry `Cauthy-Protocol: 1`, `Cache-Control: no-store`, and sign-in answers a `next` step** (`done`, `mfa`, `verify_email`, `code`, `passkey`, `one_tap`, `redirect`). Additions only.
3. **`verifyToken` refuses system and guest tokens since 1.0** (`allowSystem`, `allowAnonymous`), **and needs an audience and a workspace** (`audience`/`CAUTHY_AUDIENCE`, `tenantId`/`CAUTHY_TENANT_ID`): 0.42 skipped those checks when they were not set. It also holds tokens to the spec's stricter shape (see above), and its error's `reason` is a code, not jose's text.
4. **Calls to Cauthy have a deadline** (`timeouts`, below); `pushTheme`, `pushPolicy`, `pullPolicy` and `connectSystem` take `timeoutMs`.
5. **Error messages start with `@cauthyhq/node:`** instead of `cauthy-auth:`. Classes and codes are the same.

`/sign-in/anonymous`, `/me/upgrade` and `connectSystem` are deprecated: one `DeprecationWarning` per process, removed in 2.0.

## Contract mode

With a Pact link, everything comes from the vendored graph and one secret, `PACT_ROOT_KEY`:

```ts
import graph from './contracts/graph.json'
import { postgresKeyStore } from '@cauthyhq/node/keys'
export const auth = createCauthy({ contract: { graph, system: 'acme-crm' }, keys: postgresKeyStore(query) })
```

It refuses to start when any `CAUTHY_*` variable is also set, when the link names its workspace by slug and the graph has no `tenant_id` for it yet, or when the link asks for a system proof without a `service` block. When the link sets `require_verified_email`, a person whose address is not confirmed gets no session (`email_not_confirmed`). See [`contract/pact.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/contract/pact.md).

## Options added in 1.0

| Option | Default | What it does |
| --- | --- | --- |
| `requestHeader` | `'required'` | `'warn'` lets a `POST` without `X-Cauthy-Request` through, saying so once per process |
| `timeouts.system` | `2000` | Deadline in milliseconds of the application's own calls to Cauthy (`auth.system`, the sign-in proof) |
| `timeouts.request` | `5000` | Deadline in milliseconds of the sign-in screens' calls and of the code, refresh and userinfo calls |

## Testing your application

`@cauthyhq/node/testing` is a Cauthy that lives in memory (`FakeCauthy`) and a browser that keeps cookies (`Browser`), for the tests of your own application. **Test-only**: it signs in whoever it was told about and checks nothing a real Cauthy does. Do not import it from production code.

## Conformance

CI runs the auth-bff conformance suite at level `strict` against `examples/acme-crm` on an in-memory Cauthy:

    SPEC_DIR=../cauthy-sdk-spec LEVEL=strict npm run conformance

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).
