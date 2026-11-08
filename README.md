# @cauthyhq/node

Cauthy for Node.js backends: sign-in, cookie sessions, organizations, Pact contract mode and token verification, served as the [auth-bff protocol](https://github.com/vennet-developers/cauthy-sdk-spec) version 1, level `strict`.

The browser never holds a token. Your server mounts one route, keeps the session in an encrypted HttpOnly cookie, and every security setting (sign-in methods, second factors, session length) is a switch in Cauthy's dashboard, not code.

```bash
npm install @cauthyhq/node
```

Node 20 or later. ESM and CommonJS. One dependency: `jose`.

## The five-minute path

**1. Register the application in Cauthy's dashboard** (Applications, New application) and add this redirect URI: `${CAUTHY_BASE_URL}/api/auth/callback`, e.g. `http://localhost:3000/api/auth/callback`. The dashboard shows the client id.

**2. Set the environment** (the CLI that writes this for you, `cauthy init`, is coming; until then it is five variables):

| Variable | Where it comes from |
| --- | --- |
| `CAUTHY_ISSUER` | Your Cauthy's address, e.g. `https://id.example.com` |
| `CAUTHY_CLIENT_ID` | The client id the dashboard showed in step 1 |
| `CAUTHY_CLIENT_SECRET` | Only if you registered the application as a confidential client in the dashboard: the client secret it showed once. Public clients need none, and neither does contract mode |
| `CAUTHY_SECRET` | You make it: `openssl rand -base64 32`. It encrypts the session cookie; keep it out of git |
| `CAUTHY_TENANT` | Your workspace's slug in Cauthy, e.g. `acme`, for the sign-in screens your application draws itself |
| `CAUTHY_BASE_URL` | Your application's public address, e.g. `http://localhost:3000` |

**3. Create it and mount it.**

```ts
// auth.ts
import { createCauthy } from '@cauthyhq/node'
export const auth = createCauthy()   // reads the variables above
```

```ts
// server.ts (Express)
import express from 'express'
import { cauthyExpress, requireSession } from '@cauthyhq/node/express'
import { auth } from './auth'

const app = express()
app.use(cauthyExpress(auth))      // before your body parser
app.use(express.json())

app.get('/api/me', requireSession, async (req, res) => {
  const session = await req.cauthy()
  res.json({ id: session!.user.id, email: session!.user.email })   // key your rows by id, never by email
})

const server = app.listen(3000, () => {
  auth.checkMount('http://localhost:3000').catch((err) => { console.error(err.message); server.close() })
})
```

**4. Link to it.** Send people to `/api/auth/login?return_to=/dashboard` to sign in and to `/api/auth/logout` to sign out (or `POST /api/auth/logout` from a form).

**5. Guard a page that is not an API.** `protect()` answers a page with a redirect to sign in and anything else with a 401:

```ts
const { session, response } = await auth.protect(request)
if (response) return response          // not signed in: the redirect or the 401
console.log(session.user.id)
```

| Framework | Mount | Check the mount at startup |
| --- | --- | --- |
| Express, plain Node | `app.use(cauthyExpress(auth))` from `@cauthyhq/node/express`, before your body parser | `await auth.checkMount('http://localhost:3000')` after `listen` |
| Hono | `app.use(cauthyHono(auth))` from `@cauthyhq/node/hono` | `await auth.checkMount(app.fetch)` |
| Fastify | `await app.register(cauthyFastify, { auth })` from `@cauthyhq/node/fastify` | Done by the plugin itself when Fastify is ready (`checkMount: false` turns it off; skipped when `NODE_ENV=test`); `checkFastifyMount(app, auth)` runs it by hand |
| Next.js | `export const { GET, POST } = cauthyNext(auth)` in `app/api/auth/[...cauthy]/route.ts` | Next refuses two route files for one path at build time |
| Anything with `Request`/`Response` (TanStack Start, Bun, Deno) | `auth.handler(request)` for `/api/auth/*` | `await auth.checkMount(yourFetch)` |

`checkMount` sends three requests that never reach Cauthy and throws when another route answers under `/api/auth` (another auth library's catch-all, a proxy rule), when the mount redirects, or when the handler crashes.

```ts
const session = await auth.getSession(request, responseHeaders)   // null when nobody is signed in
await auth.organizations(session)                                  // the person's organizations and roles
```

See [`examples/acme-crm`](examples/acme-crm) for a whole application.

## Verifying a token

For an API that receives Cauthy access tokens from somewhere other than the browser's cookie:

```ts
import { auth } from './auth'

// Where each value comes from:
//   issuer   the instance's own (CAUTHY_ISSUER, or the contract)
//   tenantId by contract, the link's tenant_id; otherwise the `tenantId` option or CAUTHY_TENANT_ID
//   audience the `audience` option or CAUTHY_AUDIENCE: your Cauthy's JWT_AUDIENCE (Cauthy has no default for it)
const verify = auth.tokenVerifier()          // throws CauthyConfigError now if one is missing
const who = await verify(request)            // or: await auth.verifyToken(request)
```

Standalone, with no instance, everything is explicit:

```ts
import { createTokenVerifier } from '@cauthyhq/node'
const verify = createTokenVerifier({ issuer: 'https://id.example.com', audience: 'cauthy', tenantId: '<the workspace id>' })
```

`createTokenVerifier` checks its configuration when it is built (startup); `verifyToken(request, options)` does the same on each call, as a rejected promise. Both follow the spec's [`verification/rules.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/verification/rules.md); every vector of the spec passes in CI. The error carries a `reason` from the spec's closed list (`expired`, `wrong_audience`, `system_token`, …). If Cauthy's keys cannot be fetched you get `CauthyUnavailableError` (answer 503), which says nothing about the token.

- **The audience and the workspace are required.** Without them a token issued for another application or workspace would be accepted.
- A system's own token (`sys` claim, whatever its value) and a guest's token (`anon: true`) are refused where a person is expected. Pass `allowSystem` or `allowAnonymous` for an endpoint that takes them.
- A client's own token (a `client_credentials` grant: `token_use: "client"`, whatever the value) is refused with `client_token` where a person is expected. A backend that serves machines too passes `allowClientTokens: true`; the identity then carries `clientId`, the client's public id (its `userId` is the client's internal id).
- `authorizedParty` is the token's `azp`: the client a person's token was issued through, absent when none was named.
- Clock tolerance is 30 seconds (`leeway`, 0 to 60). A token over 8192 bytes, with a repeated JSON name, a fractional date or a wrongly typed claim is refused.
- Keys are fetched from `<issuer>/.well-known/jwks.json` with no redirect, within 5 seconds, at most 64 KiB, and kept for the answer's `max-age`.

## Moving from cauthy-auth

`@cauthyhq/node` 1.0 is the server half of `cauthy-auth` 0.42 with the same options, variables and names. Change the import:

| cauthy-auth 0.42 | @cauthyhq/node 1.0 |
| --- | --- |
| `cauthy-auth` | `@cauthyhq/node` |
| `cauthy-auth/express`, `/fastify`, `/hono`, `/next`, `/mcp`, `/keys`, `/theme` | `@cauthyhq/node/express`, … (same names) |
| `cauthy-auth/react`, `/client`, `/vue`, `/svelte`, `/styles.css` | Keep `cauthy-auth` 0.43 in the browser until `@cauthyhq/js` and `@cauthyhq/react` ship |
| `npx cauthy-auth …` | The `cauthy` CLI (coming) |

Everything that behaves differently from 0.42:

1. **Every `POST` but `/logout` needs `X-Cauthy-Request: 1`** (`403 csrf_required` otherwise). `cauthy-auth` 0.43's browser client sends it; 0.42's does not. Upgrade the browser package in the same deploy, or pass `requestHeader: 'warn'` for that one deploy. `'warn'` is a migration aid and leaves in 2.0.
2. **Answers carry `Cauthy-Protocol: 1`, `Cache-Control: no-store`, and sign-in answers a `next` step** (`done`, `mfa`, `verify_email`, `code`, `passkey`, `one_tap`, `redirect`). Additions only.
3. **`verifyToken` needs an audience and a workspace** (`audience`/`CAUTHY_AUDIENCE`, `tenantId`/`CAUTHY_TENANT_ID`): 0.42 skipped those checks when they were not set. With an instance, use `auth.verifyToken`, which takes the issuer and the workspace from it.
4. **`verifyToken` refuses system and guest tokens** (`allowSystem`, `allowAnonymous`), a `roles` claim that is not an array of strings (or null), and anything the spec's shape rules refuse (see above). Its `leeway` is 30 seconds, where 0.42 allowed none. It is async: a bad configuration is a rejected promise.
5. **A missing issuer is a `CauthyConfigError`**, not a `CauthyTokenError`. `CauthyTokenError` is now constructed with `(reason, detail?)`, and `reason` is a code from the spec's list, not jose's text.
6. **http issuers are refused** except for `localhost`, `127.0.0.1`, `*.localhost` and `*.test`.
7. **Calls to Cauthy have a deadline**: 2 seconds for `auth.system` and the sign-in proof, 5 seconds for the sign-in screens' calls and for the code, refresh and userinfo calls (`timeouts`, below). 0.42 waited forever. `pushTheme`, `pushPolicy`, `pullPolicy`, `pushCatalog`, `pullCatalog` and `connectSystem` take `timeoutMs`.
8. **The Fastify plugin checks its mount on `onReady`** and fails startup when another route answers under the base path. It is skipped when `NODE_ENV=test`; `checkMount: false` turns it off.
9. **Contract mode stops at startup** on an unknown `system_proof`, and on a workspace named by id whose `tenant_id` says another (see below).
10. **A person whose address Cauthy says is not confirmed** (`email_not_confirmed`, when the link or client requires it) gets no session: the hosted callback redirects to your sign-in page with `auth_error=email_not_confirmed`, and the refresh token Cauthy had just issued is revoked. A session made before the requirement is treated as signed out.
11. **Error messages start with `@cauthyhq/node:`** instead of `cauthy-auth:`. Classes and codes are the same.

`/sign-in/anonymous`, `/me/upgrade` and `connectSystem` are deprecated: one `DeprecationWarning` per process, removed in 2.0.

## Contract mode

With a Pact link, everything comes from the vendored graph and one secret, `PACT_ROOT_KEY`:

```ts
import { createCauthy } from '@cauthyhq/node'
import { postgresKeyStore } from '@cauthyhq/node/keys'
import graph from './contracts/graph.json'

export const auth = createCauthy({ contract: { graph, system: 'acme-crm' }, keys: postgresKeyStore(query), audience: 'cauthy' })
```

By contract the application also publishes its own key at the contract's `jwks_url` path (`/.well-known/pact-jwks.json` by default). The Express, Hono and Fastify adapters route that path to the handler as they do `/api/auth`, so those need no route of their own for it. **Next.js and TanStack Start still need a route file** for it that calls `auth.handler(request)`.

It refuses to start when any `CAUTHY_*` variable of the standard mode is also set, when the link names its workspace by slug and the graph has no `tenant_id` for it yet, when a workspace named by id is pinned to a different `tenant_id`, when `system_proof` is not `off`, `auto` or `required`, or when the link asks for a system proof without a `service` block. When the link sets `require_verified_email`, a person whose address is not confirmed gets no session. See [`contract/pact.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/contract/pact.md).

## Options added in 1.0

| Option | Default | What it does |
| --- | --- | --- |
| `requestHeader` | `'required'` | `'warn'` lets a `POST` without `X-Cauthy-Request` through, saying so once per process |
| `timeouts.system` | `2000` | Deadline in milliseconds of the application's own calls to Cauthy (`auth.system`, the sign-in proof) |
| `timeouts.request` | `5000` | Deadline in milliseconds of the sign-in screens' calls and of the code, refresh and userinfo calls |
| `audience` | `CAUTHY_AUDIENCE` | The audience `auth.verifyToken` accepts |
| `tenantId` | `CAUTHY_TENANT_ID` | The workspace id `auth.verifyToken` accepts (by contract, the link's) |

## Testing your application

`@cauthyhq/node/testing` is a Cauthy that lives in memory (`FakeCauthy`) and a browser that keeps cookies (`Browser`), for the tests of your own application. **Test-only**: it signs in whoever it was told about and checks nothing a real Cauthy does. Do not import it from production code.

## Conformance

CI runs the auth-bff conformance suite at level `strict` against `examples/acme-crm` on an in-memory Cauthy, and the spec's token vectors against `verifyToken`:

    SPEC_DIR=../cauthy-sdk-spec LEVEL=strict npm run conformance
    SPEC_DIR=../cauthy-sdk-spec LEVEL=switches npm run conformance   # also the dashboard switches, on the in-memory Cauthy
    SPEC_DIR=../cauthy-sdk-spec npm run vectors

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
