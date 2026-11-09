# @cauthyhq/node

Cauthy for Node.js backends: sign-in, cookie sessions, organizations, Pact contract mode and token verification, served as the [auth-bff protocol](https://github.com/vennet-developers/cauthy-sdk-spec) version 1, level `strict`.

The browser never holds a token. Your server mounts one route, keeps the session in an encrypted HttpOnly cookie, and every security setting (sign-in methods, second factors, session length) is a switch in Cauthy's dashboard, not code.

```bash
npm install @cauthyhq/node
```

Node 20 or later. ESM and CommonJS. One dependency: `jose`.

## The five-minute path

**1. Connect the application in Cauthy's dashboard** (**Integrate → Applications → Connect an application**), with its address, e.g. `http://localhost:3000`. The dashboard makes the application's key in your browser and shows it once, as one line.

**2. Put that line in `.env`** (keep it out of git):

    CAUTHY_KEY=cauthy1.…

That is the whole environment: Cauthy's address, the application's client and its secret are in the key; the workspace, the system and the application's addresses are asked of Cauthy when it starts. The [five-minute guide](https://cauthy.docs.vennet.dev/en/guide/get-started/) walks through it.

**3. Create it and mount it.**

```ts
// auth.ts
import { createCauthy } from '@cauthyhq/node'
export const auth = createCauthy()   // reads CAUTHY_KEY
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

## CAUTHY_KEY

One value: Cauthy's address, the application's client and a 32-byte secret,
with a checksum (`cauthy1.<issuer>.<client>.<secret>.<check>`, specified in
the spec's [`key/cauthy-key.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/key/cauthy-key.md)).
The SDK derives the session-cookie keys and an Ed25519 key from it, proves
itself to Cauthy with that key (`private_key_jwt`, a fresh assertion on every
token and revoke call; no client secret is ever sent), and asks Cauthy who it
is (`GET /v1/connect/self`). Cauthy keeps only the public half.

| When | What happens |
| --- | --- |
| `createCauthy()` | The key is parsed at once: a damaged paste throws `CauthyKeyError` naming the reason (`key_format`, `key_checksum`, …), never the key. Then Cauthy is asked who the application is, in the background |
| Cauthy not reachable yet | The server starts; `/api/auth/*` answers `503 unavailable` until the answer comes (retried from 1 to 30 seconds) |
| Cauthy refuses the key (revoked, never registered) | Logged once with the key's `kid`; `/api/auth/*` answers `503 misconfigured` |
| Running | The answer is kept and asked again every 5 minutes; while Cauthy is down the last one stands |
| `await auth.ready()` | The identity, waited for: call it at startup to fail early |

The redirect URI is built from the request's origin when it is one of the
application's addresses in Cauthy, from the only one when there is just one,
and the request is refused with `400 unknown_origin` otherwise. `baseURL`
still overrides it. Beside `CAUTHY_KEY` the variables it replaces
(`CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SYSTEM`,
`CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID`, `CAUTHY_BASE_URL`,
`CAUTHY_AUDIENCE`, `CAUTHY_TENANT_ID`) and the options they stand for are
refused at startup, naming them.

**Lost or leaked:** make a new key on the application's card and revoke the
old one. **Rotating:** move the current value to `CAUTHY_KEY_PREVIOUS`, put
the new one in `CAUTHY_KEY`, deploy, and remove `CAUTHY_KEY_PREVIOUS` after
the window: sessions made with the previous key are still read, and nothing
new is written with it.

**Moving from the variables of 1.1:** on the application's card, **Move to
CAUTHY_KEY**. Deploy with `CAUTHY_KEY` and keep `CAUTHY_SECRET` for the window
(old sessions stay readable; one warning says to remove it), remove the other
variables, then **Remove the secret**. The variables of 1.1 and `PACT_ROOT_KEY`
still work in 1.x with one `DeprecationWarning` per process and leave in 2.0.

## Verifying a token

For an API that receives Cauthy access tokens from somewhere other than the browser's cookie:

```ts
import { auth } from './auth'

// Where each value comes from:
//   issuer   the instance's own (CAUTHY_KEY, or the contract; deprecated: CAUTHY_ISSUER)
//   tenantId by contract, the link's tenant_id; on CAUTHY_KEY, Cauthy's answer; otherwise `tenantId` or CAUTHY_TENANT_ID (deprecated)
//   audience on CAUTHY_KEY, Cauthy's answer; otherwise `audience` or CAUTHY_AUDIENCE (deprecated): your Cauthy's JWT_AUDIENCE
//   clientId by contract, the link's sign-in client: a person's token issued through another is refused (wrong_client)
const verify = auth.tokenVerifier()          // throws CauthyConfigError now if one is missing
const who = await verify(request)            // or: await auth.verifyToken(request)
```

On `CAUTHY_KEY`, the issuer, the audience and the workspace are Cauthy's answer: `auth.tokenVerifier()` waits for it. With no instance:

```ts
import { createVerifierFromEnv } from '@cauthyhq/node'
const verify = await createVerifierFromEnv()   // reads CAUTHY_KEY; asks Cauthy once
```

Standalone, with no instance and no key, everything is explicit:

```ts
import { createTokenVerifier } from '@cauthyhq/node'
const verify = createTokenVerifier({ issuer: 'https://id.example.com', audience: 'cauthy', tenantId: '<the workspace id>' })
```

`createTokenVerifier` checks its configuration when it is built (startup); `verifyToken(request, options)` does the same on each call, as a rejected promise. Both follow the spec's [`verification/rules.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/verification/rules.md); every vector of the spec passes in CI. The error carries a `reason` from the spec's closed list (`expired`, `wrong_audience`, `system_token`, …). If Cauthy's keys cannot be fetched you get `CauthyUnavailableError` (answer 503), which says nothing about the token.

- **The audience and the workspace are required.** Without them a token issued for another application or workspace would be accepted.
- A system's own token (`sys` claim, whatever its value) and a guest's token (`anon: true`) are refused where a person is expected. Pass `allowSystem` or `allowAnonymous` for an endpoint that takes them.
- A client's own token (a `client_credentials` grant: `token_use: "client"`, whatever the value) is refused with `client_token` where a person is expected. A backend that serves machines too passes `allowClientTokens: true`; the identity then carries `clientId`, the client's public id (its `userId` is the client's internal id).
- `authorizedParty` is the token's `azp`: the client a person's token was issued through, absent when none was named. With `clientId` (by contract, always the link's sign-in client), a token whose `azp` names another client is refused with `wrong_client`; a token with no `azp` passes.
- Clock tolerance is 30 seconds (`leeway`, 0 to 60). A token over 8192 bytes, with a repeated JSON name, a fractional date or a wrongly typed claim is refused.
- Keys are fetched from `<issuer>/.well-known/jwks.json` with no redirect, within 5 seconds, at most 64 KiB, and kept for the answer's `max-age`.

## Moving from cauthy-auth

`@cauthyhq/node` 1.0 is the server half of `cauthy-auth` 0.42 with the same options, variables and names. Change the import:

| cauthy-auth 0.42 | @cauthyhq/node 1.0 |
| --- | --- |
| `cauthy-auth` | `@cauthyhq/node` |
| `cauthy-auth/express`, `/fastify`, `/hono`, `/next`, `/mcp`, `/keys`, `/theme` | `@cauthyhq/node/express`, … (same names) |
| `cauthy-auth/react`, `/styles.css` | `@cauthyhq/react`, `@cauthyhq/react/styles.css` |
| `cauthy-auth/client` | `@cauthyhq/js` |
| `cauthy-auth/vue`, `/svelte` | No 1.0 wrapper yet: keep `cauthy-auth` 0.43 in the browser (security fixes until 2027-02-06) |
| `npx cauthy-auth …` | The `cauthy` CLI: `npx @cauthyhq/cli …` |

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

A contract is a layer on top of an application that runs on `CAUTHY_KEY`: the environment stays that one line, and the vendored graph adds the link (system proof, drift, the link's policies). No key store and no table:

```ts
import { createCauthy } from '@cauthyhq/node'
import graph from './contracts/graph.json'

export const auth = createCauthy({ contract: { graph, system: 'acme-crm' } })   // and CAUTHY_KEY in the environment
```

The key proves the link's service client (`pact.<link>.service`); people sign in through its public client (`pact.<link>`). The key must name the graph's Cauthy (`key_contract_issuer` otherwise). The application publishes the key's public half at the contract's `jwks_url` path (`/.well-known/pact-jwks.json` by default), and the previous key's too during a rotation. The Express, Hono and Fastify adapters route that path to the handler as they do `/api/auth`, so those need no route of their own for it. **Next.js and TanStack Start still need a route file** for it that calls `auth.handler(request)`.

The 1.1 way (`PACT_ROOT_KEY` and `keys: postgresKeyStore(query)`) keeps working through 1.x with a deprecation warning. Moving: generate `CAUTHY_KEY` on the application's card, deploy it with `PACT_ROOT_KEY` and the `keys` option still beside it for the window (old sessions stay readable, its RS256 keys stay published beside the new Ed25519 key), then remove `PACT_ROOT_KEY`, the option and the table.

It refuses to start when any variable `CAUTHY_KEY` replaces is also set, when the link names its workspace by slug and the graph has no `tenant_id` for it yet, when a workspace named by id is pinned to a different `tenant_id`, when `system_proof` is not `off`, `auto` or `required`, or when the link asks for a system proof without a `service` block. When the link sets `require_verified_email`, a person whose address is not confirmed gets no session. See [`contract/pact.md`](https://github.com/vennet-developers/cauthy-sdk-spec/blob/main/contract/pact.md).

## Options added in 1.0

| Option | Default | What it does |
| --- | --- | --- |
| `requestHeader` | `'required'` | `'warn'` lets a `POST` without `X-Cauthy-Request` through, saying so once per process |
| `timeouts.system` | `2000` | Deadline in milliseconds of the application's own calls to Cauthy (`auth.system`, the sign-in proof) |
| `timeouts.request` | `5000` | Deadline in milliseconds of the sign-in screens' calls and of the code, refresh and userinfo calls |
| `audience` | `CAUTHY_AUDIENCE` | The audience `auth.verifyToken` accepts |
| `tenantId` | `CAUTHY_TENANT_ID` | The workspace id `auth.verifyToken` accepts (by contract, the link's) |

## Testing your application

`@cauthyhq/node/testing` is a Cauthy that lives in memory (`FakeCauthy`) and a browser that keeps cookies (`Browser`), for the tests of your own application. **Test-only**: it signs in whoever it was told about and checks little a real Cauthy does. Do not import it from production code.

```ts
const fake = new FakeCauthy()
fake.appUrls = ['http://localhost:3000']
const auth = createCauthy({ key: await fake.issueKey(), fetch: fake.fetch })
```

`issueKey(issuer?)` makes a `CAUTHY_KEY` for `fake.clientId` and registers its public half, as the dashboard does; from then on that client must prove itself with the key's assertion on every token and revoke call. `revokeKey(kid)` revokes it. `serveFakeCauthy(fake, port)` serves it over HTTP; issue the key with that address (`http://127.0.0.1:<port>`) for a process outside yours.

## Conformance

The auth-bff conformance suite runs at level `strict` against `examples/acme-crm` on an in-memory Cauthy, the application on `CAUTHY_KEY` alone (with the runner's `key.*` checks); the spec's token vectors run against `verifyToken`, and its `CAUTHY_KEY` vectors against the parser and the derivation:

    SPEC_DIR=../cauthy-sdk-spec LEVEL=strict npm run conformance
    SPEC_DIR=../cauthy-sdk-spec LEVEL=switches npm run conformance   # also the dashboard switches, on the in-memory Cauthy
    SPEC_DIR=../cauthy-sdk-spec MODE=variables npm run conformance   # the 1.1 way, for a runner without --key-env
    SPEC_DIR=../cauthy-sdk-spec npm run vectors

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
