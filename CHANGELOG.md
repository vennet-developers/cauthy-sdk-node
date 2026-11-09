# Changelog

## 1.2.1

### Fixed

- **Moving to `CAUTHY_KEY`**: a session sealed with `CAUTHY_SECRET`, `PACT_ROOT_KEY` or `CAUTHY_KEY_PREVIOUS` is sealed again with the key on the first request that reads it through the handler or an adapter (`GET <basePath>/session`, `req.cauthy()`, …), not only when its access token is renewed. A session read during the window now outlives the old secret's removal.
- `PACT_ROOT_KEY_PREVIOUS` beside `CAUTHY_KEY` and `PACT_ROOT_KEY` is read too: sessions sealed before a root rotation that was still open at the move stay readable. 1.2.0 read the current root only.
- A session cookie that no configured key opens is still cleared, and is now said once per process (`console.warn`), naming the secret to keep beside `CAUTHY_KEY` for the window.
- Covered end to end with the published packages: sessions signed in by `cauthy-auth` 0.41.0 and 0.42.0 (contract, `PACT_ROOT_KEY`, `keys`) and by `@cauthyhq/node` 1.1.0 (`CAUTHY_SECRET`), read by 1.2 at `GET /api/id/session`, fresh and renewed.

## 1.2.0

One variable for every application: `CAUTHY_KEY`.

### Added

- **`CAUTHY_KEY`** (`key/cauthy-key.md` of the spec): Cauthy's address, the application's client and a 32-byte secret in one value, made by Cauthy's dashboard in the browser. `createCauthy()` reads it and nothing else: the session-cookie keys and an Ed25519 key are derived from it, the application authenticates with `private_key_jwt` (`EdDSA`) on every token and revoke call, never with a client secret, and asks Cauthy who it is (`GET /v1/connect/self`: workspace, system, addresses), revalidated every 5 minutes. The `key` option takes it in code.
- **Startup**: a damaged key throws `CauthyKeyError` at once with its reason (`key_format`, `key_version`, `key_checksum`, `key_issuer`, `key_client`, `key_secret`, `key_contract_issuer`, `key_previous_mismatch`), never the value. Cauthy unreachable: the server starts and `/api/auth/*` answers `503 unavailable` until Cauthy answers. Cauthy refusing the key: `503 misconfigured`, logged once with the `kid`. `auth.ready()` awaits the identity.
- **The redirect URI** comes from the request's origin when it is one of the application's addresses in Cauthy, else the only one; otherwise `400 unknown_origin`.
- **A contract on top of the key**: `createCauthy({ contract: { graph, system } })` with `CAUTHY_KEY` needs no key store and no table. The key proves the link's service client; the JWKS route publishes the key's Ed25519 public half (and the previous key's during a rotation). The key must name the graph's Cauthy.
- **`CAUTHY_KEY_PREVIOUS`** (`keyPrevious`) for rotations: its sessions are read, never written. `CAUTHY_SECRET` and `PACT_ROOT_KEY` beside the key are read-only too while an application moves (one warning each); with `PACT_ROOT_KEY`, a contract and `keys`, the old RS256 keys stay published beside the new one.
- **`createVerifierFromEnv()`**: a token verifier from `CAUTHY_KEY` alone (issuer, audience and workspace from Cauthy).
- `verifyWebhook` takes the issuer from `CAUTHY_KEY` when it is set.
- `parseKey`, `composeKey`, `KEY_REPLACES`, `CauthyKeyError`, and the types `CauthyKey`, `CauthyKeyReason`, `Identity`.
- **`@cauthyhq/node/testing`**: `FakeCauthy.issueKey(issuer?, { clientId? })`, `revokeKey(kid)`, `registeredKids()`, `appUrls`, `system`, `tenantId`, `contract`, `oauthRequests`. The fake checks Ed25519 assertions (signature, `kid`, `iss`/`sub`/`aud`, lifetime, replay) and answers `GET /v1/connect/self`, with `ETag`.

### Refused beside `CAUTHY_KEY`

`CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SYSTEM`, `CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID`, `CAUTHY_BASE_URL`, `CAUTHY_AUDIENCE`, `CAUTHY_TENANT_ID`, and the options `issuer`, `clientId`, `clientSecret`, `secret`, `system`, `tenant`, `audience`, `tenantId`, `systemKey`, `rootKey` (and `keys`, except beside `PACT_ROOT_KEY` with a contract while moving).

### Deprecated (removed in 2.0)

One `DeprecationWarning` (code `CAUTHY_DEPRECATED`) per process each: configuring with the `CAUTHY_*` variables or their options; `PACT_ROOT_KEY[_PREVIOUS]` and the `keys` store; a verifier reading `CAUTHY_ISSUER`, `CAUTHY_AUDIENCE` or `CAUTHY_TENANT_ID`. They keep working through 1.x.

### Unchanged

Applications on the 1.1 variables or on `PACT_ROOT_KEY` work as before, apart from the warning. The MCP variables (`CAUTHY_MCP_*`) are not part of this change.

## 1.1.0 — security release

Cauthy now marks the tokens a machine holds, and names the client a person's token was issued through. This release makes `verifyToken` use those marks. Refusing a machine's token where a person is expected is a fix, not a break, so it ships as a minor version: upgrade.

### Security

- **A client's own token no longer passes as a person's.** A `client_credentials` token carries `token_use: "client"` and the client's public `client_id`. `verifyToken`, `createTokenVerifier`, `auth.verifyToken` and `auth.tokenVerifier` now refuse it with the reason `client_token` (rule R13 of the spec's `verification/rules.md`), by the claim's presence, whatever its value. In 1.0 such a token was accepted as a person whose `userId` was the client's id.
- **By contract, a person's token issued through another client is refused** with `wrong_client` (rule R15): `auth.verifyToken` and `auth.tokenVerifier` check the token's `azp` against the link's sign-in client. A token with no `azp` passes. A call that names another `clientId` in contract mode is a `CauthyConfigError`.
- `token_use` and `azp`, when present, must be strings (`invalid_claim` otherwise, rule R8).

### Backends that serve machines

If an endpoint is called by machines with a `client_credentials` token, pass `allowClientTokens: true` to the verifier that guards it:

```ts
const verifyMachine = auth.tokenVerifier({ allowClientTokens: true })
const who = await verifyMachine(request)
who.clientId // the client's public id; who.userId is its internal id
```

Without it those calls get `client_token` (answer 401) after the upgrade.

### Added

- `TokenIdentity.authorizedParty`: the token's `azp`, the client a person's token was issued through; absent when none was named.
- `TokenIdentity.clientId`: the token's `client_id` (a client's own token, with `allowClientTokens`; an AI agent's).
- `VerifyTokenOptions.allowClientTokens` (default `false`) and `VerifyTokenOptions.clientId` (default none; by contract, the link's sign-in client).
- `TokenRefusal` gains `client_token` and `wrong_client`.

### Notes

- Cauthy now answers its JWKS with `max-age=300` and publishes a key at least that long before it signs with it. Nothing changes here: the keys are kept for the answer's `max-age` and fetched again on an unknown `kid`.
- A session that began through a client renews only through it. The SDK already renews with the `clientId` it signed in with, and sends that `clientId` on its own screens' calls: keep one `clientId` per deployment.

### Development

- vitest 4.1.12, fastify 5.12.8 (tests), and postcss 8.5.32 and esbuild 0.28.2 by override: every open advisory was in development dependencies only. `npm audit` reports none.

## 1.0.0

First release: the server half of `cauthy-auth` 0.42 (see the README, "Moving from cauthy-auth").
