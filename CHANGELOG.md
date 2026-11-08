# Changelog

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
