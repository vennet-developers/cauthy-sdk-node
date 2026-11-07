// A backend that is handed a Cauthy access token: is it real, and whose is it?
//
//   const who = await verifyToken(request)        // or the token itself
//   who.userId, who.tenantId, who.roles
//
// Cauthy signs its tokens with a key it publishes (/.well-known/jwks.json), so
// checking one needs no secret and no call to Cauthy per request: the keys are
// fetched once and cached. Throws `CauthyTokenError` for anything else: answer
// it 401.

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose'
import { withoutTrailingSlashes } from './url'

/** Who a verified access token belongs to. */
export interface TokenIdentity {
  /** The person. For a system's own token, the client it identifies as. */
  userId: string
  tenantId: string
  email?: string
  roles: string[]
  /** Set when the token is a system's own and not a person's (only with `allowSystem`). */
  system?: string
  /** Set when the token is a guest's (only with `allowAnonymous`). */
  anonymous?: true
  /** UTC, ISO 8601. */
  expiresAt: string
  /** The token as it arrived, to pass on. */
  token: string
}

export class CauthyTokenError extends Error {
  constructor(readonly reason: string) {
    super(`@cauthyhq/node: token refused: ${reason}`)
    this.name = 'CauthyTokenError'
  }
}

export interface VerifyTokenOptions {
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The audience the tokens must carry. Default: `CAUTHY_AUDIENCE`; unchecked when neither is set. */
  audience?: string
  /** Refuse a token of any other workspace. Default: `CAUTHY_TENANT_ID`; unchecked when neither is set. */
  tenantId?: string
  /** Cauthy's keys. Default: fetched from the issuer and cached. */
  jwks?: JWTVerifyGetKey
  /** The moment to verify at. Default: now. */
  now?: Date
  /**
   * Accept a system's own token (a `sys` claim) too: for an endpoint another
   * system calls. Default: false, so a system's token never stands for a
   * person (rule R13 of the spec's verification/rules.md).
   */
  allowSystem?: boolean
  /** Accept a guest's token (`anon: true`). Default: false (rule R14). */
  allowAnonymous?: boolean
}

const keys = new Map<string, JWTVerifyGetKey>()

/** Cauthy's published keys, fetched once per issuer and cached. */
export function keysOf(issuer: string): JWTVerifyGetKey {
  let set = keys.get(issuer)
  if (set === undefined) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`), { cooldownDuration: 30_000 })
    keys.set(issuer, set)
  }
  return set
}

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined
}

function bearer(from: string | Request | Headers): string {
  if (typeof from === 'string') return from.replace(/^Bearer\s+/i, '').trim()
  const header = (from instanceof Headers ? from : from.headers).get('authorization') ?? ''
  return /^Bearer\s+/i.test(header) ? header.replace(/^Bearer\s+/i, '').trim() : ''
}

/**
 * Verifies an access token (or the `Authorization: Bearer` of a request) and
 * answers who it belongs to. Checked: the signature, against Cauthy's
 * published keys; that Cauthy issued it; that it has not expired; and the
 * audience and the workspace, when given.
 */
export async function verifyToken(from: string | Request | Headers, options: VerifyTokenOptions = {}): Promise<TokenIdentity> {
  const issuer = withoutTrailingSlashes(options.issuer ?? env('CAUTHY_ISSUER') ?? '')
  if (issuer === '') throw new CauthyTokenError('issuer (CAUTHY_ISSUER) is not set')
  const token = bearer(from)
  if (token === '') throw new CauthyTokenError('no token')

  let claims: Record<string, unknown>
  try {
    const verified = await jwtVerify(token, options.jwks ?? keysOf(issuer), {
      algorithms: ['RS256'],
      issuer,
      audience: options.audience ?? env('CAUTHY_AUDIENCE'),
      requiredClaims: ['exp', 'sub'],
      currentDate: options.now,
    })
    claims = verified.payload as Record<string, unknown>
  } catch (err) {
    throw new CauthyTokenError(err instanceof Error ? err.message : 'bad signature')
  }

  const tenantId = typeof claims.tid === 'string' ? claims.tid : ''
  const wanted = options.tenantId ?? env('CAUTHY_TENANT_ID')
  if (wanted && tenantId !== wanted) throw new CauthyTokenError('issued for another workspace')

  if (claims.sys !== undefined && !options.allowSystem) throw new CauthyTokenError('system_token')
  if (claims.anon === true && !options.allowAnonymous) throw new CauthyTokenError('anonymous_token')

  return {
    userId: String(claims.sub),
    tenantId,
    ...(typeof claims.email === 'string' && claims.email !== '' ? { email: claims.email } : {}),
    roles: Array.isArray(claims.roles) ? claims.roles.filter((r): r is string => typeof r === 'string') : [],
    ...(typeof claims.sys === 'string' && claims.sys !== '' ? { system: claims.sys } : {}),
    ...(claims.anon === true ? { anonymous: true as const } : {}),
    expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
    token,
  }
}
