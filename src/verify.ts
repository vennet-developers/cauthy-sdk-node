// A backend that is handed a Cauthy access token: is it real, and whose is it?
//
//   const who = await verifyToken(request)        // or the token itself
//   who.userId, who.tenantId, who.roles
//
// Cauthy signs its tokens with a key it publishes (/.well-known/jwks.json), so
// checking one needs no secret and no call to Cauthy per request: the keys are
// fetched once and cached. Throws `CauthyTokenError` for anything else: answer
// it 401, and read `reason`, one of the closed list of codes in the spec's
// verification/rules.md.

import { compactVerify, createRemoteJWKSet, type CompactVerifyGetKey, type JWTVerifyGetKey } from 'jose'
import { CauthyConfigError } from './types'
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

/** Why a token was refused: the closed list of verification/rules.md, and `no_token` when none was given. */
export type TokenRefusal =
  | 'no_token' | 'too_large' | 'malformed' | 'alg_not_allowed' | 'unsupported_header' | 'missing_kid' | 'unknown_kid' | 'weak_key'
  | 'bad_signature' | 'missing_claim' | 'invalid_claim' | 'wrong_issuer' | 'wrong_audience' | 'expired' | 'not_yet_valid'
  | 'issued_in_future' | 'wrong_tenant' | 'system_token' | 'anonymous_token'

export class CauthyTokenError extends Error {
  constructor(readonly reason: TokenRefusal, readonly detail?: string) {
    super(`@cauthyhq/node: token refused: ${reason}${detail ? ` (${detail})` : ''}`)
    this.name = 'CauthyTokenError'
  }
}

export interface VerifyTokenOptions {
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /**
   * Further issuers a token may name, e.g. a workspace's custom domain. The
   * keys always come from `issuer`. Default: none.
   */
  issuers?: string[]
  /** The audience the tokens must carry. Required: this or `CAUTHY_AUDIENCE`. */
  audience?: string
  /** The workspace's id, a lowercase UUID. Required: this or `CAUTHY_TENANT_ID`. */
  tenantId?: string
  /** Cauthy's keys. Default: fetched from the issuer and cached. */
  jwks?: JWTVerifyGetKey
  /** The moment to verify at. Default: now. */
  now?: Date
  /** Clock tolerance in seconds, 0 to 60. Default: 30. */
  leeway?: number
  /**
   * Accept a system's own token (a `sys` claim) too: for an endpoint another
   * system calls. Default: false, so a system's token never stands for a
   * person (rule R13 of the spec's verification/rules.md).
   */
  allowSystem?: boolean
  /** Accept a guest's token (`anon: true`). Default: false (rule R14). */
  allowAnonymous?: boolean
}

const MAX_TOKEN_BYTES = 8192
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const NIL_UUID = '00000000-0000-0000-0000-000000000000'
const SEGMENT = /^[A-Za-z0-9_-]+$/

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

function issuerAddress(value: string, what: string): string {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new CauthyConfigError(`${what} must be an https address, e.g. https://id.example.com`)
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new CauthyConfigError(`${what} must be https (http only for localhost)`)
  if (url.search !== '' || url.hash !== '') throw new CauthyConfigError(`${what} must have no query or fragment`)
  return withoutTrailingSlashes(value)
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const isNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)

function decodeJson(segment: string): unknown {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'))
}

/**
 * A verifier for access tokens, configured once. Refuses to be made without
 * an issuer, an audience and a workspace: a verifier that checks none of
 * them would accept a token of any other application or workspace.
 */
export function createTokenVerifier(options: VerifyTokenOptions = {}): (from: string | Request | Headers) => Promise<TokenIdentity> {
  const issuerGiven = options.issuer ?? env('CAUTHY_ISSUER') ?? ''
  if (issuerGiven === '') throw new CauthyConfigError('issuer (CAUTHY_ISSUER) is not set')
  const issuer = issuerAddress(issuerGiven, 'issuer')
  const issuers = [issuer, ...(options.issuers ?? []).map((i) => issuerAddress(i, 'issuers'))]
  const audience = options.audience ?? env('CAUTHY_AUDIENCE') ?? ''
  if (audience === '') throw new CauthyConfigError('audience (CAUTHY_AUDIENCE) is not set: without it a token issued for another application would be accepted')
  const tenant = options.tenantId ?? env('CAUTHY_TENANT_ID') ?? ''
  if (tenant === '') throw new CauthyConfigError('tenantId (CAUTHY_TENANT_ID) is not set: without it a token of another workspace would be accepted')
  if (!UUID.test(tenant) || tenant === NIL_UUID) throw new CauthyConfigError('tenantId must be the workspace\'s id, a lowercase UUID that is not the nil UUID')
  const leeway = options.leeway ?? 30
  if (!Number.isFinite(leeway) || leeway < 0 || leeway > 60) throw new CauthyConfigError('leeway must be 0 to 60 seconds')

  return async (from) => {
    const token = bearer(from)
    if (token === '') throw new CauthyTokenError('no_token')
    // R1
    if (Buffer.byteLength(token) > MAX_TOKEN_BYTES) throw new CauthyTokenError('too_large')
    // R2
    const parts = token.split('.')
    if (parts.length !== 3 || !parts.every((p) => SEGMENT.test(p) || p === '')) throw new CauthyTokenError('malformed', 'not three base64url segments')
    let header: unknown
    try {
      header = decodeJson(parts[0])
    } catch {
      throw new CauthyTokenError('malformed', 'the header is not JSON')
    }
    if (!isObject(header)) throw new CauthyTokenError('malformed', 'the header is not an object')
    // R3, R4, R5: the algorithm is the verifier's, never the token's.
    if (header.alg !== 'RS256') throw new CauthyTokenError('alg_not_allowed')
    if ('crit' in header) throw new CauthyTokenError('unsupported_header')
    if (typeof header.kid !== 'string' || header.kid === '') throw new CauthyTokenError('missing_kid')

    // R5, R6
    let payloadBytes: Uint8Array
    try {
      const verified = await compactVerify(token, (options.jwks ?? keysOf(issuer)) as CompactVerifyGetKey, { algorithms: ['RS256'] })
      payloadBytes = verified.payload
    } catch (err) {
      // By code, not by class: the keys may come from another copy of jose.
      const code = (err as { code?: unknown } | null)?.code
      if (code === 'ERR_JWKS_NO_MATCHING_KEY') throw new CauthyTokenError('unknown_kid')
      if (code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') throw new CauthyTokenError('bad_signature')
      if (err instanceof TypeError && /2048/.test(err.message)) throw new CauthyTokenError('weak_key')
      if (code === 'ERR_JWS_INVALID') throw new CauthyTokenError('malformed', err instanceof Error ? err.message : undefined)
      throw new CauthyTokenError('bad_signature', err instanceof Error ? err.message : undefined)
    }

    // R7
    let claims: unknown
    try {
      claims = JSON.parse(new TextDecoder().decode(payloadBytes))
    } catch {
      throw new CauthyTokenError('malformed', 'the payload is not JSON')
    }
    if (!isObject(claims)) throw new CauthyTokenError('malformed', 'the payload is not an object')
    for (const name of ['iss', 'sub', 'aud', 'exp', 'iat', 'tid']) {
      if (claims[name] === undefined) throw new CauthyTokenError('missing_claim', name)
    }
    // R8: no claim is null but roles.
    const bad = (name: string): never => {
      throw new CauthyTokenError('invalid_claim', name)
    }
    if (typeof claims.iss !== 'string') bad('iss')
    if (typeof claims.sub !== 'string' || !UUID.test(claims.sub)) bad('sub')
    if (typeof claims.tid !== 'string' || !UUID.test(claims.tid)) bad('tid')
    const aud = claims.aud
    if (!(typeof aud === 'string' || (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === 'string')))) bad('aud')
    for (const name of ['exp', 'iat', 'nbf']) if (claims[name] !== undefined && !isNumber(claims[name])) bad(name)
    if (claims.roles !== undefined && claims.roles !== null && !(Array.isArray(claims.roles) && claims.roles.every((r) => typeof r === 'string'))) bad('roles')
    for (const name of ['email', 'sys']) if (claims[name] !== undefined && typeof claims[name] !== 'string') bad(name)
    if (claims.anon !== undefined && typeof claims.anon !== 'boolean') bad('anon')

    // R9, R10
    if (!issuers.includes(claims.iss as string)) throw new CauthyTokenError('wrong_issuer')
    if (!(Array.isArray(aud) ? aud.includes(audience) : aud === audience)) throw new CauthyTokenError('wrong_audience')
    // R11
    const now = (options.now ?? new Date()).getTime() / 1000
    if (now >= (claims.exp as number) + leeway) throw new CauthyTokenError('expired')
    if (claims.nbf !== undefined && now < (claims.nbf as number) - leeway) throw new CauthyTokenError('not_yet_valid')
    if (now < (claims.iat as number) - leeway) throw new CauthyTokenError('issued_in_future')
    // R12
    if (claims.tid !== tenant) throw new CauthyTokenError('wrong_tenant')
    // R13, R14
    if (claims.sys !== undefined && !options.allowSystem) throw new CauthyTokenError('system_token')
    if (claims.anon === true && !options.allowAnonymous) throw new CauthyTokenError('anonymous_token')

    return {
      userId: claims.sub as string,
      tenantId: claims.tid as string,
      ...(typeof claims.email === 'string' && claims.email !== '' ? { email: claims.email } : {}),
      roles: Array.isArray(claims.roles) ? (claims.roles as string[]) : [],
      ...(typeof claims.sys === 'string' && claims.sys !== '' ? { system: claims.sys } : {}),
      ...(claims.anon === true ? { anonymous: true as const } : {}),
      expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
      token,
    }
  }
}

/**
 * Verifies an access token (or the `Authorization: Bearer` of a request) and
 * answers who it belongs to, by the rules of the spec's verification/rules.md.
 * Needs an issuer, an audience and a workspace (see `createTokenVerifier`,
 * which checks them once, at startup).
 */
export function verifyToken(from: string | Request | Headers, options: VerifyTokenOptions = {}): Promise<TokenIdentity> {
  return createTokenVerifier(options)(from)
}
