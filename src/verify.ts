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

import { compactVerify, createLocalJWKSet, type CompactVerifyGetKey, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose'
import { parseStrict } from './json'
import { CauthyConfigError } from './types'
import { withoutTrailingSlashes } from './url'

/** Who a verified access token belongs to. */
export interface TokenIdentity {
  /** The person. For a system's own token, the client it identifies as. */
  userId: string
  tenantId: string
  email?: string
  /** What the token says of the address, when it says (a boolean; absent otherwise). */
  emailVerified?: boolean
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

/**
 * Cauthy's keys could not be fetched (or are not a key set): the token may be
 * good, and the application cannot tell. Answer 503, not 401. It is not a
 * `CauthyTokenError`: it says nothing about the token.
 */
export class CauthyUnavailableError extends Error {
  constructor(detail: string) {
    super(`@cauthyhq/node: Cauthy's keys are unavailable: ${detail}`)
    this.name = 'CauthyUnavailableError'
  }
}

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
  /** Cauthy's keys. Default: fetched from the issuer and cached (see `remoteKeys`). */
  jwks?: JWTVerifyGetKey
  /** The fetch to get the keys with. Default: the global one. */
  fetch?: typeof fetch
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

const MAX_KEYS_BYTES = 64 * 1024
const KEYS_TIMEOUT_MS = 5000
const KEYS_COOLDOWN_MS = 30_000
const KEYS_DEFAULT_TTL_S = 300
const KEYS_MAX_TTL_S = 3600

/**
 * Cauthy's published keys (K1 to K5 of verification/rules.md): fetched with a
 * GET that follows no redirect, within 5 seconds, from `<issuer>/.well-known/jwks.json`;
 * only a 200 of at most 64 KiB counts. Kept for the answer's max-age (at most
 * an hour, 5 minutes when it names none); a `kid` the set lacks fetches again
 * only if the last fetch is older than 30 seconds; one fetch at a time; a
 * failed fetch keeps the last good set, and with none it is
 * `CauthyUnavailableError`.
 */
export function remoteKeys(issuer: string, fetchKeys: typeof fetch = fetch): JWTVerifyGetKey {
  let set: JWTVerifyGetKey | undefined
  let startedAt = 0
  let expiresAt = 0
  let inflight: Promise<void> | undefined

  const load = async (): Promise<void> => {
    startedAt = Date.now()
    try {
      const res = await fetchKeys(`${issuer}/.well-known/jwks.json`, { redirect: 'manual', signal: AbortSignal.timeout(KEYS_TIMEOUT_MS), headers: { accept: 'application/json' } })
      if (res.status !== 200) throw new Error(`answered ${res.status}`)
      const bytes = await readCapped(res, MAX_KEYS_BYTES)
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as JSONWebKeySet
      if (!parsed || !Array.isArray(parsed.keys)) throw new Error('not a key set')
      set = createLocalJWKSet(parsed)
      const maxAge = /max-age=(\d+)/.exec(res.headers.get('cache-control') ?? '')
      const ttl = Math.min(maxAge ? Number(maxAge[1]) : KEYS_DEFAULT_TTL_S, KEYS_MAX_TTL_S)
      expiresAt = Date.now() + ttl * 1000
    } catch (err) {
      // The last good set stands, and is not asked for again before the cooldown:
      // an outage must not cost a wait on every verification. With none, the
      // application cannot tell.
      if (set === undefined) throw new CauthyUnavailableError(err instanceof Error ? err.message : 'unreachable')
      expiresAt = Math.max(expiresAt, Date.now() + KEYS_COOLDOWN_MS)
    }
  }
  const refresh = (): Promise<void> => {
    inflight ??= load().finally(() => {
      inflight = undefined
    })
    return inflight
  }

  return async (header, token) => {
    if (set === undefined || Date.now() >= expiresAt) await refresh()
    try {
      return await set!(header, token)
    } catch (err) {
      const unknown = (err as { code?: unknown } | null)?.code === 'ERR_JWKS_NO_MATCHING_KEY'
      if (unknown && Date.now() - startedAt >= KEYS_COOLDOWN_MS) {
        await refresh()
        return set!(header, token)
      }
      throw err
    }
  }
}

async function readCapped(res: Response, max: number): Promise<Uint8Array> {
  const reader = res.body?.getReader()
  if (!reader) return new Uint8Array()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.length
    if (size > max) {
      await reader.cancel()
      throw new Error(`over ${max} bytes`)
    }
    chunks.push(value)
  }
  const out = new Uint8Array(size)
  let at = 0
  for (const c of chunks) {
    out.set(c, at)
    at += c.length
  }
  return out
}

const published = new Map<string, JWTVerifyGetKey>()
const withFetch = new WeakMap<typeof fetch, Map<string, JWTVerifyGetKey>>()

function remoteKeysFor(issuer: string, fetchKeys: typeof fetch): JWTVerifyGetKey {
  let byIssuer = withFetch.get(fetchKeys)
  if (!byIssuer) withFetch.set(fetchKeys, (byIssuer = new Map()))
  let set = byIssuer.get(issuer)
  if (!set) byIssuer.set(issuer, (set = remoteKeys(issuer, fetchKeys)))
  return set
}

/** Cauthy's published keys, fetched once per issuer and kept (see `remoteKeys`). */
export function keysOf(issuer: string): JWTVerifyGetKey {
  let set = published.get(issuer)
  if (set === undefined) {
    set = remoteKeys(issuer)
    published.set(issuer, set)
  }
  return set
}

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined
}

function bearer(from: string | Request | Headers): string {
  // A raw token is taken as it is: surrounding whitespace is the caller's mistake (R2).
  if (typeof from === 'string') return from.replace(/^Bearer\s+/i, '')
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
  // http is for a developer's own machine: localhost, 127.0.0.1, *.localhost and *.test.
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.test')
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new CauthyConfigError(`${what} must be https (http only for localhost, *.localhost and *.test)`)
  if (url.search !== '' || url.hash !== '') throw new CauthyConfigError(`${what} must have no query or fragment`)
  return withoutTrailingSlashes(value)
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

function decodeJson(segment: string): unknown {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/')
  return parseStrict(Buffer.from(padded, 'base64').toString('utf8'))
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
    // R4: typ is not required, but when present it is JWT or at+jwt, in any case.
    if ('typ' in header && !(typeof header.typ === 'string' && ['jwt', 'at+jwt'].includes(header.typ.toLowerCase()))) {
      throw new CauthyTokenError('unsupported_header', 'typ')
    }
    if (typeof header.kid !== 'string' || header.kid === '') throw new CauthyTokenError('missing_kid')

    // R5, R6
    let payloadBytes: Uint8Array
    try {
      const verified = await compactVerify(token, (options.jwks ?? (options.fetch ? remoteKeysFor(issuer, options.fetch) : keysOf(issuer))) as CompactVerifyGetKey, { algorithms: ['RS256'] })
      payloadBytes = verified.payload
    } catch (err) {
      // By code, not by class: the keys may come from another copy of jose.
      const code = (err as { code?: unknown } | null)?.code
      if (code === 'ERR_JWKS_NO_MATCHING_KEY') throw new CauthyTokenError('unknown_kid')
      if (code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') throw new CauthyTokenError('bad_signature')
      if (err instanceof TypeError && /2048/.test(err.message)) throw new CauthyTokenError('weak_key')
      if (code === 'ERR_JWS_INVALID') throw new CauthyTokenError('malformed', err instanceof Error ? err.message : undefined)
      if (err instanceof CauthyUnavailableError) throw err
      throw new CauthyTokenError('bad_signature', err instanceof Error ? err.message : undefined)
    }

    // R7
    let claims: unknown
    try {
      claims = parseStrict(new TextDecoder().decode(payloadBytes), ['exp', 'iat', 'nbf'])
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
    for (const name of ['exp', 'iat', 'nbf']) if (claims[name] !== undefined && !Number.isInteger(claims[name])) bad(name)
    if (claims.roles !== undefined && claims.roles !== null && !(Array.isArray(claims.roles) && claims.roles.every((r) => typeof r === 'string'))) bad('roles')
    if (claims.email !== undefined && typeof claims.email !== 'string') bad('email')
    for (const name of ['email_verified', 'anon']) if (claims[name] !== undefined && typeof claims[name] !== 'boolean') bad(name)

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
    // Its presence is the mark, whatever the value (null and false included).
    if ('sys' in claims && !options.allowSystem) throw new CauthyTokenError('system_token')
    if (claims.anon === true && !options.allowAnonymous) throw new CauthyTokenError('anonymous_token')

    return {
      userId: claims.sub as string,
      tenantId: claims.tid as string,
      ...(typeof claims.email === 'string' && claims.email !== '' ? { email: claims.email } : {}),
      ...(typeof claims.email_verified === 'boolean' ? { emailVerified: claims.email_verified } : {}),
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
export async function verifyToken(from: string | Request | Headers, options: VerifyTokenOptions = {}): Promise<TokenIdentity> {
  return createTokenVerifier(options)(from)
}
