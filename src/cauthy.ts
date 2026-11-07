// Sign in with Cauthy, held by the application's own server.
//
// The application mounts one route (`handler`) and asks who is there
// (`getSession`). Signing in, signing up, second factors, passkeys, recovering
// a password and the account page are Cauthy's pages: this sends the browser
// to them and keeps what comes back in an encrypted, httpOnly cookie. There is
// no database and no screen to build.
//
// The session is Cauthy's short-lived access token plus the refresh token that
// renews it. When the access token expires the session is renewed with Cauthy,
// which is where an account disabled there, or signed out everywhere, stops
// being signed in here — within minutes, with nothing to synchronise.

import { clearParts, readCookies, readParts, writeCookie, writeParts, type CookieAttributes } from './cookies'
import { keyOf, seal, unsealAny } from './seal'
import { failClosed, readContract, type PactStatus, type ResolvedContract } from './contract'
import { JWKS_MAX_AGE_S, pactKeys, type PactKeys } from './keys'
import { deriveKeys, type KeyRing } from './rootkey'
import { checkResultOf, checkWire, organizationIdOf } from './permissions'
import { CauthyApiError, createSystem, type CauthySystem } from './system'
import { checkCode, checkEmail, checkName, checkNewPassword, checkPassword, firstProblem, passwordPolicyOf, type FieldProblem, type PasswordPolicy, checkOrganization, checkOrganizationName } from './validate'
import { memoryReplayStore, verifyWebhook, type CauthyEvent, type VerifyWebhookOptions } from './webhook'
import {
  CauthyConfigError,
  type CauthyOptions,
  type CheckQuestion,
  type CheckResult,
  type ConditionalPermission,
  type JsonValue,
  type OrganizationRef,
  type PublicSession,
  type Session,
  type SessionOrganization,
  type SessionStatus,
  type SessionUser,
} from './types'
import { withoutTrailingSlashes } from './url'
import { finish } from './protocol'
import { deadline } from './deadline'
import { deprecated } from './deprecate'
import { checkMount as probeMount, type MountTarget } from './mount'

/** What the session cookie holds. Short names: it rides every request. */
interface Stored {
  at: string // access token
  rt: string // refresh token
  exp: number // when the access token expires, epoch seconds
  u: SessionUser
  tid: string
  roles: string[]
  p?: 1 // the person asked to stay signed in, and Cauthy allowed it
}

/** What the sign-in in progress holds, between leaving for Cauthy and coming back. */
interface Flow {
  state: string
  verifier: string
  returnTo: string
}

// A session that stays signed in keeps its cookie this long, renewed on each
// use; a short one has a cookie that ends with the browser session. Cauthy
// alone decides how long the session itself lives.
const PERSISTENT_SECONDS = 30 * 86_400
// How long a sign-in may sit open at Cauthy and still be finished here. The
// same hour Cauthy keeps its side of it.
const FLOW_SECONDS = 3600
/** How long a sign-in that had to start again is remembered, so it starts again once and not forever. */
const AGAIN_SECONDS = 120
/** Renew this long before the access token runs out, so a request never carries one about to. */
const SKEW_SECONDS = 30
const ORGANIZATIONS_TTL_MS = 60_000
/** How long the workspace's look is kept before Cauthy is asked again. */
const LOOK_TTL_MS = 60_000
/** A provider's id: `google`, `linkedin_oidc`, or one the workspace defined itself, `custom:<slug>`. */
const PROVIDER_ID = /^(custom:)?[a-z0-9_-]{1,40}$/

/** The provider named in a route, as written or percent-encoded (`custom%3Aacme`). */
function providerIn(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return ''
  }
}

/** What `resolve` answers: who is there, and the cookies that must go back. */
export interface Resolved {
  session: Session | null
  status: SessionStatus
  /** `Set-Cookie` values to send with the response. Empty when nothing changed. */
  cookies: string[]
}

export interface Cauthy {
  /** Serves the routes under `basePath`: login, callback, session, refresh, logout, account. */
  handler(request: Request): Promise<Response>
  /**
   * Checks that this handler is what answers under `basePath` in the running
   * application, and throws `CauthyConfigError` naming the route when another
   * one does. Call it once at startup: with the origin after the server
   * listens (`'http://localhost:3000'`), or with a function that serves a
   * request in process (Hono's `app.fetch`; `checkFastifyMount` for
   * Fastify). Nothing it sends reaches Cauthy.
   */
  checkMount(target: MountTarget): Promise<void>
  /**
   * Who is signed in, or null.
   *
   * Give it the response's headers and a session that needs renewing is
   * renewed on the spot, its new cookie added to them. Without them an
   * expired session reads as null (see `status`): renewing changes the
   * cookie, and a cookie nobody sends back is a session lost.
   */
  getSession(request: Request, responseHeaders?: Headers): Promise<Session | null>
  /** Whether somebody is signed in, nobody is, or the session must be renewed first. */
  status(request: Request): Promise<SessionStatus>
  /**
   * The session, renewed when it has to be, and the cookies to send back.
   * The caller MUST send `cookies` with its response.
   */
  resolve(request: Request): Promise<Resolved>
  /**
   * For a route only a signed-in person may see: the session, or the response
   * to give instead — a redirect to sign in (or to renew) for a page, a 401
   * for anything else.
   */
  protect(request: Request): Promise<{ session: Session; response?: undefined } | { session?: undefined; response: Response }>
  /** The organizations the person belongs to (of `system`, when set), with their role in each. */
  organizations(session: Session): Promise<SessionOrganization[]>
  /**
   * Asks Cauthy whether the signed-in person may do an action on a resource
   * in an organization, with what its conditions read (`attributes`, whose
   * the record is). It is how a permission with a condition is decided —
   * `can` never counts those — and it decides any other the same way.
   *
   *   const r = await auth.check(request, { organization, resource: 'invoices', action: 'approve', attributes: { amount: 500 } })
   *   if (!r.allowed) return forbidden(r.reason)
   *
   * Nobody signed in, an organization the person is not in, or a disabled
   * account answer `allowed: false`. A request whose session must be renewed
   * first reads as nobody signed in: give it the `Session` from
   * `getSession(request, responseHeaders)` instead. Throws `CauthyApiError`
   * when Cauthy refuses the question itself (a malformed one) or cannot be reached.
   */
  check(who: Request | Session, question: CheckQuestion & { organization: OrganizationRef }): Promise<CheckResult>
  /**
   * Verifies a webhook delivery from Cauthy and answers the event it carries;
   * throws `CauthyWebhookError` for anything else. No secret is involved: the
   * delivery is signed with Cauthy's own key.
   */
  webhook(request: Request, options?: Pick<VerifyWebhookOptions, 'jwks' | 'now' | 'url'>): Promise<CauthyEvent>
  /**
   * The application acting on its own, with no person's token: its
   * organizations, their members, invitations. Needs the client's secret, or
   * `systemKey`.
   */
  system: CauthySystem
  /**
   * The application's contract, when it runs by one: what its link says,
   * its own keys, and how it stands against its contract in Cauthy.
   */
  pact?: CauthyPact
  /** What the browser may be told of a session. */
  toPublic(session: Session): Promise<PublicSession>
  /** Paths of this application that start a sign-in, a sign-out, or open the account page. */
  urls: { signIn(returnTo?: string): string; signOut(): string; account(returnTo?: string): string; session: string }
  options: Readonly<Required<Pick<CauthyOptions, 'issuer' | 'clientId' | 'basePath' | 'afterSignIn' | 'afterSignOut' | 'cookieName'>>>
}

/** A contracted application's view of its contract (`auth.pact`). */
export interface CauthyPact {
  /** What its link in the graph says. */
  contract: ResolvedContract
  /** Its own keys: the one that signs, the ones published, rotating them. */
  keys: PactKeys
  /**
   * The response for its jwks_url: the published keys. `handler` serves it
   * at that path too, when the route reaches it.
   */
  jwks(): Promise<Response>
  /** How it stands against its contract, as Cauthy checks it now. For a health endpoint. */
  status(): Promise<PactStatus>
}

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined
}

function hostOf(origin: string): string | undefined {
  try { return new URL(origin).hostname } catch { return undefined }
}

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function random(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)))
}

/**
 * A path of this application, and nothing else: never another site, never
 * `//host`. Browsers drop tabs and line breaks from a URL, so `/\t/evil.test`
 * would become `//evil.test`: control characters are refused outright, and
 * what is left must resolve to this origin.
 */
function localPath(candidate: string | null | undefined, fallback: string): string {
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('\\')) return fallback
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return fallback
  try {
    if (new URL(candidate, 'http://x').origin !== 'http://x') return fallback
  } catch {
    return fallback
  }
  return candidate
}

function json(body: unknown, status = 200, headers?: Headers): Response {
  const h = headers ?? new Headers()
  h.set('content-type', 'application/json; charset=utf-8')
  h.set('cache-control', 'no-store')
  return new Response(JSON.stringify(body), { status, headers: h })
}

function redirect(location: string, cookies: string[] = []): Response {
  const h = new Headers({ location, 'cache-control': 'no-store' })
  for (const c of cookies) h.append('set-cookie', c)
  return new Response(null, { status: 302, headers: h })
}

/** A permission with a condition, as Cauthy lists it with an organization. */
function conditionalOf(c: any): ConditionalPermission {
  return { resource: String(c?.resource ?? ''), action: String(c?.action ?? ''), effect: c?.effect === 'deny' ? 'deny' : 'allow' }
}

/** What a contracted application reads of its contract, its keys and its root key. */
function byContract(given: CauthyOptions): { contract: ResolvedContract; root: string; previous?: string } {
  // Fail closed: one source. Every variable of the standard mode is a second.
  failClosed(typeof process !== 'undefined' ? process.env : undefined)
  for (const [name, value] of [['clientId', given.clientId], ['clientSecret', given.clientSecret], ['secret', given.secret],
    ['system', given.system], ['tenant', given.tenant], ['systemKey', given.systemKey]] as const) {
    if (value !== undefined) throw new CauthyConfigError(`with a contract, ${name} comes from the contract: do not pass it`)
  }
  const contract = readContract(given.contract as NonNullable<CauthyOptions['contract']>)
  const root = given.rootKey ?? env('PACT_ROOT_KEY') ?? ''
  if (root === '') throw new CauthyConfigError('rootKey (PACT_ROOT_KEY) is required with a contract: 32 random bytes, e.g. openssl rand -base64 32')
  if (contract.serviceClientId && !given.keys) {
    throw new CauthyConfigError(`the link ${contract.link} gives ${contract.system} its own identity: pass keys, where its key is kept (@cauthyhq/node/keys)`)
  }
  return { contract, root, previous: given.rootKeyPrevious ?? env('PACT_ROOT_KEY_PREVIOUS') }
}

/** requestHeader: 'warn' says so once per process, whatever number of Cauthy instances run in it. */
let toldOfHeader = false

export function createCauthy(given: CauthyOptions = {}): Cauthy {
  const pacted = given.contract ? byContract(given) : undefined
  const contract = pacted?.contract
  const issuer = withoutTrailingSlashes(given.issuer ?? contract?.issuer ?? env('CAUTHY_ISSUER') ?? '')
  const clientId = contract?.clientId ?? given.clientId ?? env('CAUTHY_CLIENT_ID') ?? ''
  const clientSecret = contract ? undefined : given.clientSecret ?? env('CAUTHY_CLIENT_SECRET')
  const secret = contract ? '' : given.secret ?? env('CAUTHY_SECRET') ?? ''
  const system = contract?.system ?? given.system ?? env('CAUTHY_SYSTEM') ?? ''
  const tenant = contract?.tenant ?? given.tenant ?? env('CAUTHY_TENANT') ?? ''
  if (!/^https?:\/\//.test(issuer)) throw new CauthyConfigError('issuer (CAUTHY_ISSUER) must be Cauthy\'s address, e.g. https://id.example.com')
  if (clientId === '') throw new CauthyConfigError('clientId (CAUTHY_CLIENT_ID) is required')
  if (!contract && secret.length < 32) throw new CauthyConfigError('secret (CAUTHY_SECRET) must be at least 32 characters: it encrypts the session cookie')
  // The keys the cookies are sealed with. By contract, one per job, derived
  // from the root key; otherwise the one CAUTHY_SECRET stands for.
  const derived = pacted ? deriveKeys(pacted.root, pacted.previous) : undefined
  const single: Promise<KeyRing> | undefined = derived ? undefined : keyOf(secret).then(k => [k])
  const cookieKeys = (derived?.cookie ?? single) as Promise<KeyRing>
  const flowKeys = (derived?.flow ?? single) as Promise<KeyRing>
  const ownKeys = derived && given.keys ? pactKeys(given.keys, derived.seal) : undefined
  const baseURL = given.baseURL ?? env('CAUTHY_BASE_URL')
  if (baseURL !== undefined && baseURL !== '' && !/^https?:\/\/[^/]+\/*$/.test(baseURL)) {
    throw new CauthyConfigError('baseURL (CAUTHY_BASE_URL) must be the application\'s public origin, e.g. https://app.example.com')
  }

  const basePath = '/' + (given.basePath ?? '/api/auth').replace(/^\/+|\/+$/g, '')
  const requestHeader = given.requestHeader ?? 'required'
  if (requestHeader !== 'required' && requestHeader !== 'warn') throw new CauthyConfigError("requestHeader must be 'required' or 'warn'")
  const afterSignIn = localPath(given.afterSignIn, '/')
  const afterSignOut = localPath(given.afterSignOut, '/')
  const cookieName = given.cookieName ?? 'cauthy_session'
  const flowCookie = `${cookieName}_flow`
  const againCookie = `${cookieName}_again`
  const stepCookie = `${cookieName}_step`
  const systemTimeout = given.timeouts?.system ?? 2000
  const requestTimeout = given.timeouts?.request ?? 5000
  for (const [name, ms] of [['system', systemTimeout], ['request', requestTimeout]] as const) {
    if (!Number.isFinite(ms) || ms <= 0) throw new CauthyConfigError(`timeouts.${name} must be a positive number of milliseconds`)
  }
  // Every call to Cauthy has a deadline; for the event stream it covers the
  // first response only, and the page that goes away ends the rest.
  const doFetch = deadline(given.fetch, requestTimeout)
  const iconOf = iconFor(issuer)
  const pages = {
    signIn: given.pages?.signIn ? localPath(given.pages.signIn, '/') : undefined,
    resetPassword: given.pages?.resetPassword ? localPath(given.pages.resetPassword, '/') : undefined,
    verifyEmail: given.pages?.verifyEmail ? localPath(given.pages.verifyEmail, '/') : undefined,
    acceptInvite: given.pages?.acceptInvite ? localPath(given.pages.acceptInvite, '/') : undefined,
  }
  // The application acting on its own has no request to read its origin
  // from: its invitations open the application's page only when it was told
  // its public origin.
  const acceptInviteUrl = baseURL && pages.acceptInvite ? `${withoutTrailingSlashes(baseURL)}${pages.acceptInvite}` : undefined
  const ownSystem = createSystem({ issuer, clientId, clientSecret, key: given.systemKey, system: system || undefined, acceptInviteUrl, fetch: given.fetch, timeoutMs: systemTimeout,
    ...(ownKeys ? { keys: ownKeys, keysClientId: contract?.serviceClientId } : {}) })

  // The application's public origin. Without baseURL it is the request's, with
  // the scheme a TLS-terminating proxy (Railway, Fly, Render, a load balancer)
  // says the browser used: the server itself only sees plain http.
  const originOf = (request: Request) => {
    if (baseURL) return withoutTrailingSlashes(baseURL)
    const url = new URL(request.url)
    const proto = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase()
    return proto === 'https' || proto === 'http' ? `${proto}://${url.host}` : url.origin
  }
  const attrs = (request: Request, maxAge?: number): CookieAttributes => ({ secure: originOf(request).startsWith('https://'), maxAge })

  // ── Talking to Cauthy ────────────────────────────────────────────────────

  // `proof`: the system's own headers (passedOn), sent on a code exchange — a
  // contract may ask for them (require_system_proof), so a copied client id
  // is no use on its own.
  async function token(form: Record<string, string>, proof: Record<string, string> = {}): Promise<{ ok: true; body: any } | { ok: false; ended: boolean; code?: string }> {
    const body = new URLSearchParams({ client_id: clientId, ...form })
    if (clientSecret) body.set('client_secret', clientSecret)
    try {
      const res = await doFetch(`${issuer}/v1/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...proof },
        body,
      })
      if (res.ok) return { ok: true, body: await res.json() }
      // 4xx is Cauthy's answer: the grant is no good. Anything else is a
      // failure to ask, and says nothing about the session.
      // Cauthy names why, as an OAuth error (RFC 6749 §5.2) with an extension code.
      const why = (await res.json().catch(() => null)) as { error?: unknown } | null
      return { ok: false, ended: res.status >= 400 && res.status < 500, ...(typeof why?.error === 'string' ? { code: why.error } : {}) }
    } catch {
      return { ok: false, ended: false }
    }
  }

  async function userinfo(accessToken: string): Promise<{ u: SessionUser; tid: string; roles: string[] } | null> {
    try {
      const res = await doFetch(`${issuer}/v1/oauth/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })
      if (!res.ok) return null
      const b = (await res.json()) as Record<string, any>
      return {
        tid: String(b.tid ?? ''),
        roles: Array.isArray(b.roles) ? b.roles.filter((r: unknown) => typeof r === 'string') : [],
        u: {
          id: String(b.sub ?? ''),
          email: String(b.email ?? ''),
          name: String(b.name ?? ''),
          emailVerified: b.email_verified === true,
          restricted: b.restricted === true,
          ...(typeof b.email_verify_by === 'string' ? { emailVerifyBy: b.email_verify_by } : {}),
          ...(typeof b.locale === 'string' && b.locale !== '' ? { locale: b.locale } : {}),
          ...(b.anonymous === true ? { isAnonymous: true } : {}),
        },
      }
    } catch {
      return null
    }
  }

  /** Whether the session stays signed in: as Cauthy says, or as it was when an older Cauthy says nothing. */
  const kindOf = (body: any, was?: Stored): { p?: 1 } =>
    (typeof body?.persistent === 'boolean' ? body.persistent : was?.p === 1) ? { p: 1 } : {}

  /** Best effort: tells Cauthy a refresh token is no longer wanted. */
  async function revoke(refreshToken: string): Promise<void> {
    const form = new URLSearchParams({ client_id: clientId, token: refreshToken })
    if (clientSecret) form.set('client_secret', clientSecret)
    await doFetch(`${issuer}/v1/oauth/revoke`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form }).catch(() => undefined)
  }

  /**
   * A link that requires a verified address lets nobody in on a token whose
   * person has not confirmed it, whatever Cauthy issued. The token itself
   * does not say (verification/rules.md), so this reads the user it came with.
   */
  const unverified = (u: SessionUser) => contract?.requireVerifiedEmail === true && !u.emailVerified

  /** What Cauthy's answer to a token request becomes in the cookie. */
  async function stored(body: any, was?: Stored): Promise<Stored | null> {
    if (typeof body?.access_token !== 'string' || typeof body?.refresh_token !== 'string') return null
    const who = await userinfo(body.access_token)
    if (who === null || who.u.id === '') return null
    if (unverified(who.u)) {
      // Cauthy just issued these tokens: the session they would have started never begins.
      await revoke(body.refresh_token)
      throw new CauthyApiError(403, 'email_not_confirmed', 'Confirm your email address first.')
    }
    const lifetime = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 300
    return { at: body.access_token, rt: body.refresh_token, exp: Math.floor(Date.now() / 1000) + lifetime, ...who, ...kindOf(body, was) }
  }

  function toSession(s: Stored): Session {
    return { user: s.u, tenantId: s.tid, roles: s.roles, accessToken: s.at, expiresAt: new Date(s.exp * 1000).toISOString() }
  }

  // ── The cookie ───────────────────────────────────────────────────────────

  async function read(request: Request): Promise<{ had: Map<string, string>; value: Stored | null; present: boolean }> {
    const had = readCookies(request.headers.get('cookie'))
    const raw = readParts(had, cookieName)
    if (raw === null) return { had, value: null, present: false }
    const value = await unsealAny<Stored>(raw, await cookieKeys)
    const sound = value !== null && typeof value.at === 'string' && typeof value.rt === 'string' && typeof value.exp === 'number'
    return { had, value: sound ? value : null, present: true }
  }

  async function write(request: Request, s: Stored, had: Map<string, string>): Promise<string[]> {
    return writeParts(cookieName, await seal(s, (await cookieKeys)[0]), attrs(request, s.p === 1 ? PERSISTENT_SECONDS : undefined), had)
  }

  const fresh = (s: Stored) => s.exp - Date.now() / 1000 > SKEW_SECONDS

  // One renewal per refresh token at a time in this process: requests that
  // arrive together share it. (Across processes Cauthy gives a few seconds'
  // grace to the same token, for the same reason.)
  const renewing = new Map<string, Promise<Stored | 'ended' | 'unreachable'>>()

  function renew(was: Stored): Promise<Stored | 'ended' | 'unreachable'> {
    let running = renewing.get(was.rt)
    if (running === undefined) {
      const rt = was.rt
      running = (async (): Promise<Stored | 'ended' | 'unreachable'> => {
        const res = await token({ grant_type: 'refresh_token', refresh_token: rt })
        if (!res.ok) return res.ended ? 'ended' : 'unreachable'
        let next: Stored | null
        try {
          next = await stored(res.body, was)
        } catch (err) {
          if (err instanceof CauthyApiError && err.code === 'email_not_confirmed') return 'ended'
          throw err
        }
        if (next !== null) return next
        // Renewed, but who it is could not be read just now. The new tokens
        // are kept all the same — the old refresh token is spent, and losing
        // its successor would lose the session — with what was known before.
        if (typeof res.body?.access_token !== 'string' || typeof res.body?.refresh_token !== 'string') return 'unreachable'
        const lifetime = typeof res.body.expires_in === 'number' && res.body.expires_in > 0 ? res.body.expires_in : 300
        const { p: _, ...rest } = was
        return { ...rest, at: res.body.access_token, rt: res.body.refresh_token, exp: Math.floor(Date.now() / 1000) + lifetime, ...kindOf(res.body, was) }
      })()
      renewing.set(rt, running)
      // A renewal that worked is remembered for a moment, for requests still
      // arriving with the old cookie; one that could not ask is tried again
      // by the next request.
      void running.then((result) => {
        if (result === 'unreachable') return renewing.delete(rt)
        const timer = setTimeout(() => renewing.delete(rt), 5_000)
        ;(timer as { unref?: () => void }).unref?.()
      })
    }
    return running
  }

  async function resolve(request: Request): Promise<Resolved> {
    const { had, value, present } = await read(request)
    if (value === null) {
      // A cookie this key did not make (a rotated secret, a tampered value) is cleared.
      return { session: null, status: 'unauthenticated', cookies: present ? clearParts(cookieName, attrs(request, 0), had) : [] }
    }
    // A session made before the link required a verified address does not outlive the requirement.
    if (unverified(value.u)) return { session: null, status: 'unauthenticated', cookies: clearParts(cookieName, attrs(request, 0), had) }
    if (fresh(value)) return { session: toSession(value), status: 'authenticated', cookies: [] }

    const renewed = await renew(value)
    if (renewed === 'ended') {
      return { session: null, status: 'unauthenticated', cookies: clearParts(cookieName, attrs(request, 0), had) }
    }
    // Cauthy could not be asked: the cookie stays as it is, and the next
    // request tries again. Nobody is let in on an expired token meanwhile.
    if (renewed === 'unreachable') return { session: null, status: 'expired', cookies: [] }
    return { session: toSession(renewed), status: 'authenticated', cookies: await write(request, renewed, had) }
  }

  async function getSession(request: Request, responseHeaders?: Headers): Promise<Session | null> {
    if (responseHeaders === undefined) {
      const { value } = await read(request)
      return value !== null && fresh(value) && !unverified(value.u) ? toSession(value) : null
    }
    const r = await resolve(request)
    for (const c of r.cookies) responseHeaders.append('set-cookie', c)
    return r.session
  }

  async function status(request: Request): Promise<SessionStatus> {
    const { value } = await read(request)
    if (value === null || unverified(value.u)) return 'unauthenticated'
    return fresh(value) ? 'authenticated' : 'expired'
  }

  // ── Organizations ────────────────────────────────────────────────────────

  const orgCache = new Map<string, { at: number; value: SessionOrganization[] }>()

  async function organizations(session: Session): Promise<SessionOrganization[]> {
    const hit = orgCache.get(session.accessToken)
    if (hit && Date.now() - hit.at < ORGANIZATIONS_TTL_MS) return hit.value
    const url = `${issuer}/v1/oauth/organizations${system ? `?system=${encodeURIComponent(system)}` : ''}`
    const res = await doFetch(url, { headers: { authorization: `Bearer ${session.accessToken}` } })
    if (!res.ok) throw new Error(`@cauthyhq/node: reading organizations: ${res.status}`)
    const body = (await res.json()) as { data?: Record<string, any>[] }
    const value = (body.data ?? []).map(
      (o): SessionOrganization => ({
        id: String(o.id),
        system: String(o.system ?? ''),
        name: String(o.name ?? ''),
        kind: String(o.kind ?? ''),
        role: String(o.role ?? ''),
        metadata: (o.metadata as Record<string, JsonValue>) ?? {},
        ...(o.external_id ? { externalId: String(o.external_id) } : {}),
        ...(Array.isArray(o.permissions)
          ? { permissions: o.permissions.map(String), denied: Array.isArray(o.denied) ? o.denied.map(String) : [], conditional: Array.isArray(o.conditional) ? o.conditional.map(conditionalOf) : [] }
          : {}),
      }),
    )
    if (orgCache.size > 5_000) orgCache.clear()
    orgCache.set(session.accessToken, { at: Date.now(), value })
    return value
  }

  // ── Asking Cauthy ────────────────────────────────────────────────────────

  /** Cauthy's decision for the person whose token this is; refusals about the person are a no. */
  async function decide(token: string, question: CheckQuestion & { organization: OrganizationRef }): Promise<CheckResult> {
    const org = organizationIdOf(question.organization)
    if (org === '') return { allowed: false, reason: 'no organization named' }
    const res = await doFetch(`${issuer}/v1/oauth/organizations/${encodeURIComponent(org)}/check`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(checkWire(question)),
    }).catch(() => null)
    if (res === null) throw new CauthyApiError(503, 'unavailable', 'Cauthy could not be reached to check a permission')
    const body = (await res.json().catch(() => null)) as { data?: unknown; errors?: { code?: string; message?: string }[] } | null
    if (res.ok) return checkResultOf(body?.data)
    const first = body?.errors?.[0]
    // About the person, not the question: a token no longer good, an account
    // disabled, an organization they are not in. Each is a plain no.
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      return { allowed: false, reason: first?.message ?? (res.status === 401 ? 'not signed in' : res.status === 404 ? 'not a member of the organization' : 'refused') }
    }
    throw new CauthyApiError(res.status, first?.code ?? 'error', `Cauthy refused to check a permission (${res.status}): ${first?.message ?? res.statusText}`)
  }

  async function check(who: Request | Session, question: CheckQuestion & { organization: OrganizationRef }): Promise<CheckResult> {
    // A Session carries its token; anything else is the request it rides on.
    const session = 'accessToken' in who ? who : await getSession(who)
    if (!session) return { allowed: false, reason: 'not signed in' }
    return decide(session.accessToken, question)
  }

  // The application's own identity, as `auth.system`. A change it makes to who
  // belongs where (a new member, a new role, an organization gone) empties the
  // organizations read above: a person added a moment ago sees the
  // organization on the next page, not a minute later.
  const forgetting = <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
    async (...args: A): Promise<R> => {
      const out = await fn(...args)
      orgCache.clear()
      return out
    }
  const systemThatRefreshes: CauthySystem = {
    ...ownSystem,
    organizations: {
      ...ownSystem.organizations,
      update: forgetting(ownSystem.organizations.update),
      remove: forgetting(ownSystem.organizations.remove),
    },
    members: {
      ...ownSystem.members,
      add: forgetting(ownSystem.members.add),
      setRole: forgetting(ownSystem.members.setRole),
      remove: forgetting(ownSystem.members.remove),
    },
  }

  async function toPublic(session: Session): Promise<PublicSession> {
    let orgs: SessionOrganization[] = []
    try {
      orgs = await organizations(session)
    } catch {
      // The person is signed in all the same; their organizations come back on the next read.
    }
    return { user: session.user, tenantId: session.tenantId, roles: session.roles, organizations: orgs, expiresAt: session.expiresAt }
  }

  // ── Routes ───────────────────────────────────────────────────────────────

  const urls = {
    signIn: (returnTo?: string) => `${basePath}/login${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`,
    signOut: () => `${basePath}/logout`,
    account: (returnTo?: string) => `${basePath}/account${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`,
    session: `${basePath}/session`,
  }

  async function login(request: Request, url: URL): Promise<Response> {
    const flow: Flow = { state: random(), verifier: random(48), returnTo: localPath(url.searchParams.get('return_to'), afterSignIn) }
    const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(flow.verifier))))
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: `${originOf(request)}${basePath}/callback`,
      response_type: 'code',
      state: flow.state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })
    // What the application may ask of the sign-in page: to ask again, and a language.
    const prompt = url.searchParams.get('prompt')
    if (prompt === 'login' || prompt === 'none') q.set('prompt', prompt)
    const locale = url.searchParams.get('locale') ?? url.searchParams.get('ui_locales')
    if (locale && /^[a-zA-Z-]{2,10}$/.test(locale)) q.set('ui_locales', locale)
    // An application whose own page cannot use the person's passkey sends
    // them to Cauthy's for that step alone: a page that asks for the passkey
    // and nothing else, and comes straight back.
    let passkey = ''
    if (url.searchParams.get('method') === 'passkey') {
      q.set('method', 'passkey')
      passkey = '#passkey' // what a Cauthy from before that page reads
    }
    return redirect(`${issuer}/v1/oauth/authorize?${q}${passkey}`, [
      writeCookie(flowCookie, await seal(flow, (await flowKeys)[0]), attrs(request, FLOW_SECONDS)),
    ])
  }

  function failed(request: Request, reason: string): Response {
    const h = new Headers({ 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    h.append('set-cookie', writeCookie(flowCookie, '', attrs(request, 0)))
    h.append('set-cookie', writeCookie(againCookie, '', attrs(request, 0)))
    return new Response(`Sign-in could not be completed (${reason}). Go back and try again.`, { status: 400, headers: h })
  }

  async function callback(request: Request, url: URL): Promise<Response> {
    const had = readCookies(request.headers.get('cookie'))
    const sealed = had.get(flowCookie)
    const flow = sealed ? await unsealAny<Flow>(sealed, await flowKeys) : null
    // The answer must be to a question THIS browser asked: without that, a
    // stranger's link could sign a person in to the stranger's account.
    if (flow === null || url.searchParams.get('state') !== flow.state) {
      // Not this browser's question — or its question was asked so long ago
      // that it is forgotten: the page sat open, or the answer is to an older
      // tab's. Nobody is signed in by it; the sign-in starts again, once. The
      // person is still signed in at Cauthy, so they are not asked twice.
      if (had.get(againCookie) === undefined) {
        const back = flow?.returnTo ?? afterSignIn
        return redirect(`${basePath}/login?return_to=${encodeURIComponent(back)}`, [writeCookie(againCookie, '1', attrs(request, AGAIN_SECONDS))])
      }
      return failed(request, 'state_mismatch')
    }
    const error = url.searchParams.get('error')
    if (error !== null) {
      // prompt=none and nobody signed in: not an error, just "nobody".
      if (error === 'login_required') return redirect(flow.returnTo, [writeCookie(flowCookie, '', attrs(request, 0))])
      // The person went back from Cauthy's page: to the sign-in they came from.
      if (error === 'access_denied') {
        const back = pages.signIn ?? flow.returnTo
        return redirect(`${back}${back.includes('?') ? '&' : '?'}auth_error=cancelled`, [writeCookie(flowCookie, '', attrs(request, 0))])
      }
      return failed(request, error.slice(0, 60))
    }
    const code = url.searchParams.get('code')
    if (!code) return failed(request, 'no_code')
    const res = await token({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${originOf(request)}${basePath}/callback`,
      code_verifier: flow.verifier,
    }, await passedOn(request))
    // Back to the application's sign-in page with the reason, and the question forgotten.
    const unconfirmed = () => {
      const page = pages.signIn ?? '/'
      return redirect(`${page}${page.includes('?') ? '&' : '?'}auth_error=email_not_confirmed`,
        [writeCookie(flowCookie, '', attrs(request, 0)), writeCookie(againCookie, '', attrs(request, 0))])
    }
    // Cauthy refuses at the token endpoint when the client requires a confirmed address…
    if (!res.ok && res.code === 'email_not_confirmed') return unconfirmed()
    let s: Stored | null
    try {
      s = res.ok ? await stored(res.body) : null
    } catch (err) {
      // …and this side checks too, should an older Cauthy not.
      if (!(err instanceof CauthyApiError && err.code === 'email_not_confirmed')) throw err
      return unconfirmed()
    }
    if (s === null) return failed(request, 'exchange_failed')
    return redirect(flow.returnTo, [...(await write(request, s, had)), writeCookie(flowCookie, '', attrs(request, 0)), writeCookie(againCookie, '', attrs(request, 0))])
  }

  async function logout(request: Request): Promise<Response> {
    const { had, value } = await read(request)
    if (value !== null) {
      // Best effort: the session is over here whether or not Cauthy heard.
      const body = new URLSearchParams({ client_id: clientId, token: value.rt })
      if (clientSecret) body.set('client_secret', clientSecret)
      await doFetch(`${issuer}/v1/oauth/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }).catch(() => undefined)
      orgCache.delete(value.at)
    }
    // Then through Cauthy, which ends its own session in this browser too:
    // otherwise the next "sign in" would walk straight back in.
    const q = new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: `${originOf(request)}${afterSignOut}` })
    return redirect(`${issuer}/v1/oauth/logout?${q}`, clearParts(cookieName, attrs(request, 0), had))
  }

  // ── The application's own screens ────────────────────────────────────────
  //
  // The application draws its sign-in, with its own components; these routes
  // do the work behind it. The browser talks to the application's server and
  // to nobody else: the password goes from the form to here and from here to
  // Cauthy, the tokens Cauthy answers with go into the same encrypted cookie
  // as ever, and nothing the browser could keep is sent back to it.

  /** How long a sign-in waits for its second step, or for a provider to answer. */
  const STEP_SECONDS = 600
  /** How long a passkey ceremony waits for the person: Cauthy's own limit. */
  const PASSKEY_SECONDS = 300

  /** How an account takes its second step, as Cauthy says it. */
  const factorsOf = (d: any) => ({
    totp: d?.totp === true,
    phone: d?.phone ? { number: String(d.phone.number ?? ''), channel: String(d.phone.channel ?? 'sms') } : null,
    phoneChannels: Array.isArray(d?.phone_channels) ? d.phone_channels.map(String) : [],
  })

  /** What the browser answered a passkey ceremony with, as JSON. */
  const isCredential = (v: unknown): v is Record<string, unknown> =>
    typeof v === 'object' && v !== null && !Array.isArray(v) && typeof (v as { id?: unknown }).id === 'string' && typeof (v as { response?: unknown }).response === 'object'

  const passkeyOf = (d: any) => ({
    id: String(d?.id ?? ''), name: String(d?.nickname ?? ''),
    kind: ['security_key', 'synced', 'device'].includes(d?.kind) ? d.kind : 'unknown', createdAt: String(d?.created_at ?? ''), lastUsedAt: d?.last_used_at ? String(d.last_used_at) : null,
  })

  const UUID = /^[0-9a-f-]{36}$/i

  /** An organization the person belongs to, with what they may do with it and its people. */
  const seatOf = (d: any) => ({
    id: String(d?.id ?? ''), system: String(d?.system ?? ''), name: String(d?.name ?? ''), kind: String(d?.kind ?? ''), role: String(d?.role ?? ''),
    // A Cauthy from before a power says nothing of it: then it is not given.
    can: {
      readMembers: d?.can?.read_members === true, manageMembers: d?.can?.manage_members === true, removeMembers: d?.can?.remove_members === true,
      update: d?.can?.update === true, archive: d?.can?.archive === true, delete: d?.can?.delete === true,
    },
  })
  /** A person of an organization, as a member who may see them reads it. */
  const orgMemberOf = (d: any) => ({
    userId: String(d?.user_id ?? ''), email: String(d?.email ?? ''), name: String(d?.name ?? ''), role: String(d?.role ?? ''),
    status: String(d?.status ?? ''), invited: d?.invited === true, manager: d?.manager === true, you: d?.you === true, since: String(d?.since ?? ''),
  })
  /** A role of the organization's system that a member may give. */
  const orgRoleOf = (d: any) => ({
    role: String(d?.role ?? ''), name: String(d?.name ?? ''), description: String(d?.description ?? ''), manager: d?.manager === true,
  })

  /** An AI agent the person connected, as Cauthy says it. */
  const agentOf = (d: any) => ({
    id: String(d?.id ?? ''),
    name: String(d?.agent?.name ?? ''),
    redirectHost: String(d?.agent?.redirect_host ?? ''),
    resource: { name: String(d?.resource?.name ?? ''), uri: String(d?.resource?.uri ?? '') },
    scopes: Array.isArray(d?.scopes) ? d.scopes.map((s: any) => ({ name: String(s?.name ?? ''), description: String(s?.description ?? '') })) : [],
    connectedAt: String(d?.created_at ?? ''),
    lastUsedAt: String(d?.last_used_at ?? ''),
  })

  interface Step {
    /** `mfa`: Cauthy asked for a code. `social`: a provider is answering. `link`: a provider is answering to be linked to the signed-in account. `passkey`/`enrol`: a passkey ceremony is under way on the page. `sso`: the person's company is answering; `token` is the PKCE verifier. */
    kind: 'mfa' | 'social' | 'code' | 'link' | 'passkey' | 'enrol' | 'sso' | 'upgrade'
    token: string
    provider?: string
    returnTo: string
    /** The person asked to stay signed in: every call of the sign-in says so to Cauthy. */
    remember?: boolean
  }

  /** A form's yes: true, "1" or "on". */
  const wants = (v: unknown) => v === true || v === '1' || v === 'on' || v === 'true'

  const problem = (status: number, code: string, message: string, field?: string, headers?: Headers, reasons?: string[]) =>
    json({ error: { code, message, ...(field ? { field } : {}), ...(reasons && reasons.length > 0 ? { reasons } : {}) } }, status, headers)

  const invalid = (p: FieldProblem) => problem(400, p.code, p.message, p.field)

  let explained = false

  /**
   * A mutation carries X-Cauthy-Request: 1, which another site cannot add
   * without CORS: the answer to send instead, or null when it may go on.
   */
  function withoutRequestHeader(request: Request, route: string): Response | null {
    if (request.headers.get('x-cauthy-request') === '1') return null
    if (requestHeader === 'warn') {
      if (!toldOfHeader) {
        toldOfHeader = true
        console.warn(`@cauthyhq/node: POST ${basePath}${route} arrived without X-Cauthy-Request: 1 and was let through (requestHeader: 'warn'). ` +
          'Update the browser to cauthy-auth 0.43 or @cauthyhq/js, then remove requestHeader.')
      }
      return null
    }
    return problem(403, 'csrf_required', 'This request did not come from this application\'s own client.')
  }

  /** A request this application's own page made: never another site's form. */
  function ownRequest(request: Request): boolean {
    const origin = request.headers.get('origin')
    if (origin !== null) {
      const own = originOf(request)
      if (origin === own || origin === new URL(request.url).origin) return true
      // The same host on another scheme or port is this application seen
      // through a proxy, not another site: say so once, where it can be fixed.
      if (!explained && hostOf(origin) === new URL(own).hostname) {
        explained = true
        console.warn(`@cauthyhq/node: refused a request from ${origin} as cross_site: this application sees itself as ${own}. ` +
          'Behind a proxy? Set CAUTHY_BASE_URL (or baseURL) to the public origin.')
      }
      return false
    }
    // No Origin: a browser sends one on every cross-site POST, so this is a
    // same-origin form of an old browser, or not a browser at all.
    return (request.headers.get('sec-fetch-site') ?? 'same-origin') === 'same-origin'
  }

  async function body(request: Request): Promise<Record<string, unknown> | null> {
    if (!(request.headers.get('content-type') ?? '').includes('application/json')) return null
    try {
      const b = (await request.json()) as unknown
      return typeof b === 'object' && b !== null && !Array.isArray(b) ? (b as Record<string, unknown>) : null
    } catch {
      return null
    }
  }

  // Every person signing in here reaches Cauthy from this server's address.
  // So the application says whose request it is passing on, and proves it is
  // a system of the workspace with its own token: Cauthy believes the address
  // from nobody else. The proof goes even when the address is unknown (no
  // proxy in front, as in development): it also tells Cauthy which
  // application signed the person in. An application that is no system
  // passes nothing on.
  // By default the address the last proxy wrote that is not the application's
  // own network: a platform may put its own hop (127.0.0.1, 10.x) after it.
  const clientIp = given.clientIp ?? ((request: Request) =>
    request.headers.get('x-forwarded-for')?.split(',').map(a => a.trim()).reverse().find(a => a !== '' && !ownNetwork(a)))
  let noProofUntil = 0
  async function passedOn(request: Request): Promise<Record<string, string>> {
    if (Date.now() < noProofUntil) return {}
    const ip = clientIp(request)
    try {
      // The application's address too: a sign-in at a production one ticks
      // its "In production" step in Cauthy's dashboard.
      const proof = { 'x-cauthy-system-token': await ownSystem.token(), 'x-cauthy-app-origin': originOf(request) }
      return ip ? { ...proof, 'x-cauthy-client-ip': ip } : proof
    } catch {
      // Not a system, or Cauthy is not answering: ask again shortly. Not
      // long: a contract may ask for the proof on every sign-in.
      noProofUntil = Date.now() + 30_000
      return {}
    }
  }

  /** Asks Cauthy's own API, as this workspace's application. */
  async function ask(request: Request, method: string, path: string, payload?: unknown, page?: string, bearer?: string, remember = false): Promise<{ status: number; data: any; error?: { code: string; message: string; reasons?: string[] } }> {
    try {
      const res = await doFetch(`${issuer}${path}`, {
        method,
        headers: {
          'x-tenant-key': tenant,
          accept: 'application/json',
          // A link Cauthy mails opens the application's page for it when it
          // has one; otherwise Cauthy's own. Either way in the reader's language.
          ...(page ? { 'x-cauthy-link-to': `${originOf(request)}${page}` } : { 'x-cauthy-links': 'hosted' }),
          // Whose request it is: what Cauthy mails goes in this application's
          // name, under its logo.
          ...(clientId ? { 'x-cauthy-client-id': clientId } : {}),
          ...(await passedOn(request)),
          ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
          // The person asked to stay signed in: Cauthy keeps the session long if the client allows it.
          ...(remember ? { 'x-cauthy-remember': '1' } : {}),
          // The answer to the workspace's Turnstile challenge, from the
          // person's browser: Cauthy checks it at the doors that ask for it.
          ...(request.headers.get('x-cauthy-captcha') ? { 'x-captcha-token': request.headers.get('x-cauthy-captcha') as string } : {}),
          ...(request.headers.get('accept-language') ? { 'accept-language': request.headers.get('accept-language') as string } : {}),
          // The language the application says its person reads, over the browser's.
          ...(request.headers.get('x-cauthy-locale') ? { 'x-cauthy-locale': request.headers.get('x-cauthy-locale') as string } : {}),
          ...(request.headers.get('user-agent') ? { 'user-agent': request.headers.get('user-agent') as string } : {}),
          ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: payload === undefined ? undefined : JSON.stringify(payload),
      })
      const b = res.status === 204 || res.status === 202 ? null : ((await res.json().catch(() => null)) as any)
      if (res.ok) return { status: res.status, data: b?.data ?? b }
      const first = b?.errors?.[0]
      // weak_password says which rules of the workspace's policy failed.
      const reasons = Array.isArray(first?.meta?.reasons) ? (first.meta.reasons as unknown[]).map(String) : undefined
      return { status: res.status, data: null, error: { code: String(first?.code ?? 'error'), message: String(first?.message ?? 'The request could not be completed.'), ...(reasons ? { reasons } : {}) } }
    } catch {
      return { status: 503, data: null, error: { code: 'unavailable', message: 'Sign-in is unavailable right now. Try again in a moment.' } }
    }
  }

  const accountOf = (d: any) => ({
    id: String(d?.id ?? ''), email: String(d?.email ?? ''), name: String(d?.name ?? ''),
    emailVerified: d?.email_verified === true, hasPassword: d?.has_password === true, mfaEnabled: d?.mfa_enabled === true,
  })

  /**
   * Who is signed in, for a route about their own account: their token, and
   * the cookie to send back when the session had to be renewed. Nobody signed
   * in gets the 401 to answer with.
   */
  async function signedInAs(request: Request): Promise<{ token: string; kept: Stored | null; headers: Headers } | { response: Response }> {
    const r = await resolve(request)
    const headers = new Headers()
    for (const c of r.cookies) headers.append('set-cookie', c)
    if (r.session === null) return { response: problem(401, 'unauthenticated', 'Sign in first.', undefined, headers) }
    // `kept` is the session as the request's cookie holds it, or null when it
    // was renewed just now: then the cookies above carry the new one.
    return { token: r.session.accessToken, kept: r.cookies.length === 0 ? (await read(request)).value : null, headers }
  }

  /** Cauthy answered with tokens: the person is signed in here. */
  async function signedIn(request: Request, tokens: any, extra: string[] = [], more: Record<string, unknown> = {}, was?: Stored): Promise<Response> {
    const s = await stored(tokens, was)
    if (s === null) return problem(502, 'unavailable', 'Sign-in is unavailable right now. Try again in a moment.')
    const h = new Headers()
    for (const c of [...(await write(request, s, readCookies(request.headers.get('cookie')))), ...extra]) h.append('set-cookie', c)
    return json({ status: 'signed_in', session: await toPublic(toSession(s)), ...more }, 200, h)
  }

  /**
   * Cauthy's answer to a sign-in with a password: the person is signed in, or
   * the second step is asked for next. Then what proves the password was
   * right stays here, sealed, and never reaches the page.
   */
  async function loggedIn(request: Request, data: any, remember = false): Promise<Response> {
    if (data?.mfa_required === true) {
      const step: Step = { kind: 'mfa', token: String(data.mfa_token ?? ''), returnTo: afterSignIn, ...(remember ? { remember } : {}) }
      // By email: the account has no factor and a code was just mailed to it.
      const how = data.mfa_method === 'email' ? { method: 'email' } : {}
      return json({ status: 'mfa_required', ...how }, 200, new Headers({ 'set-cookie': writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS)) }))
    }
    return signedIn(request, data)
  }

  let lookCache: { until: number; look: Record<string, unknown> } | null = null

  // The workspace's password policy, kept a minute like the look: what a new
  // password is checked against here before it is sent. Cauthy checks it
  // again, and alone knows whether a password was in a breach.
  let policyCache: { until: number; policy: PasswordPolicy | null } | null = null
  const keepPolicy = (settings: { data: any; error?: unknown }) => {
    policyCache = { until: Date.now() + LOOK_TTL_MS, policy: settings.error || !settings.data?.password_policy ? null : passwordPolicyOf(settings.data.password_policy) }
    return policyCache.policy
  }
  /** The workspace's password policy; null when Cauthy cannot say, and then only Cauthy checks. */
  async function workspacePolicy(request: Request): Promise<PasswordPolicy | null> {
    if (policyCache !== null && policyCache.until >= Date.now()) return policyCache.policy
    return keepPolicy(await ask(request, 'GET', '/v1/auth/settings'))
  }
  /** A new password, checked here against the workspace's rule when it is known. */
  async function newPasswordProblem(request: Request, value: unknown): Promise<FieldProblem | null> {
    const policy = await workspacePolicy(request)
    // Not known: only what no workspace accepts is refused here (8–128).
    return checkNewPassword(value, policy ?? { min: 8, max: 128, requires: [], min_classes: 0, reject_breached: false })
  }

  async function ownRoute(request: Request, url: URL, route: string): Promise<Response | null> {
    const post = request.method === 'POST'
    const own = ['/sign-in/email', '/sign-in/mfa', '/sign-up/email', '/forgot-password', '/reset-password', '/verify-email', '/sign-in/magic-link', '/sign-in/magic-link/verify', '/sign-in/email-code', '/me', '/me/password', '/me/mfa/setup', '/me/mfa/verify', '/me/mfa/disable', '/me/mfa/recovery-codes', '/me/mfa/factors', '/me/mfa/phone', '/me/mfa/phone/verify', '/me/mfa/phone/remove', '/sign-in/mfa/methods', '/sign-in/mfa/send', '/sign-in/mfa/email', '/sign-in/mfa/push', '/sign-in/mfa/push/events', '/sign-in/mfa/push/finish', '/me/sessions', '/me/sessions/end', '/me/legal', '/me/legal/accept', '/me/email', '/me/identities', '/me/identities/unlink', '/sign-out', '/methods', '/look',
      '/sign-in/passkey/begin', '/sign-in/passkey/finish', '/sign-in/google-one-tap/begin', '/sign-in/google-one-tap', '/me/passkeys', '/me/passkeys/add/begin', '/me/passkeys/add/finish', '/me/passkeys/remove', '/me/agents', '/me/agents/disconnect',
      '/sign-in/anonymous', '/me/upgrade',
      '/me/organizations', '/me/organizations/members', '/me/organizations/roles', '/me/organizations/members/add', '/me/organizations/members/role', '/me/organizations/members/remove', '/me/organizations/members/invite',
      '/me/organizations/rename', '/me/organizations/archive', '/me/organizations/delete',
      '/invitation', '/invitation/accept'].includes(route) ||
      route.startsWith('/sign-in/social/') || route.startsWith('/callback/') || route.startsWith('/me/identities/link/') || route.startsWith('/me/upgrade/social/') ||
      route === '/sign-in/sso' || route === '/sign-in/sso/discover' || route === '/sso/callback'
    if (!own) return null
    if (post) {
      const refused = withoutRequestHeader(request, route)
      if (refused) return refused
    }
    // Guest sessions and their upgrade leave the protocol in version 2.
    if (route === '/sign-in/anonymous' || route === '/me/upgrade') deprecated(`POST ${route}`, 'Guest sessions leave the auth-bff protocol in version 2.')
    if (route.startsWith('/me/upgrade/social/')) deprecated('GET /me/upgrade/social/{provider}', 'Guest sessions leave the auth-bff protocol in version 2.')
    if (tenant === '') {
      return problem(500, 'not_configured', '@cauthyhq/node: tenant (CAUTHY_TENANT) is required for the application\'s own sign-in screens')
    }

    // How the forms look, as a person set it in Cauthy's dashboard. Kept a
    // minute: every form of every page reads it.
    if (route === '/look' && !post) {
      if (lookCache === null || lookCache.until < Date.now()) {
        const res = await ask(request, 'GET', `/v1/auth/look/${encodeURIComponent(clientId)}`)
        lookCache = { until: Date.now() + LOOK_TTL_MS, look: res.error ? {} : (res.data ?? {}) }
      }
      return json(lookCache.look)
    }

    // What the screen may offer: which providers, whether people may register.
    if (route === '/methods' && !post) {
      const [providers, settings, place, sso] = await Promise.all([
        ask(request, 'GET', '/v1/auth/social/providers'),
        ask(request, 'GET', '/v1/auth/settings'),
        ask(request, 'GET', `/v1/auth/webauthn/place?origin=${encodeURIComponent(originOf(request))}`),
        ask(request, 'GET', '/v1/auth/sso/connections'),
      ])
      const list = Array.isArray(providers.data) ? providers.data : []
      const password = keepPolicy(settings)
      // Passkeys the workspace turned off are offered nowhere: not the
      // button, not the email field's autofill, not Cauthy's page.
      const passkeys = settings.data?.allow_passkeys !== false
      // Where the person uses a passkey: on this page, or on Cauthy's for that
      // step alone. A Cauthy that cannot say yet has them on its page.
      const here = passkeys && place.data?.here === true
      return json({
        providers: list.map((p: any) => ({ id: String(p.provider ?? p.id ?? ''), name: String(p.label ?? p.name ?? p.provider ?? ''), ...iconOf(p) })).filter((p: { id: string }) => p.id !== ''),
        // Whether the workspace signs people in with a password at all. A
        // Cauthy from before the setting says nothing of it: then it does.
        passwordSignIn: settings.data?.allow_password !== false,
        // The workspace's switch, and how the application's own system takes sign-ups.
        signUp: settings.data?.allow_signup !== false && settings.data?.signup?.mode !== 'invite_only',
        // The application's system makes an organization per sign-up: the form asks the company's name.
        ...(settings.data?.signup?.organization?.ask === true
          ? { organization: { ask: true, required: settings.data.signup.organization.required === true } }
          : {}),
        // Whether the person may ask to stay signed in: the client's choice in Cauthy.
        ...(typeof settings.data?.persistent_sessions === 'boolean' ? { persistentSessions: settings.data.persistent_sessions } : {}),
        // A sign-in link needs a page of the application to open.
        magicLink: settings.data?.allow_magic_link === true && pages.signIn !== undefined,
        passkey: passkeys && (place.error ? true : here || place.data?.on_cauthy === true),
        passkeyHere: here,
        passkeyOnCauthy: passkeys && (place.error ? true : place.data?.on_cauthy === true),
        // A company's sign-in, found by the person's work address.
        sso: Array.isArray(sso.data) && sso.data.some((c: any) => c?.discoverable === true),
        // The terms a sign-up accepts and the consents it answers, when the workspace asks any.
        ...(settings.data?.legal ? { legal: legalOf(settings.data.legal) } : {}),
        ...(settings.data?.captcha_enabled === true && settings.data?.captcha_site_key ? { captchaSiteKey: String(settings.data.captcha_site_key) } : {}),
        // What a new password must be: for the form to say it and check it.
        ...(password ? { password } : {}),
      })
    }

    // An invitation, read before the person chooses a password: who is invited
    // to what. Reading it does not spend it.
    if (route === '/invitation' && !post) {
      const token = (url.searchParams.get('token') ?? '').trim()
      if (token === '' || token.length > 512) return problem(422, 'invalid_token', 'This invitation is not valid, or it has expired.')
      const res = await ask(request, 'GET', `/v1/auth/invitation?token=${encodeURIComponent(token)}`)
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      const organization = typeof res.data?.organization === 'string' && res.data.organization !== '' ? { organization: res.data.organization } : {}
      return json({ status: 'ok', invitation: { email: String(res.data?.email ?? ''), workspace: String(res.data?.workspace ?? ''), ...organization } })
    }

    // The person's company: to its IdP and back. Cauthy ends the flow on
    // this site's page with a code, which only the browser holding the
    // sealed PKCE verifier can trade for the session.
    if (route === '/sign-in/sso' && !post) {
      const returnTo = localPath(url.searchParams.get('return_to'), afterSignIn)
      const failed = (code: string) => redirect(`${returnTo}${returnTo.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(code)}`)
      const email = (url.searchParams.get('email') ?? '').trim()
      const connection = (url.searchParams.get('connection') ?? '').trim()
      if (email === '' && connection === '') return failed('sso_not_found')
      const verifier = random(48)
      const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
      const callback = `${basePath}/sso/callback`
      const remember = wants(url.searchParams.get('remember'))
      const started = await ask(request, 'POST', '/v1/auth/sso/start', {
        ...(connection ? { connection } : { email }),
        redirect_uri: `${originOf(request)}${callback}`, code_challenge: challenge,
      }, callback, undefined, remember)
      if (started.error || typeof started.data?.redirect_url !== 'string') return failed(started.error?.code ?? 'sso_unavailable')
      const step: Step = { kind: 'sso', token: verifier, returnTo, ...(remember ? { remember } : {}) }
      return redirect(started.data.redirect_url, [writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS))])
    }
    if (route === '/sso/callback' && !post) {
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      const clear = writeCookie(stepCookie, '', attrs(request, 0))
      const back = step?.returnTo ?? afterSignIn
      const failedTo = (code: string) => redirect(`${back}${back.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(code)}`, [clear])
      if (step === null || step.kind !== 'sso') return failedTo('state_mismatch')
      const refused = url.searchParams.get('error')
      if (refused) return failedTo(refused)
      const code = url.searchParams.get('code')
      if (!code) return failedTo('sso_failed')
      const done = await ask(request, 'POST', '/v1/auth/sso/token', { code, redirect_uri: `${originOf(request)}${basePath}/sso/callback`, code_verifier: step.token }, undefined, undefined, step.remember === true)
      if (done.error) return failedTo(done.error.code)
      const s = await stored(done.data)
      if (s === null) return failedTo('unavailable')
      return redirect(back, [...(await write(request, s, readCookies(request.headers.get('cookie')))), clear])
    }

    // A provider: to it and back. The state is this browser's, kept sealed.
    if (route.startsWith('/sign-in/social/') && !post) {
      const provider = providerIn(route.slice('/sign-in/social/'.length))
      if (!PROVIDER_ID.test(provider)) return new Response('Not found', { status: 404 })
      const returnTo = localPath(url.searchParams.get('return_to'), afterSignIn)
      const callback = `${basePath}/callback/${provider}`
      // The callback is named as this client's page, so a provider that
      // answers through Cauthy's relay (Apple) may return the browser to it.
      const remember = wants(url.searchParams.get('remember'))
      const started = await ask(request, 'GET', `/v1/auth/social/${provider}?redirect_uri=${encodeURIComponent(`${originOf(request)}${callback}`)}`, undefined, callback, undefined, remember)
      if (started.error || typeof started.data?.redirect_url !== 'string') {
        return redirect(`${returnTo}${returnTo.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(started.error?.code ?? 'provider_unavailable')}`)
      }
      const step: Step = { kind: 'social', token: String(started.data.state ?? ''), provider, returnTo, ...(remember ? { remember } : {}) }
      return redirect(started.data.redirect_url, [writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS))])
    }
    if (route.startsWith('/callback/') && !post) {
      const provider = providerIn(route.slice('/callback/'.length))
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      const clear = writeCookie(stepCookie, '', attrs(request, 0))
      const back = step?.returnTo ?? afterSignIn
      const failedTo = (code: string) => redirect(`${back}${back.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(code)}`, [clear])
      // The answer must be to the question this browser asked of this provider.
      if (step === null || (step.kind !== 'social' && step.kind !== 'link' && step.kind !== 'upgrade') || step.provider !== provider || url.searchParams.get('state') !== step.token) return failedTo('state_mismatch')
      const code = url.searchParams.get('code')
      if (!code) return failedTo(url.searchParams.get('error') === 'access_denied' ? 'cancelled' : 'provider_refused')
      const q = new URLSearchParams({ code, state: step.token, redirect_uri: `${originOf(request)}${basePath}/callback/${provider}` })
      if (step.kind === 'upgrade') {
        // The guest is now the account of that address: its session from here on.
        const mine = await signedInAs(request)
        if ('response' in mine) return failedTo('unauthenticated')
        const done = await ask(request, 'GET', `/v1/auth/anonymous/upgrade/${provider}/callback?${q}`, undefined, undefined, mine.token)
        if (done.error) return failedTo(done.error.code)
        const s = await stored(done.data, (await read(request)).value ?? undefined)
        if (s === null) return failedTo('unavailable')
        return redirect(back, [...(await write(request, s, readCookies(request.headers.get('cookie')))), clear])
      }
      if (step.kind === 'link') {
        // Linked to the account signed in here, and back to where it was asked.
        const mine = await signedInAs(request)
        if ('response' in mine) return failedTo('unauthenticated')
        const linked = await ask(request, 'GET', `/v1/auth/identities/${provider}/link/callback?${q}`, undefined, undefined, mine.token)
        if (linked.error) return failedTo(linked.error.code)
        const h = new Headers(mine.headers)
        h.append('set-cookie', clear)
        return redirect(`${back}${back.includes('?') ? '&' : '?'}linked=${encodeURIComponent(provider)}`, [...h.getSetCookie()])
      }
      const done = await ask(request, 'GET', `/v1/auth/social/${provider}/callback?${q}`, undefined, undefined, undefined, step.remember === true)
      if (done.error) return failedTo(done.error.code)
      const s = await stored(done.data)
      if (s === null) return failedTo('unavailable')
      return redirect(back, [...(await write(request, s, readCookies(request.headers.get('cookie')))), clear])
    }

    // A guest becoming the account of a provider's address: to it and back.
    if (route.startsWith('/me/upgrade/social/') && !post) {
      const provider = providerIn(route.slice('/me/upgrade/social/'.length))
      if (!PROVIDER_ID.test(provider)) return new Response('Not found', { status: 404 })
      const returnTo = localPath(url.searchParams.get('return_to'), afterSignIn)
      const failed = (code: string) => redirect(`${returnTo}${returnTo.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(code)}`)
      const mine = await signedInAs(request)
      if ('response' in mine) return failed('unauthenticated')
      const callback = `${basePath}/callback/${provider}`
      const started = await ask(request, 'GET', `/v1/auth/anonymous/upgrade/${provider}?redirect_uri=${encodeURIComponent(`${originOf(request)}${callback}`)}`, undefined, callback, mine.token)
      if (started.error || typeof started.data?.redirect_url !== 'string') return failed(started.error?.code ?? 'provider_unavailable')
      const step: Step = { kind: 'upgrade', token: String(started.data.state ?? ''), provider, returnTo }
      return redirect(started.data.redirect_url, [...mine.headers.getSetCookie(), writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS))])
    }

    // A provider linked to the signed-in account: to it and back, like a sign-in.
    if (route.startsWith('/me/identities/link/') && !post) {
      const provider = providerIn(route.slice('/me/identities/link/'.length))
      if (!PROVIDER_ID.test(provider)) return new Response('Not found', { status: 404 })
      const returnTo = localPath(url.searchParams.get('return_to'), afterSignIn)
      const failed = (code: string) => redirect(`${returnTo}${returnTo.includes('?') ? '&' : '?'}auth_error=${encodeURIComponent(code)}`)
      const mine = await signedInAs(request)
      if ('response' in mine) return failed('unauthenticated')
      const callback = `${basePath}/callback/${provider}`
      const started = await ask(request, 'GET', `/v1/auth/identities/${provider}/link?redirect_uri=${encodeURIComponent(`${originOf(request)}${callback}`)}`, undefined, callback, mine.token)
      if (started.error || typeof started.data?.redirect_url !== 'string') return failed(started.error?.code ?? 'provider_unavailable')
      const step: Step = { kind: 'link', token: String(started.data.state ?? ''), provider, returnTo }
      return redirect(started.data.redirect_url, [...mine.headers.getSetCookie(), writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS))])
    }

    // The person's own account: read here, changed below.
    if (route === '/me/identities' && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const res = await ask(request, 'GET', '/v1/auth/identities', undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      const list = Array.isArray(res.data) ? res.data : []
      return json({ identities: list.map((x: any) => ({ provider: String(x.provider ?? ''), email: String(x.email ?? ''), name: String(x.name ?? ''), linkedAt: String(x.linked_at ?? '') })) }, 200, mine.headers)
    }
    if (route === '/me/passkeys' && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const res = await ask(request, 'GET', '/v1/auth/webauthn/credentials', undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      const list = Array.isArray(res.data) ? res.data : []
      return json({ passkeys: list.map(passkeyOf) }, 200, mine.headers)
    }
    // The AI agents the person connected.
    if (route === '/me/agents' && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const res = await ask(request, 'GET', '/v1/auth/me/agents', undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      const list = Array.isArray(res.data) ? res.data : []
      return json({ agents: list.map(agentOf) }, 200, mine.headers)
    }
    // The person's organizations, and the people of one: as far as their
    // role in the system's catalog lets them see (cauthy:members read).
    if ((route === '/me/organizations' || route === '/me/organizations/members' || route === '/me/organizations/roles') && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      let path = '/v1/auth/me/organizations'
      if (route !== '/me/organizations') {
        const id = url.searchParams.get('id') ?? ''
        if (!UUID.test(id)) return problem(400, 'invalid_organization', 'Say which organization.', undefined, mine.headers)
        path += `/${id}/${route.endsWith('/roles') ? 'roles' : 'members'}`
      } else if (url.searchParams.get('system')) {
        path += `?system=${encodeURIComponent(url.searchParams.get('system')!)}`
      }
      const res = await ask(request, 'GET', path, undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      const list = Array.isArray(res.data) ? res.data : []
      if (route === '/me/organizations') return json({ organizations: list.map(seatOf) }, 200, mine.headers)
      if (route === '/me/organizations/roles') return json({ roles: list.map(orgRoleOf) }, 200, mine.headers)
      return json({ members: list.map(orgMemberOf) }, 200, mine.headers)
    }
    // How the account takes its second step, and what the workspace offers.
    if (route === '/me/mfa/factors' && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const res = await ask(request, 'GET', '/v1/auth/mfa/factors', undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      return json(factorsOf(res.data), 200, mine.headers)
    }
    if ((route === '/me' || route === '/me/sessions' || route === '/me/legal') && !post) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const res = await ask(request, 'GET', route === '/me' ? '/v1/auth/me' : route === '/me/legal' ? '/v1/auth/me/legal' : '/v1/auth/me/sessions', undefined, undefined, mine.token)
      if (res.error) return problem(res.status, res.error.code, res.error.message, undefined, mine.headers)
      // The legal documents the person has not accepted in their current version.
      if (route === '/me/legal') {
        const list = Array.isArray(res.data?.pending) ? res.data.pending : []
        return json({ pending: list.map((d: any) => ({ kind: String(d.kind ?? ''), version: String(d.version ?? ''), url: String(d.url ?? '') })) }, 200, mine.headers)
      }
      if (route === '/me/sessions') {
        const list = Array.isArray(res.data) ? res.data : []
        return json({ sessions: list.map((x: any) => ({ device: String(x.device ?? ''), ip: String(x.ip ?? ''), createdAt: String(x.created_at ?? ''), expiresAt: String(x.expires_at ?? '') })) }, 200, mine.headers)
      }
      return json({ account: accountOf(res.data) }, 200, mine.headers)
    }

    // The phone's answer to a push, as it comes: Cauthy's server-sent events,
    // passed through to the page that waits on them.
    if (route === '/sign-in/mfa/push/events' && !post) {
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'mfa') return problem(400, 'step_expired', 'Sign in again: the code was asked for too long ago.')
      let upstream: Response
      try {
        upstream = await doFetch(`${issuer}/v1/auth/mfa/push/events`, {
          headers: { 'x-tenant-key': tenant, 'x-mfa-token': step.token, accept: 'text/event-stream' },
          signal: request.signal,
        })
      } catch {
        return problem(503, 'unavailable', 'Cauthy could not be reached.')
      }
      if (!upstream.ok || !upstream.body) {
        const b = (await upstream.json().catch(() => null)) as any
        return problem(upstream.status, String(b?.errors?.[0]?.code ?? 'error'), String(b?.errors?.[0]?.message ?? 'The request could not be completed.'))
      }
      return new Response(upstream.body, {
        status: 200,
        headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-store', 'x-accel-buffering': 'no' },
      })
    }

    if (!post) return new Response('Method not allowed', { status: 405, headers: { allow: 'POST' } })
    if (!ownRequest(request)) return problem(403, 'cross_site', 'This request did not come from this application.')

    if (route === '/sign-out') {
      const { had, value } = await read(request)
      if (value !== null) {
        const form = new URLSearchParams({ client_id: clientId, token: value.rt })
        if (clientSecret) form.set('client_secret', clientSecret)
        await doFetch(`${issuer}/v1/oauth/revoke`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form }).catch(() => undefined)
        orgCache.delete(value.at)
      }
      const h = new Headers()
      for (const c of clearParts(cookieName, attrs(request, 0), had)) h.append('set-cookie', c)
      return json({ status: 'signed_out' }, 200, h)
    }

    const b = await body(request)
    if (b === null) return problem(400, 'bad_request', 'Send the form as JSON.')

    // Which company's sign-in an address uses, if any: said of its domain,
    // never of whether the address has an account.
    if (route === '/sign-in/sso/discover') {
      const bad = checkEmail(b.email)
      if (bad) return invalid(bad)
      const res = await ask(request, 'POST', '/v1/auth/sso/discover', { email: String(b.email).trim() })
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      const c = res.data?.connection
      return json(c ? { status: 'found', connection: { id: String(c.slug ?? ''), name: String(c.display_name ?? ''), enforced: c.enforced === true } } : { status: 'none' })
    }

    // A guest session, before the visitor signs up (the workspace's allow_anonymous).
    if (route === '/sign-in/anonymous') {
      if (!post) return new Response('Method not allowed', { status: 405, headers: { allow: 'POST' } })
      const res = await ask(request, 'POST', '/v1/auth/anonymous', {})
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return signedIn(request, res.data)
    }

    if (route === '/sign-in/email') {
      const bad = firstProblem(checkEmail(b.email), checkPassword(b.password))
      if (bad) return invalid(bad)
      const remember = wants(b.remember)
      const res = await ask(request, 'POST', '/v1/auth/login', { email: String(b.email).trim(), password: b.password }, undefined, undefined, remember)
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return loggedIn(request, res.data, remember)
    }

    if (route === '/sign-in/mfa') {
      const bad = checkCode(b.code)
      if (bad) return invalid(bad)
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'mfa') return problem(400, 'step_expired', 'Sign in again: the code was asked for too long ago.')
      const res = await ask(request, 'POST', '/v1/auth/mfa/challenge', { mfa_token: step.token, code: String(b.code).trim() }, undefined, undefined, step.remember === true)
      if (res.error) return problem(res.status, res.error.code, res.error.message, 'code')
      return signedIn(request, res.data, [writeCookie(stepCookie, '', attrs(request, 0))])
    }

    // The second step by phone, while signing in: which ways the account has,
    // and a code sent to its phone. The challenge's token stays sealed here.
    // The second step approved on the phone: a push, then the sign-in once the
    // phone approved it (the answer itself streams from /sign-in/mfa/push/events).
    if (route === '/sign-in/mfa/push' || route === '/sign-in/mfa/push/finish') {
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'mfa') return problem(400, 'step_expired', 'Sign in again: the code was asked for too long ago.')
      if (route === '/sign-in/mfa/push') {
        const res = await ask(request, 'POST', '/v1/auth/mfa/push', { mfa_token: step.token }, undefined, undefined, step.remember === true)
        if (res.error) return problem(res.status, res.error.code, res.error.message)
        return json({ status: 'sent', number: Number(res.data?.number ?? 0) })
      }
      const res = await ask(request, 'POST', '/v1/auth/mfa/challenge', { mfa_token: step.token, push: true }, undefined, undefined, step.remember === true)
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return signedIn(request, res.data, [writeCookie(stepCookie, '', attrs(request, 0))])
    }

    if (route === '/sign-in/mfa/methods' || route === '/sign-in/mfa/send' || route === '/sign-in/mfa/email') {
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'mfa') return problem(400, 'step_expired', 'Sign in again: the code was asked for too long ago.')
      if (route === '/sign-in/mfa/methods') {
        const res = await ask(request, 'POST', '/v1/auth/mfa/methods', { mfa_token: step.token }, undefined, undefined, step.remember === true)
        if (res.error) return problem(res.status, res.error.code, res.error.message)
        const p = res.data?.phone
        const push = res.data?.push
        const mail = res.data?.email
        return json({ status: 'ok', totp: res.data?.totp === true, phone: p ? { number: String(p.number ?? ''), channel: String(p.channel ?? 'sms') } : null,
          push: push ? { devices: Number(push.devices ?? 0) } : null, email: mail ? { to: String(mail.to ?? '') } : null })
      }
      if (route === '/sign-in/mfa/email') {
        const res = await ask(request, 'POST', '/v1/auth/mfa/email', { mfa_token: step.token }, undefined, undefined, step.remember === true)
        if (res.error) return problem(res.status, res.error.code, res.error.message)
        return json({ status: 'sent', sentTo: String(res.data?.sent_to ?? '') })
      }
      const res = await ask(request, 'POST', '/v1/auth/mfa/send', { mfa_token: step.token }, undefined, undefined, step.remember === true)
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return json({ status: 'sent', sentTo: String(res.data?.sent_to ?? ''), channel: String(res.data?.channel ?? 'sms') })
    }

    if (route === '/sign-up/email') {
      const bad = firstProblem(checkName(b.name), checkEmail(b.email), await newPasswordProblem(request, b.password), checkOrganization(b.organization))
      if (bad) return invalid(bad)
      const email = String(b.email).trim()
      // The company's name, when the application's system makes an organization per sign-up.
      const organization = typeof b.organization === 'string' && b.organization.trim() !== '' ? { organization: { name: b.organization.trim() } } : {}
      // The terms accepted and the consents answered, when the workspace asks any (methods().legal).
      const legal = { ...(b.acceptLegal === true ? { accept_legal: true } : {}), ...(b.consents && typeof b.consents === 'object' ? { consents: b.consents } : {}) }
      const made = await ask(request, 'POST', '/v1/auth/register', { email, password: b.password, display_name: typeof b.name === 'string' ? b.name.trim() : '', ...organization, ...legal }, pages.verifyEmail)
      if (made.error) return problem(made.status, made.error.code, made.error.message, made.error.code === 'weak_password' ? 'password' : undefined, undefined, made.error.reasons)
      // An account that must confirm its address first cannot sign in yet.
      if (made.data?.verification_required === true) return json({ status: 'verification_required', email })
      const res = await ask(request, 'POST', '/v1/auth/login', { email, password: b.password })
      if (res.error || res.data?.mfa_required === true) return json({ status: 'verification_required', email })
      return signedIn(request, res.data)
    }

    if (route === '/forgot-password') {
      const bad = checkEmail(b.email)
      if (bad) return invalid(bad)
      // The same answer whether or not the address has an account.
      await ask(request, 'POST', '/v1/auth/password/reset', { email: String(b.email).trim() }, pages.resetPassword)
      return json({ status: 'sent' })
    }

    if (route.startsWith('/me')) {
      const mine = await signedInAs(request)
      if ('response' in mine) return mine.response
      const as = (path: string, payload?: unknown, method = 'POST') => ask(request, method, path, payload, undefined, mine.token)
      const refused = (res: { status: number; error?: { code: string; message: string; reasons?: string[] } }, field?: string) =>
        problem(res.status, res.error!.code, res.error!.message, field, mine.headers, res.error!.reasons)
      // Asked again for what weakens the account; an account with no password sends none.
      const password = typeof b.password === 'string' ? b.password : ''

      if (route === '/me') {
        const bad = checkName(b.name)
        if (bad) return invalid(bad)
        const res = await as('/v1/auth/me', { name: typeof b.name === 'string' ? b.name.trim() : '' }, 'PATCH')
        if (res.error) return refused(res, 'name')
        // The name is part of the session: the cookie says the new one at once.
        const h = mine.headers
        if (mine.kept !== null) {
          const again = await stored({ access_token: mine.kept.at, refresh_token: mine.kept.rt, expires_in: Math.max(1, mine.kept.exp - Math.floor(Date.now() / 1000)) }, mine.kept)
          if (again !== null) for (const c of await write(request, again, readCookies(request.headers.get('cookie')))) h.append('set-cookie', c)
        }
        return json({ status: 'saved', account: accountOf(res.data) }, 200, h)
      }
      if (route === '/me/legal/accept') {
        const kinds = Array.isArray(b.kinds) ? b.kinds.filter((k: unknown) => typeof k === 'string') : []
        const res = await as('/v1/auth/me/legal/accept', { kinds })
        if (res.error) return refused(res)
        return json({ status: 'accepted' }, 200, mine.headers)
      }
      if (route === '/me/password') {
        const bad = await newPasswordProblem(request, b.newPassword)
        if (bad) return problem(400, bad.code, bad.message, 'newPassword')
        const res = await as('/v1/auth/me/password', { current_password: password, new_password: b.newPassword })
        if (res.error) return refused(res, res.error.code === 'wrong_password' ? 'password' : res.error.code === 'weak_password' ? 'newPassword' : undefined)
        // The change ended every session of the account. Cauthy answered with
        // a new one for this browser, which just proved the password.
        const next = await stored(res.data, (await read(request)).value ?? undefined)
        const h = new Headers()
        const had = readCookies(request.headers.get('cookie'))
        for (const c of next !== null ? await write(request, next, had) : clearParts(cookieName, attrs(request, 0), had)) h.append('set-cookie', c)
        return json({ status: 'changed', signedIn: next !== null }, 200, h)
      }
      if (route === '/me/mfa/setup') {
        const res = await as('/v1/auth/mfa/setup', { password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : undefined)
        // The QR comes drawn by Cauthy; only a PNG data: URI goes on to the page.
        const qr = String(res.data?.qr ?? '')
        return json({ status: 'started', secret: String(res.data?.secret ?? ''), otpauthUri: String(res.data?.otpauth_uri ?? ''), qr: qr.startsWith('data:image/png;base64,') ? qr : '' }, 200, mine.headers)
      }
      if (route === '/me/mfa/verify') {
        const bad = checkCode(b.code)
        if (bad) return invalid(bad)
        const res = await as('/v1/auth/mfa/verify', { code: String(b.code).trim() })
        if (res.error) return refused(res, 'code')
        return json({ status: 'enabled', recoveryCodes: Array.isArray(res.data?.recovery_codes) ? res.data.recovery_codes.map(String) : [] }, 200, mine.headers)
      }
      if (route === '/me/mfa/phone') {
        const res = await as('/v1/auth/mfa/phone', { phone: typeof b.phone === 'string' ? b.phone : '', channel: typeof b.channel === 'string' ? b.channel : 'sms', password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : res.error.code === 'validation_error' ? 'phone' : undefined)
        return json({ status: 'sent', sentTo: String(res.data?.sent_to ?? ''), channel: String(res.data?.channel ?? '') }, 200, mine.headers)
      }
      if (route === '/me/mfa/phone/verify') {
        const bad = checkCode(b.code)
        if (bad) return invalid(bad)
        const res = await as('/v1/auth/mfa/phone/verify', { code: String(b.code).trim() })
        if (res.error) return refused(res, 'code')
        return json({ status: 'enabled', recoveryCodes: Array.isArray(res.data?.recovery_codes) ? res.data.recovery_codes.map(String) : [] }, 200, mine.headers)
      }
      if (route === '/me/mfa/phone/remove') {
        const res = await as('/v1/auth/mfa/phone/remove', { password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : undefined)
        return json({ status: 'removed' }, 200, mine.headers)
      }
      if (route === '/me/mfa/disable') {
        const res = await as('/v1/auth/me/mfa/disable', { password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : undefined)
        return json({ status: 'disabled' }, 200, mine.headers)
      }
      if (route === '/me/mfa/recovery-codes') {
        const res = await as('/v1/auth/me/mfa/recovery-codes', { password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : undefined)
        return json({ status: 'renewed', recoveryCodes: Array.isArray(res.data?.recovery_codes) ? res.data.recovery_codes.map(String) : [] }, 200, mine.headers)
      }
      if (route === '/me/email') {
        const bad = checkEmail(b.email)
        if (bad) return invalid(bad)
        const email = String(b.email).trim()
        const res = await as('/v1/auth/me/email', { email, password })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : ['invalid_email', 'email_unchanged', 'email_taken'].includes(res.error.code) ? 'email' : undefined)
        // Nothing changed yet: the new address confirms it from the link it was sent.
        return json({ status: 'sent', email }, 200, mine.headers)
      }
      if (route === '/me/identities/unlink') {
        const provider = typeof b.provider === 'string' ? b.provider : ''
        if (!PROVIDER_ID.test(provider)) return problem(400, 'invalid_provider', 'Say which provider to unlink.', 'provider', mine.headers)
        const res = await as(`/v1/auth/identities/${provider}`, undefined, 'DELETE')
        if (res.error) return refused(res)
        return json({ status: 'unlinked', provider }, 200, mine.headers)
      }
      // A passkey made on this page, for the domain the workspace's passkeys
      // belong to. The ceremony's id stays here, sealed, between its two calls.
      if (route === '/me/passkeys/add/begin') {
        const kind = b.kind === 'device' || b.kind === 'security_key' ? b.kind : ''
        const res = await as('/v1/auth/webauthn/register/begin', { password, ...(kind ? { kind } : {}) })
        if (res.error) return refused(res, res.error.code === 'step_up_required' ? 'password' : undefined)
        const step: Step = { kind: 'enrol', token: String(res.data?.session_id ?? ''), returnTo: afterSignIn }
        const h = new Headers(mine.headers)
        h.append('set-cookie', writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, PASSKEY_SECONDS)))
        return json({ status: 'started', options: res.data?.options?.publicKey ?? res.data?.options ?? null }, 200, h)
      }
      if (route === '/me/passkeys/add/finish') {
        const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
        const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
        if (step === null || step.kind !== 'enrol') return problem(400, 'step_expired', 'Start adding the passkey again: it was asked for too long ago.', undefined, mine.headers)
        if (!isCredential(b.credential)) return problem(400, 'bad_request', 'Send the passkey the browser made.', undefined, mine.headers)
        const name = typeof b.name === 'string' ? b.name.trim().slice(0, 60) : ''
        const res = await as('/v1/auth/webauthn/register/finish', { session_id: step.token, nickname: name, credential: b.credential })
        const h = new Headers(mine.headers)
        h.append('set-cookie', writeCookie(stepCookie, '', attrs(request, 0)))
        if (res.error) return problem(res.status, res.error.code === 'attestation_invalid' ? 'passkey_failed' : res.error.code, res.error.code === 'attestation_invalid' ? 'The passkey could not be added. Try again.' : res.error.message, undefined, h)
        return json({ status: 'added', passkey: passkeyOf(res.data) }, 200, h)
      }
      if (route === '/me/passkeys/remove') {
        const id = typeof b.id === 'string' ? b.id : ''
        if (!/^[0-9a-f-]{36}$/i.test(id)) return problem(400, 'invalid_passkey', 'Say which passkey to remove.', undefined, mine.headers)
        const res = await as(`/v1/auth/webauthn/credentials/${id}`, undefined, 'DELETE')
        if (res.error) return refused(res)
        return json({ status: 'removed', id }, 200, mine.headers)
      }
      // A guest becoming an account of their own, with an address and a password.
      if (route === '/me/upgrade') {
        const bad = firstProblem(checkName(b.name), checkEmail(b.email), await newPasswordProblem(request, b.password))
        if (bad) return invalid(bad)
        const res = await as('/v1/auth/anonymous/upgrade', { email: String(b.email).trim(), password: b.password, display_name: typeof b.name === 'string' ? b.name.trim() : '' })
        if (res.error) return refused(res, res.error.code === 'weak_password' ? 'password' : 'email')
        // The guest's session becomes the account's: of the same kind.
        return signedIn(request, res.data, [], {}, (await read(request)).value ?? undefined)
      }
      // A member administering the organization itself (cauthy:organization
      // update, archive, delete). Cauthy decides by the person's role.
      if (route === '/me/organizations/rename' || route === '/me/organizations/archive' || route === '/me/organizations/delete') {
        const org = typeof b.organizationId === 'string' ? b.organizationId : ''
        if (!UUID.test(org)) return problem(400, 'invalid_organization', 'Say which organization.', undefined, mine.headers)
        const path = `/v1/auth/me/organizations/${org}`
        if (route === '/me/organizations/rename') {
          const bad = checkOrganizationName(b.name)
          if (bad) return invalid(bad)
          const res = await as(path, { name: String(b.name).trim() }, 'PATCH')
          if (res.error) return refused(res, res.error.code === 'validation_error' ? 'name' : undefined)
          // The session's organizations carry the name: read them again.
          orgCache.delete(mine.token)
          return json({ status: 'renamed', organization: seatOf(res.data) }, 200, mine.headers)
        }
        const res = route === '/me/organizations/archive' ? await as(`${path}/archive`) : await as(path, undefined, 'DELETE')
        if (res.error) return refused(res)
        // Gone from the person's organizations either way.
        orgCache.delete(mine.token)
        return json({ status: route === '/me/organizations/archive' ? 'archived' : 'deleted', organizationId: org }, 200, mine.headers)
      }
      // A member administering their organization's people (cauthy:members
      // manage; removing someone else, cauthy:members remove).
      if (route.startsWith('/me/organizations/members/')) {
        const org = typeof b.organizationId === 'string' ? b.organizationId : ''
        if (!UUID.test(org)) return problem(400, 'invalid_organization', 'Say which organization.', undefined, mine.headers)
        const base = `/v1/auth/me/organizations/${org}/members`
        if (route === '/me/organizations/members/add') {
          const bad = checkEmail(b.email)
          if (bad) return invalid(bad)
          const role = typeof b.role === 'string' ? b.role : ''
          if (role === '') return problem(400, 'invalid_role', 'Choose a role.', 'role', mine.headers)
          // A person new to the workspace is invited: the mail opens this
          // application's page for it when it has one.
          // Adding never changes the role of somebody already there: that is
          // setRole's. The member's route only adds; it is asked so anyway.
          const res = await ask(request, 'POST', base, { email: String(b.email).trim(), role, name: typeof b.name === 'string' ? b.name.trim() : '',
            client_id: clientId, only_new: true, ...(typeof b.locale === 'string' && b.locale ? { locale: b.locale } : {}) }, pages.acceptInvite, mine.token)
          // One code for "already a member", whichever route answered it.
          if (res.error?.code === 'already_member') res.error.code = 'member_exists'
          if (res.error) return refused(res, res.error.code === 'unknown_role' ? 'role' : 'email')
          return json({ status: 'added', member: orgMemberOf(res.data) }, 200, mine.headers)
        }
        const user = typeof b.userId === 'string' ? b.userId : ''
        if (!UUID.test(user)) return problem(400, 'invalid_member', 'Say which member.', undefined, mine.headers)
        if (route === '/me/organizations/members/role') {
          const role = typeof b.role === 'string' ? b.role : ''
          if (role === '') return problem(400, 'invalid_role', 'Choose a role.', 'role', mine.headers)
          const res = await as(`${base}/${user}`, { role }, 'PUT')
          if (res.error) return refused(res, 'role')
          return json({ status: 'changed', userId: user, role }, 200, mine.headers)
        }
        if (route === '/me/organizations/members/remove') {
          const res = await as(`${base}/${user}`, undefined, 'DELETE')
          if (res.error) return refused(res)
          orgCache.delete(mine.token)
          return json({ status: 'removed', userId: user }, 200, mine.headers)
        }
        if (route === '/me/organizations/members/invite') {
          const res = await ask(request, 'POST', `${base}/${user}/invite`, { client_id: clientId, ...(typeof b.locale === 'string' && b.locale ? { locale: b.locale } : {}) }, pages.acceptInvite, mine.token)
          if (res.error) return refused(res)
          return json({ status: 'sent', userId: user }, 200, mine.headers)
        }
      }
      if (route === '/me/agents/disconnect') {
        const id = typeof b.id === 'string' ? b.id : ''
        if (!/^[0-9a-f-]{36}$/i.test(id)) return problem(400, 'invalid_agent', 'Say which agent to disconnect.', undefined, mine.headers)
        const res = await as(`/v1/auth/me/agents/${id}`, undefined, 'DELETE')
        if (res.error) return refused(res)
        return json({ status: 'disconnected', id }, 200, mine.headers)
      }
      if (route === '/me/sessions/end') {
        const res = await as('/v1/auth/me/sessions', undefined, 'DELETE')
        if (res.error) return refused(res)
        // Everywhere is here too.
        const h = new Headers()
        for (const c of clearParts(cookieName, attrs(request, 0), readCookies(request.headers.get('cookie')))) h.append('set-cookie', c)
        orgCache.delete(mine.token)
        return json({ status: 'signed_out' }, 200, h)
      }
      return null
    }

    const isToken = (v: unknown): v is string => typeof v === 'string' && v !== '' && v.length <= 512
    const badLink = () => problem(422, 'invalid_token', 'This link is not valid, or it has expired.')

    // What a mailed link carries back: the token it was opened with.
    if (route === '/reset-password') {
      if (!isToken(b.token)) return badLink()
      const bad = await newPasswordProblem(request, b.password)
      if (bad) return invalid(bad)
      const res = await ask(request, 'POST', '/v1/auth/password/change', { token: String(b.token), new_password: b.password })
      if (res.error) return problem(res.status, res.error.code, res.error.message, res.error.code === 'weak_password' ? 'password' : undefined, undefined, res.error.reasons)
      return json({ status: 'changed' })
    }
    if (route === '/verify-email') {
      if (!isToken(b.token)) return badLink()
      const res = await ask(request, 'POST', '/v1/auth/email/verify', { token: String(b.token) })
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      // The link proved the address: Cauthy signs the person in from it, unless
      // their account asks a second step — then they sign in the usual way.
      if (res.data?.access_token) return signedIn(request, res.data)
      return json({ status: 'verified' })
    }
    // An invitation accepted: the password the person chose, checked against
    // the workspace's policy, and a sign-in like one with a password — the
    // second step next, when the account owes one. A refused password does
    // not spend the invitation.
    if (route === '/invitation/accept') {
      if (!isToken(b.token)) return problem(422, 'invalid_token', 'This invitation is not valid, or it has expired.')
      const bad = await newPasswordProblem(request, b.password)
      if (bad) return invalid(bad)
      const res = await ask(request, 'POST', '/v1/auth/invitation/accept', { token: String(b.token), password: b.password })
      if (res.error) return problem(res.status, res.error.code, res.error.message, res.error.code === 'weak_password' ? 'password' : undefined, undefined, res.error.reasons)
      return loggedIn(request, res.data)
    }

    // A passkey, on this page: Cauthy says what to ask the browser for, the
    // browser asks the person, and the answer goes back to Cauthy through here.
    if (route === '/sign-in/passkey/begin') {
      // With the person's address, the browser is told which passkeys are
      // theirs; Cauthy answers the same for an address with none.
      const email = typeof b.email === 'string' && checkEmail(b.email) === null ? b.email.trim() : ''
      const remember = wants(b.remember)
      const res = await ask(request, 'POST', '/v1/auth/webauthn/login/begin', email !== '' ? { email } : {}, undefined, undefined, remember)
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      const step: Step = { kind: 'passkey', token: String(res.data?.session_id ?? ''), returnTo: afterSignIn, ...(remember ? { remember } : {}) }
      return json({ status: 'started', options: res.data?.options?.publicKey ?? res.data?.options ?? null }, 200,
        new Headers({ 'set-cookie': writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, PASSKEY_SECONDS)) }))
    }
    if (route === '/sign-in/passkey/finish') {
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'passkey') return problem(400, 'step_expired', 'Try the passkey again: it was asked for too long ago.')
      if (!isCredential(b.credential)) return problem(400, 'bad_request', 'Send the passkey the browser answered with.')
      const res = await ask(request, 'POST', '/v1/auth/webauthn/login/finish', { session_id: step.token, credential: b.credential }, undefined, undefined, step.remember === true || wants(b.remember))
      const clear = writeCookie(stepCookie, '', attrs(request, 0))
      if (res.error) {
        // Which check failed is Cauthy's to log; the page says only that it did.
        const failed = ['assertion_invalid', 'session_expired', 'clone_detected', 'not_found'].includes(res.error.code)
        return problem(res.status, failed ? 'passkey_failed' : res.error.code, failed ? 'The passkey sign-in could not be completed. Try again, or sign in another way.' : res.error.message, undefined, new Headers({ 'set-cookie': clear }))
      }
      return signedIn(request, res.data, [clear])
    }

    // Google One Tap: Cauthy gives the workspace's Google client and a nonce
    // for one prompt; Google's prompt gives the page an ID token, which comes
    // back here and is traded, once, for a session.
    if (route === '/sign-in/google-one-tap/begin') {
      const res = await ask(request, 'POST', '/v1/auth/google/one-tap/begin', {})
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return json({ status: 'started', clientId: String(res.data?.client_id ?? ''), nonce: String(res.data?.nonce ?? '') })
    }
    if (route === '/sign-in/google-one-tap') {
      if (typeof b.credential !== 'string' || b.credential === '') return problem(400, 'bad_request', 'Send the credential Google gave the page.')
      const res = await ask(request, 'POST', '/v1/auth/google/one-tap', { credential: b.credential }, undefined, undefined, wants(b.remember))
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return signedIn(request, res.data)
    }

    // A sign-in link: asked for here, mailed by Cauthy, opened on the
    // application's sign-in page, which gives the token back.
    if (route === '/sign-in/magic-link') {
      const bad = checkEmail(b.email)
      if (bad) return invalid(bad)
      if (pages.signIn === undefined) return problem(500, 'not_configured', '@cauthyhq/node: pages.signIn is required for sign-in links: it is the page the link opens')
      // The same answer whether or not the address has an account. With
      // create, an address with none gets one when the link or code is used
      // (if the workspace accepts new accounts): one screen for both.
      const email = String(b.email).trim()
      // Where the person goes once in travels in the link itself, as
      // `return_to` on the page it opens: it may be opened in another browser.
      const back = typeof b.returnTo === 'string' ? localPath(b.returnTo, afterSignIn) : afterSignIn
      const remember = wants(b.remember)
      // The choice to stay signed in travels in the link too: the mail may be opened anywhere.
      const query = [...(back === afterSignIn ? [] : [`return_to=${encodeURIComponent(back)}`]), ...(remember ? ['remember=1'] : [])].join('&')
      const page = query === '' ? pages.signIn : `${pages.signIn}${pages.signIn.includes('?') ? '&' : '?'}${query}`
      await ask(request, 'POST', '/v1/auth/magic-link/request', { email, ...(b.create === true ? { create_account: true } : {}) }, page)
      // The mail carries a code too. Whose it is stays here, sealed, so the
      // page that asks for the code needs only the code.
      const step: Step = { kind: 'code', token: email, returnTo: back, ...(remember ? { remember } : {}) }
      return json({ status: 'sent' }, 200, new Headers({ 'set-cookie': writeCookie(stepCookie, await seal(step, (await flowKeys)[0]), attrs(request, STEP_SECONDS)) }))
    }
    if (route === '/sign-in/email-code') {
      const bad = checkCode(b.code)
      if (bad) return invalid(bad)
      const sealed = readCookies(request.headers.get('cookie')).get(stepCookie)
      const step = sealed ? await unsealAny<Step>(sealed, await flowKeys) : null
      if (step === null || step.kind !== 'code') return problem(400, 'step_expired', 'Ask for a new link: this one was asked for too long ago.')
      const res = await ask(request, 'POST', '/v1/auth/magic-link/verify-code', { email: step.token, code: String(b.code).trim() }, undefined, undefined, step.remember === true)
      if (res.error) return problem(res.status, res.error.code, res.error.message, 'code')
      return signedIn(request, res.data, [writeCookie(stepCookie, '', attrs(request, 0))], { returnTo: step.returnTo })
    }
    if (route === '/sign-in/magic-link/verify') {
      if (!isToken(b.token)) return badLink()
      const res = await ask(request, 'POST', '/v1/auth/magic-link/verify', { token: String(b.token) }, undefined, undefined, wants(b.remember))
      if (res.error) return problem(res.status, res.error.code, res.error.message)
      return signedIn(request, res.data)
    }
    return null
  }

  /** Every answer as protocol version 1 sends it (protocol.ts); the published keys keep their cache. */
  async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const inside = url.pathname === basePath || url.pathname.startsWith(`${basePath}/`)
    const route = inside ? withoutTrailingSlashes(url.pathname.slice(basePath.length)) || '/' : null
    const published = pact !== undefined && url.pathname === contract?.jwksPath && (request.method === 'GET' || request.method === 'HEAD')
    try {
      return finish(await serve(request), route, published)
    } catch (err) {
      // A sign-in that Cauthy completed for an address not yet confirmed, on a link that requires it.
      if (!(err instanceof CauthyApiError && err.code === 'email_not_confirmed')) throw err
      const wantsPage = request.method === 'GET' && (request.headers.get('sec-fetch-mode') ?? 'navigate') === 'navigate'
      return finish(wantsPage
        ? new Response('Sign-in refused (email_not_confirmed). Confirm your email address first.', { status: 403, headers: { 'content-type': 'text/plain; charset=utf-8' } })
        : problem(403, 'email_not_confirmed', 'Confirm your email address first.'), route)
    }
  }

  async function serve(request: Request): Promise<Response> {
    const url = new URL(request.url)
    if (pact && url.pathname === contract?.jwksPath && (request.method === 'GET' || request.method === 'HEAD')) return pact.jwks()
    if (url.pathname !== basePath && !url.pathname.startsWith(`${basePath}/`)) return new Response('Not found', { status: 404 })
    const route = withoutTrailingSlashes(url.pathname.slice(basePath.length)) || '/'
    const get = request.method === 'GET' || request.method === 'HEAD'

    const mine = await ownRoute(request, url, route)
    if (mine !== null) return mine

    // The browser asking about a permission (organizations.check). Outside the
    // own screens: it needs no tenant, only the person's session.
    if (route === '/me/organizations/check') return checkRoute(request)

    if (route === '/login' && get) return login(request, url)
    if (route === '/callback' && get) return callback(request, url)
    if (route === '/logout' && (get || request.method === 'POST')) return logout(request)

    if (route === '/session' && get) {
      const r = await resolve(request)
      const h = new Headers()
      for (const c of r.cookies) h.append('set-cookie', c)
      return json({ session: r.session ? await toPublic(r.session) : null, status: r.status }, 200, h)
    }

    // For a page that found its session expired: renew, and go back to it.
    if (route === '/refresh' && get) {
      const r = await resolve(request)
      const back = localPath(url.searchParams.get('return_to'), afterSignIn)
      if (r.status === 'unauthenticated') return redirect(urls.signIn(back), r.cookies)
      if (r.status === 'expired') return new Response('Sign-in is unavailable right now. Try again in a moment.', { status: 503 })
      return redirect(back, r.cookies)
    }

    if (route === '/account' && get) {
      const q = new URLSearchParams({ client_id: clientId })
      const back = localPath(url.searchParams.get('return_to'), '')
      if (back !== '') q.set('return_to', `${originOf(request)}${back}`)
      const locale = url.searchParams.get('locale')
      if (locale && /^[a-zA-Z-]{2,10}$/.test(locale)) q.set('ui_locales', locale)
      return redirect(`${issuer}/v1/oauth/account?${q}`)
    }
    return new Response('Not found', { status: 404 })
  }

  async function checkRoute(request: Request): Promise<Response> {
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: { allow: 'POST' } })
    const refused = withoutRequestHeader(request, '/me/organizations/check')
    if (refused) return refused
    if (!ownRequest(request)) return problem(403, 'cross_site', 'This request did not come from this application.')
    const b = await body(request)
    if (b === null) return problem(400, 'bad_request', 'Send the question as JSON.')
    const asker = await signedInAs(request)
    if ('response' in asker) return asker.response
    const org = typeof b.organizationId === 'string' ? b.organizationId : ''
    if (!UUID.test(org)) return problem(400, 'invalid_organization', 'Say which organization.', undefined, asker.headers)
    const named = (v: unknown) => typeof v === 'string' && v !== '' && v.length <= 200
    if (!named(b.resource) || !named(b.action)) return problem(400, 'bad_request', 'Say which resource and action.', undefined, asker.headers)
    const attributes = b.attributes
    if (attributes !== undefined && (typeof attributes !== 'object' || attributes === null || Array.isArray(attributes))) {
      return problem(400, 'bad_request', 'The attributes are an object.', undefined, asker.headers)
    }
    try {
      const r = await decide(asker.token, {
        organization: org, resource: b.resource as string, action: b.action as string,
        ...(attributes !== undefined ? { attributes: attributes as Record<string, unknown> } : {}),
        ...(typeof b.resourceId === 'string' ? { resourceId: b.resourceId } : {}),
        ...(typeof b.ownerId === 'string' ? { ownerId: b.ownerId } : {}),
      })
      return json({ status: 'decided', ...r }, 200, asker.headers)
    } catch (e) {
      const err = e instanceof CauthyApiError ? e : new CauthyApiError(503, 'unavailable', 'Cauthy could not be reached.')
      return problem(err.status, err.code, err.message.replace(/^@cauthyhq\/node: /, ''), undefined, asker.headers)
    }
  }

  async function protect(request: Request) {
    const read1 = await read(request)
    // A session of a person the link does not let in (address not confirmed) is none.
    const value = read1.value !== null && unverified(read1.value.u) ? null : read1.value
    if (value !== null && fresh(value)) return { session: toSession(value) }
    const url = new URL(request.url)
    const state = value === null ? 'none' : 'expired'
    // A page is sent to sign in, or to renew and come back. Anything else —
    // a fetch, a form post — is told, and its caller decides.
    const page = request.method === 'GET' && (request.headers.get('sec-fetch-mode') ?? 'navigate') === 'navigate' &&
      (request.headers.get('accept') ?? 'text/html').includes('text/html')
    if (!page) {
      return { response: json({ error: 'unauthenticated', session: state }, 401, new Headers({ 'x-cauthy-session': state })) }
    }
    const back = url.pathname + url.search
    const to = value === null ? urls.signIn(back) : `${basePath}/refresh?return_to=${encodeURIComponent(back)}`
    return { response: redirect(to) }
  }

  // The endpoint's public address: the application's origin when it was
  // given (a proxy may hide it from the request), with the request's path.
  const replay = given.webhookReplay ?? memoryReplayStore()
  const webhook: Cauthy['webhook'] = (request, o = {}) =>
    verifyWebhook(request, { issuer, url: o.url ?? `${originOf(request)}${new URL(request.url).pathname}`, jwks: o.jwks, now: o.now, replay })

  const pact: CauthyPact | undefined = contract && ownKeys ? {
    contract,
    keys: ownKeys,
    async jwks() {
      // Cauthy reads it when it meets a key it does not know, and at most
      // hourly otherwise. A new key signs only after it has been published
      // longer than this cache lasts (SIGN_AFTER_MS): caching never hides it.
      return new Response(JSON.stringify(await ownKeys.published()), {
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': `public, max-age=${JWKS_MAX_AGE_S}` },
      })
    },
    status: () => ownSystem.request<PactStatus>('GET', `/v1/pact/status?system=${encodeURIComponent(contract.system)}`),
  } : undefined

  return {
    handler,
    checkMount: (target: MountTarget) => probeMount(basePath, target),
    webhook,
    system: systemThatRefreshes,
    getSession,
    status,
    resolve,
    protect,
    organizations,
    check,
    toPublic,
    urls,
    ...(pact ? { pact } : {}),
    options: { issuer, clientId, basePath, afterSignIn, afterSignOut, cookieName },
  }
}

/**
 * A provider's logo, as Cauthy serves it. An address of Cauthy's own path (a
 * Cauthy with no public address of its own) is read against the issuer; only
 * an http(s) address is passed on.
 */
function iconFor(issuer: string): (p: any) => { iconUrl?: string } {
  return (p) => {
    const raw = typeof p?.icon_url === 'string' ? p.icon_url.trim() : ''
    if (raw === '') return {}
    try {
      const url = new URL(raw.startsWith('/') && !raw.startsWith('//') ? `${issuer}${raw}` : raw)
      return url.protocol === 'https:' || url.protocol === 'http:' ? { iconUrl: url.href } : {}
    } catch {
      return {}
    }
  }
}

/** What a sign-up form shows for the law: the documents to accept and the consents to ask, as the API tells them. */
function legalOf(raw: any): { documents: { kind: string; version: string; url: string }[]; consentPurposes: { key: string; label: string; required: boolean }[] } {
  const documents = Array.isArray(raw?.documents) ? raw.documents : []
  const purposes = Array.isArray(raw?.consent_purposes) ? raw.consent_purposes : []
  return {
    documents: documents.map((d: any) => ({ kind: String(d.kind ?? ''), version: String(d.version ?? ''), url: String(d.url ?? '') })),
    consentPurposes: purposes.map((p: any) => ({ key: String(p.key ?? ''), label: String(p.label ?? ''), required: p.required === true })),
  }
}

/** A loopback, private or link-local address: a network's own hop, never a person. */
function ownNetwork(address: string): boolean {
  const a = address.toLowerCase()
  return /^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(a) || /^172\.(1[6-9]|2\d|3[01])\./.test(a) ||
    a === '::1' || /^f[cd]/.test(a) || /^fe[89ab]/.test(a) || a.startsWith('::ffff:127.') || a === 'localhost'
}
