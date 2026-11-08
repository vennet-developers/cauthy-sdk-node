// A Cauthy that lives in memory, and a browser that keeps cookies: what the
// tests sign in against. Exported as `@cauthyhq/node/testing`, for tests only:
// it signs in anyone it was told about, and checks nothing a real Cauthy does.

import { createServer, type Server } from 'node:http'

/** The settings the fake's admin API changes (PUT /v1/settings/auth), as the dashboard's switches do. */
const ADMIN_SETTINGS = ['allow_signup', 'allow_password', 'allow_magic_link', 'allow_passkeys', 'confirm_email', 'verify_grace_days'] as const

export class FakeCauthy {
  readonly issuer = 'https://id.test'
  users = new Map<string, { sub: string; email: string; name: string; active: boolean; restricted: boolean; anonymous?: boolean; verified?: boolean }>()
  codes = new Map<string, { sub: string; challenge: string; redirectUri: string }>()
  refresh = new Map<string, string>() // refresh token → sub
  access = new Map<string, string>() // access token → sub
  orgs = new Map<string, Record<string, unknown>[]>() // sub → organizations
  revoked: string[] = []
  checks: { organization: string; sub: string; body: any }[] = []
  calls: string[] = []
  down = false
  expiresIn = 600
  /** What token answers say of the session's kind; absent means an older Cauthy that does not say. */
  persistent: boolean | undefined = undefined
  /** Serve the API an application's own screens use (/v1/auth/*). Off unless a test asks. */
  ownScreens = false
  /** The workspace those screens sign in to, as X-Tenant-Key names it. */
  tenant = 'acme'
  /** Each account's password, by email: only these accounts sign in with one. */
  passwords = new Map<string, string>()
  /** What GET /v1/auth/settings answers. */
  settings: Record<string, unknown> = { allow_password: true, allow_signup: false, allow_passkeys: false, persistent_sessions: false }
  /** The bearer the admin API takes (settings, the application's client, accounts); '' refuses every admin call. */
  adminToken = ''
  /** The application's client, as the admin API lists it; its allow_persistent_sessions is settings.persistent_sessions. */
  clientId = 'acme-crm'
  private n = 0

  constructor() {
    this.users.set('u1', { sub: 'u1', email: 'ana@acme.com', name: 'Ana', active: true, restricted: false })
  }

  /** What the hosted page does once the person has signed in: hands the browser a code. */
  authorize(location: string, sub = 'u1'): string {
    const q = new URL(location).searchParams
    if (q.get('response_type') !== 'code') throw new Error('Cauthy answers unsupported_response_type: response_type=code is required')
    const code = `code-${++this.n}`
    this.codes.set(code, { sub, challenge: q.get('code_challenge') ?? '', redirectUri: q.get('redirect_uri') ?? '' })
    return `${q.get('redirect_uri')}?code=${code}&state=${q.get('state')}`
  }

  /** A token answer. `kind` is what a sign-in asked for (remember) when the client allows long sessions; `persistent` wins when set. */
  private issue(sub: string, kind?: boolean) {
    const at = `at-${++this.n}`
    const rt = `rt-${++this.n}`
    this.access.set(at, sub)
    this.refresh.set(rt, sub)
    const persistent = this.persistent ?? kind
    return { access_token: at, refresh_token: rt, token_type: 'Bearer', expires_in: this.expiresIn, scope: '', ...(persistent === undefined ? {} : { persistent }) }
  }

  fetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    this.calls.push(`${init?.method ?? 'GET'} ${url.pathname}`)
    if (this.down) throw new TypeError('fetch failed')
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
    const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''))
    const bearer = new Headers(init?.headers).get('authorization')?.replace('Bearer ', '') ?? ''
    const admin = adminAnswer(this, url, init)
    if (admin) return admin
    if (this.ownScreens && url.pathname.startsWith('/v1/auth/')) return this.ownScreen(url, init)

    if (url.pathname === '/v1/oauth/token') {
      if (form.get('grant_type') === 'authorization_code') {
        const c = this.codes.get(form.get('code') ?? '')
        this.codes.delete(form.get('code') ?? '')
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(form.get('code_verifier') ?? ''))
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        if (!c || c.challenge !== challenge || c.redirectUri !== form.get('redirect_uri')) return reply(400, { error: 'invalid_grant', error_description: 'the grant is invalid, expired or already used' })
        return reply(200, this.issue(c.sub))
      }
      if (form.get('grant_type') === 'refresh_token') {
        const sub = this.refresh.get(form.get('refresh_token') ?? '')
        this.refresh.delete(form.get('refresh_token') ?? '') // used once
        if (!sub || !this.users.get(sub)?.active) return reply(400, { error: 'invalid_grant', error_description: 'the grant is invalid, expired or already used' })
        return reply(200, this.issue(sub))
      }
      return reply(400, { error: 'unsupported_grant_type', error_description: 'supported grant types: authorization_code, refresh_token' })
    }
    if (url.pathname === '/v1/oauth/revoke') {
      this.revoked.push(form.get('token') ?? '')
      this.refresh.delete(form.get('token') ?? '')
      return reply(200, {})
    }
    const sub = this.access.get(bearer)
    const user = sub ? this.users.get(sub) : undefined
    if (url.pathname === '/v1/oauth/userinfo') {
      if (!user) return reply(401, {})
      return reply(200, { sub: user.sub, tid: 't1', email: user.email, name: user.name, email_verified: user.verified ?? !user.anonymous, restricted: user.restricted, roles: ['member'], ...(user.anonymous ? { anonymous: true } : {}) })
    }
    const asking = url.pathname.match(/^\/v1\/oauth\/organizations\/([^/]+)\/check$/)
    if (asking && init?.method === 'POST') {
      if (!user) return reply(401, { errors: [{ code: 'unauthorized', message: 'invalid or expired token' }] })
      const org = decodeURIComponent(asking[1])
      const body = JSON.parse(String(init.body))
      this.checks.push({ organization: org, sub: user.sub, body })
      if (!(this.orgs.get(user.sub) ?? []).some((o) => o.id === org)) return reply(404, { errors: [{ code: 'organization_not_found', message: 'organization not found' }] })
      // An accountant approves invoices up to a million.
      const allowed = body.resource === 'invoices' && body.action === 'approve' && Number(body.attributes?.amount) <= 1_000_000
      return reply(200, { data: allowed
        ? { allowed, reason: 'allowed by role accountant: invoices:approve', rule: { source: 'role', role: 'accountant', kind: '*', resource: 'invoices', action: 'approve', effect: 'allow', condition: 'resource.attrs.amount <= 1000000' } }
        : { allowed, reason: 'no rule allows it' } })
    }
    if (url.pathname === '/v1/oauth/organizations') {
      if (!user) return reply(401, {})
      const system = url.searchParams.get('system')
      const data = (this.orgs.get(user.sub) ?? []).filter((o) => !system || o.system === system)
      return reply(200, { data, total_count: data.length })
    }
    return reply(404, {})
  }

  /** The part of /v1/auth/* a password sign-in and the sign-in form read. */
  private ownScreen(url: URL, init: RequestInit | undefined): Response {
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
    const refuse = (status: number, code: string, message: string) => reply(status, { errors: [{ code, message }] })
    if (new Headers(init?.headers).get('x-tenant-key') !== this.tenant) return refuse(404, 'tenant_not_found', 'no such workspace')
    const method = init?.method ?? 'GET'
    if (method === 'POST' && url.pathname === '/v1/auth/login') {
      if (this.settings.allow_password === false) return refuse(403, 'password_disabled', 'this workspace does not take passwords: sign in another way')
      const body = JSON.parse(String(init?.body ?? '{}')) as { email?: string; password?: string }
      const user = [...this.users.values()].find((u) => u.email === body.email)
      const password = body.email === undefined ? undefined : this.passwords.get(body.email)
      if (!user || !user.active || password === undefined || password !== body.password) {
        return refuse(401, 'invalid_credentials', 'invalid email or password')
      }
      // A long session only when the person asked and the client allows it.
      const kind = this.settings.persistent_sessions === true ? new Headers(init?.headers).get('x-cauthy-remember') === '1' : undefined
      return reply(200, { data: this.issue(user.sub, kind) })
    }
    if (method === 'POST' && url.pathname === '/v1/auth/register') {
      if (this.settings.allow_signup === false) return refuse(403, 'signups_disabled', 'this workspace is not accepting new accounts')
      if (this.settings.allow_password === false) return refuse(403, 'password_disabled', 'this workspace does not take passwords: sign in another way')
      const body = JSON.parse(String(init?.body ?? '{}')) as { email?: string; password?: string; display_name?: string }
      if (!body.email || !body.password) return refuse(400, 'validation_error', 'email and password are required')
      if ([...this.users.values()].some((u) => u.email === body.email)) return refuse(409, 'email_taken', 'an account with this email exists')
      // With confirm_email the account waits for its address (verify_grace_days 0 in the fake).
      const confirm = this.settings.confirm_email === true
      const sub = `u-${++this.n}`
      this.users.set(sub, { sub, email: body.email, name: body.display_name ?? '', active: !confirm, restricted: false, verified: !confirm })
      this.passwords.set(body.email, body.password)
      return reply(201, { data: { user_id: sub, email: body.email, ...(confirm ? { verification_required: true } : {}) } })
    }
    if (method === 'GET' && url.pathname === '/v1/auth/settings') return reply(200, { data: this.settings })
    if (method === 'GET' && (url.pathname === '/v1/auth/social/providers' || url.pathname === '/v1/auth/sso/connections')) return reply(200, { data: [] })
    if (method === 'GET' && url.pathname === '/v1/auth/webauthn/place') return reply(200, { data: { here: false, on_cauthy: false } })
    return refuse(404, 'not_found', 'not found')
  }
}

/**
 * The part of Cauthy's admin API the conformance runner's dashboard-switch
 * checks drive: GET and PUT /v1/settings/auth, GET /v1/oauth/clients,
 * PATCH /v1/oauth/clients/{id}, GET /v1/users and DELETE /v1/users/{id}.
 * null when the request is none of them.
 */
function adminAnswer(fake: FakeCauthy, url: URL, init: RequestInit | undefined): Response | null {
  const method = (init?.method ?? 'GET').toUpperCase()
  const route = `${method} ${url.pathname}`
  const client = method === 'PATCH' ? url.pathname.match(/^\/v1\/oauth\/clients\/([^/]+)$/) : null
  const user = method === 'DELETE' ? url.pathname.match(/^\/v1\/users\/([^/]+)$/) : null
  const known = ['GET /v1/settings/auth', 'PUT /v1/settings/auth', 'GET /v1/oauth/clients', 'GET /v1/users'].includes(route)
  if (!known && !client && !user) return null
  const reply = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  const refuse = (status: number, code: string, message: string) => reply(status, { errors: [{ code, message }] })
  const headers = new Headers(init?.headers)
  if (fake.adminToken === '' || headers.get('authorization') !== `Bearer ${fake.adminToken}`) return refuse(401, 'unauthorized', 'invalid or expired token')
  if (headers.get('x-tenant-key') !== fake.tenant) return refuse(404, 'tenant_not_found', 'no such workspace')
  if (route === 'GET /v1/settings/auth') return reply(200, { data: fake.settings })
  if (route === 'PUT /v1/settings/auth') {
    const change = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
    const next = { ...fake.settings }
    for (const key of ADMIN_SETTINGS) if (change[key] !== undefined && change[key] !== null) next[key] = change[key]
    if (next.allow_password === false && next.allow_magic_link !== true && next.allow_passkeys !== true) {
      return refuse(409, 'last_method', 'the change would leave no way to sign in')
    }
    fake.settings = next
    return reply(200, { data: fake.settings })
  }
  const persistent = () => fake.settings.persistent_sessions === true
  if (route === 'GET /v1/oauth/clients') return reply(200, { data: [{ client_id: fake.clientId, allow_persistent_sessions: persistent() }], total_count: 1 })
  if (client) {
    if (decodeURIComponent(client[1]) !== fake.clientId) return refuse(404, 'client_not_found', 'no such client')
    const change = JSON.parse(String(init?.body ?? '{}')) as { allow_persistent_sessions?: unknown }
    if (typeof change.allow_persistent_sessions === 'boolean') fake.settings = { ...fake.settings, persistent_sessions: change.allow_persistent_sessions }
    return reply(200, { data: { client_id: fake.clientId, allow_persistent_sessions: persistent() } })
  }
  if (route === 'GET /v1/users') {
    const q = (url.searchParams.get('q') ?? '').toLowerCase()
    const data = [...fake.users.values()].filter((u) => u.email.toLowerCase().includes(q)).map((u) => ({ id: u.sub, email: u.email, name: u.name }))
    return reply(200, { data, total_count: data.length })
  }
  const id = decodeURIComponent(user![1])
  const gone = fake.users.get(id)
  if (!gone) return refuse(404, 'user_not_found', 'no such user')
  fake.users.delete(id)
  fake.passwords.delete(gone.email)
  return new Response(null, { status: 204 })
}

/**
 * Serves a FakeCauthy over HTTP on 127.0.0.1, for a process outside this one
 * (the conformance runner) to reach it, as `--cauthy http://127.0.0.1:<port>`.
 */
export function serveFakeCauthy(fake: FakeCauthy, port: number): Promise<Server> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(chunk as Buffer)
    const headers = new Headers()
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v)
    const answer = await fake.fetch(`${fake.issuer}${req.url ?? '/'}`, {
      method: req.method,
      headers,
      ...(chunks.length > 0 ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
    })
    res.writeHead(answer.status, Object.fromEntries(answer.headers))
    res.end(Buffer.from(await answer.arrayBuffer()))
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve(server))
  })
}

/** A browser as far as cookies go: it keeps what it is told to and sends it back. */
export class Browser {
  jar = new Map<string, string>()
  /** `requestHeader: false`: a browser whose client sends no X-Cauthy-Request, as cauthy-auth 0.42's does not. */
  constructor(readonly origin = 'https://app.test', private readonly options: { requestHeader?: boolean } = {}) {}

  request(path: string, init: RequestInit = {}): Request {
    const headers = new Headers(init.headers)
    if (this.jar.size > 0) headers.set('cookie', [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '))
    // What a protocol-1 client sends on every mutation.
    const method = (init.method ?? 'GET').toUpperCase()
    if (method !== 'GET' && method !== 'HEAD' && this.options.requestHeader !== false && !headers.has('x-cauthy-request')) {
      headers.set('x-cauthy-request', '1')
    }
    return new Request(this.origin + path, { ...init, headers })
  }

  /** Keeps the cookies of a response, as a browser would. */
  take(source: Response | string[]): void {
    const cookies = Array.isArray(source) ? source : source.headers.getSetCookie()
    for (const c of cookies) {
      const [pair, ...attrs] = c.split('; ')
      const i = pair.indexOf('=')
      const name = pair.slice(0, i)
      const value = pair.slice(i + 1)
      if (value === '' || attrs.includes('Max-Age=0')) this.jar.delete(name)
      else this.jar.set(name, value)
    }
  }
}
