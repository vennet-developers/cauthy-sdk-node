// A Cauthy that lives in memory, and a browser that keeps cookies: what the
// tests sign in against. Not exported from the package.

export class FakeCauthy {
  readonly issuer = 'https://id.test'
  users = new Map<string, { sub: string; email: string; name: string; active: boolean; restricted: boolean; anonymous?: boolean }>()
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

  private issue(sub: string) {
    const at = `at-${++this.n}`
    const rt = `rt-${++this.n}`
    this.access.set(at, sub)
    this.refresh.set(rt, sub)
    return { access_token: at, refresh_token: rt, token_type: 'Bearer', expires_in: this.expiresIn, scope: '', ...(this.persistent === undefined ? {} : { persistent: this.persistent }) }
  }

  fetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    this.calls.push(`${init?.method ?? 'GET'} ${url.pathname}`)
    if (this.down) throw new TypeError('fetch failed')
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
    const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''))
    const bearer = new Headers(init?.headers).get('authorization')?.replace('Bearer ', '') ?? ''
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
      return reply(200, { sub: user.sub, tid: 't1', email: user.email, name: user.name, email_verified: !user.anonymous, restricted: user.restricted, roles: ['member'], ...(user.anonymous ? { anonymous: true } : {}) })
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
      const body = JSON.parse(String(init?.body ?? '{}')) as { email?: string; password?: string }
      const user = [...this.users.values()].find((u) => u.email === body.email)
      const password = body.email === undefined ? undefined : this.passwords.get(body.email)
      if (!user || !user.active || password === undefined || password !== body.password) {
        return refuse(401, 'invalid_credentials', 'invalid email or password')
      }
      return reply(200, { data: this.issue(user.sub) })
    }
    if (method === 'GET' && url.pathname === '/v1/auth/settings') return reply(200, { data: this.settings })
    if (method === 'GET' && (url.pathname === '/v1/auth/social/providers' || url.pathname === '/v1/auth/sso/connections')) return reply(200, { data: [] })
    if (method === 'GET' && url.pathname === '/v1/auth/webauthn/place') return reply(200, { data: { here: false, on_cauthy: false } })
    return refuse(404, 'not_found', 'not found')
  }
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
