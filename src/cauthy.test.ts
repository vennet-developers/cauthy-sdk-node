import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCauthy, type Cauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'
import { CauthyConfigError } from './types'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'

function setup(extra: Record<string, unknown> = {}) {
  const cauthy = new FakeCauthy()
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET, system: 'ledger', fetch: cauthy.fetch, ...extra })
  return { cauthy, auth, browser: new Browser() }
}

/** Signs a browser in, through the routes, as the person would. */
async function signIn(auth: Cauthy, cauthy: FakeCauthy, browser: Browser, returnTo?: string, sub = 'u1') {
  const start = await auth.handler(browser.request(auth.urls.signIn(returnTo)))
  browser.take(start)
  const back = cauthy.authorize(start.headers.get('location')!, sub)
  const done = await auth.handler(browser.request(new URL(back).pathname + new URL(back).search))
  browser.take(done)
  return { start, done }
}

beforeEach(() => vi.useFakeTimers({ now: new Date('2026-10-12T00:00:00Z'), toFake: ['Date'] }))
afterEach(() => vi.useRealTimers())

describe('configuration', () => {
  it('says what is missing', () => {
    expect(() => createCauthy({ clientId: 'c', secret: SECRET })).toThrow(CauthyConfigError)
    expect(() => createCauthy({ issuer: 'https://id.test', secret: SECRET })).toThrow(/clientId/)
    expect(() => createCauthy({ issuer: 'https://id.test', clientId: 'c', secret: 'short' })).toThrow(/32 characters/)
    expect(() => createCauthy({ issuer: 'https://id.test', clientId: 'c', secret: SECRET, baseURL: 'app.example.com' })).toThrow(/CAUTHY_BASE_URL/)
    expect(() => createCauthy({ issuer: 'https://id.test', clientId: 'c', secret: SECRET, baseURL: 'https://app.example.com/sign-in' })).toThrow(/origin/)
  })

  it('reads its public origin from CAUTHY_BASE_URL', async () => {
    vi.stubEnv('CAUTHY_BASE_URL', 'https://app.example.com/')
    try {
      const { auth } = setup()
      const start = await auth.handler(new Request('http://10.0.0.7:8080' + auth.urls.signIn()))
      expect(new URL(start.headers.get('location')!).searchParams.get('redirect_uri')).toBe('https://app.example.com/api/auth/callback')
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('takes the scheme a proxy that ends TLS names', async () => {
    const { auth } = setup()
    const start = await auth.handler(new Request('http://app.test' + auth.urls.signIn(), { headers: { 'x-forwarded-proto': 'https' } }))
    expect(new URL(start.headers.get('location')!).searchParams.get('redirect_uri')).toBe('https://app.test/api/auth/callback')
    expect(start.headers.getSetCookie().join()).toContain('Secure')
  })
})

describe('signing in', () => {
  it('sends the browser to Cauthy with PKCE and brings it back signed in', async () => {
    const { cauthy, auth, browser } = setup()
    expect(await auth.getSession(browser.request('/'))).toBeNull()

    const { start, done } = await signIn(auth, cauthy, browser, '/books?year=2026')
    const to = new URL(start.headers.get('location')!)
    expect(to.origin + to.pathname).toBe('https://id.test/v1/oauth/authorize')
    expect(to.searchParams.get('client_id')).toBe('client_app')
    expect(to.searchParams.get('redirect_uri')).toBe('https://app.test/api/auth/callback')
    expect(to.searchParams.get('code_challenge_method')).toBe('S256')
    expect(to.searchParams.get('code_challenge')).toMatch(/^[\w-]{43}$/)

    expect(done.status).toBe(302)
    expect(done.headers.get('location')).toBe('/books?year=2026')
    const session = await auth.getSession(browser.request('/'))
    expect(session?.user).toEqual({ id: 'u1', email: 'ana@acme.com', name: 'Ana', emailVerified: true, restricted: false })
    expect(session?.tenantId).toBe('t1')
    expect(session?.roles).toEqual(['member'])
    expect(session?.expiresAt).toBe('2026-10-12T00:10:00.000Z')
  })

  it('keeps the session where script cannot read or change it', async () => {
    const { cauthy, auth, browser } = setup()
    const { done } = await signIn(auth, cauthy, browser)
    const cookie = done.headers.getSetCookie().find((c) => c.startsWith('cauthy_session.0='))!
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).toContain('Secure')
    // Encrypted: no token and no address can be read out of it.
    expect(cookie).not.toMatch(/at-|rt-|ana@acme/)

    // Changed by a byte, or made with another key, it is nobody's — and is cleared.
    const value = browser.jar.get('cauthy_session.0')!
    browser.jar.set('cauthy_session.0', value.slice(0, -2) + (value.endsWith('AA') ? 'BB' : 'AA'))
    const r = await auth.resolve(browser.request('/'))
    expect(r.session).toBeNull()
    expect(r.cookies.join()).toContain('Max-Age=0')

    browser.jar.set('cauthy_session.0', value)
    const other = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET + '-rotated', fetch: cauthy.fetch })
    expect(await other.getSession(browser.request('/'))).toBeNull()
  })

  it('only returns to a path of the application', async () => {
    const { cauthy, auth, browser } = setup({ afterSignIn: '/home' })
    for (const evil of ['https://evil.test/x', '//evil.test/x', '/\\evil.test', 'javascript:alert(1)',
      '/\t/evil.test', '/\n/evil.test', '/\r/evil.test', '/\\/evil.test', '///evil.test', '/\u0000/evil.test', '/\u007f/evil.test']) {
      const { done } = await signIn(auth, cauthy, new Browser(), evil)
      expect(done.headers.get('location')).toBe('/home')
    }
    const { done } = await signIn(auth, cauthy, browser)
    expect(done.headers.get('location')).toBe('/home')
  })

  it('refuses an answer to a question this browser did not ask', async () => {
    const { cauthy, auth, browser } = setup()
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    const back = new URL(cauthy.authorize(start.headers.get('location')!))

    // Another browser, with no sign-in of its own in progress: nobody is
    // signed in by the answer. It is sent to start a sign-in of its own, once.
    const stranger = new Browser()
    const first = await auth.handler(stranger.request(back.pathname + back.search))
    expect(first.status).toBe(302)
    expect(first.headers.get('location')).toBe('/api/auth/login?return_to=%2F')
    stranger.take(first)
    expect(await auth.getSession(stranger.request('/'))).toBeNull()
    // The same answer again does not go round for ever.
    expect((await auth.handler(stranger.request(back.pathname + back.search))).status).toBe(400)

    // The right browser, with the state swapped for one it never issued.
    browser.take(start)
    back.searchParams.set('state', 'forged')
    const res = await auth.handler(browser.request(back.pathname + back.search))
    expect(res.status).toBe(302) // starts again; the forged answer signs nobody in
    browser.take(res)
    expect((await auth.handler(browser.request(back.pathname + back.search))).status).toBe(400)
    expect(await auth.getSession(browser.request('/'))).toBeNull()
    expect(cauthy.calls).not.toContain('POST /v1/oauth/token')
  })

  it('finishes a sign-in whose page sat open until its question was forgotten', async () => {
    const { cauthy, auth, browser } = setup()
    const start = await auth.handler(browser.request(auth.urls.signIn('/books')))
    const late = new URL(cauthy.authorize(start.headers.get('location')!))
    // The browser kept nothing of the first start: its cookie ran out.
    const again = await auth.handler(browser.request(late.pathname + late.search))
    expect(again.status).toBe(302)
    browser.take(again)
    // It starts over; Cauthy still knows the person and answers at once.
    const restart = await auth.handler(browser.request(again.headers.get('location')!))
    browser.take(restart)
    const back = new URL(cauthy.authorize(restart.headers.get('location')!))
    const done = await auth.handler(browser.request(back.pathname + back.search))
    browser.take(done)
    expect(done.status).toBe(302)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect([...browser.jar.keys()].some((k) => k.endsWith('_again'))).toBe(false)
  })

  it('passes on what Cauthy refused, and treats "nobody signed in" as nobody', async () => {
    const { auth, browser } = setup()
    const start = await auth.handler(browser.request(auth.urls.signIn('/x') + '&prompt=none'))
    browser.take(start)
    const state = new URL(start.headers.get('location')!).searchParams.get('state')
    expect(new URL(start.headers.get('location')!).searchParams.get('prompt')).toBe('none')

    const nobody = await auth.handler(browser.request(`/api/auth/callback?error=login_required&state=${state}`))
    expect(nobody.status).toBe(302)
    expect(nobody.headers.get('location')).toBe('/x')

    const again = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(again)
    const state2 = new URL(again.headers.get('location')!).searchParams.get('state')
    expect((await auth.handler(browser.request(`/api/auth/callback?error=server_error&state=${state2}`))).status).toBe(400)

    // The person went back from Cauthy's page: to where they came from, told so.
    const third = await auth.handler(browser.request(auth.urls.signIn('/books') + '&method=passkey'))
    browser.take(third)
    const to = new URL(third.headers.get('location')!)
    expect(to.searchParams.get('method')).toBe('passkey')
    const back = await auth.handler(browser.request(`/api/auth/callback?error=access_denied&state=${to.searchParams.get('state')}`))
    expect(back.status).toBe(302)
    expect(back.headers.get('location')).toBe('/books?auth_error=cancelled')
  })
})

describe('renewing the session', () => {
  it('renews with Cauthy when the access token runs out, and sends the new cookie', async () => {
    const { cauthy, auth, browser } = setup()
    await signIn(auth, cauthy, browser)
    const before = browser.jar.get('cauthy_session.0')

    vi.setSystemTime(new Date('2026-10-12T00:09:45Z')) // inside the last 30 seconds
    // Without the response's headers nothing is renewed: the cookie could not go back.
    expect(await auth.getSession(browser.request('/'))).toBeNull()
    expect(await auth.status(browser.request('/'))).toBe('expired')
    expect(cauthy.calls.filter((c) => c === 'POST /v1/oauth/token')).toHaveLength(1)

    const headers = new Headers()
    const session = await auth.getSession(browser.request('/'), headers)
    expect(session?.user.id).toBe('u1')
    expect(session?.expiresAt).toBe('2026-10-12T00:19:45.000Z')
    browser.take(headers.getSetCookie())
    expect(browser.jar.get('cauthy_session.0')).not.toBe(before)
    expect(await auth.status(browser.request('/'))).toBe('authenticated')
  })

  it('shares one renewal between requests that arrive together', async () => {
    const { cauthy, auth, browser } = setup()
    await signIn(auth, cauthy, browser)
    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    const all = await Promise.all([1, 2, 3, 4].map(() => auth.resolve(browser.request('/'))))
    expect(all.every((r) => r.status === 'authenticated')).toBe(true)
    expect(cauthy.calls.filter((c) => c === 'POST /v1/oauth/token')).toHaveLength(2) // the sign-in, and one renewal
  })

  it('ends the session when Cauthy says it is over', async () => {
    const { cauthy, auth, browser } = setup()
    await signIn(auth, cauthy, browser)
    cauthy.users.get('u1')!.active = false // disabled in Cauthy
    expect((await auth.getSession(browser.request('/')))?.user.id).toBe('u1') // until the token runs out

    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    const r = await auth.resolve(browser.request('/'))
    expect(r.status).toBe('unauthenticated')
    browser.take(r.cookies)
    expect(browser.jar.size).toBe(0)
  })

  it('keeps the session, and lets nobody in, while Cauthy cannot be reached', async () => {
    const { cauthy, auth, browser } = setup()
    await signIn(auth, cauthy, browser)
    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    cauthy.down = true
    const r = await auth.resolve(browser.request('/'))
    expect(r).toEqual({ session: null, status: 'expired', cookies: [] })

    cauthy.down = false
    // The failed attempt is not remembered: the next request asks again.
    expect((await auth.resolve(browser.request('/'))).status).toBe('authenticated')
  })
})

describe('the routes', () => {
  it('tells the browser who is signed in and their organizations, and never a token', async () => {
    const { cauthy, auth, browser } = setup()
    cauthy.orgs.set('u1', [
      { id: 'o1', system: 'ledger', name: 'Acme SAS', kind: 'business', external_id: 'ent-1', role: 'owner', metadata: { nit: '900' } },
      { id: 'o2', system: 'clinic', name: 'Clínica', kind: '', role: 'medico', metadata: {} },
    ])
    const nobody = await (await auth.handler(browser.request('/api/auth/session'))).json()
    expect(nobody).toEqual({ session: null, status: 'unauthenticated' })

    await signIn(auth, cauthy, browser)
    const res = await auth.handler(browser.request('/api/auth/session'))
    expect(res.headers.get('cache-control')).toBe('no-store')
    const text = await res.text()
    expect(text).not.toMatch(/at-|rt-|accessToken/)
    const body = JSON.parse(text)
    expect(body.status).toBe('authenticated')
    expect(body.session.user.email).toBe('ana@acme.com')
    // Only this system's organizations, with the person's role in each.
    expect(body.session.organizations).toEqual([
      { id: 'o1', system: 'ledger', name: 'Acme SAS', kind: 'business', externalId: 'ent-1', role: 'owner', metadata: { nit: '900' } },
    ])
  })

  it('signs out here and in Cauthy', async () => {
    const { cauthy, auth, browser } = setup({ afterSignOut: '/bye' })
    await signIn(auth, cauthy, browser)
    const res = await auth.handler(browser.request(auth.urls.signOut()))
    browser.take(res)
    expect(browser.jar.size).toBe(0)
    expect(cauthy.revoked).toHaveLength(1)
    const to = new URL(res.headers.get('location')!)
    expect(to.pathname).toBe('/v1/oauth/logout')
    expect(to.searchParams.get('post_logout_redirect_uri')).toBe('https://app.test/bye')
    expect(await auth.getSession(browser.request('/'))).toBeNull()
  })

  it('opens the account page of Cauthy, with a way back to the application', async () => {
    const { auth, browser } = setup()
    const res = await auth.handler(browser.request(auth.urls.account('/settings')))
    const to = new URL(res.headers.get('location')!)
    expect(to.pathname).toBe('/v1/oauth/account')
    expect(to.searchParams.get('client_id')).toBe('client_app')
    expect(to.searchParams.get('return_to')).toBe('https://app.test/settings')
    const evil = await auth.handler(browser.request('/api/auth/account?return_to=https://evil.test'))
    expect(new URL(evil.headers.get('location')!).searchParams.has('return_to')).toBe(false)
  })

  it('renews for a page that found its session expired, and goes back to it', async () => {
    const { cauthy, auth, browser } = setup()
    await signIn(auth, cauthy, browser)
    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    const res = await auth.handler(browser.request('/api/auth/refresh?return_to=/books'))
    expect(res.headers.get('location')).toBe('/books')
    browser.take(res)
    expect(await auth.status(browser.request('/'))).toBe('authenticated')
    expect((await auth.handler(new Browser().request('/api/auth/refresh?return_to=/books'))).headers.get('location')).toBe('/api/auth/login?return_to=%2Fbooks')
    expect((await auth.handler(browser.request('/api/auth/nope'))).status).toBe(404)
    expect((await auth.handler(browser.request('/elsewhere'))).status).toBe(404)
  })
})

describe('protecting a route', () => {
  it('sends a page to sign in, tells a fetch, and lets a signed-in person through', async () => {
    const { cauthy, auth, browser } = setup()
    const page = await auth.protect(browser.request('/books?year=2026', { headers: { accept: 'text/html', 'sec-fetch-mode': 'navigate' } }))
    expect(page.response?.headers.get('location')).toBe('/api/auth/login?return_to=%2Fbooks%3Fyear%3D2026')

    const api = await auth.protect(browser.request('/api/books', { headers: { accept: 'application/json', 'sec-fetch-mode': 'cors' } }))
    expect(api.response?.status).toBe(401)
    expect(api.response?.headers.get('x-cauthy-session')).toBe('none')
    const post = await auth.protect(browser.request('/books', { method: 'POST', headers: { accept: 'text/html' } }))
    expect(post.response?.status).toBe(401)

    await signIn(auth, cauthy, browser)
    expect((await auth.protect(browser.request('/books'))).session?.user.id).toBe('u1')

    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    const stale = await auth.protect(browser.request('/books', { headers: { accept: 'text/html' } }))
    expect(stale.response?.headers.get('location')).toBe('/api/auth/refresh?return_to=%2Fbooks')
    const staleApi = await auth.protect(browser.request('/api/books', { headers: { accept: 'application/json' } }))
    expect(staleApi.response?.headers.get('x-cauthy-session')).toBe('expired')
  })
})

describe('a session too large for one cookie', () => {
  it('is written in parts and read back whole, and shrinks cleanly', async () => {
    const { cauthy, auth, browser } = setup()
    cauthy.users.get('u1')!.name = 'A'.repeat(6000)
    await signIn(auth, cauthy, browser)
    expect(browser.jar.has('cauthy_session.1')).toBe(true)
    expect((await auth.getSession(browser.request('/')))?.user.name).toHaveLength(6000)

    cauthy.users.get('u1')!.name = 'Ana'
    vi.setSystemTime(new Date('2026-10-12T00:11:00Z'))
    browser.take((await auth.resolve(browser.request('/'))).cookies)
    expect(browser.jar.has('cauthy_session.1')).toBe(false)
    expect((await auth.getSession(browser.request('/')))?.user.name).toBe('Ana')
  })
})

describe('organizations the application changes', () => {
  it('shows a person an organization they were just added to, without waiting for the cache', async () => {
    const cauthy = new FakeCauthy()
    // What the application's own identity calls: its token, and adding a member.
    const fetch: typeof cauthy.fetch = async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
      if (url.pathname === '/v1/oauth/token' && String(init?.body ?? '').includes('client_credentials')) {
        return new Response(JSON.stringify({ access_token: 'system-token', expires_in: 300 }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      const added = /^\/v1\/organizations\/([^/]+)\/members$/.exec(url.pathname)
      if (added && init?.method === 'POST') {
        cauthy.orgs.set('u1', [{ id: added[1], system: 'ledger', name: 'Acme', kind: 'customer', role: 'owner' }])
        const member = { user_id: 'u1', email: 'u1@example.com', role: 'owner', status: 'active' }
        return new Response(JSON.stringify({ data: member }), { status: 201, headers: { 'content-type': 'application/json' } })
      }
      return cauthy.fetch(input, init)
    }
    const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET, clientSecret: 'cs_app', system: 'ledger', fetch })
    const browser = new Browser()
    await signIn(auth, cauthy, browser)
    const session = (await auth.getSession(browser.request('/')))!

    expect(await auth.organizations(session)).toEqual([])
    await auth.system.members.add('o1', { userId: 'u1', role: 'owner' })
    expect((await auth.organizations(session)).map((o) => o.name)).toEqual(['Acme'])
  })
})

// A contract may ask that a code be exchanged only with the system's own
// proof (require_system_proof): the exchange carries it, so a copied client
// id is no use on its own.
describe('the code exchange', () => {
  function proving(system: boolean) {
    const cauthy = new FakeCauthy()
    const exchanges: Headers[] = []
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''))
      if (form.get('grant_type') === 'client_credentials') {
        return system
          ? new Response(JSON.stringify({ access_token: 'the-system-token', token_type: 'Bearer', expires_in: 600 }), { status: 200 })
          : new Response(JSON.stringify({ error: 'unauthorized_client' }), { status: 400 })
      }
      if (form.get('grant_type') === 'authorization_code') exchanges.push(new Headers(init?.headers))
      return cauthy.fetch(input, init)
    }
    const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', clientSecret: 'cs_x', secret: SECRET, tenant: 'acme', fetch })
    return { cauthy, auth, exchanges }
  }

  it('carries the system\'s proof', async () => {
    const { cauthy, auth, exchanges } = proving(true)
    const { done } = await signIn(auth, cauthy, new Browser())
    expect(done.status).toBe(302)
    expect(exchanges[0].get('x-cauthy-system-token')).toBe('the-system-token')
  })

  it('still signs in when the application is no system', async () => {
    const { cauthy, auth, exchanges } = proving(false)
    const browser = new Browser()
    await signIn(auth, cauthy, browser)
    expect(exchanges[0].get('x-cauthy-system-token')).toBeNull()
    expect((await auth.getSession(browser.request('/')))?.user.id).toBe('u1')
  })
})
