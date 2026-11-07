import { describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'
import { POST_ROUTES } from '../test-support/post-routes'
import type { CauthyOptions } from './types'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'

function app(over: Partial<CauthyOptions> = {}) {
  const cauthy = new FakeCauthy()
  cauthy.ownScreens = true
  cauthy.passwords.set('ana@acme.com', 'right-password')
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: SECRET, tenant: cauthy.tenant, fetch: cauthy.fetch, baseURL: 'https://app.test', ...over })
  return { cauthy, auth, browser: new Browser('https://app.test') }
}

const signIn = (a: ReturnType<typeof app>, base = '/api/auth', browser = a.browser) =>
  a.auth.handler(browser.request(`${base}/sign-in/email`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: browser.origin },
    body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
  }))

describe('protocol version 1 at level strict', () => {
  it('says its version and no-store on every answer, the plain-text ones too', async () => {
    const { auth, browser } = app()
    const answers = [
      await auth.handler(browser.request('/api/auth/session')),
      await auth.handler(browser.request('/api/auth/nope')), // plain-text 404
      await auth.handler(browser.request('/api/auth/sign-in/email')), // plain-text 405
      await auth.handler(browser.request('/api/auth/login')), // redirect
    ]
    expect(answers.map((r) => r.status)).toEqual([200, 404, 405, 302])
    for (const res of answers) {
      expect(res.headers.get('cauthy-protocol')).toBe('1')
      expect(res.headers.get('cache-control')).toContain('no-store')
    }
  })

  it('answers next on a sign-in', async () => {
    const a = app()
    const res = await signIn(a)
    expect(await res.json()).toMatchObject({ status: 'signed_in', next: 'done' })
    expect(res.headers.getSetCookie().some((c) => c.startsWith('cauthy_session.0='))).toBe(true)
  })

  it('does the same under another basePath', async () => {
    const a = app({ basePath: '/auth' })
    const res = await signIn(a, '/auth')
    expect(res.headers.get('cauthy-protocol')).toBe('1')
    expect((await res.json()).next).toBe('done')
  })
})

describe('X-Cauthy-Request on every mutation', () => {
  // A browser whose client sends no X-Cauthy-Request, as cauthy-auth 0.42's does not.
  const bare = (a: ReturnType<typeof app>, path: string, body: unknown = { email: 'ana@acme.com', password: 'right-password' }) => {
    const browser = new Browser('https://app.test', { requestHeader: false })
    return a.auth.handler(browser.request(path, { method: 'POST', headers: { 'content-type': 'application/json', origin: browser.origin }, body: JSON.stringify(body) }))
  }

  it('refuses a POST without it, 403 csrf_required, before anything reaches Cauthy', async () => {
    const a = app()
    const res = await bare(a, '/api/auth/sign-in/email')
    expect(res.status).toBe(403)
    expect((await res.json()).error.code).toBe('csrf_required')
    expect(a.cauthy.calls).toEqual([])
  })

  it.each(['yes', 'true', '0', '', '1, 1', ' 1', '1 '])('refuses the value %j: only 1 counts', async (value) => {
    const a = app()
    const browser = new Browser('https://app.test', { requestHeader: false })
    const res = await a.auth.handler(browser.request('/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: browser.origin, 'x-cauthy-request': value },
      body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
    }))
    // (A header value is trimmed by the platform, so ' 1' and '1 ' may count as 1.)
    if (value.trim() === '1') expect(res.status).toBe(200)
    else {
      expect(res.status).toBe(403)
      expect((await res.json()).error.code).toBe('csrf_required')
      expect(a.cauthy.calls).toEqual([])
    }
  })

  const routes = POST_ROUTES.filter((r) => r.path !== '/logout')
  it('has the whole table of the spec', () => {
    expect(POST_ROUTES.length).toBe(49)
    expect(POST_ROUTES.some((r) => r.path === '/logout')).toBe(true)
  })

  it.each(routes.map((r) => [r.id, r.path]))('%s (POST %s) without it is 403 csrf_required, and Cauthy hears nothing', async (_id, path) => {
    const a = app()
    const res = await bare(a, `/api/auth${path}`, {})
    expect(res.status).toBe(403)
    expect((await res.json()).error.code).toBe('csrf_required')
    expect(res.headers.get('cauthy-protocol')).toBe('1')
    expect(a.cauthy.calls).toEqual([])
  })

  it('refuses it on the permission check too', async () => {
    const a = app()
    const res = await bare(a, '/api/auth/me/organizations/check', { organizationId: '00000000-0000-4000-8000-000000000000', resource: 'deals', action: 'read' })
    expect(res.status).toBe(403)
    expect((await res.json()).error.code).toBe('csrf_required')
    expect(a.cauthy.calls).toEqual([])
  })

  it('lets POST /logout through without it: a plain HTML form signs out', async () => {
    const res = await bare(app(), '/api/auth/logout', {})
    expect(res.status).toBe(302)
  })

  it('lets it through with requestHeader warn, and says so once', async () => {
    const a = app({ requestHeader: 'warn' })
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect((await bare(a, '/api/auth/sign-in/email')).status).toBe(200)
      expect((await bare(a, '/api/auth/sign-in/email')).status).toBe(200)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(String(warn.mock.calls[0][0])).toContain('X-Cauthy-Request')
    } finally {
      warn.mockRestore()
    }
  })

  it('says so once per process, not once per Cauthy', async () => {
    vi.resetModules()
    const fresh = await import('./cauthy')
    const testing = await import('./testing')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      for (let i = 0; i < 2; i++) {
        const cauthy = new testing.FakeCauthy()
        cauthy.ownScreens = true
        const auth = fresh.createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: SECRET, tenant: cauthy.tenant, fetch: cauthy.fetch, baseURL: 'https://app.test', requestHeader: 'warn' })
        const browser = new testing.Browser('https://app.test', { requestHeader: false })
        await auth.handler(browser.request('/api/auth/sign-in/email', { method: 'POST', headers: { 'content-type': 'application/json', origin: browser.origin }, body: '{}' }))
      }
      expect(warn).toHaveBeenCalledTimes(1)
    } finally {
      warn.mockRestore()
    }
  })

  it('refuses a requestHeader it does not know', () => {
    expect(() => app({ requestHeader: 'off' as never })).toThrow(/requestHeader/)
  })
})

describe('the envelope on every kind of answer', () => {
  const envelope = (res: Response) => {
    expect(res.headers.get('cauthy-protocol')).toBe('1')
    expect(res.headers.get('cache-control')).toContain('no-store')
  }

  it('is on the callback\'s plain-text 400', async () => {
    const { auth, browser } = app()
    browser.jar.set('cauthy_session_again', '1') // already sent back to sign in once
    const res = await auth.handler(browser.request('/api/auth/callback?code=c&state=s'))
    expect(res.status).toBe(400)
    expect(res.headers.get('content-type')).toContain('text/plain')
    envelope(res)
  })

  it('is on the refresh\'s plain-text 503', async () => {
    const a = app()
    a.cauthy.expiresIn = 1 // inside the renewal window at once
    const browser = a.browser
    browser.take(await signIn(a))
    a.cauthy.down = true
    const res = await a.auth.handler(browser.request('/api/auth/refresh?return_to=/books'))
    expect(res.status).toBe(503)
    envelope(res)
  })

  it('is on the 404 for a provider id that is not one', async () => {
    const { auth, browser } = app()
    const res = await auth.handler(browser.request('/api/auth/sign-in/social/%20bad%20id'))
    expect(res.status).toBe(404)
    envelope(res)
  })

  it('is on the 403 csrf_required', async () => {
    const a = app()
    const browser = new Browser('https://app.test', { requestHeader: false })
    const res = await a.auth.handler(browser.request('/api/auth/sign-in/email', { method: 'POST', headers: { 'content-type': 'application/json', origin: browser.origin }, body: '{}' }))
    expect(res.status).toBe(403)
    envelope(res)
  })

  it('is on an error Cauthy gave, passed through as it is, with no next', async () => {
    const a = app()
    const res = await a.auth.handler(a.browser.request('/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: a.browser.origin },
      body: JSON.stringify({ email: 'ana@acme.com', password: 'wrong' }),
    }))
    expect(res.status).toBe(401)
    envelope(res)
    expect(await res.json()).toMatchObject({ error: { code: 'invalid_credentials' } })
  })
})
