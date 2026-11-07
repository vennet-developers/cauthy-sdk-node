import { describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'
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

// vi is used by the describe block Task 9 adds to this file.
void vi
