import { describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'

const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'
const TENANT = '8c2f1d6e-5b0a-4f7e-9a3d-2e6b1c4d7f90'

function graph(requireVerifiedEmail: boolean) {
  return {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: 'https://id.test', tenants: [{ id: TENANT, slug: 'acme', name: 'Acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test' },
    ],
    edges: [{
      from: 'acme-crm', relation: 'links', to: 'cauthy', link: 'acme-crm-signs-in-with-cauthy',
      identity: { issuer: 'cauthy', tenant: TENANT, subject: 'users' },
      sign_in: { client_id: 'pact.acme-crm-signs-in-with-cauthy', redirect_uris: ['https://app.test/api/auth/callback'], require_system_proof: false, require_verified_email: requireVerifiedEmail },
    }],
  }
}

function app(requireVerifiedEmail: boolean, verified: boolean) {
  const cauthy = new FakeCauthy()
  cauthy.ownScreens = true
  cauthy.passwords.set('ana@acme.com', 'right-password')
  cauthy.users.get('u1')!.verified = verified
  const auth = createCauthy({ contract: { graph: graph(requireVerifiedEmail), system: 'acme-crm' }, rootKey: ROOT, fetch: cauthy.fetch })
  return { cauthy, auth, browser: new Browser('https://app.test') }
}

const signIn = (a: ReturnType<typeof app>) =>
  a.auth.handler(a.browser.request('/api/auth/sign-in/email', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: a.browser.origin },
    body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
  }))

describe('a link that requires a verified address', () => {
  it('refuses a person whose address is not confirmed, and sets no session', async () => {
    const a = app(true, false)
    const res = await signIn(a)
    expect(res.status).toBe(403)
    expect((await res.json()).error.code).toBe('email_not_confirmed')
    expect(res.headers.getSetCookie().filter((c) => c.startsWith('cauthy_session'))).toEqual([])
  })

  it('revokes the refresh token it was just given, when it refuses', async () => {
    const a = app(true, false)
    await signIn(a)
    expect(a.cauthy.revoked).toHaveLength(1)
  })

  it('sends the hosted callback back to the sign-in page with the reason, and clears the flow', async () => {
    const a = app(true, false)
    const start = await a.auth.handler(a.browser.request(a.auth.urls.signIn()))
    a.browser.take(start)
    const back = new URL(a.cauthy.authorize(start.headers.get('location')!))
    const res = await a.auth.handler(a.browser.request(back.pathname + back.search))
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('auth_error=email_not_confirmed')
    expect(res.headers.getSetCookie().some((c) => c.startsWith('cauthy_session_flow=;') || c.startsWith('cauthy_session_flow=; '))).toBe(true)
    expect(res.headers.getSetCookie().filter((c) => c.startsWith('cauthy_session.'))).toEqual([])
    expect(a.cauthy.revoked).toHaveLength(1)
    expect(res.headers.get('cauthy-protocol')).toBe('1')
  })

  it('hears Cauthy say so at the token endpoint (400 email_not_confirmed) and does the same', async () => {
    const cauthy = new FakeCauthy()
    const refusing: typeof fetch = async (input, init) => {
      const url = new URL(String(input))
      if (url.pathname === '/v1/oauth/token' && String(init?.body).includes('authorization_code')) {
        return new Response(JSON.stringify({ error: 'email_not_confirmed', error_description: 'the person has not confirmed their email address' }), { status: 400, headers: { 'content-type': 'application/json' } })
      }
      return cauthy.fetch(input, init)
    }
    const auth = createCauthy({ contract: { graph: graph(false), system: 'acme-crm' }, rootKey: ROOT, fetch: refusing })
    const browser = new Browser('https://app.test')
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(start)
    const back = new URL(cauthy.authorize(start.headers.get('location')!))
    const res = await auth.handler(browser.request(back.pathname + back.search))
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('auth_error=email_not_confirmed')
    expect(res.headers.getSetCookie().some((c) => c.startsWith('cauthy_session_flow=;'))).toBe(true)
  })

  it('lets a confirmed address in', async () => {
    expect((await signIn(app(true, true))).status).toBe(200)
  })

  it('does not ask when the link does not', async () => {
    expect((await signIn(app(false, false))).status).toBe(200)
  })

  it('does not honour a session the person got before the link required it', async () => {
    const before = app(false, false)
    const res = await signIn(before)
    before.browser.take(res)
    const after = createCauthy({ contract: { graph: graph(true), system: 'acme-crm' }, rootKey: ROOT, fetch: before.cauthy.fetch })
    expect(await after.getSession(before.browser.request('/api/auth/session'))).toBeNull()
    expect(await before.auth.getSession(before.browser.request('/api/auth/session'))).not.toBeNull()
    const answer = await after.handler(before.browser.request('/api/auth/session'))
    expect((await answer.json()).status).toBe('unauthenticated')
    // protect() sends such a person to sign in, as it does nobody.
    const guarded = await after.protect(before.browser.request('/books'))
    expect(guarded.response?.headers.get('location')).toContain('/api/auth/login')
    expect('session' in guarded).toBe(false)
  })
})
