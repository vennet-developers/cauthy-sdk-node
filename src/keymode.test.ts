import { afterEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'
import { CauthyKeyError } from './types'

afterEach(() => vi.unstubAllEnvs())

async function app(env: Record<string, string> = {}) {
  const fake = new FakeCauthy()
  vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
  for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v)
  const auth = createCauthy({ fetch: fake.fetch })
  return { fake, auth }
}

/** Sign in through Cauthy's page, as a person would. */
async function signIn(fake: FakeCauthy, auth: ReturnType<typeof createCauthy>, b: Browser) {
  const login = await auth.handler(b.request('/api/auth/login?return_to=/'))
  b.take(login)
  const back = new URL(fake.authorize(login.headers.get('location')!))
  const done = await auth.handler(b.request(back.pathname + back.search))
  b.take(done)
  return { login, done }
}

describe('key mode', () => {
  it('signs a person in with nothing but CAUTHY_KEY', async () => {
    const { fake, auth } = await app()
    const b = new Browser('http://localhost:3000')
    const { login, done } = await signIn(fake, auth, b)
    expect(new URL(login.headers.get('location')!).searchParams.get('client_id')).toBe(fake.clientId)
    expect(done.status).toBe(302)
    const session = await auth.handler(b.request('/api/auth/session'))
    expect((await session.json()).session.user.id).toBe('u1')
    const exchange = fake.oauthRequests.find(r => r.form.grant_type === 'authorization_code')!
    expect(exchange.form.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
    expect(exchange.form.client_secret).toBeUndefined()
    expect(exchange.headers['x-cauthy-system-token']).toBeTruthy() // the proof, always
    expect(fake.oauthRequests.some(r => r.form.client_secret !== undefined)).toBe(false)
  })

  it('renews and signs out with the assertion too', async () => {
    const { fake, auth } = await app()
    const b = new Browser('http://localhost:3000')
    await signIn(fake, auth, b)
    fake.expiresIn = 1
    const out = await auth.handler(b.request('/api/auth/logout', { method: 'POST' }))
    expect(out.status).toBe(302)
    const revoke = fake.oauthRequests.find(r => r.path === '/v1/oauth/revoke')!
    expect(revoke.form.client_assertion).toBeTruthy()
    expect(fake.revoked.length).toBe(1)
  })

  it('takes the workspace and the system from Cauthy\'s answer', async () => {
    const { fake, auth } = await app()
    const id = await auth.ready()
    expect(id).toMatchObject({ issuer: fake.issuer, client_id: fake.clientId, tenant: { slug: 'acme' }, system: 'acme-crm' })
    fake.ownScreens = true
    fake.passwords.set('ana@acme.com', 'right-password')
    const b = new Browser('http://localhost:3000')
    const res = await auth.handler(b.request('/api/auth/sign-in/email', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
    }))
    expect(res.status).toBe(200) // the fake checks X-Tenant-Key: acme
  })

  it('refuses a damaged key at once, naming the reason only', async () => {
    const fake = new FakeCauthy()
    const key = await fake.issueKey()
    vi.stubEnv('CAUTHY_KEY', key.slice(0, -1) + (key.endsWith('A') ? 'B' : 'A'))
    expect(() => createCauthy({ fetch: fake.fetch })).toThrow(/key_checksum/)
    let err: unknown
    try { createCauthy({ fetch: fake.fetch }) } catch (e) { err = e }
    expect(err).toBeInstanceOf(CauthyKeyError)
    expect(String((err as Error).message)).not.toContain(key.split('.')[3])
  })

  it('refuses CAUTHY_KEY beside the old variables', async () => {
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    vi.stubEnv('CAUTHY_CLIENT_ID', 'x')
    vi.stubEnv('CAUTHY_BASE_URL', 'http://localhost:3000')
    expect(() => createCauthy({ fetch: fake.fetch })).toThrow(/CAUTHY_CLIENT_ID, CAUTHY_BASE_URL/)
  })

  it('refuses options the key owns', async () => {
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    expect(() => createCauthy({ fetch: fake.fetch, clientId: 'x' })).toThrow(/clientId comes from CAUTHY_KEY/)
    expect(() => createCauthy({ fetch: fake.fetch, secret: 'x'.repeat(40) })).toThrow(/secret comes from CAUTHY_KEY/)
  })

  it('takes the key as an option too', async () => {
    const fake = new FakeCauthy()
    const auth = createCauthy({ key: await fake.issueKey(), fetch: fake.fetch })
    expect(auth.options.clientId).toBe(fake.clientId)
    expect((await auth.ready()).client_id).toBe(fake.clientId)
  })

  it('answers 503 unavailable while Cauthy cannot be asked, then works', async () => {
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    fake.down = true
    const auth = createCauthy({ fetch: fake.fetch })
    const b = new Browser('http://localhost:3000')
    const res = await auth.handler(b.request('/api/auth/session'))
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('unavailable')
    fake.down = false
    await auth.ready()
    expect((await auth.handler(b.request('/api/auth/session'))).status).toBe(200)
  })

  it('answers 503 misconfigured when the key was revoked', async () => {
    const { fake, auth } = await app()
    fake.revokeKey(fake.registeredKids()[0])
    await expect(auth.ready()).rejects.toMatchObject({ code: 'misconfigured' })
    const res = await auth.handler(new Browser('http://localhost:3000').request('/api/auth/session'))
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('misconfigured')
  })

  it('builds the redirect URI from a registered origin only', async () => {
    const { fake, auth } = await app()
    fake.appUrls = ['http://localhost:3000', 'https://crm.example.com']
    const evil = await auth.handler(new Browser('https://evil.example.com').request('/api/auth/login'))
    expect(evil.status).toBe(400)
    const body = await evil.json()
    expect(body.error.code).toBe('unknown_origin')
    expect(body.error.message).toContain('https://crm.example.com')
    const prod = await auth.handler(new Browser('https://crm.example.com').request('/api/auth/login'))
    expect(new URL(prod.headers.get('location')!).searchParams.get('redirect_uri')).toBe('https://crm.example.com/api/auth/callback')
  })

  it('uses the only registered origin when the request names another', async () => {
    const { auth } = await app()
    const res = await auth.handler(new Browser('http://127.0.0.1:3000').request('/api/auth/login'))
    expect(new URL(res.headers.get('location')!).searchParams.get('redirect_uri')).toBe('http://localhost:3000/api/auth/callback')
  })

  it('acts on its own with the key: auth.system asks with an assertion', async () => {
    const { fake, auth } = await app()
    const token = await auth.system.token()
    expect(token).toMatch(/^sys-/)
    const cc = fake.oauthRequests.filter(r => r.form.grant_type === 'client_credentials')
    expect(cc.length).toBeGreaterThan(0)
    expect(cc.every(r => r.form.client_assertion && !r.form.client_secret)).toBe(true)
  })
})
