// On CAUTHY_KEY, people sign in through the client Cauthy names
// (sign_in_client_id), which is not always the key's: an application once
// connected by contract has its key on `pact.<link>.service` and its people,
// and their refresh tokens, on `pact.<link>`. The key proves the key's client
// only; the sign-in client is public, and the code exchange carries the
// system's proof, as contract mode always sent.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { Browser, FakeCauthy } from './testing'

const LINK = 'acme-crm-signs-in-with-cauthy'
const SERVICE = `pact.${LINK}.service`
const SIGN_IN = `pact.${LINK}`

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

async function app(signInClient?: string) {
  const fake = new FakeCauthy()
  const keyClient = signInClient ? SERVICE : fake.clientId
  if (signInClient) fake.signInClients.set(SERVICE, signInClient)
  vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: keyClient }))
  const auth = createCauthy({ fetch: fake.fetch })
  return { fake, auth, keyClient }
}

async function signIn(fake: FakeCauthy, auth: ReturnType<typeof createCauthy>, b: Browser) {
  const login = await auth.handler(b.request('/api/auth/login?return_to=/'))
  b.take(login)
  const back = new URL(fake.authorize(login.headers.get('location')!))
  const done = await auth.handler(b.request(back.pathname + back.search))
  b.take(done)
  return { login, done }
}

describe('a key whose client is not the one people sign in with', () => {
  it('sends people to Cauthy through the sign-in client, and exchanges the code as that public client with the proof', async () => {
    const { fake, auth } = await app(SIGN_IN)
    expect(await auth.ready()).toMatchObject({ client_id: SERVICE, sign_in_client_id: SIGN_IN })
    const b = new Browser('http://localhost:3000')
    const { login, done } = await signIn(fake, auth, b)
    expect(new URL(login.headers.get('location')!).searchParams.get('client_id')).toBe(SIGN_IN)
    expect(done.status).toBe(302)
    expect((await auth.getSession(b.request('/')))?.user.id).toBe('u1')

    const exchange = fake.oauthRequests.find(r => r.form.grant_type === 'authorization_code')!
    expect(exchange.form.client_id).toBe(SIGN_IN)
    expect(exchange.form.client_assertion).toBeUndefined()
    expect(exchange.form.client_secret).toBeUndefined()
    expect(exchange.headers['x-cauthy-system-token']).toMatch(/^sys-/)
    // The key still proves the key's own client.
    const cc = fake.oauthRequests.find(r => r.form.grant_type === 'client_credentials')!
    expect(cc.form.client_id).toBe(SERVICE)
    expect(cc.form.client_assertion).toBeTruthy()
  })

  it('renews and revokes through the sign-in client, which owns the refresh token', async () => {
    const { fake, auth } = await app(SIGN_IN)
    const b = new Browser('http://localhost:3000')
    await signIn(fake, auth, b)
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 3_600_000)
    const res = await auth.handler(b.request('/api/auth/session'))
    b.take(res)
    expect((await res.json()).status).toBe('authenticated')
    const refresh = fake.oauthRequests.filter(r => r.form.grant_type === 'refresh_token')
    expect(refresh).toHaveLength(1)
    expect(refresh[0].form.client_id).toBe(SIGN_IN)
    expect(refresh[0].form.client_assertion).toBeUndefined()

    const out = await auth.handler(b.request('/api/auth/logout', { method: 'POST' }))
    expect(out.status).toBe(302)
    expect(new URL(out.headers.get('location')!).searchParams.get('client_id')).toBe(SIGN_IN)
    const revoke = fake.oauthRequests.find(r => r.path === '/v1/oauth/revoke')!
    expect(revoke.form.client_id).toBe(SIGN_IN)
    expect(revoke.form.client_assertion).toBeUndefined()
    expect(fake.revoked).toHaveLength(1)
  })

  it('waits for Cauthy\'s answer before renewing outside the handler, so the refresh token is never spent on the wrong client', async () => {
    const { fake, auth } = await app(SIGN_IN)
    const b = new Browser('http://localhost:3000')
    await signIn(fake, auth, b)
    // A second process with the same key, asked by getSession before anything else.
    const again = createCauthy({ fetch: fake.fetch })
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 3_600_000)
    const headers = new Headers()
    expect((await again.getSession(b.request('/'), headers))?.user.id).toBe('u1')
    expect(fake.oauthRequests.filter(r => r.form.grant_type === 'refresh_token').map(r => r.form.client_id)).toEqual([SIGN_IN])
  })

  it('opens the account page as the sign-in client', async () => {
    const { auth } = await app(SIGN_IN)
    const res = await auth.handler(new Browser('http://localhost:3000').request('/api/auth/account'))
    expect(new URL(res.headers.get('location')!).searchParams.get('client_id')).toBe(SIGN_IN)
  })
})

describe('a key whose client is the one people sign in with', () => {
  it('is unchanged: everything goes as the key\'s client, with the assertion', async () => {
    const { fake, auth, keyClient } = await app()
    expect(await auth.ready()).toMatchObject({ client_id: keyClient, sign_in_client_id: keyClient })
    const b = new Browser('http://localhost:3000')
    const { login } = await signIn(fake, auth, b)
    expect(new URL(login.headers.get('location')!).searchParams.get('client_id')).toBe(keyClient)
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 3_600_000)
    expect((await (await auth.handler(b.request('/api/auth/session'))).json()).status).toBe('authenticated')
    for (const grant of ['authorization_code', 'refresh_token']) {
      const r = fake.oauthRequests.find(x => x.form.grant_type === grant)!
      expect(r.form.client_id).toBe(keyClient)
      expect(r.form.client_assertion).toBeTruthy()
    }
  })
})

describe('the contract option', () => {
  it('still works, and says once that contracts are retired', async () => {
    vi.resetModules()
    const warn = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined)
    const { createCauthy: fresh } = await import('./cauthy')
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: SERVICE }))
    const graph = {
      version: 1,
      nodes: [
        { id: 'cauthy', type: 'system', url: fake.issuer, tenants: [{ id: '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b', slug: 'acme' }] },
        { id: 'acme-crm', type: 'system', url: 'https://app.test', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
      ],
      edges: [{
        from: 'acme-crm', relation: 'links', to: 'cauthy', link: LINK,
        identity: { issuer: 'cauthy', tenant: '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b', subject: 'b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e' },
        sign_in: { client_id: SIGN_IN, redirect_uris: ['https://app.test/api/auth/callback'] },
        service: { client_id: SERVICE, system: 'acme-crm', jwks_url: 'https://app.test/.well-known/pact-jwks.json', import: false },
      }],
    }
    const a = fresh({ contract: { graph, system: 'acme-crm' }, fetch: fake.fetch })
    fresh({ contract: { graph, system: 'acme-crm' }, fetch: fake.fetch })
    const said = warn.mock.calls.filter(c => String(c[0]).includes('The contract option is deprecated'))
    expect(said).toHaveLength(1)
    expect(String(said[0][0])).toMatch(/Contracts are retired.*CAUTHY_KEY.*same key keeps every session/)
    const start = await a.handler(new Browser().request(a.urls.signIn()))
    expect(new URL(start.headers.get('location')!).searchParams.get('client_id')).toBe(SIGN_IN)
  })
})
