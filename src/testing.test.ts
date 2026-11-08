import { describe, expect, it } from 'vitest'
import { FakeCauthy, serveFakeCauthy } from './testing'

const login = (fake: FakeCauthy, body: unknown, tenant = 'acme') =>
  fake.fetch(`${fake.issuer}/v1/auth/login`, {
    method: 'POST',
    headers: { 'x-tenant-key': tenant, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

describe('the fake Cauthy, for an application\'s own screens', () => {
  it('answers nothing of /v1/auth unless asked to', async () => {
    const fake = new FakeCauthy()
    fake.passwords.set('ana@acme.com', 'right-password')
    expect((await login(fake, { email: 'ana@acme.com', password: 'right-password' })).status).toBe(404)
  })

  it('signs a password account in, and refuses a wrong password or another workspace', async () => {
    const fake = new FakeCauthy()
    fake.ownScreens = true
    fake.passwords.set('ana@acme.com', 'right-password')
    const ok = await login(fake, { email: 'ana@acme.com', password: 'right-password' })
    expect(ok.status).toBe(200)
    const { data } = await ok.json()
    expect(fake.access.get(data.access_token)).toBe('u1')
    const wrong = await login(fake, { email: 'ana@acme.com', password: 'nope' })
    expect(wrong.status).toBe(401)
    expect((await wrong.json()).errors[0].code).toBe('invalid_credentials')
    expect((await login(fake, { email: 'ana@acme.com', password: 'right-password' }, 'other')).status).toBe(404)
  })

  it('says what the workspace offers', async () => {
    const fake = new FakeCauthy()
    fake.ownScreens = true
    const headers = { 'x-tenant-key': 'acme' }
    const settings = await fake.fetch(`${fake.issuer}/v1/auth/settings`, { headers })
    expect((await settings.json()).data).toMatchObject({ allow_password: true, persistent_sessions: false })
    const providers = await fake.fetch(`${fake.issuer}/v1/auth/social/providers`, { headers })
    expect((await providers.json()).data).toEqual([])
  })
})

describe('the fake Cauthy, as the dashboard changes it', () => {
  const asAdmin = (fake: FakeCauthy, path: string, init: RequestInit = {}, token = 'admin-token') =>
    fake.fetch(`${fake.issuer}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'x-tenant-key': 'acme', 'content-type': 'application/json' } })
  const make = () => {
    const fake = new FakeCauthy()
    fake.ownScreens = true
    fake.adminToken = 'admin-token'
    return fake
  }

  it('refuses the admin API without its token, and with none set at all', async () => {
    const fake = make()
    expect((await asAdmin(fake, '/v1/settings/auth', {}, 'wrong')).status).toBe(401)
    fake.adminToken = ''
    expect((await asAdmin(fake, '/v1/settings/auth', {}, '')).status).toBe(401)
  })

  it('changes the settings the sign-in form reads, and keeps one way in', async () => {
    const fake = make()
    const put = (body: unknown) => asAdmin(fake, '/v1/settings/auth', { method: 'PUT', body: JSON.stringify(body) })
    expect((await put({ allow_signup: true, allow_magic_link: true, unknown: 1 })).status).toBe(200)
    const settings = await fake.fetch(`${fake.issuer}/v1/auth/settings`, { headers: { 'x-tenant-key': 'acme' } })
    expect((await settings.json()).data).toMatchObject({ allow_signup: true, allow_magic_link: true })
    expect(fake.settings).not.toHaveProperty('unknown')
    expect((await put({ allow_magic_link: false, allow_password: false })).status).toBe(409)
  })

  it('refuses a password and a sign-up the workspace turned off', async () => {
    const fake = make()
    fake.passwords.set('ana@acme.com', 'right-password')
    const post = (path: string, body: unknown) =>
      fake.fetch(`${fake.issuer}${path}`, { method: 'POST', headers: { 'x-tenant-key': 'acme' }, body: JSON.stringify(body) })
    expect((await post('/v1/auth/register', { email: 'new@acme.com', password: 'Long-enough-1' })).status).toBe(403)
    fake.settings = { ...fake.settings, allow_signup: true, confirm_email: true }
    const held = await post('/v1/auth/register', { email: 'new@acme.com', password: 'Long-enough-1' })
    expect(held.status).toBe(201)
    expect((await held.json()).data.verification_required).toBe(true)
    expect((await post('/v1/auth/login', { email: 'new@acme.com', password: 'Long-enough-1' })).status).toBe(401)
    fake.settings = { ...fake.settings, allow_password: false, allow_magic_link: true }
    const off = await post('/v1/auth/login', { email: 'ana@acme.com', password: 'right-password' })
    expect(off.status).toBe(403)
    expect((await off.json()).errors[0].code).toBe('password_disabled')
  })

  it('lets the client keep long sessions, as its admin says', async () => {
    const fake = make()
    fake.passwords.set('ana@acme.com', 'right-password')
    const patch = await asAdmin(fake, '/v1/oauth/clients/acme-crm', { method: 'PATCH', body: JSON.stringify({ allow_persistent_sessions: true }) })
    expect((await patch.json()).data.allow_persistent_sessions).toBe(true)
    const listed = await asAdmin(fake, '/v1/oauth/clients')
    expect((await listed.json()).data[0]).toMatchObject({ client_id: 'acme-crm', allow_persistent_sessions: true })
    const login = await fake.fetch(`${fake.issuer}/v1/auth/login`, {
      method: 'POST', headers: { 'x-tenant-key': 'acme', 'x-cauthy-remember': '1' }, body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
    })
    expect((await login.json()).data.persistent).toBe(true)
  })

  it('finds and deletes an account', async () => {
    const fake = make()
    const found = await (await asAdmin(fake, '/v1/users?q=ana@acme.com')).json()
    expect(found.data).toEqual([{ id: 'u1', email: 'ana@acme.com', name: 'Ana' }])
    expect((await asAdmin(fake, '/v1/users/u1', { method: 'DELETE' })).status).toBe(204)
    expect(fake.users.has('u1')).toBe(false)
    expect((await asAdmin(fake, '/v1/users/u1', { method: 'DELETE' })).status).toBe(404)
  })

  it('answers over HTTP for a process outside this one', async () => {
    const fake = make()
    const server = await serveFakeCauthy(fake, 0)
    const { port } = server.address() as { port: number }
    try {
      const res = await fetch(`http://127.0.0.1:${port}/v1/settings/auth`, { headers: { authorization: 'Bearer admin-token', 'x-tenant-key': 'acme' } })
      expect(res.status).toBe(200)
      expect((await res.json()).data).toMatchObject({ allow_password: true })
    } finally {
      server.close()
    }
  })
})
