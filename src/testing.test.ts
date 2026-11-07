import { describe, expect, it } from 'vitest'
import { FakeCauthy } from './testing'

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
