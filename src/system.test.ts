import { createLocalJWKSet, exportPKCS8, generateKeyPair, jwtVerify } from 'jose'
import { describe, expect, it } from 'vitest'
import { connectSystem } from './connect'
import { createCauthy } from './cauthy'
import { CauthyApiError, createSystem } from './system'
import { CauthyConfigError } from './types'

const ISSUER = 'https://id.test'

// A Cauthy that answers the application's own requests the way core-api does.
function fakeCauthy() {
  const state = {
    tokens: 0,
    forms: [] as URLSearchParams[],
    calls: [] as { method: string; path: string; auth: string; body: any }[],
    revoked: new Set<string>(),
    expiresIn: 600,
  }
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input))
    const reply = (status: number, body?: unknown) =>
      new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
    if (url.pathname === '/v1/oauth/token') {
      const form = new URLSearchParams(String(init?.body))
      state.forms.push(form)
      if (form.get('client_secret') === 'wrong') return reply(401, { error: 'invalid_client', error_description: 'client authentication failed' })
      return reply(200, { access_token: `sys-${++state.tokens}`, token_type: 'Bearer', expires_in: state.expiresIn, scope: 'system:ledger' })
    }
    const auth = new Headers(init?.headers).get('authorization') ?? ''
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    state.calls.push({ method: init?.method ?? 'GET', path: url.pathname + url.search, auth, body })
    if (state.revoked.has(auth)) return reply(401, { errors: [{ code: 'unauthorized', message: 'unauthorized' }] })
    const org = { id: 'o1', system: 'ledger', name: 'Acme', kind: 'business', external_id: 'b-1', status: 'active', metadata: { nit: '900' },
      members: 2, created_at: '2026-10-12T12:00:00Z', updated_at: '2026-10-12T12:00:00Z' }
    const member = { user_id: 'u1', email: 'ana@acme.com', name: 'Ana', status: 'active', role: 'owner' }
    if (url.pathname === '/v1/organizations' && init?.method === 'GET') return reply(200, { data: [org], total_count: 1 })
    if (url.pathname === '/v1/organizations') return reply(201, { data: { ...org, name: body.name, external_id: body.external_id } })
    if (url.pathname === '/v1/organizations/other') return reply(404, { errors: [{ code: 'organization_not_found', message: 'no such organization in this workspace' }] })
    if (url.pathname === '/v1/organizations/o1' && init?.method === 'DELETE') return reply(204)
    if (url.pathname === '/v1/organizations/o1/members' && init?.method === 'POST' && body.user_id === 'u1' && body.only_new) {
      return reply(409, { errors: [{ code: 'member_exists', message: 'that person is already a member of the organization' }] })
    }
    if (url.pathname === '/v1/organizations/o1/members' && init?.method === 'POST') return reply(201, { data: { ...member, email: body.email ?? member.email, invited: body.email !== undefined } })
    if (url.pathname === '/v1/organizations/o1/members') return reply(200, { data: [member], total_count: 1 })
    if (url.pathname.endsWith('/theme') && (init?.method ?? 'GET') === 'GET') return reply(200, { data: { primary: '#3d5afe', button_radius: 6, fonts: [{ family: 'DM Sans', url: 'https://app.test/f.woff2', weight: '600' }] } })
    if (url.pathname.endsWith('/theme')) return reply(init?.method === 'DELETE' ? 200 : 200, { data: body ?? {} })
    if (url.pathname === '/v1/systems/ledger/catalog') return reply(200, { data: { system: 'ledger', resources: body?.resources ?? [{ resource: 'invoices', description: '', actions: ['read'], attributes: { amount: 'number' } }] } })
    if (url.pathname === '/v1/systems/ledger/check') {
      if (body.organization_id === 'other') return reply(404, { errors: [{ code: 'organization_not_found', message: 'organization not found' }] })
      return reply(200, { data: body.user_id === 'u1'
        ? { allowed: true, reason: 'allowed by an exception: invoices:approve', rule: { source: 'exception', kind: '*', resource: 'invoices', action: 'approve', effect: 'allow' } }
        : { allowed: false, reason: 'not a member of the organization' } })
    }
    if (url.pathname === '/v1/users' && init?.method === 'POST') return reply(201, { data: { id: 'u9', email: body.email, status: 'pending' } })
    return reply(403, { errors: [{ code: 'outside_system_scope', message: 'a system\'s own token works only on its organizations' }] })
  }
  return { state, fetch }
}

describe('the application acting on its own', () => {
  it('asks for its token with its secret, once, and uses it', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER + '/', clientId: 'client_ledger', clientSecret: 's3cret', fetch })

    const [a, b] = await Promise.all([system.organizations.list({ status: 'active', limit: 10 }), system.members.list('o1')])
    expect(state.tokens).toBe(1) // two callers, one token
    expect(Object.fromEntries(state.forms[0])).toEqual({ grant_type: 'client_credentials', client_id: 'client_ledger', client_secret: 's3cret' })
    expect(state.calls.map((c) => c.auth)).toEqual(['Bearer sys-1', 'Bearer sys-1'])
    expect(state.calls[0].path).toBe('/v1/organizations?status=active&limit=10')
    expect(a).toEqual({ total: 1, items: [{ id: 'o1', system: 'ledger', name: 'Acme', kind: 'business', externalId: 'b-1', status: 'active',
      metadata: { nit: '900' }, members: 2, createdAt: '2026-10-12T12:00:00Z', updatedAt: '2026-10-12T12:00:00Z' }] })
    expect(b).toEqual([{ userId: 'u1', email: 'ana@acme.com', name: 'Ana', status: 'active', role: 'owner' }])

    const made = await system.organizations.create({ name: 'Casa', externalId: 'b-2' })
    expect(made.name).toBe('Casa')
    expect(state.calls.at(-1)?.body).toEqual({ name: 'Casa', external_id: 'b-2' }) // the system is the token's: never sent
    await system.organizations.remove('o1')
    expect(state.tokens).toBe(1)
  })

  it('invites through this application, and tells a new member from one who had an account', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    expect(await system.invite({ email: 'bea@acme.com', name: 'Bea', locale: 'es' })).toEqual({ id: 'u9', email: 'bea@acme.com' })
    expect(state.calls.at(-1)?.body).toEqual({ email: 'bea@acme.com', name: 'Bea', locale: 'es', client_id: 'client_ledger' })
    expect((await system.members.add('o1', { role: 'reader', email: 'new@acme.com' })).invited).toBe(true)
    expect(state.calls.at(-1)?.body).toEqual({ role: 'reader', email: 'new@acme.com', client_id: 'client_ledger', only_new: true })
    expect((await system.members.add('o1', { role: 'owner', userId: 'u1', onlyNew: false })).invited).toBe(false)
  })

  it('adds and nothing else: a member already there keeps their role unless asked', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    const refused = await system.members.add('o1', { role: 'reader', userId: 'u1' }).catch((e: unknown) => e)
    expect(refused).toBeInstanceOf(CauthyApiError)
    expect(refused).toMatchObject({ status: 409, code: 'member_exists' })
    expect(state.calls.at(-1)?.body).toMatchObject({ user_id: 'u1', only_new: true })
    expect((await system.members.add('o1', { role: 'reader', userId: 'u1', onlyNew: false })).role).toBe('owner')
    expect(state.calls.at(-1)?.body).toMatchObject({ user_id: 'u1', only_new: false })
  })

  it('reads the look of its own sign-in page, and has no way to change it', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    expect(await system.theme.get()).toEqual({ primary: '#3d5afe', buttonRadius: 6, fonts: [{ family: 'DM Sans', url: 'https://app.test/f.woff2', weight: '600' }] })
    expect(state.calls.at(-1)?.path).toBe('/v1/oauth/clients/client_ledger/theme')
    expect(Object.keys(system.theme)).toEqual(['get'])
  })

  it('asks again when its token runs out or is taken back', async () => {
    const { state, fetch } = fakeCauthy()
    state.expiresIn = 20 // under the margin: every call asks again
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    await system.members.list('o1')
    await system.members.list('o1')
    expect(state.tokens).toBe(2)

    state.expiresIn = 600
    await system.members.list('o1') // sys-3, kept
    state.revoked.add('Bearer sys-3')
    expect(await system.members.list('o1')).toHaveLength(1)
    expect(state.calls.slice(-2).map((c) => c.auth)).toEqual(['Bearer sys-3', 'Bearer sys-4'])
  })

  it('says what Cauthy refused, with its code', async () => {
    const { fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    const err = await system.organizations.get('other').catch((e) => e)
    expect(err).toBeInstanceOf(CauthyApiError)
    expect(err).toMatchObject({ status: 404, code: 'organization_not_found' })
    await expect(system.request('GET', '/v1/users')).rejects.toMatchObject({ status: 403, code: 'outside_system_scope' })
    const wrong = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 'wrong', fetch })
    await expect(wrong.token()).rejects.toMatchObject({ status: 401, code: 'invalid_client', message: expect.stringContaining('client authentication failed') })
  })

  it('proves itself with a key instead of a secret, and publishes only the public half', async () => {
    const { state, fetch } = fakeCauthy()
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const system = createSystem({ issuer: ISSUER, clientId: 'pact.ledger.service', key: { privateKey: await exportPKCS8(privateKey), keyId: 'k1' }, fetch })

    await system.token()
    const form = state.forms[0]
    expect(form.get('client_secret')).toBeNull()
    expect(form.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')

    const jwks = await system.publicJwks()
    expect(jwks.keys).toHaveLength(1)
    expect(Object.keys(jwks.keys[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']) // nothing private
    // What Cauthy checks: signed by the published key, about the client, for the token endpoint, short-lived, with an id.
    const { payload, protectedHeader } = await jwtVerify(form.get('client_assertion') as string, createLocalJWKSet(jwks),
      { issuer: 'pact.ledger.service', subject: 'pact.ledger.service', audience: `${ISSUER}/v1/oauth/token`, algorithms: ['RS256'] })
    expect(protectedHeader.kid).toBe('k1')
    expect(payload.jti).toBeTruthy()
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(300)

    // A second token carries another assertion: each is used once.
    const again = createSystem({ issuer: ISSUER, clientId: 'pact.ledger.service', key: { privateKey: await exportPKCS8(privateKey), keyId: 'k1' }, fetch })
    await again.token()
    expect(state.forms[1].get('client_assertion')).not.toBe(form.get('client_assertion'))
  })

  it('signs as the key\'s own client when people sign in with another', async () => {
    const { state, fetch } = fakeCauthy()
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const key = { privateKey: await exportPKCS8(privateKey), keyId: 'k1', clientId: 'pact.ledger.service' }
    const system = createSystem({ issuer: ISSUER, clientId: 'pact.ledger', key, fetch })
    await system.token()
    const form = state.forms[0]
    expect(form.get('client_id')).toBe('pact.ledger.service')
    await jwtVerify(form.get('client_assertion') as string, createLocalJWKSet(await system.publicJwks()),
      { issuer: 'pact.ledger.service', subject: 'pact.ledger.service', audience: `${ISSUER}/v1/oauth/token`, algorithms: ['RS256'] })
  })

  it('is part of createCauthy, and asks for nothing until it is used', async () => {
    const { state, fetch } = fakeCauthy()
    const signInOnly = createCauthy({ issuer: ISSUER, clientId: 'client_app', secret: 'x'.repeat(32), fetch })
    await expect(signInOnly.system.token()).rejects.toBeInstanceOf(CauthyConfigError) // no secret, no key
    expect(await signInOnly.system.publicJwks()).toEqual({ keys: [] })

    const auth = createCauthy({ issuer: ISSUER, clientId: 'client_app', clientSecret: 's3cret', secret: 'x'.repeat(32), fetch })
    expect((await auth.system.organizations.list()).total).toBe(1)
    expect(state.tokens).toBe(1)
  })
})

describe('connecting a system', () => {
  it('asks Cauthy for everything at once and adds the session key', async () => {
    let sent: any
    const fetch: typeof globalThis.fetch = async (input, init) => {
      sent = { url: String(input), headers: new Headers(init?.headers), body: JSON.parse(String(init?.body)) }
      return new Response(JSON.stringify({ data: { system: 'ledger', client_secret: 'cs', client: { client_id: 'client_x', redirect_uris: ['https://app.test/api/auth/callback'] },
        webhook: { id: 'w1', url: 'https://app.test/api/hooks/cauthy', events: [], secret: 'whsec_x' },
        env: { CAUTHY_ISSUER: ISSUER, CAUTHY_CLIENT_ID: 'client_x', CAUTHY_CLIENT_SECRET: 'cs', CAUTHY_SYSTEM: 'ledger' } } }),
        { status: 201 })
    }
    const done = await connectSystem({ system: 'ledger', appUrl: 'https://app.test', eventsUrl: 'https://app.test/api/hooks/cauthy',
      issuer: ISSUER, tenant: 'acme', token: 'cpat_x', fetch })
    expect(sent.url).toBe(`${ISSUER}/v1/connect`)
    expect(sent.headers.get('x-tenant-key')).toBe('acme')
    expect(sent.body).toEqual({ system: 'ledger', app_url: 'https://app.test', events_url: 'https://app.test/api/hooks/cauthy' })
    expect(done).toMatchObject({ system: 'ledger', clientId: 'client_x', clientSecret: 'cs', webhook: { id: 'w1', secret: 'whsec_x' } })
    expect(Object.keys(done.env).sort()).toEqual(['CAUTHY_CLIENT_ID', 'CAUTHY_CLIENT_SECRET', 'CAUTHY_ISSUER', 'CAUTHY_SECRET',
      'CAUTHY_SYSTEM'])
    expect(done.env.CAUTHY_SECRET.length).toBeGreaterThanOrEqual(32)
  })

  it('says why Cauthy would not', async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ errors: [{ field: 'app_url', message: 'app_url must be the application\'s address' }] }), { status: 400 })
    await expect(connectSystem({ system: 'ledger', appUrl: 'ftp://x', issuer: ISSUER, tenant: 'acme', token: 't', fetch }))
      .rejects.toThrow(/did not connect the system \(400\): app_url must be/)
    await expect(connectSystem({ system: 'ledger', appUrl: 'https://app.test', issuer: ISSUER, tenant: '', token: 't', fetch })).rejects.toThrow(/CAUTHY_TENANT/)
  })
})

describe('the system\'s own catalog and checks', () => {
  it('reads and replaces the resources the system declares', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', fetch })
    expect(await system.catalog.get('ledger')).toEqual([{ resource: 'invoices', description: '', actions: ['read'], attributes: { amount: 'number' } }])
    const resources = [{ resource: 'invoices', actions: ['read', 'approve'], attributes: { amount: 'number' as const, branch: 'string' as const } }]
    expect(await system.catalog.set('ledger', resources)).toEqual(resources)
    expect(state.calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['GET', '/v1/systems/ledger/catalog', undefined],
      ['PUT', '/v1/systems/ledger/catalog', { resources }],
    ])
  })

  it('asks about any member of its organizations', async () => {
    const { state, fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', system: 'ledger', fetch })
    expect(await system.check({ organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'approve', attributes: { amount: 10 }, resourceId: 'inv_1' })).toEqual({
      allowed: true, reason: 'allowed by an exception: invoices:approve',
      rule: { source: 'exception', kind: '*', resource: 'invoices', action: 'approve', effect: 'allow' },
    })
    expect(await system.check({ organizationId: 'o1', userId: 'u9', resource: 'invoices', action: 'read' })).toEqual({ allowed: false, reason: 'not a member of the organization' })
    expect(state.calls[0]).toMatchObject({ method: 'POST', path: '/v1/systems/ledger/check', auth: 'Bearer sys-1',
      body: { organization_id: 'o1', user_id: 'u1', resource: 'invoices', action: 'approve', resource_id: 'inv_1', attributes: { amount: 10 } } })
    await expect(system.check({ organizationId: 'other', userId: 'u1', resource: 'invoices', action: 'read' })).rejects.toMatchObject({ status: 404, code: 'organization_not_found' })
  })

  it('needs to know which system it asks in', async () => {
    const { fetch } = fakeCauthy()
    const system = createSystem({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', system: '', fetch })
    await expect(system.check({ organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'read' })).rejects.toThrow(CauthyConfigError)
    expect((await system.check({ system: 'ledger', organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'read' })).allowed).toBe(true)
  })

  it('is what auth.system asks with, in the application\'s system', async () => {
    const { state, fetch } = fakeCauthy()
    const auth = createCauthy({ issuer: ISSUER, clientId: 'client_ledger', clientSecret: 's3cret', secret: 'a-secret-of-at-least-thirty-two-characters', system: 'ledger', fetch })
    expect((await auth.system.check({ organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'approve' })).allowed).toBe(true)
    expect(state.calls[0].path).toBe('/v1/systems/ledger/check')
  })
})

describe('a Cauthy that does not answer', () => {
  // A fetch that answers only when it is aborted.
  const hanging: typeof fetch = (_input, init) =>
    new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason)))

  it('fails the call after the deadline, as 503 unavailable', async () => {
    const system = createSystem({ issuer: 'https://id.test', clientId: 'acme-crm', clientSecret: 'cs_x', fetch: hanging, timeoutMs: 50 })
    const started = Date.now()
    await expect(system.token()).rejects.toMatchObject({ status: 503, code: 'unavailable' })
    expect(Date.now() - started).toBeLessThan(1000)
  })

  it('gives every call a deadline by default', async () => {
    let signal: AbortSignal | null | undefined
    const seen: typeof fetch = async (_input, init) => {
      signal = init?.signal
      return new Response(JSON.stringify({ access_token: 't', expires_in: 600 }), { status: 200 })
    }
    await createSystem({ issuer: 'https://id.test', clientId: 'acme-crm', clientSecret: 'cs_x', fetch: seen }).token()
    expect(signal).toBeInstanceOf(AbortSignal)
  })

  it('takes the system deadline from createCauthy timeouts', async () => {
    const auth = createCauthy({ issuer: 'https://id.test', clientId: 'acme-crm', clientSecret: 'cs_x', secret: 'a-secret-of-at-least-thirty-two-characters', fetch: hanging, timeouts: { system: 50 } })
    await expect(auth.system.token()).rejects.toBeInstanceOf(CauthyApiError)
  })

  it('gives the own screens\' calls their own deadline, and answers 503 when it passes', async () => {
    const auth = createCauthy({ issuer: 'https://id.test', clientId: 'acme-crm', secret: 'a-secret-of-at-least-thirty-two-characters', tenant: 'acme', fetch: hanging, timeouts: { request: 50 } })
    const started = Date.now()
    const res = await auth.handler(new Request('https://app.test/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.test', 'x-cauthy-request': '1' },
      body: JSON.stringify({ email: 'ana@acme.com', password: 'right-password' }),
    }))
    expect(res.status).toBe(503)
    expect((await res.json()).error.code).toBe('unavailable')
    expect(Date.now() - started).toBeLessThan(1000)
  })

  it('refuses a deadline that is not a positive number', () => {
    expect(() => createSystem({ timeoutMs: 0 })).toThrow(/timeoutMs/)
    expect(() => createCauthy({ issuer: 'https://id.test', clientId: 'acme-crm', secret: 'a-secret-of-at-least-thirty-two-characters', timeouts: { request: -1 } })).toThrow(/timeouts.request/)
    expect(() => createCauthy({ issuer: 'https://id.test', clientId: 'acme-crm', secret: 'a-secret-of-at-least-thirty-two-characters', timeouts: { system: 0 } })).toThrow(/timeouts.system/)
  })
})
