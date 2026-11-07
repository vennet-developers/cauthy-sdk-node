import { describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { createAuthClient } from '../test-support/client'
import { can, pullCatalog, pushCatalog, pushPolicy, readPolicyFile } from './permissions'
import { Browser, FakeCauthy } from './testing'

describe('what a person may do in an organization', () => {
  it('is allowed by an entry and denied by none', () => {
    const org = { permissions: ['ledger:read', 'ledger:write', 'invoicing:*', 'books.close:write'], denied: ['ledger:write'] }
    expect(can(org, 'ledger', 'read')).toBe(true)
    expect(can(org, 'ledger', 'write')).toBe(false) // a denial wins
    expect(can(org, 'invoicing', 'send')).toBe(true) // any action
    expect(can(org, 'books.close', 'write')).toBe(true)
    expect(can(org, 'users', 'read')).toBe(false)
  })

  it('reads wildcards on either side, and a resource with a colon in it', () => {
    expect(can({ permissions: ['*:*'] }, 'anything', 'at-all')).toBe(true)
    expect(can({ permissions: ['*:*'], denied: ['users:*'] }, 'users', 'write')).toBe(false)
    expect(can({ permissions: ['*:*'], denied: ['*:write'] }, 'ledger', 'write')).toBe(false)
    expect(can({ permissions: ['*:*'], denied: ['*:write'] }, 'ledger', 'read')).toBe(true)
    expect(can({ permissions: ['invoicing:draft:write'] }, 'invoicing:draft', 'write')).toBe(true)
    expect(can({ permissions: ['invoicing:draft:write'] }, 'invoicing', 'draft:write')).toBe(false)
  })

  it("reads Cauthy's reserved powers like any other", () => {
    const owner = { permissions: ['cauthy:members:*', 'cauthy:organization:*', 'ledger:read'] }
    expect(can(owner, 'cauthy:organization', 'delete')).toBe(true)
    expect(can(owner, 'cauthy:members', 'remove')).toBe(true)
    const admin = { permissions: ['cauthy:members:read', 'cauthy:members:manage', 'cauthy:organization:update'] }
    expect(can(admin, 'cauthy:members', 'remove')).toBe(false) // manage no longer implies it
    expect(can(admin, 'cauthy:organization', 'update')).toBe(true)
    expect(can(admin, 'cauthy:organization', 'delete')).toBe(false)
    expect(can({ ...owner, denied: ['cauthy:organization:delete'] }, 'cauthy:organization', 'delete')).toBe(false)
  })

  it('answers no where the system keeps no catalog in Cauthy', () => {
    expect(can({}, 'ledger', 'read')).toBe(false)
    expect(can(null, 'ledger', 'read')).toBe(false)
    expect(can(undefined, 'ledger', 'read')).toBe(false)
  })

  it('arrives with the session, so checking asks nobody', async () => {
    const cauthy = new FakeCauthy()
    cauthy.orgs.set('u1', [
      { id: 'o1', system: 'books', name: 'Acme', kind: 'business', role: 'accountant', metadata: {}, permissions: ['ledger:read', 'ledger:write'], denied: ['ledger:write'] },
      { id: 'o2', system: 'books', name: 'Old books', kind: 'business', role: 'owner', metadata: {} },
    ])
    const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'c', secret: 'a-secret-of-at-least-thirty-two-characters', fetch: cauthy.fetch })
    const browser = new Browser()
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(start)
    const back = new URL(cauthy.authorize(start.headers.get('location')!))
    browser.take(await auth.handler(browser.request(back.pathname + back.search)))

    const session = (await auth.getSession(browser.request('/')))!
    const [acme, old] = await auth.organizations(session)
    const calls = cauthy.calls.length
    expect(can(acme, 'ledger', 'read')).toBe(true)
    expect(can(acme, 'ledger', 'write')).toBe(false)
    expect(acme.denied).toEqual(['ledger:write'])
    // No catalog: no permissions to read, only the role.
    expect(old.permissions).toBeUndefined()
    expect(can(old, 'ledger', 'read')).toBe(false)
    expect(cauthy.calls.length).toBe(calls)
  })
})

describe('loading a catalog of roles', () => {
  it('replaces the catalog of the system', async () => {
    const calls: { url: string; init: RequestInit }[] = []
    const fake: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init! })
      return new Response('{}', { status: 200 })
    }
    const roles = [{ role: 'reader', permissions: [{ resource: 'ledger', action: 'read' }] }]
    await pushPolicy({ issuer: 'https://id.test', system: 'books', tenant: 'acme', token: 'cpat_x', roles, fetch: fake })
    expect(calls[0].url).toBe('https://id.test/v1/systems/books/policy')
    expect(calls[0].init.method).toBe('PUT')
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ roles })
  })

  it('says what Cauthy refused, and what is missing', async () => {
    const refuse: typeof fetch = async () =>
      new Response(JSON.stringify({ errors: [{ code: 'role_in_use', message: 'members hold a role this catalog leaves out (intern)' }] }), { status: 409 })
    await expect(pushPolicy({ issuer: 'https://id.test', system: 'books', tenant: 't', token: 'k', roles: [], fetch: refuse })).rejects.toThrow(/intern/)
    await expect(pushPolicy({ issuer: 'https://id.test', tenant: 't', token: 'k', roles: [], system: '' })).rejects.toThrow(/CAUTHY_SYSTEM/)
  })
})

describe('the catalog beside the roles', () => {
  const catalog = [{ resource: 'invoices', description: 'Customer invoices', actions: ['read', 'approve'], attributes: { amount: 'number' as const } }]
  const recorder = (answer: (url: string, init: RequestInit) => Response = () => Response.json({ data: { system: 'acme-crm', resources: catalog } })) => {
    const calls: { url: string; method: string; body: unknown; tenant: string | null }[] = []
    const fetch: typeof globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : undefined, tenant: new Headers(init?.headers).get('x-tenant-key') })
      return answer(String(url), init ?? {})
    }
    return { calls, fetch }
  }
  const where = { issuer: 'https://id.test', system: 'acme-crm', tenant: 'acme', token: 'cpat_x' }

  it('goes first, so the roles are checked against it', async () => {
    const { calls, fetch } = recorder()
    const roles = [{ role: 'accountant', permissions: [{ resource: 'invoices', action: 'approve', condition: 'resource.attrs.amount <= 1000' }] }]
    await pushPolicy({ ...where, roles, catalog, fetch })
    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['PUT', 'https://id.test/v1/systems/acme-crm/catalog', { resources: catalog }],
      ['PUT', 'https://id.test/v1/systems/acme-crm/policy', { roles }],
    ])
  })

  it('is left alone when a push gives none', async () => {
    const { calls, fetch } = recorder()
    await pushPolicy({ ...where, roles: [], fetch })
    expect(calls.map((c) => c.url)).toEqual(['https://id.test/v1/systems/acme-crm/policy'])
  })

  it('is read and replaced on its own', async () => {
    const { calls, fetch } = recorder()
    expect(await pullCatalog({ ...where, fetch })).toEqual(catalog)
    expect(await pushCatalog({ ...where, resources: catalog, fetch })).toEqual(catalog)
    expect(calls.map((c) => [c.method, c.url, c.tenant])).toEqual([
      ['GET', 'https://id.test/v1/systems/acme-crm/catalog', 'acme'],
      ['PUT', 'https://id.test/v1/systems/acme-crm/catalog', 'acme'],
    ])
  })

  it('is read from a policy file beside the roles, or the roles alone as before', () => {
    const roles = [{ role: 'reader', permissions: [{ resource: 'invoices', action: 'read' }] }]
    expect(readPolicyFile(roles)).toEqual({ catalog: [], roles })
    expect(readPolicyFile({ roles })).toEqual({ catalog: [], roles })
    expect(readPolicyFile({ catalog, roles })).toEqual({ catalog, roles })
    expect(() => readPolicyFile({ catalog })).toThrow(/no "roles" list/)
    expect(() => readPolicyFile({ catalog: {}, roles })).toThrow(/"catalog" is not a list/)
  })

  it('stops the push when Cauthy refuses it, before the roles go', async () => {
    const { calls, fetch } = recorder(() => Response.json({ errors: [{ code: 'catalog_in_use', message: 'the policy still names invoices:approve' }] }, { status: 409 }))
    await expect(pushPolicy({ ...where, roles: [], catalog: [], fetch })).rejects.toThrow(/refused the catalog \(409\): the policy still names invoices:approve/)
    expect(calls.length).toBe(1)
  })
})

describe('asking Cauthy about a permission', () => {
  const ACME = '7f0c1a52-5a7e-4c38-9a8e-3f7a1c2b9d01'
  const OTHER = '7f0c1a52-5a7e-4c38-9a8e-3f7a1c2b9d02'
  async function signedIn() {
    const cauthy = new FakeCauthy()
    cauthy.orgs.set('u1', [{ id: ACME, system: 'acme-crm', name: 'Acme', kind: 'business', role: 'accountant', metadata: {},
      permissions: ['invoices:read'], denied: [], conditional: [{ resource: 'invoices', action: 'approve', effect: 'allow' }] }])
    const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'c', secret: 'a-secret-of-at-least-thirty-two-characters', fetch: cauthy.fetch })
    const browser = new Browser()
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(start)
    const back = new URL(cauthy.authorize(start.headers.get('location')!))
    browser.take(await auth.handler(browser.request(back.pathname + back.search)))
    return { cauthy, auth, browser }
  }

  it('lists a conditional permission apart, and can never counts it', async () => {
    const { auth, browser } = await signedIn()
    const [acme] = await auth.organizations((await auth.getSession(browser.request('/')))!)
    expect(acme.conditional).toEqual([{ resource: 'invoices', action: 'approve', effect: 'allow' }])
    expect(can(acme, 'invoices', 'read')).toBe(true)
    expect(can(acme, 'invoices', 'approve')).toBe(false)
  })

  it('asks with the person\'s token, by the organization or its id', async () => {
    const { cauthy, auth, browser } = await signedIn()
    const session = (await auth.getSession(browser.request('/')))!
    const [acme] = await auth.organizations(session)
    const yes = await auth.check(browser.request('/'), { organization: acme, resource: 'invoices', action: 'approve', attributes: { amount: 500 }, resourceId: 'inv_1', ownerId: 'u2' })
    expect(yes).toEqual({ allowed: true, reason: 'allowed by role accountant: invoices:approve',
      rule: { source: 'role', role: 'accountant', kind: '*', resource: 'invoices', action: 'approve', effect: 'allow', condition: 'resource.attrs.amount <= 1000000' } })
    expect(await auth.check(session, { organization: ACME, resource: 'invoices', action: 'approve', attributes: { amount: 5_000_000 } })).toEqual({ allowed: false, reason: 'no rule allows it' })
    expect(cauthy.checks[0]).toEqual({ organization: ACME, sub: 'u1', body: { resource: 'invoices', action: 'approve', resource_id: 'inv_1', owner_id: 'u2', attributes: { amount: 500 } } })
    expect(cauthy.calls).toContain(`POST /v1/oauth/organizations/${ACME}/check`)
  })

  it('answers no for nobody signed in, and for an organization the person is not in', async () => {
    const { cauthy, auth, browser } = await signedIn()
    expect(await auth.check(new Request('https://app.test/'), { organization: ACME, resource: 'invoices', action: 'read' })).toEqual({ allowed: false, reason: 'not signed in' })
    expect(await auth.check(browser.request('/'), { organization: OTHER, resource: 'invoices', action: 'read' })).toEqual({ allowed: false, reason: 'organization not found' })
    cauthy.down = true
    await expect(auth.check(browser.request('/'), { organization: ACME, resource: 'invoices', action: 'read' })).rejects.toThrow(/could not be reached/)
  })

  it('is asked from the browser through the application\'s route', async () => {
    const { auth, browser } = await signedIn()
    const sent: { url: string; body: unknown }[] = []
    const client = createAuthClient({
      fetch: (async (url: string, init: RequestInit) => {
        sent.push({ url, body: JSON.parse(String(init.body)) })
        return auth.handler(browser.request(url, { ...init, headers: { ...(init.headers as Record<string, string>), origin: 'https://app.test' } }))
      }) as unknown as typeof fetch,
    })
    const yes = await client.organizations.check({ organization: { id: ACME }, resource: 'invoices', action: 'approve', attributes: { amount: 10 } })
    expect(yes).toMatchObject({ allowed: true, rule: { role: 'accountant' } })
    expect(sent[0]).toEqual({ url: '/api/auth/me/organizations/check', body: { organizationId: ACME, resource: 'invoices', action: 'approve', attributes: { amount: 10 } } })
    expect(await client.organizations.check({ organization: OTHER, resource: 'invoices', action: 'read' })).toEqual({ allowed: false, reason: 'organization not found' })
    // A question the route cannot read is a no, with why.
    expect(await client.organizations.check({ organization: 'not-an-id', resource: 'invoices', action: 'read' })).toMatchObject({ allowed: false, error: { code: 'invalid_organization' } })
  })

  it('refuses the route to another site, and to nobody signed in', async () => {
    const { auth, browser } = await signedIn()
    const post = (b: Browser, origin: string) => auth.handler(b.request('/api/auth/me/organizations/check', {
      method: 'POST', headers: { 'content-type': 'application/json', origin }, body: JSON.stringify({ organizationId: ACME, resource: 'invoices', action: 'read' }),
    }))
    expect((await post(browser, 'https://evil.test')).status).toBe(403)
    expect((await post(new Browser(), 'https://app.test')).status).toBe(401)
    expect((await auth.handler(browser.request('/api/auth/me/organizations/check'))).status).toBe(405)
  })
})
