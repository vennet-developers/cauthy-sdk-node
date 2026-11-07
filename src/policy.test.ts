import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { definePolicy, policySource, pullPolicy, type CatalogResource, type CheckOf, type PermissionOf, type PolicyRole, type RoleOf } from './permissions'
import { createSystem } from './system'

const policy = definePolicy([
  { role: 'reader', name: 'Reader', permissions: [{ resource: 'ledger', action: 'read' }] },
  { role: 'accountant', inherits: ['reader'], permissions: [{ resource: 'ledger', action: 'write' }, { kind: 'business', resource: 'books.close', action: 'write' }] },
  { role: 'owner', inherits: ['accountant'], permissions: [{ resource: 'users', action: '*' }] },
])
const { can, hasRole } = policy

describe('a catalog of roles with its types', () => {
  it('names its roles and permissions', () => {
    expect(policy.roleNames).toEqual(['reader', 'accountant', 'owner'])
    expect(policy.permissions).toEqual(['ledger:read', 'ledger:write', 'books.close:write', 'users:*'])
    expect(policy.permissionsOf('owner').sort()).toEqual(['books.close:write', 'ledger:read', 'ledger:write', 'users:*'])
    expect(policy.permissionsOf('reader')).toEqual(['ledger:read'])
    // As Cauthy takes it, to load a first catalog from the one in code.
    expect(policy.roles[1]).toEqual({ role: 'accountant', inherits: ['reader'], permissions: [{ resource: 'ledger', action: 'write' }, { kind: 'business', resource: 'books.close', action: 'write' }] })
  })

  it('decides from what Cauthy sent with the session, not from the file', () => {
    const acme = { role: 'accountant', permissions: ['ledger:read', 'ledger:write'], denied: ['ledger:write'] }
    expect(can(acme, 'ledger:read')).toBe(true)
    expect(can(acme, 'ledger:write')).toBe(false) // denied to this person, whatever the role says
    expect(can(acme, 'books.close:write')).toBe(false)
    const owner = { role: 'owner', permissions: ['users:*'] }
    expect(can(owner, 'users:invite')).toBe(true) // "*" in the catalog is any action
    expect(can(null, 'ledger:read')).toBe(false)
    expect(hasRole(acme, 'accountant', 'owner')).toBe(true)
    expect(hasRole(acme, 'owner')).toBe(false)
    expect(hasRole(null, 'owner')).toBe(false)
  })

  it('takes only what the catalog names', () => {
    const org = { role: 'reader', permissions: ['ledger:read'] }
    // @ts-expect-error a permission the catalog does not have
    can(org, 'ledger:wirte')
    // @ts-expect-error a resource the catalog does not have
    can(org, 'invoices:read')
    // @ts-expect-error a role the catalog does not have
    hasRole(org, 'admin')
    // @ts-expect-error a role the catalog does not have
    policy.permissionsOf('nobody')
    const role: RoleOf<typeof policy> = 'owner'
    const permission: PermissionOf<typeof policy> = 'books.close:write'
    expect([role, permission]).toEqual(['owner', 'books.close:write'])
  })

  it('ends on a catalog that inherits in a circle', () => {
    const odd = definePolicy([
      { role: 'a', inherits: ['b'], permissions: [{ resource: 'x', action: 'read' }] },
      { role: 'b', inherits: ['a'], permissions: [{ resource: 'y', action: 'read' }] },
    ])
    expect(odd.permissionsOf('a').sort()).toEqual(['x:read', 'y:read'])
  })
})

describe('the catalog Cauthy has, as a module', () => {
  const roles: PolicyRole[] = [
    { role: 'reader', name: 'Reader "of" books', permissions: [{ kind: '*', resource: 'ledger', action: 'read' }] },
    { role: 'accountant', description: 'Keeps the books', inherits: ['reader'], permissions: [{ kind: 'business', resource: 'books.close', action: 'write' }] },
    { role: 'guest' },
  ]

  it('is read with a person\'s token or with the application\'s own identity', async () => {
    const asked: { url: string; auth: string | null; tenant: string | null }[] = []
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/oauth/token')) return Response.json({ access_token: 'the-system-token', token_type: 'Bearer', expires_in: 600 })
      const h = new Headers(init?.headers)
      asked.push({ url, auth: h.get('authorization'), tenant: h.get('x-tenant-key') })
      return Response.json({ data: { roles } })
    }
    expect(await pullPolicy({ issuer: 'https://id.test/', system: 'books', tenant: 'acme', token: 'cpat_x', fetch })).toEqual(roles)
    expect(await createSystem({ issuer: 'https://id.test', clientId: 'client_app', clientSecret: 'cs_x', fetch }).policy.get('books')).toEqual(roles)
    expect(asked).toEqual([
      { url: 'https://id.test/v1/systems/books/policy', auth: 'Bearer cpat_x', tenant: 'acme' },
      { url: 'https://id.test/v1/systems/books/policy', auth: 'Bearer the-system-token', tenant: null },
    ])
    await expect(pullPolicy({ issuer: 'https://id.test', system: 'books', tenant: 'acme', token: '' })).rejects.toThrow(/CAUTHY_TOKEN/)
  })

  it('compiles, and types the application from it', () => {
    const source = policySource('books', roles)
    expect(source).toContain(`{ kind: "business", resource: "books.close", action: "write" },`)
    expect(source).toContain(`name: "Reader \\"of\\" books"`)
    expect(source).not.toContain('kind: "*"')

    // The module as an application would have it, checked by the compiler:
    // what the catalog names compiles, and what it does not is refused.
    const dir = mkdtempSync(join(tmpdir(), 'cauthy-policy-'))
    writeFileSync(join(dir, 'policy.ts'), source.replace(`from 'cauthy-auth'`, `from ${JSON.stringify(join(process.cwd(), 'src/permissions'))}`))
    writeFileSync(join(dir, 'app.ts'), `import { can, hasRole, type Role } from './policy'
const org = { role: 'reader', permissions: ['ledger:read'] }
export const ok = [can(org, 'ledger:read'), can(org, 'books.close:write'), hasRole(org, 'guest')]
export const who: Role = 'accountant'
// @ts-expect-error not in the catalog
can(org, 'ledger:write')
// @ts-expect-error not in the catalog
hasRole(org, 'owner')
`)
    const tsc = join(process.cwd(), 'node_modules/.bin/tsc')
    expect(() => execFileSync(tsc, ['--noEmit', '--strict', '--target', 'es2022', '--module', 'esnext', '--moduleResolution', 'bundler', '--skipLibCheck', '--lib', 'es2022,dom', join(dir, 'app.ts')], { stdio: 'pipe' })).not.toThrow()
  }, 60_000)
})

// A system that declares its resources: the catalog types what a check asks.
const books = definePolicy({
  catalog: [
    { resource: 'invoices', description: 'Customer invoices', actions: ['read', 'approve'], attributes: { amount: 'number', branch: 'string', draft: 'bool', tags: 'list' } },
    { resource: 'ledger', actions: ['read', 'write'] },
  ],
  roles: [
    { role: 'reader', permissions: [{ resource: 'ledger', action: 'read' }, { resource: 'invoices', action: '*' }] },
    { role: 'accountant', inherits: ['reader'], permissions: [{ resource: 'invoices', action: 'approve', condition: 'resource.attrs.amount <= 1000000' }, { resource: 'cauthy:members', action: 'read' }] },
  ],
})

describe('a catalog that declares its resources', () => {
  it('keeps the catalog and the roles as Cauthy takes them', () => {
    expect(books.catalog).toEqual([
      { resource: 'invoices', description: 'Customer invoices', actions: ['read', 'approve'], attributes: { amount: 'number', branch: 'string', draft: 'bool', tags: 'list' } },
      { resource: 'ledger', actions: ['read', 'write'] },
    ])
    expect(books.roles[1].permissions?.[0]).toEqual({ resource: 'invoices', action: 'approve', condition: 'resource.attrs.amount <= 1000000' })
    expect(books.roleNames).toEqual(['reader', 'accountant'])
    expect(books.permissionsOf('accountant').sort()).toEqual(['cauthy:members:read', 'invoices:*', 'invoices:approve', 'ledger:read'])
    // A catalog of roles alone has no resources declared.
    expect(policy.catalog).toEqual([])
  })

  it('never counts a conditional permission in can', () => {
    const org = { role: 'accountant', permissions: ['ledger:read'], denied: [], conditional: [{ resource: 'invoices', action: 'approve', effect: 'allow' as const }] }
    expect(books.can(org, 'ledger:read')).toBe(true)
    expect(books.can(org, 'invoices:approve')).toBe(false)
  })

  it('hands a typed question to whoever asks', async () => {
    const asked: unknown[][] = []
    const decision = { allowed: true, reason: 'allowed by role accountant: invoices:approve' }
    const server = { check: async (request: Request, input: { organization: string | { id: string }; resource: string; action: string; attributes?: Record<string, unknown> }) => (asked.push([request, input]), decision) }
    const browser = { prefix: 'kept', async check(this: { prefix: string }, input: { organization: string | { id: string }; resource: string; action: string }) { asked.push([this.prefix, input]); return decision } }
    const system = { check: async (input: { organizationId: string; userId: string; resource: string; action: string }) => (asked.push([input]), decision) }
    const request = new Request('https://app.test/')

    expect(await books.check(server, request, { organization: 'o1', resource: 'invoices', action: 'approve', attributes: { amount: 500, draft: false, tags: ['a'] } })).toEqual(decision)
    expect(await books.check(browser, { organization: { id: 'o1' }, resource: 'ledger', action: 'write' })).toEqual(decision)
    expect(await books.check(system, { organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'read', ownerId: 'u1' })).toEqual(decision)
    expect(asked).toEqual([
      [request, { organization: 'o1', resource: 'invoices', action: 'approve', attributes: { amount: 500, draft: false, tags: ['a'] } }],
      ['kept', { organization: { id: 'o1' }, resource: 'ledger', action: 'write' }],
      [{ organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'read', ownerId: 'u1' }],
    ])
  })

  it('takes only what the catalog declares', () => {
    const server = { check: async (_r: Request, _i: { organization: string; resource: string; action: string; attributes?: Record<string, unknown> }) => ({ allowed: false, reason: '' }) }
    const request = new Request('https://app.test/')
    // @ts-expect-error a resource the catalog does not declare
    void books.check(server, request, { organization: 'o1', resource: 'payroll', action: 'read' })
    // @ts-expect-error an action the resource does not have
    void books.check(server, request, { organization: 'o1', resource: 'ledger', action: 'approve' })
    // @ts-expect-error an attribute of the wrong type
    void books.check(server, request, { organization: 'o1', resource: 'invoices', action: 'approve', attributes: { amount: '500' } })
    // @ts-expect-error an attribute the resource does not declare
    void books.check(server, request, { organization: 'o1', resource: 'invoices', action: 'approve', attributes: { colour: 'red' } })
    // @ts-expect-error what the asker needs is still asked for
    void books.check(server, request, { resource: 'invoices', action: 'read' })

    // @ts-expect-error a role may name only what the catalog declares
    definePolicy({
      catalog: [{ resource: 'invoices', actions: ['read'] }],
      roles: [{ role: 'reader', permissions: [{ resource: 'payroll', action: 'read' }] }],
    })
    // @ts-expect-error nor an action the resource does not have
    definePolicy({
      catalog: [{ resource: 'invoices', actions: ['read'] }],
      roles: [{ role: 'reader', permissions: [{ resource: 'invoices', action: 'approve' }] }],
    })
    const question: CheckOf<typeof books> = { resource: 'invoices', action: 'approve', attributes: { branch: 'north' } }
    const permission: PermissionOf<typeof books> = 'invoices:approve'
    expect([question.resource, permission]).toEqual(['invoices', 'invoices:approve'])
  })
})

describe('the catalog Cauthy has, with resources declared, as a module', () => {
  const catalog: CatalogResource[] = [
    { resource: 'invoices', description: 'Customer invoices', actions: ['read', 'approve'], attributes: { amount: 'number', branch: 'string', tags: 'list' } },
    { resource: 'ledger', description: '', actions: ['read'], attributes: {} },
  ]
  const roles: PolicyRole[] = [
    { role: 'reader', permissions: [{ kind: '*', resource: 'ledger', action: 'read' }] },
    { role: 'accountant', inherits: ['reader'], permissions: [{ resource: 'invoices', action: 'approve', condition: 'resource.attrs.amount <= 1000000 && subject.attrs.branch == "north"' }] },
  ]

  it('keeps the old shape when there is no catalog', () => {
    expect(policySource('acme-crm', { catalog: [], roles })).toBe(policySource('acme-crm', roles))
    expect(policySource('acme-crm', roles)).toContain('definePolicy([')
  })

  it('writes the catalog, the conditions, and the type of a check', () => {
    const source = policySource('acme-crm', { catalog, roles })
    expect(source).toContain('definePolicy({')
    expect(source).toContain(`{ resource: "invoices", description: "Customer invoices", actions: ["read", "approve"], attributes: { amount: "number", branch: "string", tags: "list" } },`)
    expect(source).toContain(`{ resource: "ledger", actions: ["read"] },`)
    expect(source).toContain(`condition: "resource.attrs.amount <= 1000000 && subject.attrs.branch == \\"north\\""`)
    expect(source).toContain('export type Check = CheckOf<typeof policy>')

    const dir = mkdtempSync(join(tmpdir(), 'cauthy-catalog-'))
    const src = (m: string) => JSON.stringify(join(process.cwd(), `src/${m}`))
    writeFileSync(join(dir, 'policy.ts'), source.replace(`from 'cauthy-auth'`, `from ${src('index')}`))
    writeFileSync(join(dir, 'app.ts'), `import { can, policy, type Check } from './policy'
import type { Cauthy } from ${src('cauthy')}
import type { AuthClient } from ${JSON.stringify(join(process.cwd(), 'test-support/client'))}
declare const auth: Cauthy
declare const browser: AuthClient
declare const request: Request
const org = { id: 'o1', role: 'reader', permissions: ['ledger:read'] }
export const ok = [can(org, 'ledger:read'), can(org, 'invoices:approve')]
export const asked = [
  policy.check(auth, request, { organization: org, resource: 'invoices', action: 'approve', attributes: { amount: 500, tags: ['x'] } }),
  policy.check(browser.organizations, { organization: 'o1', resource: 'ledger', action: 'read' }),
  policy.check(auth.system, { organizationId: 'o1', userId: 'u1', resource: 'invoices', action: 'read', ownerId: 'u1' }),
]
export const q: Check = { resource: 'invoices', action: 'read' }
// @ts-expect-error not declared
policy.check(auth, request, { organization: org, resource: 'payroll', action: 'read' })
// @ts-expect-error amount is a number
policy.check(auth, request, { organization: org, resource: 'invoices', action: 'approve', attributes: { amount: 'a lot' } })
`)
    const tsc = join(process.cwd(), 'node_modules/.bin/tsc')
    try {
      execFileSync(tsc, ['--noEmit', '--strict', '--target', 'es2022', '--module', 'esnext', '--moduleResolution', 'bundler', '--skipLibCheck', '--jsx', 'react-jsx', '--lib', 'es2022,dom,dom.iterable', '--types', 'node', join(dir, 'app.ts')], { stdio: 'pipe' })
    } catch (e) {
      throw new Error(String((e as { stdout?: Buffer }).stdout ?? e))
    }
  }, 60_000)
})
