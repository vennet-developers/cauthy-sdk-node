// What a person may do in an organization.
//
// When a system keeps its catalog of roles in Cauthy, each of a person's
// organizations arrives with what their role — and anything given or denied to
// them apart from it — lets them do. Checking is a lookup in that list: no
// call to Cauthy, on the server or in the browser.

import type { CheckQuestion, CheckResult, CheckRule, ConditionalPermission, OrganizationRef } from './types'
import { withoutTrailingSlashes } from './url'

/** The part of an organization that says what its member may do. */
export interface Permitted {
  /** "resource:action" entries the person is allowed; "*" is any. Absent when the system keeps no catalog in Cauthy. */
  permissions?: string[]
  /** Entries the person is denied whatever else allows them. */
  denied?: string[]
  /** Permissions with a condition: in neither list, so `can` never counts them. Ask with `auth.check`. */
  conditional?: ConditionalPermission[]
}

function matches(entry: string, resource: string, action: string): boolean {
  // The resource may itself hold a colon: the action is what follows the last one.
  const i = entry.lastIndexOf(':')
  if (i < 0) return false
  const r = entry.slice(0, i)
  const a = entry.slice(i + 1)
  return (r === '*' || r === resource) && (a === '*' || a === action)
}

/**
 * Whether the person may do an action on a resource in an organization:
 * allowed by some entry, and denied by none. A denial wins.
 *
 * An organization of a system that keeps no catalog in Cauthy carries no
 * permissions, and the answer is `false`: decide by its `role` instead.
 *
 * A permission with a condition (`organization.conditional`) is not in the
 * lists, so `can` answers `false` for what only it allows: the condition reads
 * the record at hand, which only Cauthy can weigh. Ask with `auth.check`
 * (`organizations.check` in the browser).
 *
 *   if (!can(organization, 'invoicing', 'write')) return forbidden()
 */
export function can(organization: Permitted | null | undefined, resource: string, action: string): boolean {
  if (!organization?.permissions) return false
  if ((organization.denied ?? []).some((d) => matches(d, resource, action))) return false
  return organization.permissions.some((p) => matches(p, resource, action))
}

// ── A system's catalog of roles ────────────────────────────────────────────

/** Something a role may do: an action on a resource, in organizations of a kind ("*", the default, is every kind). */
export interface PolicyPermission {
  kind?: string
  resource: string
  action: string
  /**
   * When it holds, in CEL: `resource.attrs.amount <= 1000000`. A permission
   * with one is decided by Cauthy per question (`auth.check`), never by `can`.
   */
  condition?: string
}

/** The type of an attribute a condition may read: `list` is any JSON array. */
export type AttributeType = 'string' | 'number' | 'bool' | 'list'

/** A resource of a system's catalog: the actions done on it and the attributes its conditions read. */
export interface CatalogResource {
  resource: string
  description?: string
  actions: string[]
  /** Name → type, as `resource.attrs.<name>` in a condition. */
  attributes?: Record<string, AttributeType>
}

export interface PolicyRole {
  role: string
  name?: string
  description?: string
  /** Roles whose permissions this one has as well. */
  inherits?: string[]
  permissions?: PolicyPermission[]
}

// ── The catalog, with its types ────────────────────────────────────────────
//
// A catalog written down once gives the roles and the permissions their
// names: `can(org, 'ledger:write')` then takes only a permission the catalog
// has, the editor offers them, and a typo does not compile.
//
//   export const policy = definePolicy([
//     { role: 'reader', permissions: [{ resource: 'ledger', action: 'read' }] },
//     { role: 'accountant', inherits: ['reader'], permissions: [{ resource: 'ledger', action: 'write' }] },
//   ])
//   export const { can, hasRole } = policy
//
//   can(organization, 'ledger:write')        // 'ledger:wirte' does not compile
//   hasRole(organization, 'accountant')
//
// A system that declares its resources gives them too, with their actions and
// the attributes a condition reads, and a check is typed by them:
//
//   export const policy = definePolicy({
//     catalog: [{ resource: 'invoices', actions: ['read', 'approve'], attributes: { amount: 'number' } }],
//     roles: [{ role: 'accountant', permissions: [{ resource: 'invoices', action: 'approve', condition: 'resource.attrs.amount <= 1000' }] }],
//   })
//
//   await policy.check(auth, request, { organization, resource: 'invoices', action: 'approve', attributes: { amount: 500 } })
//
// Write it by hand, or let `cauthy-auth policy --pull` write it from the
// catalog Cauthy has.

type PermissionShape = { readonly kind?: string; readonly resource: string; readonly action: string; readonly condition?: string }

/** A role as `definePolicy` reads it: any `PolicyRole`, kept as written. */
type RoleShape = {
  readonly role: string
  readonly name?: string
  readonly description?: string
  readonly inherits?: readonly string[]
  readonly permissions?: readonly PermissionShape[]
}

/** A resource as `definePolicy` reads it: any `CatalogResource`, kept as written. */
type ResourceShape = {
  readonly resource: string
  readonly description?: string
  readonly actions: readonly string[]
  readonly attributes?: { readonly [name: string]: AttributeType }
}

// "*" in a catalog is "any": the name it stands for is any text.
type Named<S extends string> = S extends '*' ? string : S

type PermissionsIn<R> = R extends { readonly permissions: readonly (infer P)[] }
  ? P extends { readonly resource: infer Res extends string; readonly action: infer Act extends string } ? `${Named<Res>}:${Named<Act>}` : never
  : never

type ValueOf<T> = T extends 'string' ? string : T extends 'number' ? number : T extends 'bool' ? boolean : T extends 'list' ? unknown[] : never

/** What a check may say about one declared resource. */
type QuestionAbout<E> = E extends { readonly resource: infer R extends string; readonly actions: readonly (infer A extends string)[] }
  ? {
      resource: R
      action: A
      attributes?: E extends { readonly attributes: infer T } ? { [K in keyof T]?: ValueOf<T[K]> } : Record<string, never>
      resourceId?: string
      ownerId?: string
    }
  : never

/**
 * What a role of a catalog that declares its resources may name: a declared
 * resource with one of its actions, or "*", or one of Cauthy's own powers.
 */
type PermissionFor<C extends readonly ResourceShape[]> = { readonly kind?: string; readonly condition?: string } & (
  | (C[number] extends infer E ? E extends { readonly resource: infer R extends string; readonly actions: readonly (infer A extends string)[] } ? { readonly resource: R; readonly action: A | '*' } : never : never)
  | { readonly resource: '*'; readonly action: string }
  | { readonly resource: `cauthy:${string}`; readonly action: string }
)
type RoleFor<C extends readonly ResourceShape[]> = Omit<RoleShape, 'permissions'> & { readonly permissions?: readonly PermissionFor<C>[] }

/** The roles a catalog names: `RoleOf<typeof policy>`. */
export type RoleOf<P> = P extends Policy<infer R, any, any> ? R : never
/** The "resource:action" permissions a catalog names: `PermissionOf<typeof policy>`. */
export type PermissionOf<P> = P extends Policy<any, infer X, any> ? X : never
/** What a check about this catalog may ask: `CheckOf<typeof policy>`. Any resource when it declares none. */
export type CheckOf<P> = P extends Policy<any, any, infer Q> ? Q : never

/** The fields of a question: whatever else the asker takes (the organization, the person) passes through. */
type QuestionKeys = keyof CheckQuestion

export interface Policy<Role extends string = string, Permission extends string = string, Question extends CheckQuestion = CheckQuestion> {
  /** The catalog as Cauthy takes it: `pushPolicy({ roles: policy.roles })`. */
  roles: PolicyRole[]
  /** The resources the system declares, as Cauthy takes them; empty when it declares none. */
  catalog: CatalogResource[]
  /** Every role's name. */
  roleNames: Role[]
  /** Every permission some role has, as "resource:action". */
  permissions: Permission[]
  /**
   * Whether the person may do this in the organization: `can(org, 'ledger:write')`.
   * It reads what Cauthy sent with the session, so a catalog edited in Cauthy
   * since this file was written is still what decides. A permission with a
   * condition is not there: ask with `check`.
   */
  can(organization: Permitted | null | undefined, permission: Permission): boolean
  /** Whether the person's role in the organization is one of these. */
  hasRole(organization: { role: string } | null | undefined, ...roles: Role[]): boolean
  /**
   * What a role may do by this catalog, with what it inherits: for showing a
   * role, never for deciding about a person (their exceptions are not here).
   */
  permissionsOf(role: Role): Permission[]
  /**
   * Asks Cauthy, with the resource, action and attributes typed by the
   * catalog. Give it whoever asks: the server's `auth` with the request,
   * the browser's `organizations`, or the application's `system`.
   *
   *   await policy.check(auth, request, { organization, resource: 'invoices', action: 'approve', attributes: { amount: 500 } })
   *   await policy.check(auth.system, { organizationId, userId, resource: 'invoices', action: 'read' })
   */
  check<I extends CheckQuestion>(asker: { check(input: I): Promise<CheckResult> }, input: Omit<I, QuestionKeys> & Question): Promise<CheckResult>
  check<R, I extends CheckQuestion>(asker: { check(request: R, input: I): Promise<CheckResult> }, request: R, input: Omit<I, QuestionKeys> & Question): Promise<CheckResult>
}

/** A catalog with its resources declared, for `definePolicy`. */
export interface PolicyDefinition<C extends readonly ResourceShape[], T extends readonly RoleShape[]> {
  catalog: C
  roles: T
}

/** Gives a catalog of roles its types. See the top of this section. */
export function definePolicy<const T extends readonly RoleShape[]>(roles: T): Policy<T[number]['role'], PermissionsIn<T[number]>>
/** Gives a catalog of resources and roles its types: a role names only what the catalog declares. */
export function definePolicy<const C extends readonly ResourceShape[], const T extends readonly RoleFor<C>[]>(
  definition: PolicyDefinition<C, T>,
): Policy<T[number]['role'], PermissionsIn<T[number]>, QuestionAbout<C[number]>>
export function definePolicy(given: readonly RoleShape[] | PolicyDefinition<readonly ResourceShape[], readonly RoleShape[]>): Policy {
  const roles: readonly RoleShape[] = Array.isArray(given) ? given : (given as PolicyDefinition<readonly ResourceShape[], readonly RoleShape[]>).roles
  const resources: readonly ResourceShape[] = Array.isArray(given) ? [] : (given as PolicyDefinition<readonly ResourceShape[], readonly RoleShape[]>).catalog ?? []
  const entry = (p: { resource: string; action: string }) => `${p.resource}:${p.action}`
  const byName = new Map(roles.map((r) => [r.role, r]))
  const split = (permission: string): [string, string] => {
    const i = permission.lastIndexOf(':')
    return i < 0 ? [permission, ''] : [permission.slice(0, i), permission.slice(i + 1)]
  }
  return {
    roles: roles.map((r) => ({
      role: r.role,
      ...(r.name !== undefined ? { name: r.name } : {}),
      ...(r.description !== undefined ? { description: r.description } : {}),
      ...(r.inherits ? { inherits: [...r.inherits] } : {}),
      ...(r.permissions ? { permissions: r.permissions.map((p) => ({ ...p })) } : {}),
    })),
    catalog: resources.map((c) => ({
      resource: c.resource,
      ...(c.description !== undefined ? { description: c.description } : {}),
      actions: [...c.actions],
      ...(c.attributes ? { attributes: { ...c.attributes } } : {}),
    })),
    roleNames: roles.map((r) => r.role),
    permissions: [...new Set(roles.flatMap((r) => (r.permissions ?? []).map(entry)))],
    can(organization, permission) {
      const [resource, action] = split(permission)
      return can(organization, resource, action)
    },
    hasRole(organization, ...wanted) {
      return organization != null && wanted.includes(organization.role)
    },
    permissionsOf(role) {
      const seen = new Set<string>()
      const out = new Set<string>()
      const walk = (name: string) => {
        if (seen.has(name)) return // a catalog that inherits in a circle still ends
        seen.add(name)
        const r = byName.get(name)
        for (const p of r?.permissions ?? []) out.add(entry(p))
        for (const parent of r?.inherits ?? []) walk(parent)
      }
      walk(role)
      return [...out]
    },
    // The types did the work; this only hands the question on, as a method of
    // the asker so it keeps its `this`.
    check(asker: { check(...args: unknown[]): Promise<CheckResult> }, ...args: unknown[]) {
      return asker.check(...args)
    },
  }
}

const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/

/** A system's policy as Cauthy has it: the resources it declares (maybe none) and its roles. */
export interface SystemPolicy {
  catalog: CatalogResource[]
  roles: PolicyRole[]
}

/**
 * A TypeScript module that defines the catalog given, for `cauthy-auth policy
 * --pull` to write: the application's types then come from the catalog
 * Cauthy has. With resources declared it is `definePolicy({ catalog, roles })`;
 * without, the list of roles alone, as it always was.
 */
export function policySource(system: string, read: PolicyRole[] | { catalog?: CatalogResource[]; roles: PolicyRole[] }): string {
  const roles = Array.isArray(read) ? read : read.roles
  const catalog = Array.isArray(read) ? [] : (read.catalog ?? [])
  const text = (v: string) => JSON.stringify(v)
  const key = (k: string) => (IDENT.test(k) ? k : text(k))
  const one = (r: PolicyRole, pad: string) => {
    const parts = [`role: ${text(r.role)}`]
    if (r.name) parts.push(`name: ${text(r.name)}`)
    if (r.description) parts.push(`description: ${text(r.description)}`)
    if (r.inherits?.length) parts.push(`inherits: [${r.inherits.map(text).join(', ')}]`)
    if (r.permissions?.length) {
      const list = r.permissions.map((p) => `${pad}      { ${[
        ...(p.kind && p.kind !== '*' ? [`${key('kind')}: ${text(p.kind)}`] : []),
        `resource: ${text(p.resource)}`,
        `action: ${text(p.action)}`,
        ...(p.condition ? [`condition: ${text(p.condition)}`] : []),
      ].join(', ')} },`)
      parts.push(`permissions: [\n${list.join('\n')}\n${pad}    ]`)
    }
    return `${pad}  {\n${pad}    ${parts.join(`,\n${pad}    `)},\n${pad}  },`
  }
  const resource = (c: CatalogResource) => {
    const parts = [`resource: ${text(c.resource)}`]
    if (c.description) parts.push(`description: ${text(c.description)}`)
    parts.push(`actions: [${c.actions.map(text).join(', ')}]`)
    const attrs = Object.entries(c.attributes ?? {})
    if (attrs.length) parts.push(`attributes: { ${attrs.map(([k, v]) => `${key(k)}: ${text(v)}`).join(', ')} }`)
    return `    { ${parts.join(', ')} },`
  }
  const head = `// The catalog of roles of ${text(system)}, as Cauthy has it.
// Written by \`cauthy-auth policy --pull\`: run it again after the catalog
// changes, and do not edit this file by hand.
`
  if (catalog.length === 0) {
    return `${head}
import { definePolicy, type PermissionOf, type RoleOf } from 'cauthy-auth'

export const policy = definePolicy([
${roles.map((r) => one(r, '')).join('\n')}
])

export const { can, hasRole } = policy
export type Role = RoleOf<typeof policy>
export type Permission = PermissionOf<typeof policy>
`
  }
  return `${head}
import { definePolicy, type CheckOf, type PermissionOf, type RoleOf } from 'cauthy-auth'

export const policy = definePolicy({
  catalog: [
${catalog.map(resource).join('\n')}
  ],
  roles: [
${roles.map((r) => one(r, '  ')).join('\n')}
  ],
})

export const { can, hasRole } = policy
export type Role = RoleOf<typeof policy>
export type Permission = PermissionOf<typeof policy>
/** What a check may ask: \`policy.check(auth, request, { organization, ...question })\`. */
export type Check = CheckOf<typeof policy>
`
}

/** Who reads or writes a system's policy: Cauthy's address, the workspace, a person's token. */
interface Reach {
  issuer: string
  system: string
  tenant: string
  token: string
  fetch: typeof fetch
}

function reach(o: Omit<PushPolicyOptions, 'roles'>, doing: string): Reach {
  const env = (n: string) => (typeof process !== 'undefined' ? process.env?.[n] : undefined)
  const r = {
    issuer: withoutTrailingSlashes(o.issuer ?? env('CAUTHY_ISSUER') ?? ''),
    system: o.system ?? env('CAUTHY_SYSTEM') ?? '',
    tenant: o.tenant ?? env('CAUTHY_TENANT') ?? '',
    token: o.token ?? env('CAUTHY_TOKEN') ?? '',
  }
  for (const [name, v] of Object.entries({ CAUTHY_ISSUER: r.issuer, CAUTHY_SYSTEM: r.system, CAUTHY_TENANT: r.tenant, CAUTHY_TOKEN: r.token })) {
    if (v === '') throw new Error(`cauthy-auth: ${name} is required to ${doing}`)
  }
  return { ...r, fetch: o.fetch ?? fetch }
}

async function systemCall(r: Reach, method: 'GET' | 'PUT', what: 'policy' | 'catalog', body?: unknown): Promise<any> {
  const res = await r.fetch(`${r.issuer}/v1/systems/${encodeURIComponent(r.system)}/${what}`, {
    ...(method === 'PUT' ? { method } : {}),
    headers: {
      authorization: `Bearer ${r.token}`, 'x-tenant-key': r.tenant,
      ...(body === undefined ? { accept: 'application/json' } : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  const answer = (await res.json().catch(() => null)) as { data?: any; errors?: { message?: string }[] } | null
  if (!res.ok) {
    const verb = method === 'GET' ? `refused to give the ${what}` : `refused the ${what}`
    throw new Error(`cauthy-auth: Cauthy ${verb} (${res.status}): ${answer?.errors?.[0]?.message ?? res.statusText}`)
  }
  return answer?.data
}

/** Reads a system's catalog of roles from Cauthy, with a personal access token. */
export async function pullPolicy(o: Omit<PushPolicyOptions, 'roles'> = {}): Promise<PolicyRole[]> {
  const data = await systemCall(reach(o, 'read a policy'), 'GET', 'policy')
  return (data?.roles as PolicyRole[] | undefined) ?? []
}

/** Reads the resources a system declares (empty when it declares none), with a personal access token. */
export async function pullCatalog(o: Omit<PushPolicyOptions, 'roles'> = {}): Promise<CatalogResource[]> {
  const data = await systemCall(reach(o, 'read a catalog'), 'GET', 'catalog')
  return (data?.resources as CatalogResource[] | undefined) ?? []
}

export interface PushPolicyOptions {
  /** The system whose catalog this is. Default: `CAUTHY_SYSTEM`. */
  system?: string
  roles: PolicyRole[]
  /**
   * The resources the system declares. Given, they are sent before the roles,
   * which Cauthy then checks against them; left out, the catalog Cauthy has
   * stays as it is.
   */
  catalog?: CatalogResource[]
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The workspace's slug. Default: `CAUTHY_TENANT`. */
  tenant?: string
  /**
   * A personal access token: `organizations:manage` reads, and changing a
   * policy or a catalog takes `systems:policy`. Default: `CAUTHY_TOKEN`.
   */
  token?: string
  fetch?: typeof fetch
}

/**
 * Gives Cauthy a system's catalog of roles, replacing the one it has. It is
 * the way to load a first catalog from what a system already had; from then on
 * the catalog is Cauthy's, edited in its dashboard, and pushing again would
 * overwrite what was edited there. With `catalog` the declared resources go
 * first: the roles are checked against them.
 */
export async function pushPolicy(o: PushPolicyOptions): Promise<void> {
  const r = reach(o, 'push a policy')
  if (o.catalog !== undefined) await systemCall(r, 'PUT', 'catalog', { resources: o.catalog })
  await systemCall(r, 'PUT', 'policy', { roles: o.roles })
}

/**
 * Gives Cauthy the resources a system declares, replacing the ones it has.
 * Cauthy refuses (`catalog_in_use`) to drop a resource or an action the
 * policy still names.
 */
export async function pushCatalog(o: Omit<PushPolicyOptions, 'roles' | 'catalog'> & { resources: CatalogResource[] }): Promise<CatalogResource[]> {
  const data = await systemCall(reach(o, 'push a catalog'), 'PUT', 'catalog', { resources: o.resources })
  return (data?.resources as CatalogResource[] | undefined) ?? []
}

/** What a policy file holds: the roles alone (as it used to), or `{ catalog, roles }`. */
export function readPolicyFile(parsed: unknown): SystemPolicy {
  if (Array.isArray(parsed)) return { catalog: [], roles: parsed as PolicyRole[] }
  const o = (parsed ?? {}) as { roles?: unknown; catalog?: unknown }
  if (!Array.isArray(o.roles)) throw new Error('no "roles" list')
  if (o.catalog !== undefined && !Array.isArray(o.catalog)) throw new Error('"catalog" is not a list')
  return { catalog: (o.catalog as CatalogResource[] | undefined) ?? [], roles: o.roles as PolicyRole[] }
}

// ── Asking Cauthy ──────────────────────────────────────────────────────────

/** A check's question as Cauthy reads it. */
export function checkWire(q: CheckQuestion): Record<string, unknown> {
  return {
    resource: q.resource,
    action: q.action,
    ...(q.resourceId !== undefined ? { resource_id: q.resourceId } : {}),
    ...(q.ownerId !== undefined ? { owner_id: q.ownerId } : {}),
    ...(q.attributes !== undefined ? { attributes: q.attributes } : {}),
  }
}

/** Cauthy's answer to a check, as the SDK gives it. Anything but a plain yes is a no. */
export function checkResultOf(d: any): CheckResult {
  const r = d?.rule
  const rule: CheckRule | undefined = r && typeof r === 'object'
    ? {
        source: r.source === 'exception' ? 'exception' : 'role',
        ...(r.role ? { role: String(r.role) } : {}),
        kind: String(r.kind ?? '*'),
        resource: String(r.resource ?? ''),
        action: String(r.action ?? ''),
        effect: r.effect === 'allow' ? 'allow' : 'deny',
        ...(r.condition ? { condition: String(r.condition) } : {}),
      }
    : undefined
  return { allowed: d?.allowed === true, reason: String(d?.reason ?? ''), ...(rule ? { rule } : {}) }
}

/** The id of an organization given by its id or as the session has it. */
export function organizationIdOf(o: OrganizationRef | null | undefined): string {
  return typeof o === 'string' ? o : typeof o?.id === 'string' ? o.id : ''
}
