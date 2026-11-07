// The application acting on its own: creating its organizations, adding their
// members, inviting people. No person's token is involved — the application
// is somebody in Cauthy, and what it may touch is its own system's
// organizations and nothing else.
//
// It proves who it is with the client's secret, or with a key it holds and
// whose public half it publishes (`publicJwks`): then nothing secret is ever
// shared with Cauthy.

import { exportJWK, importJWK, importPKCS8, SignJWT, type JWK, type KeyLike } from 'jose'
import { checkResultOf, checkWire, type CatalogResource, type PolicyRole } from './permissions'
import { fromWire, type CauthyTheme } from './theme'
import { CauthyConfigError, type CheckQuestion, type CheckResult, type JsonValue } from './types'
import { withoutTrailingSlashes } from './url'

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
/** Ask for a new token this long before the one held runs out. */
const SKEW_MS = 30_000

/** The key an application signs its assertions with. */
export interface SystemKey {
  /** The private key: PKCS#8 PEM, or a JWK (as an object or its JSON). RSA, for RS256. */
  privateKey: string | JWK
  /** The id the public key is published under (`kid`). */
  keyId: string
  /**
   * The client the key belongs to, when it is not the one people sign in
   * with: a public sign-in client has no key of its own, and the system's
   * identity is a confidential client beside it. Default: the client id.
   */
  clientId?: string
}

export interface SystemOptions {
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The application's client id. Default: `CAUTHY_CLIENT_ID`. */
  clientId?: string
  /** Its secret. Default: `CAUTHY_CLIENT_SECRET`. Not needed with `key`. */
  clientSecret?: string
  /**
   * The key to prove who the application is with, instead of the secret.
   * Default: `CAUTHY_SYSTEM_KEY` (the private key) and `CAUTHY_SYSTEM_KEY_ID`.
   */
  key?: SystemKey
  /** The application's system, which `check` asks about. Default: `CAUTHY_SYSTEM`. */
  system?: string
  /**
   * The application's own page for accepting an invitation, as an absolute
   * address (`https://app.example.com/accept-invite`, where `<AcceptInvite />`
   * is). The invitations `members.add` and `invite` send open it; without it,
   * they open Cauthy's own page. Cauthy follows it only on an origin the
   * client registered to be sent back to. Default: `CAUTHY_ACCEPT_INVITE_URL`.
   */
  acceptInviteUrl?: string
  /**
   * The application's own keys, kept in its database (contract mode): it
   * signs with the newest and publishes them. Takes the place of `key`.
   */
  keys?: import('./keys').PactKeys
  /** The client the keys prove: the system's own, beside the sign-in client. */
  keysClientId?: string
  fetch?: typeof fetch
}

/** Cauthy refused a request of the application's own. */
export class CauthyApiError extends Error {
  constructor(
    readonly status: number,
    /** Cauthy's code for what went wrong: `organization_not_found`, `other_system`, `outside_system_scope`, `member_exists`… */
    readonly code: string,
    message: string,
  ) {
    super(`cauthy-auth: ${message}`)
    this.name = 'CauthyApiError'
  }
}

/** An organization of the application's system. Every moment is UTC. */
export interface Organization {
  id: string
  system: string
  name: string
  kind: string
  /** The id the application knows it by. */
  externalId?: string
  status: 'active' | 'archived'
  metadata: Record<string, JsonValue>
  members: number
  createdAt: string
  updatedAt: string
}

export interface OrganizationMember {
  userId: string
  email: string
  name: string
  /** The account's status: a disabled member is still listed. */
  status: string
  role: string
  /** True when the address had no account: one was made and invited. */
  invited?: boolean
}

/** Who to add: an account by its id, or anybody by their address (invited when new). */
export type NewMember = {
  role: string
  name?: string
  locale?: string
  /**
   * Adds and nothing else (the default): a person who already belongs keeps
   * their role, and the call throws `CauthyApiError` with code
   * `member_exists` (409). `false` sets the role of whoever is already
   * there, as `setRole` does.
   */
  onlyNew?: boolean
} & ({ userId: string; email?: undefined } | { email: string; userId?: undefined })

export interface CauthySystem {
  /** The application's own token, asked for when needed and kept until it is about to run out. */
  token(): Promise<string>
  /** Any route the application's token may call; answers what Cauthy put under `data`. */
  request<T = unknown>(method: string, path: string, body?: unknown): Promise<T>
  organizations: {
    list(query?: { q?: string; status?: 'active' | 'archived'; limit?: number; offset?: number }): Promise<{ items: Organization[]; total: number }>
    create(input: { name: string; kind?: string; externalId?: string; metadata?: Record<string, JsonValue> }): Promise<Organization>
    get(id: string): Promise<Organization>
    update(id: string, patch: { name?: string; kind?: string; status?: 'active' | 'archived'; metadata?: Record<string, JsonValue> }): Promise<Organization>
    /** Removes the organization and every membership of it, for good. */
    remove(id: string): Promise<void>
  }
  members: {
    list(organizationId: string): Promise<OrganizationMember[]>
    /** Adds a person; one who already belongs throws `member_exists` unless `onlyNew: false`. */
    add(organizationId: string, member: NewMember): Promise<OrganizationMember>
    setRole(organizationId: string, userId: string, role: string): Promise<OrganizationMember>
    remove(organizationId: string, userId: string): Promise<void>
  }
  /** Invites a person who has no account yet; answers the account made for them. */
  invite(person: { email: string; name?: string; locale?: string }): Promise<{ id: string; email: string }>
  /**
   * How the application looks on Cauthy's pages, read. It is decided in
   * Cauthy's dashboard, by a person: an application never changes it.
   */
  theme: {
    get(clientId?: string): Promise<CauthyTheme>
  }
  /** The catalog of roles of one of the application's systems, as Cauthy has it. */
  policy: {
    get(system: string): Promise<PolicyRole[]>
  }
  /**
   * The resources one of the application's systems declares, with their
   * actions and the attributes conditions read; empty when it declares none.
   */
  catalog: {
    get(system: string): Promise<CatalogResource[]>
    /** Replaces them. Cauthy refuses (`catalog_in_use`) to drop one the policy still names. */
    set(system: string, resources: CatalogResource[]): Promise<CatalogResource[]>
  }
  /**
   * Asks Cauthy whether a member of one of the system's organizations may do
   * an action on a resource, conditions weighed. A person who is not a member
   * is a no; an organization of another system throws (`organization_not_found`).
   */
  check(question: CheckQuestion & { organizationId: string; userId: string; system?: string }): Promise<CheckResult>
  /** The public half of `key`, to serve at the address Cauthy was given (`jwks_uri`). Empty with a secret. */
  publicJwks(): Promise<{ keys: JWK[] }>
}

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined
}

interface OrgWire {
  id: string; system: string; name: string; kind: string; external_id?: string; status: 'active' | 'archived'
  metadata: Record<string, JsonValue>; members: number; created_at: string; updated_at: string
}

function toOrganization(o: OrgWire): Organization {
  return { id: o.id, system: o.system, name: o.name, kind: o.kind, externalId: o.external_id, status: o.status,
    metadata: o.metadata ?? {}, members: o.members, createdAt: o.created_at, updatedAt: o.updated_at }
}

interface MemberWire { user_id: string; email: string; name: string; status: string; role: string; invited?: boolean }

function toMember(m: MemberWire): OrganizationMember {
  return { userId: m.user_id, email: m.email, name: m.name, status: m.status, role: m.role, ...(m.invited === undefined ? {} : { invited: m.invited }) }
}

function asJwk(k: SystemKey): JWK | undefined {
  if (typeof k.privateKey !== 'string') return k.privateKey
  return k.privateKey.includes('BEGIN') ? undefined : (JSON.parse(k.privateKey) as JWK)
}

async function loadKey(k: SystemKey): Promise<KeyLike | Uint8Array> {
  const jwk = asJwk(k)
  // Extractable, so its public half can be published (publicJwks).
  return jwk ? importJWK(jwk, 'RS256') : importPKCS8(k.privateKey as string, 'RS256', { extractable: true })
}

export function createSystem(given: SystemOptions = {}): CauthySystem {
  const issuer = withoutTrailingSlashes(given.issuer ?? env('CAUTHY_ISSUER') ?? '')
  const clientId = given.clientId ?? env('CAUTHY_CLIENT_ID') ?? ''
  const clientSecret = given.clientSecret ?? env('CAUTHY_CLIENT_SECRET') ?? ''
  const envKey = env('CAUTHY_SYSTEM_KEY')
  const key = given.key ?? (envKey ? { privateKey: envKey, keyId: env('CAUTHY_SYSTEM_KEY_ID') ?? '' } : undefined)
  const ownSystem = given.system ?? env('CAUTHY_SYSTEM') ?? ''
  const acceptInviteUrl = given.acceptInviteUrl ?? env('CAUTHY_ACCEPT_INVITE_URL') ?? ''
  // What a call that sends an invitation says of the page it opens: the
  // application names itself, and the page, the same as its own screens do.
  const inviteHeaders: Record<string, string> = /^https?:\/\//.test(acceptInviteUrl)
    ? { 'x-cauthy-client-id': clientId, 'x-cauthy-link-to': acceptInviteUrl }
    : {}
  const doFetch: typeof fetch = (...args) => (given.fetch ?? fetch)(...args)
  const tokenEndpoint = `${issuer}/v1/oauth/token`

  // Checked when it is first used, not when it is made: an application that
  // only signs people in never needs any of this.
  function configured(): void {
    if (!/^https?:\/\//.test(issuer)) throw new CauthyConfigError('issuer (CAUTHY_ISSUER) must be Cauthy\'s address')
    if (clientId === '') throw new CauthyConfigError('clientId (CAUTHY_CLIENT_ID) is required')
    if (given.keys) {
      if (!given.keysClientId) throw new CauthyConfigError('the contract gives the system no identity of its own: its link needs a service block')
      return
    }
    if (key ? key.keyId === '' : clientSecret === '') {
      throw new CauthyConfigError(key ? 'the key needs its id (CAUTHY_SYSTEM_KEY_ID)'
        : 'to act on its own the application needs its secret (CAUTHY_CLIENT_SECRET) or a key (CAUTHY_SYSTEM_KEY)')
    }
  }

  let imported: Promise<KeyLike | Uint8Array> | undefined
  const signingKey = () => (imported ??= loadKey(key as SystemKey))

  // The token endpoint refuses as OAuth does ({error, error_description});
  // every other route in Cauthy's envelope ({errors: [{code, message}]}).
  async function fail(res: Response, what: string): Promise<never> {
    const body = (await res.json().catch(() => null)) as
      { error?: string; error_description?: string; errors?: { code?: string; message?: string }[] } | null
    const first = body?.errors?.[0]
    const code = typeof body?.error === 'string' ? body.error : first?.code
    const message = typeof body?.error === 'string' ? body.error_description : first?.message
    throw new CauthyApiError(res.status, code ?? 'error', `Cauthy refused ${what} (${res.status}): ${message ?? res.statusText}`)
  }

  let held: { value: string; until: number } | undefined
  let asking: Promise<string> | undefined

  async function ask(): Promise<string> {
    configured()
    const self = given.keys ? (given.keysClientId as string) : key?.clientId || clientId
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: self })
    if (given.keys || key) {
      const signer = given.keys ? await given.keys.current() : { kid: (key as SystemKey).keyId, privateKey: await signingKey() }
      const assertion = await new SignJWT({})
        .setProtectedHeader({ alg: 'RS256', kid: signer.kid })
        .setIssuer(self).setSubject(self).setAudience(tokenEndpoint)
        .setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime('2m')
        .sign(signer.privateKey)
      form.set('client_assertion_type', ASSERTION_TYPE)
      form.set('client_assertion', assertion)
    } else {
      form.set('client_secret', clientSecret)
    }
    const res = await doFetch(tokenEndpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form })
    if (!res.ok) await fail(res, 'the application\'s own token')
    const t = (await res.json()) as { access_token: string; expires_in: number }
    held = { value: t.access_token, until: Date.now() + t.expires_in * 1000 - SKEW_MS }
    return t.access_token
  }

  function token(): Promise<string> {
    if (held && Date.now() < held.until) return Promise.resolve(held.value)
    // One request, however many callers arrive while it is out.
    return (asking ??= ask().finally(() => { asking = undefined }))
  }

  async function call(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<unknown> {
    const send = async () => doFetch(`${issuer}${path}`, {
      method,
      headers: { authorization: `Bearer ${await token()}`, ...extra, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    let res = await send()
    if (res.status === 401 && held) {
      // The token was taken back early (the client's keys or secret changed): once more, with a new one.
      held = undefined
      res = await send()
    }
    if (!res.ok) await fail(res, `${method} ${path}`)
    return res.status === 204 ? undefined : res.json()
  }

  const data = async <T>(method: string, path: string, body?: unknown, extra?: Record<string, string>) => ((await call(method, path, body, extra)) as { data: T } | undefined)?.data as T
  const id = encodeURIComponent

  return {
    token,
    request: data,
    organizations: {
      async list(query = {}) {
        const q = new URLSearchParams()
        for (const [k, v] of Object.entries(query)) if (v !== undefined) q.set(k, String(v))
        const out = (await call('GET', `/v1/organizations${q.size ? `?${q}` : ''}`)) as { data: OrgWire[]; total_count: number }
        return { items: out.data.map(toOrganization), total: out.total_count }
      },
      async create(input) {
        return toOrganization(await data<OrgWire>('POST', '/v1/organizations',
          { name: input.name, kind: input.kind, external_id: input.externalId, metadata: input.metadata }))
      },
      async get(orgId) {
        return toOrganization(await data<OrgWire>('GET', `/v1/organizations/${id(orgId)}`))
      },
      async update(orgId, patch) {
        return toOrganization(await data<OrgWire>('PATCH', `/v1/organizations/${id(orgId)}`, patch))
      },
      async remove(orgId) {
        await call('DELETE', `/v1/organizations/${id(orgId)}`)
      },
    },
    members: {
      async list(orgId) {
        return (await data<MemberWire[]>('GET', `/v1/organizations/${id(orgId)}/members`)).map(toMember)
      },
      async add(orgId, m) {
        return toMember(await data<MemberWire>('POST', `/v1/organizations/${id(orgId)}/members`,
          { role: m.role, user_id: m.userId, email: m.email, name: m.name, locale: m.locale, client_id: clientId, only_new: m.onlyNew !== false }, inviteHeaders))
      },
      async setRole(orgId, userId, role) {
        return toMember(await data<MemberWire>('PUT', `/v1/organizations/${id(orgId)}/members/${id(userId)}`, { role }))
      },
      async remove(orgId, userId) {
        await call('DELETE', `/v1/organizations/${id(orgId)}/members/${id(userId)}`)
      },
    },
    async invite(person) {
      // The invitation leads back to this application once it is accepted.
      const u = await data<{ id: string; email: string }>('POST', '/v1/users', { ...person, client_id: clientId }, inviteHeaders)
      return { id: u.id, email: u.email }
    },
    theme: {
      async get(of = clientId) {
        return fromWire(await data<Record<string, unknown>>('GET', `/v1/oauth/clients/${id(of)}/theme`))
      },
    },
    policy: {
      async get(system) {
        return (await data<{ roles?: PolicyRole[] }>('GET', `/v1/systems/${id(system)}/policy`)).roles ?? []
      },
    },
    catalog: {
      async get(system) {
        return (await data<{ resources?: CatalogResource[] }>('GET', `/v1/systems/${id(system)}/catalog`)).resources ?? []
      },
      async set(system, resources) {
        return (await data<{ resources?: CatalogResource[] }>('PUT', `/v1/systems/${id(system)}/catalog`, { resources })).resources ?? []
      },
    },
    async check(q) {
      const system = q.system ?? ownSystem
      if (system === '') throw new CauthyConfigError('name the system to check in (system, or CAUTHY_SYSTEM)')
      return checkResultOf(await data('POST', `/v1/systems/${id(system)}/check`, { organization_id: q.organizationId, user_id: q.userId, ...checkWire(q) }))
    },
    async publicJwks() {
      if (given.keys) return given.keys.published()
      if (!key) return { keys: [] }
      const { kty, n, e } = asJwk(key) ?? (await exportJWK(await signingKey()))
      return { keys: [{ kty, n, e, kid: key.keyId, alg: 'RS256', use: 'sig' }] }
    },
  }
}
