// Contract mode: everything an application needs to know about Cauthy, read
// from the network's context graph (core-contracts' graph.json), never typed.
//
// A link of the contracts repository says "this system signs its people in
// with Cauthy, returns to these addresses, and acts on its own with the keys
// it publishes there". Cauthy applies that link — its clients are made with
// the ids the link names — and the application reads the same link: the
// issuer, the workspace, the sign-in client, the system's own client, where
// its keys are published. Both ends read one file, so nothing is copied.

import { CauthyConfigError } from './types'
import { withoutTrailingSlashes } from './url'

/** What createCauthy is given to run by contract. */
export interface ContractOptions {
  /** The context graph, as `cauthy contracts pull` writes it (contracts/graph.json). */
  graph: unknown
  /** This application's system in the graph: `"acme-crm"`. */
  system: string
  /** The link to read, when the system has more than one with Cauthy. */
  link?: string
  /** Cauthy's system in the graph. Default: `"cauthy"`. */
  provider?: string
}

/** What an application reads of its contract. */
export interface ResolvedContract {
  system: string
  link: string
  /** Cauthy's public address. */
  issuer: string
  /** The workspace's id, and its slug (what the application's own screens send). */
  tenantId: string
  tenant: string
  /** The public client people sign in with: `pact.<link>`. */
  clientId: string
  /** Where people may return after signing in. */
  redirectUris: string[]
  /** Whether Cauthy asks the system's proof on the code exchange now (`systemProof` is `required`). */
  requireSystemProof: boolean
  /** How the link asks for the proof: never, from the first proved sign-in on (`auto`), or always. */
  systemProof: 'off' | 'auto' | 'required'
  /** Whether Cauthy issues no token through this link before the address is confirmed. */
  requireVerifiedEmail: boolean
  /** Whether the link lets its people ask to stay signed in. */
  persistentSessions: boolean
  /** The system's own client, when the link gives it one: `pact.<link>.service`. */
  serviceClientId?: string
  /** Where the system publishes its keys, and the path of that address. */
  jwksUrl?: string
  jwksPath?: string
  /** Where the system receives Cauthy's events, when it says. */
  eventsUrl?: string
}

/**
 * The variables of the standard mode. With a contract none may be set: two
 * sources of the same thing, one silently winning, is how a system ends up
 * signing people in through a client nobody meant.
 */
export const STANDARD_VARIABLES = [
  'CAUTHY_ISSUER', 'CAUTHY_CLIENT_ID', 'CAUTHY_CLIENT_SECRET', 'CAUTHY_SECRET',
  'CAUTHY_SYSTEM', 'CAUTHY_TENANT', 'CAUTHY_SYSTEM_KEY', 'CAUTHY_SYSTEM_KEY_ID',
] as const

/** Refuses to run by contract with a variable of the standard mode set: names it. */
export function failClosed(environment: Record<string, string | undefined> | undefined): void {
  const set = STANDARD_VARIABLES.filter(name => (environment?.[name] ?? '') !== '')
  if (set.length > 0) {
    throw new CauthyConfigError(`the application runs by contract, and ${set.join(', ')} ${set.length === 1 ? 'is' : 'are'} also set: ` +
      'remove ' + (set.length === 1 ? 'it' : 'them') + ' from the environment. Everything comes from the contract.')
  }
}

const SLUG = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = '00000000-0000-0000-0000-000000000000'

interface GraphNode {
  id?: unknown
  type?: unknown
  url?: unknown
  events_url?: unknown
  jwks_url?: unknown
  tenants?: { id?: unknown; slug?: unknown }[] | null
}

interface GraphEdge {
  from?: unknown
  relation?: unknown
  to?: unknown
  link?: unknown
  identity?: { tenant?: unknown; subject?: unknown; tenant_id?: unknown; create_tenant?: unknown }
  sign_in?: { client_id?: unknown; redirect_uris?: unknown; require_system_proof?: unknown; system_proof?: unknown; require_verified_email?: unknown; persistent_sessions?: unknown } | null
  service?: { client_id?: unknown; system?: unknown; jwks_url?: unknown } | null
}

const text = (v: unknown) => (typeof v === 'string' ? v : '')

function httpsAddress(raw: string, what: string): URL {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    throw new CauthyConfigError(`the contract's ${what} is not an address: ${JSON.stringify(raw)}`)
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1'
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
    throw new CauthyConfigError(`the contract's ${what} must be https: ${raw}`)
  }
  return u
}

/** Reads what the graph says of the system's link with Cauthy. */
export function readContract(options: ContractOptions): ResolvedContract {
  const { system } = options
  const provider = options.provider ?? 'cauthy'
  if (!SLUG.test(system ?? '')) throw new CauthyConfigError('contract.system must be the system\'s id in the graph, e.g. "acme-crm"')
  const graph = (options.graph && typeof options.graph === 'object' && 'default' in options.graph && !('edges' in options.graph)
    ? (options.graph as { default: unknown }).default
    : options.graph) as { nodes?: GraphNode[]; edges?: GraphEdge[] } | null
  if (!graph || !Array.isArray(graph.edges) || !Array.isArray(graph.nodes)) {
    throw new CauthyConfigError('contract.graph is not a context graph: pass the graph.json that `cauthy contracts pull` writes')
  }
  const node = (id: string) => graph.nodes?.find(n => n.type === 'system' && n.id === id)
  const own = node(system)
  if (!own) throw new CauthyConfigError(`the graph has no system "${system}"`)
  const cauthy = node(provider)
  if (!cauthy) throw new CauthyConfigError(`the graph has no system "${provider}"`)

  const links = graph.edges.filter(e => e.relation === 'links' && e.from === system && e.to === provider && e.sign_in)
    .filter(e => options.link === undefined || e.link === options.link)
  if (links.length === 0) {
    throw new CauthyConfigError(options.link
      ? `the graph has no link "${options.link}" from ${system} to ${provider} with sign_in`
      : `no link of the graph signs ${system}'s people in with ${provider}: merge one in the contracts repository, then pull the graph again`)
  }
  if (links.length > 1) {
    throw new CauthyConfigError(`${system} has ${links.length} links to ${provider}: name the one to read (contract.link): ${links.map(l => text(l.link)).join(', ')}`)
  }
  const e = links[0]
  const link = text(e.link)
  // The link names its workspace by id (the graph lists its slug) or by slug
  // (the graph pins its id as tenant_id). A slug with no tenant_id is a
  // workspace Cauthy has not created yet, or a graph pulled before it was.
  const named = text(e.identity?.tenant)
  const pinned = text(e.identity?.tenant_id)
  if (named === NIL_UUID || pinned === NIL_UUID) throw new CauthyConfigError(`the link ${link} names the nil UUID as its workspace: name the workspace by its slug`)
  let tenantId: string
  let tenant: string
  if (UUID.test(named)) {
    tenantId = named
    tenant = text((cauthy.tenants ?? []).find(t => t.id === named)?.slug)
    if (tenant === '') throw new CauthyConfigError(`the graph does not name the slug of the workspace ${named} that the link ${link} uses`)
  } else {
    if (!SLUG.test(named)) throw new CauthyConfigError(`the link ${link} names no workspace: identity.tenant is a UUID or a slug`)
    if (!UUID.test(pinned)) {
      throw new CauthyConfigError(e.identity?.create_tenant === true
        ? `the link ${link} asks Cauthy for a new workspace "${named}", and the graph has no tenant_id for it yet: once Cauthy has created it and core-contracts lists it, pull the graph again`
        : `the link ${link} names the workspace "${named}" by its slug, and the graph carries no tenant_id for it: pull the graph again`)
    }
    tenantId = pinned
    tenant = named
  }
  const issuer = withoutTrailingSlashes(httpsAddress(text(cauthy.url), `address of ${provider}`).href)
  const signIn = e.sign_in ?? {}
  const clientId = text(signIn.client_id) || `pact.${link}`
  const redirectUris = Array.isArray(signIn.redirect_uris) ? signIn.redirect_uris.map(text).filter(Boolean) : []
  if (redirectUris.length === 0) throw new CauthyConfigError(`the link ${link} names no redirect URI`)

  // system_proof says the whole of it; a graph from before it has only the boolean.
  const proof = text(signIn.system_proof)
  const systemProof: ResolvedContract['systemProof'] = proof === 'off' || proof === 'auto' || proof === 'required'
    ? proof
    : signIn.require_system_proof === true ? 'required' : 'off'
  if (systemProof !== 'off' && !e.service) {
    throw new CauthyConfigError(`the link ${link} asks for the system's proof (${systemProof}) and gives ${system} no identity to make it with: it needs a service block`)
  }

  const out: ResolvedContract = {
    system, link, issuer, tenantId, tenant, clientId, redirectUris,
    requireSystemProof: systemProof === 'required',
    systemProof,
    requireVerifiedEmail: signIn.require_verified_email === true,
    persistentSessions: signIn.persistent_sessions === true,
  }
  if (e.service) {
    out.serviceClientId = text(e.service.client_id) || `pact.${link}.service`
    const jwks = text(e.service.jwks_url) || text(own.jwks_url)
    if (jwks === '') throw new CauthyConfigError(`the link ${link} gives ${system} its own identity, and ${system} names no jwks_url`)
    out.jwksUrl = httpsAddress(jwks, 'jwks_url').href
    out.jwksPath = new URL(out.jwksUrl).pathname
  }
  if (text(own.events_url) !== '') out.eventsUrl = httpsAddress(text(own.events_url), 'events_url').href
  return out
}

/** One difference between a contract and what Cauthy holds. */
export interface PactItem {
  kind: 'client' | 'redirect_uri' | 'grant_type' | 'role' | 'organization' | 'require_system_proof' | 'persistent_sessions' | 'jwks_url'
  client_id?: string
  value: string
  detail?: string
}

/** How the system stands against its contract, as Cauthy checks it (GET /v1/pact/status). Moments are UTC. */
export interface PactStatus {
  system: string
  tenant_id: string
  checked_at: string
  /** When Cauthy's daily reconciliation last checked it; null before the first. */
  reconciled_at: string | null
  in_step: boolean
  /** In Cauthy, and the contract does not name it. Nothing is ever deleted for it. */
  outside: PactItem[]
  /** Named by the contract, and Cauthy does not hold it as it says. */
  missing: PactItem[]
  contract: { clients: { client_id: string; link: string; purpose: 'sign_in' | 'service'; redirect_uris?: string[]; grant_types: string[]; require_system_proof?: boolean; jwks_url?: string }[]; roles?: Record<string, string[]> }
  held: { clients: Record<string, unknown>[]; roles: string[]; organizations: Record<string, number> }
}
