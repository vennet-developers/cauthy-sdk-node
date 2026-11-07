// An MCP server (or any API) that AI agents use as one of your people.
//
//   import { mcpAuth } from '@cauthyhq/node/mcp'
//   const auth = mcpAuth({ resource: 'https://mcp.example.com/mcp', scopes: ['books:read'] })
//
//   // Fetch-style (Hono, Next.js, Workers, Bun, Deno):
//   export default { fetch: auth.protect((request, agent) => handleMcp(request, agent)) }
//
//   // Express or plain Node, with the MCP TypeScript SDK (its transport reads req.auth):
//   app.use(auth.middleware())
//
// How an agent gets in, as the MCP specification lays it out: it calls the
// server, which answers 401 and points at its protected resource metadata
// (RFC 9728); that names Cauthy as the authorization server; the agent
// registers itself there, sends the person to sign in and allow it, and comes
// back with a token issued for this server alone (its `aud`). This module is
// the server's half: the metadata, the 401 that points at it, and checking
// the token. The resource must be registered in Cauthy's dashboard (AI
// agents), with the same address, for the workspace whose people use it.
//
// A server that calls another of the workspace's servers for the person
// trades the agent's token for one for that server (token exchange, RFC 8693):
//
//   const auth = mcpAuth({ resource, clientId, clientSecret })   // from the dashboard
//   const { accessToken } = await auth.exchange(agent, 'https://api.example.com', ['orders:read'])
//
// The workspace's admins must have delegated that call in the dashboard, and
// the person allowed it when they connected the agent.

import { jwtVerify, type JWTVerifyGetKey } from 'jose'
import { keysOf } from './verify'
import { withoutTrailingSlashes } from './url'

/** The person an agent acts for, and what they allowed it. */
export interface AgentIdentity {
  /** The person. */
  userId: string
  tenantId: string
  email?: string
  /** The person's roles in the workspace. */
  roles: string[]
  /** What the person allowed the agent to do here. */
  scopes: string[]
  /** The agent (its client_id at Cauthy). */
  clientId: string
  /** UTC, ISO 8601. */
  expiresAt: string
  /** The token as it arrived. */
  token: string
  /**
   * Set when the token came by token exchange: the server that called this
   * one for the person (the `act` claim's subject).
   */
  actor?: string
}

export interface McpAuthOptions {
  /** This server's address, as registered in Cauthy. Default: `CAUTHY_MCP_RESOURCE`. */
  resource?: string
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** Scopes every call needs. Default: none. */
  scopes?: string[]
  /** The scopes this server understands, to tell agents (`scopes_supported`). Default: `scopes`. */
  scopesSupported?: string[]
  /** A name for the server, shown by some agents. */
  resourceName?: string
  /** Cauthy's keys. Default: fetched from the issuer and cached. */
  jwks?: JWTVerifyGetKey
  /** The moment to verify at. Default: now. */
  now?: () => Date
  /**
   * Ask Cauthy, besides checking the token here, whether the person still
   * allows the agent (RFC 7662). Then an agent is cut off the moment it is
   * disconnected, not when its token runs out, at the price of a call to
   * Cauthy per token every `cacheSeconds` (default 30). Default: off.
   */
  introspect?: boolean | { cacheSeconds?: number }
  /** The fetch to call Cauthy with. Default: the global one. */
  fetch?: typeof fetch
  /** How long a call to Cauthy (introspection, token exchange) may take, in milliseconds. Default: 5000. */
  timeoutMs?: number
  /**
   * This server's client_id and secret at Cauthy, for token exchange (AI
   * agents → the server → Server credentials). Defaults:
   * `CAUTHY_MCP_CLIENT_ID`, `CAUTHY_MCP_CLIENT_SECRET`.
   */
  clientId?: string
  clientSecret?: string
}

/** What a token exchange answers. */
export interface ExchangedToken {
  /** The token for the other server, as the person. Send it as `Authorization: Bearer`. */
  accessToken: string
  /** What it allows there. */
  scopes: string[]
  /** UTC, ISO 8601. Never later than the agent's own token. */
  expiresAt: string
}

/** A token exchange Cauthy refused, with the OAuth error it answered. */
export class CauthyExchangeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly description: string,
  ) {
    super(`@cauthyhq/node: token exchange refused (${code}): ${description}`)
    this.name = 'CauthyExchangeError'
  }
}

/** A token refused: `status` is 401 (no token, or not a good one) or 403 (a scope missing). */
export class McpAuthError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly code: 'invalid_request' | 'invalid_token' | 'insufficient_scope',
    readonly description: string,
  ) {
    super(`@cauthyhq/node: ${description}`)
    this.name = 'McpAuthError'
  }
}

/** What the MCP TypeScript SDK reads from `req.auth` (its AuthInfo). */
export interface McpAuthInfo {
  token: string
  clientId: string
  scopes: string[]
  /** Seconds since the epoch. */
  expiresAt: number
  resource: URL
  extra: { userId: string; tenantId: string; email?: string; roles: string[] }
}

export interface McpAuth {
  /** This server's address, in the form Cauthy compares it in. */
  resource: string
  /** Where the protected resource metadata is served. */
  metadataUrl: string
  /** The protected resource metadata (RFC 9728). */
  metadata(): Record<string, unknown>
  /** The metadata's paths: `/.well-known/oauth-protected-resource` plus this server's path. */
  metadataPaths: string[]
  /** Verifies the `Authorization: Bearer` of a request (or a token). Throws `McpAuthError`. */
  verify(from: string | Request | Headers, needs?: string[]): Promise<AgentIdentity>
  /** The answer to a refused token: 401 or 403, with the `WWW-Authenticate` that points an agent at Cauthy. */
  challenge(error?: McpAuthError): Response
  /** The metadata, when the request asks for it; `null` otherwise. */
  handleMetadata(request: Request): Response | null
  /** Wraps a fetch-style handler: serves the metadata, refuses what has no good token, passes the rest with who it is. */
  protect(handler: (request: Request, agent: AgentIdentity) => Response | Promise<Response>, needs?: string[]): (request: Request) => Promise<Response>
  /**
   * Connect-style middleware (Express, Node's http): serves the metadata,
   * refuses what has no good token, and sets `req.agent` and `req.auth` —
   * what the MCP TypeScript SDK's transport hands its tools as `authInfo`.
   */
  middleware(needs?: string[]): (req: NodeRequest, res: NodeResponse, next: (err?: unknown) => void) => void
  /**
   * Trades the agent's token this server received for one for another of the
   * workspace's servers, to call it for the person (RFC 8693). Needs this
   * server's `clientId` and `clientSecret`. Answers are kept until shortly
   * before they expire. Throws `CauthyExchangeError` when Cauthy refuses.
   */
  exchange(from: string | AgentIdentity, target: string, scopes?: string[]): Promise<ExchangedToken>
}

// The slice of Node's (and Express's) request and response this needs.
interface NodeRequest {
  method?: string
  url?: string
  originalUrl?: string
  headers: Record<string, string | string[] | undefined>
  auth?: McpAuthInfo
  agent?: AgentIdentity
}
interface NodeResponse {
  statusCode: number
  setHeader(name: string, value: string): unknown
  end(body?: string): unknown
}

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined
}

/**
 * The address in the one form Cauthy keeps it: scheme and host in lower case,
 * no default port, no trailing slash, no query, no fragment.
 */
export function canonicalResource(raw: string): string {
  let u: URL
  try {
    u = new URL(raw.trim())
  } catch {
    throw new Error(`@cauthyhq/node: resource ${JSON.stringify(raw)} is not an absolute address`)
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]'
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
    throw new Error('@cauthyhq/node: resource must be an https address')
  }
  if (u.search !== '' || u.hash !== '') throw new Error('@cauthyhq/node: resource may not have a query or a fragment')
  return `${u.protocol}//${u.host}${withoutTrailingSlashes(u.pathname)}`
}

function bearer(from: string | Request | Headers): string {
  if (typeof from === 'string') return from.replace(/^Bearer\s+/i, '').trim()
  const header = (from instanceof Headers ? from : from.headers).get('authorization') ?? ''
  return /^Bearer\s+/i.test(header) ? header.replace(/^Bearer\s+/i, '').trim() : ''
}

function isActor(v: unknown): v is { sub: string } {
  return typeof v === 'object' && v !== null && typeof (v as { sub?: unknown }).sub === 'string'
}

function quoted(v: string): string {
  return `"${v.replace(/["\\]/g, '')}"`
}

/** Protects an MCP server with Cauthy. */
export function mcpAuth(options: McpAuthOptions = {}): McpAuth {
  const rawResource = options.resource ?? env('CAUTHY_MCP_RESOURCE') ?? ''
  if (rawResource === '') throw new Error('@cauthyhq/node: resource (CAUTHY_MCP_RESOURCE) is not set')
  const resource = canonicalResource(rawResource)
  const issuer = withoutTrailingSlashes(options.issuer ?? env('CAUTHY_ISSUER') ?? '')
  if (issuer === '') throw new Error('@cauthyhq/node: issuer (CAUTHY_ISSUER) is not set')
  const timeoutMs = options.timeoutMs ?? 5000
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('@cauthyhq/node: timeoutMs must be a positive number of milliseconds')
  const required = options.scopes ?? []
  const url = new URL(resource)
  const path = url.pathname === '/' ? '' : url.pathname
  const metadataPaths = [...new Set([`/.well-known/oauth-protected-resource${path}`, '/.well-known/oauth-protected-resource'])]
  const metadataUrl = `${url.origin}${metadataPaths[0]}`

  const metadata = () => ({
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ['header'],
    scopes_supported: options.scopesSupported ?? required,
    ...(options.resourceName ? { resource_name: options.resourceName } : {}),
  })

  const introspect = options.introspect ? { cacheMs: ((typeof options.introspect === 'object' ? options.introspect.cacheSeconds : undefined) ?? 30) * 1000 } : null
  const answers = new Map<string, { active: boolean; until: number }>()
  const stillAllowed = async (token: string, cacheMs: number): Promise<boolean> => {
    const now = Date.now()
    const kept = answers.get(token)
    if (kept && kept.until > now) return kept.active
    let active = false
    try {
      const res = await (options.fetch ?? fetch)(`${issuer}/v1/oauth/introspect`, {
        signal: AbortSignal.timeout(timeoutMs),
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({ token }),
      })
      if (!res.ok) throw new Error(`introspection answered ${res.status}`)
      active = ((await res.json()) as { active?: unknown }).active === true
    } catch (err) {
      // Cauthy could not be asked: what it last said holds.
      if (kept) return kept.active
      throw new McpAuthError(401, 'invalid_token', `could not check the token with Cauthy: ${err instanceof Error ? err.message : 'unreachable'}`)
    }
    if (answers.size > 10_000) answers.clear()
    answers.set(token, { active, until: now + cacheMs })
    return active
  }

  const verify = async (from: string | Request | Headers, needs: string[] = []): Promise<AgentIdentity> => {
    const token = bearer(from)
    if (token === '') throw new McpAuthError(401, 'invalid_request', 'no access token')
    let claims: Record<string, unknown>
    try {
      const verified = await jwtVerify(token, options.jwks ?? keysOf(issuer), {
        algorithms: ['RS256'],
        issuer,
        audience: resource,
        requiredClaims: ['exp', 'sub'],
        currentDate: options.now?.(),
      })
      claims = verified.payload as Record<string, unknown>
    } catch (err) {
      throw new McpAuthError(401, 'invalid_token', err instanceof Error ? err.message : 'the token is not valid')
    }
    const clientId = typeof claims.client_id === 'string' ? claims.client_id : ''
    if (clientId === '') throw new McpAuthError(401, 'invalid_token', 'not a token issued to an agent')
    const scopes = typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : []
    if (introspect && !(await stillAllowed(token, introspect.cacheMs))) throw new McpAuthError(401, 'invalid_token', 'the token is no longer allowed: the agent was disconnected, or its access withdrawn')
    const missing = [...required, ...needs].filter((s) => !scopes.includes(s))
    if (missing.length > 0) throw new McpAuthError(403, 'insufficient_scope', `this needs ${missing.join(' ')}`)
    return {
      userId: String(claims.sub),
      tenantId: typeof claims.tid === 'string' ? claims.tid : '',
      ...(typeof claims.email === 'string' && claims.email !== '' ? { email: claims.email } : {}),
      roles: Array.isArray(claims.roles) ? claims.roles.filter((r): r is string => typeof r === 'string') : [],
      scopes,
      clientId,
      expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
      token,
      ...(isActor(claims.act) ? { actor: claims.act.sub } : {}),
    }
  }

  const clientId = options.clientId ?? env('CAUTHY_MCP_CLIENT_ID') ?? ''
  const clientSecret = options.clientSecret ?? env('CAUTHY_MCP_CLIENT_SECRET') ?? ''
  const exchanged = new Map<string, ExchangedToken & { until: number }>()
  const exchange = async (from: string | AgentIdentity, target: string, scopes: string[] = []): Promise<ExchangedToken> => {
    if (clientId === '' || clientSecret === '') {
      throw new Error('@cauthyhq/node: token exchange needs clientId and clientSecret (CAUTHY_MCP_CLIENT_ID, CAUTHY_MCP_CLIENT_SECRET)')
    }
    const subject = typeof from === 'string' ? bearer(from) : from.token
    const to = canonicalResource(target)
    const key = `${subject}\n${to}\n${scopes.join(' ')}`
    const kept = exchanged.get(key)
    if (kept && kept.until > Date.now()) return { accessToken: kept.accessToken, scopes: kept.scopes, expiresAt: kept.expiresAt }
    let res: Response
    try {
      res = await (options.fetch ?? fetch)(`${issuer}/v1/oauth/token`, {
        signal: AbortSignal.timeout(timeoutMs),
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
          authorization: `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`,
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: subject,
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          resource: to,
          ...(scopes.length > 0 ? { scope: scopes.join(' ') } : {}),
        }),
      })
    } catch (err) {
      throw new CauthyExchangeError(503, 'temporarily_unavailable', `Cauthy could not be reached: ${err instanceof Error ? err.message : 'unreachable'}`)
    }
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
    if (!res.ok || typeof body.access_token !== 'string') {
      throw new CauthyExchangeError(res.status, typeof body.error === 'string' ? body.error : 'server_error',
        typeof body.error_description === 'string' ? body.error_description : `Cauthy answered ${res.status}`)
    }
    const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0
    const out: ExchangedToken = {
      accessToken: body.access_token,
      scopes: typeof body.scope === 'string' ? body.scope.split(' ').filter(Boolean) : [],
      expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
    }
    if (exchanged.size > 10_000) exchanged.clear()
    // Kept until 30 seconds before it runs out, so it is never sent stale.
    exchanged.set(key, { ...out, until: Date.now() + Math.max(0, expiresIn - 30) * 1000 })
    return out
  }

  const authenticate = (error?: McpAuthError): string => {
    const parts = [`resource_metadata=${quoted(metadataUrl)}`]
    if (error && error.code !== 'invalid_request') {
      parts.push(`error=${quoted(error.code)}`, `error_description=${quoted(error.description)}`)
    }
    // What to ask the person for: said when there is no token or it falls short.
    const scope = error?.code === 'invalid_token' ? [] : required
    if (scope.length > 0) parts.push(`scope=${quoted(scope.join(' '))}`)
    return `Bearer ${parts.join(', ')}`
  }

  const challenge = (error?: McpAuthError): Response => {
    const status = error?.status ?? 401
    return new Response(JSON.stringify({ error: error?.code ?? 'invalid_request', error_description: error?.description ?? 'an access token is required' }), {
      status,
      headers: { 'content-type': 'application/json', 'www-authenticate': authenticate(error) },
    })
  }

  const metadataResponse = () =>
    new Response(JSON.stringify(metadata()), {
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*' },
    })

  const isMetadata = (pathname: string, method = 'GET') => method === 'GET' && metadataPaths.includes(withoutTrailingSlashes(pathname) || '/')

  const handleMetadata = (request: Request): Response | null =>
    isMetadata(new URL(request.url).pathname, request.method) ? metadataResponse() : null

  const toAuthInfo = (a: AgentIdentity): McpAuthInfo => ({
    token: a.token,
    clientId: a.clientId,
    scopes: a.scopes,
    expiresAt: Math.floor(new Date(a.expiresAt).getTime() / 1000),
    resource: new URL(resource),
    extra: { userId: a.userId, tenantId: a.tenantId, ...(a.email ? { email: a.email } : {}), roles: a.roles },
  })

  return {
    resource,
    metadataUrl,
    metadataPaths,
    metadata,
    verify,
    challenge,
    handleMetadata,
    protect(handler, needs) {
      return async (request) => {
        const meta = handleMetadata(request)
        if (meta) return meta
        let agent: AgentIdentity
        try {
          agent = await verify(request, needs)
        } catch (err) {
          if (err instanceof McpAuthError) return challenge(err)
          throw err
        }
        return handler(request, agent)
      }
    },
    exchange,
    middleware(needs) {
      return (req, res, next) => {
        const pathname = (req.originalUrl ?? req.url ?? '/').split('?')[0] ?? '/'
        if (isMetadata(pathname, req.method)) {
          res.statusCode = 200
          res.setHeader('content-type', 'application/json')
          res.setHeader('cache-control', 'public, max-age=3600')
          res.setHeader('access-control-allow-origin', '*')
          res.end(JSON.stringify(metadata()))
          return
        }
        const raw = req.headers.authorization
        const header = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '')
        verify(/^Bearer\s+/i.test(header) ? header : '', needs).then(
          (agent) => {
            req.agent = agent
            req.auth = toAuthInfo(agent)
            next()
          },
          (err: unknown) => {
            if (!(err instanceof McpAuthError)) return next(err)
            res.statusCode = err.status
            res.setHeader('content-type', 'application/json')
            res.setHeader('www-authenticate', authenticate(err))
            res.end(JSON.stringify({ error: err.code, error_description: err.description }))
          },
        )
      }
    },
  }
}
