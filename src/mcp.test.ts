import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { CauthyExchangeError, McpAuthError, canonicalResource, mcpAuth } from './mcp'

const issuer = 'https://cauthy.example.com'
const resource = 'https://mcp.example.com/mcp'
let sign: (claims: Record<string, unknown>, over?: { audience?: string; expiresIn?: string }) => Promise<string>
let jwks: ReturnType<typeof createLocalJWKSet>

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256' }] })
  sign = (claims, over = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(issuer)
      .setAudience(over.audience ?? resource)
      .setIssuedAt()
      .setExpirationTime(over.expiresIn ?? '10m')
      .sign(pair.privateKey as CryptoKey)
})

const agent = { sub: 'u-1', tid: 't-1', email: 'ana@acme.com', roles: ['member'], scope: 'books:read', client_id: 'agt_1' }
const bearer = (token: string) => new Request(`${resource}`, { method: 'POST', headers: { authorization: `Bearer ${token}` } })

describe('an MCP server protected with Cauthy', () => {
  it('publishes where to sign in (RFC 9728), at its path and at the root', async () => {
    const auth = mcpAuth({ resource: 'https://MCP.example.com/mcp/', issuer: `${issuer}/`, scopes: ['books:read'], resourceName: 'Books', jwks })
    expect(auth.resource).toBe(resource)
    expect(auth.metadataUrl).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp')
    expect(auth.metadataPaths).toEqual(['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource'])
    const res = auth.handleMetadata(new Request('https://mcp.example.com/.well-known/oauth-protected-resource/mcp'))
    expect(await res?.json()).toEqual({ resource, authorization_servers: [issuer], bearer_methods_supported: ['header'], scopes_supported: ['books:read'], resource_name: 'Books' })
    expect(auth.handleMetadata(new Request('https://mcp.example.com/.well-known/oauth-protected-resource'))).not.toBeNull()
    expect(auth.handleMetadata(new Request(resource))).toBeNull()
  })

  it('answers 401 pointing at the metadata, then lets a good token through', async () => {
    const auth = mcpAuth({ resource, issuer, scopes: ['books:read'], jwks })
    const handler = auth.protect((_req, who) => Response.json({ who: who.userId, scopes: who.scopes, agent: who.clientId }))
    const none = await handler(new Request(resource, { method: 'POST' }))
    expect(none.status).toBe(401)
    expect(none.headers.get('www-authenticate')).toBe('Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="books:read"')
    const ok = await handler(bearer(await sign(agent)))
    expect(await ok.json()).toEqual({ who: 'u-1', scopes: ['books:read'], agent: 'agt_1' })
  })

  it('refuses a token for another server, a person\'s own, an expired one, or one short of a scope', async () => {
    const auth = mcpAuth({ resource, issuer, jwks })
    const refused = async (token: string, status: number, code: string, needs?: string[]) => {
      const err = await auth.verify(bearer(token), needs).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(McpAuthError)
      expect(err).toMatchObject({ status, code })
    }
    await refused(await sign(agent, { audience: 'https://other.example.com' }), 401, 'invalid_token')
    await refused(await sign(agent, { audience: 'cauthy-api' }), 401, 'invalid_token')
    await refused(await sign({ ...agent, client_id: undefined }), 401, 'invalid_token')
    await refused(await sign(agent, { expiresIn: '-1m' }), 401, 'invalid_token')
    await refused(await sign(agent), 403, 'insufficient_scope', ['books:write'])
    const challenge = auth.challenge(new McpAuthError(403, 'insufficient_scope', 'this needs books:write'))
    expect(challenge.status).toBe(403)
    expect(challenge.headers.get('www-authenticate')).toContain('error="insufficient_scope"')
    expect((await auth.verify(bearer(await sign(agent)))).email).toBe('ana@acme.com')
  })

  it('is Express-style middleware too, setting req.auth for the MCP SDK', async () => {
    const auth = mcpAuth({ resource, issuer, jwks })
    const run = (req: any) =>
      new Promise<{ status: number; headers: Record<string, string>; body?: string; next: boolean }>((done) => {
        const res = { statusCode: 200, headers: {} as Record<string, string>, setHeader(n: string, v: string) { this.headers[n] = v }, end(body?: string) { done({ status: this.statusCode, headers: this.headers, body, next: false }) } }
        auth.middleware()(req, res, () => done({ status: 0, headers: {}, next: true }))
      })
    const meta = await run({ method: 'GET', url: '/.well-known/oauth-protected-resource/mcp', headers: {} })
    expect(JSON.parse(meta.body ?? '{}').resource).toBe(resource)
    const none = await run({ method: 'POST', url: '/mcp', headers: { authorization: 'Basic abc' } })
    expect(none.status).toBe(401)
    expect(none.headers['www-authenticate']).toContain('resource_metadata=')
    const req: any = { method: 'POST', url: '/mcp', headers: { authorization: `Bearer ${await sign(agent)}` } }
    expect((await run(req)).next).toBe(true)
    expect(req.auth).toMatchObject({ clientId: 'agt_1', scopes: ['books:read'], extra: { userId: 'u-1', tenantId: 't-1' } })
    expect(req.auth.resource.href).toBe(resource)
  })

  it('asks Cauthy whether the person still allows the agent, when told to', async () => {
    let active = true
    let calls = 0
    const fake = (async (_url: string, init: RequestInit) => {
      calls++
      expect(String(init.body)).toMatch(/^token=/)
      return Response.json({ active })
    }) as unknown as typeof fetch
    const auth = mcpAuth({ resource, issuer, jwks, introspect: { cacheSeconds: 0 }, fetch: fake })
    const token = await sign(agent)
    expect((await auth.verify(bearer(token))).userId).toBe('u-1')
    active = false
    await expect(auth.verify(bearer(token))).rejects.toMatchObject({ status: 401, code: 'invalid_token' })
    expect(calls).toBe(2)
    const cached = mcpAuth({ resource, issuer, jwks, introspect: true, fetch: fake })
    active = true
    await cached.verify(bearer(token))
    await cached.verify(bearer(token))
    expect(calls).toBe(3)
  })

  it('trades the agent\'s token for one for another of the workspace\'s servers (RFC 8693)', async () => {
    const seen: { url: string; auth: string; body: URLSearchParams }[] = []
    let answer: () => Response = () => Response.json({ access_token: 'xt-1', token_type: 'Bearer', expires_in: 300, scope: 'orders:read', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' })
    const fake = (async (url: string, init: RequestInit) => {
      seen.push({ url, auth: String((init.headers as Record<string, string>).authorization), body: new URLSearchParams(String(init.body)) })
      return answer()
    }) as unknown as typeof fetch
    const auth = mcpAuth({ resource, issuer, jwks, fetch: fake, clientId: 'rsc_1', clientSecret: 'rss_s' })
    const who = await auth.verify(bearer(await sign(agent)))

    const out = await auth.exchange(who, 'https://API.example.com/', ['orders:read'])
    expect(out.accessToken).toBe('xt-1')
    expect(out.scopes).toEqual(['orders:read'])
    expect(seen[0]?.url).toBe(`${issuer}/v1/oauth/token`)
    expect(seen[0]?.auth).toBe(`Basic ${btoa('rsc_1:rss_s')}`)
    expect(Object.fromEntries(seen[0]?.body ?? [])).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: who.token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      resource: 'https://api.example.com',
      scope: 'orders:read',
    })
    // Kept: the same exchange again does not call Cauthy.
    await auth.exchange(who.token, 'https://api.example.com', ['orders:read'])
    expect(seen).toHaveLength(1)

    answer = () => Response.json({ error: 'invalid_target', error_description: 'not delegated' }, { status: 400 })
    await expect(auth.exchange(who, 'https://other.example.com')).rejects.toBeInstanceOf(CauthyExchangeError)
    await expect(auth.exchange(who, 'https://other.example.com')).rejects.toMatchObject({ status: 400, code: 'invalid_target' })
    await expect(mcpAuth({ resource, issuer, jwks }).exchange(who, 'https://api.example.com')).rejects.toThrow(/clientId/)
  })

  it('says who acts, on a token that came by exchange', async () => {
    const auth = mcpAuth({ resource, issuer, jwks })
    const who = await auth.verify(bearer(await sign({ ...agent, act: { sub: 'https://front.example.com/mcp' } })))
    expect(who.actor).toBe('https://front.example.com/mcp')
    expect((await auth.verify(bearer(await sign(agent)))).actor).toBeUndefined()
  })

  it('takes its address in Cauthy\'s form, and refuses one that is not https', () => {
    expect(canonicalResource('https://MCP.example.com:443/')).toBe('https://mcp.example.com')
    expect(canonicalResource('http://localhost:3000/mcp/')).toBe('http://localhost:3000/mcp')
    expect(() => canonicalResource('http://mcp.example.com')).toThrow()
    expect(() => canonicalResource('https://mcp.example.com/?x=1')).toThrow()
    expect(() => mcpAuth({ issuer })).toThrow(/CAUTHY_MCP_RESOURCE/)
  })
})
