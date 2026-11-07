import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { failClosed, readContract } from './contract'
import { memoryKeyStore, pactKeys, pactKeysTableSql, postgresKeyStore, RETIRE_AFTER_MS, SIGN_AFTER_MS, type StoredKey } from './keys'
import { fileKeyStore } from './keystores'
import { deriveKeys } from './rootkey'
import { Browser, FakeCauthy } from './testing'
import { CauthyConfigError } from './types'
import { memoryReplayStore } from './webhook'

const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'
const TENANT = '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b'
const SUBJECT = 'b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e'

/** The context graph, with Acme CRM signing in with Cauthy and acting in it by its own key. */
function graph(over: { service?: boolean; links?: number; slug?: boolean; jwks?: string } = {}) {
  const link = (n: number) => ({
    from: 'acme-crm', relation: 'links', to: 'cauthy', link: n === 0 ? 'acme-crm-signs-in-with-cauthy' : `acme-crm-other-${n}`,
    identity: { issuer: 'cauthy', tenant: TENANT, subject: SUBJECT },
    sign_in: { client_id: n === 0 ? 'pact.acme-crm-signs-in-with-cauthy' : `pact.acme-crm-other-${n}`,
      redirect_uris: ['https://app.test/api/auth/callback'], require_system_proof: false },
    ...(over.service === false ? {} : {
      service: { client_id: 'pact.acme-crm-signs-in-with-cauthy.service', system: 'acme-crm', jwks_url: over.jwks ?? 'https://app.test/.well-known/pact-jwks.json', import: false },
    }),
  })
  return {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: 'https://id.test', tenants: over.slug === false ? [] : [{ id: TENANT, slug: 'acme', name: 'Acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test', events_url: 'https://app.test/api/cauthy/events', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
    ],
    edges: Array.from({ length: over.links ?? 1 }, (_, n) => link(n)),
  }
}

const contract = { graph: graph(), system: 'acme-crm' }

beforeEach(() => vi.useFakeTimers({ now: new Date('2026-11-03T12:00:00Z'), toFake: ['Date'] }))
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

describe('reading the contract', () => {
  it('reads everything the application needs from its link', () => {
    expect(readContract(contract)).toEqual({
      system: 'acme-crm', link: 'acme-crm-signs-in-with-cauthy', issuer: 'https://id.test', tenantId: TENANT, tenant: 'acme',
      clientId: 'pact.acme-crm-signs-in-with-cauthy', redirectUris: ['https://app.test/api/auth/callback'], requireSystemProof: false, persistentSessions: false,
      systemProof: 'off', requireVerifiedEmail: false,
      serviceClientId: 'pact.acme-crm-signs-in-with-cauthy.service',
      jwksUrl: 'https://app.test/.well-known/pact-jwks.json', jwksPath: '/.well-known/pact-jwks.json',
      eventsUrl: 'https://app.test/api/cauthy/events',
    })
    // A JSON module imported with `import graph from './graph.json'` comes as its default.
    expect(readContract({ graph: { default: graph() }, system: 'acme-crm' }).clientId).toBe('pact.acme-crm-signs-in-with-cauthy')
  })

  it('reads whether the link lets its people stay signed in', () => {
    const g = graph()
    ;(g.edges[0].sign_in as Record<string, unknown>).persistent_sessions = true
    expect(readContract({ graph: g, system: 'acme-crm' }).persistentSessions).toBe(true)
  })

  it('says what is wrong with it', () => {
    expect(() => readContract({ graph: {}, system: 'acme-crm' })).toThrow(/not a context graph/)
    expect(() => readContract({ graph: graph(), system: 'clinic' })).toThrow(/no system "clinic"/)
    expect(() => readContract({ graph: { ...graph(), edges: [] }, system: 'acme-crm' })).toThrow(/no link of the graph signs/)
    expect(() => readContract({ graph: graph({ links: 2 }), system: 'acme-crm' })).toThrow(/2 links .*contract.link/)
    expect(readContract({ graph: graph({ links: 2 }), system: 'acme-crm', link: 'acme-crm-other-1' }).clientId).toBe('pact.acme-crm-other-1')
    expect(() => readContract({ graph: graph({ slug: false }), system: 'acme-crm' })).toThrow(/slug of the workspace/)
    expect(() => readContract({ graph: graph({ jwks: 'http://app.test/jwks.json' }), system: 'acme-crm' })).toThrow(/must be https/)
  })
})

describe('failing closed', () => {
  it('refuses to run by contract with a variable of the standard mode set, and names it', () => {
    expect(() => failClosed({ CAUTHY_CLIENT_ID: 'client_x', CAUTHY_BASE_URL: 'https://app.test' })).toThrow(/CAUTHY_CLIENT_ID is also set/)
    expect(() => failClosed({ CAUTHY_CLIENT_SECRET: 's', CAUTHY_TENANT: 'acme' })).toThrow(/CAUTHY_CLIENT_SECRET, CAUTHY_TENANT are also set/)
    expect(() => failClosed({ CAUTHY_BASE_URL: 'https://app.test', CAUTHY_CLIENT_ID: '' })).not.toThrow()

    vi.stubEnv('CAUTHY_SYSTEM_KEY', '{"kty":"RSA"}')
    expect(() => createCauthy({ contract, keys: memoryKeyStore(), rootKey: ROOT })).toThrow(/CAUTHY_SYSTEM_KEY is also set/)
  })

  it('takes nothing the contract says from anywhere else', () => {
    expect(() => createCauthy({ contract, keys: memoryKeyStore(), rootKey: ROOT, clientId: 'client_x' })).toThrow(/clientId comes from the contract/)
    expect(() => createCauthy({ contract, keys: memoryKeyStore(), rootKey: ROOT, secret: 'x'.repeat(40) })).toThrow(/secret comes from the contract/)
    expect(() => createCauthy({ contract, keys: memoryKeyStore() })).toThrow(/PACT_ROOT_KEY/)
    expect(() => createCauthy({ contract, keys: memoryKeyStore(), rootKey: 'short' })).toThrow(/at least 32/)
    expect(() => createCauthy({ contract, rootKey: ROOT })).toThrow(/pass keys/)
    // A link with no service block needs no keys.
    expect(() => createCauthy({ contract: { graph: graph({ service: false }), system: 'acme-crm' }, rootKey: ROOT })).not.toThrow()
  })

  it('reads the root key from PACT_ROOT_KEY', () => {
    vi.stubEnv('PACT_ROOT_KEY', ROOT)
    expect(createCauthy({ contract, keys: memoryKeyStore() }).options.clientId).toBe('pact.acme-crm-signs-in-with-cauthy')
  })
})

/** A contracted application against a fake Cauthy that also answers the system's own token. */
function contracted(store = memoryKeyStore(), extra: Record<string, unknown> = {}) {
  const cauthy = new FakeCauthy()
  const assertions: string[] = []
  const statusAsked: string[] = []
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''))
    if (url.pathname === '/v1/oauth/token' && form.get('grant_type') === 'client_credentials') {
      assertions.push(`${form.get('client_id')} ${form.get('client_assertion')}`)
      return new Response(JSON.stringify({ access_token: 'the-system-token', token_type: 'Bearer', expires_in: 600 }), { status: 200 })
    }
    if (url.pathname === '/v1/pact/status') {
      statusAsked.push(`${new Headers(init?.headers).get('authorization')} ${url.search}`)
      return new Response(JSON.stringify({ data: { system: 'acme-crm', in_step: true, outside: [], missing: [] } }), { status: 200 })
    }
    return cauthy.fetch(input, init)
  }
  const auth = createCauthy({ contract, keys: store, rootKey: ROOT, fetch, ...extra })
  return { cauthy, auth, store, assertions, statusAsked }
}

describe('running by contract', () => {
  it('signs people in through the client its link names, and keeps them signed in', async () => {
    const { cauthy, auth } = contracted()
    const browser = new Browser()
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(start)
    const to = new URL(start.headers.get('location')!)
    expect(to.origin).toBe('https://id.test')
    expect(to.searchParams.get('client_id')).toBe('pact.acme-crm-signs-in-with-cauthy')
    const back = new URL(cauthy.authorize(to.href))
    browser.take(await auth.handler(browser.request(back.pathname + back.search)))
    expect((await auth.getSession(browser.request('/')))?.user.id).toBe('u1')
  })

  it('keeps the cache of the published keys for GET and HEAD only', async () => {
    const { auth } = contracted()
    const url = 'https://app.test/.well-known/pact-jwks.json'
    expect((await auth.handler(new Request(url, { method: 'HEAD' }))).headers.get('cache-control')).toContain('max-age=300')
    const post = await auth.handler(new Request(url, { method: 'POST', body: '{}' }))
    expect(post.status).toBe(404)
    expect(post.headers.get('cache-control')).toBe('no-store')
  })

  it('makes its key once, serves its public half at its jwks_url and proves itself with it', async () => {
    const { auth, store, assertions, statusAsked } = contracted()
    const res = await auth.handler(new Request('https://app.test/.well-known/pact-jwks.json'))
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toContain('max-age=300')
    const jwks = (await res.json()) as { keys: { kid: string; d?: string; alg: string; use: string }[] }
    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0]).toMatchObject({ alg: 'RS256', use: 'sig' })
    expect(jwks.keys[0].d).toBeUndefined()
    const kept = await store.list()
    expect(kept).toHaveLength(1)
    expect(kept[0].kid).toBe(jwks.keys[0].kid)
    // Nothing private is kept in the clear.
    expect(JSON.stringify(kept[0])).not.toContain('"d"')

    await auth.system.token()
    const [client, assertion] = assertions[0].split(' ')
    expect(client).toBe('pact.acme-crm-signs-in-with-cauthy.service')
    expect(decodeProtectedHeader(assertion).kid).toBe(jwks.keys[0].kid)
    const { payload } = await jwtVerify(assertion, createLocalJWKSet(jwks as never), { audience: 'https://id.test/v1/oauth/token' })
    expect(payload.iss).toBe('pact.acme-crm-signs-in-with-cauthy.service')
    expect(await store.list()).toHaveLength(1)

    // Its standing against the contract, with its own token.
    expect((await auth.pact!.status()).in_step).toBe(true)
    expect(statusAsked).toEqual(['Bearer the-system-token ?system=acme-crm'])
  })

  it('sends its proof on the code exchange', async () => {
    const { cauthy, auth } = contracted()
    const exchanges: Headers[] = []
    const seen = cauthy.fetch
    cauthy.fetch = async (input, init) => {
      const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : String(init?.body ?? ''))
      if (form.get('grant_type') === 'authorization_code') exchanges.push(new Headers(init?.headers))
      return seen(input, init)
    }
    const browser = new Browser()
    const start = await auth.handler(browser.request(auth.urls.signIn()))
    browser.take(start)
    const back = new URL(cauthy.authorize(start.headers.get('location')!))
    await auth.handler(browser.request(back.pathname + back.search))
    expect(exchanges[0].get('x-cauthy-system-token')).toBe('the-system-token')
  })

  it('rotates: the new key is published at once, signs once no cached copy can miss it, and the old one stays published a day', async () => {
    const { auth } = contracted()
    const keys = auth.pact!.keys
    const first = (await keys.current()).kid
    const second = await keys.rotate()
    expect((await keys.published()).keys.map(k => k.kid).sort()).toEqual([first, second].sort())
    expect((await keys.current()).kid).toBe(first)
    vi.setSystemTime(Date.now() + SIGN_AFTER_MS + 1000)
    expect((await keys.current()).kid).toBe(second)
    expect((await keys.published()).keys.map(k => k.kid).sort()).toEqual([first, second].sort())
    vi.setSystemTime(Date.now() + RETIRE_AFTER_MS + 1000)
    expect((await keys.published()).keys.map(k => k.kid)).toEqual([second])
  })

  it('reads a session sealed with the previous root key while it rotates, and seals its key again', async () => {
    const store = memoryKeyStore()
    const before = contracted(store)
    const browser = new Browser()
    const start = await before.auth.handler(browser.request(before.auth.urls.signIn()))
    browser.take(start)
    const back = new URL(before.cauthy.authorize(start.headers.get('location')!))
    browser.take(await before.auth.handler(browser.request(back.pathname + back.search)))
    const kid = (await before.auth.pact!.keys.current()).kid

    const NEW = 'another-root-key-of-thirty-two-random-bytes'
    const during = createCauthy({ contract, keys: store, rootKey: NEW, rootKeyPrevious: ROOT, fetch: before.cauthy.fetch })
    expect((await during.getSession(browser.request('/')))?.user.id).toBe('u1')
    expect(await during.pact!.keys.reseal()).toBe(1)
    expect(await during.pact!.keys.reseal()).toBe(0)

    // Without the previous root, the session is gone and the resealed key still opens.
    const after = createCauthy({ contract, keys: store, rootKey: NEW, fetch: before.cauthy.fetch })
    expect(await after.getSession(browser.request('/'))).toBeNull()
    expect((await after.pact!.keys.current()).kid).toBe(kid)
  })

  it('keeps one key per purpose: the cookie key never opens the sealed private key', async () => {
    const d = deriveKeys(ROOT)
    const [seal, cookie, flow] = await Promise.all([d.seal, d.cookie, d.flow])
    expect(Buffer.from(seal[0]).equals(Buffer.from(cookie[0]))).toBe(false)
    expect(Buffer.from(cookie[0]).equals(Buffer.from(flow[0]))).toBe(false)
    const store = memoryKeyStore()
    await pactKeys(store, Promise.resolve(seal)).current()
    await expect(pactKeys(store, Promise.resolve(cookie)).current()).rejects.toThrow(/cannot be opened/)
  })
})

describe('the first key', () => {
  it('is made once when instances start together, with a store that keeps only the first', async () => {
    const store = memoryKeyStore()
    const seal = deriveKeys(ROOT).seal
    const kids = await Promise.all([1, 2, 3].map(() => pactKeys(store, seal).current().then(k => k.kid)))
    expect((await store.list()).length).toBe(1)
    expect(new Set(kids).size).toBe(1)
  })

  it('is the same on every instance within seconds, with a store that may keep several', async () => {
    const { addFirst: _, ...plain } = memoryKeyStore()
    const seal = deriveKeys(ROOT).seal
    const instances = [1, 2, 3].map(() => pactKeys(plain, seal))
    await Promise.all(instances.map(k => k.current()))
    const kept = await plain.list()
    vi.setSystemTime(Date.now() + 6000)
    const kids = await Promise.all(instances.map(k => k.current().then(c => c.kid)))
    expect(new Set(kids).size).toBe(1)
    // Every key made in the race is published, so whichever signed verifies.
    const published = (await instances[0].published()).keys.map(k => k.kid).sort()
    expect(published).toEqual(kept.map(k => k.kid).sort())
  })
})

describe('key stores', () => {
  it('postgresKeyStore speaks plain SQL through the application\'s own client', async () => {
    const calls: [string, unknown[]][] = []
    const rows: Record<string, unknown>[] = []
    const store = postgresKeyStore(async (text, params) => {
      calls.push([text, params])
      if (text.startsWith('INSERT')) rows.push({ kid: params[0], public_jwk: JSON.parse(params[1] as string), sealed: params[2], created_at: new Date(params[3] as string) })
      return text.startsWith('SELECT') ? { rows } : []
    }, { table: 'pact_keys' })
    const key: StoredKey = { kid: 'k1', publicJwk: { kty: 'RSA', n: 'n', e: 'AQAB' }, sealed: 'sealed', createdAt: '2026-11-03T12:00:00.000Z' }
    await store.add(key)
    expect(await store.list()).toEqual([key])
    await store.update({ ...key, sealed: 'again' })
    await store.remove('k1')
    expect(calls.map(c => c[0].split(' ').slice(0, 3).join(' '))).toEqual([
      'INSERT INTO pact_keys', 'SELECT kid, public_jwk,', 'UPDATE pact_keys SET', 'DELETE FROM pact_keys'])
    await store.addFirst!({ ...key, kid: 'k2' })
    expect(calls.at(-1)![0]).toContain('WHERE NOT EXISTS (SELECT 1 FROM pact_keys)')
    expect(pactKeysTableSql('pact_keys')).toContain('CREATE TABLE IF NOT EXISTS pact_keys')
    expect(() => postgresKeyStore(async () => [], { table: 'keys; DROP TABLE users' })).toThrow(CauthyConfigError)
  })

  it('fileKeyStore keeps them in a file only its owner reads', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cauthy-keys-'))
    try {
      const path = join(dir, 'nested', 'keys.json')
      const store = fileKeyStore(path)
      expect(await store.list()).toEqual([])
      const keys = pactKeys(store, deriveKeys(ROOT).seal)
      const kid = (await keys.current()).kid
      expect(JSON.parse(readFileSync(path, 'utf8'))[0].kid).toBe(kid)
      expect(statSync(path).mode & 0o777).toBe(0o600)
      expect((await pactKeys(fileKeyStore(path), deriveKeys(ROOT).seal).current()).kid).toBe(kid)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('deliveries taken once', () => {
  it('claims a delivery once until it expires', async () => {
    let t = Date.parse('2026-11-03T12:00:00Z')
    const replay = memoryReplayStore(() => t)
    const until = new Date(t + 300_000)
    expect(await replay.claim('d1:100', until)).toBe(true)
    expect(await replay.claim('d1:100', until)).toBe(false)
    // Sent again by Cauthy: signed again, another moment.
    expect(await replay.claim('d1:160', until)).toBe(true)
    t += 301_000
    expect(await replay.claim('d1:100', new Date(t + 300_000))).toBe(true)
  })
})

describe('the link fields core-contracts added in November 2026', () => {
  const bySlug = (identity: Record<string, unknown>) => {
    const g = graph()
    g.edges[0].identity = { issuer: 'cauthy', tenant: 'acme', subject: SUBJECT, tenant_id: TENANT, ...identity } as (typeof g)['edges'][number]['identity']
    return { graph: g, system: 'acme-crm' }
  }

  it('reads a workspace named by its slug and pinned by tenant_id', () => {
    expect(readContract(bySlug({}))).toMatchObject({ tenant: 'acme', tenantId: TENANT })
  })

  it('refuses a slug the graph has not pinned yet, and says what to do', () => {
    expect(() => readContract(bySlug({ tenant_id: undefined, create_tenant: true }))).toThrow(/new workspace "acme".*pull the graph again/)
    expect(() => readContract(bySlug({ tenant_id: undefined }))).toThrow(/carries no tenant_id/)
  })

  it('refuses the nil UUID', () => {
    expect(() => readContract(bySlug({ tenant: '00000000-0000-0000-0000-000000000000', tenant_id: undefined }))).toThrow(/nil UUID/)
  })

  it('reads system_proof and require_verified_email', () => {
    const g = graph()
    Object.assign(g.edges[0].sign_in, { require_system_proof: false, system_proof: 'auto', require_verified_email: true })
    expect(readContract({ graph: g, system: 'acme-crm' })).toMatchObject({ systemProof: 'auto', requireSystemProof: false, requireVerifiedEmail: true })
  })

  it('derives system_proof from the boolean in a graph from before it', () => {
    const g = graph()
    Object.assign(g.edges[0].sign_in, { require_system_proof: true })
    expect(readContract({ graph: g, system: 'acme-crm' })).toMatchObject({ systemProof: 'required', requireSystemProof: true })
  })

  it('refuses a proof the link gives no identity to make', () => {
    const g = graph({ service: false })
    Object.assign(g.edges[0].sign_in, { system_proof: 'auto' })
    expect(() => readContract({ graph: g, system: 'acme-crm' })).toThrow(/needs a service block/)
  })
})
