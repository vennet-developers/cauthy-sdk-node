import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { composeKey, parseKey } from './cauthykey'
import { deriveFromKey } from './keyderive'
import { memoryKeyStore } from './keys'
import { Browser, FakeCauthy } from './testing'
import { CauthyKeyError } from './types'

const TENANT = '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b'
const SUBJECT = 'b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e'
const LINK = 'acme-crm-signs-in-with-cauthy'
const SERVICE = `pact.${LINK}.service`
const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'

/** Acme CRM's link with Cauthy, with a service block: its identity is the key's. */
function graph(issuer = 'https://id.test') {
  return {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: issuer, tenants: [{ id: TENANT, slug: 'acme', name: 'Acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
    ],
    edges: [{
      from: 'acme-crm', relation: 'links', to: 'cauthy', link: LINK,
      identity: { issuer: 'cauthy', tenant: TENANT, subject: SUBJECT },
      sign_in: { client_id: `pact.${LINK}`, redirect_uris: ['https://app.test/api/auth/callback'], system_proof: 'auto' },
      service: { client_id: SERVICE, system: 'acme-crm', jwks_url: 'https://app.test/.well-known/pact-jwks.json', import: false },
    }],
  }
}

const contract = { graph: graph(), system: 'acme-crm' }

beforeEach(() => vi.unstubAllEnvs())
afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

async function keyed(fake = new FakeCauthy()) {
  const key = await fake.issueKey(fake.issuer, { clientId: SERVICE })
  vi.stubEnv('CAUTHY_KEY', key)
  return { fake, key, auth: createCauthy({ contract, fetch: fake.fetch }) }
}

describe('key mode with a contract', () => {
  it('needs no key store: the JWKS is the key\'s public half', async () => {
    const { key, auth } = await keyed()
    const s = await deriveFromKey(parseKey(key)).signer
    const res = await auth.handler(new Request('https://app.test/.well-known/pact-jwks.json'))
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    expect(await res.json()).toEqual({ keys: [{ kty: 'OKP', crv: 'Ed25519', x: s.publicJwk.x, kid: s.kid, alg: 'EdDSA', use: 'sig' }] })
    expect(auth.pact?.contract.link).toBe(LINK)
    expect(await (await auth.pact!.jwks()).json()).toMatchObject({ keys: [{ kid: s.kid }] })
    await expect(auth.pact!.keys.rotate()).rejects.toThrow(/dashboard/)
  })

  it('signs in through pact.<link> with the proof made by the service client', async () => {
    const { fake, auth } = await keyed()
    const b = new Browser()
    const start = await auth.handler(b.request(auth.urls.signIn()))
    b.take(start)
    const to = new URL(start.headers.get('location')!)
    expect(to.searchParams.get('client_id')).toBe(`pact.${LINK}`)
    const back = new URL(fake.authorize(to.href))
    b.take(await auth.handler(b.request(back.pathname + back.search)))
    expect((await auth.getSession(b.request('/')))?.user.id).toBe('u1')
    const exchange = fake.oauthRequests.find(r => r.form.grant_type === 'authorization_code')!
    expect(exchange.form.client_id).toBe(`pact.${LINK}`)
    expect(exchange.form.client_assertion).toBeUndefined() // a public client
    expect(exchange.headers['x-cauthy-system-token']).toMatch(/^sys-/)
    const cc = fake.oauthRequests.find(r => r.form.grant_type === 'client_credentials')!
    expect(cc.form.client_id).toBe(SERVICE)
    expect(JSON.parse(Buffer.from(cc.form.client_assertion.split('.')[0], 'base64url').toString()).alg).toBe('EdDSA')
    expect(fake.calls).not.toContain('GET /v1/connect/self') // the graph is the identity
  })

  it('reads the workspace and the system from the graph, at once', async () => {
    const { auth } = await keyed()
    expect(await auth.ready()).toMatchObject({ issuer: 'https://id.test', tenant: { id: TENANT, slug: 'acme' }, system: 'acme-crm',
      sign_in_client_id: `pact.${LINK}`, contract: { link: LINK, system_proof: 'auto' } })
  })

  it('asks Cauthy its status as the service client', async () => {
    const { fake, auth } = await keyed()
    const seen: string[] = []
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(String(input))
      if (url.pathname === '/v1/pact/status') {
        seen.push(new Headers(init?.headers).get('authorization') ?? '')
        return Response.json({ data: { system: 'acme-crm', in_step: true, outside: [], missing: [] } })
      }
      return fake.fetch(input, init)
    }
    const auth2 = createCauthy({ contract, fetch })
    expect((await auth2.pact!.status()).in_step).toBe(true)
    expect(seen[0]).toMatch(/^Bearer sys-/)
    expect(auth).toBeTruthy()
  })

  it('refuses a key for another Cauthy than the graph\'s', async () => {
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey('https://other.test', { clientId: SERVICE }))
    let err: unknown
    try { createCauthy({ contract, fetch: fake.fetch }) } catch (e) { err = e }
    expect(err).toBeInstanceOf(CauthyKeyError)
    expect((err as CauthyKeyError).reason).toBe('key_contract_issuer')
  })

  it('refuses the old variables and the root key option beside the key', async () => {
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: SERVICE }))
    expect(() => createCauthy({ contract, fetch: fake.fetch, rootKey: ROOT })).toThrow(/rootKey comes from CAUTHY_KEY/)
    vi.stubEnv('CAUTHY_TENANT', 'acme')
    expect(() => createCauthy({ contract, fetch: fake.fetch })).toThrow(/CAUTHY_TENANT is also set/)
  })

  it('publishes the previous key too during a rotation', async () => {
    const { key } = await keyed()
    const k = parseKey(key)
    const previous = composeKey(k.issuer, k.clientId, 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8') // the test secret
    vi.stubEnv('CAUTHY_KEY_PREVIOUS', previous)
    const auth = createCauthy({ contract, fetch: new FakeCauthy().fetch })
    const { keys } = await (await auth.pact!.jwks()).json()
    expect(keys).toHaveLength(2)
    expect(keys.map((j: { kid: string }) => j.kid)).toEqual([
      (await deriveFromKey(k).signer).kid, (await deriveFromKey(parseKey(previous)).signer).kid,
    ])
  })

  it('keeps the legacy path: PACT_ROOT_KEY + key store, with one deprecation warning', async () => {
    const warn = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined)
    vi.stubEnv('PACT_ROOT_KEY', ROOT)
    const auth = createCauthy({ contract, keys: memoryKeyStore(), fetch: new FakeCauthy().fetch })
    createCauthy({ contract, keys: memoryKeyStore(), fetch: new FakeCauthy().fetch })
    const res = await auth.handler(new Request('https://app.test/.well-known/pact-jwks.json'))
    expect((await res.json()).keys[0]).toMatchObject({ alg: 'RS256' })
    const told = warn.mock.calls.filter(c => String(c[0]).includes('PACT_ROOT_KEY'))
    expect(told).toHaveLength(1)
    expect(told[0][1]).toMatchObject({ type: 'DeprecationWarning', code: 'CAUTHY_DEPRECATED' })
    expect(String(told[0][0])).toContain('CAUTHY_KEY')
  })
})
