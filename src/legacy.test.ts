// Moving to CAUTHY_KEY: rotation with CAUTHY_KEY_PREVIOUS, old sessions read
// while an application moves off CAUTHY_SECRET or PACT_ROOT_KEY, and the one
// warning each old way of configuring gives. Each test loads the modules
// afresh: a deprecation is said once per process, and here once per test.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseKey } from './cauthykey'
import { deriveFromKey } from './keyderive'
import { deriveKeys } from './rootkey'
import { keyOf, seal, unsealAny } from './seal'
import { Browser, FakeCauthy } from './testing'

const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'
const SECRET = 'a-cauthy-secret-of-thirty-two-characters-or-more'
const TENANT = '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b'
const LINK = 'acme-crm-signs-in-with-cauthy'
const SERVICE = `pact.${LINK}.service`

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

async function fresh() {
  vi.resetModules()
  const warn = vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined)
  const { createCauthy } = await import('./cauthy')
  const { createTokenVerifier } = await import('./verify')
  const told = (part: string) => warn.mock.calls.filter(c => String(c[0]).includes(part))
  return { createCauthy, createTokenVerifier, warn, told }
}

/** A session cookie as an application sealed it with `key`. */
async function cookieWith(key: Uint8Array): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + 600
  const stored = { at: 'at-old', rt: 'rt-old', exp, u: { id: 'u-old', email: 'ana@acme.com', name: 'Ana', emailVerified: true, restricted: false }, tid: 't1', roles: [] }
  return `cauthy_session.0=${await seal(stored, key)}`
}

const asBrowser = (cookie: string) => new Request('http://localhost:3000/', { headers: { cookie } })

function graph() {
  return {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: 'https://id.test', tenants: [{ id: TENANT, slug: 'acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
    ],
    edges: [{
      from: 'acme-crm', relation: 'links', to: 'cauthy', link: LINK,
      identity: { issuer: 'cauthy', tenant: TENANT, subject: 'b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e' },
      sign_in: { client_id: `pact.${LINK}`, redirect_uris: ['https://app.test/api/auth/callback'] },
      service: { client_id: SERVICE, system: 'acme-crm', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
    }],
  }
}

describe('moving to CAUTHY_KEY', () => {
  it('reads a session of the previous key during a rotation, and writes with the new one only', async () => {
    const { createCauthy } = await fresh()
    const fake = new FakeCauthy()
    const before = await fake.issueKey()
    const now = await fake.issueKey()
    vi.stubEnv('CAUTHY_KEY', now)
    vi.stubEnv('CAUTHY_KEY_PREVIOUS', before)
    const auth = createCauthy({ fetch: fake.fetch })
    const old = await cookieWith((await deriveFromKey(parseKey(before)).cookie)[0])
    expect((await auth.getSession(asBrowser(old)))?.user.id).toBe('u-old')

    const b = new Browser('http://localhost:3000')
    const login = await auth.handler(b.request('/api/auth/login'))
    b.take(login)
    const back = new URL(fake.authorize(login.headers.get('location')!))
    b.take(await auth.handler(b.request(back.pathname + back.search)))
    const sealed = b.jar.get('cauthy_session.0')!
    expect(await unsealAny(sealed, await deriveFromKey(parseKey(now)).cookie)).not.toBeNull()
    expect(await unsealAny(sealed, await deriveFromKey(parseKey(before)).cookie)).toBeNull()
  })

  it('refuses a previous key of another client', async () => {
    const { createCauthy } = await fresh()
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    vi.stubEnv('CAUTHY_KEY_PREVIOUS', await fake.issueKey(fake.issuer, { clientId: 'another-client' }))
    expect(() => createCauthy({ fetch: fake.fetch })).toThrow(/key_previous_mismatch/)
    vi.stubEnv('CAUTHY_KEY_PREVIOUS', 'cs_not_a_key')
    expect(() => createCauthy({ fetch: fake.fetch })).toThrow(/CAUTHY_KEY_PREVIOUS is refused.*key_format/)
  })

  it('reads a session sealed with CAUTHY_SECRET beside the key, and says to remove it', async () => {
    const { createCauthy, told } = await fresh()
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    vi.stubEnv('CAUTHY_SECRET', SECRET)
    const auth = createCauthy({ fetch: fake.fetch })
    createCauthy({ fetch: fake.fetch })
    expect((await auth.getSession(asBrowser(await cookieWith(await keyOf(SECRET)))))?.user.id).toBe('u-old')
    expect(told('CAUTHY_SECRET beside CAUTHY_KEY')).toHaveLength(1)
    expect(String(told('CAUTHY_SECRET beside CAUTHY_KEY')[0][0])).toContain('rotation window')
    // Never written with: a new cookie opens with the key alone.
    expect(await unsealAny(await cookieWith((await deriveFromKey(parseKey(process.env.CAUTHY_KEY!)).cookie)[0]).then(c => c.slice('cauthy_session.0='.length)),
      [await keyOf(SECRET)])).toBeNull()
  })

  it('reads a session sealed with PACT_ROOT_KEY beside the key and a contract, and keeps its RS256 keys published', async () => {
    const { createCauthy, told } = await fresh()
    const { memoryKeyStore } = await import('./keys')
    const fake = new FakeCauthy()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: SERVICE }))
    vi.stubEnv('PACT_ROOT_KEY', ROOT)
    const auth = createCauthy({ contract: { graph: graph(), system: 'acme-crm' }, keys: memoryKeyStore(), fetch: fake.fetch })
    const old = await cookieWith((await deriveKeys(ROOT).cookie)[0])
    expect((await auth.getSession(new Request('https://app.test/', { headers: { cookie: old } })))?.user.id).toBe('u-old')
    expect(told('PACT_ROOT_KEY beside CAUTHY_KEY')).toHaveLength(1)
    const { keys } = await (await auth.handler(new Request('https://app.test/.well-known/pact-jwks.json'))).json()
    expect(keys.map((k: { alg: string }) => k.alg)).toEqual(['EdDSA', 'RS256'])
    // The system still proves itself with the key's Ed25519 half.
    await auth.system.token()
    const cc = fake.oauthRequests.find(r => r.form.grant_type === 'client_credentials')!
    expect(JSON.parse(Buffer.from(cc.form.client_assertion.split('.')[0], 'base64url').toString()).alg).toBe('EdDSA')
  })

  it('warns once per process in variables mode, naming CAUTHY_KEY', async () => {
    const { createCauthy, told } = await fresh()
    vi.stubEnv('CAUTHY_ISSUER', 'https://id.test')
    vi.stubEnv('CAUTHY_CLIENT_ID', 'acme-crm')
    vi.stubEnv('CAUTHY_SECRET', SECRET)
    createCauthy()
    createCauthy()
    const said = told('CAUTHY_KEY')
    expect(said).toHaveLength(1)
    expect(said[0][1]).toMatchObject({ type: 'DeprecationWarning', code: 'CAUTHY_DEPRECATED' })
    expect(String(said[0][0])).toContain('CAUTHY_ISSUER')
  })

  it('warns once when a verifier reads CAUTHY_AUDIENCE and the rest from the environment', async () => {
    const { createTokenVerifier, told } = await fresh()
    vi.stubEnv('CAUTHY_ISSUER', 'https://id.test')
    vi.stubEnv('CAUTHY_AUDIENCE', 'https://id.test')
    vi.stubEnv('CAUTHY_TENANT_ID', TENANT)
    createTokenVerifier()
    createTokenVerifier()
    expect(told('CAUTHY_AUDIENCE')).toHaveLength(1)
    // Given in code, nothing is said.
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    const again = await fresh()
    again.createTokenVerifier({ issuer: 'https://id.test', audience: 'https://id.test', tenantId: TENANT })
    expect(again.told('CAUTHY_AUDIENCE')).toHaveLength(0)
  })
})

