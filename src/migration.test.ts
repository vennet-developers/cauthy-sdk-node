// Moving to CAUTHY_KEY, end to end with the packages applications move from:
// cauthy-auth 0.41.0 and 0.42.0 by contract (PACT_ROOT_KEY, keys), and
// @cauthyhq/node 1.1.0 on the variables (CAUTHY_SECRET). Each signs a person
// in through FakeCauthy and keeps the cookie it sealed; 1.2 then reads it at
// GET <basePath>/session with CAUTHY_KEY and the old secret beside it, and
// seals it again with the key, so it outlives the old secret.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseKey } from './cauthykey'
import { deriveFromKey } from './keyderive'
import { deriveKeys } from './rootkey'
import { keyOf, unsealAny } from './seal'
import { Browser, FakeCauthy } from './testing'

const TENANT = '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b'
const LINK = 'acme-crm-signs-in-with-cauthy'
const SERVICE = `pact.${LINK}.service`
const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'
const OLDER_ROOT = 'the-root-key-before-it-thirty-two-bytes-456'
const SECRET = 'a-cauthy-secret-of-thirty-two-characters-or-more'
const BASE = '/api/id'

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

/** Acme CRM's link with Cauthy, as an application that signs people in on its own screens has it. */
function graph() {
  return {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: 'https://id.test', tenants: [{ id: TENANT, slug: 'acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test', jwks_url: 'https://app.test/api/pact/jwks.json' },
    ],
    edges: [{
      from: 'acme-crm', relation: 'links', to: 'cauthy', link: LINK,
      identity: { issuer: 'cauthy', tenant: TENANT, subject: 'b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e' },
      sign_in: { client_id: `pact.${LINK}`, redirect_uris: [`https://app.test${BASE}/callback`], require_system_proof: true, persistent_sessions: true },
      service: { client_id: SERVICE, system: 'acme-crm', jwks_url: 'https://app.test/api/pact/jwks.json', import: true },
    }],
  }
}

type Old = { createCauthy(o: Record<string, unknown>): { handler(r: Request): Promise<Response> } }
type Store = unknown

const packages: [string, () => Promise<Old>, () => Promise<{ memoryKeyStore(): Store }>][] = [
  ['cauthy-auth 0.41.0', () => import('cauthy-auth-0.41') as Promise<Old>, () => import('cauthy-auth-0.41/keys') as never],
  ['cauthy-auth 0.42.0', () => import('cauthy-auth') as Promise<Old>, () => import('cauthy-auth/keys') as never],
]

/** Signs Ana in with `auth`, as the browser would, and answers the browser. */
async function signIn(fake: FakeCauthy, auth: { handler(r: Request): Promise<Response> }): Promise<Browser> {
  const b = new Browser('https://app.test')
  const start = await auth.handler(b.request(`${BASE}/login`))
  b.take(start)
  const back = new URL(fake.authorize(start.headers.get('location')!))
  b.take(await auth.handler(b.request(back.pathname + back.search)))
  expect(b.jar.has('cauthy_session.0')).toBe(true)
  return b
}

/** 1.2, loaded afresh (its deprecations are said once per process). */
async function current() {
  vi.resetModules()
  vi.spyOn(process, 'emitWarning').mockImplementation(() => undefined)
  return import('./cauthy')
}

async function sessionAt(auth: { handler(r: Request): Promise<Response> }, b: Browser) {
  const res = await auth.handler(b.request(`${BASE}/session`))
  b.take(res)
  return { res, body: (await res.json()) as { status: string; session: { user: { id: string } } | null } }
}

describe.each(packages)('a session %s sealed under PACT_ROOT_KEY', (_name, load, loadKeys) => {
  async function oldSession(fake: FakeCauthy, root = ROOT, previous?: string) {
    vi.stubEnv('PACT_ROOT_KEY', root)
    if (previous) vi.stubEnv('PACT_ROOT_KEY_PREVIOUS', previous)
    const store = (await loadKeys()).memoryKeyStore()
    const old = (await load()).createCauthy({ contract: { graph: graph(), system: 'acme-crm' }, keys: store, basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    return { store, b: await signIn(fake, old) }
  }

  async function onKey(fake: FakeCauthy, store: Store) {
    const { createCauthy } = await current()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: SERVICE }))
    const key = parseKey(process.env.CAUTHY_KEY!)
    const auth = createCauthy({ contract: { graph: graph(), system: 'acme-crm' }, keys: store as never, basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    return { auth, key }
  }

  it('is authenticated by 1.2 on CAUTHY_KEY + PACT_ROOT_KEY, sealed again with the key, and outlives PACT_ROOT_KEY', async () => {
    const fake = new FakeCauthy()
    const { store, b } = await oldSession(fake)
    const { auth, key } = await onKey(fake, store)

    const { res, body } = await sessionAt(auth, b)
    expect(body.status).toBe('authenticated')
    expect(body.session?.user.id).toBe('u1')
    // Sealed again at once with the key's cookie key, not the root's.
    expect(res.headers.getSetCookie().some(c => c.startsWith('cauthy_session.0='))).toBe(true)
    const sealed = b.jar.get('cauthy_session.0')!
    expect(await unsealAny(sealed, await deriveFromKey(key).cookie)).not.toBeNull()
    expect(await unsealAny(sealed, await deriveKeys(ROOT).cookie)).toBeNull()
    // Read again: nothing more to write.
    expect((await sessionAt(auth, b)).res.headers.getSetCookie()).toEqual([])

    // The window ends: PACT_ROOT_KEY and the keys option go, the session stays.
    vi.stubEnv('PACT_ROOT_KEY', '')
    const { createCauthy } = await current()
    const after = createCauthy({ contract: { graph: graph(), system: 'acme-crm' }, basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    expect((await sessionAt(after, b)).body.status).toBe('authenticated')
  })

  it('is renewed by 1.2 when its access token ran out, through the link\'s sign-in client', async () => {
    const fake = new FakeCauthy()
    const { store, b } = await oldSession(fake)
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 3_600_000)
    const { auth, key } = await onKey(fake, store)
    const { body } = await sessionAt(auth, b)
    expect(body.status).toBe('authenticated')
    const refresh = fake.oauthRequests.filter(r => r.form.grant_type === 'refresh_token')
    expect(refresh).toHaveLength(1)
    expect(refresh[0].form.client_id).toBe(`pact.${LINK}`)
    expect(await unsealAny(b.jar.get('cauthy_session.0')!, await deriveFromKey(key).cookie)).not.toBeNull()
  })

  it('is read when it was sealed under PACT_ROOT_KEY_PREVIOUS, a root rotation still open at the move', async () => {
    const fake = new FakeCauthy()
    // Sealed before the root rotation; the rotation (ROOT, previous OLDER_ROOT) was still open.
    const { store, b } = await oldSession(fake, OLDER_ROOT)
    vi.stubEnv('PACT_ROOT_KEY', ROOT)
    vi.stubEnv('PACT_ROOT_KEY_PREVIOUS', OLDER_ROOT)
    const { auth, key } = await onKey(fake, store)
    expect((await sessionAt(auth, b)).body.status).toBe('authenticated')
    expect(await unsealAny(b.jar.get('cauthy_session.0')!, await deriveFromKey(key).cookie)).not.toBeNull()
  })
})

describe('a session @cauthyhq/node 1.1.0 sealed with CAUTHY_SECRET', () => {
  async function oldSession(fake: FakeCauthy) {
    vi.stubEnv('CAUTHY_ISSUER', fake.issuer)
    vi.stubEnv('CAUTHY_CLIENT_ID', fake.clientId)
    vi.stubEnv('CAUTHY_CLIENT_SECRET', 'the-client-secret')
    vi.stubEnv('CAUTHY_SECRET', SECRET)
    const old = (await import('cauthyhq-node-1.1')).createCauthy({ basePath: BASE, fetch: fake.fetch })
    const b = await signIn(fake, old)
    // The move: the variables go, CAUTHY_SECRET stays beside the key for the window.
    for (const name of ['CAUTHY_ISSUER', 'CAUTHY_CLIENT_ID', 'CAUTHY_CLIENT_SECRET']) vi.stubEnv(name, '')
    return b
  }

  it.each([['fresh', 0], ['with its access token run out', 3_600_000]])('is authenticated by 1.2 on CAUTHY_KEY + CAUTHY_SECRET (%s) and sealed again with the key', async (_kind, later) => {
    const fake = new FakeCauthy()
    const b = await oldSession(fake)
    if (later) {
      vi.useFakeTimers({ toFake: ['Date'] })
      vi.setSystemTime(Date.now() + later)
    }
    const { createCauthy } = await current()
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    const auth = createCauthy({ basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    expect((await sessionAt(auth, b)).body.status).toBe('authenticated')
    const sealed = b.jar.get('cauthy_session.0')!
    expect(await unsealAny(sealed, await deriveFromKey(parseKey(process.env.CAUTHY_KEY!)).cookie)).not.toBeNull()
    expect(await unsealAny(sealed, [await keyOf(SECRET)])).toBeNull()
  })
})

describe('a session cookie no key opens', () => {
  it('is cleared, and said once per process', async () => {
    const fake = new FakeCauthy()
    const { createCauthy } = await current()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey())
    const auth = createCauthy({ basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    const b = new Browser('https://app.test')
    for (let i = 0; i < 2; i++) {
      b.jar.set('cauthy_session.0', 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAA.BBBB.CCCC')
      const { res, body } = await sessionAt(auth, b)
      expect(body.status).toBe('unauthenticated')
      expect(res.headers.getSetCookie().some(c => c.startsWith('cauthy_session.0=;'))).toBe(true)
    }
    const said = warn.mock.calls.filter(c => String(c[0]).includes('no key of this application opens'))
    expect(said).toHaveLength(1)
    expect(String(said[0][0])).toContain('PACT_ROOT_KEY_PREVIOUS')
  })
})
