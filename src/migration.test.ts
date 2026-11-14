// Moving to CAUTHY_KEY, end to end with the packages applications move from:
// @cauthyhq/node 1.1.0 on the variables (CAUTHY_SECRET) signs a person in
// through FakeCauthy and keeps the cookie it sealed; 1.3 then reads it at
// GET <basePath>/session with CAUTHY_KEY and the old secret beside it, and
// seals it again with the key, so it outlives the old secret. And
// @cauthyhq/node 1.2.1 by contract on CAUTHY_KEY, whose sessions 1.3 reads and
// renews on the same key with the contract gone. (Sessions sealed with
// PACT_ROOT_KEY are no longer read: contract mode is removed in 1.3.)
import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseKey } from './cauthykey'
import { deriveFromKey } from './keyderive'
import { keyOf, unsealAny } from './seal'
import { Browser, FakeCauthy } from './testing'

const TENANT = '6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b'
const LINK = 'acme-crm-signs-in-with-cauthy'
const SERVICE = `pact.${LINK}.service`
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

/** 1.3, loaded afresh (its deprecations are said once per process). */
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

  it.each([['fresh', 0], ['with its access token run out', 3_600_000]])('is authenticated by 1.3 on CAUTHY_KEY + CAUTHY_SECRET (%s) and sealed again with the key', async (_kind, later) => {
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

describe('a session @cauthyhq/node 1.2.1 sealed by contract on CAUTHY_KEY', () => {
  // 1.2.1 signed people in through pact.<link> with the key on the link's
  // service client. Contracts retired, 1.3 runs on the same key alone: Cauthy
  // names pact.<link> as the sign-in client, and the session goes on.
  async function oldSession(fake: FakeCauthy) {
    vi.stubEnv('CAUTHY_KEY', await fake.issueKey(fake.issuer, { clientId: SERVICE }))
    const old = (await import('cauthyhq-node-1.2')).createCauthy({ contract: { graph: graph(), system: 'acme-crm' }, basePath: BASE, baseURL: 'https://app.test', fetch: fake.fetch })
    const b = await signIn(fake, old)
    expect(fake.oauthRequests.find(r => r.form.grant_type === 'authorization_code')!.form.client_id).toBe(`pact.${LINK}`)
    return b
  }

  it.each([['fresh', 0], ['with its access token run out', 3_600_000]])('is read by 1.3 on the same CAUTHY_KEY without the contract (%s)', async (_kind, later) => {
    const fake = new FakeCauthy()
    fake.signInClients.set(SERVICE, `pact.${LINK}`)
    fake.appUrls = ['https://app.test']
    const b = await oldSession(fake)
    const before = b.jar.get('cauthy_session.0')
    if (later) {
      vi.useFakeTimers({ toFake: ['Date'] })
      vi.setSystemTime(Date.now() + later)
    }
    const { createCauthy } = await current()
    const auth = createCauthy({ basePath: BASE, fetch: fake.fetch })
    const { res, body } = await sessionAt(auth, b)
    expect(body.status).toBe('authenticated')
    expect(body.session?.user.id).toBe('u1')
    const refresh = fake.oauthRequests.filter(r => r.form.grant_type === 'refresh_token')
    if (later) {
      // Renewed through the link's sign-in client, which owns the refresh token.
      expect(refresh).toHaveLength(1)
      expect(refresh[0].form.client_id).toBe(`pact.${LINK}`)
      expect(refresh[0].form.client_assertion).toBeUndefined()
      expect(await unsealAny(b.jar.get('cauthy_session.0')!, await deriveFromKey(parseKey(process.env.CAUTHY_KEY!)).cookie)).not.toBeNull()
    } else {
      // The same key's cookie key: nothing to seal again.
      expect(refresh).toHaveLength(0)
      expect(res.headers.getSetCookie()).toEqual([])
      expect(b.jar.get('cauthy_session.0')).toBe(before)
    }
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
    expect(String(said[0][0])).toContain('CAUTHY_SECRET')
  })
})
