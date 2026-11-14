// Moving to CAUTHY_KEY, end to end with the packages applications move from:
// @cauthyhq/node 1.1.0 on the variables (CAUTHY_SECRET) signs a person in
// through FakeCauthy and keeps the cookie it sealed; 1.3 then reads it at
// GET <basePath>/session with CAUTHY_KEY and the old secret beside it, and
// seals it again with the key, so it outlives the old secret.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseKey } from './cauthykey'
import { deriveFromKey } from './keyderive'
import { keyOf, unsealAny } from './seal'
import { Browser, FakeCauthy } from './testing'

const SECRET = 'a-cauthy-secret-of-thirty-two-characters-or-more'
const BASE = '/api/id'

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

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
