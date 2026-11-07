import Fastify from 'fastify'
import { describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { cauthyFastify } from './fastify'
import { FakeCauthy } from './testing'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'

async function setup() {
  const cauthy = new FakeCauthy()
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET, fetch: cauthy.fetch, baseURL: 'http://app.test' })
  const app = Fastify()
  await app.register(cauthyFastify, { auth })
  app.get('/api/me', async (req, reply) => {
    const session = await req.cauthy()
    return session ? { email: session.user.email } : reply.code(401).send({ error: 'unauthenticated' })
  })
  app.get('/api/books', { preHandler: app.requireSession }, async (req) => ({ for: (await req.cauthy())!.user.id }))
  await app.ready()

  // A browser, as far as cookies go.
  const jar = new Map<string, string>()
  const call = async (url: string) => {
    const res = await app.inject({ method: 'GET', url, headers: jar.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') } : {} })
    for (const c of ([] as string[]).concat(res.headers['set-cookie'] ?? [])) {
      const [pair, ...attrs] = c.split('; ')
      const i = pair.indexOf('=')
      if (pair.slice(i + 1) === '' || attrs.includes('Max-Age=0')) jar.delete(pair.slice(0, i))
      else jar.set(pair.slice(0, i), pair.slice(i + 1))
    }
    return res
  }
  return { cauthy, app, call, jar }
}

describe('the Fastify plugin', () => {
  it('serves the routes and knows who is signed in on every request', async () => {
    const { cauthy, call } = await setup()
    expect((await call('/api/me')).statusCode).toBe(401)
    const guarded = await call('/api/books')
    expect(guarded.statusCode).toBe(401)
    expect(guarded.headers['x-cauthy-session']).toBe('none')

    const start = await call('/api/auth/login?return_to=/books')
    expect(start.statusCode).toBe(302)
    const back = new URL(cauthy.authorize(String(start.headers.location)))
    const done = await call(back.pathname + back.search)
    expect(done.headers.location).toBe('/books')

    expect((await call('/api/me')).json()).toEqual({ email: 'ana@acme.com' })
    expect((await call('/api/books')).json()).toEqual({ for: 'u1' })
    expect((await call('/api/auth/session')).json().session.user.email).toBe('ana@acme.com')
  })

  it('renews an expired session on the spot and sends the new cookie with the answer', async () => {
    const { cauthy, call, jar } = await setup()
    cauthy.expiresIn = 1 // already inside the renewal window
    const start = await call('/api/auth/login')
    const back = new URL(cauthy.authorize(String(start.headers.location)))
    await call(back.pathname + back.search)
    const before = jar.get('cauthy_session.0')

    cauthy.expiresIn = 600
    const res = await call('/api/me')
    expect(res.json()).toEqual({ email: 'ana@acme.com' })
    expect(jar.get('cauthy_session.0')).not.toBe(before)
    // The renewed cookie is good: no further renewal is needed.
    const calls = cauthy.calls.length
    expect((await call('/api/books')).statusCode).toBe(200)
    expect(cauthy.calls.length).toBe(calls)

    cauthy.users.get('u1')!.active = false
    cauthy.expiresIn = 1
    // Disabled in Cauthy: out at the next renewal, with the cookie cleared.
    jar.clear()
    const again = await call('/api/auth/login')
    const back2 = new URL(cauthy.authorize(String(again.headers.location)))
    await call(back2.pathname + back2.search)
    expect((await call('/api/me')).statusCode).toBe(401)
    expect(jar.has('cauthy_session.0')).toBe(false)
  })

  it('signs out', async () => {
    const { cauthy, call, jar } = await setup()
    const start = await call('/api/auth/login')
    const back = new URL(cauthy.authorize(String(start.headers.location)))
    await call(back.pathname + back.search)
    const out = await call('/api/auth/logout')
    expect(String(out.headers.location)).toContain('https://id.test/v1/oauth/logout')
    expect(jar.has('cauthy_session.0')).toBe(false)
    expect((await call('/api/me')).statusCode).toBe(401)
  })
})
