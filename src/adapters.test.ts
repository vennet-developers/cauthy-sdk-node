import type { AddressInfo } from 'node:net'
import express from 'express'
import Fastify from 'fastify'
import { Hono } from 'hono'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { cauthyExpress, requireSession as expressRequire } from './express'
import { cauthyFastify } from './fastify'
import { cauthyHono, requireSession as honoRequire, type CauthyVariables } from './hono'
import { cauthyNext } from './next'
import { Browser, FakeCauthy } from './testing'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'

// What the request being served carries, for next/headers.
const serving = vi.hoisted(() => ({ headers: new Headers() }))
vi.mock('next/headers', () => ({ headers: async () => serving.headers }))

// One application, written once per framework: the routes, a page that says
// who is signed in, and a page only a signed-in person may see. `call` is a
// browser as far as cookies go.
type App = { call(path: string, init?: RequestInit): Promise<Response>; close(): Promise<void> }

function fake() {
  const cauthy = new FakeCauthy()
  const sent: { path: string; body: unknown; ip: string | null }[] = []
  // Cauthy's own API, for an application's own sign-in screen: only that it was asked, and with what.
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input))
    if (!url.pathname.startsWith('/v1/auth/')) return cauthy.fetch(input, init)
    sent.push({ path: url.pathname, body: init?.body ? JSON.parse(String(init.body)) : undefined, ip: new Headers(init?.headers).get('x-cauthy-client-ip') })
    return new Response(JSON.stringify({ errors: [{ code: 'invalid_credentials', message: 'no' }] }), { status: 401 })
  }
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET, tenant: 'acme', fetch, baseURL: 'http://app.test' })
  return { cauthy, auth, sent }
}

const frameworks: Record<string, (auth: ReturnType<typeof fake>['auth']) => Promise<App>> = {
  async express(auth) {
    const app = express()
    app.use(express.json())
    app.use(cauthyExpress(auth))
    app.get('/api/me', async (req, res) => {
      const session = await req.cauthy()
      if (!session) return void res.status(401).json({ error: 'unauthenticated' })
      res.json({ email: session.user.email })
    })
    app.get('/api/books', expressRequire, async (req, res) => void res.json({ for: (await req.cauthy())!.user.id }))
    const server = app.listen(0, '127.0.0.1')
    await new Promise((r) => server.once('listening', r))
    const at = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    return { call: (path, init) => fetch(at + path, { redirect: 'manual', ...init }), close: () => new Promise((r) => server.close(() => r())) }
  },

  async hono(auth) {
    const app = new Hono<{ Variables: CauthyVariables }>()
    app.use(cauthyHono(auth))
    app.get('/api/me', (c) => {
      const session = c.get('session')
      return session ? c.json({ email: session.user.email }) : c.json({ error: 'unauthenticated' }, 401)
    })
    app.get('/api/books', honoRequire, (c) => c.json({ for: c.get('session')!.user.id }))
    return { call: async (path, init) => app.request('http://app.test' + path, init), close: async () => undefined }
  },

  async fastify(auth) {
    const app = Fastify()
    await app.register(cauthyFastify, { auth })
    app.get('/api/me', async (req, reply) => {
      const session = await req.cauthy()
      return session ? { email: session.user.email } : reply.code(401).send({ error: 'unauthenticated' })
    })
    app.get('/api/books', { preHandler: app.requireSession }, async (req) => ({ for: (await req.cauthy())!.user.id }))
    await app.listen({ port: 0, host: '127.0.0.1' })
    const at = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`
    return { call: (path, init) => fetch(at + path, { redirect: 'manual', ...init }), close: () => app.close() }
  },

  // Next.js is its conventions: a route file, a middleware file, and pages
  // that ask who is signed in. This is what Next does with them.
  async next(auth) {
    const cauthy = cauthyNext(auth)
    const middleware = cauthy.middleware({ protect: (path) => path.startsWith('/api/books') })
    return {
      async call(path, init) {
        const request = new Request('http://app.test' + path, init)
        const passed = await middleware(request)
        if (passed.headers.get('x-middleware-next') !== '1') return passed // the middleware answered
        // What the route sees is the request as the middleware passed it on.
        const seen = new Headers(request.headers)
        const renewed = passed.headers.get('x-middleware-request-cookie')
        if (renewed !== null) seen.set('cookie', renewed)
        let answer: Response
        if (path.startsWith('/api/auth')) {
          answer = await (request.method === 'POST' ? cauthy.POST : cauthy.GET)(new Request(request, { headers: seen }))
        } else {
          serving.headers = new Headers({ ...Object.fromEntries(seen), host: 'app.test' })
          const session = await cauthy.session()
          answer = session === null
            ? Response.json({ error: 'unauthenticated' }, { status: 401 })
            : Response.json(path.startsWith('/api/books') ? { for: session.user.id } : { email: session.user.email })
        }
        const out = new Response(answer.body, answer)
        for (const c of passed.headers.getSetCookie()) out.headers.append('set-cookie', c)
        return out
      },
      close: async () => undefined,
    }
  },
}

let open: App | undefined
afterEach(async () => {
  await open?.close()
  open = undefined
})

describe.each(Object.keys(frameworks))('with %s', (name) => {
  async function setup() {
    const world = fake()
    open = await frameworks[name](world.auth)
    const browser = new Browser('http://app.test')
    const call = async (path: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers)
      if (browser.jar.size > 0) headers.set('cookie', [...browser.jar].map(([k, v]) => `${k}=${v}`).join('; '))
      const res = await open!.call(path, { ...init, headers })
      browser.take(res)
      return res
    }
    const signIn = async (returnTo = '/') => {
      const start = await call(`/api/auth/login?return_to=${returnTo}`)
      const back = new URL(world.cauthy.authorize(String(start.headers.get('location'))))
      return call(back.pathname + back.search)
    }
    return { ...world, browser, call, signIn }
  }

  it('serves the routes and knows who is signed in', async () => {
    const { call, signIn } = await setup()
    expect((await call('/api/me')).status).toBe(401)
    // Next sends a page to sign in; an API answers 401. Either way: not in.
    expect([401, 302, 307]).toContain((await call('/api/books')).status)

    const done = await signIn('/books')
    expect([302, 307]).toContain(done.status)
    expect(done.headers.get('location')).toBe('/books')

    expect(await (await call('/api/me')).json()).toEqual({ email: 'ana@acme.com' })
    expect(await (await call('/api/books')).json()).toEqual({ for: 'u1' })
    expect((await (await call('/api/auth/session')).json()).session.user.email).toBe('ana@acme.com')
  })

  it('renews an expired session on the spot and sends the new cookie with the answer', async () => {
    const { cauthy, call, signIn, browser } = await setup()
    cauthy.expiresIn = 1 // already inside the renewal window
    await signIn()
    const before = browser.jar.get('cauthy_session.0')
    expect(before).toBeDefined()

    cauthy.expiresIn = 600
    expect(await (await call('/api/me')).json()).toEqual({ email: 'ana@acme.com' })
    expect(browser.jar.get('cauthy_session.0')).not.toBe(before)
    // The renewed cookie is good: no further renewal is needed.
    const calls = cauthy.calls.length
    expect((await call('/api/books')).status).toBe(200)
    expect(cauthy.calls.length).toBe(calls)
  })

  it('keeps the protocol\'s headers on what the adapter writes back', async () => {
    const { call } = await setup()
    for (const path of ['/api/auth/session', '/api/auth/nope']) {
      const res = await call(path)
      expect(res.headers.get('cauthy-protocol')).toBe('1')
      expect(res.headers.get('cache-control')).toContain('no-store')
    }
    const refused = await call('/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://app.test' },
      body: '{}',
    })
    expect(refused.status).toBe(403)
    expect(refused.headers.get('cauthy-protocol')).toBe('1')
    expect((await refused.json()).error.code).toBe('csrf_required')
  })

  it('carries a form to the application\'s own sign-in screen, whole', async () => {
    const { call, sent } = await setup()
    const res = await call('/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'x-cauthy-request': '1', 'content-type': 'application/json', origin: 'http://app.test' },
      body: JSON.stringify({ email: 'ana@acme.com', password: 'a "quoted" pässword' }),
    })
    expect(res.status).toBe(401)
    expect((await res.json()).error.code).toBe('invalid_credentials')
    expect(sent).toEqual([{ path: '/v1/auth/login', body: { email: 'ana@acme.com', password: 'a "quoted" pässword' }, ip: null }])
  })
})
