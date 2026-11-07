import Fastify from 'fastify'
import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { cauthyFastify, checkFastifyMount } from './fastify'
import { cauthyHono, type CauthyVariables } from './hono'
import { FakeCauthy } from './testing'

function app() {
  const cauthy = new FakeCauthy()
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: 'a-secret-of-at-least-thirty-two-characters', tenant: 'acme', fetch: cauthy.fetch, baseURL: 'https://app.test' })
  return { cauthy, auth }
}

describe('checking that the handler is what answers under basePath', () => {
  it('passes when it is, and sends nothing to Cauthy', async () => {
    const { auth, cauthy } = app()
    await expect(auth.checkMount(auth.handler)).resolves.toBeUndefined()
    expect(cauthy.calls).toEqual([])
  })

  it('names the route another handler answers', async () => {
    const { auth } = app()
    const shadowed = async (r: Request) => new URL(r.url).pathname === '/api/auth/session'
      ? new Response('{}', { headers: { 'content-type': 'application/json' } })
      : auth.handler(r)
    await expect(auth.checkMount(shadowed)).rejects.toThrow(/GET \/api\/auth\/session answered 200 without Cauthy-Protocol: 1/)
  })

  it('catches a catch-all under the prefix', async () => {
    const { auth } = app()
    const catchAll = async (r: Request) => new URL(r.url).pathname === '/api/auth/session' ? auth.handler(r) : new Response('nope', { status: 404 })
    await expect(auth.checkMount(catchAll)).rejects.toThrow(/cauthy-mount-check answered 404/)
  })

  it('says it could not reach the application', async () => {
    const { auth } = app()
    await expect(auth.checkMount(async () => { throw new TypeError('fetch failed') })).rejects.toThrow(/could not reach GET \/api\/auth\/session/)
    await expect(auth.checkMount('not an origin')).rejects.toThrow(/origin/)
  })

  it('works in process with Hono', async () => {
    const { auth } = app()
    const hono = new Hono<{ Variables: CauthyVariables }>()
    hono.use(cauthyHono(auth))
    await expect(auth.checkMount(hono.fetch)).resolves.toBeUndefined()
  })

  it('works in process with Fastify, once it is ready', async () => {
    const { auth } = app()
    const fastify = Fastify()
    await fastify.register(cauthyFastify, { auth })
    await fastify.ready()
    try {
      await expect(checkFastifyMount(fastify, auth)).resolves.toBeUndefined()
    } finally {
      await fastify.close()
    }
  })

  it('is run by the Fastify plugin itself when the server is ready', async () => {
    const { auth } = app()
    const fastify = Fastify()
    // Another route, more specific than the plugin's, takes the session route.
    fastify.get('/api/auth/session', async () => ({ mine: true }))
    await fastify.register(cauthyFastify, { auth })
    await expect(fastify.ready()).rejects.toThrow(/answered 200 without Cauthy-Protocol: 1/)
    await fastify.close().catch(() => undefined)
  })

  it('can be turned off in the Fastify plugin', async () => {
    const { auth } = app()
    const fastify = Fastify()
    fastify.get('/api/auth/session', async () => ({ mine: true }))
    await fastify.register(cauthyFastify, { auth, checkMount: false })
    await expect(fastify.ready()).resolves.toBeDefined()
    await fastify.close()
  })
})
