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

  it('reports a redirect as a redirect, not as another handler', async () => {
    const { auth } = app()
    const redirecting = async () => new Response(null, { status: 307, headers: { location: 'https://login.acme.example/' } })
    await expect(auth.checkMount(redirecting)).rejects.toThrow(/the mount redirects \(307 to https:\/\/login.acme.example\/\)/)
  })

  it('reports a handler that crashes as a crash', async () => {
    const { auth } = app()
    await expect(auth.checkMount(async () => { throw new Error('boom') })).rejects.toThrow(/handler threw on .*: boom/)
    await expect(auth.checkMount(async () => new Response('oops', { status: 500 }))).rejects.toThrow(/answered 500.*crash/)
  })

  it('says it could not reach the application', async () => {
    const { auth } = app()
    await expect(auth.checkMount('http://127.0.0.1:1')).rejects.toThrow(/could not reach GET \/api\/auth\/session/)
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
    const before = process.env.NODE_ENV
    process.env.NODE_ENV = 'development' // vitest runs as 'test', which skips the check
    try {
      const fastify = Fastify()
      // Another route, more specific than the plugin's, takes the session route.
      fastify.get('/api/auth/session', async () => ({ mine: true }))
      await fastify.register(cauthyFastify, { auth })
      await expect(fastify.ready()).rejects.toThrow(/answered 200 without Cauthy-Protocol: 1/)
      await fastify.close().catch(() => undefined)
    } finally {
      if (before === undefined) delete process.env.NODE_ENV
      else process.env.NODE_ENV = before
    }
  })

  it('is skipped by the Fastify plugin under NODE_ENV=test', async () => {
    const { auth } = app()
    const before = process.env.NODE_ENV
    process.env.NODE_ENV = 'test'
    try {
      const fastify = Fastify()
      fastify.get('/api/auth/session', async () => ({ mine: true }))
      await fastify.register(cauthyFastify, { auth })
      await expect(fastify.ready()).resolves.toBeDefined()
      await fastify.close()
    } finally {
      if (before === undefined) delete process.env.NODE_ENV
      else process.env.NODE_ENV = before
    }
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
