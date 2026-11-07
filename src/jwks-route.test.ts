import type { AddressInfo } from 'node:net'
import express from 'express'
import Fastify from 'fastify'
import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { cauthyExpress } from './express'
import { cauthyFastify } from './fastify'
import { cauthyHono, type CauthyVariables } from './hono'
import { memoryKeyStore } from './keystores'
import { FakeCauthy } from './testing'

const TENANT = '8c2f1d6e-5b0a-4f7e-9a3d-2e6b1c4d7f90'
const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'

function contracted() {
  const cauthy = new FakeCauthy()
  const graph = {
    version: 1,
    nodes: [
      { id: 'cauthy', type: 'system', url: cauthy.issuer, tenants: [{ id: TENANT, slug: 'acme', name: 'Acme' }] },
      { id: 'acme-crm', type: 'system', url: 'https://app.test', jwks_url: 'https://app.test/.well-known/pact-jwks.json' },
    ],
    edges: [{
      from: 'acme-crm', relation: 'links', to: 'cauthy', link: 'acme-crm-signs-in-with-cauthy',
      identity: { issuer: 'cauthy', tenant: TENANT, subject: 'users' },
      sign_in: { client_id: 'pact.acme-crm-signs-in-with-cauthy', redirect_uris: ['https://app.test/api/auth/callback'], require_system_proof: false },
      service: { client_id: 'pact.acme-crm-signs-in-with-cauthy.service', system: 'acme-crm', jwks_url: 'https://app.test/.well-known/pact-jwks.json', import: false },
    }],
  }
  return createCauthy({ contract: { graph, system: 'acme-crm' }, keys: memoryKeyStore(), rootKey: ROOT, fetch: cauthy.fetch })
}

const KEY = '/.well-known/pact-jwks.json'

// The same app per framework: `call(path, method)` answers over HTTP.
const frameworks: Record<string, (auth: ReturnType<typeof contracted>) => Promise<{ call(path: string, method?: string): Promise<Response>; close(): Promise<void> }>> = {
  async express(auth) {
    const app = express()
    app.use(cauthyExpress(auth))
    const server = app.listen(0, '127.0.0.1')
    await new Promise((r) => server.once('listening', r))
    const at = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
    return { call: (path, method = 'GET') => fetch(at + path, { method }), close: () => new Promise((r) => server.close(() => r())) }
  },
  async hono(auth) {
    const app = new Hono<{ Variables: CauthyVariables }>()
    app.use(cauthyHono(auth))
    return { call: async (path, method = 'GET') => app.fetch(new Request(`http://app.test${path}`, { method })), close: async () => {} }
  },
  async fastify(auth) {
    const app = Fastify()
    await app.register(cauthyFastify, { auth })
    await app.listen({ port: 0, host: '127.0.0.1' })
    const at = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`
    return { call: (path, method = 'GET') => fetch(at + path, { method }), close: () => app.close() }
  },
}

describe.each(Object.keys(frameworks))('the Pact key with %s', (name) => {
  it('is served at the contract\'s jwks path without a route of its own', async () => {
    const app = await frameworks[name](contracted())
    try {
      const res = await app.call(KEY)
      expect(res.status).toBe(200)
      expect(res.headers.get('cache-control')).toContain('max-age=300')
      const body = (await res.json()) as { keys: { kty: string; d?: unknown }[] }
      expect(body.keys).toHaveLength(1)
      expect(body.keys[0].kty).toBe('RSA')
      expect(body.keys[0].d).toBeUndefined()
    } finally {
      await app.close()
    }
  })

  it('answers anything but GET and HEAD with a 404 that is not cached', async () => {
    const app = await frameworks[name](contracted())
    try {
      const res = await app.call(KEY, 'POST')
      expect(res.status).toBe(404)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(res.headers.get('cauthy-protocol')).toBe('1')
    } finally {
      await app.close()
    }
  })
})
