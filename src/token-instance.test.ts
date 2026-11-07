import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { FakeCauthy } from './testing'
import { CauthyConfigError } from './types'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'
const ROOT = 'a-root-key-of-thirty-two-random-bytes-0123'
const TENANT = '8c2f1d6e-5b0a-4f7e-9a3d-2e6b1c4d7f90'
const SUB = '92ee788d-a44d-4a80-bda9-244001e6f61c'
let jwks: ReturnType<typeof createLocalJWKSet>
let sign: (claims?: Record<string, unknown>) => Promise<string>

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256' }] })
  sign = (claims = {}) => new SignJWT({ sub: SUB, tid: TENANT, ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer('https://id.test').setAudience('cauthy').setIssuedAt().setExpirationTime('10m').sign(pair.privateKey)
})

const graph = {
  version: 1,
  nodes: [
    { id: 'cauthy', type: 'system', url: 'https://id.test', tenants: [{ id: TENANT, slug: 'acme', name: 'Acme' }] },
    { id: 'acme-crm', type: 'system', url: 'https://app.test' },
  ],
  edges: [{
    from: 'acme-crm', relation: 'links', to: 'cauthy', link: 'acme-crm-signs-in-with-cauthy',
    identity: { issuer: 'cauthy', tenant: TENANT, subject: 'users' },
    sign_in: { client_id: 'pact.acme-crm-signs-in-with-cauthy', redirect_uris: ['https://app.test/api/auth/callback'], require_system_proof: false },
  }],
}

describe('auth.verifyToken: the issuer and the workspace are the instance\'s own', () => {
  const cauthy = new FakeCauthy()
  const env = (over: Record<string, unknown> = {}) =>
    createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: SECRET, tenant: 'acme', fetch: cauthy.fetch, ...over })

  it('by contract, takes the workspace id from the link and the audience from the options', async () => {
    const auth = createCauthy({ contract: { graph, system: 'acme-crm' }, rootKey: ROOT, audience: 'cauthy', fetch: cauthy.fetch })
    const who = await auth.verifyToken(await sign(), { jwks })
    expect(who).toMatchObject({ userId: SUB, tenantId: TENANT })
    await expect(auth.verifyToken(await sign({ tid: '11111111-2222-4333-8444-555555555555' }), { jwks })).rejects.toMatchObject({ reason: 'wrong_tenant' })
  })

  it('without a contract, takes the workspace id and the audience from the options', async () => {
    const auth = env({ tenantId: TENANT, audience: 'cauthy' })
    expect((await auth.verifyToken(await sign(), { jwks })).userId).toBe(SUB)
  })

  it('reads CAUTHY_AUDIENCE and CAUTHY_TENANT_ID too', async () => {
    const before = { a: process.env.CAUTHY_AUDIENCE, t: process.env.CAUTHY_TENANT_ID }
    process.env.CAUTHY_AUDIENCE = 'cauthy'
    process.env.CAUTHY_TENANT_ID = TENANT
    try {
      expect((await env().verifyToken(await sign(), { jwks })).userId).toBe(SUB)
    } finally {
      for (const [k, v] of [['CAUTHY_AUDIENCE', before.a], ['CAUTHY_TENANT_ID', before.t]] as const) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
    }
  })

  it('says what is missing when the audience, which Cauthy has no default for, is not given', () => {
    expect(() => env({ tenantId: TENANT }).tokenVerifier()).toThrow(CauthyConfigError)
    expect(() => env({ tenantId: TENANT }).tokenVerifier()).toThrow(/audience/)
    expect(() => env({ audience: 'cauthy' }).tokenVerifier()).toThrow(/tenantId/)
  })

  it('builds a verifier once, with a per-call override', async () => {
    const verify = createCauthy({ contract: { graph, system: 'acme-crm' }, rootKey: ROOT, audience: 'cauthy', fetch: cauthy.fetch }).tokenVerifier({ jwks, allowAnonymous: true })
    expect((await verify(await sign({ anon: true }))).anonymous).toBe(true)
  })
})
