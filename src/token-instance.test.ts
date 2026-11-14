import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { createCauthy } from './cauthy'
import { FakeCauthy } from './testing'
import { CauthyConfigError } from './types'

const SECRET = 'a-secret-of-at-least-thirty-two-characters'
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

describe('auth.verifyToken: the issuer and the workspace are the instance\'s own', () => {
  const cauthy = new FakeCauthy()
  const env = (over: Record<string, unknown> = {}) =>
    createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: SECRET, tenant: 'acme', fetch: cauthy.fetch, ...over })

  it('checks no client unless one is named', async () => {
    const auth = env({ tenantId: TENANT, audience: 'cauthy' })
    expect((await auth.verifyToken(await sign({ azp: 'acme-admin' }), { jwks })).authorizedParty).toBe('acme-admin')
    await expect(auth.verifyToken(await sign({ azp: 'acme-admin' }), { jwks, clientId: 'acme-crm' })).rejects.toMatchObject({ reason: 'wrong_client' })
  })

  it('takes the workspace id and the audience from the options', async () => {
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
    const verify = env({ tenantId: TENANT, audience: 'cauthy' }).tokenVerifier({ jwks, allowAnonymous: true })
    expect((await verify(await sign({ anon: true }))).anonymous).toBe(true)
  })
})
