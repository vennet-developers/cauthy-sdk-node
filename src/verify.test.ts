import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { CauthyTokenError, verifyToken } from './verify'

const issuer = 'https://cauthy.example.com'
const tenantId = 'adbc2bca-245a-40e7-9cc3-d1746e06fff8'
let sign: (claims: Record<string, unknown>, over?: { issuer?: string; expiresIn?: string; key?: CryptoKey }) => Promise<string>
let options: { issuer: string; jwks: ReturnType<typeof createLocalJWKSet> }
let stranger: CryptoKey

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  stranger = (await generateKeyPair('RS256')).privateKey as CryptoKey
  options = { issuer, jwks: createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256' }] }) }
  sign = (claims, over = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(over.issuer ?? issuer)
      .setAudience('cauthy-api')
      .setIssuedAt()
      .setExpirationTime(over.expiresIn ?? '10m')
      .sign(over.key ?? (pair.privateKey as CryptoKey))
})

const person = { sub: '92ee788d-a44d-4a80-bda9-244001e6f61c', tid: tenantId, email: 'ana@acme.com', roles: ['admin'] }
const refused = async (p: Promise<unknown>) => {
  await expect(p).rejects.toBeInstanceOf(CauthyTokenError)
}

describe('an access token', () => {
  it('says who it belongs to, from the token or from a request', async () => {
    const token = await sign(person)
    const who = await verifyToken(token, options)
    expect(who).toMatchObject({ userId: person.sub, tenantId, email: 'ana@acme.com', roles: ['admin'], token })
    expect(who.system).toBeUndefined()
    expect(new Date(who.expiresAt).getTime()).toBeGreaterThan(Date.now())

    const request = new Request('https://api.example.com/books', { headers: { authorization: `Bearer ${token}` } })
    expect((await verifyToken(request, options)).userId).toBe(person.sub)
    expect((await verifyToken(await sign(person), { ...options, audience: 'cauthy-api', tenantId })).tenantId).toBe(tenantId)
  })

  it('says when it is a system and not a person', async () => {
    const who = await verifyToken(await sign({ sub: 'client_1', tid: tenantId, roles: [], sys: 'books' }), options)
    expect(who.system).toBe('books')
    expect(who.email).toBeUndefined()
  })

  it('is refused when it is not Cauthy\'s, not current, or not for here', async () => {
    await refused(verifyToken('', options))
    await refused(verifyToken(new Request('https://api.example.com/books'), options))
    await refused(verifyToken('not.a.token', options))
    await refused(verifyToken(await sign(person, { key: stranger }), options))
    await refused(verifyToken(await sign(person, { issuer: 'https://other.example.com' }), options))
    await refused(verifyToken(await sign(person, { expiresIn: '-1m' }), options))
    await refused(verifyToken(await sign(person), { ...options, audience: 'another-api' }))
    await refused(verifyToken(await sign(person), { ...options, tenantId: '00000000-0000-4000-8000-000000000000' }))
    const { sub: _sub, ...nobody } = person
    await refused(verifyToken(await sign(nobody), options))
  })
})
