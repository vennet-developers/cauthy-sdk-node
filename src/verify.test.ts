import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it } from 'vitest'
import { CauthyConfigError } from './types'
import { CauthyTokenError, createTokenVerifier, verifyToken } from './verify'

const issuer = 'https://cauthy.example.com'
const tenantId = 'adbc2bca-245a-40e7-9cc3-d1746e06fff8'
let sign: (claims: Record<string, unknown>, over?: { issuer?: string; expiresIn?: string; key?: CryptoKey }) => Promise<string>
let options: { issuer: string; audience: string; tenantId: string; jwks: ReturnType<typeof createLocalJWKSet> }
let stranger: CryptoKey

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  stranger = (await generateKeyPair('RS256')).privateKey as CryptoKey
  options = { issuer, audience: 'cauthy-api', tenantId, jwks: createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256' }] }) }
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

  // verification/rules.md of cauthy-sdk-spec: R13 (system_token) and R14 (anonymous_token).
  it('refuses a system\'s own token where a person is expected (R13)', async () => {
    const token = await sign({ sub: '5b0b7d1e-3c41-4f8a-9d55-0a1f6c2e8b73', tid: tenantId, roles: [], sys: 'books' })
    await expect(verifyToken(token, options)).rejects.toMatchObject({ reason: 'system_token' })
    // Whatever the value of sys.
    await expect(verifyToken(await sign({ sub: '5b0b7d1e-3c41-4f8a-9d55-0a1f6c2e8b73', tid: tenantId, sys: '' }), options)).rejects.toMatchObject({ reason: 'system_token' })
  })

  it('says when it is a system and not a person, for an endpoint that takes systems', async () => {
    const who = await verifyToken(await sign({ sub: '5b0b7d1e-3c41-4f8a-9d55-0a1f6c2e8b73', tid: tenantId, roles: [], sys: 'books' }), { ...options, allowSystem: true })
    expect(who.system).toBe('books')
    expect(who.email).toBeUndefined()
  })

  it('refuses a guest\'s token unless guests are allowed (R14)', async () => {
    const token = await sign({ sub: person.sub, tid: tenantId, roles: [], anon: true })
    await expect(verifyToken(token, options)).rejects.toMatchObject({ reason: 'anonymous_token' })
    const who = await verifyToken(token, { ...options, allowAnonymous: true })
    expect(who).toMatchObject({ userId: person.sub, anonymous: true })
    expect((await verifyToken(await sign(person), options)).anonymous).toBeUndefined()
  })

  it('does not start without an audience or a workspace, or with a bad one', () => {
    const { audience: _a, tenantId: _t, ...bare } = options
    expect(() => createTokenVerifier({ ...bare, tenantId })).toThrow(CauthyConfigError)
    expect(() => createTokenVerifier({ ...bare, audience: 'cauthy-api' })).toThrow(/tenantId/)
    expect(() => createTokenVerifier({ ...options, tenantId: '00000000-0000-0000-0000-000000000000' })).toThrow(/nil UUID/)
    expect(() => createTokenVerifier({ ...options, tenantId: tenantId.toUpperCase() })).toThrow(/lowercase UUID/)
    expect(() => createTokenVerifier({ ...options, leeway: 61 })).toThrow(/leeway/)
    expect(() => createTokenVerifier({ ...options, issuer: 'http://cauthy.example.com' })).toThrow(/https/)
    expect(() => createTokenVerifier({ ...options })).not.toThrow()
  })

  it('is async: a bad configuration is a rejected promise, not a throw', async () => {
    const { audience: _a, ...bare } = options
    const call = verifyToken('x', bare)
    expect(call).toBeInstanceOf(Promise)
    await expect(call).rejects.toBeInstanceOf(CauthyConfigError)
  })

  it('takes http for localhost, *.localhost and *.test only', () => {
    for (const ok of ['http://localhost:8080', 'http://127.0.0.1', 'http://id.localhost', 'http://cauthy.test:3000']) {
      expect(() => createTokenVerifier({ ...options, issuer: ok })).not.toThrow()
    }
    for (const bad of ['http://id.example.com', 'http://attacker-localhost.com', 'http://test.example.com', 'ftp://id.test']) {
      expect(() => createTokenVerifier({ ...options, issuer: bad })).toThrow(/https/)
    }
  })

  it('refuses a date written with a fraction or an exponent', async () => {
    const pair = await generateKeyPair('RS256')
    const jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k2', alg: 'RS256' }] })
    const iat = Math.floor(Date.now() / 1000)
    const forge = async (payload: string) => {
      const b64 = (s: string) => Buffer.from(s).toString('base64url')
      const head = b64(JSON.stringify({ alg: 'RS256', kid: 'k2' }))
      const body = b64(payload)
      const { createSign } = await import('node:crypto')
      const sig = createSign('RSA-SHA256').update(`${head}.${body}`).sign(pair.privateKey as never).toString('base64url')
      return `${head}.${body}.${sig}`
    }
    const claims = (exp: string) => `{"iss":"${issuer}","aud":"cauthy-api","sub":"${person.sub}","tid":"${tenantId}","iat":${iat},"exp":${exp}}`
    const verify = (token: string) => verifyToken(token, { ...options, jwks })
    await expect(verify(await forge(claims(String(iat + 600))))).resolves.toBeTruthy()
    await expect(verify(await forge(claims(`${iat + 600}.0`)))).rejects.toMatchObject({ reason: 'invalid_claim' })
    await expect(verify(await forge(claims(`${(iat + 600) / 1000}e3`)))).rejects.toMatchObject({ reason: 'invalid_claim' })
  })

  it('names why it refuses, with the spec\'s codes', async () => {
    await expect(verifyToken(await sign(person), { ...options, audience: 'another-api' })).rejects.toMatchObject({ reason: 'wrong_audience' })
    await expect(verifyToken(await sign(person, { key: stranger }), options)).rejects.toMatchObject({ reason: 'bad_signature' })
    await expect(verifyToken('x'.repeat(8193), options)).rejects.toMatchObject({ reason: 'too_large' })
    await expect(verifyToken('', options)).rejects.toMatchObject({ reason: 'no_token' })
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
