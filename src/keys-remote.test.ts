import { SignJWT, exportJWK, generateKeyPair } from 'jose'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { CauthyTokenError, CauthyUnavailableError, remoteKeys, verifyToken } from './verify'

const issuer = 'https://cauthy.example.com'
const tenantId = 'adbc2bca-245a-40e7-9cc3-d1746e06fff8'
const sub = '92ee788d-a44d-4a80-bda9-244001e6f61c'
let jwksBody: string
let token: string

beforeAll(async () => {
  const pair = await generateKeyPair('RS256')
  jwksBody = JSON.stringify({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }] })
  token = await new SignJWT({ sub, tid: tenantId }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(issuer).setAudience('cauthy-api').setIssuedAt().setExpirationTime('10m').sign(pair.privateKey)
})

const options = (fetch: typeof globalThis.fetch) => ({ issuer, audience: 'cauthy-api', tenantId, fetch })
const keysAnswer = (headers: Record<string, string> = {}, body = jwksBody, status = 200) => async (..._args: unknown[]) =>
  new Response(body, { status, headers: { 'content-type': 'application/json', ...headers } })

describe('Cauthy\'s published keys', () => {
  it('are fetched once and kept for the answer\'s max-age', async () => {
    const answer = vi.fn(keysAnswer({ 'cache-control': 'public, max-age=3600' }))
    const keys = remoteKeys(issuer, answer as never)
    const opts = { ...options(answer as never), jwks: keys }
    await verifyToken(token, opts)
    await verifyToken(token, opts)
    expect(answer).toHaveBeenCalledTimes(1)
    expect(String(answer.mock.calls[0][0])).toBe(`${issuer}/.well-known/jwks.json`)
  })

  it('are fetched again once the max-age has passed', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      const answer = vi.fn(keysAnswer({ 'cache-control': 'max-age=10' }))
      const keys = remoteKeys(issuer, answer as never)
      await verifyToken(token, { ...options(answer as never), jwks: keys })
      vi.setSystemTime(Date.now() + 11_000)
      await verifyToken(token, { ...options(answer as never), jwks: keys, now: new Date(Date.now()) })
      expect(answer).toHaveBeenCalledTimes(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('are refused over 64 KiB, and that is Cauthy being unavailable, not a bad token', async () => {
    const big = JSON.stringify({ keys: [], pad: 'x'.repeat(70 * 1024) })
    const answer = keysAnswer({}, big)
    const err = await verifyToken(token, { ...options(answer as never), jwks: remoteKeys(issuer, answer as never) }).catch((e) => e)
    expect(err).toBeInstanceOf(CauthyUnavailableError)
    expect(err).not.toBeInstanceOf(CauthyTokenError)
  })

  it('failing to arrive is Cauthy unavailable; a good set already held survives a later failure', async () => {
    let failing = false
    const answer = async () => (failing ? Promise.reject(new TypeError('fetch failed')) : new Response(jwksBody, { headers: { 'cache-control': 'max-age=0' } }))
    const keys = remoteKeys(issuer, answer as never)
    const opts = { ...options(answer as never), jwks: keys }
    await verifyToken(token, opts)
    failing = true
    await expect(verifyToken(token, opts)).resolves.toBeTruthy() // the last good set stands
    const cold = remoteKeys(issuer, (async () => new Response('nope', { status: 500 })) as never)
    await expect(verifyToken(token, { ...opts, jwks: cold })).rejects.toBeInstanceOf(CauthyUnavailableError)
  })

  it('follow no redirect', async () => {
    const answer = vi.fn(async () => new Response(null, { status: 302, headers: { location: 'https://elsewhere.test/jwks' } }))
    const err = await verifyToken(token, { ...options(answer as never), jwks: remoteKeys(issuer, answer as never) }).catch((e) => e)
    expect(err).toBeInstanceOf(CauthyUnavailableError)
    expect((answer.mock.calls[0] as unknown as [string, RequestInit])[1].redirect).toBe('manual')
  })
})
