import { readFileSync } from 'node:fs'
import { createLocalJWKSet } from 'jose'
import { describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { CauthyWebhookError, memoryReplayStore, verifyWebhook } from './webhook'

// A delivery signed by Cauthy's own code, with the keys it publishes (written
// by core-api's TestExportDeliveryVector): what is verified here is the real
// thing, not a signature this package made for itself.
const vector = JSON.parse(readFileSync(new URL('./testdata/delivery.json', import.meta.url), 'utf8')) as {
  issuer: string; url: string; at: string; jwks: { keys: any[] }; signature: string; body: string
  domain_issuer: string; domain_signature: string
}
const jwks = createLocalJWKSet(vector.jwks)
const at = new Date(vector.at)
const options = { issuer: vector.issuer, jwks, now: at }

function delivery(over: { url?: string; signature?: string | null; body?: string } = {}): Request {
  const headers = new Headers({ 'content-type': 'application/json' })
  if (over.signature !== null) headers.set('x-cauthy-signature-jwt', over.signature ?? vector.signature)
  return new Request(over.url ?? vector.url, { method: 'POST', headers, body: over.body ?? vector.body })
}

const refused = async (p: Promise<unknown>) => {
  await expect(p).rejects.toBeInstanceOf(CauthyWebhookError)
}

describe('a delivery from Cauthy', () => {
  it('is verified with the published keys and read as an event', async () => {
    const event = await verifyWebhook(delivery(), options)
    expect(event).toEqual({
      id: '0d1f4c3e-6a51-4b7e-9d0a-2f6f0f3b8c11',
      type: 'organization.member_added',
      tenantId: 'adbc2bca-245a-40e7-9cc3-d1746e06fff8',
      createdAt: '2026-10-12T12:00:00Z',
      userId: '92ee788d-a44d-4a80-bda9-244001e6f61c', // the member, not who added her
      actorId: '11111111-2222-4333-8444-555555555555',
      data: { organization_id: '5f0c1a4e-9d2b-4c1e-8a57-0d6c2f9b7e31', system: 'books', external_id: 'ent-1',
        user_id: '92ee788d-a44d-4a80-bda9-244001e6f61c', email: 'ana@acme.com', role: 'accountant' },
    })
    // The query string is not part of who it is for.
    expect((await verifyWebhook(delivery({ url: vector.url + '?x=1' }), options)).type).toBe('organization.member_added')
  })

  it("is taken by a subscriber whose issuer is the workspace's own domain", async () => {
    const signed = delivery({ signature: vector.domain_signature })
    expect((await verifyWebhook(signed, { ...options, issuer: vector.domain_issuer })).type).toBe('organization.member_added')
    // Cauthy's own address is still its issuer.
    expect((await verifyWebhook(delivery({ signature: vector.domain_signature }), options)).type).toBe('organization.member_added')
    // A delivery that names no domain is not the domain's.
    await refused(verifyWebhook(delivery(), { ...options, issuer: vector.domain_issuer }))
  })

  it('is refused when it is not this delivery, for this endpoint, just now', async () => {
    await refused(verifyWebhook(delivery({ signature: null }), options))
    // One byte of the body changed.
    await refused(verifyWebhook(delivery({ body: vector.body.replace('accountant', 'owner') }), options))
    await refused(verifyWebhook(delivery({ body: vector.body + ' ' }), options))
    // Captured from this subscriber and sent to another.
    await refused(verifyWebhook(delivery({ url: 'https://other.example.com/api/hooks/cauthy' }), options))
    // Played back later, or before it was made.
    await refused(verifyWebhook(delivery(), { ...options, now: new Date(at.getTime() + 6 * 60_000) }))
    await refused(verifyWebhook(delivery(), { ...options, now: new Date(at.getTime() - 5 * 60_000) }))
    // Another installation's deliveries are not this one's.
    await refused(verifyWebhook(delivery(), { ...options, issuer: 'https://elsewhere.example.com' }))
    // Not a signature at all, or one with its last bytes changed.
    await refused(verifyWebhook(delivery({ signature: 'nope' }), options))
    await refused(verifyWebhook(delivery({ signature: vector.signature.slice(0, -4) + 'AAAA' }), options))
    await expect(verifyWebhook(delivery(), { jwks, now: at, issuer: '' })).rejects.toThrow(/CAUTHY_ISSUER/)
  })

  it('is one call on the application\'s own Cauthy', async () => {
    const auth = createCauthy({ issuer: vector.issuer, clientId: 'c', secret: 'a-secret-of-at-least-thirty-two-characters', baseURL: 'https://app.example.com' })
    // Behind a proxy the request names an inner address; baseURL says the public one.
    const inner = delivery({ url: 'http://10.0.0.4:3000/api/hooks/cauthy' })
    const event = await auth.webhook(inner, { jwks, now: at })
    expect(event.data.role).toBe('accountant')
    // The very same signed delivery a second time, while it is still valid, is a replay.
    vi.useFakeTimers({ now: at, toFake: ['Date'] })
    try {
      const fresh = createCauthy({ issuer: vector.issuer, clientId: 'c', secret: 'a-secret-of-at-least-thirty-two-characters', baseURL: 'https://app.example.com' })
      await fresh.webhook(delivery({ url: 'http://10.0.0.4:3000/api/hooks/cauthy' }), { jwks, now: at })
      await expect(fresh.webhook(delivery({ url: 'http://10.0.0.4:3000/api/hooks/cauthy' }), { jwks, now: at })).rejects.toThrow(/already taken/)
    } finally {
      vi.useRealTimers()
    }
  })

  it('is taken more than once by verifyWebhook alone, unless it is given where to remember', async () => {
    expect((await verifyWebhook(delivery(), options)).type).toBe('organization.member_added')
    expect((await verifyWebhook(delivery(), options)).type).toBe('organization.member_added')
    const replay = memoryReplayStore(() => at.getTime())
    await verifyWebhook(delivery(), { ...options, replay })
    await refused(verifyWebhook(delivery(), { ...options, replay }))
  })
})
