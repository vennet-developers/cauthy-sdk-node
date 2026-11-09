import { describe, expect, it, vi } from 'vitest'
import { createIdentity, type Identity } from './identity'

const ID: Identity = {
  issuer: 'https://id.test', audience: 'https://id.test', tenant: { id: 't1', slug: 'acme' }, system: 'acme-crm',
  client_id: 'client_x', sign_in_client_id: 'client_x', app_urls: ['http://localhost:3000'],
  callback_path: '/api/auth/callback', key: { kid: 'k1', retires_at: null }, contract: null,
}

function scripted(answers: Array<() => Response>) {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    const next = answers.shift()
    if (!next) throw new Error('no more answers')
    return next()
  })
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls }
}

const refusal = (code: string) => {
  const e = new Error(code) as Error & { code?: string }
  e.code = code
  return e
}

describe('identity', () => {
  it('asks /v1/connect/self with the system token and keeps the answer', async () => {
    const f = scripted([() => Response.json({ data: ID }, { headers: { etag: '"a"' } })])
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 'sys-token', fetch: f.fetch })
    expect(await id.ready()).toEqual(ID)
    expect(f.calls[0].url).toBe('https://id.test/v1/connect/self')
    expect(new Headers(f.calls[0].init?.headers).get('authorization')).toBe('Bearer sys-token')
    expect(await id.ready()).toEqual(ID) // no second call
    expect(f.calls.length).toBe(1)
  })
  it('revalidates with If-None-Match and keeps the answer on 304', async () => {
    const f = scripted([() => Response.json({ data: ID }, { headers: { etag: '"a"' } }), () => new Response(null, { status: 304 })])
    let now = 0
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 't', fetch: f.fetch, now: () => now })
    await id.ready()
    now = 301_000
    await id.refresh()
    expect(new Headers(f.calls[1].init?.headers).get('if-none-match')).toBe('"a"')
    expect(id.current()).toEqual(ID)
  })
  it('takes a changed answer on revalidation', async () => {
    const moved = { ...ID, app_urls: ['http://localhost:3000', 'https://crm.example.com'] }
    const f = scripted([() => Response.json({ data: ID }, { headers: { etag: '"a"' } }), () => Response.json({ data: moved }, { headers: { etag: '"b"' } })])
    let now = 0
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 't', fetch: f.fetch, now: () => now })
    await id.ready()
    now = 301_000
    await id.refresh()
    expect(id.current()?.app_urls).toEqual(moved.app_urls)
  })
  it('revalidates on its own once five minutes have passed', async () => {
    const f = scripted([() => Response.json({ data: ID }), () => new Response(null, { status: 304 })])
    let now = 0
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 't', fetch: f.fetch, now: () => now })
    await id.ready()
    now = 299_000
    await id.ready()
    expect(f.calls.length).toBe(1)
    now = 300_000
    await id.ready()
    await vi.waitFor(() => expect(f.calls.length).toBe(2))
  })
  it('keeps the last answer when Cauthy is down', async () => {
    const f = scripted([() => Response.json({ data: ID }), () => { throw new TypeError('fetch failed') }])
    let now = 0
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 't', fetch: f.fetch, now: () => now })
    await id.ready()
    now = 301_000
    await id.refresh()
    expect(id.current()).toEqual(ID)
  })
  it('retries until the first answer comes', async () => {
    const f = scripted([() => { throw new TypeError('down') }, () => new Response('{}', { status: 502 }), () => Response.json({ data: ID })])
    const id = createIdentity({ issuer: 'https://id.test', token: async () => 't', fetch: f.fetch, retryMs: [1] })
    expect(id.current()).toBeUndefined()
    await expect(id.ready()).resolves.toEqual(ID)
    expect(f.calls.length).toBe(3)
  })
  it('says misconfigured on invalid_client, logs the kid once, and does not loop', async () => {
    const log = vi.fn()
    const token = vi.fn(async () => { throw refusal('invalid_client') })
    const id = createIdentity({ issuer: 'https://id.test', kid: 'k1', fetch: vi.fn() as never, token, log })
    await expect(id.ready()).rejects.toMatchObject({ status: 503, code: 'misconfigured' })
    await expect(id.ready()).rejects.toMatchObject({ code: 'misconfigured' })
    expect(token).toHaveBeenCalledTimes(1)
    expect(log).toHaveBeenCalledTimes(1)
    expect(log.mock.calls[0][0]).toContain('kid k1')
  })
})
