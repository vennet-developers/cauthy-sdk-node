import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createCauthy } from '@cauthyhq/node'
import { afterEach, describe, expect, it } from 'vitest'
import { FakeCauthy } from '../../src/testing'
import { acmeApp } from './app'

let close: (() => Promise<void>) | undefined
afterEach(async () => {
  await close?.()
  close = undefined
})

/** Acme CRM on CAUTHY_KEY alone: a key the in-memory Cauthy issued for it, as the dashboard would. */
async function serve() {
  const cauthy = new FakeCauthy()
  cauthy.ownScreens = true
  cauthy.users.set('u-member', { sub: 'u-member', email: 'member@example.com', name: 'Acme Member', active: true, restricted: false })
  cauthy.passwords.set('member@example.com', 'a-long-test-password')
  // The address first: Cauthy knows the application by it (app_urls).
  const server = createServer()
  server.listen(0, '127.0.0.1')
  await new Promise((r) => server.once('listening', r))
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  cauthy.appUrls = [origin]
  const auth = createCauthy({ key: await cauthy.issueKey(), fetch: cauthy.fetch })
  server.on('request', acmeApp(auth))
  close = () => new Promise((r) => server.close(() => r()))
  return { auth, origin }
}

const post = (origin: string, path: string, body: string) =>
  fetch(`${origin}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin, 'x-cauthy-request': '1' }, body })

describe('Acme CRM', () => {
  it('has Cauthy where it says, over HTTP', async () => {
    const { auth, origin } = await serve()
    await expect(auth.checkMount(origin)).resolves.toBeUndefined()
  })

  it('signs a member in and shows who they are', async () => {
    const { origin } = await serve()
    const signIn = await post(origin, '/api/auth/sign-in/email', JSON.stringify({ email: 'member@example.com', password: 'a-long-test-password' }))
    expect(await signIn.json()).toMatchObject({ status: 'signed_in', next: 'done' })
    const cookie = signIn.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
    expect(await (await fetch(`${origin}/api/me`, { headers: { cookie } })).json()).toMatchObject({ email: 'member@example.com' })
    expect((await fetch(`${origin}/api/deals`, { headers: { cookie } })).status).toBe(200)
    expect((await fetch(`${origin}/api/deals`)).status).toBe(401)
  })

  it('answers a body that is not JSON as the protocol says, not with an HTML page', async () => {
    const { origin } = await serve()
    const res = await post(origin, '/api/auth/sign-in/email', 'not json')
    expect(res.status).toBe(400)
    expect((await res.json()).error.code).toBe('bad_request')
  })
})
