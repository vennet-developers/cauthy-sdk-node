import { describe, expect, it } from 'vitest'
import { finish, nextOf, PROTOCOL_VERSION } from './protocol'

const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json; charset=utf-8' } })

describe('the step after a sign-in answer', () => {
  it.each([
    ['/sign-in/email', 'signed_in', 'done'],
    ['/sign-in/email', 'mfa_required', 'mfa'],
    ['/sign-up/email', 'verification_required', 'verify_email'],
    ['/sign-in/magic-link', 'sent', 'code'],
    ['/sign-in/mfa/send', 'sent', 'mfa'],
    ['/sign-in/mfa/push', 'sent', 'mfa'],
    ['/sign-in/passkey/begin', 'started', 'passkey'],
    ['/sign-in/google-one-tap/begin', 'started', 'redirect'],
  ])('%s answering %s is followed by %s', (route, status, next) => {
    expect(nextOf(route, status)).toBe(next)
  })

  it('has none for a status that is not a sign-in answer', () => {
    expect(nextOf('/sign-in/mfa/methods', 'ok')).toBeUndefined()
  })
})

describe('an answer as protocol version 1 sends it', () => {
  it('carries the version and no-store, the plain-text ones too', async () => {
    const res = await finish(new Response('Not found', { status: 404 }), null)
    expect(res.status).toBe(404)
    expect(res.headers.get('cauthy-protocol')).toBe(PROTOCOL_VERSION)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.text()).toBe('Not found')
  })

  it('keeps the cache of a cacheable answer, and every cookie', async () => {
    const h = new Headers({ 'cache-control': 'public, max-age=300' })
    h.append('set-cookie', 'a=1; Path=/')
    h.append('set-cookie', 'b=2; Path=/')
    const res = await finish(new Response('{}', { headers: h }), null, true)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    expect(res.headers.getSetCookie()).toEqual(['a=1; Path=/', 'b=2; Path=/'])
    expect(res.headers.get('cauthy-protocol')).toBe('1')
  })

  it('adds next to a sign-in answer, and to nothing else', async () => {
    expect(await (await finish(json({ status: 'signed_in' }), '/sign-in/email')).json()).toEqual({ status: 'signed_in', next: 'done' })
    expect(await (await finish(json({ status: 'saved' }), '/me')).json()).toEqual({ status: 'saved' })
    expect(await (await finish(json({ status: 'sent' }), '/forgot-password')).json()).toEqual({ status: 'sent' })
  })

  it('leaves an error and an event stream as they are', async () => {
    const error = new Response(JSON.stringify({ error: { code: 'required' } }), { status: 400, headers: { 'content-type': 'application/json' } })
    expect(await (await finish(error, '/sign-in/email')).json()).toEqual({ error: { code: 'required' } })
    const stream = new Response('data: x\n\n', { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-store' } })
    const res = await finish(stream, '/sign-in/mfa/push/events')
    expect(res.headers.get('cache-control')).toBe('no-cache, no-store')
    expect(await res.text()).toBe('data: x\n\n')
  })
})
