import { afterEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { deprecated } from './deprecate'
import { Browser, FakeCauthy } from './testing'

afterEach(() => vi.restoreAllMocks())

describe('what leaves in 2.0', () => {
  it('is said once per thing, as a DeprecationWarning', () => {
    const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {})
    deprecated('a', 'Use b.')
    deprecated('a', 'Use b.')
    deprecated('c', 'Use d.')
    expect(emit).toHaveBeenCalledTimes(2)
    expect(emit.mock.calls[0][0]).toBe('@cauthyhq/node: a is deprecated and leaves in 2.0. Use b.')
    expect(emit.mock.calls[0][1]).toMatchObject({ type: 'DeprecationWarning', code: 'CAUTHY_DEPRECATED' })
  })

  it('includes the guest routes the protocol drops in version 2', async () => {
    const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {})
    const cauthy = new FakeCauthy()
    const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'acme-crm', secret: 'a-secret-of-at-least-thirty-two-characters', tenant: 'acme', fetch: cauthy.fetch })
    const browser = new Browser()
    await auth.handler(browser.request('/api/auth/sign-in/anonymous', { method: 'POST', headers: { 'content-type': 'application/json', origin: browser.origin }, body: '{}' }))
    expect(emit.mock.calls.some((c) => String(c[0]).includes('POST /sign-in/anonymous is deprecated'))).toBe(true)
  })
})
