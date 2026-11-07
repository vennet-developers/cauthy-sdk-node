import { describe, expect, it } from 'vitest'
import { CauthyApiError, CauthyConfigError } from './index'
import { policySource } from './permissions'

describe('the package names itself', () => {
  it('in its errors', () => {
    expect(new CauthyConfigError('x').message).toBe('@cauthyhq/node: x')
    expect(new CauthyApiError(400, 'bad', 'y').message).toBe('@cauthyhq/node: y')
  })

  it('in the policy module it writes', () => {
    const source = policySource('acme-crm', [])
    expect(source).toContain("from '@cauthyhq/node'")
    expect(source).toContain('Written by `pullPolicy`')
  })
})
