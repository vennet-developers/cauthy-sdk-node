import { describe, expect, it } from 'vitest'
import { checkNewPassword, checkPassword, describePasswordPolicy, explainPasswordProblems, MIN_PASSWORD, passwordPolicyOf, passwordProblems, type PasswordPolicy } from './validate'

// The API takes passwords of 12 to 128 characters (core-api/internal/auth).
// A form checked here must refuse what the API would, and nothing it accepts.
describe('passwords', () => {
  it('a new password needs the API floor', () => {
    expect(MIN_PASSWORD).toBe(12)
    expect(checkNewPassword('a'.repeat(11))?.code).toBe('too_short')
    expect(checkNewPassword('a'.repeat(12))).toBeNull()
  })

  it('no password past the API ceiling', () => {
    expect(checkNewPassword('a'.repeat(128))).toBeNull()
    expect(checkNewPassword('a'.repeat(129))?.code).toBe('too_long')
    expect(checkPassword('a'.repeat(129))?.code).toBe('too_long')
  })

  it('signing in only needs a password', () => {
    expect(checkPassword('short')).toBeNull()
    expect(checkPassword('')?.code).toBe('required')
  })
})

// A workspace's own rule, as methods() publishes it (core-api/internal/passwordpolicy).
describe('a workspace\'s password policy', () => {
  const policy = (p: Partial<PasswordPolicy>): PasswordPolicy => passwordPolicyOf(p)

  it('without one, the defaults are the old rule', () => {
    expect(passwordPolicyOf(undefined)).toEqual({ min: 12, max: 128, requires: [], min_classes: 0, reject_breached: false })
    expect(checkNewPassword('a'.repeat(12), null)).toBeNull()
    expect(checkNewPassword('a'.repeat(11), undefined)?.code).toBe('too_short')
  })

  it('holds the length it asks, counted in bytes as Cauthy does', () => {
    const p = policy({ min: 16, max: 20 })
    expect(checkNewPassword('a'.repeat(15), p)?.code).toBe('too_short')
    expect(checkNewPassword('a'.repeat(16), p)).toBeNull()
    expect(checkNewPassword('a'.repeat(21), p)?.code).toBe('too_long')
    expect(checkNewPassword('ñ'.repeat(8), p)).toBeNull() // 16 bytes
    expect(checkNewPassword('ñ'.repeat(7) + 'a', p)?.code).toBe('too_short') // 15
  })

  it('asks each kind of character it requires', () => {
    expect(passwordProblems('abcdefghijkl', policy({ requires: ['lowercase', 'uppercase', 'digit', 'symbol'] }))).toEqual(['needs_uppercase', 'needs_digit', 'needs_symbol'])
    expect(passwordProblems('ABCDEFGHIJKL', policy({ requires: ['lowercase'] }))).toEqual(['needs_lowercase'])
    expect(passwordProblems('correct horse', policy({ requires: ['symbol'] }))).toEqual([]) // a space is a symbol
    expect(passwordProblems('Abcdefghij1!', policy({ requires: ['lowercase', 'uppercase', 'digit', 'symbol'] }))).toEqual([])
  })

  it('asks at least N of the four kinds', () => {
    const p = policy({ min_classes: 3 })
    expect(passwordProblems('abcdefghijk1', p)).toEqual(['needs_classes'])
    expect(passwordProblems('abcdefghijK1', p)).toEqual([])
    expect(passwordProblems('日本語日本語日本語', policy({ min_classes: 1 }))).toEqual(['needs_classes']) // letters without case are neither
  })

  it('never goes below 8 nor above 128, whatever it is sent', () => {
    expect(passwordPolicyOf({ min_length: 4, max_length: 500, min_classes: 9, requires: ['digit', 'emoji'] })).toEqual({ min: 8, max: 128, requires: ['digit'], min_classes: 4, reject_breached: false })
  })

  it('says the concrete rule, in English and Spanish', () => {
    const p = policy({ min: 14, requires: ['uppercase', 'digit'], min_classes: 3, reject_breached: true })
    expect(describePasswordPolicy(undefined)).toBe('Between 12 and 128 characters.')
    expect(describePasswordPolicy(p)).toBe('Between 14 and 128 characters. Include an uppercase letter and a digit. Use at least 3 of these: lowercase letters, uppercase letters, digits, symbols. Passwords found in known data breaches are not accepted.')
    expect(describePasswordPolicy(p, 'es')).toContain('Entre 14 y 128 caracteres. Incluye una mayúscula y un número.')
    expect(checkNewPassword('short', p)?.message).toBe('Use at least 14 characters. Include an uppercase letter. Include a digit. Use at least 3 of these: lowercase letters, uppercase letters, digits, symbols.')
    expect(explainPasswordProblems(['breached'], p, 'es')).toBe('Esta contraseña aparece en una filtración de datos conocida. Elige otra.')
  })
})
