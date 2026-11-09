import { describe, expect, it } from 'vitest'
import { sha256 } from './sha256'

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')

describe('sha256', () => {
  it('agrees with WebCrypto on lengths around every block boundary', async () => {
    for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1000]) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 7 + n) & 0xff)
      const want = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
      expect(hex(sha256(data)), `length ${n}`).toBe(hex(want))
    }
  })
})
