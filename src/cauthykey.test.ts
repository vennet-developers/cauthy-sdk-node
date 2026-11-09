import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { composeKey, parseKey, validIssuer } from './cauthykey'
import { CauthyKeyError } from './types'

const raw = readFileSync(new URL('./testdata/cauthy-key.json', import.meta.url))
const vectors = JSON.parse(raw.toString())
// The pinned copy of cauthy-sdk-spec's vectors/cauthy-key.json.
const PINNED = '165199405ab31ed72390c4e8eabdc7488bb07a871683341bef25525ee0020522'
// The test secret: the bytes 00 01 … 1f, a test value only.
const TEST_SECRET = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'

describe('CAUTHY_KEY parsing (vectors)', () => {
  it('is the pinned copy of the spec vectors', () => {
    expect(createHash('sha256').update(raw).digest('hex')).toBe(PINNED)
  })
  for (const v of vectors.valid) {
    it(v.name, () => {
      const k = parseKey(v.key)
      expect(k).toEqual({ issuer: v.issuer, clientId: v.client_id, secret: v.secret })
      expect(composeKey(v.issuer, v.client_id, v.secret)).toBe(v.key.trim())
    })
  }
  for (const v of vectors.invalid) {
    it(v.name, () => {
      let err: unknown
      try { parseKey(v.key) } catch (e) { err = e }
      expect(err).toBeInstanceOf(CauthyKeyError)
      expect((err as CauthyKeyError).reason).toBe(v.reason)
      expect(String((err as Error).message)).not.toContain(TEST_SECRET)
    })
  }
})

describe('CAUTHY_KEY issuers', () => {
  it('takes origins only, http only on loopback, never an IPv4-mapped address', () => {
    for (const ok of ['https://id.test', 'https://id.test:8443', 'http://localhost:4000', 'http://127.0.0.1:4000', 'http://[::1]:4000', 'https://[2001:db8::1]']) {
      expect(validIssuer(ok), ok).toBe(true)
    }
    for (const bad of ['http://id.test', 'https://id.test/', 'https://ID.test', 'https://id.test:443', 'https://127.1',
      'https://[::ffff:7f00:1]', 'http://[::ffff:127.0.0.1]', 'https://a@id.test', 'https://id.test?x', 'ftp://id.test', '']) {
      expect(validIssuer(bad), bad).toBe(false)
    }
  })
})
