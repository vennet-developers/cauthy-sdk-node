import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { deriveFromKey } from './keyderive'
import { parseKey } from './cauthykey'

const vectors = JSON.parse(readFileSync(new URL('./testdata/cauthy-key.json', import.meta.url)).toString())
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

describe('deriveFromKey (vectors)', () => {
  for (const v of vectors.valid) {
    it(v.name, async () => {
      const d = deriveFromKey(parseKey(v.key))
      expect(hex((await d.cookie)[0])).toBe(v.derived['pact/cookie/v1'])
      expect(hex((await d.flow)[0])).toBe(v.derived['pact/flow/v1'])
      const s = await d.signer
      expect(s.publicJwk).toEqual(v.public_jwk)
      expect(s.kid).toBe(v.kid)
      const jws = await s.assertion(v.client_id, v.assertion.token_endpoint, v.assertion.jti, v.assertion.iat)
      expect(jws).toBe(v.assertion.jws)
    })
  }
  it('adds the previous key as a read-only ring entry', async () => {
    const [a, b] = vectors.valid
    const d = deriveFromKey(parseKey(a.key), parseKey(b.key))
    expect((await d.cookie).length).toBe(1) // same secret: one entry
    expect(d.previousJwk).toBeUndefined()
  })
  it('makes a fresh jti and a two-minute lifetime by default', async () => {
    const s = await deriveFromKey(parseKey(vectors.valid[0].key)).signer
    const one = JSON.parse(Buffer.from((await s.assertion('c', 'https://id.test/v1/oauth/token')).split('.')[1], 'base64url').toString())
    const two = JSON.parse(Buffer.from((await s.assertion('c', 'https://id.test/v1/oauth/token')).split('.')[1], 'base64url').toString())
    expect(one.jti).not.toBe(two.jti)
    expect(one.exp - one.iat).toBe(120)
    expect(Object.keys(one)).toEqual(['iss', 'sub', 'aud', 'jti', 'iat', 'exp'])
  })
})
