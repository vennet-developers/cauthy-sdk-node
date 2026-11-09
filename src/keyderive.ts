// Everything a CAUTHY_KEY stands for (key/cauthy-key.md §4–§6): the cookie
// and flow rings (rootkey.ts's derivation, with the secret segment as the
// root) and the Ed25519 key the application proves itself with.
//
// The assertion is written by hand, member by member, as §6 fixes it: the
// vectors pin it byte for byte. WebCrypto signs; nothing here needs node:crypto.
import { b64uEncode, type CauthyKey } from './cauthykey'
import { deriveKeys, type KeyRing } from './rootkey'

const enc = new TextEncoder()
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])

export const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

export type PublicJwk = { kty: 'OKP'; crv: 'Ed25519'; x: string }

export interface Signer {
  kid: string
  publicJwk: PublicJwk
  /** §6's assertion. iat in seconds; jti a fresh UUID v4. */
  assertion(clientId: string, tokenEndpoint: string, jti?: string, iat?: number): Promise<string>
}

export interface KeyDerived {
  cookie: Promise<KeyRing>
  flow: Promise<KeyRing>
  signer: Promise<Signer>
  /** The previous key's public JWK, published during a rotation (contract). */
  previousJwk?: Promise<PublicJwk & { kid: string }>
}

async function seedOf(secret: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('cauthy/sign/v1') }, ikm, 256))
}

/** RFC 7638 thumbprint of an Ed25519 public key. */
export async function thumbprint(x: string): Promise<string> {
  return b64uEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`))))
}

async function signerOf(secret: string): Promise<Signer> {
  const seed = await seedOf(secret)
  const der = new Uint8Array(PKCS8_ED25519.length + 32)
  der.set(PKCS8_ED25519)
  der.set(seed, PKCS8_ED25519.length)
  // Extractable only to read x; the key that signs from here on is not.
  const readable = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign'])
  const { x } = await crypto.subtle.exportKey('jwk', readable)
  const signing = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign'])
  der.fill(0)
  seed.fill(0)
  const publicJwk: PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: x as string }
  const kid = await thumbprint(publicJwk.x)
  const header = b64uEncode(enc.encode(JSON.stringify({ alg: 'EdDSA', kid })))
  return {
    kid,
    publicJwk,
    async assertion(clientId, tokenEndpoint, jti = crypto.randomUUID(), iat = Math.floor(Date.now() / 1000)) {
      const claims = { iss: clientId, sub: clientId, aud: tokenEndpoint, jti, iat, exp: iat + 120 }
      const input = `${header}.${b64uEncode(enc.encode(JSON.stringify(claims)))}`
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signing, enc.encode(input)))
      return `${input}.${b64uEncode(sig)}`
    },
  }
}

/** The rings and the signer of a key, and of the one it replaces during a rotation. */
export function deriveFromKey(key: CauthyKey, previous?: CauthyKey): KeyDerived {
  const other = previous && previous.secret !== key.secret ? previous : undefined
  const rings = deriveKeys(key.secret, other?.secret)
  return {
    cookie: rings.cookie,
    flow: rings.flow,
    signer: signerOf(key.secret),
    ...(other ? { previousJwk: signerOf(other.secret).then(s => ({ ...s.publicJwk, kid: s.kid })) } : {}),
  }
}
