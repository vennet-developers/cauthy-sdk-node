// CAUTHY_KEY (key/cauthy-key.md in cauthy-sdk-spec): parsing and composing,
// synchronously. Derivation and signing are in keyderive.ts.
import { sha256 } from './sha256'
import { CauthyConfigError, CauthyKeyError, type CauthyKeyReason } from './types'

export const KEY_PREFIX = 'cauthy1'

/**
 * The variables CAUTHY_KEY replaces: set beside it, each is a second source
 * of the same thing, and the application refuses to start (key/cauthy-key.md §10).
 */
export const KEY_REPLACES = ['CAUTHY_ISSUER', 'CAUTHY_CLIENT_ID', 'CAUTHY_CLIENT_SECRET', 'CAUTHY_SYSTEM', 'CAUTHY_TENANT',
  'CAUTHY_SYSTEM_KEY', 'CAUTHY_SYSTEM_KEY_ID', 'CAUTHY_BASE_URL', 'CAUTHY_AUDIENCE', 'CAUTHY_TENANT_ID'] as const

/** Names the KEY_REPLACES variables set in `environment`, refusing them beside CAUTHY_KEY. */
export function refuseBesideKey(environment: Record<string, string | undefined> | undefined): void {
  const set = KEY_REPLACES.filter(n => (environment?.[n] ?? '') !== '')
  if (set.length > 0) {
    throw new CauthyConfigError(`the application runs on CAUTHY_KEY, and ${set.join(', ')} ${set.length === 1 ? 'is' : 'are'} also set: ` +
      `remove ${set.length === 1 ? 'it' : 'them'} from the environment. Everything comes from the key.`)
  }
}
const MAX_LEN = 512
const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: true })

/** What a CAUTHY_KEY names. Never logged, never printed. */
export interface CauthyKey {
  /** Cauthy's origin, e.g. https://cauthy.api.example.com */
  issuer: string
  clientId: string
  /** The 43-character secret segment: the HKDF input, as text. */
  secret: string
}

export function b64uEncode(b: Uint8Array): string {
  let bin = ''
  for (const x of b) bin += String.fromCharCode(x)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Strict base64url: no padding, alphabet only, canonical. Null when it is not. */
export function b64uDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4))
  const out = Uint8Array.from(bin, c => c.charCodeAt(0))
  return b64uEncode(out) === s ? out : null
}

function checksum(body: string): string {
  return b64uEncode(sha256(enc.encode(body)).slice(0, 6))
}

function printableAscii(s: string): boolean {
  return /^[\x21-\x7e]*$/.test(s)
}

/**
 * An origin as key/cauthy-key.md §3 rule 5 accepts it: exactly as a WHATWG
 * URL serializes its origin, https (http only on loopback), never an
 * IPv4-mapped IPv6 address.
 */
export function validIssuer(s: string): boolean {
  if (s === '' || !printableAscii(s)) return false
  let u: URL
  try { u = new URL(s) } catch { return false }
  if (u.origin !== s) return false
  if (/^\[::ffff:/i.test(u.host)) return false
  if (u.protocol === 'https:') return true
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)
}

const fail = (reason: CauthyKeyReason, message: string): never => {
  throw new CauthyKeyError(reason, message)
}

const NOT_A_KEY = 'not a Cauthy key (copy it again from the dashboard)'

/** Reads a CAUTHY_KEY; throws CauthyKeyError with the reason, never the value. */
export function parseKey(text: string): CauthyKey {
  const s = text.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '')
  if (s === '' || s.length > MAX_LEN || !printableAscii(s)) fail('key_format', NOT_A_KEY)
  const head = s.split('.', 1)[0]
  if (head !== KEY_PREFIX) {
    if (/^cauthy[0-9]+$/.test(head)) fail('key_version', `this key is for a newer SDK (${head}): update @cauthyhq/node`)
    fail('key_format', NOT_A_KEY)
  }
  const parts = s.split('.')
  if (parts.length !== 5 || parts.some(p => p === '')) fail('key_format', NOT_A_KEY)
  if (!constantTimeEqual(checksum(parts.slice(0, 4).join('.')), parts[4])) {
    fail('key_checksum', 'the key is damaged (part of it is missing or changed): copy it again from the dashboard')
  }
  const issuerBytes = b64uDecode(parts[1])
  let issuer = ''
  try { issuer = issuerBytes ? dec.decode(issuerBytes) : '' } catch { issuer = '' }
  if (!validIssuer(issuer)) fail('key_issuer', 'the key names no valid Cauthy address')
  const clientBytes = b64uDecode(parts[2])
  const clientId = clientBytes ? String.fromCharCode(...clientBytes) : ''
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(clientId)) fail('key_client', 'the key names no valid client')
  const secret = b64uDecode(parts[3])
  if (parts[3].length !== 43 || !secret || secret.length !== 32) fail('key_secret', 'the key\'s secret is not 32 bytes')
  return { issuer, clientId, secret: parts[3] }
}

/** Writes a CAUTHY_KEY (what the dashboard does in the browser; here for tests and tools). */
export function composeKey(issuer: string, clientId: string, secret: string): string {
  const body = `${KEY_PREFIX}.${b64uEncode(enc.encode(issuer))}.${b64uEncode(enc.encode(clientId))}.${secret}`
  const key = `${body}.${checksum(body)}`
  parseKey(key) // refuses what a reader would
  return key
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return d === 0
}
