// One secret, many keys.
//
// A contracted application keeps one secret in its environment, its root key
// (PACT_ROOT_KEY). Each job gets a key of its own derived from it with HKDF
// and a label, so no key does two jobs:
//
//   pact/seal/v1    seals the application's private key at rest
//   pact/cookie/v1  encrypts the session cookie
//   pact/flow/v1    encrypts what a sign-in carries between its steps
//
// Rotating the root: set the new one as PACT_ROOT_KEY and the old one as
// PACT_ROOT_KEY_PREVIOUS for a deploy. What is written uses the new root;
// what is read is tried with the new root, then the previous one. Sessions
// survive, and `auth.pact.keys.reseal()` seals the private key again with the
// new root. Then the previous one is removed.

import { CauthyConfigError } from './types'

/** What each derived key is for. */
export type KeyPurpose = 'seal' | 'cookie' | 'flow'

const encoder = new TextEncoder()

/** The least a root key may be: 32 characters, as 32 random bytes in base64url are 43. */
export const MIN_ROOT_KEY = 32

/** The keys of one purpose: the first writes, every one is tried to read. */
export type KeyRing = Uint8Array[]

async function derive(root: string, purpose: KeyPurpose): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', encoder.encode(root), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(`pact/${purpose}/v1`) }, ikm, 256)
  return new Uint8Array(bits)
}

/** The keys a root key (and the one before it, while rotating) stand for. */
export interface DerivedKeys {
  seal: Promise<KeyRing>
  cookie: Promise<KeyRing>
  flow: Promise<KeyRing>
}

export function deriveKeys(root: string, previous?: string): DerivedKeys {
  if (root.length < MIN_ROOT_KEY) {
    throw new CauthyConfigError(`rootKey (PACT_ROOT_KEY) must be at least ${MIN_ROOT_KEY} characters: 32 random bytes, e.g. openssl rand -base64 32`)
  }
  if (previous !== undefined && previous !== '' && previous.length < MIN_ROOT_KEY) {
    throw new CauthyConfigError(`the previous root key (PACT_ROOT_KEY_PREVIOUS) must be at least ${MIN_ROOT_KEY} characters`)
  }
  const roots = previous && previous !== root ? [root, previous] : [root]
  const ring = (purpose: KeyPurpose) => Promise.all(roots.map(r => derive(r, purpose)))
  return { seal: ring('seal'), cookie: ring('cookie'), flow: ring('flow') }
}
