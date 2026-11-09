// The session cookie's envelope: encrypted and authenticated with a key only
// the server has, so the browser carries the session without being able to
// read or change it.

import { CompactEncrypt, compactDecrypt } from 'jose'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/** The 256-bit key a secret stands for. */
export async function keyOf(secret: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(secret)))
}

export async function seal(value: unknown, key: Uint8Array): Promise<string> {
  return new CompactEncrypt(encoder.encode(JSON.stringify(value)))
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(key)
}

/** The value sealed, or null for anything that is not a cookie this key made. */
export async function unseal<T>(sealed: string, key: Uint8Array): Promise<T | null> {
  try {
    const { plaintext } = await compactDecrypt(sealed, key, {
      keyManagementAlgorithms: ['dir'],
      contentEncryptionAlgorithms: ['A256GCM'],
    })
    return JSON.parse(decoder.decode(plaintext)) as T
  } catch {
    return null
  }
}

/** The value sealed with any key of the ring (the newest first), or null. */
export async function unsealAny<T>(sealed: string, ring: Uint8Array[]): Promise<T | null> {
  return (await unsealIndexed<T>(sealed, ring))?.value ?? null
}

/** The value and the position in the ring of the key that opened it, or null. */
export async function unsealIndexed<T>(sealed: string, ring: Uint8Array[]): Promise<{ value: T; index: number } | null> {
  for (let index = 0; index < ring.length; index++) {
    const value = await unseal<T>(sealed, ring[index])
    if (value !== null) return { value, index }
  }
  return null
}
