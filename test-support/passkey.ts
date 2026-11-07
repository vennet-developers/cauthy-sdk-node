// Copied from cauthy-auth 0.42 so the tests can drive the server the way a
// browser does. Not published: the browser client ships in @cauthyhq/js.

// A passkey ceremony in the browser: what Cauthy says to ask for, in the
// shape the browser's WebAuthn API takes, and what the browser answers, in
// the shape Cauthy reads. Both travel as JSON, with bytes in base64url.

import type { AuthError } from './client'

/** Whether this browser can use a passkey at all. */
export function canUsePasskeys(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' &&
    typeof navigator !== 'undefined' && typeof navigator.credentials?.get === 'function'
}

/**
 * Whether this browser offers passkeys in the autofill of a field marked
 * `autocomplete="username webauthn"`, so the person picks one without
 * looking for a button.
 */
export async function canAutofillPasskeys(): Promise<boolean> {
  if (!canUsePasskeys()) return false
  const pkc = window.PublicKeyCredential as unknown as { isConditionalMediationAvailable?: () => Promise<boolean> }
  try {
    return typeof pkc.isConditionalMediationAvailable === 'function' && (await pkc.isConditionalMediationAvailable()) === true
  } catch {
    return false
  }
}

function bytes(text: string): ArrayBuffer {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

function text(buf: ArrayBuffer | null | undefined): string | null {
  if (!buf) return null
  const view = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < view.byteLength; i++) bin += String.fromCharCode(view[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const withId = (list: any[] | undefined) => (list ?? []).map((c) => ({ ...c, id: bytes(c.id) }))

/**
 * Asks the browser for a passkey, with the options Cauthy sent. `conditional`:
 * in the autofill of the page's username field, waiting until the person
 * picks one or `signal` aborts.
 */
export async function getPasskey(options: any, how: { mediation?: 'conditional'; signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
  const publicKey = { ...options, challenge: bytes(options.challenge), allowCredentials: withId(options.allowCredentials) }
  const cred = (await navigator.credentials.get({ publicKey, ...how } as CredentialRequestOptions)) as PublicKeyCredential | null
  if (cred === null) throw new DOMException('No passkey was chosen.', 'NotAllowedError')
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id, rawId: text(cred.rawId), type: cred.type,
    response: {
      authenticatorData: text(r.authenticatorData), clientDataJSON: text(r.clientDataJSON),
      signature: text(r.signature), userHandle: text(r.userHandle),
    },
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  }
}

/** Asks the browser to make a passkey, with the options Cauthy sent. */
export async function makePasskey(options: any): Promise<Record<string, unknown>> {
  const publicKey = {
    ...options,
    challenge: bytes(options.challenge),
    user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: withId(options.excludeCredentials),
  }
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (cred === null) throw new DOMException('No passkey was made.', 'NotAllowedError')
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id, rawId: text(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: text(r.clientDataJSON), attestationObject: text(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  }
}

/** What the browser's refusal means, for the screen. */
export function ceremonyError(e: unknown): AuthError {
  const name = e instanceof Error || e instanceof DOMException ? e.name : ''
  if (name === 'NotAllowedError' || name === 'AbortError') return { code: 'cancelled', message: 'The passkey was not used. Try again when you are ready.' }
  if (name === 'InvalidStateError') return { code: 'passkey_exists', message: 'This device already has a passkey for this account.' }
  if (name === 'SecurityError') return { code: 'passkey_unavailable', message: 'Passkeys cannot be used on this page.' }
  return { code: 'passkey_failed', message: 'The passkey could not be used. Try again, or sign in another way.' }
}
