// The auth-bff protocol, version 1, as every answer of the handler carries
// it: the version header, no caching, and on a sign-in answer the step that
// comes next — so a client never guesses which screen follows.

export const PROTOCOL_VERSION = '1'

/** What the screen does after a sign-in answer. */
export type NextStep = 'done' | 'mfa' | 'verify_email' | 'code' | 'passkey' | 'redirect'

/** The routes whose answers are sign-in answers (auth-bff.md, "Sign-in answers"). */
export const SIGN_IN_ROUTES: ReadonlySet<string> = new Set([
  '/sign-in/email', '/sign-in/mfa', '/sign-in/mfa/send', '/sign-in/mfa/email', '/sign-in/mfa/push', '/sign-in/mfa/push/finish',
  '/sign-up/email', '/invitation/accept', '/sign-in/magic-link', '/sign-in/email-code', '/sign-in/magic-link/verify',
  '/sign-in/passkey/begin', '/sign-in/passkey/finish', '/sign-in/google-one-tap/begin', '/sign-in/google-one-tap',
  '/sign-in/anonymous', '/me/upgrade',
])

/** The step after a sign-in answer of `route`, or undefined when `status` is not one. */
export function nextOf(route: string, status: unknown): NextStep | undefined {
  switch (status) {
    case 'signed_in': return 'done'
    case 'mfa_required': return 'mfa'
    case 'verification_required': return 'verify_email'
    // A code went out: the second step's, or the one that comes with a sign-in link.
    case 'sent': return route.startsWith('/sign-in/mfa') ? 'mfa' : 'code'
    // A ceremony began: Google's prompt takes the person away and back; a passkey stays here.
    case 'started': return route === '/sign-in/google-one-tap/begin' ? 'redirect' : 'passkey'
    default: return undefined
  }
}

/**
 * The answer as the protocol sends it: `Cauthy-Protocol: 1` always,
 * `Cache-Control: no-store` unless it is `cacheable` (the published keys)
 * or already says no-store, and `next` on a successful JSON sign-in answer
 * of `route` (null: outside the routes).
 */
export async function finish(res: Response, route: string | null, cacheable = false): Promise<Response> {
  const headers = new Headers()
  res.headers.forEach((value, name) => {
    if (name !== 'set-cookie') headers.set(name, value)
  })
  for (const cookie of res.headers.getSetCookie()) headers.append('set-cookie', cookie)
  headers.set('cauthy-protocol', PROTOCOL_VERSION)
  if (!cacheable && !(headers.get('cache-control') ?? '').includes('no-store')) headers.set('cache-control', 'no-store')

  let body: BodyInit | null = res.body
  if (route !== null && SIGN_IN_ROUTES.has(route) && res.ok && (headers.get('content-type') ?? '').startsWith('application/json')) {
    const text = await res.text()
    body = text
    try {
      const parsed = JSON.parse(text) as Record<string, unknown> | null
      const next = nextOf(route, parsed?.status)
      if (parsed !== null && next !== undefined) body = JSON.stringify({ ...parsed, next })
    } catch {
      // Not JSON after all: it goes as it came.
    }
    headers.delete('content-length')
  }
  return new Response(body, { status: res.status, statusText: res.statusText, headers })
}
