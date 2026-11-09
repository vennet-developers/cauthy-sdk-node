// Hearing from Cauthy: verifying a webhook delivery.
//
// Cauthy signs every delivery with its own key — the one its tokens are
// signed with, published at /.well-known/jwks.json — so there is no secret to
// receive, store or rotate. Verifying is one call:
//
//   const event = await auth.webhook(request)      // throws if it is not Cauthy's
//
// What is checked: the signature, against Cauthy's published keys; that the
// delivery was meant for THIS endpoint (a signature anyone can verify must say
// who it is for); that it is recent; and that the body is, byte for byte, the
// one that was signed.

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose'
import type { JsonValue } from './types'
import { parseKey } from './cauthykey'
import { withoutTrailingSlashes } from './url'

/** Something that happened in Cauthy, as a subscriber is told. Moments are UTC. */
export interface CauthyEvent {
  /** This delivery's id: the same event delivered again carries the same one. */
  id: string
  /** What happened: "organization.member_added". */
  type: string
  tenantId: string
  createdAt: string
  /** The person it happened to, when it is about one. */
  userId?: string
  /** Who did it. */
  actorId?: string
  /** What the event says: for an organization, its id, system, external_id, role… */
  data: Record<string, JsonValue>
}

export class CauthyWebhookError extends Error {
  constructor(readonly reason: string) {
    super(`@cauthyhq/node: webhook refused: ${reason}`)
    this.name = 'CauthyWebhookError'
  }
}

export interface VerifyWebhookOptions {
  /** Cauthy's address. Default: the one `CAUTHY_KEY` names, else `CAUTHY_ISSUER`. */
  issuer?: string
  /**
   * This endpoint's own public address, exactly as it is registered in Cauthy.
   * Default: the request's URL, which is right unless a proxy changes it.
   */
  url?: string
  /** Cauthy's keys. Default: fetched from the issuer and cached. */
  jwks?: JWTVerifyGetKey
  /** The moment to verify at. Default: now. */
  now?: Date
  /**
   * Where deliveries already taken are remembered, so the same signed
   * delivery sent twice is refused. Default for verifyWebhook: none;
   * `auth.webhook` remembers them in memory unless it is given one.
   */
  replay?: ReplayStore
}

/**
 * Remembers what was already taken. `claim` answers true the first time a
 * key is claimed and false after, until `until` passes.
 *
 * A delivery Cauthy sends again after a failure is signed again, and passes:
 * what is refused is the very same signed delivery arriving twice. Make what
 * an event does safe to do twice anyway (its `id` stays the same).
 */
export interface ReplayStore {
  claim(key: string, until: Date): Promise<boolean>
}

/** Deliveries remembered in this process's memory: enough with one instance. */
export function memoryReplayStore(now: () => number = Date.now): ReplayStore {
  const seen = new Map<string, number>()
  return {
    async claim(key, until) {
      const t = now()
      if (seen.size > 10_000) for (const [k, u] of seen) if (u <= t) seen.delete(k)
      const held = seen.get(key)
      if (held !== undefined && held > t) return false
      seen.set(key, until.getTime())
      return true
    },
  }
}

const keys = new Map<string, JWTVerifyGetKey>()

function keysOf(issuer: string): JWTVerifyGetKey {
  let set = keys.get(issuer)
  if (set === undefined) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`), { cooldownDuration: 30_000 })
    keys.set(issuer, set)
  }
  return set
}

const hex = (s: unknown) => (typeof s === 'string' && s !== '' ? s : undefined)

/**
 * Verifies a delivery and answers the event it carries. Throws
 * `CauthyWebhookError` for anything that is not a delivery Cauthy made for
 * this endpoint just now: answer it 401 and nothing else.
 */
export async function verifyWebhook(request: Request, options: VerifyWebhookOptions = {}): Promise<CauthyEvent> {
  // CAUTHY_KEY names Cauthy; without it, CAUTHY_ISSUER does (deprecated).
  const key = typeof process !== 'undefined' ? process.env?.CAUTHY_KEY : undefined
  const env = key ? parseKey(key).issuer : typeof process !== 'undefined' ? process.env?.CAUTHY_ISSUER : undefined
  const issuer = withoutTrailingSlashes(options.issuer ?? env ?? '')
  if (issuer === '') throw new CauthyWebhookError('issuer (CAUTHY_ISSUER) is not set')
  const signature = request.headers.get('x-cauthy-signature-jwt')
  if (!signature) throw new CauthyWebhookError('no signature')

  // The bytes as they arrived: what was signed is their hash, not a re-encoding.
  const raw = new Uint8Array(await request.arrayBuffer())
  const audience = options.url ?? request.url.split('?')[0]

  let claims: Record<string, unknown>
  try {
    const verified = await jwtVerify(signature, options.jwks ?? keysOf(issuer), {
      algorithms: ['RS256'],
      audience,
      typ: 'cauthy-webhook+jwt',
      requiredClaims: ['exp', 'iat', 'jti', 'body_sha256'],
      currentDate: options.now,
      clockTolerance: 30,
    })
    claims = verified.payload as Record<string, unknown>
  } catch (err) {
    throw new CauthyWebhookError(err instanceof Error ? err.message : 'bad signature')
  }
  // Signed by Cauthy, for this issuer: Cauthy's own address, or the
  // workspace's custom domain (domain_iss) when that is the issuer here.
  if (claims.iss !== issuer && claims.domain_iss !== issuer) {
    throw new CauthyWebhookError('unexpected "iss" claim value')
  }

  // Not from the future either: a clock that far off is not Cauthy's.
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000)
  if (typeof claims.iat !== 'number' || claims.iat > now + 30) throw new CauthyWebhookError('signed in the future')

  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw))
  let b64 = ''
  for (const b of digest) b64 += String.fromCharCode(b)
  const hash = btoa(b64).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  if (hash !== claims.body_sha256) throw new CauthyWebhookError('the body is not the one that was signed')

  let body: Record<string, any>
  try {
    body = JSON.parse(new TextDecoder().decode(raw))
  } catch {
    throw new CauthyWebhookError('the body is not JSON')
  }
  // The envelope and the signature must tell the same story.
  if (body.id !== claims.jti || body.event !== claims.evt || body.tenant_id !== claims.tid) {
    throw new CauthyWebhookError('the body and its signature disagree')
  }
  if (options.replay) {
    // The same signature twice is a replay; a delivery sent again is signed again.
    const exp = typeof claims.exp === 'number' ? claims.exp : now + 300
    if (!(await options.replay.claim(`${String(claims.jti)}:${String(claims.iat)}`, new Date(exp * 1000)))) {
      throw new CauthyWebhookError('this delivery was already taken')
    }
  }
  const inner = (body.data ?? {}) as Record<string, any>
  return {
    id: String(body.id),
    type: String(body.event),
    tenantId: String(body.tenant_id),
    createdAt: String(inner.created_at ?? body.created_at ?? ''),
    ...(hex(inner.user_id) ? { userId: inner.user_id } : {}),
    ...(hex(inner.actor_id) ? { actorId: inner.actor_id } : {}),
    data: (inner.data ?? {}) as Record<string, JsonValue>,
  }
}
