// Who the application is, asked of Cauthy (key/cauthy-key.md §7): once at
// start, then revalidated every five minutes with If-None-Match. Cauthy down:
// the last answer stands; never one yet: the auth routes say 503 unavailable
// until it comes. Cauthy refusing the key (invalid_client): 503 misconfigured,
// logged once with the kid.
import { CauthyApiError } from './system'

/** What `GET /v1/connect/self` answers. */
export interface Identity {
  issuer: string
  audience: string
  tenant: { id: string; slug: string }
  system: string
  client_id: string
  sign_in_client_id: string
  app_urls: string[]
  callback_path: string
  key: { kid: string; retires_at: string | null } | null
  contract: { link: string; system_proof?: 'off' | 'auto' | 'required'; require_verified_email?: boolean; in_step?: boolean; checked_at?: string } | null
}

export interface IdentityOptions {
  issuer: string
  /** The application's own access token (the system client's). */
  token: () => Promise<string>
  fetch?: typeof globalThis.fetch
  now?: () => number
  /** Backoff between first attempts, ms; the last repeats. */
  retryMs?: number[]
  /** For the log line when Cauthy refuses the key. */
  kid?: string
  log?: (message: string) => void
}

export interface IdentityCache {
  /** The identity, waiting for the first answer. Rejects with 503 misconfigured when Cauthy refuses the key. */
  ready(): Promise<Identity>
  /** The last answer, or undefined before the first. */
  current(): Identity | undefined
  /** Revalidates now; keeps the last answer on any failure. */
  refresh(): Promise<void>
}

export const REVALIDATE_MS = 300_000

const sleep = (ms: number) => new Promise<void>((resolve) => {
  const t = setTimeout(resolve, ms)
  ;(t as { unref?: () => void }).unref?.()
})

export function createIdentity(o: IdentityOptions): IdentityCache {
  const doFetch = o.fetch ?? globalThis.fetch
  const now = o.now ?? Date.now
  const retry = o.retryMs ?? [1000, 2000, 5000, 10_000, 30_000]
  let held: Identity | undefined
  let etag: string | undefined
  let checkedAt = 0
  let first: Promise<Identity> | undefined
  let refused: CauthyApiError | undefined
  let refreshing: Promise<void> | undefined

  async function ask(): Promise<Identity | 'same'> {
    const headers: Record<string, string> = { authorization: `Bearer ${await o.token()}`, accept: 'application/json' }
    if (etag && held) headers['if-none-match'] = etag
    const res = await doFetch(`${o.issuer}/v1/connect/self`, { headers })
    if (res.status === 304 && held) return 'same'
    if (res.status === 410) throw Object.assign(new Error('client_inactive'), { code: 'client_inactive' })
    if (!res.ok) throw new CauthyApiError(503, 'unavailable', `Cauthy answered ${res.status} to /v1/connect/self`)
    const body = (await res.json()) as { data?: Identity }
    if (!body?.data || typeof body.data.client_id !== 'string') throw new CauthyApiError(503, 'unavailable', 'Cauthy\'s answer to /v1/connect/self has no identity')
    etag = res.headers.get('etag') ?? undefined
    return body.data
  }

  /** Cauthy refuses the key itself: not a failure to reach it. */
  function refusalOf(e: unknown): CauthyApiError | undefined {
    const code = (e as { code?: string } | null)?.code
    if (code !== 'invalid_client' && code !== 'client_inactive') return undefined
    const message = code === 'client_inactive'
      ? `Cauthy says this application's client is no longer active (kid ${o.kid ?? '?'}). Connect it again in Cauthy's dashboard.`
      : `Cauthy refuses this application's key (kid ${o.kid ?? '?'}): it was revoked or never registered. Make a new key in Cauthy's dashboard.`
    return new CauthyApiError(503, 'misconfigured', message)
  }

  function refuse(err: CauthyApiError): CauthyApiError {
    if (refused === undefined) o.log?.(err.message.replace(/^@cauthyhq\/node: /, ''))
    refused = err
    // Asked again at the next revalidation, not before: a refused key does not loop.
    checkedAt = now()
    return err
  }

  async function firstAnswer(): Promise<Identity> {
    for (let attempt = 0; ; attempt++) {
      try {
        const got = await ask()
        if (got !== 'same') held = got
        checkedAt = now()
        return held as Identity
      } catch (e) {
        const r = refusalOf(e)
        if (r) throw refuse(r)
        await sleep(retry[Math.min(attempt, retry.length - 1)])
      }
    }
  }

  async function refresh(): Promise<void> {
    checkedAt = now()
    try {
      const got = await ask()
      if (got !== 'same') held = got
      refused = undefined
    } catch (e) {
      const r = refusalOf(e)
      if (r) refuse(r)
      // Otherwise the last answer stands.
    }
  }

  return {
    ready(): Promise<Identity> {
      if ((held || refused) && now() - checkedAt >= REVALIDATE_MS) {
        refreshing ??= refresh().finally(() => { refreshing = undefined })
      }
      if (refused) return Promise.reject(refused)
      if (held) return Promise.resolve(held)
      first ??= firstAnswer()
      return first
    },
    current: () => held,
    refresh: () => (refreshing ??= refresh().finally(() => { refreshing = undefined })),
  }
}
