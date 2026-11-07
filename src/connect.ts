// Connecting an application to Cauthy in one call: its client, where its
// people come back to, where it hears events, and its own identity. It is what
// `cauthy-auth init` runs, and what Cauthy's dashboard does under "Connect a
// system".

import { withoutTrailingSlashes } from './url'

export interface ConnectOptions {
  /** The system's name, as its organizations are filed under: lowercase, digits, - or _. */
  system: string
  /** The application's public address: `https://app.example.com`, or `http://localhost:3000` while developing. */
  appUrl: string
  /** Shown to people on Cauthy's pages. Default: the system's name. */
  name?: string
  /** Where the application serves the return from a sign-in. Default: `/api/auth/callback`. */
  callbackPath?: string
  /** An https address of the application that receives Cauthy's events. */
  eventsUrl?: string
  /** The events to receive. Default: all of them. */
  events?: string[]
  /** Where the application publishes its keys, to prove itself without a secret. */
  jwksUri?: string
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The workspace's slug. Default: `CAUTHY_TENANT`. */
  tenant?: string
  /** A personal access token with `systems:connect`. Default: `CAUTHY_TOKEN`. */
  token?: string
  fetch?: typeof fetch
}

export interface Connected {
  system: string
  clientId: string
  /** Shown this once: Cauthy keeps only its hash. */
  clientSecret: string
  redirectUris: string[]
  /**
   * The subscription to events, when `eventsUrl` was given. Its `secret` signs
   * the HMAC header (X-Cauthy-Signature) and is shown this once; `auth.webhook`
   * does not need it, as it verifies by Cauthy's published keys.
   */
  webhook: { id: string; url: string; events: string[]; secret: string } | null
  /**
   * Everything the application sets: what Cauthy answered, plus CAUTHY_SECRET,
   * the key of the session cookie, generated here and known to nobody else.
   */
  env: Record<string, string>
}

function sessionSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function connectSystem(o: ConnectOptions): Promise<Connected> {
  const env = (n: string) => (typeof process !== 'undefined' ? process.env?.[n] : undefined)
  const issuer = withoutTrailingSlashes(o.issuer ?? env('CAUTHY_ISSUER') ?? '')
  const tenant = o.tenant ?? env('CAUTHY_TENANT') ?? ''
  const token = o.token ?? env('CAUTHY_TOKEN') ?? ''
  for (const [name, v] of Object.entries({ CAUTHY_ISSUER: issuer, CAUTHY_TENANT: tenant, CAUTHY_TOKEN: token })) {
    if (v === '') throw new Error(`cauthy-auth: ${name} is required to connect a system`)
  }
  const res = await (o.fetch ?? fetch)(`${issuer}/v1/connect`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'x-tenant-key': tenant, 'content-type': 'application/json' },
    body: JSON.stringify({ system: o.system, app_url: o.appUrl, name: o.name, callback_path: o.callbackPath,
      events_url: o.eventsUrl, events: o.events, jwks_uri: o.jwksUri }),
  })
  const body = (await res.json().catch(() => null)) as {
    data?: { system: string; client_secret: string; client: { client_id: string; redirect_uris: string[] }
      webhook: Connected['webhook']; env: Record<string, string> }
    errors?: { field?: string; message?: string }[]
  } | null
  if (!res.ok || !body?.data) {
    const why = (body?.errors ?? []).map((e) => e.message).filter(Boolean).join('; ') || res.statusText
    throw new Error(`cauthy-auth: Cauthy did not connect the system (${res.status}): ${why}`)
  }
  const d = body.data
  return { system: d.system, clientId: d.client.client_id, clientSecret: d.client_secret, redirectUris: d.client.redirect_uris,
    webhook: d.webhook, env: { ...d.env, CAUTHY_SECRET: sessionSecret() } }
}

/** The variables as the lines of an env file. */
export function envFile(env: Record<string, string>): string {
  return Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n'
}
