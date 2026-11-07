// Is it this handler that answers under basePath? Another route there — a
// catch-all of another auth library, a proxy rule, a route registered first —
// takes the requests silently. Every answer of the handler carries
// Cauthy-Protocol and nothing else's does: three requests that reach nothing
// in Cauthy tell them apart.

import { PROTOCOL_VERSION } from './protocol'
import { CauthyConfigError } from './types'
import { withoutTrailingSlashes } from './url'

/**
 * Where the probes go: the running application's origin
 * (`'http://localhost:3000'`), or a function that serves a request in
 * process (Hono's `app.fetch`, `checkFastifyMount` for Fastify).
 */
export type MountTarget = string | ((request: Request) => Response | Promise<Response>)

export async function checkMount(basePath: string, target: MountTarget): Promise<void> {
  const origin = typeof target === 'string' ? withoutTrailingSlashes(target) : 'http://localhost'
  if (!/^https?:\/\/[^/\s]+$/.test(origin)) {
    throw new CauthyConfigError(`checkMount needs the application's origin, e.g. http://localhost:3000, not ${JSON.stringify(target)}`)
  }
  const send = typeof target === 'string' ? (r: Request) => fetch(r, { redirect: 'manual' }) : target
  const probes = [
    new Request(`${origin}${basePath}/session`, { headers: { accept: 'application/json' } }),
    new Request(`${origin}${basePath}/cauthy-mount-check`),
    new Request(`${origin}${basePath}/sign-out`, { method: 'POST', headers: { origin, 'content-type': 'application/json', 'x-cauthy-request': '1' }, body: '{}' }),
  ]
  for (const probe of probes) {
    const what = `${probe.method} ${new URL(probe.url).pathname}`
    let res: Response
    try {
      res = await send(probe)
    } catch (err) {
      throw new CauthyConfigError(`could not reach ${what} to check where the handler is mounted: ${(err as Error).message}`)
    }
    await res.body?.cancel()
    if (res.headers.get('cauthy-protocol') !== PROTOCOL_VERSION) {
      throw new CauthyConfigError(`${what} answered ${res.status} without Cauthy-Protocol: ${PROTOCOL_VERSION}: something other than this handler answers under ${basePath}. ` +
        'Move that route, mount Cauthy before it, or give Cauthy another basePath.')
    }
  }
}
