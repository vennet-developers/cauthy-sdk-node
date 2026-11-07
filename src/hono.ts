// Hono: the routes, and who is signed in on every request.
//
//   const app = new Hono<{ Variables: CauthyVariables }>()
//   app.use(cauthyHono(auth))
//
//   app.get('/api/me', (c) => {
//     const session = c.get('session')
//     return session ? c.json(session.user) : c.json({ error: 'unauthenticated' }, 401)
//   })
//
//   app.get('/api/books', requireSession, (c) => { … })
//
// A session that needs renewing is renewed on the spot, and its new cookie
// leaves with whatever the route answers. It runs wherever Hono does.

import type { MiddlewareHandler } from 'hono'
import type { Cauthy } from './cauthy'
import type { Session } from './types'

/** What the middleware keeps on the context: `new Hono<{ Variables: CauthyVariables }>()`. */
export interface CauthyVariables {
  /** Who is signed in, or null. */
  session: Session | null
}

type Env = { Variables: CauthyVariables }

/**
 * Serves the routes under the handler's `basePath` (and, by contract, the
 * application's published key), and sets `session` for
 * every other request. Mount it once, before the routes that use it.
 */
export function cauthyHono(auth: Cauthy): MiddlewareHandler<Env> {
  const base = auth.options.basePath
  // By contract the application also publishes its key, outside basePath.
  const key = auth.pact?.contract.jwksPath
  return async (c, next) => {
    const path = new URL(c.req.url).pathname
    if (path === base || path.startsWith(`${base}/`) || path === key) return auth.handler(c.req.raw)

    const resolved = await auth.resolve(c.req.raw)
    c.set('session', resolved.session)
    await next()
    for (const cookie of resolved.cookies) c.header('set-cookie', cookie, { append: true })
  }
}

/** For a route only a signed-in person may call: answers 401 otherwise. Needs `cauthyHono` mounted before it. */
export const requireSession: MiddlewareHandler<Env> = async (c, next) => {
  if (c.get('session') === null || c.get('session') === undefined) {
    c.header('x-cauthy-session', 'none')
    return c.json({ error: 'unauthenticated' }, 401)
  }
  await next()
}
