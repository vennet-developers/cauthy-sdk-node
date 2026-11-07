// Fastify: the routes, and who is signed in on every request.
//
//   await app.register(cauthyFastify, { auth })
//
//   app.get('/api/me', async (req, reply) => {
//     const session = await req.cauthy()
//     if (!session) return reply.code(401).send({ error: 'unauthenticated' })
//     return session.user
//   })
//
//   app.get('/api/books', { preHandler: app.requireSession }, async (req) => { … })
//
// Here a session that needs renewing is renewed on the spot: Fastify has the
// reply in hand, so the new cookie always goes back.

import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'
import type { Cauthy } from './cauthy'
import type { Session } from './types'

declare module 'fastify' {
  interface FastifyRequest {
    /** Who is signed in, or null. Asked once per request. */
    cauthy(): Promise<Session | null>
  }
  interface FastifyInstance {
    /** A preHandler that answers 401 unless somebody is signed in. */
    requireSession(request: FastifyRequest, reply: FastifyReply): Promise<void>
  }
}

export interface CauthyFastifyOptions {
  auth: Cauthy
}

function originOf(req: FastifyRequest): string {
  return `${req.protocol}://${req.headers.host ?? 'localhost'}`
}

function toWebRequest(req: FastifyRequest): Request {
  const headers = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) for (const one of v) headers.append(k, one)
    else if (v !== undefined) headers.set(k, v)
  }
  // Fastify knows who is calling (it applies `trustProxy`): that address is
  // the one passed on to Cauthy, whatever the header claimed.
  headers.set('x-forwarded-for', req.ip)
  // What Fastify parsed is the body: the application's own sign-in screens post JSON.
  const body = req.method === 'GET' || req.method === 'HEAD' || req.body === undefined || req.body === null
    ? undefined
    : typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
  return new Request(new URL(req.url, originOf(req)), { method: req.method, headers, body })
}

const kSession = Symbol('cauthy.session')
const kReply = Symbol('cauthy.reply')

const plugin: FastifyPluginAsync<CauthyFastifyOptions> = async (app: FastifyInstance, { auth }) => {
  const base = auth.options.basePath

  app.decorateRequest('cauthy', async function (this: FastifyRequest): Promise<Session | null> {
    const self = this as FastifyRequest & { [kSession]?: Promise<Session | null> }
    self[kSession] ??= (async () => {
      const resolved = await auth.resolve(toWebRequest(this))
      // Set through the raw response so the cookie leaves whatever the route
      // answers with, even an error.
      const reply = (this as FastifyRequest & { [kReply]?: FastifyReply })[kReply]
      if (resolved.cookies.length > 0 && reply) reply.header('set-cookie', resolved.cookies)
      return resolved.session
    })()
    return self[kSession]
  })

  app.addHook('onRequest', async (req, reply) => {
    ;(req as FastifyRequest & { [kReply]?: FastifyReply })[kReply] = reply
  })

  app.decorate('requireSession', async function (request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if ((await request.cauthy()) === null) {
      await reply.code(401).header('x-cauthy-session', 'none').send({ error: 'unauthenticated' })
    }
  })

  const serve = async (req: FastifyRequest, reply: FastifyReply) => {
    const res = await auth.handler(toWebRequest(req))
    reply.code(res.status)
    res.headers.forEach((value, name) => {
      if (name !== 'set-cookie') reply.header(name, value)
    })
    const cookies = res.headers.getSetCookie()
    if (cookies.length > 0) reply.header('set-cookie', cookies)
    return reply.send(res.body === null ? null : Buffer.from(await res.arrayBuffer()))
  }
  app.route({ method: ['GET', 'POST'], url: `${base}/*`, handler: serve })
}


// Outside encapsulation: `req.cauthy()` and `requireSession` are for the whole
// application, not only for routes registered beside this plugin.
;(plugin as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true
;(plugin as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] = '@cauthyhq/node'

export const cauthyFastify = plugin
export default plugin
