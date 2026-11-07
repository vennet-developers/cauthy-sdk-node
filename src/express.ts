// Express (and anything else that speaks Node's http): the routes, and who is
// signed in on every request.
//
//   app.use(cauthyExpress(auth))
//
//   app.get('/api/me', async (req, res) => {
//     const session = await req.cauthy()
//     if (!session) return res.status(401).json({ error: 'unauthenticated' })
//     res.json(session.user)
//   })
//
//   app.get('/api/books', requireSession, (req, res) => { … })
//
// A session that needs renewing is renewed on the spot, and its new cookie
// leaves with whatever the route answers.

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Cauthy } from './cauthy'
import type { Session } from './types'

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Who is signed in, or null. Asked once per request. */
      cauthy(): Promise<Session | null>
    }
  }
}

/** A request as Node gives it, with what Express adds when it is Express. */
type NodeRequest = IncomingMessage & { originalUrl?: string; protocol?: string; ip?: string; body?: unknown; cauthy?: () => Promise<Session | null> }
type Next = (error?: unknown) => void

function originOf(req: NodeRequest): string {
  const secure = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true
  return `${req.protocol ?? (secure ? 'https' : 'http')}://${req.headers.host ?? 'localhost'}`
}

async function bodyOf(req: NodeRequest): Promise<BodyInit | undefined> {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined
  // A body parser was here first (express.json()): what it read is the body.
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') return req.body
    if (req.body instanceof Uint8Array) return new Uint8Array(req.body)
    return JSON.stringify(req.body)
  }
  const chunks: Uint8Array[] = []
  for await (const chunk of req) chunks.push(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : (chunk as Uint8Array))
  return chunks.length === 0 ? undefined : new Blob(chunks as BlobPart[])
}

async function toWebRequest(req: NodeRequest, withBody: boolean): Promise<Request> {
  const headers = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) for (const one of v) headers.append(k, one)
    else if (v !== undefined) headers.set(k, v)
  }
  // Express knows who is calling (it applies `trust proxy`): that address is
  // the one passed on to Cauthy, whatever the header claimed.
  if (typeof req.ip === 'string' && req.ip !== '') headers.set('x-forwarded-for', req.ip)
  return new Request(new URL(req.originalUrl ?? req.url ?? '/', originOf(req)), {
    method: req.method,
    headers,
    body: withBody ? await bodyOf(req) : undefined,
  })
}

function addCookies(res: ServerResponse, cookies: string[]): void {
  if (cookies.length === 0 || res.headersSent) return
  const had = res.getHeader('set-cookie')
  res.setHeader('set-cookie', [...(Array.isArray(had) ? had : typeof had === 'string' ? [had] : []), ...cookies])
}

/**
 * Serves the routes under the handler's `basePath` (and, by contract, the
 * application's published key), and gives every other
 * request `req.cauthy()`. Mount it once, before the routes that use it.
 */
export function cauthyExpress(auth: Cauthy) {
  const base = auth.options.basePath
  // By contract the application also publishes its key, outside basePath.
  const key = auth.pact?.contract.jwksPath
  return function cauthy(req: IncomingMessage, res: ServerResponse, next: Next): void {
    const request = req as NodeRequest
    const path = (request.originalUrl ?? request.url ?? '/').split('?')[0]

    if (path === base || path.startsWith(`${base}/`) || path === key) {
      void (async () => {
        const answer = await auth.handler(await toWebRequest(request, true))
        res.statusCode = answer.status
        answer.headers.forEach((value, name) => {
          if (name !== 'set-cookie') res.setHeader(name, value)
        })
        addCookies(res, answer.headers.getSetCookie())
        res.end(answer.body === null ? undefined : Buffer.from(await answer.arrayBuffer()))
      })().catch(next)
      return
    }

    let asked: Promise<Session | null> | undefined
    request.cauthy = () =>
      (asked ??= (async () => {
        const resolved = await auth.resolve(await toWebRequest(request, false))
        addCookies(res, resolved.cookies)
        return resolved.session
      })())
    next()
  }
}

/** For a route only a signed-in person may call: answers 401 otherwise. Needs `cauthyExpress` mounted before it. */
export function requireSession(req: IncomingMessage, res: ServerResponse, next: Next): void {
  const ask = (req as NodeRequest).cauthy
  if (!ask) return next(new Error('@cauthyhq/node: mount cauthyExpress(auth) before requireSession'))
  ask().then((session) => {
    if (session !== null) return next()
    res.statusCode = 401
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('x-cauthy-session', 'none')
    res.end(JSON.stringify({ error: 'unauthenticated' }))
  }, next)
}
