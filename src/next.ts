// Next.js (App Router): the routes, who is signed in on the server, and a
// middleware that keeps the session renewed.
//
//   // lib/auth.ts
//   export const auth = createCauthy()
//   export const cauthy = cauthyNext(auth)
//
//   // app/api/auth/[...cauthy]/route.ts
//   export const { GET, POST } = cauthy
//
//   // middleware.ts
//   export default cauthy.middleware({ protect: (path) => path.startsWith('/app') })
//
//   // a server component, a route handler, a server action
//   const session = await cauthy.session()

import { headers } from 'next/headers'
import { NextResponse } from 'next/server'
import type { Cauthy } from './cauthy'
import type { Session } from './types'

export interface CauthyMiddlewareOptions {
  /** The pages only a signed-in person may see: anybody else is sent to sign in, and back. */
  protect?: (pathname: string) => boolean
}

export interface CauthyNext {
  GET(request: Request): Promise<Response>
  POST(request: Request): Promise<Response>
  /**
   * Who is signed in, or null: in a server component, a route handler or a
   * server action. A server component cannot set a cookie, so renewing an
   * expired session is the middleware's job: use `middleware()`.
   */
  session(): Promise<Session | null>
  /** For `middleware.ts`: renews the session when it has to be, and guards the pages named in `protect`. */
  middleware(options?: CauthyMiddlewareOptions): (request: Request) => Promise<Response>
}

/** The request's cookies with the ones a response sets applied, as the browser's next request would carry them. */
function cookiesAfter(header: string | null, setCookies: string[]): string {
  const jar = new Map<string, string>()
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=')
    if (i > 0) jar.set(part.slice(0, i).trim(), part.slice(i + 1).trim())
  }
  for (const c of setCookies) {
    const [pair, ...attrs] = c.split('; ')
    const i = pair.indexOf('=')
    if (i <= 0) continue
    if (pair.slice(i + 1) === '' || attrs.some((a) => a.toLowerCase() === 'max-age=0')) jar.delete(pair.slice(0, i))
    else jar.set(pair.slice(0, i), pair.slice(i + 1))
  }
  return [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
}

export function cauthyNext(auth: Cauthy): CauthyNext {
  const base = auth.options.basePath
  return {
    GET: (request) => auth.handler(request),
    POST: (request) => auth.handler(request),

    async session() {
      const h = await headers()
      const origin = `${h.get('x-forwarded-proto') ?? 'http'}://${h.get('x-forwarded-host') ?? h.get('host') ?? 'localhost'}`
      return auth.getSession(new Request(`${origin}/`, { headers: new Headers(h) }))
    },

    middleware(options = {}) {
      return async (request) => {
        const url = new URL(request.url)
        // The routes renew and clear the session themselves.
        if (url.pathname === base || url.pathname.startsWith(`${base}/`)) return NextResponse.next()

        const resolved = await auth.resolve(request)
        if (resolved.session === null && options.protect?.(url.pathname)) {
          const to = NextResponse.redirect(new URL(auth.urls.signIn(url.pathname + url.search), url))
          for (const c of resolved.cookies) to.headers.append('set-cookie', c)
          return to
        }
        if (resolved.cookies.length === 0) return NextResponse.next()

        // Renewed: the browser gets the new cookie, and so does what renders
        // this very request, which would otherwise still read the old one.
        const forwarded = new Headers(request.headers)
        forwarded.set('cookie', cookiesAfter(request.headers.get('cookie'), resolved.cookies))
        const on = NextResponse.next({ request: { headers: forwarded } })
        for (const c of resolved.cookies) on.headers.append('set-cookie', c)
        return on
      }
    },
  }
}
