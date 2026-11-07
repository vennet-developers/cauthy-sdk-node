// Copied from cauthy-auth 0.42 so the tests can drive the server the way a
// browser does. Not published: the browser client ships in @cauthyhq/js.

// Who is signed in, kept for the browser: the same thing <CauthyProvider>
// keeps for React, with no framework in it. `@cauthyhq/node/vue` and
// `@cauthyhq/node/svelte` are this store in each one's own terms, and anything
// else (Solid, Angular, a page with no framework) can use it as it is.
//
//   const store = createSessionStore()
//   const stop = store.subscribe(({ session, status }) => render(session))
//   await store.auth.signIn.email({ email, password })   // subscribers hear the new session
//
// While somebody listens it asks the server who is signed in, asks again
// shortly before the session's token runs out, and when the tab is looked at
// again. With nobody listening it does nothing.

import { createAuthClient, type AuthClient, type AuthClientOptions } from './client'
import type { PublicSession } from '../src/types'
import { withoutTrailingSlashes } from '../src/url'

export interface SessionState {
  /** The signed-in person and their organizations, or null. */
  session: PublicSession | null
  status: 'loading' | 'authenticated' | 'unauthenticated'
}

export interface SessionStoreOptions extends AuthClientOptions {
  /**
   * The session the server already read while rendering (SSR): the first
   * paint is then right, with no "loading". `null` means "nobody"; leave it
   * out when the server did not look.
   */
  initialSession?: PublicSession | null
}

export interface SessionStore {
  /** What is known now. */
  get(): SessionState
  /** Calls `listener` now and on every change. Answers how to stop. */
  subscribe(listener: (state: SessionState) => void): () => void
  /** Asks the server again who is signed in. */
  refresh(): Promise<PublicSession | null>
  /** Sends the browser to Cauthy's page to sign in, and back to `returnTo` (default: where it is now). */
  signIn(options?: { returnTo?: string; locale?: string; prompt?: 'login' }): void
  /** Signs out of this application and of Cauthy in this browser. */
  signOut(): void
  /** Where the person looks after their account on Cauthy's page. */
  accountUrl(returnTo?: string): string
  /**
   * The functions of an application's own screens. They are
   * `createAuthClient()`'s, and what changes who is signed in is heard by the
   * subscribers with no reload.
   */
  auth: AuthClient
  /** Where the server mounted the routes. */
  basePath: string
}

/** Ask again this long before the session's token runs out. */
const AHEAD_MS = 60_000

export function createSessionStore(options: SessionStoreOptions = {}): SessionStore {
  const base = withoutTrailingSlashes(options.basePath ?? '/api/auth')
  const doFetch: typeof fetch = (...args) => (options.fetch ?? fetch)(...args)
  const first = options.initialSession
  let state: SessionState = { session: first ?? null, status: first === undefined ? 'loading' : first === null ? 'unauthenticated' : 'authenticated' }
  const listeners = new Set<(state: SessionState) => void>()
  let asking: Promise<PublicSession | null> | null = null
  let timer: ReturnType<typeof setTimeout> | undefined
  let asked = first !== undefined

  const set = (next: SessionState) => {
    if (next.session === state.session && next.status === state.status) return
    state = next
    schedule()
    for (const l of [...listeners]) l(state)
  }

  function schedule(): void {
    clearTimeout(timer)
    timer = undefined
    if (listeners.size === 0 || state.session === null) return
    const wait = Math.max(new Date(state.session.expiresAt).getTime() - Date.now() - AHEAD_MS, 5_000)
    timer = setTimeout(() => void refresh(), wait)
  }

  function refresh(): Promise<PublicSession | null> {
    asked = true
    asking ??= (async () => {
      try {
        const res = await doFetch(`${base}/session`, { credentials: 'same-origin', headers: { accept: 'application/json' } })
        if (!res.ok) throw new Error(String(res.status))
        const body = (await res.json()) as { session: PublicSession | null; status: string }
        // "expired" is the server unable to reach Cauthy: what is on screen
        // stays, and the next ask settles it.
        if (body.status !== 'expired') set({ session: body.session, status: body.session ? 'authenticated' : 'unauthenticated' })
        return body.session
      } catch {
        if (state.status === 'loading') set({ session: null, status: 'unauthenticated' })
        return null
      } finally {
        asking = null
      }
    })()
    return asking
  }

  const onVisible = () => {
    if (document.visibilityState === 'visible') void refresh()
  }
  const inBrowser = () => typeof document !== 'undefined'

  const client = createAuthClient({ basePath: base, fetch: options.fetch })
  const then = async <T,>(running: Promise<T>): Promise<T> => {
    const r = await running
    await refresh()
    return r
  }

  return {
    get: () => state,
    subscribe(listener) {
      listeners.add(listener)
      if (listeners.size === 1 && inBrowser()) {
        document.addEventListener('visibilitychange', onVisible)
        schedule()
        if (!asked) void refresh()
      }
      listener(state)
      return () => {
        listeners.delete(listener)
        if (listeners.size === 0) {
          clearTimeout(timer)
          timer = undefined
          if (inBrowser()) document.removeEventListener('visibilitychange', onVisible)
        }
      }
    },
    refresh,
    signIn(o = {}) {
      const q = new URLSearchParams({ return_to: o.returnTo ?? window.location.pathname + window.location.search })
      if (o.locale) q.set('locale', o.locale)
      if (o.prompt) q.set('prompt', o.prompt)
      window.location.assign(`${base}/login?${q}`)
    },
    signOut() {
      window.location.assign(`${base}/logout`)
    },
    accountUrl(returnTo) {
      const back = returnTo ?? (typeof window === 'undefined' ? '/' : window.location.pathname + window.location.search)
      return `${base}/account?return_to=${encodeURIComponent(back)}`
    },
    auth: {
      ...client,
      signIn: {
        ...client.signIn,
        email: (f) => then(client.signIn.email(f)),
        mfa: (f) => then(client.signIn.mfa(f)),
        magicLinkVerify: (f) => then(client.signIn.magicLinkVerify(f)),
        emailCode: (f) => then(client.signIn.emailCode(f)),
        passkey: (o) => then(client.signIn.passkey(o)),
      },
      signUp: { email: (f) => then(client.signUp.email(f)) },
      signOut: () => then(client.signOut()),
      account: {
        ...client.account,
        update: (f) => then(client.account.update(f)),
        changePassword: (f) => then(client.account.changePassword(f)),
        signOutEverywhere: () => then(client.account.signOutEverywhere()),
      },
    },
    basePath: base,
  }
}
