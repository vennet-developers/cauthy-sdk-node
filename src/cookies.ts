// Cookies, by hand: reading the Cookie header and writing Set-Cookie.
//
// A session can outgrow one cookie (browsers stop near 4 KB), so a value is
// written in numbered parts — name.0, name.1 — and read back in order.

const PART = 3500

export function readCookies(header: string | null | undefined): Map<string, string> {
  const out = new Map<string, string>()
  for (const pair of (header ?? '').split(';')) {
    const i = pair.indexOf('=')
    if (i > 0) out.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim())
  }
  return out
}

/** A value written in parts, or null when the cookie is not there. */
export function readParts(cookies: Map<string, string>, name: string): string | null {
  let value = ''
  for (let i = 0; cookies.has(`${name}.${i}`); i++) value += cookies.get(`${name}.${i}`)
  return value === '' ? null : value
}

export interface CookieAttributes {
  secure: boolean
  maxAge?: number // seconds; 0 deletes; none makes a cookie that ends with the browser session
  path?: string
}

function attributes(a: CookieAttributes): string {
  // httpOnly: script never reads it. SameSite=Lax: it rides the navigation
  // that comes back from Cauthy, and no cross-site form post.
  return `Path=${a.path ?? '/'}; HttpOnly; SameSite=Lax${a.maxAge === undefined ? '' : `; Max-Age=${a.maxAge}`}${a.secure ? '; Secure' : ''}`
}

export function writeCookie(name: string, value: string, a: CookieAttributes): string {
  return `${name}=${value}; ${attributes(a)}`
}

/**
 * The Set-Cookie headers that store a value in parts and delete whatever
 * parts an earlier, longer value left behind.
 */
export function writeParts(name: string, value: string, a: CookieAttributes, had: Map<string, string>): string[] {
  const out: string[] = []
  let n = 0
  for (let i = 0; i < value.length; i += PART) out.push(writeCookie(`${name}.${n++}`, value.slice(i, i + PART), a))
  for (let i = n; had.has(`${name}.${i}`); i++) out.push(writeCookie(`${name}.${i}`, '', { ...a, maxAge: 0 }))
  return out
}

export function clearParts(name: string, a: CookieAttributes, had: Map<string, string>): string[] {
  const out: string[] = []
  for (let i = 0; had.has(`${name}.${i}`) || i === 0; i++) out.push(writeCookie(`${name}.${i}`, '', { ...a, maxAge: 0 }))
  return out
}
