import { describe, expect, it } from 'vitest'

// Every name cauthy-auth 0.42 exported from a server entry, @cauthyhq/node
// exports from the same entry: moving is changing the import.
type Load = () => Promise<Record<string, unknown>>
const entries: [string, Load, Load][] = [
  ['.', () => import('cauthy-auth'), () => import('./index')],
  ['/express', () => import('cauthy-auth/express'), () => import('./express')],
  ['/fastify', () => import('cauthy-auth/fastify'), () => import('./fastify')],
  ['/hono', () => import('cauthy-auth/hono'), () => import('./hono')],
  ['/next', () => import('cauthy-auth/next'), () => import('./next')],
  ['/mcp', () => import('cauthy-auth/mcp'), () => import('./mcp')],
  ['/keys', () => import('cauthy-auth/keys'), () => import('./keystores')],
  ['/theme', () => import('cauthy-auth/theme'), () => import('./theme')],
]

describe('what cauthy-auth 0.42 exported', () => {
  it.each(entries)('%s is all still here', async (_entry, theirs, ours) => {
    const [a, b] = await Promise.all([theirs(), ours()])
    expect(Object.keys(a).filter((name) => !(name in b))).toEqual([])
  })
})
