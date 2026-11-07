import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import ts from 'typescript'
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

// The types 0.42 exported are checked by `npm run typecheck`, which compiles
// test-support/compat-types.ts. This test keeps that list complete: it reads
// the type-only exports of every cauthy-auth entry and wants each one named.
describe('what cauthy-auth 0.42 exported as a type', () => {
  const dist = resolve(__dirname, '../node_modules/cauthy-auth/dist')
  const listed = readFileSync(resolve(__dirname, '../test-support/compat-types.ts'), 'utf8')
  const typeOnly = (entry: string): string[] => {
    const file = resolve(dist, `${entry}.d.ts`)
    const program = ts.createProgram([file], { moduleResolution: ts.ModuleResolutionKind.Bundler, module: ts.ModuleKind.ESNext, skipLibCheck: true, noEmit: true })
    const checker = program.getTypeChecker()
    const source = program.getSourceFile(file)!
    return checker.getExportsOfModule(checker.getSymbolAtLocation(source)!)
      .filter((symbol) => {
        const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol
        return !(target.flags & ts.SymbolFlags.Value)
      })
      .map((symbol) => symbol.name)
  }

  it.each(['index', 'express', 'fastify', 'hono', 'next', 'mcp', 'keys', 'theme'])('%s: every type is in compat-types.ts', (entry) => {
    const names = typeOnly(entry)
    const ns = `Entry_${entry === 'index' ? 'root' : entry}`
    expect(names.length > 0 || entry === 'express').toBe(true)
    expect(names.filter((name) => !new RegExp(`${ns}\\.${name}\\b`).test(listed))).toEqual([])
  })
})
