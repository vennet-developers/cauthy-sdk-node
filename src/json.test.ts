import { describe, expect, it } from 'vitest'
import { parseStrict } from './json'

describe('the strict JSON reader of tokens', () => {
  it('reads what JSON.parse reads', () => {
    const text = '{"a":[1,2.5,{"b":null}],"c":"x\\u00e9","d":true,"e":-0}'
    expect(parseStrict(text)).toEqual(JSON.parse(text))
  })

  it('refuses a name repeated, at any depth', () => {
    expect(() => parseStrict('{"a":1,"a":2}')).toThrow(/repeated name/)
    expect(() => parseStrict('{"a":[{"b":1,"b":2}]}')).toThrow(/repeated name/)
    expect(parseStrict('{"a":{"b":1},"c":{"b":2}}')).toEqual({ a: { b: 1 }, c: { b: 2 } })
  })

  it('refuses what is not JSON', () => {
    for (const bad of ['', '{', '{"a":}', '{"a":1,}', '[1,]', '{"a":1} x', "{'a':1}", '01']) expect(() => parseStrict(bad)).toThrow(SyntaxError)
  })

  it('reads an integer beyond 2^53 as NaN, never rounded into range', () => {
    expect(parseStrict('9007199254740992')).toBe(9007199254740992)
    expect(parseStrict('9007199254740993')).toBeNaN()
    expect(parseStrict('-9007199254740993')).toBeNaN()
    expect(parseStrict('1e400')).toBe(Infinity)
  })

  it('refuses a fraction or an exponent where the claim must be an integer literal', () => {
    const only = ['exp', 'iat', 'nbf']
    expect(parseStrict('{"exp":1767225600}', only)).toEqual({ exp: 1767225600 })
    expect(parseStrict('{"exp":1767225600.0}', only)).toEqual({ exp: Number.NaN })
    expect(parseStrict('{"iat":1.7672256e9}', only)).toEqual({ iat: Number.NaN })
    expect(parseStrict('{"nbf":1E3}', only)).toEqual({ nbf: Number.NaN })
    // Other members, and nested ones, are read as numbers are.
    expect(parseStrict('{"x":1.5,"n":{"exp":2.0}}', only)).toEqual({ x: 1.5, n: { exp: 2 } })
    expect(parseStrict('{"exp":2.0}')).toEqual({ exp: 2 })
  })

  it('keeps __proto__ as a name, not as a prototype', () => {
    const read = parseStrict('{"__proto__":{"x":1}}') as Record<string, unknown>
    expect(Object.keys(read)).toEqual(['__proto__'])
    expect(({} as Record<string, unknown>).x).toBeUndefined()
  })
})
