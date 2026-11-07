// A strict JSON reader for what a token carries: it refuses what JSON.parse
// accepts and verification/rules.md (R2) does not — an object that repeats a
// name, at any depth, since two readers could then see two different tokens.
// An integer literal beyond 2^53 reads as NaN, so the claim check refuses it
// (R8) instead of rounding it into range.

const SPACE = new Set([' ', '\t', '\n', '\r'])
const LIMIT = 2n ** 53n

export function parseStrict(text: string): unknown {
  let i = 0
  const fail = (what: string): never => {
    throw new SyntaxError(`${what} at ${i}`)
  }
  const skip = () => {
    while (i < text.length && SPACE.has(text[i])) i++
  }
  const value = (): unknown => {
    skip()
    const c = text[i]
    if (c === '{') return object()
    if (c === '[') return array()
    if (c === '"') return string()
    if (c === '-' || (c >= '0' && c <= '9')) return number()
    for (const [word, v] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(word, i)) {
        i += word.length
        return v
      }
    }
    return fail('unexpected character')
  }
  const string = (): string => {
    const start = i
    i++
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1
    if (text[i] !== '"') fail('unterminated string')
    i++
    return JSON.parse(text.slice(start, i)) as string
  }
  const number = (): number => {
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i))
    if (!m) return fail('bad number')
    i += m[0].length
    if (m[2] === undefined && m[3] === undefined) {
      const big = BigInt(m[0])
      if (big > LIMIT || big < -LIMIT) return Number.NaN
    }
    return Number(m[0])
  }
  const array = (): unknown[] => {
    i++
    const out: unknown[] = []
    skip()
    if (text[i] === ']') {
      i++
      return out
    }
    for (;;) {
      out.push(value())
      skip()
      if (text[i] === ',') i++
      else if (text[i] === ']') {
        i++
        return out
      } else fail('expected , or ]')
    }
  }
  const object = (): Record<string, unknown> => {
    i++
    const out: Record<string, unknown> = {}
    const seen = new Set<string>()
    skip()
    if (text[i] === '}') {
      i++
      return out
    }
    for (;;) {
      skip()
      if (text[i] !== '"') fail('expected a name')
      const name = string()
      if (seen.has(name)) fail(`repeated name ${JSON.stringify(name)}`)
      seen.add(name)
      skip()
      if (text[i] !== ':') fail('expected :')
      i++
      Object.defineProperty(out, name, { value: value(), enumerable: true, writable: true, configurable: true })
      skip()
      if (text[i] === ',') i++
      else if (text[i] === '}') {
        i++
        return out
      } else fail('expected , or }')
    }
  }
  const result = value()
  skip()
  if (i < text.length) fail('trailing characters')
  return result
}
