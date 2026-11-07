// Lets the spec's vector runner (cauthy-sdk-spec/vectors/verify.test.mjs) load
// this package: that runner reads `exports['.'].import` as a path, and ours is
// nested. It also passes `issuer` as a list when a case names further issuers
// (verifyToken takes them as `issuers`), and it does not pass a case's
// `allow_anonymous`, which this adapter reads from the vectors by token.
//
//   npm run build
//   SPEC_DIR=../cauthy-sdk-spec CAUTHY_AUTH_DIR=test-support/vectors-adapter VECTORS_STRICT=1 \
//     node --test ../cauthy-sdk-spec/vectors/verify.test.mjs
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyToken as verify } from '../../dist/index.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const spec = resolve(process.env.SPEC_DIR ?? resolve(here, '../../../cauthy-sdk-spec'))
const cases = JSON.parse(readFileSync(resolve(spec, 'vectors/tokens.json'), 'utf8')).cases
// The runner calls once per case, in order, and two cases share a token (the
// guest's, allowed and not): the call's position says which case it is.
let call = 0

export async function verifyToken(token, options = {}) {
  const { issuer, ...rest } = options
  const position = call++
  const [first, ...more] = Array.isArray(issuer) ? issuer : [issuer]
  return verify(token, { ...rest, issuer: first, ...(more.length > 0 ? { issuers: more } : {}), ...(cases[position]?.token === token && cases[position].config.allow_anonymous === true ? { allowAnonymous: true } : {}) })
}
