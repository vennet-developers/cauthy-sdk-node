// Lets the spec's vector runner (cauthy-sdk-spec/vectors/verify.test.mjs) load
// this package: that runner reads `exports['.'].import` as a path, and ours is
// nested. It also passes `issuer` as a list when a case names further issuers;
// verifyToken takes them as `issuers`.
//
//   npm run vectors
import { verifyToken as verify } from '../../dist/index.mjs'

export async function verifyToken(token, options = {}) {
  const { issuer, ...rest } = options
  const [first, ...more] = Array.isArray(issuer) ? issuer : [issuer]
  return verify(token, { ...rest, issuer: first, ...(more.length > 0 ? { issuers: more } : {}) })
}
