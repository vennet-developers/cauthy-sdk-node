#!/bin/sh
# Runs the spec's token vectors (cauthy-sdk-spec/vectors) against the built
# verifyToken, through the adapter in test-support/vectors-adapter. Every
# vector must agree, verdict and reason: the run fails on any finding.
#
#   SPEC_DIR=../cauthy-sdk-spec npm run vectors
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
test -f "$spec/vectors/verify.test.mjs" || { echo "cauthy-sdk-spec not found at $spec (set SPEC_DIR)" >&2; exit 2; }
npm run build >/dev/null
# CAUTHY_KEY's vectors are vendored in src/testdata (the unit tests run them):
# the copy must be the spec's, byte for byte. A spec from before them has none.
if [ -f "$spec/vectors/cauthy-key.json" ]; then
  cmp -s "$spec/vectors/cauthy-key.json" src/testdata/cauthy-key.json || { echo "src/testdata/cauthy-key.json differs from $spec/vectors/cauthy-key.json: copy it again and update the pin in src/cauthykey.test.ts" >&2; exit 1; }
  npx vitest run src/cauthykey.test.ts src/keyderive.test.ts >/dev/null || { echo "the CAUTHY_KEY vectors fail" >&2; exit 1; }
  echo "CAUTHY_KEY vectors: the vendored copy is the spec's, and every vector agrees"
else
  echo "no vectors/cauthy-key.json in $spec: CAUTHY_KEY vectors not compared"
fi
SPEC_DIR=$spec CAUTHY_AUTH_DIR=$root/test-support/vectors-adapter VECTORS_STRICT=1 node --test "$spec/vectors/verify.test.mjs"
