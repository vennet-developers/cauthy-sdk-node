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
SPEC_DIR=$spec CAUTHY_AUTH_DIR=$root/test-support/vectors-adapter VECTORS_STRICT=1 node --test "$spec/vectors/verify.test.mjs"
