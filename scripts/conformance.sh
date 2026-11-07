#!/bin/sh
# Runs the auth-bff conformance suite of cauthy-sdk-spec against the in-repo
# target (Acme CRM on the in-memory Cauthy). The exit code is the runner's:
# 0 passed and complete, 1 a check failed, 2 usage or setup, 3 incomplete.
#
#   SPEC_DIR=../cauthy-sdk-spec LEVEL=strict npm run conformance
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
spec=${SPEC_DIR:-$root/../cauthy-sdk-spec}
level=${LEVEL:-strict}
port=${CONFORMANCE_PORT:-3999}
report=${REPORT:-$root/conformance-report.json}

test -f "$spec/protocol/routes.yaml" || { echo "cauthy-sdk-spec not found at $spec (set SPEC_DIR)" >&2; exit 2; }
mkdir -p "$root/.conformance"
runner=$root/.conformance/cauthy-conformance
(cd "$spec/conformance" && go build -o "$runner" ./cmd/cauthy-conformance) || { echo "could not build the runner" >&2; exit 2; }
if curl -s -m 2 -o /dev/null "http://localhost:$port/" 2>/dev/null; then
  echo "port $port is in use: stop what listens there or set CONFORMANCE_PORT" >&2
  exit 2
fi

# A password made for this run; the target and the runner read it from the environment only.
CONFORMANCE_PASSWORD=$(node -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('base64url'))")
CONFORMANCE_PORT=$port
export CONFORMANCE_PASSWORD CONFORMANCE_PORT

"$root/node_modules/.bin/tsx" "$root/conformance/target.ts" &
target=$!
trap 'kill $target 2>/dev/null || true' EXIT INT TERM

i=0
until curl -s -m 1 -o /dev/null "http://localhost:$port/api/auth/session"; do
  i=$((i + 1))
  if [ $i -gt 100 ] || ! kill -0 $target 2>/dev/null; then
    echo "the target did not start" >&2
    exit 2
  fi
  sleep 0.2
done

set +e
"$runner" --target "http://localhost:$port/api/auth" --origin "http://localhost:$port" \
  --email member@example.com --level "$level" --table "$spec/protocol/routes.yaml" --json "$report"
code=$?
set -e
exit $code
