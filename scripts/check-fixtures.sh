#!/bin/sh
# Fixtures are Acme CRM and example.com only. The forbidden strings are kept
# as hashes in check-fixtures.mjs, because this repository is public.
set -eu
exec node "$(dirname "$0")/check-fixtures.mjs" "$@"
