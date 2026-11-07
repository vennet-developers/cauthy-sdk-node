#!/bin/sh
# What npm would publish, checked before it is: the build, the export map,
# the types under both module systems, every entry loading under require and
# import, nothing of the tests or of a real tenant in the tarball, and npm's
# own dry run.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

npm run build
npx publint --strict
# ./fastify keeps 0.42's shape (a default export beside named ones), which
# attw reports as false-export-default for CommonJS consumers: kept on purpose.
npx attw --pack . --profile node16 --ignore-rules false-export-default

for entry in "" /express /fastify /hono /next /mcp /keys /theme; do
  node -e "require('@cauthyhq/node$entry')"
done
# ./next is imported as ESM only inside Next's bundler: plain Node cannot
# resolve `next/headers` (Next has no exports map), as with 0.42.
for entry in "" /express /fastify /hono /mcp /keys /theme; do
  node --input-type=module -e "await import('@cauthyhq/node$entry')"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
npm pack --pack-destination "$tmp" >/dev/null
tar -xzf "$tmp"/cauthyhq-node-*.tgz -C "$tmp"
if find "$tmp/package" \( -name '*.test.*' -o -name 'testing.*' -o -path '*test-support*' -o -path '*examples*' \) | grep -q .; then
  echo "the tarball carries test files" >&2
  exit 1
fi
sh "$root/scripts/check-fixtures.sh" "$tmp/package"
npm publish --dry-run
echo "package: ready to publish"
