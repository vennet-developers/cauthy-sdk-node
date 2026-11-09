// Fixtures are Acme CRM and example.com only: no real tenant or client id, and
// no name of a real application. This repository is public, so the forbidden
// strings are not written here: only their SHA-256 hashes are. A file is read
// word by word (and every substring of a word as long as a forbidden name),
// and each candidate is hashed and looked up.
//
//   node scripts/check-fixtures.mjs [directory]     # default: the repository
//
// The company's own name is allowed as a phrase in content (a repository URL,
// a contact, the docs site); only content is read, never paths.
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const hash = (s) => createHash('sha256').update(s).digest('hex')
// [length, sha256] of each forbidden word, lower case.
const WORDS = [
  [5, '0834a044f52ddbed8d4904d94dd5fc4bd98bae9e6c0937735ca4b30d2650a3b8'],
  [7, '53c033e53a8cfa7252fc1c86ef7a72a5eda19c0ef71cbebed691d24da78de183'],
  [6, 'df7e4bae8cb955efe3ba62da7757a02eae7cbda27a377ebde6a6826faf456ff8'],
  [5, 'c47aeb912c191e428de66dbeb7c91ff2efe71df3bdda9f04dd84d5b4078e5368'],
  [6, '7d7e6589fc2ae6b5f76e94022cd123e40a8ae93e58a7a1f096c715d37f0f1015']
]
// sha256 of each forbidden id, lower case.
const IDS = new Set([
  '808ec7d60b608c875cf77ed3090996107a59236e1d4af16cc6fcd1b4ad499f6a',
  '632ade6f9637ef3b3bf60306a514d0c423c3c2b308df4581f435cc9a9fc39f4a'
])
const LENGTHS = [...new Set(WORDS.map(([n]) => n))]
const HASHES = new Set(WORDS.map(([, x]) => x))
const ALLOWED = /vennet[- ]developers|cauthy\.docs\.vennet\.dev/g
const SKIP = new Set(['node_modules', '.git', 'dist', '.conformance'])

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(process.argv[2] ?? join(here, '..'))
const self = join(here, 'check-fixtures.mjs')

function* files(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue
    const path = join(dir, entry.name)
    if (entry.isDirectory()) yield* files(path)
    else if (entry.isFile() && path !== self) yield path
  }
}

function forbidden(line) {
  const text = line.toLowerCase().replace(ALLOWED, ' ')
  for (const id of text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g) ?? []) if (IDS.has(hash(id))) return true
  for (const word of text.match(/[a-z0-9]+/g) ?? []) {
    for (const n of LENGTHS) {
      for (let i = 0; i + n <= word.length; i++) if (HASHES.has(hash(word.slice(i, i + n)))) return true
    }
  }
  return false
}

const found = []
for (const file of files(root)) {
  const bytes = readFileSync(file)
  if (bytes.includes(0)) continue // binary
  bytes.toString('utf8').split('\n').forEach((line, i) => {
    if (forbidden(line)) found.push(`${file}:${i + 1}`)
  })
}
if (found.length > 0) {
  console.error('fixtures name something real (the match is not shown):')
  for (const where of found) console.error(where)
  process.exit(1)
}
console.log('fixtures: Acme only')
