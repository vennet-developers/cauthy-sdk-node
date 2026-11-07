// cauthy-auth/keys: where a contracted application keeps its own key.
//
//   import { postgresKeyStore } from 'cauthy-auth/keys'
//   keys: postgresKeyStore((text, params) => pool.query(text, params))
//
// The file store is for a developer's machine: production keeps its key in
// its database, where every instance reads the same one.

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { KeyStore, StoredKey } from './keys'

export { memoryKeyStore, postgresKeyStore, pactKeysTableSql, type KeyStore, type PactKeys, type Query, type StoredKey } from './keys'

/** Keys kept in a JSON file, readable only by its owner. For development. */
export function fileKeyStore(path: string): KeyStore {
  async function read(): Promise<StoredKey[]> {
    try {
      const parsed = JSON.parse(await readFile(path, 'utf8')) as unknown
      return Array.isArray(parsed) ? (parsed as StoredKey[]) : []
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw err
    }
  }
  // Written whole to a file beside it, then moved over it: a crash never
  // leaves half a file.
  let writing: Promise<void> = Promise.resolve()
  function write(change: (keys: StoredKey[]) => StoredKey[]): Promise<void> {
    writing = writing.then(async () => {
      const next = change(await read())
      await mkdir(dirname(path), { recursive: true })
      const tmp = `${path}.${process.pid}.tmp`
      await writeFile(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 })
      await rename(tmp, path)
    })
    return writing
  }
  return {
    list: read,
    add: k => write(keys => (keys.some(x => x.kid === k.kid) ? keys : [...keys, k])),
    addFirst: k => write(keys => (keys.length > 0 ? keys : [k])),
    update: k => write(keys => keys.map(x => (x.kid === k.kid ? k : x))),
    remove: kid => write(keys => keys.filter(x => x.kid !== kid)),
  }
}
