// The application's own key: made by the application, kept in its own
// database, its public half published, its private half sealed at rest.
//
// A contracted application proves who it is to Cauthy with an assertion it
// signs (private_key_jwt). Nobody hands it that key: the first time it needs
// one it makes it, seals the private half with the key derived from its root
// key (pact/seal/v1) and keeps it in a KeyStore — a table of its database, a
// file while developing. Its public half is served at the jwks_url its
// manifest names, where Cauthy reads it.
//
// Rotating: `rotate()` makes a new key, published at once. It signs once it
// has been published longer than anyone caches the keys (SIGN_AFTER_MS):
// Cauthy, meeting a key it does not know, reads the keys again, and a copy
// cached on the way must already hold it. The one before it stays published
// 24 hours, so an assertion signed a moment ago, or by an instance that has
// not seen the new key yet, still verifies.
//
// The first key is made by whichever instance needs it first: the store keeps
// it only while it holds none (addFirst), so instances starting together end
// with one key. A store without addFirst may end with several; every one is
// published, and every instance settles on the same one within seconds.

import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, type KeyLike } from 'jose'
import { seal, unseal } from './seal'
import type { KeyRing } from './rootkey'
import { CauthyConfigError } from './types'

/** A key as a KeyStore keeps it. Nothing in it is secret but sealed. */
export interface StoredKey {
  /** Its id, as published (the JWK thumbprint). */
  kid: string
  /** Its public half, as published. */
  publicJwk: JWK
  /** Its private half, sealed with the key derived from the root key. */
  sealed: string
  /** When it was made (ISO 8601, UTC). The newest signs. */
  createdAt: string
}

/** Where the application keeps its keys: a table, a file. */
export interface KeyStore {
  /** Every key kept. */
  list(): Promise<StoredKey[]>
  /** Keeps a new key. A kid already kept is left as it is. */
  add(key: StoredKey): Promise<void>
  /** Keeps the key only while the store holds none, in one step: instances starting together make one key. */
  addFirst?(key: StoredKey): Promise<void>
  /** Replaces a key's sealed private half (after the root key was rotated). */
  update(key: StoredKey): Promise<void>
  /** Forgets a key no longer published. */
  remove(kid: string): Promise<void>
}

/** How long a key stays published after a newer one appears. */
export const RETIRE_AFTER_MS = 24 * 60 * 60 * 1000
/** How long a key that is no longer published is kept before it is forgotten. */
const FORGET_AFTER_MS = 7 * 24 * 60 * 60 * 1000
/** How long the key that signs is remembered before the store is read again. */
const CURRENT_TTL_MS = 5 * 60 * 1000
/** How long the published keys may be cached (the jwks_url's max-age). */
export const JWKS_MAX_AGE_S = 300
/** How long a new key is published before it signs: longer than any cached copy of the keys. */
export const SIGN_AFTER_MS = (JWKS_MAX_AGE_S + 60) * 1000
/** While every key is younger than that, the store is read again this often, so instances settle on one. */
const SETTLING_TTL_MS = 5 * 1000

/** The application's keys, as auth.pact.keys gives them. */
export interface PactKeys {
  /** The key that signs now, made the first time there is none: the newest that has been published long enough. */
  current(): Promise<{ kid: string; privateKey: KeyLike | Uint8Array }>
  /** The public keys to publish: the one that signs, and the one before it for 24 hours after. */
  published(): Promise<{ keys: JWK[] }>
  /** Makes a new key, published at once and signing once SIGN_AFTER_MS has passed. Answers its id. */
  rotate(): Promise<string>
  /** Seals every key again with the current root key; answers how many changed. */
  reseal(): Promise<number>
}

const newestFirst = (keys: StoredKey[]) => [...keys].sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.kid.localeCompare(a.kid))

function published(key: StoredKey): JWK {
  const { kty, n, e } = key.publicJwk
  return { kty, n, e, kid: key.kid, alg: 'RS256', use: 'sig' }
}

export function pactKeys(store: KeyStore, sealKeys: Promise<KeyRing>, now: () => number = Date.now): PactKeys {
  let remembered: { kid: string; privateKey: KeyLike | Uint8Array; until: number } | undefined
  let making: Promise<StoredKey> | undefined

  async function make(after?: StoredKey): Promise<StoredKey> {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true })
    const publicJwk = await exportJWK(publicKey)
    const kid = await calculateJwkThumbprint(publicJwk)
    // Always newer than the key it follows, however fast the rotation.
    const at = Math.max(now(), after ? Date.parse(after.createdAt) + 1 : 0)
    const key: StoredKey = { kid, publicJwk, sealed: await seal(await exportJWK(privateKey), (await sealKeys)[0]), createdAt: new Date(at).toISOString() }
    if (!after && store.addFirst) await store.addFirst(key)
    else await store.add(key)
    return key
  }

  const age = (key: StoredKey) => now() - Date.parse(key.createdAt)

  // The key that signs: the newest published long enough. When none is (the
  // first minutes of the first key, or a race of first keys), the oldest, read
  // again shortly so every instance lands on the same one.
  function signer(kept: StoredKey[]): { key: StoredKey; until: number } {
    const ripe = kept.find(k => age(k) >= SIGN_AFTER_MS)
    if (!ripe) return { key: kept[kept.length - 1], until: now() + SETTLING_TTL_MS }
    // A newer key ripens later: read again then, not after the usual while.
    const until = ripe === kept[0] ? now() + CURRENT_TTL_MS : Math.min(now() + CURRENT_TTL_MS, Date.parse(kept[0].createdAt) + SIGN_AFTER_MS)
    return { key: ripe, until }
  }

  async function open(key: StoredKey): Promise<{ jwk: JWK; fresh: boolean } | null> {
    const ring = await sealKeys
    for (let i = 0; i < ring.length; i++) {
      const jwk = await unseal<JWK>(key.sealed, ring[i])
      if (jwk !== null) return { jwk, fresh: i === 0 }
    }
    return null
  }

  // Every key kept, newest first; the first one is made when there is none.
  async function keptKeys(): Promise<StoredKey[]> {
    const kept = newestFirst(await store.list())
    if (kept.length > 0) return kept
    // Two callers at once make one key; two instances at once, one with
    // addFirst, and otherwise several that are all published.
    making ??= make().finally(() => { making = undefined })
    await making
    const again = newestFirst(await store.list())
    if (again.length === 0) throw new CauthyConfigError('the key store kept no key: check that it writes')
    return again
  }

  return {
    async current() {
      if (remembered && remembered.until > now()) return remembered
      const { key, until } = signer(await keptKeys())
      if (remembered?.kid === key.kid) {
        remembered.until = until
        return remembered
      }
      const opened = await open(key)
      if (opened === null) {
        throw new CauthyConfigError(`the key ${key.kid} cannot be opened with the root key (PACT_ROOT_KEY): ` +
          'if the root key was rotated, set the previous one as PACT_ROOT_KEY_PREVIOUS')
      }
      remembered = { kid: key.kid, privateKey: await importJWK(opened.jwk, 'RS256'), until }
      return remembered
    },
    async published() {
      // Asked before anything was signed: the key is made now, so what is
      // published is the key that will sign.
      const kept = await keptKeys()
      const out: JWK[] = []
      for (let i = 0; i < kept.length; i++) {
        // The newest is published; an older one while its successor is young.
        if (i === 0 || now() - Date.parse(kept[i - 1].createdAt) < RETIRE_AFTER_MS) out.push(published(kept[i]))
        else if (now() - Date.parse(kept[i - 1].createdAt) > FORGET_AFTER_MS) await store.remove(kept[i].kid)
      }
      return { keys: out }
    },
    async rotate() {
      const key = await make(newestFirst(await store.list())[0])
      remembered = undefined
      return key.kid
    },
    async reseal() {
      let changed = 0
      const ring = await sealKeys
      for (const key of await store.list()) {
        const opened = await open(key)
        if (opened === null || opened.fresh) continue
        await store.update({ ...key, sealed: await seal(opened.jwk, ring[0]) })
        changed++
      }
      return changed
    },
  }
}

/** Keys kept in memory: for tests, and for trying contract mode out. Gone on restart. */
export function memoryKeyStore(): KeyStore {
  const keys = new Map<string, StoredKey>()
  return {
    async list() { return [...keys.values()] },
    async add(k) { if (!keys.has(k.kid)) keys.set(k.kid, k) },
    async addFirst(k) { if (keys.size === 0) keys.set(k.kid, k) },
    async update(k) { keys.set(k.kid, k) },
    async remove(kid) { keys.delete(kid) },
  }
}

/**
 * The table postgresKeyStore keeps the keys in, for the application's own
 * migrations (Drizzle, Prisma, plain SQL). The store never creates it.
 */
export function pactKeysTableSql(table = 'cauthy_pact_keys'): string {
  checkTable(table)
  return `CREATE TABLE IF NOT EXISTS ${table} (
  kid        TEXT        PRIMARY KEY,
  public_jwk JSONB       NOT NULL,
  sealed     TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);`
}

function checkTable(table: string): void {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(table)) throw new CauthyConfigError(`the key table's name must be a plain SQL identifier: ${table}`)
}

/**
 * Runs one SQL statement with $1, $2… parameters and answers its rows: what
 * the application's own database client does. With node-postgres,
 * `(text, params) => pool.query(text, params)`; with postgres.js,
 * `(text, params) => sql.unsafe(text, params)`.
 */
export type Query = (text: string, params: unknown[]) => Promise<{ rows: unknown[] } | unknown[]>

/** Keys kept in a table of the application's Postgres database (see pactKeysTableSql). */
export function postgresKeyStore(query: Query, options: { table?: string } = {}): KeyStore {
  const table = options.table ?? 'cauthy_pact_keys'
  checkTable(table)
  const rows = async (text: string, params: unknown[]) => {
    const out = await query(text, params)
    return (Array.isArray(out) ? out : out.rows) as Record<string, unknown>[]
  }
  const at = (v: unknown) => (v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString())
  return {
    async list() {
      return (await rows(`SELECT kid, public_jwk, sealed, created_at FROM ${table}`, [])).map(r => ({
        kid: String(r.kid),
        publicJwk: (typeof r.public_jwk === 'string' ? JSON.parse(r.public_jwk) : r.public_jwk) as JWK,
        sealed: String(r.sealed),
        createdAt: at(r.created_at),
      }))
    },
    async add(k) {
      await rows(`INSERT INTO ${table} (kid, public_jwk, sealed, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (kid) DO NOTHING`,
        [k.kid, JSON.stringify(k.publicJwk), k.sealed, k.createdAt])
    },
    async addFirst(k) {
      // One statement: a key another instance committed a moment ago is seen.
      await rows(`INSERT INTO ${table} (kid, public_jwk, sealed, created_at) SELECT $1, $2, $3, $4 WHERE NOT EXISTS (SELECT 1 FROM ${table}) ON CONFLICT (kid) DO NOTHING`,
        [k.kid, JSON.stringify(k.publicJwk), k.sealed, k.createdAt])
    },
    async update(k) {
      await rows(`UPDATE ${table} SET sealed = $2 WHERE kid = $1`, [k.kid, k.sealed])
    },
    async remove(kid) {
      await rows(`DELETE FROM ${table} WHERE kid = $1`, [kid])
    },
  }
}
