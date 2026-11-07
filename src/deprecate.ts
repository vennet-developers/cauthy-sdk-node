// What leaves in 2.0 says so once per process, as Node's own deprecations do
// (silenced with --no-deprecation, thrown with --throw-deprecation).
const told = new Set<string>()

/** Says once per process that `what` is deprecated, and what to use instead. */
export function deprecated(what: string, instead: string): void {
  if (told.has(what)) return
  told.add(what)
  const message = `@cauthyhq/node: ${what} is deprecated and leaves in 2.0. ${instead}`
  // Edge runtimes have no `process`: the console says it there.
  if (typeof process !== 'undefined' && typeof process.emitWarning === 'function') {
    process.emitWarning(message, { type: 'DeprecationWarning', code: 'CAUTHY_DEPRECATED' })
  } else {
    console.warn(message)
  }
}
