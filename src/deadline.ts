// A deadline for a call to Cauthy that does not get in the way of the caller's
// own cancellation: the call fails with a `TimeoutError` when Cauthy has not
// answered in time, and with the caller's own reason when the caller gave up.
// For a stream (`accept: text/event-stream`) the deadline covers the first
// response only: the stream then lives as long as its caller wants it.

export const DEFAULT_DEADLINE_MS = 5000

/** Whether `err` is the deadline of `deadline()` passing, and not a caller giving up. */
export const isTimeout = (err: unknown): boolean => (err as { name?: unknown } | null)?.name === 'TimeoutError'

export function deadline(base: typeof fetch | undefined, ms: number): typeof fetch {
  return async (input, init = {}) => {
    const send = base ?? fetch
    const stream = new Headers(init.headers).get('accept')?.includes('text/event-stream') === true
    if (!stream) {
      // The whole answer, body included, is inside the deadline.
      const limit = AbortSignal.timeout(ms)
      return send(input, { ...init, signal: init.signal ? anySignal([init.signal, limit]) : limit })
    }
    const own = new AbortController()
    const timer = setTimeout(() => own.abort(new DOMException(`Cauthy did not answer within ${ms} ms`, 'TimeoutError')), ms)
    try {
      return await send(input, { ...init, signal: init.signal ? anySignal([init.signal, own.signal]) : own.signal })
    } finally {
      clearTimeout(timer)
    }
  }
}

function anySignal(signals: AbortSignal[]): AbortSignal {
  if (typeof AbortSignal.any === 'function') return AbortSignal.any(signals)
  // Node 20.0 to 20.2: no AbortSignal.any.
  const controller = new AbortController()
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason)
      break
    }
    signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true })
  }
  return controller.signal
}
