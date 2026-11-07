import { describe, expect, it } from 'vitest'
import { pushTheme } from './theme'
import { connectSystem } from './connect'
import { pullPolicy, pushPolicy } from './permissions'
import { deadline, isTimeout } from './deadline'

// A fetch that answers only when it is aborted.
const hanging: typeof fetch = (_input, init) =>
  new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(init.signal?.reason)))

describe('the deadline of a call to Cauthy', () => {
  it('fails with a TimeoutError when Cauthy does not answer', async () => {
    const err = await deadline(hanging, 30)('https://id.test/x').catch((e) => e)
    expect(isTimeout(err)).toBe(true)
  })

  it('is not reported when the caller gave up first', async () => {
    const caller = new AbortController()
    const call = deadline(hanging, 5000)('https://id.test/x', { signal: caller.signal })
    caller.abort(new DOMException('gone', 'AbortError'))
    const err = await call.catch((e) => e)
    expect(isTimeout(err)).toBe(false)
    expect(err.name).toBe('AbortError')
  })

  it('covers only the first response of a stream, and lets the stream run', async () => {
    let signal: AbortSignal | null | undefined
    const stream: typeof fetch = async (_input, init) => {
      signal = init?.signal
      return new Response('data: x\n\n', { headers: { 'content-type': 'text/event-stream' } })
    }
    const res = await deadline(stream, 20)('https://id.test/events', { headers: { accept: 'text/event-stream' } })
    await new Promise((r) => setTimeout(r, 60))
    expect(signal?.aborted).toBe(false)
    expect(await res.text()).toBe('data: x\n\n')
  })

  it('stops the stream when its caller does, after the answer began', async () => {
    const caller = new AbortController()
    let signal: AbortSignal | null | undefined
    const stream: typeof fetch = async (_input, init) => {
      signal = init?.signal
      return new Response('data: x\n\n')
    }
    await deadline(stream, 5000)('https://id.test/events', { headers: { accept: 'text/event-stream' }, signal: caller.signal })
    caller.abort()
    expect(signal?.aborted).toBe(true)
  })
})

describe('the tools that call Cauthy from a pipeline', () => {
  const common = { issuer: 'https://id.test', tenant: 'acme', token: 'pat_x', fetch: hanging, timeoutMs: 30 }

  it('give up on a Cauthy that does not answer', async () => {
    const theme = await pushTheme({ ...common, clientId: 'acme-crm', theme: {} }).catch((e) => e)
    const connect = await connectSystem({ ...common, system: 'acme-crm', appUrl: 'https://app.example.com' }).catch((e) => e)
    const pull = await pullPolicy({ ...common, system: 'acme-crm' }).catch((e) => e)
    const push = await pushPolicy({ ...common, system: 'acme-crm', roles: [] } as never).catch((e) => e)
    for (const err of [theme, connect, pull, push]) expect(isTimeout(err)).toBe(true)
  })
})
