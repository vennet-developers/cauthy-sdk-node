// Acme CRM: an Express application that signs its people in with Cauthy.
import express from 'express'
import type { Cauthy } from '@cauthyhq/node'
import { cauthyExpress, requireSession } from '@cauthyhq/node/express'

export function acmeApp(auth: Cauthy) {
  const app = express()
  // Cauthy first: it reads its own bodies, and answers a malformed one the way
  // the protocol says. A body parser in front of it would answer with a page.
  app.use(cauthyExpress(auth))
  app.use(express.json())

  app.get('/api/me', async (req, res) => {
    const session = await req.cauthy()
    if (!session) return void res.status(401).json({ error: 'unauthenticated' })
    res.json({ id: session.user.id, email: session.user.email, name: session.user.name })
  })

  // A page of the CRM only a signed-in person reaches. Rows are keyed by the
  // person's id (sub), never by their email.
  app.get('/api/deals', requireSession, async (req, res) => {
    const session = await req.cauthy()
    res.json({ owner: session?.user.id, deals: [] })
  })

  return app
}
