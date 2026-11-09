// Acme CRM on a real Cauthy, with one variable: CAUTHY_KEY, the key Cauthy's
// dashboard made for the application (Integrate → Applications → Connect an
// application). Everything else comes from Cauthy.
//
//   node --env-file=examples/acme-crm/.env --import tsx examples/acme-crm/main.ts
import { createCauthy } from '@cauthyhq/node'
import { acmeApp } from './app'

const port = Number(process.env.PORT ?? 3000)
const auth = createCauthy() // reads CAUTHY_KEY
const server = acmeApp(auth).listen(port, () => {
  auth.checkMount(`http://localhost:${port}`).then(
    () => console.log(`Acme CRM on http://localhost:${port}`),
    (err: Error) => {
      console.error(err.message)
      server.close()
      process.exitCode = 1
    },
  )
})
