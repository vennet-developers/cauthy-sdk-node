// Acme CRM on a real Cauthy. The CAUTHY_* variables come from the
// environment (see example.env):
//
//   node --env-file=examples/acme-crm/.env --import tsx examples/acme-crm/main.ts
import { createCauthy } from '@cauthyhq/node'
import { acmeApp } from './app'

const port = Number(process.env.PORT ?? 3000)
const auth = createCauthy()
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
