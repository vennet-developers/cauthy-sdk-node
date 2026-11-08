// The conformance target: Acme CRM on a Cauthy that lives in memory, so the
// auth-bff suite of cauthy-sdk-spec runs at level strict with no real Cauthy.
//
//   CONFORMANCE_PASSWORD=… npx tsx conformance/target.ts
//
// One account, member@example.com: a password, MFA off, a verified email,
// no captcha — what the runner signs in as.
//
// With CONFORMANCE_ADMIN_TOKEN set, the in-memory Cauthy also serves its admin
// API on CONFORMANCE_CAUTHY_PORT (default: the target's port + 1), so the
// runner's dashboard-switch checks (level switches) can change its settings.
import { randomBytes } from 'node:crypto'
import { createCauthy } from '@cauthyhq/node'
import { acmeApp } from '../examples/acme-crm/app'
import { FakeCauthy, serveFakeCauthy } from '../src/testing'

const port = Number(process.env.CONFORMANCE_PORT ?? 3999)
const cauthyPort = Number(process.env.CONFORMANCE_CAUTHY_PORT ?? port + 1)
const password = process.env.CONFORMANCE_PASSWORD ?? ''
if (password.length < 12) {
  console.error('CONFORMANCE_PASSWORD is required (12 characters or more)')
  process.exit(2)
}

const cauthy = new FakeCauthy()
cauthy.ownScreens = true
cauthy.adminToken = process.env.CONFORMANCE_ADMIN_TOKEN ?? ''
cauthy.users.set('u-member', { sub: 'u-member', email: 'member@example.com', name: 'Acme Member', active: true, restricted: false })
cauthy.passwords.set('member@example.com', password)

const origin = `http://localhost:${port}`
const auth = createCauthy({
  issuer: cauthy.issuer,
  clientId: 'acme-crm',
  secret: randomBytes(32).toString('base64url'),
  tenant: cauthy.tenant,
  baseURL: origin,
  // A sign-in link opens the application's sign-in page.
  pages: { signIn: '/sign-in' },
  fetch: cauthy.fetch,
})
const admin = cauthy.adminToken === '' ? Promise.resolve(null) : serveFakeCauthy(cauthy, cauthyPort)
admin.then(
  (cauthyServer) => {
    const server = acmeApp(auth).listen(port, () => {
      auth.checkMount(origin).then(
        () => console.log(`conformance target on ${origin}${cauthyServer ? `, its Cauthy on http://127.0.0.1:${cauthyPort}` : ''}`),
        (err: Error) => {
          console.error(err.message)
          server.close()
          cauthyServer?.close()
          process.exitCode = 2
        },
      )
    })
    process.on('SIGTERM', () => {
      server.close()
      cauthyServer?.close()
    })
  },
  (err: Error) => {
    console.error(`the in-memory Cauthy could not listen on ${cauthyPort}: ${err.message}`)
    process.exit(2)
  },
)
