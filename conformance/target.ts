// The conformance target: Acme CRM on a Cauthy that lives in memory, so the
// auth-bff suite of cauthy-sdk-spec runs at level strict with no real Cauthy.
//
//   CONFORMANCE_PASSWORD=… CONFORMANCE_KEY_FILE=… npx tsx conformance/target.ts
//
// One account, member@example.com: a password, MFA off, a verified email,
// no captcha — what the runner signs in as.
//
// The application runs on CAUTHY_KEY alone: the in-memory Cauthy issues a key
// for acme-crm, served over HTTP on CONFORMANCE_CAUTHY_PORT (default: the
// target's port + 1) so the runner's key.* checks (--key-env) can ask it who
// the key is. The key is written to CONFORMANCE_KEY_FILE (mode 0600) for the
// runner, and printed nowhere. CONFORMANCE_MODE=variables runs the 1.1 way
// instead (CAUTHY_ISSUER, CAUTHY_CLIENT_ID, …), for as long as 1.x keeps it.
//
// With CONFORMANCE_ADMIN_TOKEN set, the in-memory Cauthy also serves its admin
// API, so the runner's dashboard-switch checks (level switches) can change its
// settings.
import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { createCauthy, KEY_REPLACES } from '@cauthyhq/node'
import { acmeApp } from '../examples/acme-crm/app'
import { FakeCauthy, serveFakeCauthy } from '../src/testing'

const port = Number(process.env.CONFORMANCE_PORT ?? 3999)
const cauthyPort = Number(process.env.CONFORMANCE_CAUTHY_PORT ?? port + 1)
const password = process.env.CONFORMANCE_PASSWORD ?? ''
const variables = process.env.CONFORMANCE_MODE === 'variables'
const keyFile = process.env.CONFORMANCE_KEY_FILE ?? ''
if (password.length < 12) {
  console.error('CONFORMANCE_PASSWORD is required (12 characters or more)')
  process.exit(2)
}
if (!variables && keyFile === '') {
  console.error('CONFORMANCE_KEY_FILE is required: where the key the application runs on is written for the runner')
  process.exit(2)
}

const cauthy = new FakeCauthy()
cauthy.ownScreens = true
cauthy.adminToken = process.env.CONFORMANCE_ADMIN_TOKEN ?? ''
cauthy.users.set('u-member', { sub: 'u-member', email: 'member@example.com', name: 'Acme Member', active: true, restricted: false })
cauthy.passwords.set('member@example.com', password)

const origin = `http://localhost:${port}`
cauthy.appUrls = [origin]

async function start() {
  // On the key, Cauthy is reached over HTTP by the runner: it is always served.
  const cauthyServer = variables && cauthy.adminToken === '' ? null : await serveFakeCauthy(cauthy, cauthyPort)
  let auth
  if (variables) {
    auth = createCauthy({
      issuer: cauthy.issuer,
      clientId: 'acme-crm',
      secret: randomBytes(32).toString('base64url'),
      tenant: cauthy.tenant,
      baseURL: origin,
      pages: { signIn: '/sign-in' },
      fetch: cauthy.fetch,
    })
  } else {
    const key = await cauthy.issueKey(`http://127.0.0.1:${cauthyPort}`)
    writeFileSync(keyFile, key, { mode: 0o600 })
    for (const name of [...KEY_REPLACES, 'CAUTHY_SECRET', 'PACT_ROOT_KEY']) delete process.env[name]
    process.env.CAUTHY_KEY = key
    // Nothing but the key: the workspace, the system and the address come from Cauthy.
    auth = createCauthy({ pages: { signIn: '/sign-in' }, fetch: cauthy.fetch })
    await auth.ready()
  }
  const server = acmeApp(auth).listen(port, () => {
    auth.checkMount(origin).then(
      () => console.log(`conformance target on ${origin} (${variables ? 'variables' : 'CAUTHY_KEY'})${cauthyServer ? `, its Cauthy on http://127.0.0.1:${cauthyPort}` : ''}`),
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
}

start().catch((err: Error) => {
  console.error(`the conformance target could not start: ${err.message}`)
  process.exit(2)
})
