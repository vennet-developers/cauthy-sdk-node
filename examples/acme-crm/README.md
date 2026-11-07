# Acme CRM

An Express application that signs its people in with Cauthy through `@cauthyhq/node`.

| File | What it is |
| --- | --- |
| `app.ts` | The application: Cauthy mounted under `/api/auth`, `/api/me`, and `/api/deals` for signed-in people only |
| `main.ts` | Runs it on a real Cauthy, from the `CAUTHY_*` variables below |
| `app.test.ts` | Runs it on an in-memory Cauthy: sign-in, session, and `checkMount` over HTTP |

The conformance suite of `cauthy-sdk-spec` runs against this same application (`conformance/target.ts`).

## Running it on a real Cauthy

Set these variables (in a local env file you do not commit, or in the shell):

| Variable | Value |
| --- | --- |
| `CAUTHY_ISSUER` | Your Cauthy's address, e.g. `https://id.example.com` |
| `CAUTHY_CLIENT_ID` | `acme-crm` |
| `CAUTHY_SECRET` | 32 random characters or more: `openssl rand -base64 32` |
| `CAUTHY_TENANT` | The workspace's slug, e.g. `acme`, for the sign-in screens the application draws itself |
| `CAUTHY_BASE_URL` | `http://localhost:3000` |

Then:

    node --env-file=examples/acme-crm/local.env --import tsx examples/acme-crm/main.ts
