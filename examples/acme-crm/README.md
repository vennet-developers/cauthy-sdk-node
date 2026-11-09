# Acme CRM

An Express application that signs its people in with Cauthy through `@cauthyhq/node`.

| File | What it is |
| --- | --- |
| `app.ts` | The application: Cauthy mounted under `/api/auth`, `/api/me`, and `/api/deals` for signed-in people only |
| `main.ts` | Runs it on a real Cauthy, from `CAUTHY_KEY` alone |
| `app.test.ts` | Runs it on an in-memory Cauthy with a key it issued: sign-in, session, and `checkMount` over HTTP |

The conformance suite of `cauthy-sdk-spec` runs against this same application (`conformance/target.ts`).

## Running it on a real Cauthy

In Cauthy's dashboard, **Integrate → Applications → Connect an application**,
with `http://localhost:3000` as its address. The dashboard shows one line,
once; put it in `examples/acme-crm/.env` (never committed):

    CAUTHY_KEY=cauthy1.…

Then:

    node --env-file=examples/acme-crm/.env --import tsx examples/acme-crm/main.ts

The workspace, the system and the application's addresses come from Cauthy.
