/** How an application is set up to sign its people in with Cauthy. */
export interface CauthyOptions {
  /** Cauthy's public address, e.g. `https://id.example.com`. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The application's OAuth client id. Default: `CAUTHY_CLIENT_ID`. */
  clientId?: string
  /** Its secret, when the client is confidential. Default: `CAUTHY_CLIENT_SECRET`. */
  clientSecret?: string
  /**
   * The key the session cookie is encrypted with: any string of 32 characters
   * or more, kept on the server. Default: `CAUTHY_SECRET`.
   */
  secret?: string
  /**
   * The system this application is, as its organizations are filed under in
   * Cauthy (`"acme-crm"`). When set, a session's organizations are that
   * system's. Default: `CAUTHY_SYSTEM`.
   */
  system?: string
  /**
   * The workspace's slug in Cauthy. Needed for the application's own sign-in
   * screens (`signIn.email`, `signUp.email`…), which sign people in through
   * the application's server instead of Cauthy's page. Default: `CAUTHY_TENANT`.
   */
  tenant?: string
  /** Where the routes are mounted. Default: `/api/auth`. */
  basePath?: string
  /**
   * What happens to a POST without `X-Cauthy-Request: 1` (every POST but
   * `/logout`). `required`, the default, answers `403 csrf_required`, as
   * protocol level strict asks. `warn` lets it through and says so once per
   * process: for the one deploy that moves an application whose browser still
   * runs cauthy-auth 0.42, which does not send the header. Remove it once the
   * browser runs cauthy-auth 0.43 or @cauthyhq/js.
   */
  requestHeader?: 'required' | 'warn'
  /**
   * The audience of the access tokens `auth.verifyToken` accepts: the
   * deployment's `JWT_AUDIENCE`, which Cauthy requires its operator to set and
   * has no default for. Default: `CAUTHY_AUDIENCE`.
   */
  audience?: string
  /**
   * The workspace's id (a lowercase UUID) for `auth.verifyToken`. By contract
   * it comes from the link's `tenant_id`; otherwise: this, or `CAUTHY_TENANT_ID`.
   */
  tenantId?: string
  /**
   * The application's own public origin (`https://app.example.com`): the
   * redirect URI, the cookies' `Secure` flag and which forms are its own come
   * from it. Default: `CAUTHY_BASE_URL`, else the origin of each request, with
   * the scheme a proxy names in `x-forwarded-proto`. Set it whenever a proxy
   * also changes the host or the port.
   */
  baseURL?: string
  /** Where a person lands after signing in, when no `return_to` was asked. Default: `/`. */
  afterSignIn?: string
  /** Where a person lands after signing out. Default: `/`. */
  afterSignOut?: string
  /** Name of the session cookie. Default: `cauthy_session`. */
  cookieName?: string
  /**
   * A key the application proves who it is with when it acts on its own
   * (`auth.system`), instead of its secret. Default: `CAUTHY_SYSTEM_KEY` and
   * `CAUTHY_SYSTEM_KEY_ID`.
   */
  systemKey?: import('./system').SystemKey
  /**
   * The application's own pages for what arrives by mail. A link Cauthy mails
   * opens the page named here, with a `token` to give back; with none, it
   * opens Cauthy's own page.
   *
   *   signIn         where `<SignIn />` is: a sign-in link opens it
   *   resetPassword  where `<ResetPassword />` is
   *   verifyEmail    where `<VerifyEmail />` is
   *   acceptInvite   where `<AcceptInvite />` is: an invitation opens it
   *
   * An invitation sent by `auth.system.members.add` or `auth.system.invite`
   * opens `acceptInvite` only when the application knows its public origin
   * (`baseURL`): that call has no request to read it from.
   */
  pages?: { signIn?: string; resetPassword?: string; verifyEmail?: string; acceptInvite?: string }
  /**
   * The address of the person a request comes from, passed on to Cauthy so
   * its limits on attempts count the person and not this server. Default: the
   * last address in `X-Forwarded-For`, which is the one the proxy in front of
   * the application wrote. With several proxies, or none, give your own.
   */
  clientIp?: (request: Request) => string | undefined
  /** `fetch` to reach Cauthy with. Default: the global one. */
  fetch?: typeof fetch
  /**
   * How long a call to Cauthy may take before it fails, in milliseconds.
   * `system`: the application's own calls (`auth.system`, and the proof its
   * sign-ins carry). Default 2000. `request`: the sign-in screens' calls and
   * the code, refresh and userinfo calls of a session. Default 5000. The
   * push-approval event stream has no deadline.
   */
  timeouts?: { system?: number; request?: number }
  /**
   * Run by contract: the issuer, the workspace, the clients and where the
   * application's keys are published all come from its link in the network's
   * context graph, and none of the CAUTHY_* variables may be set. See
   * "Connect a system by contract".
   *
   *   createCauthy({ contract: { graph, system: 'acme-crm' }, keys: postgresKeyStore(query) })
   */
  contract?: import('./contract').ContractOptions
  /** Where the application keeps its own key, with a contract (@cauthyhq/node/keys). */
  keys?: import('./keys').KeyStore
  /**
   * The one secret of a contracted application: every key it needs is
   * derived from it. 32 random bytes or more. Default: `PACT_ROOT_KEY`.
   */
  rootKey?: string
  /** The root key before the current one, while rotating it. Default: `PACT_ROOT_KEY_PREVIOUS`. */
  rootKeyPrevious?: string
  /**
   * Where `auth.webhook` remembers the deliveries it took, so one sent twice
   * is refused. Default: this process's memory. Give a shared one (a table)
   * when the application runs on several instances.
   */
  webhookReplay?: import('./webhook').ReplayStore
}

/** The person signed in. Every moment is UTC. */
export interface SessionUser {
  id: string
  email: string
  name: string
  emailVerified: boolean
  /**
   * True when the account ran out of time to confirm its address: let it read
   * and refuse its writes.
   */
  restricted: boolean
  /** When an unconfirmed address stops being enough (ISO 8601, UTC), if there is a deadline. */
  emailVerifyBy?: string
  /** The language the person reads in ("es", "en-US"), when Cauthy knows it. */
  locale?: string
  /** A guest: a visitor's session before they sign up. No email; `account.upgrade` makes it an account, keeping `id`. */
  isAnonymous?: boolean
}

/** A value JSON can carry. What crosses from server to browser is typed as this, never `unknown`. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

/** An organization the person belongs to, with their role in it. */
export interface SessionOrganization {
  id: string
  system: string
  name: string
  kind: string
  externalId?: string
  role: string
  /** What the system keeps about the organization, as it filed it in Cauthy. */
  metadata: Record<string, JsonValue>
  /**
   * What the person may do here, as "resource:action" entries ("*" is any):
   * their role's permissions, what it inherits, and anything given to them
   * apart from it. Absent when the system keeps no catalog of roles in Cauthy.
   * Check with `can(organization, resource, action)`.
   */
  permissions?: string[]
  /** What the person is denied here, whatever else allows it. */
  denied?: string[]
  /**
   * Permissions that hold only when their condition does (an amount under a
   * limit, the person's own records…). They are in neither list above: `can`
   * answers no for them, and `auth.check` asks Cauthy. Present, maybe empty,
   * whenever `permissions` is.
   */
  conditional?: ConditionalPermission[]
}

/** A permission with a condition: Cauthy decides it per question (`auth.check`). */
export interface ConditionalPermission {
  resource: string
  action: string
  effect: 'allow' | 'deny'
}

/** What to ask Cauthy about: an action on a resource, with what the conditions read of it. */
export interface CheckQuestion {
  resource: string
  action: string
  /** What a condition reads as `resource.attrs`: `{ amount: 500 }`. */
  attributes?: Record<string, unknown>
  /** The record's id, as a condition reads it (`resource.id`). */
  resourceId?: string
  /** Whose the record is (`resource.owner_id`): `resource.owner_id == subject.id`. */
  ownerId?: string
}

/** An organization, by its id or as the session has it. */
export type OrganizationRef = string | { id: string }

/** The rule that decided a check. */
export interface CheckRule {
  /** A permission of the person's role, or an exception given to the person. */
  source: 'role' | 'exception'
  /** The role, when `source` is `role`. */
  role?: string
  kind: string
  resource: string
  action: string
  effect: 'allow' | 'deny'
  condition?: string
}

/** Cauthy's answer to a check. */
export interface CheckResult {
  allowed: boolean
  /** Why, in words: "allowed by role accountant: invoices:approve". */
  reason: string
  /** The rule that decided; absent when none did (nothing allows it). */
  rule?: CheckRule
}

/** A signed-in person, as the server sees them. */
export interface Session {
  user: SessionUser
  /** The Cauthy tenant the account is of. */
  tenantId: string
  /** The roles the account holds in that tenant. */
  roles: string[]
  /**
   * Cauthy's access token for this person: send it as `Authorization: Bearer`
   * to another service that verifies Cauthy's tokens. Never give it to the browser.
   */
  accessToken: string
  /** When the access token expires and the session is checked with Cauthy again (ISO 8601, UTC). */
  expiresAt: string
}

/** What the browser is told of a session: who, and their organizations — never a token. */
export interface PublicSession {
  user: SessionUser
  tenantId: string
  roles: string[]
  organizations: SessionOrganization[]
  expiresAt: string
}

/** Why there is no session. */
export type SessionStatus =
  | 'authenticated'
  | 'unauthenticated' // nobody is signed in
  | 'expired' // signed in, but the session must be renewed first (see `Cauthy.resolve`)

export class CauthyConfigError extends Error {
  constructor(message: string) {
    super(`@cauthyhq/node: ${message}`)
    this.name = 'CauthyConfigError'
  }
}
