// Copied from cauthy-auth 0.42 so the tests can drive the server the way a
// browser does. Not published: the browser client ships in @cauthyhq/js.

// The application's own sign-in screens, in the browser.
//
//   const auth = createAuthClient()
//   const r = await auth.signIn.email({ email, password })
//   if (!r.ok) show(r.error.message)            // r.error.field says which input
//   else if (r.status === 'mfa_required') askForTheCode()
//
// Every call goes to the application's own server (`/api/auth/*`), never to
// Cauthy: the browser holds no token, before or after. A form is checked here
// before it is sent, with the rules the server checks again.

import { canAutofillPasskeys, canUsePasskeys, ceremonyError, getPasskey, makePasskey } from './passkey'
import { fromWire, type CauthyTheme } from '../src/theme'
import type { CheckQuestion, CheckResult, OrganizationRef, PublicSession } from '../src/types'
export type { CheckQuestion, CheckResult, CheckRule, OrganizationRef } from '../src/types'
import { checkCode, checkEmail, checkName, checkNewPassword, checkPassword, firstProblem, passwordPolicyOf, type AuthField, type FieldProblem, type PasswordPolicy, checkOrganization, checkOrganizationName } from '../src/validate'
import { withoutTrailingSlashes } from '../src/url'

export { checkCode, checkEmail, checkName, checkNewPassword, checkPassword, describePasswordPolicy, explainPasswordProblems, passwordPolicyOf, passwordProblems, DEFAULT_PASSWORD_POLICY, MIN_PASSWORD, type AuthField, type FieldProblem, type PasswordClass, type PasswordLocale, type PasswordPolicy, type PasswordReason } from '../src/validate'

/** What went wrong, in a form the screen can show. */
export interface AuthError {
  /** Stable, for translating: `invalid_credentials`, `invalid_email`, `too_short`, `email_taken`, `unavailable`… */
  code: string
  message: string
  /** The input it is about, when it is about one. */
  field?: AuthField
  /** `weak_password`: the rules of the workspace's password policy it failed (`too_short`, `needs_digit`, …). */
  reasons?: string[]
}

export type AuthResult<S extends string, More = unknown> = ({ ok: true; status: S } & More) | { ok: false; error: AuthError }

/** What the screen may offer. */
export interface AuthMethods {
  /**
   * The providers the workspace signs people in with and has turned on:
   * `{ id: 'google', name: 'Google', iconUrl: 'https://…/v1/social/icons/google.svg' }`.
   * `iconUrl` is the provider's logo, served by Cauthy; absent from a Cauthy
   * that does not serve logos.
   */
  providers: { id: string; name: string; iconUrl?: string }[]
  /**
   * Whether the workspace signs people in with a password. False: the
   * password field, "forgot your password" and a sign-up with a password are
   * not offered, and Cauthy refuses them (`password_disabled`). True from a
   * server that does not say. (`password` is something else: the policy a new
   * password must meet.)
   */
  passwordSignIn: boolean
  /**
   * Whether the application's client may keep people signed in when they ask
   * (an administrator turns it on in Cauthy). The ready-made sign-in shows
   * "Keep me signed in" by itself; absent from a Cauthy that does not say.
   */
  persistentSessions?: boolean
  /** Whether people may create an account themselves. */
  signUp: boolean
  /** Set when the application's system makes an organization per sign-up: the form asks the company's name. */
  organization?: { ask: boolean; required: boolean }
  magicLink: boolean
  /** Whether to offer a passkey. False when the workspace turned passkeys off. */
  passkey: boolean
  /**
   * Whether the passkey is used on this page itself. False: `signIn.passkey`
   * sends the person to Cauthy's page for that step alone, and they come back
   * signed in. That happens only when this page is outside the domain the
   * workspace's passkeys belong to.
   */
  passkeyHere: boolean
  /**
   * Whether Cauthy's page can use the passkey, for that step alone: where a
   * page that cannot, or a browser that refuses to here, sends the person.
   */
  passkeyOnCauthy: boolean
  /**
   * The workspace's Cloudflare Turnstile site key, when it asks for the
   * challenge: signing in, creating an account, and asking for a sign-in link
   * or a new password then take its answer (`captchaToken`). The ready-made
   * forms show it themselves.
   */
  captchaSiteKey?: string
  /**
   * Whether the workspace signs some people in through their company's SSO,
   * found by their work address (`signIn.ssoDiscover`, `signIn.sso`).
   */
  sso: boolean
  /**
   * Set when the workspace asks something of a sign-up: the legal documents
   * to accept (the terms, the privacy policy: show the links and a box, send
   * `acceptLegal: true`) and the consents to ask (one box each, sent as
   * `consents`; a required one must be ticked). The ready-made form shows them.
   */
  legal?: { documents: { kind: string; version: string; url: string }[]; consentPurposes: { key: string; label: string; required: boolean }[] }
  /**
   * What a new password must be in the workspace. Once `methods()` has
   * answered, this client checks new passwords against it before sending
   * them; until then, against the defaults (12 to 128 characters). Absent
   * from a server that does not say.
   */
  password?: PasswordPolicy
}

/** An invitation, as its page shows it before the person chooses a password. */
export interface Invitation {
  /** The address invited: the account the person signs in as. */
  email: string
  /** The workspace's name. */
  workspace: string
  /** The organization the person was invited to, when there is one. */
  organization?: string
}

/** A legal document the person owes: not yet accepted in its current version. */
export interface PendingLegal { kind: string; version: string; url: string }

/** A company's sign-in (an SSO connection of the workspace). */
export interface SSOConnection {
  /** What `signIn.sso({ connection })` takes. */
  id: string
  /** The company's name, for "Continue with …". */
  name: string
  /** The address can sign in no other way: a password, link or provider answers `sso_required`. */
  enforced: boolean
}

/**
 * What holds a passkey, as its authenticator says: a security key (a YubiKey),
 * one synced across the person's devices (iCloud Keychain, Google Password
 * Manager), one on a single device (Windows Hello), or unknown (made before
 * Cauthy kept this).
 */
export type PasskeyKind = 'security_key' | 'synced' | 'device' | 'unknown'

/** A passkey of the signed-in account. Moments are UTC. */
export interface Passkey {
  id: string
  /** What the person called it ("My laptop"), or "". */
  name: string
  kind: PasskeyKind
  createdAt: string
  /** When it last signed the person in, or null. */
  lastUsedAt: string | null
}

/** A person's own account, as their account screen shows it. */
export interface Account {
  id: string
  email: string
  name: string
  emailVerified: boolean
  /** False for an account that only signs in through a provider: it has no current password to ask for. */
  hasPassword: boolean
  mfaEnabled: boolean
}

/** Somewhere the person is signed in. Moments are UTC. */
/** An AI agent the person allowed to act for them on one of the workspace's servers. */
export interface ConnectedAgent {
  id: string
  /** The name the agent gave itself (Claude, Cursor…): not checked by anyone. */
  name: string
  /** Where the agent receives its access: the one thing about it that is sure. */
  redirectHost: string
  resource: { name: string; uri: string }
  /** What the person allowed it, in their words. */
  scopes: { name: string; description: string }[]
  /** UTC, ISO 8601. */
  connectedAt: string
  lastUsedAt: string
}

/** An organization the person belongs to, with what their role lets them do with it and its people. */
export interface OrganizationSeat {
  id: string
  /** The client system it is of (`acme-crm`). */
  system: string
  name: string
  kind: string
  /** The person's role in it. */
  role: string
  /**
   * Cauthy's reserved powers, from the system's catalog. `manageMembers`
   * (cauthy:members:manage) adds, invites and changes roles; removing another
   * member is `removeMembers` (cauthy:members:remove), and anybody may leave.
   * `update`, `archive` and `delete` are cauthy:organization's: rename it,
   * archive it, delete it for good.
   */
  can: { readMembers: boolean; manageMembers: boolean; removeMembers: boolean; update: boolean; archive: boolean; delete: boolean }
}

/** A person of an organization, as a member who may see them reads it. */
export interface OrganizationPerson {
  userId: string
  email: string
  name: string
  role: string
  /** The account's: `active`, `suspended`… A disabled member is still listed. */
  status: string
  /** Invited and not yet accepted. */
  invited: boolean
  /** Manages the organization's members. */
  manager: boolean
  /** The signed-in person. */
  you: boolean
  /** UTC, ISO 8601. */
  since: string
}

/** A role of the organization's system, as the catalog names it. */
export interface OrganizationRoleChoice {
  role: string
  name: string
  description: string
  /** Holding it manages the organization's members. */
  manager: boolean
}

/**
 * The signed-in person's organizations, and their people. Seeing them needs
 * cauthy:members read in the person's role; changing them needs manage, and
 * removing someone needs remove. The organization itself is renamed, archived
 * or deleted with cauthy:organization update, archive or delete. Only an
 * `owner` gives the owner role or changes an owner, and the last owner stays
 * (`last_owner`). Cauthy decides, with the person's own session: the
 * application authorizes nothing.
 */
export interface OrganizationsClient {
  /** The organizations the person belongs to; one system's only with `system`. */
  list(system?: string): Promise<OrganizationSeat[]>
  /** The people of one, or null when the person may not see them. */
  members(organizationId: string): Promise<OrganizationPerson[] | null>
  /** The roles a member may be given, or null when the person may not see them. */
  roles(organizationId: string): Promise<OrganizationRoleChoice[] | null>
  /**
   * Adds a person by their address; an address with no account gets one and
   * its invitation. It only adds: a person who already belongs keeps their
   * role and the result is the error `member_exists` (change it with `setRole`).
   */
  add(organizationId: string, form: { email: string; role: string; name?: string; locale?: string }): Promise<AuthResult<'added', { member: OrganizationPerson }>>
  setRole(organizationId: string, userId: string, role: string): Promise<AuthResult<'changed', { userId: string; role: string }>>
  /** Removes a member; the person themself may always leave. */
  remove(organizationId: string, userId: string): Promise<AuthResult<'removed', { userId: string }>>
  /** Sends a member's invitation again. */
  inviteAgain(organizationId: string, userId: string, form?: { locale?: string }): Promise<AuthResult<'sent', { userId: string }>>
  /** Gives the organization a new name (cauthy:organization update). */
  rename(organizationId: string, name: string): Promise<AuthResult<'renamed', { organization: OrganizationSeat }>>
  /** Archives the organization: its members no longer reach it, and only the workspace restores it. */
  archive(organizationId: string): Promise<AuthResult<'archived', { organizationId: string }>>
  /** Deletes the organization for good. */
  delete(organizationId: string): Promise<AuthResult<'deleted', { organizationId: string }>>
  /**
   * Asks Cauthy, through the application's server, whether the person may do
   * an action on a resource in the organization, with what its conditions
   * read. A question that could not be asked is a no, with `error` saying why.
   *
   *   const r = await organizations.check({ organization, resource: 'invoices', action: 'approve', attributes: { amount: 500 } })
   *   if (r.allowed) showApprove()
   */
  check(question: CheckQuestion & { organization: OrganizationRef }): Promise<CheckResult & { error?: AuthError }>
}

export interface AccountSession {
  /** "Mac · Chrome", or "" when the browser did not say. */
  device: string
  ip: string
  createdAt: string
  expiresAt: string
}

/**
 * The signed-in person's own account. What weakens it — the password, the
 * second step, its recovery codes — asks for the current password again.
 */
/** A provider the account can also sign in with. */
export interface LinkedIdentity {
  provider: string
  /** The address the provider has for the person, when it said. */
  email: string
  name: string
  /** When it was linked, in UTC (ISO 8601). */
  linkedAt: string
}

/** How an account takes its second step. */
export interface SecondStep {
  totp: boolean
  /** The phone codes are sent to, masked (`+57 ••• ••• 4567`). */
  phone: { number: string; channel: string } | null
  /** The ways the workspace sends codes to phones. */
  phoneChannels: string[]
}

export interface AccountClient {
  /** The account, or null when nobody is signed in. */
  get(): Promise<Account | null>
  update(form: { name: string }): Promise<AuthResult<'saved', { account: Account }>>
  /** Ends every other session of the account; this one stays signed in. */
  changePassword(form: { password: string; newPassword: string }): Promise<AuthResult<'changed', { signedIn: boolean }>>
  /**
   * The legal documents the person has not accepted in their current version
   * (a new version of the terms, say): show them and call `acceptLegal`.
   * Nothing stops the person meanwhile; the application decides what waits.
   */
  legal(): Promise<AuthResult<'ok', { pending: PendingLegal[] }>>
  /** Records the person's acceptance of the documents in force (the kinds named, or every one). */
  acceptLegal(form?: { kinds?: string[] }): Promise<AuthResult<'accepted'>>
  mfa: {
    /** Starts turning the second step on: show `qr` (the `otpauthUri` drawn by Cauthy, a PNG `data:` URI; empty from an older Cauthy) and `secret` to add to an authenticator app, then call `verify`. */
    setup(form: { password: string }): Promise<AuthResult<'started', { secret: string; otpauthUri: string; qr: string }>>
    /** Turns it on with a code from the app. `recoveryCodes` are shown this once. */
    verify(form: { code: string }): Promise<AuthResult<'enabled', { recoveryCodes: string[] }>>
    disable(form: { password: string }): Promise<AuthResult<'disabled'>>
    /** New recovery codes; the earlier ones stop working. */
    recoveryCodes(form: { password: string }): Promise<AuthResult<'renewed', { recoveryCodes: string[] }>>
    /**
     * How the account takes its second step: an authenticator app, a phone
     * (masked), and the ways the workspace sends codes to phones (`sms`,
     * `whatsapp`; none when it has no Twilio account for it).
     */
    factors(): Promise<SecondStep | null>
    /** Adds a phone as the second step: a code is sent to it, for `verifyPhone`. */
    addPhone(form: { phone: string; channel: 'sms' | 'whatsapp'; password: string }): Promise<AuthResult<'sent', { sentTo: string; channel: string }>>
    /** Proves the phone with the code it received. `recoveryCodes` come with a first second step, shown this once. */
    verifyPhone(form: { code: string }): Promise<AuthResult<'enabled', { recoveryCodes: string[] }>>
    removePhone(form: { password: string }): Promise<AuthResult<'removed'>>
  }
  /**
   * Asks to sign in with another address. Nothing changes yet: the new address
   * is mailed a link to confirm it, and once it is confirmed the old one is
   * told, with a link that undoes it. Both open Cauthy's own page.
   */
  changeEmail(form: { email: string; password: string }): Promise<AuthResult<'sent', { email: string }>>
  /** The providers (Google…) the account can also sign in with. */
  identities(): Promise<LinkedIdentity[]>
  /**
   * Sends the browser to the provider, to link it to the account; it comes back
   * at `returnTo` with `?linked=<provider>`, or `?auth_error=<code>`.
   */
  link(provider: string, options?: { returnTo?: string }): void
  /** Where `link` sends the browser, for a plain link. */
  linkUrl(provider: string, options?: { returnTo?: string }): string
  /** The account stops signing in with that provider. Refused when it would be left with no way to sign in. */
  unlink(provider: string): Promise<AuthResult<'unlinked', { provider: string }>>
  /**
   * A guest becomes an account of their own with an address and a password —
   * the same id, so what they did stays theirs. `email_taken`: the address has
   * an account already; offer to sign in with it.
   */
  upgrade(form: { email: string; password: string; name?: string }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
  /** Where a guest goes to become the account of a provider's address (Google…). */
  upgradeUrl(provider: string, options?: { returnTo?: string }): string
  /** Sends a guest to `upgradeUrl`; they come back signed in as the account. */
  upgradeWith(provider: string, options?: { returnTo?: string }): void
  /** Where the account is signed in. */
  sessions(): Promise<AccountSession[]>
  /** Signs the account out everywhere, here too. */
  signOutEverywhere(): Promise<AuthResult<'signed_out'>>
  /** The AI agents the person connected. */
  agents(): Promise<ConnectedAgent[]>
  /** Disconnects an agent: it loses its access within minutes. */
  disconnectAgent(id: string): Promise<AuthResult<'disconnected', { id: string }>>
  /** The account's passkeys. */
  passkeys(): Promise<Passkey[]>
  /**
   * Makes a passkey on this device, on this page: the browser asks the person
   * for their fingerprint, face or screen lock. An account with a password
   * proves it again first. `cancelled`: the person closed the browser's prompt.
   * `kind` sends the browser straight to one: `'device'`, this device's
   * fingerprint, face or screen lock; `'security_key'`, a security key.
   * Without it, the browser offers all.
   */
  addPasskey(form?: { password?: string; name?: string; kind?: 'device' | 'security_key' }): Promise<AuthResult<'added', { passkey: Passkey }>>
  removePasskey(id: string): Promise<AuthResult<'removed', { id: string }>>
}

export interface AuthClient {
  signIn: {
    /**
     * A guest session, before the visitor signs up: the application keeps what
     * they do under `session.user.id`, and `account.upgrade` (or
     * `account.upgradeWith`) makes it their account, same id. Only where the
     * workspace allows guests (`anonymous_disabled` otherwise).
     */
    anonymously(form?: { captchaToken?: string }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /**
     * With address and password. `mfa_required`: ask for the code and call
     * `signIn.mfa`. `method: 'email'` says the code was just mailed to the
     * account's address (it has no factor of its own and the workspace, or
     * the sign-in's risk, asked a second step): say so, and offer
     * `mfaSendEmail` for another.
     */
    email(form: { email: string; password: string; captchaToken?: string; remember?: boolean }): Promise<AuthResult<'signed_in', { session: PublicSession }> | AuthResult<'mfa_required', { method?: 'email' }>>
    /** The second step: the code of the authenticator app, the phone, the email, or a recovery code. */
    mfa(form: { code: string }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /**
     * While the second step is asked for: whether the account has an
     * authenticator app, the phone (masked) a code can be sent to, phones
     * that approve sign-ins, and the address (masked) a code went to when
     * the step is by email.
     */
    mfaMethods(): Promise<AuthResult<'ok', { totp: boolean; phone: { number: string; channel: string } | null; push: { devices: number } | null; email: { to: string } | null }>>
    /** Mails the sign-in's code again, when its second step is by email; `mfa` takes it. A few per sign-in. */
    mfaSendEmail(): Promise<AuthResult<'sent', { sentTo: string }>>
    /**
     * Sends a push to the account's phones (the application's app, with
     * cauthy-expo): show `number`, which the person picks on the phone, then
     * call `mfaPushWait`.
     */
    mfaPush(): Promise<AuthResult<'sent', { number: number }>>
    /**
     * Waits for the phone's answer, listening (server-sent events) rather than
     * asking again and again, and signs in when it approves. `denied`: turned
     * down on the phone; `expired`: nobody answered in time.
     */
    mfaPushWait(o?: { signal?: AbortSignal }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /** Sends a code to the account's phone, by SMS or WhatsApp; `mfa` takes it. A few per sign-in. */
    mfaSendCode(): Promise<AuthResult<'sent', { sentTo: string; channel: string }>>
    /**
     * Mails a link (and a code) that signs the person in. The answer is the
     * same whether or not the address has an account. `create`: an address
     * with no account gets one when the link or code is used, if the
     * workspace accepts new accounts — one screen signs people in and up.
     * `returnTo` (a path of this site) travels in the link: the page it opens
     * gets it as `?return_to=`, and `emailCode` answers it.
     */
    magicLink(form: { email: string; captchaToken?: string; create?: boolean; returnTo?: string; remember?: boolean }): Promise<AuthResult<'sent'>>
    /** Signs in with the token the mailed link opened the page with (`ml_token`). */
    magicLinkVerify(form: { token: string; remember?: boolean }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /** Signs in with the code that came in the same mail as the link, for somebody reading it on another device. */
    emailCode(form: { code: string }): Promise<AuthResult<'signed_in', { session: PublicSession; returnTo?: string }>>
    /**
     * Signs in with a passkey, on this page: the browser asks the person for
     * their fingerprint, face or screen lock. When this page cannot use the
     * workspace's passkeys (`methods().passkeyHere` is false), the browser goes
     * to Cauthy's page for that step alone and comes back signed in, at
     * `returnTo`: then the answer is `redirected`. `cancelled`: the person
     * closed the browser's prompt. `email`, when the person typed it: the
     * browser is told which passkeys are theirs, so a security key that did
     * not keep its passkey (one made before cauthy-auth 0.18.0) is found too.
     */
    passkey(options?: { returnTo?: string; locale?: string; email?: string; remember?: boolean }): Promise<AuthResult<'signed_in', { session: PublicSession }> | AuthResult<'redirected'>>
    /**
     * Offers the person's passkeys in the browser's autofill of the email
     * field, which must carry `autocomplete="username webauthn"`, and signs in
     * with the one they pick. It waits until they pick one or `signal`
     * aborts: abort it before calling `passkey` or sending the form.
     * `cancelled`: aborted, or this browser or page cannot (then there is
     * nothing to offer, and the passkey button still works).
     */
    passkeyAutofill(options?: { signal?: AbortSignal; remember?: () => boolean }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /**
     * Google One Tap: Google's prompt over the page offers the Google account
     * the browser already has, and signs in with it in one tap, as the Google
     * sign-in does (the same account). Needs the workspace's Google sign-in,
     * and the page's address among the Google client's authorized JavaScript
     * origins. Waits until the person picks an account or closes the prompt
     * (`cancelled`), or `signal` aborts. `one_tap_unavailable`: the workspace
     * has no Google sign-in.
     */
    googleOneTap(options?: { signal?: AbortSignal; context?: 'signin' | 'signup' | 'use'; remember?: () => boolean }): Promise<AuthResult<'signed_in', { session: PublicSession }>>
    /** Where `passkey` sends the browser when this page cannot use the passkey itself. */
    passkeyUrl(options?: { returnTo?: string; locale?: string }): string
    /** Sends the browser to the provider; it comes back signed in, at `returnTo`. */
    social(provider: string, options?: { returnTo?: string; remember?: boolean }): void
    /**
     * Which company's sign-in a work address uses, if any (`found`), or
     * `none`. It says so of the address's domain, never whether the address
     * has an account.
     */
    ssoDiscover(form: { email: string }): Promise<AuthResult<'found', { connection: SSOConnection }> | AuthResult<'none'>>
    /**
     * Sends the browser to the person's company (found by `email`, or named
     * by `connection`); it comes back signed in, at `returnTo`. A sign-in the
     * company refused comes back with `?auth_error=`. Any other way of
     * signing in answers `sso_required` for an address its company holds to
     * SSO: send it here then.
     */
    sso(target: { email: string } | { connection: string }, options?: { returnTo?: string; remember?: boolean }): void
    /** Where `sso` sends the browser, for a plain link. */
    ssoUrl(target: { email: string } | { connection: string }, options?: { returnTo?: string; remember?: boolean }): string
    /** Where `social` sends the browser, for a plain link. */
    socialUrl(provider: string, options?: { returnTo?: string; remember?: boolean }): string
  }
  signUp: {
    /**
     * `verification_required`: the account exists and must open the link Cauthy mailed before it can sign in.
     * `acceptLegal` and `consents` answer what `methods().legal` asks; a sign-up that leaves them out is refused.
     */
    email(form: { email: string; password: string; name?: string; organization?: string; acceptLegal?: boolean; consents?: Record<string, boolean>; captchaToken?: string }): Promise<AuthResult<'signed_in', { session: PublicSession }> | AuthResult<'verification_required', { email: string }>>
  }
  /** Mails a link to choose a new password. The answer is the same whether or not the address has an account. */
  forgotPassword(form: { email: string; captchaToken?: string }): Promise<AuthResult<'sent'>>
  /** Sets the new password, with the token the mailed link opened the page with (`token`). */
  resetPassword(form: { token: string; password: string }): Promise<AuthResult<'changed'>>
  /**
   * Who an invitation is for and to what, with the token the mailed link
   * opened the page with (`token`). Reading it does not spend it.
   * `invalid_token`: unknown, spent or expired.
   */
  invitation(token: string): Promise<AuthResult<'ok', { invitation: Invitation }>>
  /**
   * Accepts an invitation with the password the person chose (the workspace's
   * policy, as for a sign-up) and signs them in. `mfa_required`: the account
   * owes a second step; ask for the code and call `signIn.mfa`, as after
   * `signIn.email`. A password refused leaves the invitation good.
   */
  acceptInvitation(token: string, password: string): Promise<AuthResult<'signed_in', { session: PublicSession }> | AuthResult<'mfa_required', { method?: 'email' }>>
  /** Confirms the address a mailed link is for. The person is signed in from the link when their account asks no second step. */
  verifyEmail(form: { token: string }): Promise<AuthResult<'verified'> | AuthResult<'signed_in', { session: PublicSession }>>
  signOut(): Promise<AuthResult<'signed_out'>>
  /** The signed-in person's own account. */
  account: AccountClient
  /** The signed-in person's organizations, and their people. */
  organizations: OrganizationsClient
  /** Who is signed in, or null. */
  getSession(): Promise<PublicSession | null>
  methods(): Promise<AuthMethods>
  /**
   * How the workspace's forms look — colours, corners, typeface — as a person
   * set it in Cauthy's dashboard. Read once per page; null when Cauthy cannot say.
   */
  look(): Promise<CauthyTheme | null>
}

export interface AuthClientOptions {
  /** Where the server mounted the routes. Default: `/api/auth`. */
  basePath?: string
  fetch?: typeof fetch
  /**
   * The language the person reads, for what Cauthy mails them (a sign-in
   * link, a new password, a confirmation): a tag like `es` or `es-CO`, or a
   * function that answers it when the person can change it. Default: the
   * page's own (`<html lang>`), else the browser's.
   */
  locale?: string | (() => string | undefined)
}

/** Google Identity Services, as much of it as One Tap uses. */
interface GoogleMoment {
  isNotDisplayed?: () => boolean
  isSkippedMoment?: () => boolean
  isDismissedMoment?: () => boolean
  getDismissedReason?: () => string
}
interface GoogleIdentity {
  initialize(config: Record<string, unknown>): void
  prompt(listener?: (moment: GoogleMoment) => void): void
  cancel(): void
}

let googleScript: Promise<GoogleIdentity> | null = null

/** Loads Google's script once per page. */
function loadGoogleIdentity(): Promise<GoogleIdentity> {
  const ready = () => (window as unknown as { google?: { accounts?: { id?: GoogleIdentity } } }).google?.accounts?.id
  if (ready()) return Promise.resolve(ready()!)
  googleScript ??= new Promise<GoogleIdentity>((resolve, reject) => {
    const script = document.createElement('script')
    script.src = 'https://accounts.google.com/gsi/client'
    script.async = true
    script.onload = () => (ready() ? resolve(ready()!) : reject(new Error('google identity services did not load')))
    script.onerror = () => {
      googleScript = null
      reject(new Error('google identity services did not load'))
    }
    document.head.appendChild(script)
  })
  return googleScript
}

/** How long Cauthy waits for a passkey ceremony to be answered. */
const PASSKEY_SECONDS = 300

const UNAVAILABLE: AuthError = { code: 'unavailable', message: 'Sign-in is unavailable right now. Try again in a moment.' }

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
  const base = withoutTrailingSlashes(options.basePath ?? '/api/auth')
  const doFetch: typeof fetch = (...args) => (options.fetch ?? fetch)(...args)
  const locale = (): string => {
    const said = typeof options.locale === 'function' ? options.locale() : options.locale
    return (said ?? (typeof document === 'undefined' ? '' : document.documentElement?.lang) ?? '').trim()
  }

  async function post(path: string, form: Record<string, unknown>, bad: FieldProblem | null, captchaToken?: string): Promise<any> {
    if (bad) return { ok: false, error: { code: bad.code, message: bad.message, field: bad.field } }
    try {
      const res = await doFetch(`${base}${path}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', accept: 'application/json', 'x-cauthy-request': '1', ...(locale() ? { 'x-cauthy-locale': locale() } : {}), ...(captchaToken ? { 'x-cauthy-captcha': captchaToken } : {}) },
        body: JSON.stringify(form),
      })
      const body = (await res.json().catch(() => null)) as any
      if (res.ok && body && typeof body.status === 'string') return { ok: true, ...body }
      const e = body?.error
      return { ok: false, error: e && typeof e.code === 'string' ? { code: e.code, message: String(e.message ?? ''), ...(e.field ? { field: e.field } : {}), ...(Array.isArray(e.reasons) ? { reasons: e.reasons.map(String) } : {}) } : UNAVAILABLE }
    } catch {
      return { ok: false, error: UNAVAILABLE }
    }
  }

  let looked: Promise<CauthyTheme | null> | undefined

  async function read(path: string): Promise<any> {
    try {
      const res = await doFetch(`${base}${path}`, { credentials: 'same-origin', headers: { accept: 'application/json' } })
      return res.ok ? await res.json() : null
    } catch {
      return null
    }
  }

  const upgradeUrl = (provider: string, o: { returnTo?: string } = {}) =>
    `${base}/me/upgrade/social/${encodeURIComponent(provider)}${o.returnTo ? `?return_to=${encodeURIComponent(o.returnTo)}` : ''}`
  const linkUrl = (provider: string, o: { returnTo?: string } = {}) =>
    `${base}/me/identities/link/${encodeURIComponent(provider)}${o.returnTo ? `?return_to=${encodeURIComponent(o.returnTo)}` : ''}`
  const socialUrl = (provider: string, o: { returnTo?: string; remember?: boolean } = {}) => {
    const q = new URLSearchParams()
    if (o.returnTo) q.set('return_to', o.returnTo)
    if (o.remember) q.set('remember', '1')
    const query = q.toString()
    return `${base}/sign-in/social/${encodeURIComponent(provider)}${query === '' ? '' : `?${query}`}`
  }

  const ssoUrl = (target: { email: string } | { connection: string }, o: { returnTo?: string; remember?: boolean } = {}) => {
    const q = new URLSearchParams('connection' in target ? { connection: target.connection } : { email: target.email.trim() })
    if (o.returnTo) q.set('return_to', o.returnTo)
    if (o.remember) q.set('remember', '1')
    return `${base}/sign-in/sso?${q}`
  }

  const passkeyUrl = (o: { returnTo?: string; locale?: string } = {}) => {
    const q = new URLSearchParams({ method: 'passkey' })
    if (o.returnTo) q.set('return_to', o.returnTo)
    if (o.locale) q.set('locale', o.locale)
    return `${base}/login?${q}`
  }

  // The workspace's password policy, once methods() has said it.
  let policy: PasswordPolicy | undefined

  async function methods(): Promise<AuthMethods> {
    try {
      const res = await doFetch(`${base}/methods`, { credentials: 'same-origin', headers: { accept: 'application/json' } })
      if (res.ok) {
        // A server from before the passkey on the page does not say; then it is not.
        const m = (await res.json()) as Partial<AuthMethods>
        // The workspace's password rule, for the checks before a password is sent.
        if (m.password) policy = passwordPolicyOf(m.password)
        return { providers: [], signUp: true, magicLink: false, passkey: false, ...m, ...(policy ? { password: policy } : {}), passwordSignIn: m.passwordSignIn !== false, passkeyHere: m.passkeyHere === true, passkeyOnCauthy: m.passkeyOnCauthy ?? m.passkey === true, sso: m.sso === true }
      }
    } catch {
      // falls through
    }
    return { providers: [], signUp: true, passwordSignIn: true, magicLink: false, passkey: false, passkeyHere: false, passkeyOnCauthy: false, sso: false }
  }

  /** The two steps of a ceremony: what to ask the browser, then its answer. */
  async function ceremony(begin: string, finish: string, form: Record<string, unknown>, run: (options: any) => Promise<Record<string, unknown>>, more: Record<string, unknown> = {}): Promise<any> {
    const begun = await post(begin, form, null)
    if (!begun.ok) return begun
    let credential: Record<string, unknown>
    try {
      credential = await run(begun.options)
    } catch (e) {
      return { ok: false, error: ceremonyError(e) }
    }
    return post(finish, { credential, ...more }, null)
  }

  return {
    signIn: {
      anonymously: (f = {}) => post('/sign-in/anonymous', {}, null, f.captchaToken),
      email: (f) => post('/sign-in/email', { email: f.email, password: f.password, ...(f.remember ? { remember: true } : {}) }, firstProblem(checkEmail(f.email), checkPassword(f.password)), f.captchaToken),
      mfa: (f) => post('/sign-in/mfa', { code: f.code }, checkCode(f.code)),
      mfaMethods: () => post('/sign-in/mfa/methods', {}, null),
      mfaSendCode: () => post('/sign-in/mfa/send', {}, null),
      mfaSendEmail: () => post('/sign-in/mfa/email', {}, null),
      mfaPush: () => post('/sign-in/mfa/push', {}, null),
      async mfaPushWait(o = {}) {
        const status = await new Promise<string>((resolve) => {
          if (typeof EventSource !== 'function') return resolve('approved') // finish says whether it was
          const source = new EventSource(`${base}/sign-in/mfa/push/events`, { withCredentials: true })
          const stop = (st: string) => {
            source.close()
            resolve(st)
          }
          o.signal?.addEventListener('abort', () => stop('aborted'))
          source.addEventListener('status', (e) => {
            const st = (() => {
              try {
                return String(JSON.parse((e as MessageEvent).data).status)
              } catch {
                return ''
              }
            })()
            if (st && st !== 'pending') stop(st)
          })
          source.onerror = () => {
            if (source.readyState === EventSource.CLOSED) stop('expired')
          }
        })
        if (status === 'aborted') return { ok: false, error: { code: 'aborted', message: 'Stopped waiting.' } }
        if (status === 'denied') return { ok: false, error: { code: 'push_denied', message: 'The sign-in was turned down on the phone.' } }
        if (status === 'expired') return { ok: false, error: { code: 'push_expired', message: 'Nobody answered on the phone in time.' } }
        return post('/sign-in/mfa/push/finish', {}, null)
      },
      magicLink: (f) => post('/sign-in/magic-link', { email: f.email, ...(f.create ? { create: true } : {}), ...(f.returnTo ? { returnTo: f.returnTo } : {}), ...(f.remember ? { remember: true } : {}) }, checkEmail(f.email), f.captchaToken),
      magicLinkVerify: (f) => post('/sign-in/magic-link/verify', { token: f.token, ...(f.remember ? { remember: true } : {}) }, null),
      emailCode: (f) => post('/sign-in/email-code', { code: f.code }, checkCode(f.code)),
      passkeyUrl,
      async passkey(o) {
        const m = await methods()
        if (m.passkeyHere && canUsePasskeys()) {
          const email = o?.email?.trim() ?? ''
          const r = await ceremony('/sign-in/passkey/begin', '/sign-in/passkey/finish', { ...(email !== '' && checkEmail(email) === null ? { email } : {}), ...(o?.remember ? { remember: true } : {}) }, getPasskey)
          // A browser that does not read the domain's related origins refuses
          // this page: Cauthy's, then, when it can.
          if (r.ok || r.error.code !== 'passkey_unavailable' || !m.passkeyOnCauthy) return r
        } else if (!m.passkeyOnCauthy) {
          return { ok: false, error: { code: 'passkey_unavailable', message: 'Passkeys cannot be used here.' } }
        }
        window.location.assign(passkeyUrl(o))
        return { ok: true, status: 'redirected' }
      },
      async passkeyAutofill(o = {}) {
        const cancelled = { ok: false as const, error: { code: 'cancelled', message: 'No passkey was chosen.' } }
        const m = await methods()
        if (!m.passkeyHere || !(await canAutofillPasskeys())) return cancelled
        for (;;) {
          if (o.signal?.aborted) return cancelled
          const begun = await post('/sign-in/passkey/begin', {}, null)
          if (!begun.ok) return begun
          // Cauthy's challenge lives five minutes: a page left open asks for
          // a fresh one before it runs out.
          const renew = new AbortController()
          const stop = () => renew.abort()
          o.signal?.addEventListener('abort', stop, { once: true })
          const timer = setTimeout(stop, (PASSKEY_SECONDS - 30) * 1000)
          let credential: Record<string, unknown>
          try {
            credential = await getPasskey(begun.options, { mediation: 'conditional', signal: renew.signal })
          } catch (e) {
            if (o.signal?.aborted) return cancelled
            if (renew.signal.aborted) continue
            return { ok: false, error: ceremonyError(e) }
          } finally {
            clearTimeout(timer)
            o.signal?.removeEventListener('abort', stop)
          }
          return post('/sign-in/passkey/finish', { credential, ...(o.remember?.() ? { remember: true } : {}) }, null)
        }
      },
      async googleOneTap(o = {}) {
        const cancelled = { ok: false as const, error: { code: 'cancelled', message: 'No Google account was chosen.' } }
        if (typeof window === 'undefined' || o.signal?.aborted) return cancelled
        const begun = await post('/sign-in/google-one-tap/begin', {}, null)
        if (!begun.ok) return begun
        let gis: GoogleIdentity
        try {
          gis = await loadGoogleIdentity()
        } catch {
          return { ok: false, error: { code: 'unavailable', message: 'Google could not be reached. Try again, or sign in another way.' } }
        }
        const credential = await new Promise<string | null>((done) => {
          o.signal?.addEventListener('abort', () => {
            gis.cancel()
            done(null)
          }, { once: true })
          gis.initialize({
            client_id: begun.clientId, nonce: begun.nonce, context: o.context ?? 'signin',
            callback: (r: { credential?: string }) => done(r.credential ?? null),
            auto_select: false, cancel_on_tap_outside: true, itp_support: true, use_fedcm_for_prompt: true,
          })
          gis.prompt((moment: GoogleMoment) => {
            // The prompt was not shown, or the person closed it.
            if (moment.isNotDisplayed?.() || moment.isSkippedMoment?.()) done(null)
            else if (moment.isDismissedMoment?.() && moment.getDismissedReason?.() !== 'credential_returned') done(null)
          })
        })
        if (credential === null) return cancelled
        return post('/sign-in/google-one-tap', { credential, ...(o.remember?.() ? { remember: true } : {}) }, null)
      },
      socialUrl,
      social(provider, o) {
        window.location.assign(socialUrl(provider, o))
      },
      ssoDiscover: (f) => post('/sign-in/sso/discover', { email: f.email.trim() }, checkEmail(f.email)),
      ssoUrl,
      sso(target, o) {
        window.location.assign(ssoUrl(target, o))
      },
    },
    signUp: {
      email: (f) => post('/sign-up/email', { email: f.email, password: f.password, name: f.name, organization: f.organization, acceptLegal: f.acceptLegal, consents: f.consents },
        firstProblem(checkName(f.name), checkEmail(f.email), checkNewPassword(f.password, policy), checkOrganization(f.organization)), f.captchaToken),
    },
    forgotPassword: (f) => post('/forgot-password', { email: f.email }, checkEmail(f.email), f.captchaToken),
    resetPassword: (f) => post('/reset-password', { token: f.token, password: f.password }, checkNewPassword(f.password, policy)),
    verifyEmail: (f) => post('/verify-email', { token: f.token }, null),
    async invitation(token) {
      const bad = { ok: false as const, error: { code: 'invalid_token', message: 'This invitation is not valid, or it has expired.' } }
      if (typeof token !== 'string' || token.trim() === '') return bad
      try {
        const res = await doFetch(`${base}/invitation?token=${encodeURIComponent(token.trim())}`, { credentials: 'same-origin', headers: { accept: 'application/json' } })
        const body = (await res.json().catch(() => null)) as any
        if (res.ok && body?.invitation) return { ok: true as const, status: 'ok' as const, invitation: body.invitation as Invitation }
        const e = body?.error
        return { ok: false as const, error: e && typeof e.code === 'string' ? { code: e.code, message: String(e.message ?? '') } : UNAVAILABLE }
      } catch {
        return { ok: false as const, error: UNAVAILABLE }
      }
    },
    acceptInvitation: (token, password) => post('/invitation/accept', { token, password }, checkNewPassword(password, policy)),
    signOut: () => post('/sign-out', {}, null),
    organizations: {
      async list(system) {
        const body = await read(`/me/organizations${system ? `?system=${encodeURIComponent(system)}` : ''}`)
        return body && Array.isArray(body.organizations) ? (body.organizations as OrganizationSeat[]) : []
      },
      async members(id) {
        const body = await read(`/me/organizations/members?id=${encodeURIComponent(id)}`)
        return body && Array.isArray(body.members) ? (body.members as OrganizationPerson[]) : null
      },
      async roles(id) {
        const body = await read(`/me/organizations/roles?id=${encodeURIComponent(id)}`)
        return body && Array.isArray(body.roles) ? (body.roles as OrganizationRoleChoice[]) : null
      },
      add: (id, f) => post('/me/organizations/members/add', { organizationId: id, email: f.email, role: f.role, name: f.name ?? '', locale: f.locale ?? '' }, checkEmail(f.email)),
      setRole: (id, userId, role) => post('/me/organizations/members/role', { organizationId: id, userId, role }, null),
      remove: (id, userId) => post('/me/organizations/members/remove', { organizationId: id, userId }, null),
      inviteAgain: (id, userId, f = {}) => post('/me/organizations/members/invite', { organizationId: id, userId, locale: f.locale ?? '' }, null),
      rename: (id, name) => post('/me/organizations/rename', { organizationId: id, name }, checkOrganizationName(name)),
      archive: (id) => post('/me/organizations/archive', { organizationId: id }, null),
      delete: (id) => post('/me/organizations/delete', { organizationId: id }, null),
      async check(q) {
        const organizationId = typeof q.organization === 'string' ? q.organization : (q.organization?.id ?? '')
        const r = await post('/me/organizations/check', {
          organizationId, resource: q.resource, action: q.action,
          ...(q.attributes !== undefined ? { attributes: q.attributes } : {}),
          ...(q.resourceId !== undefined ? { resourceId: q.resourceId } : {}),
          ...(q.ownerId !== undefined ? { ownerId: q.ownerId } : {}),
        }, null)
        if (!r.ok) return { allowed: false, reason: r.error.message, error: r.error }
        return { allowed: r.allowed === true, reason: String(r.reason ?? ''), ...(r.rule ? { rule: r.rule } : {}) }
      },
    },
    account: {
      async get() {
        const body = await read('/me')
        return body && typeof body.account === 'object' ? (body.account as Account) : null
      },
      update: (f) => post('/me', { name: f.name }, checkName(f.name)),
      async legal() {
        const body = await read('/me/legal')
        if (!body) return { ok: false as const, error: { code: 'not_signed_in', message: 'Nobody is signed in.' } }
        return { ok: true as const, status: 'ok' as const, pending: Array.isArray(body.pending) ? body.pending : [] }
      },
      acceptLegal: (f = {}) => post('/me/legal/accept', { kinds: f.kinds ?? [] }, null),
      changePassword: (f) => {
        const bad = checkNewPassword(f.newPassword, policy)
        return post('/me/password', { password: f.password, newPassword: f.newPassword }, bad ? { ...bad, field: 'newPassword' } : null)
      },
      mfa: {
        setup: (f) => post('/me/mfa/setup', { password: f.password }, null),
        verify: (f) => post('/me/mfa/verify', { code: f.code }, checkCode(f.code)),
        disable: (f) => post('/me/mfa/disable', { password: f.password }, null),
        recoveryCodes: (f) => post('/me/mfa/recovery-codes', { password: f.password }, null),
        async factors() {
          const body = await read('/me/mfa/factors')
          return body && typeof body.totp === 'boolean' ? (body as SecondStep) : null
        },
        addPhone: (f) => post('/me/mfa/phone', { phone: f.phone, channel: f.channel, password: f.password }, null),
        verifyPhone: (f) => post('/me/mfa/phone/verify', { code: f.code }, checkCode(f.code)),
        removePhone: (f) => post('/me/mfa/phone/remove', { password: f.password }, null),
      },
      changeEmail: (f) => post('/me/email', { email: f.email, password: f.password }, checkEmail(f.email)),
      async identities() {
        const body = await read('/me/identities')
        return body && Array.isArray(body.identities) ? (body.identities as LinkedIdentity[]) : []
      },
      linkUrl,
      link(provider, o) {
        window.location.assign(linkUrl(provider, o))
      },
      unlink: (provider) => post('/me/identities/unlink', { provider }, null),
      async sessions() {
        const body = await read('/me/sessions')
        return body && Array.isArray(body.sessions) ? (body.sessions as AccountSession[]) : []
      },
      signOutEverywhere: () => post('/me/sessions/end', {}, null),
      upgrade: (f) => post('/me/upgrade', { email: f.email, password: f.password, name: f.name ?? '' }, firstProblem(checkName(f.name), checkEmail(f.email), checkNewPassword(f.password, policy))),
      upgradeUrl,
      upgradeWith(provider, o) {
        window.location.assign(upgradeUrl(provider, o))
      },
      async agents() {
        const body = await read('/me/agents')
        return body && Array.isArray(body.agents) ? (body.agents as ConnectedAgent[]) : []
      },
      disconnectAgent: (id) => post('/me/agents/disconnect', { id }, null),
      async passkeys() {
        const body = await read('/me/passkeys')
        return body && Array.isArray(body.passkeys) ? (body.passkeys as Passkey[]) : []
      },
      addPasskey(f = {}) {
        if (!canUsePasskeys()) return Promise.resolve({ ok: false, error: { code: 'passkey_unavailable', message: 'This browser cannot make passkeys.' } })
        return ceremony('/me/passkeys/add/begin', '/me/passkeys/add/finish', { password: f.password ?? '', ...(f.kind ? { kind: f.kind } : {}) }, makePasskey, { name: f.name ?? '' })
      },
      removePasskey: (id) => post('/me/passkeys/remove', { id }, null),
    },
    async getSession() {
      try {
        const res = await doFetch(`${base}/session`, { credentials: 'same-origin', headers: { accept: 'application/json' } })
        if (!res.ok) return null
        return ((await res.json()) as { session: PublicSession | null }).session
      } catch {
        return null
      }
    },
    look() {
      looked ??= read('/look').then((wire) => (wire && typeof wire === 'object' ? fromWire(wire) : null))
      return looked
    },
    methods,
  }
}

export { canAutofillPasskeys, canUsePasskeys } from './passkey'
export { createSessionStore, type SessionState, type SessionStore, type SessionStoreOptions } from './store'
