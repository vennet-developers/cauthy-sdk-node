// What a sign-in or sign-up form is checked for before anything is sent, in
// the browser and again on the server: the same rules in both places, so the
// form says what the server would.

export type AuthField = 'email' | 'password' | 'newPassword' | 'name' | 'code' | 'organization'

/** A value of a form that cannot be sent as it is. */
export interface FieldProblem {
  field: AuthField
  /**
   * Stable, for translating: `required`, `invalid_email`, `too_short`,
   * `too_long`, and for a new password the rule of the workspace it fails:
   * `needs_lowercase`, `needs_uppercase`, `needs_digit`, `needs_symbol`,
   * `needs_classes`.
   */
  code: 'required' | 'invalid_email' | PasswordReason
  message: string
}

/** The shortest password Cauthy takes by default: a workspace's policy may ask otherwise (`methods().password`). */
export const MIN_PASSWORD = 12
/** The longest: the API bounds what Argon2id is given, whatever the workspace asks. */
const MAX_PASSWORD = 128
/** The shortest any workspace may allow. */
const FLOOR_PASSWORD = 8
const MAX_NAME = 120

/** A kind of character a workspace's password policy can ask for. */
export type PasswordClass = 'lowercase' | 'uppercase' | 'digit' | 'symbol'

/** Why a new password is refused: the API's `weak_password` `meta.reasons`. */
export type PasswordReason = 'too_short' | 'too_long' | 'needs_lowercase' | 'needs_uppercase' | 'needs_digit' | 'needs_symbol' | 'needs_classes' | 'breached'

/**
 * What a new password must be in the workspace, as `methods().password` says
 * it. Length is counted in bytes of UTF-8, as Cauthy counts it. A symbol is
 * any character that is neither a letter nor a digit, a space included.
 */
export interface PasswordPolicy {
  min: number
  max: number
  /** The kinds the password must each carry at least once. */
  requires: PasswordClass[]
  /** At least this many of the four kinds; 0 asks none. */
  min_classes: number
  /** Cauthy refuses a password found in a published breach (checked by Cauthy alone). */
  reject_breached: boolean
}

const CLASSES: PasswordClass[] = ['lowercase', 'uppercase', 'digit', 'symbol']

/** The policy of a workspace that set none: what every one asked before they could choose. */
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = Object.freeze({ min: MIN_PASSWORD, max: MAX_PASSWORD, requires: [], min_classes: 0, reject_breached: false }) as PasswordPolicy

const int = (v: unknown, fallback: number) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : fallback)

/**
 * A password policy as Cauthy sent it — `{ min_length, max_length, … }` from
 * the sign-in settings, or `{ min, max, … }` from `methods()` — made safe to
 * use: the defaults where nothing is said, and never outside 8–128.
 */
export function passwordPolicyOf(raw: unknown): PasswordPolicy {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const min = Math.min(Math.max(int(r.min ?? r.min_length, MIN_PASSWORD) || MIN_PASSWORD, FLOOR_PASSWORD), MAX_PASSWORD)
  const max = Math.max(Math.min(int(r.max ?? r.max_length, MAX_PASSWORD) || MAX_PASSWORD, MAX_PASSWORD), min)
  const asked = Array.isArray(r.requires) ? r.requires : []
  return {
    min, max,
    requires: CLASSES.filter((c) => asked.includes(c)),
    min_classes: Math.min(Math.max(int(r.min_classes ?? r.minClasses, 0), 0), CLASSES.length),
    reject_breached: (r.reject_breached ?? r.rejectBreached) === true,
  }
}

/** Bytes of UTF-8: what Cauthy counts a password's length in. */
function utf8Length(v: string): number {
  let n = 0
  for (const ch of v) {
    const c = ch.codePointAt(0)!
    n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4
  }
  return n
}

/** Which of the four kinds a password carries, as Cauthy tells them apart. */
function classesOf(v: string): Set<PasswordClass> {
  const has = new Set<PasswordClass>()
  for (const ch of v) {
    if (/\p{Ll}/u.test(ch)) has.add('lowercase')
    else if (/\p{Lu}/u.test(ch)) has.add('uppercase')
    else if (/\p{Nd}/u.test(ch)) has.add('digit')
    else if (!/\p{L}/u.test(ch)) has.add('symbol') // a letter without case is neither
  }
  return has
}

/**
 * Every rule of the policy a new password fails, as the API names them;
 * empty when it meets them all. Whether it was in a breach only Cauthy knows.
 */
export function passwordProblems(value: string, policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY): PasswordReason[] {
  const p = passwordPolicyOf(policy)
  const out: PasswordReason[] = []
  const length = utf8Length(value)
  if (length < p.min) out.push('too_short')
  if (length > p.max) out.push('too_long')
  const has = classesOf(value)
  for (const c of p.requires) if (!has.has(c)) out.push(`needs_${c}` as PasswordReason)
  if (p.min_classes > 0 && CLASSES.filter((c) => has.has(c)).length < p.min_classes) out.push('needs_classes')
  return out
}

/** The languages the rule is said in. */
export type PasswordLocale = 'en' | 'es'

const RULES: Record<PasswordLocale, {
  between: string; requires: string; classes: string; breached: string; and: string; kinds: Record<PasswordClass, string>
  reasons: Record<PasswordReason, string>
}> = {
  en: {
    between: 'Between {min} and {max} characters.', requires: 'Include {kinds}.', and: 'and',
    classes: 'Use at least {n} of these: lowercase letters, uppercase letters, digits, symbols.',
    breached: 'Passwords found in known data breaches are not accepted.',
    kinds: { lowercase: 'a lowercase letter', uppercase: 'an uppercase letter', digit: 'a digit', symbol: 'a symbol' },
    reasons: {
      too_short: 'Use at least {min} characters.', too_long: 'Use at most {max} characters.',
      needs_lowercase: 'Include a lowercase letter.', needs_uppercase: 'Include an uppercase letter.', needs_digit: 'Include a digit.', needs_symbol: 'Include a symbol.',
      needs_classes: 'Use at least {n} of these: lowercase letters, uppercase letters, digits, symbols.',
      breached: 'This password appears in a known data breach. Choose a different one.',
    },
  },
  es: {
    between: 'Entre {min} y {max} caracteres.', requires: 'Incluye {kinds}.', and: 'y',
    classes: 'Usa al menos {n} de estos tipos: minúsculas, mayúsculas, números, símbolos.',
    breached: 'No se aceptan contraseñas que aparecen en filtraciones de datos conocidas.',
    kinds: { lowercase: 'una minúscula', uppercase: 'una mayúscula', digit: 'un número', symbol: 'un símbolo' },
    reasons: {
      too_short: 'Usa al menos {min} caracteres.', too_long: 'Usa como máximo {max} caracteres.',
      needs_lowercase: 'Incluye una minúscula.', needs_uppercase: 'Incluye una mayúscula.', needs_digit: 'Incluye un número.', needs_symbol: 'Incluye un símbolo.',
      needs_classes: 'Usa al menos {n} de estos tipos: minúsculas, mayúsculas, números, símbolos.',
      breached: 'Esta contraseña aparece en una filtración de datos conocida. Elige otra.',
    },
  },
}

const fill = (s: string, p: PasswordPolicy) => s.replace('{min}', String(p.min)).replace('{max}', String(p.max)).replace('{n}', String(p.min_classes))

/** What a new password must be, said for the person choosing it: "Between 12 and 128 characters. Include a digit." */
export function describePasswordPolicy(policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY, locale: PasswordLocale = 'en'): string {
  const p = passwordPolicyOf(policy)
  const t = RULES[locale] ?? RULES.en
  const parts = [fill(t.between, p)]
  if (p.requires.length > 0) {
    const kinds = p.requires.map((c) => t.kinds[c])
    const listed = kinds.length === 1 ? kinds[0] : `${kinds.slice(0, -1).join(', ')} ${t.and} ${kinds[kinds.length - 1]}`
    parts.push(t.requires.replace('{kinds}', listed))
  }
  if (p.min_classes > 0) parts.push(fill(t.classes, p))
  if (p.reject_breached) parts.push(t.breached)
  return parts.join(' ')
}

/** Why a new password was refused, rule by rule, for the person who typed it. */
export function explainPasswordProblems(reasons: readonly string[], policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY, locale: PasswordLocale = 'en'): string {
  const p = passwordPolicyOf(policy)
  const t = RULES[locale] ?? RULES.en
  const said = reasons.filter((r): r is PasswordReason => r in t.reasons).map((r) => fill(t.reasons[r], p))
  return said.length > 0 ? said.join(' ') : describePasswordPolicy(p, locale)
}

// One @, something on each side, a dot in the domain, no spaces: what catches
// a typo. Whether the address exists is Cauthy's to find out.
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function checkEmail(value: unknown): FieldProblem | null {
  const v = typeof value === 'string' ? value.trim() : ''
  if (v === '') return { field: 'email', code: 'required', message: 'Enter your email address.' }
  if (v.length > 254 || !EMAIL.test(v)) return { field: 'email', code: 'invalid_email', message: 'That does not look like an email address.' }
  return null
}

/** A password being typed to sign in: only that there is one. */
export function checkPassword(value: unknown): FieldProblem | null {
  if (typeof value !== 'string' || value === '') return { field: 'password', code: 'required', message: 'Enter your password.' }
  if (value.length > MAX_PASSWORD) return { field: 'password', code: 'too_long', message: 'That password is too long.' }
  return null
}

/**
 * A password being chosen for a new account, or a new one for an account.
 * Held to the workspace's policy when it is given (`methods().password`),
 * otherwise to the defaults: 12 to 128 characters.
 */
export function checkNewPassword(value: unknown, policy?: PasswordPolicy | null): FieldProblem | null {
  if (typeof value !== 'string' || value === '') return { field: 'password', code: 'required', message: 'Enter your password.' }
  const p = policy ? passwordPolicyOf(policy) : DEFAULT_PASSWORD_POLICY
  const reasons = passwordProblems(value, p)
  if (reasons.length === 0) return null
  return { field: 'password', code: reasons[0], message: explainPasswordProblems(reasons, p) }
}

export function checkName(value: unknown): FieldProblem | null {
  if (value === undefined || value === null || value === '') return null
  if (typeof value !== 'string' || value.trim().length > MAX_NAME) return { field: 'name', code: 'too_long', message: `Use at most ${MAX_NAME} characters.` }
  return null
}

/** The company's name a sign-up carries when the application's system makes an organization per sign-up. */
export const MAX_ORGANIZATION = 120

export function checkOrganization(value: unknown, required = false): FieldProblem | null {
  const v = typeof value === 'string' ? value.trim() : ''
  if (v === '') return required ? { field: 'organization', code: 'required', message: "Enter your company's name." } : null
  if (v.length > MAX_ORGANIZATION) return { field: 'organization', code: 'too_long', message: `Use at most ${MAX_ORGANIZATION} characters.` }
  return null
}

/** An organization's new name, when a member renames it: the same rule as at sign-up, always required. */
export function checkOrganizationName(value: unknown): FieldProblem | null {
  const v = typeof value === 'string' ? value.trim() : ''
  if (v === '') return { field: 'name', code: 'required', message: "Enter the organization's name." }
  if (v.length > MAX_ORGANIZATION) return { field: 'name', code: 'too_long', message: `Use at most ${MAX_ORGANIZATION} characters.` }
  return null
}

export function checkCode(value: unknown): FieldProblem | null {
  const v = typeof value === 'string' ? value.trim() : ''
  if (v === '') return { field: 'code', code: 'required', message: 'Enter the code.' }
  if (v.length > 40) return { field: 'code', code: 'too_long', message: 'That is not a code.' }
  return null
}

/** The first problem of a form, or null when it can be sent. */
export function firstProblem(...checks: (FieldProblem | null)[]): FieldProblem | null {
  return checks.find((c) => c !== null) ?? null
}
