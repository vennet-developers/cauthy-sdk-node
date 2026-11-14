// @cauthyhq/node 1.0 takes every configuration cauthy-auth 0.42 took: an
// application's options compile unchanged, and every type 0.42 exported from a
// server entry is still exported from the same entry. `npm run typecheck`
// checks this file; compat.test.ts checks that its lists are complete.
//
// The imports below are the type-only exports of cauthy-auth 0.42, entry by
// entry (values are checked at runtime in compat.test.ts), less the names 1.3
// dropped, which compat.test.ts lists in GONE.
import type * as Entry_root from '../src/index'
import type * as Entry_fastify from '../src/fastify'
import type * as Entry_hono from '../src/hono'
import type * as Entry_next from '../src/next'
import type * as Entry_mcp from '../src/mcp'
import type * as Entry_theme from '../src/theme'

/** Type-only exports of cauthy-auth 0.42. */
export type Types_root = [
  Entry_root.AttributeType,
  Entry_root.AuthField,
  Entry_root.CatalogResource,
  Entry_root.Cauthy,
  Entry_root.CauthyEvent,
  Entry_root.CauthyOptions,
  Entry_root.CauthySystem,
  Entry_root.CauthyTheme,
  Entry_root.CheckOf<any>,
  Entry_root.CheckQuestion,
  Entry_root.CheckResult,
  Entry_root.CheckRule,
  Entry_root.ConditionalPermission,
  Entry_root.ConnectOptions,
  Entry_root.Connected,
  Entry_root.FieldProblem,
  Entry_root.ImportedTheme,
  Entry_root.JsonValue,
  Entry_root.NewMember,
  Entry_root.Organization,
  Entry_root.OrganizationMember,
  Entry_root.OrganizationRef,
  Entry_root.PasswordClass,
  Entry_root.PasswordLocale,
  Entry_root.PasswordPolicy,
  Entry_root.PasswordReason,
  Entry_root.PermissionOf<any>,
  Entry_root.Permitted,
  Entry_root.Policy,
  Entry_root.PolicyDefinition<any, any>,
  Entry_root.PolicyPermission,
  Entry_root.PolicyRole,
  Entry_root.PublicSession,
  Entry_root.PushPolicyOptions,
  Entry_root.PushThemeOptions,
  Entry_root.ReplayStore,
  Entry_root.Resolved,
  Entry_root.RoleOf<any>,
  Entry_root.Session,
  Entry_root.SessionOrganization,
  Entry_root.SessionStatus,
  Entry_root.SessionUser,
  Entry_root.StackmythThemeOptions,
  Entry_root.StackmythTokens,
  Entry_root.SystemKey,
  Entry_root.SystemOptions,
  Entry_root.SystemPolicy,
  Entry_root.ThemeFont,
  Entry_root.ThemeTexts,
  Entry_root.TokenIdentity,
  Entry_root.VerifyTokenOptions,
  Entry_root.VerifyWebhookOptions,
]

/** Type-only exports of cauthy-auth/fastify 0.42. */
export type Types_fastify = [
  Entry_fastify.CauthyFastifyOptions,
]

/** Type-only exports of cauthy-auth/hono 0.42. */
export type Types_hono = [
  Entry_hono.CauthyVariables,
]

/** Type-only exports of cauthy-auth/next 0.42. */
export type Types_next = [
  Entry_next.CauthyMiddlewareOptions,
  Entry_next.CauthyNext,
]

/** Type-only exports of cauthy-auth/mcp 0.42. */
export type Types_mcp = [
  Entry_mcp.AgentIdentity,
  Entry_mcp.ExchangedToken,
  Entry_mcp.McpAuth,
  Entry_mcp.McpAuthInfo,
  Entry_mcp.McpAuthOptions,
]

/** Type-only exports of cauthy-auth/theme 0.42. */
export type Types_theme = [
  Entry_theme.CauthyTheme,
  Entry_theme.CssFormat,
  Entry_theme.CssImportedTheme,
  Entry_theme.CssThemeOptions,
  Entry_theme.ImportedTheme,
  Entry_theme.PushThemeOptions,
  Entry_theme.StackmythThemeOptions,
  Entry_theme.StackmythTokens,
  Entry_theme.ThemeField,
  Entry_theme.ThemeFont,
  Entry_theme.ThemeTexts,
]

import type {
  CauthyFastifyOptions as TheirFastify,
} from 'cauthy-auth/fastify'
import type {
  CauthyOptions as TheirOptions,
  ConnectOptions as TheirConnect,
  SystemOptions as TheirSystem,
  PushPolicyOptions as TheirPushPolicy,
  VerifyTokenOptions as TheirVerify,
} from 'cauthy-auth'
import type { McpAuthOptions as TheirMcp } from 'cauthy-auth/mcp'
import type {
  CssThemeOptions as TheirCss,
  PushThemeOptions as TheirPush,
  StackmythThemeOptions as TheirStackmyth,
} from 'cauthy-auth/theme'
import type { CauthyFastifyOptions as OurFastify } from '../src/fastify'
import type { ConnectOptions as OurConnect } from '../src/connect'
import type { PushPolicyOptions as OurPushPolicy } from '../src/permissions'
import type { McpAuthOptions as OurMcp } from '../src/mcp'
import type { SystemOptions as OurSystem } from '../src/system'
import type { CssThemeOptions as OurCss, PushThemeOptions as OurPush, StackmythThemeOptions as OurStackmyth } from '../src/theme'
import type { CauthyOptions as OurOptions } from '../src/types'
import type { VerifyTokenOptions as OurVerify } from '../src/verify'

// Less the options 1.3 dropped.
export const options = (o: Omit<TheirOptions, 'contract' | 'keys' | 'rootKey' | 'rootKeyPrevious'>): OurOptions => o
export const system = (o: TheirSystem): OurSystem => o
export const mcp = (o: TheirMcp): OurMcp => o
// `auth` is left out: a 0.42 Cauthy is never mixed with our plugin (both come
// from the same import), and ours no longer has `pact`.
export const fastify = (o: Omit<TheirFastify, 'auth'>): Omit<OurFastify, 'auth'> => o
export const verify = (o: TheirVerify): OurVerify => o
export const connect = (o: TheirConnect): OurConnect => o
export const push = (o: TheirPush): OurPush => o
export const css = (o: TheirCss): OurCss => o
export const stackmyth = (o: TheirStackmyth): OurStackmyth => o
export const pushPolicy = (o: TheirPushPolicy): OurPushPolicy => o
