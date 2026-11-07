import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCauthy } from './cauthy'
import { createAuthClient } from '../test-support/client'
import { Browser, FakeCauthy } from './testing'

// The QR the fake Cauthy draws for a second step being turned on.
let setupQR = 'data:image/png;base64,iVBORw0KGgo='

const SECRET = 'a-secret-of-at-least-thirty-two-characters'

// Cauthy's own API, as an application that draws its own screens asks it.
function setup(over: { confirm?: boolean; company?: boolean; inviteOnly?: boolean; mfa?: boolean; mfaByEmail?: boolean; legal?: boolean; noGoogle?: boolean; captcha?: boolean; pages?: { signIn?: string; resetPassword?: string; verifyEmail?: string; acceptInvite?: string }; noPassword?: boolean; noPasskeys?: boolean; icons?: boolean; invitedMfa?: boolean; baseURL?: string; place?: { here: boolean; on_cauthy: boolean }; sso?: boolean; noGuests?: boolean; pushApproved?: boolean; persistent?: boolean; policy?: Record<string, unknown> } = {}) {
  const cauthy = new FakeCauthy()
  const asked: { path: string; headers: Headers; body: any }[] = []
  const account = { mfa: false, phone: null as { number: string; channel: string } | null, linked: ['google'] as string[], passkeys: [{ id: '0b9f6a52-3a4e-4d8e-9f55-1c2d3e4f5a6b', nickname: 'Laptop', kind: 'security_key', created_at: '2026-10-14T12:00:00Z', last_used_at: null as string | null }],
    agents: [{ id: '7f0c2a52-8a51-4d38-b2c4-2b7e0f0d9c11', agent: { name: 'Claude', redirect_host: 'claude.ai' }, resource: { name: 'Books MCP', uri: 'https://mcp.acme.test' },
      scopes: [{ name: 'books:read', description: 'Read your books' }], created_at: '2026-10-16T12:00:00Z', last_used_at: '2026-10-16T13:00:00Z' }] as unknown[],
    members: [{ user_id: 'u1', email: 'ana@acme.com', name: 'Ana', role: 'owner', status: 'active', invited: false, manager: true, you: true, since: '2026-10-20T12:00:00Z' },
      { user_id: 'b2c3d4e5-0000-4000-8000-000000000002', email: 'beto@acme.com', name: '', role: 'reader', status: 'active', invited: true, manager: false, you: false, since: '2026-10-21T12:00:00Z' }] as any[] }
  const sso = { challenge: '', page: '' }
  let n = 0
  const tokens = (sub = 'u1') => {
    const at = `own-at-${++n}`
    const rt = `own-rt-${n}`
    cauthy.access.set(at, sub)
    cauthy.refresh.set(rt, sub)
    return { access_token: at, refresh_token: rt, token_type: 'Bearer', expires_in: 600, ...(over.persistent === undefined ? {} : { persistent: over.persistent }) }
  }
  const reply = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status })
  const refuse = (status: number, code: string, message: string) => reply(status, { errors: [{ code, message }] })
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input))
    if (!url.pathname.startsWith('/v1/auth/')) return cauthy.fetch(input, init)
    const headers = new Headers(init?.headers)
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    // What the screens may offer is read, and kept a minute, around the
    // requests these tests are about: not counted among them.
    if (url.pathname !== '/v1/auth/settings') asked.push({ path: url.pathname + url.search, headers, body })
    if (headers.get('x-tenant-key') !== 'acme') return refuse(404, 'tenant_not_found', 'no such workspace')
    // A person's own account, by their own token.
    if (url.pathname.startsWith('/v1/auth/me') || url.pathname.startsWith('/v1/auth/anonymous/upgrade') || url.pathname.startsWith('/v1/auth/mfa/setup') || url.pathname === '/v1/auth/mfa/verify' || url.pathname.startsWith('/v1/auth/identities') ||
      url.pathname.startsWith('/v1/auth/webauthn/credentials') || url.pathname.startsWith('/v1/auth/webauthn/register') || url.pathname === '/v1/auth/mfa/factors' || url.pathname.startsWith('/v1/auth/mfa/phone')) {
      const sub = cauthy.access.get((headers.get('authorization') ?? '').replace('Bearer ', ''))
      if (sub === undefined) return refuse(401, 'unauthorized', 'no')
      const user = cauthy.users.get(sub)!
      const me = () => ({ id: user.sub, email: user.email, name: user.name, email_verified: true, has_password: true, mfa_enabled: account.mfa })
      const route = `${init?.method ?? 'GET'} ${url.pathname}`
      const stepUp = () => (body?.password === 'right-password' ? null : refuse(401, 'step_up_required', 'your current password is required for this'))
      switch (route) {
        case 'GET /v1/auth/me': return reply(200, { data: me() })
        case 'GET /v1/auth/mfa/factors': return reply(200, { data: { totp: false, phone: account.phone, phone_channels: ['sms', 'whatsapp'] } })
        case 'POST /v1/auth/mfa/phone': return stepUp() ?? (body.phone === '+573001234567' ? reply(200, { data: { sent_to: '+57 ••• ••• 4567', channel: body.channel } }) : refuse(400, 'validation_error', 'the number must be in international form'))
        case 'POST /v1/auth/mfa/phone/verify':
          if (body.code !== '424242') return refuse(422, 'invalid_code', 'that code is not right, or it has expired')
          account.phone = { number: '+57 ••• ••• 4567', channel: 'whatsapp' }
          return reply(200, { data: { verified: true, recovery_codes: ['aaaa-bbbb'] } })
        case 'POST /v1/auth/me/email':
          if (body?.password !== 'right-password') return refuse(401, 'step_up_required', 'your current password is required for this')
          return body.email === 'taken@acme.com' ? refuse(409, 'email_taken', 'that address already has an account') : reply(202)
        case 'GET /v1/auth/identities':
          return reply(200, { data: account.linked.map((p) => ({ provider: p, email: 'ana@gmail.test', linked_at: '2026-10-13T12:00:00Z' })), total_count: account.linked.length })
        case 'GET /v1/auth/anonymous/upgrade/google':
          return reply(200, { data: { redirect_url: 'https://google.test/authorize?state=up-1', state: 'up-1' } })
        case 'GET /v1/auth/anonymous/upgrade/google/callback': {
          if (url.searchParams.get('state') !== 'up-1' || url.searchParams.get('code') !== 'g-code') return refuse(400, 'invalid_state', 'no')
          cauthy.users.set(user.sub, { ...user, email: 'bea@gmail.test', name: 'Bea', anonymous: false })
          return reply(200, { data: tokens(user.sub) })
        }
        case 'GET /v1/auth/identities/github/link':
          return reply(200, { data: { redirect_url: `https://github.test/authorize?state=lk-1`, state: 'lk-1' } })
        case 'GET /v1/auth/identities/github/link/callback':
          if (url.searchParams.get('state') !== 'lk-1' || url.searchParams.get('code') !== 'gh-code') return refuse(400, 'invalid_state', 'no')
          account.linked.push('github')
          return reply(200, { data: { provider: 'github', linked_at: '2026-10-14T12:00:00Z' } })
        case 'DELETE /v1/auth/identities/google':
          if (account.linked.length === 1) return refuse(409, 'last_sign_in_method', 'it is the only way in')
          account.linked = account.linked.filter((p) => p !== 'google')
          return reply(204)
        case 'PATCH /v1/auth/me': user.name = body.name; return reply(200, { data: me() })
        case 'POST /v1/auth/me/password':
          if (body.current_password !== 'right-password') return refuse(401, 'wrong_password', 'the current password is not right')
          cauthy.access.clear(); cauthy.refresh.clear() // every session of the account ends
          return reply(200, { data: tokens(sub) })
        case 'POST /v1/auth/mfa/setup': return stepUp() ?? reply(200, { data: { credential_id: 'c1', secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Acme:ana?secret=JBSWY3DPEHPK3PXP', qr: setupQR } })
        case 'POST /v1/auth/mfa/verify':
          if (body.code !== '123456') return refuse(422, 'invalid_mfa_code', 'that code is not right')
          account.mfa = true
          return reply(200, { data: { recovery_codes: ['aaaa-bbbb', 'cccc-dddd'] } })
        case 'POST /v1/auth/me/mfa/disable': { const no = stepUp(); if (no) return no; account.mfa = false; return reply(204) }
        case 'POST /v1/auth/me/mfa/recovery-codes': return stepUp() ?? reply(200, { data: { recovery_codes: ['eeee-ffff'] } })
        case 'GET /v1/auth/me/sessions': return reply(200, { data: [{ device: 'Mac · Chrome', ip: '198.51.100.9', user_agent: 'x', created_at: '2026-10-13T12:00:00Z', expires_at: '2026-10-20T12:00:00Z' }], total_count: 1 })
        case 'DELETE /v1/auth/me/sessions': cauthy.access.clear(); cauthy.refresh.clear(); return reply(204)
        case 'POST /v1/auth/anonymous/upgrade': {
          if (!user.anonymous) return refuse(409, 'not_anonymous', 'this session is already an account')
          if (body.email === 'ana@acme.com') return refuse(409, 'email_taken', 'an account with this email already exists')
          // Same id: the guest is the account now.
          cauthy.users.set(user.sub, { ...user, email: body.email, name: body.display_name, anonymous: false })
          return reply(200, { data: tokens(user.sub) })
        }
        case 'GET /v1/auth/me/agents': return reply(200, { data: account.agents, total_count: account.agents.length })
        case 'DELETE /v1/auth/me/agents/7f0c2a52-8a51-4d38-b2c4-2b7e0f0d9c11': account.agents = []; return reply(204)
        case 'GET /v1/auth/me/organizations':
          return reply(200, { data: [{ id: 'a1b2c3d4-0000-4000-8000-000000000001', system: 'books', name: 'Casa Pérez', kind: 'household', role: 'owner', can: { read_members: true, manage_members: true, remove_members: true, update: true, archive: true, delete: true } }], total_count: 1 })
        case 'GET /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members': return reply(200, { data: account.members, total_count: account.members.length })
        case 'GET /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/roles':
          return reply(200, { data: [{ role: 'owner', name: 'Owner', description: '', manager: true }, { role: 'reader', name: '', description: 'Reads', manager: false }], total_count: 2 })
        case 'POST /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members': {
          if (body.role === 'boss') return refuse(400, 'unknown_role', 'the system has no such role')
          if (account.members.some((m) => m.email === body.email)) return refuse(409, 'already_member', 'that person already belongs to the organization; change their role instead')
          const made = { user_id: 'c3d4e5f6-0000-4000-8000-000000000003', email: body.email, name: body.name, role: body.role, status: 'active', invited: true, manager: false, you: false, since: '2026-10-22T12:00:00Z' }
          account.members.push(made)
          return reply(201, { data: made })
        }
        case 'PUT /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members/d4e5f6a7-0000-4000-8000-000000000004': return refuse(409, 'last_manager', 'the organization would be left without a manager')
        case 'PUT /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members/b2c3d4e5-0000-4000-8000-000000000002': account.members[1].role = body.role; return reply(204)
        case 'POST /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members/b2c3d4e5-0000-4000-8000-000000000002/invite': return reply(204)
        case 'DELETE /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members/b2c3d4e5-0000-4000-8000-000000000002': account.members = account.members.filter((m) => m.user_id !== 'b2c3d4e5-0000-4000-8000-000000000002'); return reply(204)
        case 'DELETE /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members/f6a7b8c9-0000-4000-8000-000000000006': return refuse(409, 'last_owner', 'the organization would be left without an owner')
        case 'PATCH /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001':
          return reply(200, { data: { id: 'a1b2c3d4-0000-4000-8000-000000000001', system: 'books', name: body.name, kind: 'household', role: 'owner', can: { read_members: true, manage_members: true, remove_members: true, update: true, archive: true, delete: true } } })
        case 'PATCH /v1/auth/me/organizations/e5f6a7b8-0000-4000-8000-000000000005': return refuse(403, 'not_allowed', 'your role in this organization does not allow that')
        case 'POST /v1/auth/me/organizations/e5f6a7b8-0000-4000-8000-000000000005/archive': return refuse(403, 'not_allowed', 'your role in this organization does not allow that')
        case 'POST /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/archive': return reply(204)
        case 'DELETE /v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001': return reply(204)
        case 'DELETE /v1/auth/me/organizations/e5f6a7b8-0000-4000-8000-000000000005': return refuse(404, 'organization_not_found', 'no such organization')
        case 'GET /v1/auth/webauthn/credentials': return reply(200, { data: account.passkeys, total_count: account.passkeys.length })
        case 'POST /v1/auth/webauthn/register/begin':
          return stepUp() ?? reply(200, { data: { session_id: 'enrol-1', options: { publicKey: { challenge: 'Y2hhbGxlbmdl', rp: { id: 'acme.test', name: 'Acme' }, user: { id: 'dTE', name: 'ana@acme.com', displayName: 'Ana' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } } } })
        case 'POST /v1/auth/webauthn/register/finish': {
          if (body.session_id !== 'enrol-1' || body.credential?.id !== 'new-cred') return refuse(400, 'attestation_invalid', 'webauthn: attestation validation failed')
          const made = { id: '7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f', nickname: body.nickname, kind: 'synced', created_at: '2026-10-15T12:00:00Z', last_used_at: null }
          account.passkeys.push(made)
          return reply(201, { data: made })
        }
      }
      if (init?.method === 'DELETE' && url.pathname.startsWith('/v1/auth/webauthn/credentials/')) {
        account.passkeys = account.passkeys.filter((p) => p.id !== url.pathname.split('/').pop())
        return reply(204)
      }
    }
    switch (url.pathname) {
      case '/v1/auth/anonymous': {
        if (over.noGuests) return refuse(403, 'anonymous_disabled', 'this workspace gives no guest sessions')
        cauthy.users.set('g1', { sub: 'g1', email: '', name: '', active: true, restricted: false, anonymous: true })
        return reply(200, { data: tokens('g1') })
      }
      case '/v1/auth/login':
        if (body.email !== 'ana@acme.com' || body.password !== 'right-password') return refuse(401, 'invalid_credentials', 'invalid email or password')
        if (over.mfaByEmail) return reply(200, { data: { mfa_required: true, mfa_token: 'mfa-secret-token', mfa_method: 'email' } })
        return over.mfa ? reply(200, { data: { mfa_required: true, mfa_token: 'mfa-secret-token' } }) : reply(200, { data: tokens() })
      case '/v1/auth/mfa/challenge':
        if (body.mfa_token === 'mfa-secret-token' && body.push === true) {
          return over.pushApproved ? reply(200, { data: tokens() }) : refuse(409, 'push_not_approved', 'the phone has not approved this sign-in')
        }
        if (body.mfa_token !== 'mfa-secret-token' || body.code !== '123456') return refuse(401, 'invalid_mfa_code', 'that code is not right')
        return reply(200, { data: tokens() })
      case '/v1/auth/mfa/push':
        return body.mfa_token === 'mfa-secret-token' ? reply(200, { data: { challenge_id: 'c1', number: 47 } }) : refuse(401, 'token_expired', 'no')
      case '/v1/auth/mfa/push/events':
        if (headers.get('x-mfa-token') !== 'mfa-secret-token') return refuse(401, 'token_expired', 'no')
        return new Response(`event: status\ndata: {"status":"pending"}\n\nevent: status\ndata: {"status":"${over.pushApproved ? 'approved' : 'denied'}"}\n\n`,
          { status: 200, headers: { 'content-type': 'text/event-stream' } })
      case '/v1/auth/register':
        if (body.email === 'taken@acme.com') return refuse(409, 'email_taken', 'that address already has an account')
        // Only Cauthy knows a password was in a breach.
        if (body.password === 'Breached-password-1') return reply(400, { errors: [{ code: 'weak_password', message: 'the password does not meet the workspace\'s rules: this password appears in a known data breach; choose a different one', meta: { reasons: ['breached'] } }] })
        if (over.legal && body.accept_legal !== true) return refuse(400, 'validation_error', 'request validation failed')
        // An application whose system makes an organization per sign-up refuses a sign-up with no company.
        if (over.company && !body.organization?.name) return refuse(400, 'validation_error', 'request validation failed')
        cauthy.users.set('u2', { sub: 'u2', email: body.email, name: body.display_name, active: true, restricted: false })
        return reply(201, { data: { user_id: 'u2', email: body.email, verification_required: over.confirm === true,
          ...(body.organization?.name ? { organization: { id: 'o-new', name: body.organization.name } } : {}) } })
      case '/v1/auth/password/reset':
        return reply(202)
      case '/v1/auth/password/change':
        if (body.token !== 'reset-token') return refuse(422, 'invalid_token', 'reset token is invalid or has expired')
        if (body.new_password === 'passwordpassword') return refuse(400, 'weak_password', 'choose a stronger one')
        return reply(204)
      case '/v1/auth/email/verify':
        // A confirmed address signs the person in from the link; an account
        // with a second step is only confirmed.
        if (body.token === 'verify-token') return reply(200, { verified: true, ...tokens() })
        if (body.token === 'verify-second-step') return reply(200, { verified: true })
        return refuse(422, 'invalid_token', 'no')
      case '/v1/auth/magic-link/request':
        return reply(202)
      case '/v1/auth/magic-link/verify-code':
        return body.email === 'ana@acme.com' && body.code === '123456' ? reply(200, tokens()) : refuse(401, 'invalid_code', 'that code is not right, or it has expired')
      case '/v1/auth/magic-link/verify':
        return body.token === 'link-token' ? reply(200, tokens()) : refuse(401, 'invalid_token', 'no')
      case '/v1/auth/social/providers':
        // Logos as Cauthy serves them: absolute, or its own path when it has no public address.
        return reply(200, { data: over.icons
          ? [{ provider: 'google', label: 'Google', icon_url: 'https://id.test/v1/social/icons/google.svg' }, { provider: 'custom:acme-sso', label: 'Acme SSO', icon_url: '/v1/social/icons/custom.svg' }, { provider: 'github', label: 'GitHub', icon_url: 'javascript:alert(1)' }]
          : [{ provider: 'google', label: 'Google' }], total_count: over.icons ? 3 : 1 })
      // An invitation: read without spending it, accepted with a password.
      case '/v1/auth/invitation':
        return url.searchParams.get('token') === 'invite-token'
          ? reply(200, { data: { email: 'carla@acme.com', workspace: 'Acme', organization: 'Casa Pérez' } })
          : refuse(422, 'invalid_token', 'the invitation is invalid, expired or already used')
      case '/v1/auth/invitation/accept': {
        if (body.token !== 'invite-token') return refuse(422, 'invalid_token', 'the invitation is invalid, expired or already used')
        if (body.password === 'Breached-password-1') return reply(400, { errors: [{ code: 'weak_password', message: 'the password does not meet the workspace\'s rules', meta: { reasons: ['breached'] } }] })
        cauthy.users.set('u3', { sub: 'u3', email: 'carla@acme.com', name: 'Carla', active: true, restricted: false })
        if (over.invitedMfa) return reply(200, { data: { mfa_required: true, mfa_token: 'mfa-secret-token', tenant: { id: 't1', slug: 'acme', name: 'Acme' } } })
        return reply(200, { data: { ...tokens('u3'), session_id: 's1', tenant: { id: 't1', slug: 'acme', name: 'Acme' } } })
      }
      case '/v1/auth/look/client_app':
        return reply(200, { data: { primary: '#0e7c9e', radius: 10 } })
      case '/v1/auth/webauthn/place':
        return over.place ? reply(200, { data: { rp_id: 'acme.test', ...over.place } }) : refuse(404, 'not_found', 'not found')
      case '/v1/auth/webauthn/login/begin':
        return reply(200, { data: { session_id: 'ceremony-1', options: { publicKey: { challenge: 'Y2hhbGxlbmdl', rpId: 'acme.test', allowCredentials: [], userVerification: 'required' } } } })
      case '/v1/auth/webauthn/login/finish':
        return body.session_id === 'ceremony-1' && body.credential?.id === 'cred-1' ? reply(200, { data: tokens() }) : refuse(400, 'assertion_invalid', 'webauthn: assertion validation failed: bad signature')
      case '/v1/auth/settings':
        return reply(200, { data: { allow_signup: true, allow_magic_link: false, ...(over.persistent === undefined ? {} : { persistent_sessions: over.persistent }), ...(over.captcha ? { captcha_enabled: true, captcha_site_key: '0x4AAAAAAAsite' } : {}),
          ...(over.legal ? { legal: { documents: [{ kind: 'terms', version: '2026-10', url: 'https://acme.com/terms' }], consent_purposes: [{ key: 'marketing', label: 'News', required: false }] } } : {}),
          ...(over.company ? { signup: { mode: 'organization', organization: { ask: true, required: true } } } : {}),
          ...(over.inviteOnly ? { signup: { mode: 'invite_only', organization: { ask: false, required: false } } } : {}),
          ...(over.policy ? { password_policy: over.policy } : {}),
          ...(over.noPassword ? { allow_password: false } : {}), ...(over.noPasskeys ? { allow_passkeys: false } : {}) } })
      case '/v1/auth/mfa/methods':
        if (over.mfaByEmail) return body.mfa_token === 'mfa-secret-token' ? reply(200, { data: { totp: false, phone: null, push: null, email: { to: 'a***@acme.com' } } }) : refuse(401, 'token_expired', 'no')
        return body.mfa_token === 'mfa-secret-token' ? reply(200, { data: { totp: false, phone: { number: '+57 ••• ••• 4567', channel: 'whatsapp' } } }) : refuse(401, 'token_expired', 'no')
      case '/v1/auth/mfa/email':
        return body.mfa_token === 'mfa-secret-token' ? reply(200, { data: { sent_to: 'a***@acme.com' } }) : refuse(401, 'token_expired', 'no')
      case '/v1/auth/mfa/send':
        return body.mfa_token === 'mfa-secret-token' ? reply(200, { data: { sent_to: '+57 ••• ••• 4567', channel: 'whatsapp' } }) : refuse(401, 'token_expired', 'no')
      case '/v1/auth/google/one-tap/begin':
        return over.noGoogle ? refuse(404, 'one_tap_unavailable', 'Google One Tap needs the workspace\'s Google sign-in configured') : reply(200, { data: { client_id: 'g-client.apps.googleusercontent.com', nonce: 'nonce-1' } })
      case '/v1/auth/google/one-tap':
        return body.credential === 'google-id-token' ? reply(200, { data: tokens() }) : refuse(401, 'invalid_token', 'the Google credential was already used or is from another prompt; show the prompt again')
      case '/v1/auth/social/google':
        return reply(200, { data: { redirect_url: `https://accounts.google.test/o?state=st-1&redirect_uri=${url.searchParams.get('redirect_uri')}`, state: 'st-1' } })
      case '/v1/auth/social/custom:acme-sso':
        return reply(200, { data: { redirect_url: 'https://sso.acme.test/authorize?state=st-2', state: 'st-2' } })
      case '/v1/auth/social/custom:acme-sso/callback':
        return url.searchParams.get('state') === 'st-2' ? reply(200, { data: tokens() }) : refuse(400, 'invalid_state', 'no')
      case '/v1/auth/social/google/callback':
        if (url.searchParams.get('code') !== 'g-code' || url.searchParams.get('state') !== 'st-1') return refuse(400, 'invalid_state', 'no')
        return reply(200, { data: tokens() })
      // The workspace's company sign-in: acme.com answers to Okta, and holds to it.
      case '/v1/auth/sso/connections':
        return reply(200, { data: over.sso ? [{ slug: 'okta', display_name: 'Acme', protocol: 'oidc', discoverable: true }] : [], total_count: over.sso ? 1 : 0 })
      case '/v1/auth/sso/discover':
        return reply(200, { data: { connection: String(body.email).endsWith('@acme.com') ? { slug: 'okta', display_name: 'Acme', protocol: 'oidc', enforced: true } : null } })
      case '/v1/auth/sso/start': {
        if (body.email && !String(body.email).endsWith('@acme.com')) return refuse(404, 'sso_not_found', 'no SSO connection of this workspace answers for this address')
        sso.challenge = body.code_challenge
        sso.page = body.redirect_uri
        return reply(200, { data: { redirect_url: 'https://okta.acme.test/authorize?state=okta-st', connection: 'okta' } })
      }
      case '/v1/auth/sso/token': {
        const proof = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body.code_verifier))).toString('base64url')
        if (body.code !== 'sso-code' || body.redirect_uri !== sso.page || proof !== sso.challenge || headers.get('x-cauthy-client-id') !== 'client_app') return refuse(400, 'invalid_grant', 'the sign-in code is invalid or expired')
        return reply(200, { data: tokens() })
      }
    }
    return refuse(404, 'not_found', 'not found')
  }
  const auth = createCauthy({ issuer: cauthy.issuer, clientId: 'client_app', secret: SECRET, tenant: 'acme', fetch, pages: over.pages, baseURL: over.baseURL })
  const browser = new Browser()
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    auth.handler(browser.request(`/api/auth${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: browser.origin, ...headers }, body: JSON.stringify(body) }))
  const request = (method: string, path: string) => auth.handler(browser.request(`/api/auth${path}`, { method, headers: { origin: browser.origin } }))
  return { cauthy, auth, browser, post, request, asked }
}

describe('an application that draws its own sign-in', () => {
  it('signs a person in with their address and password, and gives the browser no token', async () => {
    const { auth, browser, post, asked } = setup()
    const res = await post('/sign-in/email', { email: ' ana@acme.com ', password: 'right-password' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('signed_in')
    expect(body.session.user.email).toBe('ana@acme.com')
    expect(JSON.stringify(body)).not.toMatch(/own-at|own-rt|access_token|refresh_token/)
    browser.take(res)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    // Asked of Cauthy as this workspace, for mail that opens Cauthy's pages.
    expect(asked[0].path).toBe('/v1/auth/login')
    expect(asked[0].body).toEqual({ email: 'ana@acme.com', password: 'right-password' })
    expect(asked[0].headers.get('x-tenant-key')).toBe('acme')
    expect(asked[0].headers.get('x-cauthy-links')).toBe('hosted')
  })

  it('says what Cauthy said when it refuses, and checks the form before asking', async () => {
    const { post, asked } = setup()
    const wrong = await post('/sign-in/email', { email: 'ana@acme.com', password: 'nope' })
    expect(wrong.status).toBe(401)
    expect((await wrong.json()).error).toEqual({ code: 'invalid_credentials', message: 'invalid email or password' })

    for (const [form, code, field] of [
      [{ email: '', password: 'x' }, 'required', 'email'],
      [{ email: 'not an address', password: 'x' }, 'invalid_email', 'email'],
      [{ email: 'ana@acme.com', password: '' }, 'required', 'password'],
    ] as const) {
      const res = await post('/sign-in/email', form)
      expect(res.status).toBe(400)
      expect((await res.json()).error).toMatchObject({ code, field })
    }
    expect(asked).toHaveLength(1) // only the first reached Cauthy
  })

  it('takes a form only from its own pages', async () => {
    const { post, asked } = setup()
    const other = await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }, { origin: 'https://evil.test' })
    expect(other.status).toBe(403)
    expect((await other.json()).error.code).toBe('cross_site')
    expect(asked).toHaveLength(0)
  })

  it('knows its own pages behind a proxy that ends TLS', async () => {
    const { auth, asked } = setup()
    // The proxy speaks https to the browser and plain http to the server.
    const inner = new Request('http://app.test/api/auth/sign-in/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.test', 'x-forwarded-proto': 'https' },
      body: JSON.stringify({ email: 'ana@acme.com', password: 'nope' }),
    })
    expect((await auth.handler(inner)).status).toBe(401)
    expect(asked).toHaveLength(1)
  })

  it('says once on the server why its own page was refused', async () => {
    const { auth } = setup()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const inner = () => new Request('http://app.test/api/auth/sign-in/email', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'https://app.test' },
        body: JSON.stringify({ email: 'ana@acme.com', password: 'nope' }),
      })
      expect((await (await auth.handler(inner())).json()).error.code).toBe('cross_site')
      await auth.handler(inner())
      expect(warn).toHaveBeenCalledTimes(1)
      expect(String(warn.mock.calls[0][0])).toContain('CAUTHY_BASE_URL')
    } finally {
      warn.mockRestore()
    }
  })

  it('asks for the second step without ever showing what proves the first', async () => {
    const { auth, browser, post } = setup({ mfa: true })
    const first = await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' })
    const body = await first.text()
    expect(JSON.parse(body)).toEqual({ status: 'mfa_required' })
    expect(body + first.headers.getSetCookie().join()).not.toContain('mfa-secret-token')
    // A code with no first step behind it goes nowhere.
    const cold = await post('/sign-in/mfa', { code: '123456' })
    expect((await cold.json()).error.code).toBe('step_expired')
    browser.take(first)
    const bad = await post('/sign-in/mfa', { code: '000000' })
    expect(bad.status).toBe(401)
    expect((await bad.json()).error).toMatchObject({ code: 'invalid_mfa_code', field: 'code' })
    const done = await post('/sign-in/mfa', { code: ' 123456 ' })
    expect((await done.json()).status).toBe('signed_in')
    browser.take(done)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect([...browser.jar.keys()].some((k) => k.endsWith('_step'))).toBe(false)
  })

  it('says when the second step went by email, and mails the code again', async () => {
    const { browser, post } = setup({ mfaByEmail: true })
    const first = await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' })
    expect(await first.json()).toEqual({ status: 'mfa_required', method: 'email' })
    browser.take(first)
    expect(await (await post('/sign-in/mfa/methods', {})).json()).toEqual({ status: 'ok', totp: false, phone: null, push: null, email: { to: 'a***@acme.com' } })
    expect(await (await post('/sign-in/mfa/email', {})).json()).toEqual({ status: 'sent', sentTo: 'a***@acme.com' })
    expect((await (await setup({ mfaByEmail: true }).post('/sign-in/mfa/email', {})).json()).error.code).toBe('step_expired')
  })

  it('offers the account\'s phone for the second step, and sends it a code', async () => {
    const { browser, post } = setup({ mfa: true })
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    expect(await (await post('/sign-in/mfa/methods', {})).json()).toEqual({ status: 'ok', totp: false, phone: { number: '+57 ••• ••• 4567', channel: 'whatsapp' }, push: null, email: null })
    expect(await (await post('/sign-in/mfa/send', {})).json()).toEqual({ status: 'sent', sentTo: '+57 ••• ••• 4567', channel: 'whatsapp' })
    // Nobody waiting on a second step: nothing to send.
    const cold = setup({ mfa: true })
    expect((await (await cold.post('/sign-in/mfa/send', {})).json()).error.code).toBe('step_expired')
  })

  it('approves the second step on the phone: a push, its answer passed through as it comes, and the sign-in', async () => {
    const { auth, browser, post, request } = setup({ mfa: true, pushApproved: true })
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    expect(await (await post('/sign-in/mfa/push', {})).json()).toEqual({ status: 'sent', number: 47 })
    const events = await request('GET', '/sign-in/mfa/push/events')
    expect(events.headers.get('content-type')).toBe('text/event-stream')
    expect(await events.text()).toContain('"status":"approved"')
    const done = await post('/sign-in/mfa/push/finish', {})
    expect((await done.json()).status).toBe('signed_in')
    browser.take(done)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect([...browser.jar.keys()].some((k) => k.endsWith('_step'))).toBe(false)
  })

  it('a push the phone has not approved signs nobody in', async () => {
    const { browser, post } = setup({ mfa: true })
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const r = await post('/sign-in/mfa/push/finish', {})
    expect(r.status).toBe(409)
    expect((await r.json()).error.code).toBe('push_not_approved')
    const cold = setup({ mfa: true })
    expect((await (await cold.post('/sign-in/mfa/push', {})).json()).error.code).toBe('step_expired')
  })

  it('tells the form what the law asks, and sends the answers with the sign-up', async () => {
    const { post, asked, request } = setup({ legal: true })
    const m = await (await request('GET', '/methods')).json()
    expect(m.legal).toEqual({ documents: [{ kind: 'terms', version: '2026-10', url: 'https://acme.com/terms' }], consentPurposes: [{ key: 'marketing', label: 'News', required: false }] })
    const refused = await post('/sign-up/email', { email: 'bea@acme.com', password: 'right-password' })
    expect(refused.status).toBe(400)
    const made = await post('/sign-up/email', { email: 'bea@acme.com', password: 'right-password', acceptLegal: true, consents: { marketing: true } })
    expect((await made.json()).status).toBe('verification_required')
    expect(asked.find((a) => a.path === '/v1/auth/register' && a.body.accept_legal === true)?.body).toMatchObject({ accept_legal: true, consents: { marketing: true } })
  })

  it('makes an account and signs it in, or says to confirm the address first', async () => {
    const open = setup()
    const made = await open.post('/sign-up/email', { name: 'Bea', email: 'bea@acme.com', password: 'right-password' })
    expect((await made.json()).status).toBe('verification_required') // the fake only signs Ana in
    expect(open.asked[0].body).toEqual({ email: 'bea@acme.com', password: 'right-password', display_name: 'Bea' })

    const confirming = setup({ confirm: true })
    const waiting = await confirming.post('/sign-up/email', { email: 'bea@acme.com', password: 'right-password' })
    expect(await waiting.json()).toEqual({ status: 'verification_required', email: 'bea@acme.com' })
    expect(confirming.asked).toHaveLength(1) // no sign-in attempted for an account that cannot yet

    const taken = await open.post('/sign-up/email', { email: 'taken@acme.com', password: 'right-password' })
    expect(taken.status).toBe(409)
    expect((await taken.json()).error.code).toBe('email_taken')
    const short = await open.post('/sign-up/email', { email: 'bea@acme.com', password: 'short' })
    expect((await short.json()).error).toMatchObject({ code: 'too_short', field: 'password' })
  })

  it('answers the same for any address that asks to recover its password', async () => {
    const { post } = setup()
    expect(await (await post('/forgot-password', { email: 'ana@acme.com' })).json()).toEqual({ status: 'sent' })
    expect(await (await post('/forgot-password', { email: 'nobody@acme.com' })).json()).toEqual({ status: 'sent' })
  })

  it('goes to a provider and back, for the browser that left', async () => {
    const { auth, browser } = setup()
    const start = await auth.handler(browser.request('/api/auth/sign-in/social/google?return_to=/books'))
    expect(start.status).toBe(302)
    expect(start.headers.get('location')).toBe('https://accounts.google.test/o?state=st-1&redirect_uri=https://app.test/api/auth/callback/google')

    // Another browser with the same answer signs nobody in.
    const stranger = new Browser()
    const stolen = await auth.handler(stranger.request('/api/auth/callback/google?code=g-code&state=st-1'))
    expect(stolen.headers.get('location')).toBe('/?auth_error=state_mismatch')

    browser.take(start)
    const refused = await auth.handler(browser.request('/api/auth/callback/google?error=access_denied&state=st-1'))
    expect(refused.headers.get('location')).toBe('/books?auth_error=cancelled')

    const again = await auth.handler(browser.request('/api/auth/sign-in/social/google?return_to=/books'))
    browser.take(again)
    const back = await auth.handler(browser.request('/api/auth/callback/google?code=g-code&state=st-1'))
    expect(back.headers.get('location')).toBe('/books')
    browser.take(back)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
  })

  it('goes to the person\'s company and back, trading the code with the verifier only this browser holds', async () => {
    const { auth, browser, asked, post } = setup({ sso: true })
    expect(await (await auth.handler(browser.request('/api/auth/methods'))).json()).toMatchObject({ sso: true })

    // Which company an address signs in with: its domain's, account or not.
    expect(await (await post('/sign-in/sso/discover', { email: 'ana@acme.com' })).json()).toEqual({ status: 'found', connection: { id: 'okta', name: 'Acme', enforced: true } })
    expect(await (await post('/sign-in/sso/discover', { email: 'ana@other.test' })).json()).toEqual({ status: 'none' })

    const start = await auth.handler(browser.request('/api/auth/sign-in/sso?email=ana%40acme.com&return_to=/books'))
    expect(start.status).toBe(302)
    expect(start.headers.get('location')).toBe('https://okta.acme.test/authorize?state=okta-st')
    const started = asked.find((a) => a.path === '/v1/auth/sso/start')!
    expect(started.body).toMatchObject({ email: 'ana@acme.com', redirect_uri: 'https://app.test/api/auth/sso/callback' })
    expect(started.body.code_challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    // The page is named as this client's, which Cauthy checks against its registered addresses.
    expect(started.headers.get('x-cauthy-link-to')).toBe('https://app.test/api/auth/sso/callback')
    expect(started.headers.get('x-cauthy-client-id')).toBe('client_app')

    // The code, in another browser, signs nobody in: that browser has no verifier.
    const stolen = await auth.handler(new Browser().request('/api/auth/sso/callback?code=sso-code'))
    expect(stolen.headers.get('location')).toBe('/?auth_error=state_mismatch')

    browser.take(start)
    const back = await auth.handler(browser.request('/api/auth/sso/callback?code=sso-code'))
    expect(back.headers.get('location')).toBe('/books')
    browser.take(back)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')

    // A company that refused comes back saying why.
    browser.take(await auth.handler(browser.request('/api/auth/sign-in/sso?connection=okta&return_to=/books')))
    expect((await auth.handler(browser.request('/api/auth/sso/callback?error=provisioning_disabled'))).headers.get('location')).toBe('/books?auth_error=provisioning_disabled')
    // An address no company answers for never leaves.
    expect((await auth.handler(browser.request('/api/auth/sign-in/sso?email=ana%40other.test'))).headers.get('location')).toBe('/?auth_error=sso_not_found')
    // A tab or line break that a browser would drop never turns into `//host`.
    for (const evil of ['/%09/evil.test', '/%0a/evil.test', '/%0d/evil.test', '/%5C/evil.test', '///evil.test']) {
      const res = await auth.handler(browser.request(`/api/auth/sign-in/sso?email=ana%40other.test&return_to=${evil}`))
      expect(res.headers.get('location')).toBe('/?auth_error=sso_not_found')
    }
  })

  it('names its callback page, so a provider answering through Cauthy can return to it', async () => {
    const { auth, browser, asked } = setup()
    await auth.handler(browser.request('/api/auth/sign-in/social/google'))
    expect(asked[0].headers.get('x-cauthy-link-to')).toBe('https://app.test/api/auth/callback/google')
    expect(asked[0].headers.get('x-cauthy-client-id')).toBe('client_app')
  })

  it('signs in with a provider the workspace defined itself', async () => {
    const { auth, browser, asked } = setup()
    // The client writes the id percent-encoded; the provider comes back to it as written.
    const start = await auth.handler(browser.request('/api/auth/sign-in/social/custom%3Aacme-sso'))
    expect(start.headers.get('location')).toBe('https://sso.acme.test/authorize?state=st-2')
    expect(asked[0].path).toMatch(/^\/v1\/auth\/social\/custom:acme-sso\?redirect_uri=/)
    browser.take(start)
    const back = await auth.handler(browser.request('/api/auth/callback/custom:acme-sso?code=c&state=st-2'))
    expect(back.headers.get('location')).toBe('/')
    browser.take(back)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect((await auth.handler(browser.request('/api/auth/sign-in/social/other%3Ax'))).status).toBe(404)
  })

  it('tells its forms how the workspace looks, asking Cauthy once a minute at most', async () => {
    const { auth, browser, asked } = setup()
    const first = await auth.handler(browser.request('/api/auth/look'))
    expect(await first.json()).toEqual({ primary: '#0e7c9e', radius: 10 })
    await auth.handler(browser.request('/api/auth/look'))
    expect(asked.filter((a) => a.path.startsWith('/v1/auth/look/')).map((a) => a.path)).toEqual(['/v1/auth/look/client_app'])
  })

  it('asks to change the address with the password, and changes nothing yet', async () => {
    const { browser, post, asked } = setup()
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const wrong = await post('/me/email', { email: 'ana@new.com', password: 'nope' })
    expect((await wrong.json()).error).toMatchObject({ code: 'step_up_required', field: 'password' })
    const taken = await post('/me/email', { email: 'taken@acme.com', password: 'right-password' })
    expect((await taken.json()).error).toMatchObject({ code: 'email_taken', field: 'email' })
    const bad = await post('/me/email', { email: 'not an address', password: 'right-password' })
    expect((await bad.json()).error).toMatchObject({ code: 'invalid_email', field: 'email' })
    const sent = await post('/me/email', { email: ' ana@new.com ', password: 'right-password' })
    expect(await sent.json()).toEqual({ status: 'sent', email: 'ana@new.com' })
    // The links Cauthy mails open its own pages.
    expect(asked.at(-1)!.headers.get('x-cauthy-links')).toBe('hosted')
  })

  it('lists, links and unlinks the providers of the signed-in account', async () => {
    const { auth, browser, post } = setup()
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const list = await auth.handler(browser.request('/api/auth/me/identities'))
    expect(await list.json()).toEqual({ identities: [{ provider: 'google', email: 'ana@gmail.test', name: '', linkedAt: '2026-10-13T12:00:00Z' }] })

    // The last way in is not taken away.
    const last = await post('/me/identities/unlink', { provider: 'google' })
    expect((await last.json()).error.code).toBe('last_sign_in_method')

    // To the provider and back, through the callback a sign-in uses.
    const start = await auth.handler(browser.request('/api/auth/me/identities/link/github?return_to=/account'))
    expect(start.headers.get('location')).toBe('https://github.test/authorize?state=lk-1')
    browser.take(start)
    const back = await auth.handler(browser.request('/api/auth/callback/github?code=gh-code&state=lk-1'))
    expect(back.headers.get('location')).toBe('/account?linked=github')
    browser.take(back)
    // Still signed in as Ana: linking is not a sign-in.
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')

    const unlinked = await post('/me/identities/unlink', { provider: 'google' })
    expect(await unlinked.json()).toEqual({ status: 'unlinked', provider: 'google' })

    // Nobody signed in: nothing to link to.
    const stranger = await auth.handler(new Browser().request('/api/auth/me/identities/link/github?return_to=/account'))
    expect(stranger.headers.get('location')).toBe('/account?auth_error=unauthenticated')
  })

  it('signs out here and at Cauthy, without leaving the page', async () => {
    const { auth, browser, post, cauthy } = setup()
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const out = await post('/sign-out', {})
    expect(await out.json()).toEqual({ status: 'signed_out' })
    browser.take(out)
    expect(await auth.getSession(browser.request('/'))).toBeNull()
    expect(cauthy.calls).toContain('POST /v1/oauth/revoke')
  })

  it('says what the screen may offer, and what it needs to work', async () => {
    const { auth, browser } = setup()
    const methods = await auth.handler(browser.request('/api/auth/methods'))
    // A Cauthy that cannot say where the passkey is used has it on its own page.
    expect(await methods.json()).toEqual({ providers: [{ id: 'google', name: 'Google' }], passwordSignIn: true, signUp: true, magicLink: false, passkey: true, passkeyHere: false, passkeyOnCauthy: true, sso: false })
    for (const [place, passkey, passkeyHere] of [[{ here: true, on_cauthy: false }, true, true], [{ here: false, on_cauthy: true }, true, false], [{ here: false, on_cauthy: false }, false, false]] as const) {
      const { auth, browser, asked } = setup({ place })
      expect(await (await auth.handler(browser.request('/api/auth/methods'))).json()).toMatchObject({ passkey, passkeyHere, passkeyOnCauthy: place.on_cauthy })
      expect(asked.find((a) => a.path.startsWith('/v1/auth/webauthn/place'))?.path).toBe(`/v1/auth/webauthn/place?origin=${encodeURIComponent(browser.origin)}`)
    }

    const bare = createCauthy({ issuer: 'https://id.test', clientId: 'client_app', secret: SECRET })
    const res = await bare.handler(browser.request('/api/auth/sign-in/email', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }))
    expect(res.status).toBe(500)
    expect((await res.json()).error.code).toBe('not_configured')
  })
})

describe('the browser\'s side', () => {
  it('says the language its person reads, all the way to Cauthy', async () => {
    const { auth, browser, asked } = setup()
    let lang = 'es-CO'
    const client = createAuthClient({
      locale: () => lang,
      fetch: async (input, init) => auth.handler(browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: browser.origin } })),
    })
    await client.forgotPassword({ email: 'ana@acme.com' })
    lang = 'en'
    await client.forgotPassword({ email: 'ana@acme.com' })
    expect(asked.map((a) => a.headers.get('x-cauthy-locale'))).toEqual(['es-CO', 'en'])
  })

  it('checks a form before sending it, and reads the answer', async () => {
    const { auth, browser } = setup()
    let sent = 0
    const client = createAuthClient({
      fetch: async (input, init) => {
        sent++
        const res = await auth.handler(browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: browser.origin } }))
        browser.take(res)
        return res
      },
    })
    expect(await client.signIn.email({ email: 'nope', password: 'x' })).toEqual({ ok: false, error: { code: 'invalid_email', message: 'That does not look like an email address.', field: 'email' } })
    expect(await client.signUp.email({ email: 'bea@acme.com', password: 'short' })).toMatchObject({ ok: false, error: { code: 'too_short', field: 'password' } })
    expect(sent).toBe(0) // neither left the browser

    expect(await client.signIn.email({ email: 'ana@acme.com', password: 'wrong' })).toEqual({ ok: false, error: { code: 'invalid_credentials', message: 'invalid email or password' } })
    const ok = await client.signIn.email({ email: 'ana@acme.com', password: 'right-password' })
    expect(ok).toMatchObject({ ok: true, status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
    expect((await client.getSession())?.user.email).toBe('ana@acme.com')
    expect(await client.methods()).toMatchObject({ providers: [{ id: 'google', name: 'Google' }] })
    expect(client.signIn.socialUrl('google', { returnTo: '/books' })).toBe('/api/auth/sign-in/social/google?return_to=%2Fbooks')
    expect(await client.signOut()).toEqual({ ok: true, status: 'signed_out' })
    expect(await client.getSession()).toBeNull()
  })
})

// Every person reaches Cauthy from the application's server. The application
// passes their address on, with the proof that it is a system of the workspace.
describe('the address of the person signing in', () => {
  function app(over: { system?: boolean; clientIp?: (r: Request) => string | undefined } = {}) {
    const asked: Headers[] = []
    let tokensAsked = 0
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(String(input))
      if (url.pathname === '/v1/oauth/token') {
        tokensAsked++
        return over.system === false
          ? new Response(JSON.stringify({ error: 'unauthorized_client' }), { status: 400 })
          : new Response(JSON.stringify({ access_token: 'the-system-token', token_type: 'Bearer', expires_in: 600 }), { status: 200 })
      }
      asked.push(new Headers(init?.headers))
      return new Response(JSON.stringify({ errors: [{ code: 'invalid_credentials', message: 'no' }] }), { status: 401 })
    }
    const auth = createCauthy({ issuer: 'https://cauthy.test', clientId: 'client_app', clientSecret: 'cs_x', secret: SECRET, tenant: 'acme', fetch, clientIp: over.clientIp })
    const signIn = (headers: Record<string, string> = {}) =>
      auth.handler(new Request('https://app.test/api/auth/sign-in/email', {
        method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://app.test', ...headers },
        body: JSON.stringify({ email: 'ana@acme.com', password: 'some-password' }),
      }))
    return { asked, signIn, tokens: () => tokensAsked }
  }

  it('is passed on with the application\'s own token: the one its proxy wrote, not one the browser claims', async () => {
    const { asked, signIn, tokens } = app()
    await signIn({ 'x-forwarded-for': '10.0.0.1, 198.51.100.9' })
    expect(asked[0].get('x-cauthy-client-ip')).toBe('198.51.100.9')
    expect(asked[0].get('x-cauthy-system-token')).toBe('the-system-token')
    await signIn({ 'x-forwarded-for': '203.0.113.4' })
    expect(asked[1].get('x-cauthy-client-ip')).toBe('203.0.113.4')
    expect(tokens()).toBe(1) // the token is kept, not asked for on every sign-in
  })

  it('skips the platform\'s own hop, and says the application\'s address', async () => {
    const { asked, signIn } = app()
    await signIn({ 'x-forwarded-for': '198.51.100.9, 10.1.2.3, 127.0.0.1' })
    expect(asked[0].get('x-cauthy-client-ip')).toBe('198.51.100.9')
    expect(asked[0].get('x-cauthy-app-origin')).toBe('https://app.test')
    await signIn({ 'x-forwarded-for': '127.0.0.1' })
    expect(asked[1].get('x-cauthy-client-ip')).toBeNull()
  })

  it('is whatever the application says, when it knows better', async () => {
    const { asked, signIn } = app({ clientIp: (r) => r.headers.get('cf-connecting-ip') ?? undefined })
    await signIn({ 'cf-connecting-ip': '198.51.100.20', 'x-forwarded-for': '1.1.1.1' })
    expect(asked[0].get('x-cauthy-client-ip')).toBe('198.51.100.20')
  })

  it('is not passed on when there is none, or when the application is no system', async () => {
    // No address: none is passed on, but the application still proves itself,
    // which tells Cauthy which application signed the person in.
    const none = app()
    await none.signIn()
    expect(none.asked[0].get('x-cauthy-client-ip')).toBeNull()
    expect(none.asked[0].get('x-cauthy-system-token')).not.toBeNull()

    const plain = app({ system: false })
    await plain.signIn({ 'x-forwarded-for': '198.51.100.9' })
    await plain.signIn({ 'x-forwarded-for': '198.51.100.9' })
    expect(plain.asked[1].get('x-cauthy-client-ip')).toBeNull()
    expect(plain.asked[1].get('x-cauthy-system-token')).toBeNull()
    expect(plain.tokens()).toBe(1) // and Cauthy is not asked again at once
  })
})

// What arrives by mail opens a page of the application, when it has one.
describe('what a mailed link opens', () => {
  const pages = { signIn: '/entrar', resetPassword: '/nueva-clave', verifyEmail: '/confirmar' }

  it('is the application\'s own page, named to Cauthy with the client it belongs to', async () => {
    const { post, asked, browser } = setup({ pages, confirm: true })
    await post('/forgot-password', { email: 'ana@acme.com' })
    await post('/sign-up/email', { email: 'new@acme.com', password: 'a-good-password' })
    await post('/sign-in/magic-link', { email: 'ana@acme.com' })
    expect(asked.map((a) => [a.path, a.headers.get('x-cauthy-link-to')])).toEqual([
      ['/v1/auth/password/reset', `${browser.origin}/nueva-clave`],
      ['/v1/auth/register', `${browser.origin}/confirmar`],
      ['/v1/auth/magic-link/request', `${browser.origin}/entrar`],
    ])
    for (const a of asked) {
      expect(a.headers.get('x-cauthy-client-id')).toBe('client_app')
      expect(a.headers.get('x-cauthy-links')).toBeNull()
    }
  })

  it('is Cauthy\'s page when the application has none, and a sign-in link is not offered', async () => {
    const { post, asked, auth, browser } = setup()
    await post('/forgot-password', { email: 'ana@acme.com' })
    expect(asked[0].headers.get('x-cauthy-links')).toBe('hosted')
    expect(asked[0].headers.get('x-cauthy-link-to')).toBeNull()
    expect((await post('/sign-in/magic-link', { email: 'ana@acme.com' })).status).toBe(500)
    const methods = await (await auth.handler(browser.request('/api/auth/methods'))).json()
    expect(methods.magicLink).toBe(false)
  })

  it('goes in the application\'s name, in the language its person reads', async () => {
    const { post, asked } = setup()
    await post('/forgot-password', { email: 'ana@acme.com' }, { 'x-cauthy-locale': 'es-CO', 'accept-language': 'en-US' })
    // Cauthy's page, and still the application's mail: its client is named.
    expect(asked[0].headers.get('x-cauthy-links')).toBe('hosted')
    expect(asked[0].headers.get('x-cauthy-client-id')).toBe('client_app')
    expect(asked[0].headers.get('x-cauthy-locale')).toBe('es-CO')
    expect(asked[0].headers.get('accept-language')).toBe('en-US')
  })

  it('never names a page on another site', async () => {
    const { post, asked, browser } = setup({ pages: { resetPassword: 'https://evil.example.net/x' } })
    await post('/forgot-password', { email: 'ana@acme.com' })
    expect(asked[0].headers.get('x-cauthy-link-to')).toBe(`${browser.origin}/`)
  })

  it('sets the new password with the token the link carried', async () => {
    const { post, asked } = setup({ pages })
    const ok = await post('/reset-password', { token: 'reset-token', password: 'a-good-password' })
    expect(await ok.json()).toEqual({ status: 'changed' })
    expect(asked[0].body).toEqual({ token: 'reset-token', new_password: 'a-good-password' })

    const short = await post('/reset-password', { token: 'reset-token', password: 'short' })
    expect((await short.json()).error).toMatchObject({ code: 'too_short', field: 'password' })
    const weak = await post('/reset-password', { token: 'reset-token', password: 'passwordpassword' })
    expect((await weak.json()).error).toMatchObject({ code: 'weak_password', field: 'password' })
    const stale = await post('/reset-password', { token: 'old', password: 'a-good-password' })
    expect(stale.status).toBe(422)
    expect((await stale.json()).error.code).toBe('invalid_token')
    expect((await post('/reset-password', { password: 'a-good-password' })).status).toBe(422)
    expect(asked).toHaveLength(3) // neither the short one nor the one without a token reached Cauthy
  })

  it('confirms an address with the token the link carried', async () => {
    const { post } = setup({ pages })
    const signedIn = await post('/verify-email', { token: 'verify-token' })
    expect((await signedIn.json()).status).toBe('signed_in')
    expect(signedIn.headers.get('set-cookie')).toContain('cauthy_session')
    expect(await (await post('/verify-email', { token: 'verify-second-step' })).json()).toEqual({ status: 'verified' })
    expect((await (await post('/verify-email', { token: 'nope' })).json()).error.code).toBe('invalid_token')
  })

  it('signs a person in with the token of a sign-in link, and gives the browser no token', async () => {
    const { post, auth, browser } = setup({ pages })
    expect(await (await post('/sign-in/magic-link', { email: 'ana@acme.com' })).json()).toEqual({ status: 'sent' })
    const res = await post('/sign-in/magic-link/verify', { token: 'link-token' })
    const body = await res.json()
    expect(body.status).toBe('signed_in')
    expect(JSON.stringify(body)).not.toMatch(/own-at|own-rt|access_token/)
    browser.take(res)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect((await post('/sign-in/magic-link/verify', { token: 'used' })).status).toBe(401)
  })
})

describe('the code that comes with a sign-in link', () => {
  const pages = { signIn: '/entrar' }

  it('signs the person in, for the address the link was asked for', async () => {
    const { post, asked, auth, browser } = setup({ pages })
    browser.take(await post('/sign-in/magic-link', { email: ' ana@acme.com ' }))
    const wrong = await post('/sign-in/email-code', { code: '000000' })
    expect(wrong.status).toBe(401)
    expect((await wrong.json()).error).toMatchObject({ code: 'invalid_code', field: 'code' })
    const res = await post('/sign-in/email-code', { code: ' 123456 ' })
    const body = await res.json()
    expect(body.status).toBe('signed_in')
    expect(JSON.stringify(body)).not.toMatch(/own-at|access_token/)
    // The address came from this browser's own request, never from the form.
    expect(asked.at(-1)?.body).toEqual({ email: 'ana@acme.com', code: '123456' })
    browser.take(res)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    // The step is over: the code cannot be tried again from here.
    expect((await post('/sign-in/email-code', { code: '123456' })).status).toBe(400)
  })

  it('signs people in and up from one screen, and comes back where they were going', async () => {
    const { post, asked, browser } = setup({ pages })
    browser.take(await post('/sign-in/magic-link', { email: 'new@acme.com', create: true, returnTo: '/e/abc?x=1' }))
    // Cauthy is asked to make the account when the link is used; the page
    // the link opens carries where the person was going.
    expect(asked.at(-1)?.body).toEqual({ email: 'new@acme.com', create_account: true })
    expect(asked.at(-1)?.headers.get('x-cauthy-link-to')).toBe(`${browser.origin}/entrar?return_to=${encodeURIComponent('/e/abc?x=1')}`)
    // A destination that is not a path of this site is not carried.
    await post('/sign-in/magic-link', { email: 'new@acme.com', returnTo: 'https://evil.example.com' })
    expect(asked.at(-1)?.headers.get('x-cauthy-link-to')).toBe(`${browser.origin}/entrar`)
    expect(asked.at(-1)?.body).toEqual({ email: 'new@acme.com' })
  })

  it('answers the destination with the code, typed in the browser that asked', async () => {
    const { post, browser } = setup({ pages })
    browser.take(await post('/sign-in/magic-link', { email: 'ana@acme.com', returnTo: '/e/abc' }))
    const body = await (await post('/sign-in/email-code', { code: '123456' })).json()
    expect(body).toMatchObject({ status: 'signed_in', returnTo: '/e/abc' })
  })

  it('is not taken from a browser that asked for no link', async () => {
    const { post, asked } = setup({ pages })
    const res = await post('/sign-in/email-code', { code: '123456' })
    expect(res.status).toBe(400)
    expect((await res.json()).error.code).toBe('step_expired')
    expect(asked).toHaveLength(0)
  })
})

describe('a passkey, from an application\'s own screen', () => {
  it('is asked for on Cauthy\'s page, which starts it at once', async () => {
    const { auth, browser } = setup()
    const res = await auth.handler(browser.request('/api/auth/login?method=passkey&return_to=/books'))
    expect(res.status).toBe(302)
    const to = res.headers.get('location') ?? ''
    expect(to).toMatch(/\/v1\/oauth\/authorize\?.*code_challenge=.*#passkey$/)
    expect((await auth.handler(browser.request('/api/auth/login'))).headers.get('location')).not.toContain('#')
    expect((await (await auth.handler(browser.request('/api/auth/methods'))).json()).passkey).toBe(true)
    expect(createAuthClient().signIn.passkeyUrl({ returnTo: '/books', locale: 'es' })).toBe('/api/auth/login?method=passkey&return_to=%2Fbooks&locale=es')
  })
})

describe('a workspace that asks for the Turnstile challenge', () => {
  it('names its site key to the forms, and passes the answer on to Cauthy', async () => {
    const { auth, browser, post, asked } = setup({ captcha: true })
    expect((await (await auth.handler(browser.request('/api/auth/methods'))).json()).captchaSiteKey).toBe('0x4AAAAAAAsite')
    await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }, { 'x-cauthy-captcha': 'the-answer' })
    expect(asked.find((a) => a.path === '/v1/auth/login')!.headers.get('x-captcha-token')).toBe('the-answer')
  })

  it('says nothing of it to a workspace that does not', async () => {
    const { auth, browser } = setup()
    expect((await (await auth.handler(browser.request('/api/auth/methods'))).json()).captchaSiteKey).toBeUndefined()
  })
})

describe('Google One Tap, on an application\'s own page', () => {
  it('gives the prompt its client and nonce, and signs in with what Google gave the page', async () => {
    const { post, browser, auth } = setup()
    expect(await (await post('/sign-in/google-one-tap/begin', {})).json()).toEqual({ status: 'started', clientId: 'g-client.apps.googleusercontent.com', nonce: 'nonce-1' })
    const signed = await post('/sign-in/google-one-tap', { credential: 'google-id-token' })
    expect(await signed.json()).toMatchObject({ status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
    browser.take(signed)
    expect((await (await auth.handler(browser.request('/api/auth/session'))).json()).session.user.email).toBe('ana@acme.com')
    expect((await post('/sign-in/google-one-tap', { credential: 'used-before' })).status).toBe(401)
    expect((await post('/sign-in/google-one-tap', {})).status).toBe(400)
  })

  it('says so where the workspace has no Google sign-in', async () => {
    const { post } = setup({ noGoogle: true })
    const res = await post('/sign-in/google-one-tap/begin', {})
    expect(res.status).toBe(404)
    expect((await res.json()).error.code).toBe('one_tap_unavailable')
  })

  describe('in the browser', () => {
    const shown: Record<string, unknown>[] = []
    let answer: ((cb: (r: { credential?: string }) => void, moment: (m: object) => void) => void) | null = null
    beforeEach(() => {
      shown.length = 0
      let config: any
      const id = {
        initialize: (c: any) => { config = c; shown.push(c) },
        prompt: (moment: (m: object) => void) => answer?.(config.callback, moment),
        cancel: () => {},
      }
      vi.stubGlobal('window', { google: { accounts: { id } } })
    })
    afterEach(() => {
      vi.unstubAllGlobals()
      answer = null
    })
    const clientOf = (s: ReturnType<typeof setup>) => createAuthClient({
      fetch: async (input, init) => {
        const res = await s.auth.handler(s.browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: s.browser.origin } }))
        s.browser.take(res)
        return res
      },
    })

    it('shows Google\'s prompt with Cauthy\'s nonce, and signs in with the account picked', async () => {
      answer = (callback) => callback({ credential: 'google-id-token' })
      const client = clientOf(setup())
      expect(await client.signIn.googleOneTap()).toMatchObject({ ok: true, status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
      expect(shown).toEqual([expect.objectContaining({ client_id: 'g-client.apps.googleusercontent.com', nonce: 'nonce-1', context: 'signin', auto_select: false })])
    })

    it('carries the choice to stay signed in, read when the person taps', async () => {
      answer = (callback) => callback({ credential: 'google-id-token' })
      const s = setup()
      let ticked = true
      await clientOf(s).signIn.googleOneTap({ remember: () => ticked })
      ticked = false
      await clientOf(s).signIn.googleOneTap({ remember: () => ticked })
      const taps = s.asked.filter((a) => a.path === '/v1/auth/google/one-tap')
      expect(taps.map((a) => a.headers.get('x-cauthy-remember'))).toEqual(['1', null])
    })

    it('is cancelled when the person closes the prompt, or the page stops it', async () => {
      answer = (_, moment) => moment({ isDismissedMoment: () => true, getDismissedReason: () => 'cancel_called' })
      const client = clientOf(setup())
      expect(await client.signIn.googleOneTap()).toMatchObject({ ok: false, error: { code: 'cancelled' } })
      answer = () => {} // the prompt stays open
      const ctl = new AbortController()
      const waiting = client.signIn.googleOneTap({ signal: ctl.signal })
      await vi.waitFor(() => expect(shown.length).toBe(2))
      ctl.abort()
      expect(await waiting).toMatchObject({ ok: false, error: { code: 'cancelled' } })
    })
  })
})

describe('a person\'s own account, in the application', () => {
  async function signedIn() {
    const world = setup()
    world.browser.take(await world.post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const post = async (path: string, body: unknown) => {
      const res = await world.post(path, body)
      world.browser.take(res)
      return res
    }
    const get = async (path: string) => {
      const res = await world.auth.handler(world.browser.request(`/api/auth${path}`))
      world.browser.take(res)
      return res
    }
    const who = async () => world.auth.getSession(world.browser.request('/'))
    return { ...world, post, get, who }
  }

  it('is nobody\'s without a session', async () => {
    const { auth, browser, post, asked } = setup()
    expect((await auth.handler(browser.request('/api/auth/me'))).status).toBe(401)
    expect((await post('/me', { name: 'x' })).status).toBe(401)
    expect((await post('/me/password', { password: 'a', newPassword: 'a-new-password' })).status).toBe(401)
    expect(asked).toHaveLength(0)
  })

  it('is read with the person\'s own token, and renamed at once', async () => {
    const { get, post, who, asked } = await signedIn()
    expect((await (await get('/me')).json()).account).toEqual({ id: 'u1', email: 'ana@acme.com', name: expect.any(String), emailVerified: true, hasPassword: true, mfaEnabled: false })
    expect(asked.at(-1)?.headers.get('authorization')).toMatch(/^Bearer own-at-/)

    const res = await post('/me', { name: '  Ana María  ' })
    expect(await res.json()).toMatchObject({ status: 'saved', account: { name: 'Ana María' } })
    // The session says the new name without signing in again.
    expect((await who())?.user.name).toBe('Ana María')
    expect((await (await get('/me/sessions')).json()).sessions).toEqual([{ device: 'Mac · Chrome', ip: '198.51.100.9', createdAt: '2026-10-13T12:00:00Z', expiresAt: '2026-10-20T12:00:00Z' }])
  })

  it('lists the AI agents the person connected, and disconnects one', async () => {
    const { get, post } = await signedIn()
    expect((await (await get('/me/agents')).json()).agents).toEqual([{
      id: '7f0c2a52-8a51-4d38-b2c4-2b7e0f0d9c11', name: 'Claude', redirectHost: 'claude.ai',
      resource: { name: 'Books MCP', uri: 'https://mcp.acme.test' }, scopes: [{ name: 'books:read', description: 'Read your books' }],
      connectedAt: '2026-10-16T12:00:00Z', lastUsedAt: '2026-10-16T13:00:00Z',
    }])
    expect((await post('/me/agents/disconnect', { id: 'not-an-id' })).status).toBe(400)
    expect(await (await post('/me/agents/disconnect', { id: '7f0c2a52-8a51-4d38-b2c4-2b7e0f0d9c11' })).json()).toEqual({ status: 'disconnected', id: '7f0c2a52-8a51-4d38-b2c4-2b7e0f0d9c11' })
    expect((await (await get('/me/agents')).json()).agents).toEqual([])
  })

  it('gives a visitor a guest session, and makes it their account with an address — same id', async () => {
    const world = setup()
    const res = await world.post('/sign-in/anonymous', {})
    world.browser.take(res)
    expect(await res.json()).toMatchObject({ status: 'signed_in', session: { user: { id: 'g1', email: '', isAnonymous: true } } })
    const post = async (path: string, body: unknown) => {
      const r = await world.post(path, body)
      world.browser.take(r)
      return r
    }
    // The address is checked here; that it is free, in Cauthy.
    expect((await post('/me/upgrade', { email: 'nope', password: 'a-good-password' })).status).toBe(400)
    const taken = await post('/me/upgrade', { email: 'ana@acme.com', password: 'a-good-password' })
    expect(taken.status).toBe(409)
    expect(await taken.json()).toMatchObject({ error: { code: 'email_taken', field: 'email' } })
    const up = await post('/me/upgrade', { email: 'bea@acme.com', password: 'a-good-password', name: 'Bea' })
    expect(await up.json()).toMatchObject({ status: 'signed_in', session: { user: { id: 'g1', email: 'bea@acme.com', name: 'Bea' } } })
    expect((await (await world.auth.handler(world.browser.request('/api/auth/session'))).json()).session.user.isAnonymous).toBeUndefined()
  })

  it("makes a guest the account of a provider's address, and the session that account's — same id", async () => {
    const world = setup()
    world.browser.take(await world.post('/sign-in/anonymous', {}))
    const start = await world.auth.handler(world.browser.request('/api/auth/me/upgrade/social/google?return_to=/cart'))
    expect(start.headers.get('location')).toBe('https://google.test/authorize?state=up-1')
    world.browser.take(start)
    const back = await world.auth.handler(world.browser.request('/api/auth/callback/google?code=g-code&state=up-1'))
    expect(back.headers.get('location')).toBe('/cart')
    world.browser.take(back)
    const who = await world.auth.getSession(world.browser.request('/'))
    expect(who?.user).toMatchObject({ id: 'g1', email: 'bea@gmail.test' })
    expect(who?.user.isAnonymous).toBeUndefined()
  })

  it('says so when the workspace gives no guest sessions', async () => {
    const world = setup({ noGuests: true })
    const res = await world.post('/sign-in/anonymous', {})
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ error: { code: 'anonymous_disabled' } })
  })

  it("administers the people of the person's organization, with their session", async () => {
    const { get, post, asked } = await signedIn()
    expect((await (await get('/me/organizations')).json()).organizations).toEqual([{
      id: 'a1b2c3d4-0000-4000-8000-000000000001', system: 'books', name: 'Casa Pérez', kind: 'household', role: 'owner',
      can: { readMembers: true, manageMembers: true, removeMembers: true, update: true, archive: true, delete: true },
    }])
    expect((await get('/me/organizations/members?id=nope')).status).toBe(400)
    const members = (await (await get('/me/organizations/members?id=a1b2c3d4-0000-4000-8000-000000000001')).json()).members
    expect(members[1]).toEqual({ userId: 'b2c3d4e5-0000-4000-8000-000000000002', email: 'beto@acme.com', name: '', role: 'reader', status: 'active', invited: true, manager: false, you: false, since: '2026-10-21T12:00:00Z' })
    expect((await (await get('/me/organizations/roles?id=a1b2c3d4-0000-4000-8000-000000000001')).json()).roles[0]).toEqual({ role: 'owner', name: 'Owner', description: '', manager: true })
    expect(asked.at(-1)?.headers.get('authorization')).toMatch(/^Bearer own-at-/)

    // Adding: the address is checked here; the role, in Cauthy.
    expect((await post('/me/organizations/members/add', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', email: 'nope', role: 'reader' })).status).toBe(400)
    const wrong = await post('/me/organizations/members/add', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', email: 'conta@firma.co', role: 'boss' })
    expect(wrong.status).toBe(400)
    expect(await wrong.json()).toMatchObject({ error: { code: 'unknown_role', field: 'role' } })
    const added = await (await post('/me/organizations/members/add', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', email: ' conta@firma.co ', role: 'reader', locale: 'es' })).json()
    expect(added).toMatchObject({ status: 'added', member: { email: 'conta@firma.co', role: 'reader', invited: true } })
    // The invitation lands back in this application, in the person's language.
    expect(asked.at(-1)?.body).toMatchObject({ email: 'conta@firma.co', role: 'reader', locale: 'es', client_id: expect.any(String), only_new: true })
    // Somebody already there keeps their role: one code for it, on the address.
    const again = await post('/me/organizations/members/add', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', email: 'beto@acme.com', role: 'owner' })
    expect(again.status).toBe(409)
    expect(await again.json()).toMatchObject({ error: { code: 'member_exists', field: 'email' } })
    expect(asked.at(-1)?.path).toBe('/v1/auth/me/organizations/a1b2c3d4-0000-4000-8000-000000000001/members')

    // Who is changed is an id; and Cauthy's refusal comes through as it said it.
    expect(await (await post('/me/organizations/members/role', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', userId: 'u1', role: 'reader' })).json()).toMatchObject({ error: { code: 'invalid_member' } })
    const last = await post('/me/organizations/members/role', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', userId: 'd4e5f6a7-0000-4000-8000-000000000004', role: 'reader' })
    expect(last.status).toBe(409)
    expect(await last.json()).toMatchObject({ error: { code: 'last_manager', field: 'role' } })
    expect(await (await post('/me/organizations/members/role', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', userId: 'b2c3d4e5-0000-4000-8000-000000000002', role: 'owner' })).json()).toEqual({ status: 'changed', userId: 'b2c3d4e5-0000-4000-8000-000000000002', role: 'owner' })
    expect(await (await post('/me/organizations/members/invite', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', userId: 'b2c3d4e5-0000-4000-8000-000000000002' })).json()).toEqual({ status: 'sent', userId: 'b2c3d4e5-0000-4000-8000-000000000002' })
    expect(await (await post('/me/organizations/members/remove', { organizationId: 'a1b2c3d4-0000-4000-8000-000000000001', userId: 'b2c3d4e5-0000-4000-8000-000000000002' })).json()).toEqual({ status: 'removed', userId: 'b2c3d4e5-0000-4000-8000-000000000002' })
    expect((await (await get('/me/organizations/members?id=a1b2c3d4-0000-4000-8000-000000000001')).json()).members.map((m: { userId: string }) => m.userId)).not.toContain('b2c3d4e5-0000-4000-8000-000000000002')
  })

  it("renames, archives and deletes the person's organization, as far as their role lets them", async () => {
    const { post, asked } = await signedIn()
    const A = 'a1b2c3d4-0000-4000-8000-000000000001'
    const B = 'e5f6a7b8-0000-4000-8000-000000000005'
    // Which organization, and its new name, are checked here: Cauthy is not asked.
    const before = asked.length
    expect(await (await post('/me/organizations/rename', { organizationId: 'nope', name: 'Acme' })).json()).toMatchObject({ error: { code: 'invalid_organization' } })
    expect(await (await post('/me/organizations/rename', { organizationId: A, name: '  ' })).json()).toMatchObject({ error: { code: 'required', field: 'name' } })
    expect(await (await post('/me/organizations/rename', { organizationId: A, name: 'x'.repeat(121) })).json()).toMatchObject({ error: { code: 'too_long', field: 'name' } })
    expect(asked.length).toBe(before)

    const renamed = await (await post('/me/organizations/rename', { organizationId: A, name: ' Acme Books ' })).json()
    expect(renamed).toEqual({ status: 'renamed', organization: {
      id: A, system: 'books', name: 'Acme Books', kind: 'household', role: 'owner',
      can: { readMembers: true, manageMembers: true, removeMembers: true, update: true, archive: true, delete: true },
    } })
    expect(asked.at(-1)).toMatchObject({ path: `/v1/auth/me/organizations/${A}`, body: { name: 'Acme Books' } })
    expect(asked.at(-1)?.headers.get('authorization')).toMatch(/^Bearer own-at-/)

    // Cauthy's refusals come through as it said them.
    const refused = await post('/me/organizations/rename', { organizationId: B, name: 'Mine now' })
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject({ error: { code: 'not_allowed' } })
    expect((await post('/me/organizations/archive', { organizationId: B })).status).toBe(403)
    const missing = await post('/me/organizations/delete', { organizationId: B })
    expect(missing.status).toBe(404)
    expect(await missing.json()).toMatchObject({ error: { code: 'organization_not_found' } })

    expect(await (await post('/me/organizations/archive', { organizationId: A })).json()).toEqual({ status: 'archived', organizationId: A })
    expect(asked.at(-1)?.path).toBe(`/v1/auth/me/organizations/${A}/archive`)
    expect(await (await post('/me/organizations/delete', { organizationId: A })).json()).toEqual({ status: 'deleted', organizationId: A })
    expect(asked.at(-1)?.path).toBe(`/v1/auth/me/organizations/${A}`)

    // The last owner stays.
    const last = await post('/me/organizations/members/remove', { organizationId: A, userId: 'f6a7b8c9-0000-4000-8000-000000000006' })
    expect(last.status).toBe(409)
    expect(await last.json()).toMatchObject({ error: { code: 'last_owner' } })
  })

  it('changes the password given the current one, and stays signed in with a new session', async () => {
    const { post, who, asked, browser } = await signedIn()
    const wrong = await post('/me/password', { password: 'a-guess', newPassword: 'a-new-password' })
    expect(wrong.status).toBe(401)
    expect((await wrong.json()).error).toMatchObject({ code: 'wrong_password', field: 'password' })
    const short = await post('/me/password', { password: 'right-password', newPassword: 'short' })
    expect((await short.json()).error).toMatchObject({ code: 'too_short', field: 'newPassword' })

    const before = browser.jar.get('cauthy_session.0')
    const res = await post('/me/password', { password: 'right-password', newPassword: 'a-new-password' })
    const body = await res.json()
    expect(body).toEqual({ status: 'changed', signedIn: true })
    expect(JSON.stringify(body)).not.toMatch(/own-at|own-rt/)
    expect(asked.at(-1)?.body).toEqual({ current_password: 'right-password', new_password: 'a-new-password' })
    // Every session ended at Cauthy; this browser holds the new one.
    expect(browser.jar.get('cauthy_session.0')).not.toBe(before)
    expect((await who())?.user.email).toBe('ana@acme.com')
  })

  it('turns the second step on and off, asking for the password', async () => {
    const { post, get } = await signedIn()
    const refused = await post('/me/mfa/setup', { password: 'a-guess' })
    expect((await refused.json()).error).toMatchObject({ code: 'step_up_required', field: 'password' })
    expect(await (await post('/me/mfa/setup', { password: 'right-password' })).json()).toEqual({ status: 'started', secret: 'JBSWY3DPEHPK3PXP', otpauthUri: 'otpauth://totp/Acme:ana?secret=JBSWY3DPEHPK3PXP', qr: 'data:image/png;base64,iVBORw0KGgo=' })
    // Only a PNG data: URI reaches the page, whatever comes back.
    setupQR = 'javascript:alert(1)'
    expect((await (await post('/me/mfa/setup', { password: 'right-password' })).json()).qr).toBe('')
    setupQR = 'data:image/png;base64,iVBORw0KGgo='
    expect((await (await post('/me/mfa/verify', { code: '000000' })).json()).error).toMatchObject({ code: 'invalid_mfa_code', field: 'code' })
    expect(await (await post('/me/mfa/verify', { code: '123456' })).json()).toEqual({ status: 'enabled', recoveryCodes: ['aaaa-bbbb', 'cccc-dddd'] })
    expect((await (await get('/me')).json()).account.mfaEnabled).toBe(true)

    expect((await post('/me/mfa/recovery-codes', {})).status).toBe(401)
    expect(await (await post('/me/mfa/recovery-codes', { password: 'right-password' })).json()).toEqual({ status: 'renewed', recoveryCodes: ['eeee-ffff'] })
    expect((await post('/me/mfa/disable', { password: 'a-guess' })).status).toBe(401)
    expect(await (await post('/me/mfa/disable', { password: 'right-password' })).json()).toEqual({ status: 'disabled' })
    expect((await (await get('/me')).json()).account.mfaEnabled).toBe(false)
  })

  it('adds a phone as the second step, with the password and the code it receives', async () => {
    const { browser, post, auth } = setup()
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    expect(await (await auth.handler(browser.request('/api/auth/me/mfa/factors'))).json()).toEqual({ totp: false, phone: null, phoneChannels: ['sms', 'whatsapp'] })
    expect((await (await post('/me/mfa/phone', { phone: '+573001234567', channel: 'whatsapp', password: 'wrong' })).json()).error).toMatchObject({ code: 'step_up_required', field: 'password' })
    expect(await (await post('/me/mfa/phone', { phone: '+573001234567', channel: 'whatsapp', password: 'right-password' })).json()).toEqual({ status: 'sent', sentTo: '+57 ••• ••• 4567', channel: 'whatsapp' })
    expect((await (await post('/me/mfa/phone/verify', { code: '111111' })).json()).error).toMatchObject({ code: 'invalid_code', field: 'code' })
    expect(await (await post('/me/mfa/phone/verify', { code: '424242' })).json()).toEqual({ status: 'enabled', recoveryCodes: ['aaaa-bbbb'] })
    expect((await (await auth.handler(browser.request('/api/auth/me/mfa/factors'))).json()).phone).toEqual({ number: '+57 ••• ••• 4567', channel: 'whatsapp' })
  })

  it('signs out everywhere, here too', async () => {
    const { post, who } = await signedIn()
    expect(await (await post('/me/sessions/end', {})).json()).toEqual({ status: 'signed_out' })
    expect(await who()).toBeNull()
  })
})

// A passkey on the application's own page: the browser asks the person, and
// the answer goes to Cauthy through the application's server.
describe('passkeys on the application\'s page', () => {
  const credential = (id: string) => ({ id, rawId: id, type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', userHandle: 'dTE' } })

  it('signs in with one, the ceremony\'s id kept on the server', async () => {
    const { auth, browser, post, asked } = setup({ place: { here: true, on_cauthy: false } })
    // No ceremony begun here: nothing to finish.
    expect(await (await post('/sign-in/passkey/finish', { credential: credential('cred-1') })).json()).toMatchObject({ error: { code: 'step_expired' } })

    const begun = await post('/sign-in/passkey/begin', {})
    const b = await begun.json()
    expect(b).toEqual({ status: 'started', options: { challenge: 'Y2hhbGxlbmdl', rpId: 'acme.test', allowCredentials: [], userVerification: 'required' } })
    expect(JSON.stringify(b)).not.toContain('ceremony-1')
    browser.take(begun)

    const bad = await post('/sign-in/passkey/finish', { credential: credential('stolen') })
    expect(await bad.json()).toEqual({ error: { code: 'passkey_failed', message: 'The passkey sign-in could not be completed. Try again, or sign in another way.' } })
    browser.take(bad)
    // A failed answer spends the ceremony.
    expect(await (await post('/sign-in/passkey/finish', { credential: credential('cred-1') })).json()).toMatchObject({ error: { code: 'step_expired' } })

    browser.take(await post('/sign-in/passkey/begin', {}))
    const done = await post('/sign-in/passkey/finish', { credential: credential('cred-1') })
    expect(await done.json()).toMatchObject({ status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
    browser.take(done)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('ana@acme.com')
    expect(asked.filter((a) => a.path === '/v1/auth/webauthn/login/finish').at(-1)?.body).toEqual({ session_id: 'ceremony-1', credential: credential('cred-1') })
    // Only the application's own page may ask.
    expect((await post('/sign-in/passkey/begin', {}, { origin: 'https://evil.test' })).status).toBe(403)
  })

  it('names the person\'s passkeys when the address comes with the ask', async () => {
    const { post, asked } = setup({ place: { here: true, on_cauthy: false } })
    await post('/sign-in/passkey/begin', { email: ' ana@acme.com ' })
    await post('/sign-in/passkey/begin', { email: 'not an address' })
    expect(asked.filter((a) => a.path === '/v1/auth/webauthn/login/begin').map((a) => a.body)).toEqual([{ email: 'ana@acme.com' }, {}])
  })

  it('adds and removes the account\'s passkeys', async () => {
    const { browser, post, auth, asked } = setup({ place: { here: true, on_cauthy: false } })
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const list = await auth.handler(browser.request('/api/auth/me/passkeys'))
    expect(await list.json()).toEqual({ passkeys: [{ id: '0b9f6a52-3a4e-4d8e-9f55-1c2d3e4f5a6b', name: 'Laptop', kind: 'security_key', createdAt: '2026-10-14T12:00:00Z', lastUsedAt: null }] })

    expect(await (await post('/me/passkeys/add/begin', { password: 'wrong' })).json()).toMatchObject({ error: { code: 'step_up_required', field: 'password' } })
    // The kind asked for goes to Cauthy; anything else is not passed on.
    await post('/me/passkeys/add/begin', { password: 'right-password', kind: 'security_key' })
    await post('/me/passkeys/add/begin', { password: 'right-password', kind: 'anything' })
    expect(asked.filter((a) => a.path === '/v1/auth/webauthn/register/begin').slice(-2).map((a) => a.body)).toEqual([{ password: 'right-password', kind: 'security_key' }, { password: 'right-password' }])
    const begun = await post('/me/passkeys/add/begin', { password: 'right-password' })
    expect(await begun.json()).toMatchObject({ status: 'started', options: { rp: { id: 'acme.test' }, user: { id: 'dTE' } } })
    browser.take(begun)
    const added = await post('/me/passkeys/add/finish', { credential: { id: 'new-cred', response: { clientDataJSON: 'e30', attestationObject: 'AA' } }, name: '  Phone  ' })
    expect(await added.json()).toEqual({ status: 'added', passkey: { id: '7c1e2d3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f', name: 'Phone', kind: 'synced', createdAt: '2026-10-15T12:00:00Z', lastUsedAt: null } })

    expect(await (await post('/me/passkeys/remove', { id: '../../me' })).json()).toMatchObject({ error: { code: 'invalid_passkey' } })
    expect(await (await post('/me/passkeys/remove', { id: '0b9f6a52-3a4e-4d8e-9f55-1c2d3e4f5a6b' })).json()).toEqual({ status: 'removed', id: '0b9f6a52-3a4e-4d8e-9f55-1c2d3e4f5a6b' })
    expect((await (await auth.handler(browser.request('/api/auth/me/passkeys'))).json()).passkeys.map((p: { name: string }) => p.name)).toEqual(['Phone'])
    // Nobody signed in: none to see.
    expect((await auth.handler(new Browser().request('/api/auth/me/passkeys'))).status).toBe(401)
  })

  describe('in the browser', () => {
    const asks: string[] = []
    const assigned: string[] = []
    beforeEach(() => {
      asks.length = 0
      assigned.length = 0
      const answer = (kind: string) => async ({ publicKey, mediation, signal }: { publicKey: any; mediation?: string; signal?: AbortSignal }) => {
        asks.push(`${kind}${mediation ? ` ${mediation}` : ''} ${new TextDecoder().decode(publicKey.challenge)}`)
        if (globalThis.__refuse) throw new DOMException('The person closed it.', 'NotAllowedError')
        // Autofill waits for the person; until they pick, only an abort ends it.
        if (globalThis.__waiting && signal) {
          await new Promise((_, reject) => signal.addEventListener('abort', () => reject(new DOMException('Aborted.', 'AbortError'))))
        }
        const buf = (s: string) => new TextEncoder().encode(s).buffer
        return {
          id: kind === 'get' ? 'cred-1' : 'new-cred', rawId: buf('raw'), type: 'public-key',
          response: kind === 'get'
            ? { authenticatorData: buf('a'), clientDataJSON: buf('{}'), signature: buf('s'), userHandle: buf('u1') }
            : { attestationObject: buf('o'), clientDataJSON: buf('{}'), getTransports: () => ['internal'] },
          getClientExtensionResults: () => ({}),
        }
      }
      vi.stubGlobal('window', { PublicKeyCredential: function PublicKeyCredential() {}, location: { assign: (to: string) => assigned.push(to) } })
      vi.stubGlobal('navigator', { credentials: { get: answer('get'), create: answer('create') } })
    })
    afterEach(() => {
      vi.unstubAllGlobals()
      globalThis.__refuse = false
      globalThis.__waiting = false
    })
    const withAutofill = () => {
      const pkc = Object.assign(function PublicKeyCredential() {}, { isConditionalMediationAvailable: async () => true })
      vi.stubGlobal('window', { PublicKeyCredential: pkc, location: { assign: (to: string) => assigned.push(to) } })
    }
    const clientOf = (s: ReturnType<typeof setup>) => createAuthClient({
      fetch: async (input, init) => {
        const res = await s.auth.handler(s.browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: s.browser.origin } }))
        s.browser.take(res)
        return res
      },
    })

    it('asks the person on this page, and signs them in', async () => {
      const client = clientOf(setup({ place: { here: true, on_cauthy: false } }))
      expect(await client.signIn.passkey()).toMatchObject({ ok: true, status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
      expect(asks).toEqual(['get challenge'])
      expect(assigned).toEqual([])
      globalThis.__refuse = true
      expect(await client.signIn.passkey()).toMatchObject({ ok: false, error: { code: 'cancelled' } })
    })

    it('goes to Cauthy\'s page for that step alone when this page cannot', async () => {
      const client = clientOf(setup({ place: { here: false, on_cauthy: true } }))
      expect(await client.signIn.passkey({ returnTo: '/books' })).toEqual({ ok: true, status: 'redirected' })
      expect(assigned).toEqual(['/api/auth/login?method=passkey&return_to=%2Fbooks'])
      expect(asks).toEqual([])
      const nowhere = clientOf(setup({ place: { here: false, on_cauthy: false } }))
      expect(await nowhere.signIn.passkey()).toMatchObject({ ok: false, error: { code: 'passkey_unavailable' } })
    })

    it('offers the passkeys in the email field\'s autofill, and signs in with the one picked', async () => {
      withAutofill()
      const client = clientOf(setup({ place: { here: true, on_cauthy: false } }))
      expect(await client.signIn.passkeyAutofill()).toMatchObject({ ok: true, status: 'signed_in', session: { user: { email: 'ana@acme.com' } } })
      expect(asks).toEqual(['get conditional challenge'])
    })

    it('offers nothing where the browser or the page cannot', async () => {
      const unable = clientOf(setup({ place: { here: true, on_cauthy: false } }))
      expect(await unable.signIn.passkeyAutofill()).toMatchObject({ ok: false, error: { code: 'cancelled' } })
      withAutofill()
      const elsewhere = clientOf(setup({ place: { here: false, on_cauthy: true } }))
      expect(await elsewhere.signIn.passkeyAutofill()).toMatchObject({ ok: false, error: { code: 'cancelled' } })
      expect(asks).toEqual([])
    })

    it('stops offering when the page says so', async () => {
      withAutofill()
      globalThis.__waiting = true
      const client = clientOf(setup({ place: { here: true, on_cauthy: false } }))
      const ctl = new AbortController()
      const offered = client.signIn.passkeyAutofill({ signal: ctl.signal })
      await vi.waitFor(() => expect(asks).toEqual(['get conditional challenge']))
      ctl.abort()
      expect(await offered).toMatchObject({ ok: false, error: { code: 'cancelled' } })
    })

    it('adds one on this device', async () => {
      const s = setup({ place: { here: true, on_cauthy: false } })
      const client = clientOf(s)
      await client.signIn.email({ email: 'ana@acme.com', password: 'right-password' })
      expect(await client.account.addPasskey({ password: 'right-password', name: 'Phone' })).toMatchObject({ ok: true, status: 'added', passkey: { name: 'Phone' } })
      expect(asks).toEqual(['create challenge'])
      expect((await client.account.passkeys()).map((p) => p.name)).toEqual(['Laptop', 'Phone'])
    })
  })
})

declare global {
  // eslint-disable-next-line no-var
  var __refuse: boolean | undefined
  // eslint-disable-next-line no-var
  var __waiting: boolean | undefined
}

// An application whose system makes an organization per sign-up: the form is
// told to ask the company's name, and the sign-up carries it to Cauthy.
describe('a sign-up that makes the company', () => {
  it('offers no sign-up when the system takes people by invitation only', async () => {
    const { request } = setup({ inviteOnly: true })
    expect(await (await request('GET', '/methods')).json()).toMatchObject({ signUp: false })
  })

  it('is told to ask the company, and sends it', async () => {
    const { post, asked, request } = setup({ company: true })
    expect((await (await request('GET', '/methods')).json()).organization).toEqual({ ask: true, required: true })
    const made = await post('/sign-up/email', { name: 'Bea', email: 'bea@acme.com', password: 'right-password', organization: ' Ferretería El Tornillo ' })
    expect((await made.json()).status).toBe('verification_required') // the fake only signs Ana in
    const registered = asked.find((a) => a.path === '/v1/auth/register')
    expect(registered?.body.organization).toEqual({ name: 'Ferretería El Tornillo' })
  })

  it('refuses a company name that is too long before asking Cauthy', async () => {
    const { post, asked } = setup({ company: true })
    const long = await post('/sign-up/email', { email: 'bea@acme.com', password: 'right-password', organization: 'x'.repeat(121) })
    expect((await long.json()).error).toMatchObject({ field: 'organization', code: 'too_long' })
    expect(asked.some((a) => a.path === '/v1/auth/register')).toBe(false)
  })

  it('says nothing of a company for an application whose system makes none', async () => {
    const { request } = setup()
    expect((await (await request('GET', '/methods')).json()).organization).toBeUndefined()
  })
})

// The workspace's password policy: published to the screens, and held to
// before a new password is sent.
describe('a workspace\'s password policy', () => {
  const strict = { min_length: 14, max_length: 64, requires: ['uppercase', 'digit'], min_classes: 0, reject_breached: true }

  it('is published by methods()', async () => {
    const { auth, browser } = setup({ policy: strict })
    const methods = await (await auth.handler(browser.request('/api/auth/methods'))).json()
    expect(methods.password).toEqual({ min: 14, max: 64, requires: ['uppercase', 'digit'], min_classes: 0, reject_breached: true })
    // A Cauthy that does not say publishes nothing: the defaults hold.
    const quiet = setup()
    expect((await (await quiet.auth.handler(quiet.browser.request('/api/auth/methods'))).json()).password).toBeUndefined()
  })

  it('is checked before a new password is sent, rule by rule', async () => {
    const { post, asked } = setup({ policy: strict })
    const res = await post('/sign-up/email', { email: 'bea@acme.com', password: 'twelve chars' })
    expect(res.status).toBe(400)
    const { error } = await res.json()
    expect(error).toMatchObject({ code: 'too_short', field: 'password' })
    expect(error.message).toContain('at least 14 characters')
    expect(error.message).toContain('uppercase letter')
    expect(asked.some((a) => a.path === '/v1/auth/register')).toBe(false)
    expect((await post('/sign-up/email', { email: 'bea@acme.com', password: 'Fourteen chars 1' })).status).not.toBe(400)
  })

  it('lets through what a looser workspace takes', async () => {
    const { post, asked } = setup({ policy: { min_length: 8, max_length: 128, requires: [], min_classes: 0, reject_breached: false } })
    await post('/sign-up/email', { email: 'bea@acme.com', password: 'ten chars!' })
    expect(asked.find((a) => a.path === '/v1/auth/register')?.body.password).toBe('ten chars!')
  })

  it('passes on which rules Cauthy refused', async () => {
    const { post } = setup()
    const res = await post('/sign-up/email', { email: 'bea@acme.com', password: 'Breached-password-1' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatchObject({ code: 'weak_password', field: 'password', reasons: ['breached'] })
  })

  it('is what the browser client checks against once methods() said it', async () => {
    const { auth, browser } = setup({ policy: strict })
    let sent = 0
    const client = createAuthClient({
      fetch: async (input, init) => {
        sent++
        return auth.handler(browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: browser.origin } }))
      },
    })
    // Before: the defaults, which this 13-character password meets: it is
    // sent, and refused on the server, which knows the workspace's rule.
    const before = await client.signUp.email({ email: 'bea@acme.com', password: 'thirteen char' })
    expect(sent).toBeGreaterThan(0)
    expect(before).toMatchObject({ ok: false, error: { code: 'too_short' } })
    await client.methods()
    sent = 0
    const after = await client.signUp.email({ email: 'bea@acme.com', password: 'thirteen char' })
    expect(after).toMatchObject({ ok: false, error: { code: 'too_short', field: 'password' } })
    expect(sent).toBe(0) // refused in the browser
  })
})

// An invitation accepted on the application's own page (<AcceptInvite />).
describe('an invitation', () => {
  it('is read before the password is chosen, without spending it', async () => {
    const { request, asked } = setup()
    const res = await request('GET', '/invitation?token=invite-token')
    expect(await res.json()).toEqual({ status: 'ok', invitation: { email: 'carla@acme.com', workspace: 'Acme', organization: 'Casa Pérez' } })
    expect(asked[0].path).toBe('/v1/auth/invitation?token=invite-token')
    expect(asked[0].headers.get('x-tenant-key')).toBe('acme')
    const spent = await request('GET', '/invitation?token=used')
    expect(spent.status).toBe(422)
    expect((await spent.json()).error.code).toBe('invalid_token')
    // No token: Cauthy is not asked.
    expect((await request('GET', '/invitation')).status).toBe(422)
    expect(asked).toHaveLength(2)
  })

  it('is accepted with a password, and the person is signed in here with no token in the browser', async () => {
    const { post, auth, browser, asked } = setup()
    const res = await post('/invitation/accept', { token: 'invite-token', password: 'a-good-password' })
    const body = await res.json()
    expect(body.status).toBe('signed_in')
    expect(JSON.stringify(body)).not.toMatch(/own-at|own-rt|access_token|refresh_token/)
    expect(res.headers.get('set-cookie')).toContain('cauthy_session')
    browser.take(res)
    expect((await auth.getSession(browser.request('/')))?.user.email).toBe('carla@acme.com')
    expect(asked.at(-1)).toMatchObject({ path: '/v1/auth/invitation/accept', body: { token: 'invite-token', password: 'a-good-password' } })
  })

  it('asks for the second step next when the account owes one, as a sign-in does', async () => {
    const { post, browser } = setup({ invitedMfa: true })
    const res = await post('/invitation/accept', { token: 'invite-token', password: 'a-good-password' })
    expect(await res.json()).toEqual({ status: 'mfa_required' })
    expect(res.headers.get('set-cookie')).toContain('cauthy_session_step')
    expect(res.headers.get('set-cookie')).not.toMatch(/cauthy_session=/)
    browser.take(res)
    const done = await post('/sign-in/mfa', { code: '123456' })
    expect((await done.json()).status).toBe('signed_in')
  })

  it("checks the password against the workspace's policy, and says what Cauthy refused", async () => {
    const { post, asked } = setup()
    expect((await (await post('/invitation/accept', { token: 'invite-token', password: 'short' })).json()).error).toMatchObject({ code: 'too_short', field: 'password' })
    const weak = await (await post('/invitation/accept', { token: 'invite-token', password: 'Breached-password-1' })).json()
    expect(weak.error).toMatchObject({ code: 'weak_password', field: 'password', reasons: ['breached'] })
    const stale = await post('/invitation/accept', { token: 'used', password: 'a-good-password' })
    expect(stale.status).toBe(422)
    expect((await stale.json()).error.code).toBe('invalid_token')
    expect((await post('/invitation/accept', { password: 'a-good-password' })).status).toBe(422)
    expect(asked.filter((a) => a.path === '/v1/auth/invitation/accept')).toHaveLength(2) // neither the short one nor the one without a token
  })

  it('is read and accepted by the browser through the application', async () => {
    const { auth, browser } = setup()
    const client = createAuthClient({
      fetch: async (input, init) => auth.handler(browser.request(String(input), { ...init, headers: { ...(init?.headers as Record<string, string>), origin: browser.origin } })),
    })
    expect(await client.invitation('invite-token')).toEqual({ ok: true, status: 'ok', invitation: { email: 'carla@acme.com', workspace: 'Acme', organization: 'Casa Pérez' } })
    expect(await client.invitation('used')).toMatchObject({ ok: false, error: { code: 'invalid_token' } })
    expect(await client.invitation('')).toMatchObject({ ok: false, error: { code: 'invalid_token' } })
    expect(await client.acceptInvitation('invite-token', 'short')).toMatchObject({ ok: false, error: { code: 'too_short', field: 'password' } })
    expect(await client.acceptInvitation('invite-token', 'a-good-password')).toMatchObject({ ok: true, status: 'signed_in', session: { user: { email: 'carla@acme.com' } } })
  })

  it("is mailed with the application's page, from every call that invites", async () => {
    const world = setup({ pages: { acceptInvite: '/aceptar-invitacion' } })
    world.browser.take(await world.post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    const org = 'a1b2c3d4-0000-4000-8000-000000000001'
    await world.post('/me/organizations/members/add', { organizationId: org, email: 'conta@firma.co', role: 'reader' })
    await world.post('/me/organizations/members/invite', { organizationId: org, userId: 'b2c3d4e5-0000-4000-8000-000000000002' })
    const sent = world.asked.filter((a) => a.path.includes('/members'))
    expect(sent.map((a) => [a.path, a.headers.get('x-cauthy-link-to'), a.headers.get('x-cauthy-client-id')])).toEqual([
      [`/v1/auth/me/organizations/${org}/members`, `${world.browser.origin}/aceptar-invitacion`, 'client_app'],
      [`/v1/auth/me/organizations/${org}/members/b2c3d4e5-0000-4000-8000-000000000002/invite`, `${world.browser.origin}/aceptar-invitacion`, 'client_app'],
    ])
    // Still the person's own session that asks.
    for (const a of sent) expect(a.headers.get('authorization')).toMatch(/^Bearer own-at-/)

    // Without the page, Cauthy's own.
    const bare = setup()
    bare.browser.take(await bare.post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))
    await bare.post('/me/organizations/members/invite', { organizationId: org, userId: 'b2c3d4e5-0000-4000-8000-000000000002' })
    expect(bare.asked.at(-1)?.headers.get('x-cauthy-links')).toBe('hosted')
  })

  it("is mailed with the application's page by the application acting on its own, when it knows its origin", async () => {
    const cauthy = new FakeCauthy()
    const seen: { path: string; headers: Headers }[] = []
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = new URL(String(input))
      if (url.pathname === '/v1/oauth/token') return new Response(JSON.stringify({ access_token: 'sys', expires_in: 300 }), { status: 200 })
      seen.push({ path: url.pathname, headers: new Headers(init?.headers) })
      if (url.pathname === '/v1/users') return new Response(JSON.stringify({ data: { id: 'u9', email: 'dora@acme.com' } }), { status: 201 })
      return new Response(JSON.stringify({ data: { user_id: 'u9', email: 'dora@acme.com', name: '', status: 'active', role: 'reader', invited: true } }), { status: 201 })
    }
    const options = { issuer: cauthy.issuer, clientId: 'client_app', clientSecret: 'shh', secret: SECRET, fetch, pages: { acceptInvite: '/aceptar-invitacion' } }
    const auth = createCauthy({ ...options, baseURL: 'https://app.example.com' })
    await auth.system.members.add('o1', { email: 'dora@acme.com', role: 'reader' })
    await auth.system.invite({ email: 'dora@acme.com' })
    for (const a of seen) {
      expect(a.headers.get('x-cauthy-link-to')).toBe('https://app.example.com/aceptar-invitacion')
      expect(a.headers.get('x-cauthy-client-id')).toBe('client_app')
    }
    // No origin known: nothing named, and Cauthy's page it is.
    seen.length = 0
    await createCauthy(options).system.members.add('o1', { email: 'dora@acme.com', role: 'reader' })
    expect(seen[0].headers.get('x-cauthy-link-to')).toBeNull()
  })
})

describe('what the workspace turned off, and the logos', () => {
  it('says the password and the passkeys are off, everywhere they would be offered', async () => {
    const { request } = setup({ noPassword: true, noPasskeys: true, place: { here: true, on_cauthy: true } })
    expect(await (await request('GET', '/methods')).json()).toMatchObject({ passwordSignIn: false, passkey: false, passkeyHere: false, passkeyOnCauthy: false })
    // A Cauthy from before the settings: both on.
    expect(await (await setup({ place: { here: true, on_cauthy: false } }).request('GET', '/methods')).json()).toMatchObject({ passwordSignIn: true, passkey: true, passkeyHere: true })
  })

  it("gives each provider its logo, as an address of Cauthy's, and nothing that is not one", async () => {
    const { request } = setup({ icons: true })
    expect((await (await request('GET', '/methods')).json()).providers).toEqual([
      { id: 'google', name: 'Google', iconUrl: 'https://id.test/v1/social/icons/google.svg' },
      { id: 'custom:acme-sso', name: 'Acme SSO', iconUrl: 'https://id.test/v1/social/icons/custom.svg' },
      { id: 'github', name: 'GitHub' },
    ])
  })

  it('reads the flags in the browser, on from a server that does not say', async () => {
    const answer = (body: unknown) => createAuthClient({ fetch: (async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch })
    expect(await answer({ providers: [], signUp: true, passwordSignIn: false }).methods()).toMatchObject({ passwordSignIn: false })
    expect(await answer({ providers: [], signUp: true }).methods()).toMatchObject({ passwordSignIn: true })
    const down = createAuthClient({ fetch: (async () => { throw new TypeError('fetch failed') }) as unknown as typeof fetch })
    expect(await down.methods()).toMatchObject({ passwordSignIn: true, passkey: false })
  })
})

describe('keeping the person signed in', () => {
  const cookieLine = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('cauthy_session.0='))!

  it('tells Cauthy the person asked to stay signed in, only when they did', async () => {
    const { post, asked } = setup()
    await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true })
    expect(asked[0].path).toBe('/v1/auth/login')
    expect(asked[0].headers.get('x-cauthy-remember')).toBe('1')
    await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' })
    expect(asked[1].headers.get('x-cauthy-remember')).toBeNull()
    await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: 'on' })
    expect(asked[2].headers.get('x-cauthy-remember')).toBe('1')
    await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: false })
    expect(asked[3].headers.get('x-cauthy-remember')).toBeNull()
  })

  it('keeps the cookie 30 days when Cauthy says the session is persistent, and for the browser session otherwise', async () => {
    const long = await setup({ persistent: true }).post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true })
    expect(cookieLine(long)).toContain('Max-Age=2592000')
    for (const over of [{ persistent: false }, {}]) {
      const res = await setup(over).post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' })
      expect(cookieLine(res)).not.toMatch(/Max-Age|Expires/)
    }
  })

  it('sends the choice on the second step too', async () => {
    const { post, browser, asked } = setup({ mfa: true })
    browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true }))
    await post('/sign-in/mfa/methods', {})
    await post('/sign-in/mfa', { code: '123456' })
    const mfa = asked.filter((a) => a.path.startsWith('/v1/auth/mfa/'))
    expect(mfa.length).toBe(2)
    for (const a of mfa) expect(a.headers.get('x-cauthy-remember')).toBe('1')
  })

  it('a renewal keeps the kind of session, or the old one when Cauthy does not say', async () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(new Date('2026-10-12T00:00:00Z'))
      const { cauthy, auth, post, browser } = setup({ persistent: true })
      browser.take(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true }))
      vi.setSystemTime(new Date('2026-10-12T00:09:45Z'))
      cauthy.persistent = true
      let h = new Headers()
      await auth.getSession(browser.request('/'), h)
      expect(h.getSetCookie()[0]).toContain('Max-Age=2592000')
      browser.take(h.getSetCookie())
      // An older Cauthy says nothing: the session stays what it was.
      cauthy.persistent = undefined
      vi.setSystemTime(new Date('2026-10-12T00:19:30Z'))
      h = new Headers()
      await auth.getSession(browser.request('/'), h)
      expect(h.getSetCookie()[0]).toContain('Max-Age=2592000')
      browser.take(h.getSetCookie())
      // Cauthy now says it is short.
      cauthy.persistent = false
      vi.setSystemTime(new Date('2026-10-12T00:29:15Z'))
      h = new Headers()
      await auth.getSession(browser.request('/'), h)
      expect(h.getSetCookie()[0]).not.toMatch(/Max-Age|Expires/)
    } finally {
      vi.useRealTimers()
    }
  })

  it('a long session stays long through a name change and a password change', async () => {
    const over: { persistent?: boolean; noGuests?: boolean } = { persistent: true }
    const { post, browser } = setup(over)
    const keep = (res: Response) => {
      browser.take(res)
      return cookieLine(res)
    }
    expect(keep(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true }))).toContain('Max-Age=2592000')
    // An older Cauthy says nothing about it: the session stays what it was.
    delete over.persistent
    expect(keep(await post('/me', { name: 'Ana María' }))).toContain('Max-Age=2592000')
    expect(keep(await post('/me/password', { password: 'right-password', newPassword: 'a-new-password' }))).toContain('Max-Age=2592000')
    // A short one stays short.
    over.persistent = false
    expect(keep(await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password' }))).not.toMatch(/Max-Age|Expires/)
    delete over.persistent
    expect(keep(await post('/me', { name: 'Ana' }))).not.toMatch(/Max-Age|Expires/)
  })

  it('every chunk of a split cookie carries the same Max-Age', async () => {
    const { post, cauthy } = setup({ persistent: true })
    cauthy.users.get('u1')!.name = 'Ana '.repeat(2000)
    const res = await post('/sign-in/email', { email: 'ana@acme.com', password: 'right-password', remember: true })
    const parts = res.headers.getSetCookie().filter((c) => c.startsWith('cauthy_session.'))
    expect(parts.length).toBeGreaterThan(1)
    for (const c of parts) expect(c).toContain('Max-Age=2592000')
  })

  it('a guest session never asks for a long one, and the passkey and the emailed code carry the choice', async () => {
    const { post, browser, asked } = setup({ place: { here: true, on_cauthy: false }, pages: { signIn: '/entrar' } })
    await post('/sign-in/anonymous', { remember: true })
    expect(asked.find((a) => a.path === '/v1/auth/anonymous')!.headers.get('x-cauthy-remember')).toBeNull()
    browser.take(await post('/sign-in/passkey/begin', { remember: true }))
    await post('/sign-in/passkey/finish', { credential: { id: 'cred-1', rawId: 'cred-1', type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', userHandle: 'dTE' } } })
    for (const path of ['/v1/auth/webauthn/login/begin', '/v1/auth/webauthn/login/finish']) expect(asked.find((a) => a.path === path)!.headers.get('x-cauthy-remember')).toBe('1')
    browser.take(await post('/sign-in/magic-link', { email: 'ana@acme.com', remember: true }))
    await post('/sign-in/email-code', { code: '123456' })
    expect(asked.find((a) => a.path === '/v1/auth/magic-link/verify-code')!.headers.get('x-cauthy-remember')).toBe('1')
  })

  it('a mailed link carries the choice, and opening it asks for the long session', async () => {
    const { post, asked, browser } = setup({ pages: { signIn: '/entrar' } })
    await post('/sign-in/magic-link', { email: 'ana@acme.com', returnTo: '/e/abc', remember: true })
    await post('/sign-in/magic-link', { email: 'ana@acme.com', remember: true })
    await post('/sign-in/magic-link', { email: 'ana@acme.com' })
    const pages = asked.filter((a) => a.path === '/v1/auth/magic-link/request').map((a) => a.headers.get('x-cauthy-link-to'))
    expect(pages).toEqual([`${browser.origin}/entrar?return_to=%2Fe%2Fabc&remember=1`, `${browser.origin}/entrar?remember=1`, `${browser.origin}/entrar`])
    await post('/sign-in/magic-link/verify', { token: 'link-token', remember: true })
    expect(asked.find((a) => a.path === '/v1/auth/magic-link/verify')!.headers.get('x-cauthy-remember')).toBe('1')
    expect(asked.filter((a) => a.path === '/v1/auth/magic-link/request').every((a) => a.headers.get('x-cauthy-remember') === null)).toBe(true)
  })

  it('carries the choice to a provider, and to the company\'s sign-in', async () => {
    const { auth, browser, asked } = setup({ sso: true })
    await auth.handler(browser.request('/api/auth/sign-in/social/google?remember=1'))
    expect(asked[0].path).toContain('/v1/auth/social/google')
    expect(asked[0].headers.get('x-cauthy-remember')).toBe('1')
    await auth.handler(browser.request('/api/auth/sign-in/social/google'))
    expect(asked[1].headers.get('x-cauthy-remember')).toBeNull()
    await auth.handler(browser.request('/api/auth/sign-in/sso?email=ana@acme.com&remember=1'))
    expect(asked[2].path).toBe('/v1/auth/sso/start')
    expect(asked[2].headers.get('x-cauthy-remember')).toBe('1')
  })

  it('the provider\'s answer comes back with the choice made at the start', async () => {
    const { auth, browser, asked } = setup()
    browser.take(await auth.handler(browser.request('/api/auth/sign-in/social/google?remember=1')))
    await auth.handler(browser.request('/api/auth/callback/google?code=g-code&state=st-1'))
    expect(asked.at(-1)!.path).toContain('/v1/auth/social/google/callback')
    expect(asked.at(-1)!.headers.get('x-cauthy-remember')).toBe('1')
  })

  it('says whether the application\'s sign-in may offer to stay signed in', async () => {
    expect(await (await setup({ persistent: true }).request('GET', '/methods')).json()).toMatchObject({ persistentSessions: true })
    expect(await (await setup({ persistent: false }).request('GET', '/methods')).json()).toMatchObject({ persistentSessions: false })
    expect((await (await setup().request('GET', '/methods')).json()).persistentSessions).toBeUndefined()
  })
})
