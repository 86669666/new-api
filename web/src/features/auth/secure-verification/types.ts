/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { z } from 'zod'

import {
  isOrganizationAuthReplacement,
  type AuthTokenRotation,
} from '@/lib/auth-session'
import { AuthOperationError } from '@/lib/secure-verification'
import type { AuthBundle, LoginSession } from '@/stores/auth-store'

export type VerificationErrorProjector = (error: unknown) => AuthOperationError

export type OrganizationVerificationScope =
  | 'organization.change_role'
  | 'organization.remove'
export type OrganizationVerificationOperation =
  | {
      scope: 'organization.change_role'
      context: {
        schema_version: 1
        command: {
          organization_id: string
          revision: string
          target_user_id: string
          role: 'admin' | 'member'
        }
        snapshot: Record<string, never>
      }
    }
  | {
      scope: 'organization.remove'
      context: {
        schema_version: 1
        command: {
          organization_id: string
          revision: string
          target_user_id: string
        }
        snapshot: { target_role: 'admin' }
      }
    }

export function isOrganizationVerificationScope(
  scope: string
): scope is OrganizationVerificationScope {
  return scope === 'organization.change_role' || scope === 'organization.remove'
}

// Shared only by the two organization producers and their hook rejection exits.
// Never retain the original error, even when it is already an AuthOperationError.
const organizationFailureMessages = {
  AUTH_CANCELLED: 'Verification failed. Please try again.',
  AUTH_SESSION_REVOKED: 'The login session is no longer active.',
  AUTH_UNAUTHORIZED: 'Session expired!',
  AUTH_SESSION_REQUIRED: 'A dashboard session is required.',
  AUTH_ORIGIN_FORBIDDEN: 'request origin is not allowed',
  ORG_REQUEST_INVALID: 'Invalid organization request.',
  ORG_NOT_FOUND: 'Organization is unavailable.',
  ORG_FORBIDDEN: 'Organization operation is forbidden.',
  ORG_STATE_CHANGED:
    'Organization state changed. Refresh the organization state before retrying.',
  ORG_DISABLED: 'Organization is disabled.',
  ORG_REQUEST_RESOLVED: 'Organization request is already resolved.',
  SECURITY_CONTEXT_INVALID: 'The action details are invalid.',
  SECURITY_PROOF_REQUIRED: 'Additional verification required',
  SECURITY_PROOF_INVALID:
    'Security verification is no longer valid. Please verify again.',
  SECURITY_PROOF_EXPIRED:
    'Security verification has expired. Please verify again.',
  SECURITY_PROOF_CONSUMED:
    'This verification has already been used. Please verify again.',
  SECURITY_PROOF_SCOPE_MISMATCH: 'Verification does not match this action.',
  SECURITY_PROOF_CONTEXT_MISMATCH:
    "Verification does not match this action's details. Please verify again.",
  SECURITY_PROOF_METHOD_MISMATCH:
    'This verification method is not allowed for this action.',
  SECURITY_METHOD_UNAVAILABLE:
    'This verification method is currently unavailable.',
  SECURITY_VERIFICATION_LOCKED:
    'Two-factor authentication is temporarily locked.',
  SECURITY_VERIFICATION_FAILED: 'Verification failed. Please try again.',
  SECURITY_VERIFICATION_RATE_LIMITED:
    'Security verification rate limit exceeded.',
  PASSKEY_RP_ID_UNAVAILABLE:
    'This Passkey domain is not available on this website. Use its original website or another verification method.',
} as const

export type OrganizationVerificationFailure = AuthOperationError & {
  status?: number
  retryAfter?: number
  cancelled: boolean
  __CANCEL__?: true
}

export function projectOrganizationVerificationError(
  error: unknown
): OrganizationVerificationFailure {
  let code: keyof typeof organizationFailureMessages | undefined
  let status: number | undefined
  let retryAfter: number | undefined
  let cancelled = false
  const seen = new Set<unknown>()
  let current = error
  try {
    for (let depth = 0; depth < 8; depth++) {
      if (!current || typeof current !== 'object' || seen.has(current)) break
      seen.add(current)
      const source = current as Record<string, unknown>
      const response = source.response as
        | { status?: unknown; data?: { code?: unknown }; headers?: unknown }
        | undefined
      const candidate = response?.data?.code ?? source.code
      if (
        typeof candidate === 'string' &&
        Object.hasOwn(organizationFailureMessages, candidate)
      ) {
        code ??= candidate as keyof typeof organizationFailureMessages
      }
      cancelled ||=
        source.__CANCEL__ === true ||
        source.name === 'AbortError' ||
        source.code === 'AUTH_CANCELLED' ||
        source.code === 'ERR_CANCELED' ||
        source.name === 'NotAllowedError' ||
        (source instanceof AuthOperationError &&
          (source.message ===
            'Passkey verification was cancelled or timed out' ||
            source.message === 'Passkey verification was cancelled'))
      const responseStatus = response?.status ?? source.status
      if (
        typeof responseStatus === 'number' &&
        Number.isInteger(responseStatus) &&
        responseStatus >= 100 &&
        responseStatus <= 599
      ) {
        status ??= responseStatus
      }
      const headers = response?.headers as Record<string, unknown> | undefined
      const retryKey =
        headers &&
        Object.keys(headers).find((key) => key.toLowerCase() === 'retry-after')
      const retry =
        (retryKey ? headers?.[retryKey] : undefined) ?? source.retryAfter
      const seconds =
        typeof retry === 'string' && /^[0-9]{1,5}$/.test(retry)
          ? Number(retry)
          : retry
      if (
        typeof seconds === 'number' &&
        Number.isSafeInteger(seconds) &&
        seconds >= 0 &&
        seconds <= 86400
      ) {
        retryAfter ??= seconds
      }
      current = source.cause
    }
  } catch {
    // Even an accessor on a foreign error must not escape this narrow boundary.
    code = undefined
    status = undefined
    retryAfter = undefined
    cancelled = false
  }
  if (cancelled) code = 'AUTH_CANCELLED'
  return Object.assign(
    new AuthOperationError(
      code
        ? organizationFailureMessages[code]
        : 'Verification failed. Please try again.',
      code
    ),
    { status, retryAfter, cancelled },
    cancelled ? { __CANCEL__: true as const } : {}
  )
}

export type VerificationMethod =
  | '2fa'
  | 'passkey'
  | 'password'
  | 'oauth'
  | 'session'
export type SecurityProofScope =
  | OrganizationVerificationScope
  | 'channel.key.read'
  | 'passkey.register'
  | 'passkey.delete'
  | '2fa.setup'
  | '2fa.disable'
  | '2fa.backup_codes.regenerate'
  | 'access_token.generate'
  | 'access_token.update'
  | 'access_token.revoke'
  | 'account.binding.bind'
  | 'account.binding.unbind'
  | 'account.password.set'
  | 'account.password.change'
  | 'account.delete'
  | 'session.revoke'
  | 'session.revoke_others'
  | 'admin.user.create'
  | 'admin.user.update'
  | 'admin.user.delete'
  | 'admin.user.manage'
  | 'admin.user.passkey.reset'
  | 'admin.user.2fa.disable'
  | 'admin.user.binding.clear'
  | 'oauth.public_client.manage'
  | 'oauth.app.revoke'

/** ManageUser actions that change a user's status or role and need step-up. */
export type AdminUserManageAction = 'disable' | 'enable' | 'promote' | 'demote'

export type VerificationOperation =
  | OrganizationVerificationOperation
  | { scope: 'channel.key.read'; context: { channel_id: number } }
  | {
      scope: 'account.binding.bind'
      context: { provider: string; email?: string; code?: string }
    }
  | { scope: 'account.binding.unbind'; context: { provider_id: number } }
  | { scope: 'session.revoke'; context: { sid: string } }
  | { scope: 'admin.user.create'; context: { role: number } }
  | {
      scope:
        | 'admin.user.update'
        | 'admin.user.delete'
        | 'admin.user.passkey.reset'
        | 'admin.user.2fa.disable'
      context: { user_id: number }
    }
  | {
      scope: 'admin.user.manage'
      context: { user_id: number; action: AdminUserManageAction }
    }
  | {
      scope: 'admin.user.binding.clear'
      context:
        | { user_id: number; binding_type: string }
        | { user_id: number; provider_id: number }
    }
  | {
      scope: 'access_token.generate'
      context: { scopes: string[]; expires_at: number }
    }
  | {
      scope: 'access_token.update'
      context: { token_id: number; scopes: string[] }
    }
  | {
      scope: 'access_token.revoke'
      context: { token_id: number } | { legacy: true }
    }
  | {
      scope: 'oauth.public_client.manage'
      context: {
        action: 'create' | 'update' | 'delete'
        client_id: string
      }
    }
  | { scope: 'oauth.app.revoke'; context: { client_id: string } }
  | {
      scope: Exclude<
        SecurityProofScope,
        | 'channel.key.read'
        | 'account.binding.bind'
        | 'account.binding.unbind'
        | 'session.revoke'
        | 'access_token.generate'
        | 'access_token.update'
        | 'access_token.revoke'
        | 'oauth.public_client.manage'
        | 'oauth.app.revoke'
        | `admin.user.${string}`
        | OrganizationVerificationScope
      >
      context?: Record<string, never>
    }

export interface SecurityProof {
  proof_token: string
  expires_at: number
  method: VerificationMethod
  scope: SecurityProofScope
}

export type OrganizationSecurityProof = Omit<
  SecurityProof,
  'scope' | 'method'
> & {
  scope: OrganizationVerificationScope
  method: 'password' | '2fa' | 'passkey'
  auth_bundle: AuthTokenRotation
}

const organizationTime = z
  .number()
  .int()
  .nonnegative()
  .refine(Number.isSafeInteger)
const organizationProofSchema = z.object({
  proof_token: z.string().min(1),
  scope: z.enum(['organization.change_role', 'organization.remove']),
  method: z.enum(['password', '2fa', 'passkey']),
  expires_at: organizationTime,
  auth_bundle: z.object({
    access_token: z.string().min(1),
    token_type: z.literal('Bearer'),
    access_expires_at: organizationTime,
    session: z.object({
      sid: z.string().min(1),
      current: z.literal(true),
      login_method: z.string(),
      ip: z.string(),
      user_agent: z.string(),
      created_at: organizationTime,
      last_active_at: organizationTime,
      expires_at: organizationTime,
    }),
  }),
})

export function parseOrganizationSecurityProof(
  value: unknown,
  scope: OrganizationVerificationScope,
  method: OrganizationSecurityProof['method'],
  source: LoginSession
): OrganizationSecurityProof {
  try {
    const result = organizationProofSchema.parse(value)
    if (
      result.scope !== scope ||
      result.method !== method ||
      !result.proof_token.trim() ||
      result.expires_at <= Math.floor(Date.now() / 1000) ||
      result.expires_at > result.auth_bundle.session.expires_at ||
      !isOrganizationAuthReplacement(result.auth_bundle, source)
    ) {
      throw new AuthOperationError(
        'Verification failed. Please try again.',
        'SECURITY_PROOF_INVALID'
      )
    }
    return result
  } catch {
    // A schema error can contain the rejected input; never expose it.
    throw projectOrganizationVerificationError({
      code: 'SECURITY_PROOF_INVALID',
    })
  }
}

export type VerificationProofFor<T> =
  T extends OrganizationVerificationOperation
    ? OrganizationSecurityProof
    : SecurityProof

export interface VerificationRequirements {
  scope: SecurityProofScope | 'auth.login'
  methods: { method: VerificationMethod; available: boolean; reason?: string }[]
  oauth_providers: { slug: string; name: string }[]
  password_encryption_enabled: boolean
}

export type VerificationInput =
  | { method: '2fa'; code: string }
  | { method: 'password'; password: string }
  | { method: 'passkey'; rpID?: string }
  | { method: 'oauth'; provider: string }
  | { method: 'session' }

export type RequestVerificationOptions = VerificationOperation & {
  title?: string
  description?: string
}

export interface LoginChallenge {
  require_verification: true
  flow_token: string
  expires_at: number
  methods: VerificationRequirements['methods']
}

export interface RequestLoginVerificationOptions {
  scope: 'auth.login'
  challenge: LoginChallenge
  title?: string
  description?: string
}

export type VerificationRequest =
  | RequestVerificationOptions
  | RequestLoginVerificationOptions
export type LoginResult = AuthBundle | LoginChallenge

export type SecureVerificationState =
  | { phase: 'idle' }
  | { phase: 'loading'; request: VerificationRequest }
  | { phase: 'error'; request: VerificationRequest; error: string }
  | {
      phase: 'ready' | 'verifying'
      request: VerificationRequest
      requirements: VerificationRequirements
      input: VerificationInput | null
      error?: string
    }
