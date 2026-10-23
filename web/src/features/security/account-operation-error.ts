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
import { AuthOperationError } from '@/lib/secure-verification'
import {
  getServerErrorMessageKey,
  getServerErrorSources,
  getServerErrorStatus,
  isServerErrorCancelled,
} from '@/lib/server-error-message'

const accountFailureMessages: Readonly<Record<string, string>> = {
  AUTH_CANCELLED: 'Request failed',
  AUTH_SESSION_REVOCATION_PENDING: 'Please try again later.',
  AUTH_UNAUTHORIZED: 'Session expired!',
  AUTH_SESSION_REVOKED: 'Session expired!',
  AUTH_TOKEN_EXPIRED: 'Session expired!',
  CURRENT_PASSWORD_INVALID: 'Current password is incorrect.',
  ACCOUNT_SECURITY_STATE_CHANGED:
    'Password settings have changed. Reload the page and try again.',
  LAST_LOGIN_METHOD: 'Add another login method before unlinking this account.',
  ACCOUNT_ALREADY_BOUND: 'This external account is already bound.',
  EMAIL_ADDRESS_REJECTED: 'Please enter a valid email address',
  EMAIL_ALREADY_TAKEN: 'This email address is already in use.',
  EMAIL_BINDING_DELIVERY_FAILED:
    'Verification email could not be sent. Start email verification again.',
  EMAIL_BINDING_CODE_INVALID: 'Email verification code is incorrect.',
  EMAIL_BINDING_LOCKED:
    'Too many incorrect codes. Start email verification again.',
  EMAIL_BINDING_RESEND_WAIT:
    'Please wait before requesting another verification code.',
  PASSWORD_POLICY_REJECTED:
    'Password must contain between 8 and 128 characters.',
}

const fixedAccountMessages = new Set([
  ...Object.values(accountFailureMessages),
  'Account bindings have changed. Start this operation again.',
  "This email address is not allowed by the administrator's email policy.",
  'New password must be different from current password',
  'Long passwords are unavailable until the password storage upgrade is complete.',
  'Failed to delete account',
  'Request failed',
  'Verification failed. Please try again.',
])

export type AccountOperationError = AuthOperationError & {
  status?: number
  retryAfter?: number
  session_revocation_complete?: false
  credential_change_committed?: boolean
  revoked_count?: number
  __CANCEL__?: true
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object'
}

// Only finite public account facts cross this boundary. In particular, safe
// display text alone does not make an Axios cause/config safe to retain.
export function projectAccountOperationError(
  error: unknown
): AccountOperationError {
  let code: string | undefined
  let message = 'Request failed'
  const fields: Omit<AccountOperationError, keyof AuthOperationError> = {}
  try {
    const sources = getServerErrorSources(error)
    if (
      isServerErrorCancelled(error) ||
      sources.some((source) => source.code === 'AUTH_CANCELLED')
    ) {
      return Object.assign(
        new AuthOperationError('Request failed', 'AUTH_CANCELLED'),
        { __CANCEL__: true as const }
      )
    }
    const status = getServerErrorStatus(error)
    if (
      Number.isInteger(status) &&
      status !== undefined &&
      status >= 100 &&
      status <= 599
    ) {
      fields.status = status
    }
    if (status !== undefined && status >= 500) {
      message = 'Please try again later.'
    }
    for (const source of sources) {
      if (typeof source.code !== 'string') continue
      const fixed = Object.hasOwn(accountFailureMessages, source.code)
        ? accountFailureMessages[source.code]
        : getServerErrorMessageKey({ code: source.code })
      if (typeof fixed === 'string') {
        code = source.code
        message = fixed
        break
      }
    }
    for (const source of sources) {
      const fixed = source.message_key ?? source.message
      if (typeof fixed === 'string' && fixedAccountMessages.has(fixed)) {
        message = fixed
        break
      }
    }
    for (const source of sources) {
      const response = isRecord(source.response) ? source.response : undefined
      const headers =
        response && isRecord(response.headers) ? response.headers : undefined
      const header =
        headers?.['retry-after'] ??
        headers?.['Retry-After'] ??
        source.retryAfter
      const retry =
        typeof header === 'string' && /^\d{1,5}$/.test(header)
          ? Number(header)
          : header
      if (
        typeof retry === 'number' &&
        Number.isSafeInteger(retry) &&
        retry >= 0 &&
        retry <= 86400
      ) {
        fields.retryAfter = retry
        break
      }
    }
    if (code === 'AUTH_SESSION_REVOCATION_PENDING' && status === 503) {
      for (const source of sources) {
        if (source.code !== code) continue
        const data = isRecord(source.data) ? source.data : source
        if (data.session_revocation_complete !== false) continue
        fields.session_revocation_complete = false
        if (typeof data.credential_change_committed === 'boolean') {
          fields.credential_change_committed = data.credential_change_committed
        }
        if (
          typeof data.revoked_count === 'number' &&
          Number.isSafeInteger(data.revoked_count) &&
          data.revoked_count >= 0
        ) {
          fields.revoked_count = data.revoked_count
        }
        break
      }
    }
  } catch {
    // Foreign accessors must not escape, or carry any partially read origin.
    return new AuthOperationError('Request failed')
  }
  return Object.assign(new AuthOperationError(message, code), fields)
}

// Profile callers may be queries/mutations before any account hook can catch.
// Reject business failures here as well, before a response can become cache data.
export async function accountOperation<T>(request: Promise<T>): Promise<T> {
  try {
    const result = await request
    if (
      isRecord(result) &&
      isRecord(result.data) &&
      result.data.success === false
    ) {
      throw projectAccountOperationError({ response: result })
    }
    return result
  } catch (error) {
    throw projectAccountOperationError(error)
  }
}
