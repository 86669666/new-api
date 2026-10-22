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
import axios from 'axios'

import {
  authorizationIdentityMatches,
  validateAuthorizationRedirect,
  type AuthorizationIdentity,
  type AuthorizationPhase,
} from './lib/authorization'

export const oauthProviderScopes = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'balance:read',
  'usage:read',
  'tokens:read',
  'tokens:write',
] as const

export type AuthorizationPreview = {
  preview_token: string
  expires_at: number
  phase: AuthorizationPhase
  client_id: string
  client_name: string
  username: string
  requested_scopes: string[]
  allowed_scopes: string[]
  audience: string
}

// Intentionally separate from the dashboard client's refresh/token interceptors.
// No shared query/mutation cache ever retains this instance's responses/errors.
export const providerHTTP = axios.create({
  baseURL: '/',
  withCredentials: true,
  withXSRFToken: false,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'Cache-Control': 'no-store',
  },
})

export async function requestAuthorization(
  identity: AuthorizationIdentity,
  phase: AuthorizationPhase,
  signal: AbortSignal,
  challenge: string,
  decision?: {
    preview: AuthorizationPreview
    approve: boolean
    scopes: readonly string[]
  }
): Promise<AuthorizationPreview | string> {
  try {
    if (signal.aborted || !authorizationIdentityMatches(identity)) {
      throw new Error('invalid_identity')
    }
    const body: Record<string, unknown> = { challenge }
    if (decision) {
      body.preview_token = decision.preview.preview_token
      let action = 'deny'
      if (decision.approve) {
        action = phase === 'login' ? 'continue' : 'approve'
      }
      body.decision = action
      if (phase === 'consent') {
        const allowed = new Set(decision.preview.allowed_scopes)
        body.selected_scopes = decision.approve
          ? oauthProviderScopes.filter(
              (scope) => allowed.has(scope) && decision.scopes.includes(scope)
            )
          : []
      }
    }
    const response = await providerHTTP.post<unknown>(
      `/api/oauth/provider/${phase}${decision ? '' : '/preview'}`,
      body,
      { signal, headers: { Authorization: `Bearer ${identity.token}` } }
    )
    if (signal.aborted || !authorizationIdentityMatches(identity)) {
      throw new Error('invalid_identity')
    }
    const value = response.data
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('invalid_response')
    }
    const record = value as Record<string, unknown>
    if (decision) {
      if (Object.keys(record).length !== 1) {
        throw new Error('invalid_response')
      }
      return validateAuthorizationRedirect(record.redirect_to)
    }
    const fields = [
      'preview_token',
      'expires_at',
      'phase',
      'client_id',
      'client_name',
      'username',
      'requested_scopes',
      'allowed_scopes',
      'audience',
    ]
    if (
      Object.keys(record).length !== fields.length ||
      fields.some((key) => !(key in record)) ||
      record.phase !== phase ||
      typeof record.expires_at !== 'number' ||
      !Number.isSafeInteger(record.expires_at) ||
      record.expires_at <= Date.now() / 1000 ||
      typeof record.preview_token !== 'string' ||
      !/^[A-Za-z0-9._~-]{1,2048}$/.test(record.preview_token) ||
      ['client_id', 'client_name', 'username', 'audience'].some(
        (key) => typeof record[key] !== 'string'
      ) ||
      !record.client_id ||
      !record.username ||
      !record.audience ||
      !Array.isArray(record.requested_scopes) ||
      !record.requested_scopes.every((scope) => typeof scope === 'string') ||
      !Array.isArray(record.allowed_scopes) ||
      !record.allowed_scopes.includes('profile') ||
      record.allowed_scopes.length > oauthProviderScopes.length ||
      !record.allowed_scopes.every(
        (scope) =>
          typeof scope === 'string' &&
          (oauthProviderScopes as readonly string[]).includes(scope)
      ) ||
      new Set(record.allowed_scopes).size !== record.allowed_scopes.length
    ) {
      throw new Error('invalid_response')
    }
    // Every required field and its type was checked above.
    return record as unknown as AuthorizationPreview
  } catch {
    // Discard Axios config/cause/request/response, which can contain capabilities.
    throw new Error(
      'Authorization could not be completed. Start again from your client.'
    )
  }
}
