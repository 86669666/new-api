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

export const PUBLIC_OAUTH_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'balance:read',
  'usage:read',
  'tokens:read',
  'tokens:write',
] as const

export type PublicOAuthScope = (typeof PUBLIC_OAUTH_SCOPES)[number]

export type PublicOAuthClientPreset = {
  key: string
  name: string
  redirect_uris: string[]
  scopes: string[]
  grant_types: string[]
}

export type PublicOAuthClient = {
  id: number
  client_id: string
  name: string
  redirect_uris: string[]
  scopes: string[]
  grant_types: string[]
  token_endpoint_auth_method: 'none'
  enabled: boolean
  created_at: string
  updated_at: string
}

export type PublicOAuthClientInput = {
  client_id?: string
  name: string
  redirect_uris: string[]
  scopes: string[]
  enabled: boolean
}

export type AuthorizedOAuthApp = {
  client_id: string
  name: string
  scopes: string[]
  grant_count: number
  approved_at: number
  expires_at: number
}

export function publicOAuthScopeLabel(
  t: (key: string) => string,
  scope: string
): string {
  switch (scope) {
    case 'openid':
      return t('OpenID')
    case 'profile':
      return t('Profile')
    case 'email':
      return t('Email')
    case 'offline_access':
      return t('Offline access')
    case 'balance:read':
      return t('Read balance')
    case 'usage:read':
      return t('Read usage')
    case 'tokens:read':
      return t('Read tokens')
    case 'tokens:write':
      return t('Write tokens')
    default:
      return scope
  }
}
