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

export const OAUTH_CLIENT_KNOWN_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'balance:read',
  'usage:read',
  'tokens:read',
  'tokens:write',
] as const

export type OAuthClientScope = (typeof OAUTH_CLIENT_KNOWN_SCOPES)[number]
export type OAuthClientPresetName = 'boxo' | 'cherry_studio'

export const OAUTH_CLIENT_PRESETS: Record<
  OAuthClientPresetName,
  { redirects: readonly string[] }
> = {
  boxo: { redirects: ['http://127.0.0.1/oauth/callback'] },
  cherry_studio: { redirects: ['http://127.0.0.1:29873/oauth/callback'] },
}

const deniedSchemes = new Set([
  'javascript',
  'data',
  'file',
  'blob',
  'filesystem',
  'vbscript',
  'about',
  'jar',
])

function portOK(raw: string) {
  if (raw === '') return true
  if (!/^[0-9]+$/.test(raw)) return false
  const port = Number(raw)
  return port >= 1 && port <= 65535
}

function customScheme(scheme: string) {
  return (
    scheme.length > 0 &&
    scheme.length <= 32 &&
    !deniedSchemes.has(scheme) &&
    /^[a-z][a-z0-9+.-]*$/.test(scheme)
  )
}

/** Canonical public-client redirect. The server repeats this check. */
export function validOAuthClientRedirect(raw: string) {
  if (
    raw === '' ||
    raw.length > 2048 ||
    /[\r\n\\]/.test(raw) ||
    raw !== raw.trim()
  ) {
    return false
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return false
  }
  if (
    url.href !== raw ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    return false
  }
  const scheme = url.protocol.slice(0, -1)
  if (scheme === 'https') {
    return url.hostname !== '' && url.pathname !== '' && portOK(url.port)
  }
  if (scheme === 'http') {
    const host = url.hostname.replaceAll(/^\[|\]$/g, '')
    return (
      (host === '127.0.0.1' || host === '::1') &&
      url.pathname !== '' &&
      portOK(url.port)
    )
  }
  return (
    customScheme(scheme) && url.hostname !== '' && url.pathname.startsWith('/')
  )
}

export type OAuthClientManageContext =
  | {
      action: 'create'
      name: string
      redirects: string[]
      scopes: string[]
    }
  | {
      action: 'update'
      client_row_id: number
      name: string
      redirects: string[]
      scopes: string[]
    }
  | { action: 'delete'; client_row_id: number }

export function oauthClientManageContext(input: {
  action: 'create' | 'update' | 'delete'
  clientRowId?: number
  name?: string
  preset?: '' | OAuthClientPresetName
  redirects?: string[]
  scopes?: string[]
}): OAuthClientManageContext {
  if (input.action === 'delete') {
    return { action: 'delete', client_row_id: input.clientRowId ?? 0 }
  }
  const preset = input.preset ? OAUTH_CLIENT_PRESETS[input.preset] : undefined
  const redirects = [...(preset ? preset.redirects : (input.redirects ?? []))]
  redirects.sort()
  const selected = new Set(input.scopes ?? [])
  if (preset && selected.size === 0) {
    for (const scope of OAUTH_CLIENT_KNOWN_SCOPES) selected.add(scope)
  }
  selected.add('profile')
  const scopes = OAUTH_CLIENT_KNOWN_SCOPES.filter((scope) =>
    selected.has(scope)
  )
  const name = (input.name ?? '').trim()
  if (input.action === 'update') {
    return {
      action: 'update',
      client_row_id: input.clientRowId ?? 0,
      name,
      redirects,
      scopes,
    }
  }
  return { action: 'create', name, redirects, scopes }
}
