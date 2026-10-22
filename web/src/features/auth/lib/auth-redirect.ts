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
import { appPath, getAppBasePath } from '@/lib/deployment-path'
import type { AuthUser } from '@/stores/auth-store'

const allowedRedirectProtocols = new Set(['http:', 'https:'])

export function getSavedLanguage(user: AuthUser): string | undefined {
  if (typeof user.language === 'string') {
    return user.language
  }

  if (user.setting && typeof user.setting === 'object') {
    return typeof user.setting.language === 'string'
      ? user.setting.language
      : undefined
  }

  if (typeof user.setting !== 'string') {
    return undefined
  }

  try {
    const setting = JSON.parse(user.setting) as { language?: unknown }
    return typeof setting.language === 'string' ? setting.language : undefined
  } catch {
    return undefined
  }
}

export function sanitizeAuthRedirect(
  value: unknown,
  origin: string
): string | null {
  if (typeof value !== 'string') return null

  const target = value.trim()
  if (
    [...value].some(
      (character) =>
        character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127
    )
  ) {
    return null
  }
  // Reject encoded separators and dot segments before URL normalization.
  const rawPath = target.split(/[?#]/, 1)[0]
  if (
    /%(?:2e|2f|5c|25)/i.test(rawPath) ||
    /(?:^|\/)\.{1,2}(?:\/|$)/.test(rawPath)
  ) {
    return null
  }
  if (!target || target.includes('\\') || target.startsWith('//')) return null

  let trustedOrigin: URL
  try {
    trustedOrigin = new URL(origin)
  } catch {
    return null
  }
  if (!allowedRedirectProtocols.has(trustedOrigin.protocol)) return null

  let redirectURL: URL
  try {
    redirectURL = target.startsWith('/')
      ? new URL(target, trustedOrigin.origin)
      : new URL(target)
  } catch {
    return null
  }

  if (
    !allowedRedirectProtocols.has(redirectURL.protocol) ||
    redirectURL.origin !== trustedOrigin.origin
  ) {
    return null
  }

  const basePath = getAppBasePath()
  if (
    !target.startsWith('/') &&
    basePath !== '/' &&
    redirectURL.pathname !== basePath &&
    !redirectURL.pathname.startsWith(`${basePath}/`)
  ) {
    return null
  }

  return appPath(
    `${redirectURL.pathname}${redirectURL.search}${redirectURL.hash}`,
    basePath
  )
}
