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
import { useAuthStore } from '@/stores/auth-store'

export type AuthorizationPhase = 'login' | 'consent'
export type AuthorizationIdentity = {
  userId: number
  sid: string
  token: string
}
export type AuthorizationCeremony = {
  phase: AuthorizationPhase
  challenge: string
  active: boolean
}

export function createAuthorizationEntry(phase: AuthorizationPhase) {
  let ceremony: AuthorizationCeremony | null = null
  const path = `/oauth/provider/${phase}`
  return {
    phase,
    capture(): Record<never, never> {
      if (window.location.pathname !== path) {
        return {}
      }
      const raw = window.location.search
      const fragment = window.location.href.includes('#')
      // Validation can run repeatedly while matching a route. Never put its
      // capability into router search/context or a persisted continuation.
      if (!raw && !fragment) {
        return {}
      }
      if (ceremony) {
        ceremony.active = false
      }
      ceremony = null
      try {
        if (fragment || !raw.startsWith('?') || raw.length > 32768) {
          return {}
        }
        const parts = raw.slice(1).split('&')
        if (parts.length !== 1) {
          return {}
        }
        const separator = parts[0].indexOf('=')
        if (separator < 0) {
          return {}
        }
        const key = decodeURIComponent(
          parts[0].slice(0, separator).replaceAll('+', ' ')
        )
        const value = decodeURIComponent(
          parts[0].slice(separator + 1).replaceAll('+', ' ')
        )
        if (
          key !== `${phase}_challenge` ||
          value.length > 16384 ||
          !/^[A-Za-z0-9._~-]+={0,2}$/.test(value) ||
          (value.includes('=') && value.length % 4 !== 0)
        ) {
          return {}
        }
        ceremony = { phase, challenge: value, active: true }
      } catch {
        // Malformed percent escapes/UTF-8 are terminal, with no raw error retained.
      } finally {
        // Browser history subscribers can synchronously capture again. They
        // must see the final ceremony before the single URL scrub notifies.
        try {
          window.history.replaceState(null, '', path)
        } catch {
          if (ceremony) {
            ceremony.active = false
          }
          ceremony = null
          // The existing missing-ceremony branch remains terminal and fixed.
        }
      }
      return {}
    },
    read(): AuthorizationCeremony | null {
      return ceremony
    },
    discard(value: AuthorizationCeremony): void {
      value.active = false
      value.challenge = ''
      if (ceremony === value) {
        ceremony = null
      }
    },
  }
}
export type AuthorizationEntry = ReturnType<typeof createAuthorizationEntry>

export function currentAuthorizationIdentity(): AuthorizationIdentity | null {
  const auth = useAuthStore.getState().auth
  const now = Date.now() / 1000
  if (
    auth.bootstrapState !== 'complete' ||
    !auth.user ||
    !auth.session ||
    !auth.accessToken ||
    !auth.accessExpiresAt ||
    auth.accessExpiresAt <= now ||
    auth.session.expires_at <= now
  ) {
    return null
  }
  return {
    userId: auth.user.id,
    sid: auth.session.sid,
    token: auth.accessToken,
  }
}

export function authorizationIdentityMatches(
  expected: AuthorizationIdentity
): boolean {
  const current = currentAuthorizationIdentity()
  return (
    current !== null &&
    current.userId === expected.userId &&
    current.sid === expected.sid &&
    current.token === expected.token
  )
}

// The own backend validates the issuer and prefix. This is an additional shape
// check, never a caller-supplied return target or a status-derived authority.
export function validateAuthorizationRedirect(value: unknown): string {
  if (typeof value !== 'string' || value.length > 32768) {
    throw new Error('invalid_redirect')
  }
  const url = new URL(value)
  if (
    url.protocol !== 'https:' ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.hash ||
    url.href !== value
  ) {
    throw new Error('invalid_redirect')
  }
  return value
}

export const providerBrowser = {
  replace(href: string): void {
    window.location.replace(href)
  },
}
