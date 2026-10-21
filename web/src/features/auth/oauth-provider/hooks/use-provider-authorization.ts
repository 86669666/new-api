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
import { useEffect, useRef, useState } from 'react'

import { resolveAuthentication } from '@/lib/auth-session'
import { useAuthStore } from '@/stores/auth-store'

import { requestAuthorization, type AuthorizationPreview } from '../api'
import {
  authorizationIdentityMatches,
  currentAuthorizationIdentity,
  providerBrowser,
  type AuthorizationCeremony,
  type AuthorizationEntry,
  type AuthorizationIdentity,
} from '../lib/authorization'

type AuthorizationState =
  | { kind: 'loading' }
  | { kind: 'anonymous' }
  | { kind: 'terminal' }
  | { kind: 'submitting' }
  | { kind: 'ready'; preview: AuthorizationPreview }

export function useProviderAuthorization(entry: AuthorizationEntry) {
  const [ceremony] = useState(() => entry.read())
  const [state, setState] = useState<AuthorizationState>({ kind: 'loading' })
  const [email, setEmail] = useState(false)
  const mounted = useRef(false)
  const invalidated = useRef(false)
  const submitted = useRef(false)
  const identity = useRef<AuthorizationIdentity | null>(null)
  const controller = useRef(new AbortController())
  const initialization = useRef<Promise<AuthorizationPreview | null> | null>(
    null
  )

  useEffect(() => {
    mounted.current = true
    let active = true
    let expiry: ReturnType<typeof setTimeout> | undefined
    const stop = () => {
      invalidated.current = true
      controller.current.abort()
      if (ceremony) {
        entry.discard(ceremony)
      }
      if (mounted.current) {
        setState({ kind: 'terminal' })
      }
    }
    const unsubscribe = useAuthStore.subscribe(() => {
      if (identity.current && !authorizationIdentityMatches(identity.current)) {
        stop()
      }
    })
    const initialize = async (): Promise<AuthorizationPreview | null> => {
      if (
        !ceremony?.active ||
        window.location.pathname !== `/oauth/provider/${entry.phase}`
      ) {
        throw new Error('invalid_ceremony')
      }
      const result = await resolveAuthentication()
      if (
        !mounted.current ||
        invalidated.current ||
        !ceremony.active ||
        controller.current.signal.aborted ||
        window.location.pathname !== `/oauth/provider/${entry.phase}`
      ) {
        throw new Error('invalid_ceremony')
      }
      if (result.kind === 'anonymous') {
        return null
      }
      const captured = currentAuthorizationIdentity()
      if (result.kind !== 'authenticated' || !captured) {
        throw new Error('invalid_identity')
      }
      identity.current = captured
      const value = await requestAuthorization(
        captured,
        ceremony.phase,
        controller.current.signal,
        ceremony.challenge
      )
      if (typeof value === 'string') {
        throw new Error('invalid_preview')
      }
      return value
    }
    initialization.current ??= initialize()
    void initialization.current
      .then((preview) => {
        if (!active || invalidated.current) {
          return
        }
        if (window.location.pathname !== `/oauth/provider/${entry.phase}`) {
          stop()
          return
        }
        if (!preview) {
          if (ceremony) {
            entry.discard(ceremony)
          }
          setState({ kind: 'anonymous' })
          return
        }
        setState({ kind: 'ready', preview })
        expiry = setTimeout(
          stop,
          Math.max(0, preview.expires_at * 1000 - Date.now())
        )
      })
      .catch(() => {
        if (active) {
          stop()
        }
      })
    return () => {
      active = false
      mounted.current = false
      unsubscribe()
      clearTimeout(expiry)
      // StrictMode's immediate setup/cleanup/setup may reuse the same pending
      // initialization. An actual unmount invalidates it before later results.
      queueMicrotask(() => {
        if (!mounted.current) {
          stop()
        }
      })
    }
  }, [ceremony, entry])

  async function decide(approve: boolean): Promise<void> {
    const captured = identity.current
    const current: AuthorizationCeremony | null = ceremony
    if (
      submitted.current ||
      invalidated.current ||
      !mounted.current ||
      !captured ||
      !current?.active ||
      state.kind !== 'ready'
    ) {
      return
    }
    submitted.current = true
    const preview = state.preview
    setState({ kind: 'submitting' })
    try {
      if (
        !authorizationIdentityMatches(captured) ||
        preview.expires_at <= Date.now() / 1000 ||
        window.location.pathname !== `/oauth/provider/${entry.phase}`
      ) {
        throw new Error('invalid_ceremony')
      }
      const result = await requestAuthorization(
        captured,
        current.phase,
        controller.current.signal,
        current.challenge,
        {
          preview,
          approve,
          email: email && preview.allowed_scopes.includes('email'),
        }
      )
      if (
        !mounted.current ||
        invalidated.current ||
        !current.active ||
        !authorizationIdentityMatches(captured) ||
        typeof result !== 'string' ||
        window.location.pathname !== `/oauth/provider/${entry.phase}`
      ) {
        throw new Error('invalid_ceremony')
      }
      entry.discard(current)
      invalidated.current = true
      setState({ kind: 'terminal' })
      providerBrowser.replace(result)
    } catch {
      entry.discard(current)
      invalidated.current = true
      controller.current.abort()
      if (mounted.current) {
        setState({ kind: 'terminal' })
      }
    }
  }
  return { state, email, setEmail, decide }
}
