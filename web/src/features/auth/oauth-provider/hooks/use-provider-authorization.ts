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
import { useCallback, useEffect, useRef, useState } from 'react'

import {
  refreshAuthentication,
  resolveAuthentication,
} from '@/lib/auth-session'
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
  const [deadline] = useState(() => Date.now() + 300_000)
  const [state, setState] = useState<AuthorizationState>({ kind: 'loading' })
  const [email, setEmail] = useState(false)
  const [offline, setOffline] = useState(false)
  const [balance, setBalance] = useState(false)
  const mounted = useRef(false)
  const invalidated = useRef(false)
  const submitted = useRef(false)
  const waiting = useRef(false)
  const resuming = useRef(false)
  const identity = useRef<AuthorizationIdentity | null>(null)
  const controller = useRef(new AbortController())
  const expiry = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const initialization = useRef<Promise<AuthorizationPreview | null> | null>(
    null
  )

  const stop = useCallback(() => {
    invalidated.current = true
    controller.current.abort()
    clearTimeout(expiry.current)
    if (ceremony) {
      entry.discard(ceremony)
    }
    if (mounted.current) {
      setState({ kind: 'terminal' })
    }
  }, [ceremony, entry])

  const isLive = useCallback(
    () =>
      mounted.current &&
      !invalidated.current &&
      ceremony?.active === true &&
      !controller.current.signal.aborted &&
      window.location.pathname === `/oauth/provider/${entry.phase}` &&
      (!waiting.current || Date.now() < deadline),
    [ceremony, deadline, entry.phase]
  )

  const readPreview = useCallback(
    async (captured: AuthorizationIdentity): Promise<AuthorizationPreview> => {
      if (!isLive() || !ceremony || !authorizationIdentityMatches(captured)) {
        throw new Error('invalid_ceremony')
      }
      const preview = await requestAuthorization(
        captured,
        ceremony.phase,
        controller.current.signal,
        ceremony.challenge
      )
      if (
        !isLive() ||
        !authorizationIdentityMatches(captured) ||
        typeof preview === 'string'
      ) {
        throw new Error('invalid_preview')
      }
      return preview
    },
    [ceremony, isLive]
  )

  const showPreview = useCallback(
    (preview: AuthorizationPreview) => {
      if (!isLive()) {
        stop()
        return
      }
      setState({ kind: 'ready', preview })
      clearTimeout(expiry.current)
      const expires = waiting.current
        ? Math.min(deadline, preview.expires_at * 1000)
        : preview.expires_at * 1000
      expiry.current = setTimeout(stop, Math.max(0, expires - Date.now()))
    },
    [deadline, isLive, stop]
  )

  useEffect(() => {
    mounted.current = true
    let active = true
    const unsubscribe = useAuthStore.subscribe(() => {
      if (identity.current && !authorizationIdentityMatches(identity.current)) {
        stop()
      }
    })
    const initialize = async (): Promise<AuthorizationPreview | null> => {
      if (!isLive()) {
        throw new Error('invalid_ceremony')
      }
      const result = await resolveAuthentication()
      if (result.kind === 'anonymous') {
        waiting.current = true
      }
      if (!isLive()) {
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
      return readPreview(captured)
    }
    initialization.current ??= initialize()
    void initialization.current
      .then((preview) => {
        if (!active || invalidated.current) {
          return
        }
        if (!isLive()) {
          stop()
          return
        }
        if (!preview) {
          setState({ kind: 'anonymous' })
          expiry.current = setTimeout(stop, Math.max(0, deadline - Date.now()))
          return
        }
        showPreview(preview)
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
      clearTimeout(expiry.current)
      // StrictMode can reuse pending initialization during immediate remount.
      queueMicrotask(() => {
        if (!mounted.current) {
          stop()
        }
      })
    }
  }, [deadline, isLive, readPreview, showPreview, stop])

  async function resume(): Promise<void> {
    if (state.kind !== 'anonymous' || resuming.current || identity.current) {
      return
    }
    if (!isLive()) {
      stop()
      return
    }
    resuming.current = true
    setState({ kind: 'loading' })
    try {
      const result = await refreshAuthentication()
      if (!isLive()) {
        throw new Error('invalid_ceremony')
      }
      if (result.kind === 'anonymous') {
        setState({ kind: 'anonymous' })
        return
      }
      const captured = currentAuthorizationIdentity()
      if (
        result.kind !== 'authenticated' ||
        !captured ||
        captured.userId !== result.bundle.user.id ||
        captured.sid !== result.bundle.session.sid ||
        captured.token !== result.bundle.access_token
      ) {
        throw new Error('invalid_identity')
      }
      identity.current = captured
      const preview = await readPreview(captured)
      if (!isLive()) {
        throw new Error('invalid_ceremony')
      }
      showPreview(preview)
    } catch {
      stop()
    } finally {
      resuming.current = false
    }
  }

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
        !isLive() ||
        !authorizationIdentityMatches(captured) ||
        preview.expires_at <= Date.now() / 1000
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
          offline: offline && preview.allowed_scopes.includes('offline_access'),
          balance: balance && preview.allowed_scopes.includes('balance:read'),
        }
      )
      if (
        !isLive() ||
        !authorizationIdentityMatches(captured) ||
        typeof result !== 'string'
      ) {
        throw new Error('invalid_ceremony')
      }
      entry.discard(current)
      invalidated.current = true
      clearTimeout(expiry.current)
      setState({ kind: 'terminal' })
      providerBrowser.replace(result)
    } catch {
      stop()
    }
  }
  return {
    state,
    email,
    setEmail,
    offline,
    setOffline,
    balance,
    setBalance,
    decide,
    resume,
    cancel: stop,
  }
}
