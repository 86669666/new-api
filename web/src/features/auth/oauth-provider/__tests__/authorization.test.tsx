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
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createBrowserHistory,
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios'
import { StrictMode } from 'react'
import { toast } from 'sonner'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { Route as ConsentRoute } from '@/routes/oauth/provider/consent'
import { Route as LoginRoute } from '@/routes/oauth/provider/login'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { providerHTTP, type AuthorizationPreview } from '../api'
import {
  createAuthorizationEntry,
  providerBrowser,
  type AuthorizationCeremony,
  type AuthorizationPhase,
} from '../lib/authorization'

const capability = 'owned-challenge-CANARY'
const originalAdapter = providerHTTP.defaults.adapter
const requests: InternalAxiosRequestConfig[] = []
let client: QueryClient
const navigate = vi.fn<(href: string) => void>()

function bundle(
  token = 'synthetic-dashboard-token',
  sid = 'synthetic-sid',
  userId = 17
): AuthBundle {
  const expires = Math.floor(Date.now() / 1000) + 3600
  return {
    access_token: token,
    token_type: 'Bearer',
    access_expires_at: expires,
    user: { id: userId, username: 'Synthetic account', role: 1 },
    session: {
      sid,
      current: true,
      login_method: 'password',
      ip: '127.0.0.1',
      user_agent: 'fixture',
      created_at: expires - 3600,
      last_active_at: expires - 3600,
      expires_at: expires,
    },
  }
}
function preview(phase: AuthorizationPhase): AuthorizationPreview {
  return {
    preview_token: 'owned-preview-token',
    expires_at: Math.floor(Date.now() / 1000) + 300,
    phase,
    client_id: 'synthetic-client',
    client_name: '<img src=x onerror=CANARY>',
    username: 'Synthetic account',
    requested_scopes: ['profile', 'email', 'tokens:read'],
    allowed_scopes: ['profile', 'email'],
    audience: 'newapi-userinfo',
  }
}
function response(config: InternalAxiosRequestConfig, data: unknown) {
  return { config, data, status: 200, statusText: 'OK', headers: {} }
}
function deferred<T>() {
  let resolve: (value: T) => void = () => {
    throw new Error('uninitialized deferred')
  }
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}
async function mountPage(
  phase: AuthorizationPhase,
  query = `?${phase}_challenge=${capability}`,
  strict = false
) {
  const path = `/oauth/provider/${phase}`
  window.history.replaceState(null, '', path + query)
  const actual = phase === 'login' ? LoginRoute : ConsentRoute
  const root = createRootRoute({
    beforeLoad: () => {
      expect(window.location.search).toBe('')
      expect(window.location.hash).toBe('')
    },
    component: () => (
      <QueryClientProvider client={client}>
        <Outlet />
      </QueryClientProvider>
    ),
  })
  const page = createRoute({
    getParentRoute: () => root,
    path,
    validateSearch: actual.options.validateSearch,
    component: actual.options.component,
  })
  const signin = createRoute({
    getParentRoute: () => root,
    path: '/sign-in',
    component: () => <p>Normal sign in</p>,
  })
  const router = createRouter({
    routeTree: root.addChildren([page, signin]),
    history: createMemoryHistory({ initialEntries: [path + query] }),
    defaultPendingMinMs: 0,
  })
  const view = render(
    strict ? (
      <StrictMode>
        <RouterProvider router={router} />
      </StrictMode>
    ) : (
      <RouterProvider router={router} />
    )
  )
  return { ...view, router }
}

beforeEach(() => {
  requests.length = 0
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  useAuthStore.getState().auth.setBundle(bundle())
  vi.spyOn(providerBrowser, 'replace').mockImplementation(navigate)
  providerHTTP.defaults.adapter = async (config) => {
    requests.push(config)
    const phase = config.url?.includes('/consent') ? 'consent' : 'login'
    return response(
      config,
      config.url?.endsWith('/preview')
        ? preview(phase)
        : {
            redirect_to:
              'https://issuer.example/oauth2/auth?login_verifier=synthetic',
          }
    )
  }
})
afterEach(() => {
  cleanup()
  client.clear()
  useAuthStore.getState().auth.reset()
  providerHTTP.defaults.adapter = originalAdapter
  window.history.replaceState(null, '', '/')
  vi.useRealTimers()
})

describe('explicit dashboard-session provider authorization', () => {
  it.each(['login', 'consent'] as const)(
    '%s approval uses exact direct JSON and a frozen bearer once',
    async (phase) => {
      const user = userEvent.setup()
      await mountPage(phase)
      const approve = await screen.findByRole('button', {
        name: phase === 'login' ? 'Continue' : 'Approve',
      })
      expect(screen.getByText('<img src=x onerror=CANARY>')).toBeInTheDocument()
      expect(document.querySelector('img[onerror]')).toBeNull()
      expect(screen.getByText('newapi-userinfo')).toBeInTheDocument()
      if (phase === 'consent') {
        const profile = screen.getByRole('checkbox', {
          name: 'Profile (required)',
        })
        expect(profile).toBeChecked()
        expect(profile).toHaveAttribute('aria-disabled', 'true')
        await user.click(profile)
        expect(profile).toBeChecked()
        const email = screen.getByRole('checkbox', {
          name: 'Email address (optional)',
        })
        expect(email).not.toBeChecked()
        await user.click(email)
      }
      await user.click(approve)
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(requests).toHaveLength(2)
      expect(JSON.parse(String(requests[0].data))).toEqual({
        challenge: capability,
      })
      expect(JSON.parse(String(requests[1].data))).toEqual(
        phase === 'login'
          ? {
              challenge: capability,
              preview_token: 'owned-preview-token',
              decision: 'continue',
            }
          : {
              challenge: capability,
              preview_token: 'owned-preview-token',
              decision: 'approve',
              selected_scopes: ['profile', 'email'],
            }
      )
      for (const config of requests) {
        expect(config.headers.get('Authorization')).toBe(
          'Bearer synthetic-dashboard-token'
        )
        expect(config.withCredentials).toBe(true)
        expect(config.headers.get('Cache-Control')).toBe('no-store')
        expect(config.url).toMatch(
          /^\/api\/oauth\/provider\/(login|consent)(\/preview)?$/
        )
      }
      expect(client.getQueryCache().getAll()).toHaveLength(0)
      expect(client.getMutationCache().getAll()).toHaveLength(0)
      for (const storage of [localStorage, sessionStorage]) {
        for (let index = 0; index < storage.length; index++) {
          const key = storage.key(index)
          expect(key ? storage.getItem(key) : '').not.toContain(capability)
        }
      }
    }
  )

  it.each(['login', 'consent'] as const)(
    '%s denial is explicit; consent includes an empty selected_scopes array',
    async (phase) => {
      await mountPage(phase)
      await userEvent.click(await screen.findByRole('button', { name: 'Deny' }))
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(JSON.parse(String(requests[1].data))).toEqual(
        phase === 'login'
          ? {
              challenge: capability,
              preview_token: 'owned-preview-token',
              decision: 'deny',
            }
          : {
              challenge: capability,
              preview_token: 'owned-preview-token',
              decision: 'deny',
              selected_scopes: [],
            }
      )
    }
  )

  it('anonymous entry scrubs the capability before auth and only offers a fixed normal sign-in', async () => {
    useAuthStore.getState().auth.reset('complete')
    await mountPage('login')
    const signin = await screen.findByRole('link', { name: 'Sign in' })
    expect(signin).toHaveAttribute('href', '/sign-in')
    expect(requests).toHaveLength(0)
    expect(window.location.search).toBe('')
    expect(useAuthStore.getState().auth.pendingLoginVerification).toBeNull()
  })

  it.each([
    '?login_challenge=a&login_challenge=b',
    '?login_challenge=a&unknown=b',
    '?login_challenge=%ZZ',
    '?login_challenge=%FF',
    '?login_challenge=a+b',
    '?login_challenge',
    '?consent_challenge=a',
    `?login_challenge=${'a'.repeat(2049)}`,
    '?login_challenge=a#fragment',
  ])(
    'malformed raw query is scrubbed and cannot start preview: %s',
    async (query) => {
      await mountPage('login', query)
      await screen.findByText('Authorization could not be completed.')
      expect(requests).toHaveLength(0)
      expect(navigate).not.toHaveBeenCalled()
      expect(window.location.search + window.location.hash).toBe('')
    }
  )

  it('StrictMode does not duplicate a preview or resurrect a discarded ceremony on remount', async () => {
    const view = await mountPage('login', undefined, true)
    await screen.findByRole('button', { name: 'Continue' })
    expect(requests).toHaveLength(1)
    view.unmount()
    await act(async () => {
      await Promise.resolve()
    })
    await mountPage('login', '')
    await screen.findByText('Authorization could not be completed.')
    expect(requests).toHaveLength(1)
  })

  it.each(['token', 'sid', 'user'] as const)(
    'a %s change during preview drops the old promise without dispatching a replacement decision',
    async (change) => {
      const pending = deferred<unknown>()
      providerHTTP.defaults.adapter = async (config) => {
        requests.push(config)
        return response(config, await pending.promise)
      }
      await mountPage('login')
      await waitFor(() => expect(requests).toHaveLength(1))
      act(() =>
        useAuthStore
          .getState()
          .auth.setBundle(
            bundle(
              change === 'token' ? 'replacement-token' : undefined,
              change === 'sid' ? 'replacement-sid' : undefined,
              change === 'user' ? 22 : undefined
            )
          )
      )
      await act(async () => {
        pending.resolve(preview('login'))
        await pending.promise
      })
      await screen.findByText('Authorization could not be completed.')
      expect(requests).toHaveLength(1)
      expect(requests[0].headers.get('Authorization')).toBe(
        'Bearer synthetic-dashboard-token'
      )
      expect(navigate).not.toHaveBeenCalled()
    }
  )

  it('opposing synchronous decisions send once and an unknown result is terminal with fixed errors', async () => {
    const pending = deferred<unknown>()
    const adapter: AxiosAdapter = async (config) => {
      requests.push(config)
      if (config.url?.endsWith('/preview')) {
        return response(config, preview('login'))
      }
      await pending.promise
      throw Object.assign(new Error('RAW-ERROR-CANARY'), {
        response: { data: capability },
        config,
      })
    }
    providerHTTP.defaults.adapter = adapter
    const errorToast = vi.spyOn(toast, 'error')
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    await mountPage('login')
    const approve = await screen.findByRole('button', { name: 'Continue' })
    const deny = screen.getByRole('button', { name: 'Deny' })
    act(() => {
      approve.click()
      deny.click()
    })
    await waitFor(() => expect(requests).toHaveLength(2))
    await act(async () => {
      pending.resolve(null)
      await pending.promise
    })
    await screen.findByText('Authorization could not be completed.')
    expect(
      screen.queryByRole('button', { name: 'Retry' })
    ).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('RAW-ERROR-CANARY')
    expect(errorToast).not.toHaveBeenCalled()
    expect(log).not.toHaveBeenCalled()
    expect(navigate).not.toHaveBeenCalled()
    expect(requests).toHaveLength(2)
  })

  it.each(['identity', 'route', 'unmount'] as const)(
    'a delayed decision cannot navigate after %s invalidation',
    async (change) => {
      const pending = deferred<unknown>()
      providerHTTP.defaults.adapter = async (config) => {
        requests.push(config)
        return response(
          config,
          config.url?.endsWith('/preview')
            ? preview('login')
            : await pending.promise
        )
      }
      const view = await mountPage('login')
      await userEvent.click(
        await screen.findByRole('button', { name: 'Continue' })
      )
      await waitFor(() => expect(requests).toHaveLength(2))
      if (change === 'identity') {
        act(() =>
          useAuthStore.getState().auth.setBundle(bundle('rotated-token'))
        )
      }
      if (change === 'route') {
        window.history.replaceState(null, '', '/elsewhere')
      }
      if (change === 'unmount') {
        view.unmount()
      }
      await act(async () => {
        pending.resolve({
          redirect_to: 'https://issuer.example/oauth2/auth?login_verifier=old',
        })
        await pending.promise
      })
      expect(navigate).not.toHaveBeenCalled()
      expect(requests).toHaveLength(2)
    }
  )

  it.each([
    { success: true, data: preview('login') },
    { ...preview('login'), audience: ['newapi-userinfo'] },
    { ...preview('login'), phase: 'consent' },
    { ...preview('login'), expires_at: 1 },
  ])('malformed or expired preview never enables a decision', async (body) => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      return response(config, body)
    }
    await mountPage('login')
    await screen.findByText('Authorization could not be completed.')
    expect(requests).toHaveLength(1)
    expect(
      screen.queryByRole('button', { name: 'Continue' })
    ).not.toBeInTheDocument()
  })

  it.each([
    'http://issuer.example/auth',
    'https://user@issuer.example/auth',
    'https://issuer.example/auth#fragment',
  ])('unsafe successful redirect is terminal: %s', async (redirect_to) => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      return response(
        config,
        config.url?.endsWith('/preview') ? preview('login') : { redirect_to }
      )
    }
    await mountPage('login')
    await userEvent.click(
      await screen.findByRole('button', { name: 'Continue' })
    )
    await screen.findByText('Authorization could not be completed.')
    expect(navigate).not.toHaveBeenCalled()
    expect(requests).toHaveLength(2)
  })

  it('a preview expiring before the click sends no decision request', async () => {
    await mountPage('login')
    const approve = await screen.findByRole('button', { name: 'Continue' })
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 301_000)
    await userEvent.click(approve)
    await screen.findByText('Authorization could not be completed.')
    expect(requests).toHaveLength(1)
    expect(navigate).not.toHaveBeenCalled()
  })

  it('401 after submitting a decision cannot invoke dashboard refresh or replay', async () => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      if (config.url?.endsWith('/preview')) {
        return response(config, preview('consent'))
      }
      throw Object.assign(new Error('unauthorized'), {
        response: { status: 401, data: capability },
        config,
      })
    }
    await mountPage('consent')
    await userEvent.click(
      await screen.findByRole('button', { name: 'Approve' })
    )
    await screen.findByText('Authorization could not be completed.')
    expect(requests).toHaveLength(2)
    expect(navigate).not.toHaveBeenCalled()
  })
})

describe('provider authorization with synchronous browser history', () => {
  it.each(['login', 'consent'] as const)(
    '%s capture finalizes once before a browser-history subscriber re-enters',
    (phase) => {
      const path = `/oauth/provider/${phase}`
      const nativeReplace = window.history.replaceState
      nativeReplace.call(window.history, null, '', path)
      const history = createBrowserHistory()
      const replace = vi.spyOn(window.history, 'replaceState')
      const entry = createAuthorizationEntry(phase)
      const observed: Array<AuthorizationCeremony | null> = []
      let reentering = false
      const notify = vi.fn(() => {
        if (reentering) {
          throw new Error('recursive browser-history capture')
        }
        reentering = true
        try {
          entry.capture()
          observed.push(entry.read())
        } finally {
          reentering = false
        }
      })
      const unsubscribe = history.subscribe(notify)
      try {
        entry.capture()
        expect(entry.read()).toBeNull()
        expect(replace).not.toHaveBeenCalled()
        expect(notify).not.toHaveBeenCalled()

        // Seed a fresh arrival with the native writer; the scrub itself uses
        // TanStack's real patched replaceState and synchronous notification.
        nativeReplace.call(
          window.history,
          null,
          '',
          `${path}?${phase}_challenge=${capability}`
        )
        entry.capture()
        const first = entry.read()
        expect(first).toEqual({ phase, challenge: capability, active: true })
        expect(observed).toEqual([first])
        expect(replace).toHaveBeenCalledExactlyOnceWith(null, '', path)
        entry.capture()
        entry.capture()
        expect(entry.read()).toBe(first)
        expect(notify).toHaveBeenCalledTimes(1)
        expect(replace).toHaveBeenCalledTimes(1)
        if (!first) {
          throw new Error('valid browser-history capture missing')
        }
        entry.discard(first)
        entry.capture()
        entry.capture()
        expect(entry.read()).toBeNull()
        expect(first).toEqual({ phase, challenge: '', active: false })
        expect(notify).toHaveBeenCalledTimes(1)
        expect(replace).toHaveBeenCalledTimes(1)

        const wrongPhase = phase === 'login' ? 'consent' : 'login'
        for (const invalid of [
          `?${phase}_challenge=a&${phase}_challenge=b`,
          `?${phase}_challenge=%ZZ`,
          `?${wrongPhase}_challenge=wrong`,
          `?${phase}_challenge=valid#fragment`,
          '#',
        ]) {
          nativeReplace.call(
            window.history,
            null,
            '',
            `${path}?${phase}_challenge=fresh`
          )
          entry.capture()
          const fresh = entry.read()
          expect(fresh).toEqual({ phase, challenge: 'fresh', active: true })
          expect(fresh).not.toBe(first)
          expect(observed.at(-1)).toBe(fresh)
          const notificationsBeforeInvalid = notify.mock.calls.length
          const scrubsBeforeInvalid = replace.mock.calls.length
          nativeReplace.call(window.history, null, '', path + invalid)
          entry.capture()
          expect(entry.read()).toBeNull()
          expect(fresh?.active).toBe(false)
          expect(observed.at(-1)).toBeNull()
          expect(window.location.search + window.location.hash).toBe('')
          expect(notify).toHaveBeenCalledTimes(notificationsBeforeInvalid + 1)
          expect(replace).toHaveBeenCalledTimes(scrubsBeforeInvalid + 1)
          entry.capture()
          expect(entry.read()).toBeNull()
          expect(notify).toHaveBeenCalledTimes(notificationsBeforeInvalid + 1)
          expect(replace).toHaveBeenCalledTimes(scrubsBeforeInvalid + 1)
        }
      } finally {
        unsubscribe()
        replace.mockRestore()
        history.destroy()
      }
      expect(window.history.replaceState).toBe(nativeReplace)
    }
  )

  it('a failed URL scrub keeps capture terminal without exposing the history cause', () => {
    window.history.replaceState(
      null,
      '',
      `/oauth/provider/login?login_challenge=${capability}`
    )
    const entry = createAuthorizationEntry('login')
    const replace = vi
      .spyOn(window.history, 'replaceState')
      .mockImplementation(() => {
        throw new Error('RAW-HISTORY-CAUSE-CANARY')
      })
    try {
      expect(entry.capture()).toEqual({})
      expect(entry.read()).toBeNull()
      expect(replace).toHaveBeenCalledTimes(1)
      expect(requests).toHaveLength(0)
    } finally {
      replace.mockRestore()
    }
  })
})
