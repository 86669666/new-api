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

import { Route as ApplicationRoute } from '@/routes/__root'
import { Route as ConsentRoute } from '@/routes/oauth/provider/consent'
import { Route as LoginRoute } from '@/routes/oauth/provider/login'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import {
  providerHTTP,
  requestAuthorization,
  type AuthorizationPreview,
} from '../api'
import {
  createAuthorizationEntry,
  currentAuthorizationIdentity,
  providerBrowser,
  type AuthorizationCeremony,
  type AuthorizationPhase,
} from '../lib/authorization'

// Keep the real auth refresh runner and axios instances; control only their
// network adapter, including the private refresh client's HTTP boundary.
const refreshTransport = vi.hoisted(() => ({
  requests: [] as InternalAxiosRequestConfig[],
  handler: undefined as AxiosAdapter | undefined,
}))
vi.mock('axios', async (importOriginal) => {
  const actual = await importOriginal<typeof import('axios')>()
  actual.default.defaults.adapter = async (config) => {
    refreshTransport.requests.push(config)
    if (!refreshTransport.handler) {
      throw new Error('fixture_transport_not_initialized')
    }
    return refreshTransport.handler(config)
  }
  return actual
})

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
  strict = false,
  applicationRoot = false
) {
  const path = `/oauth/provider/${phase}`
  window.history.replaceState(null, '', path + query)
  const actual = phase === 'login' ? LoginRoute : ConsentRoute
  const ApplicationRoot = ApplicationRoute.options.component
  if (!ApplicationRoot) {
    throw new Error('production_root_component_missing')
  }
  const root = createRootRoute({
    beforeLoad: () => {
      expect(window.location.search).toBe('')
      expect(window.location.hash).toBe('')
    },
    component: () => (
      <QueryClientProvider client={client}>
        {applicationRoot ? <ApplicationRoot /> : <Outlet />}
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
  const ordinary = createRoute({
    getParentRoute: () => root,
    path: '/ordinary',
    component: () => <p>Ordinary page</p>,
  })
  const router = createRouter({
    routeTree: root.addChildren([page, signin, ordinary]),
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
  refreshTransport.requests.length = 0
  refreshTransport.handler = async (config) => {
    if (config.url === '/api/user/auth/refresh') {
      return { ...response(config, { success: false }), status: 401 }
    }
    if (config.url === '/api/status') {
      return response(config, { success: true, data: {} })
    }
    throw new Error('unexpected_fixture_http_path')
  }
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
  vi.unstubAllGlobals()
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
    expect(signin).toHaveAttribute('target', '_blank')
    expect(signin).toHaveAttribute('rel', 'noopener noreferrer')
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
    `?login_challenge=${'a'.repeat(16385)}`,
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

describe('first-login continuation in the original authorization tab', () => {
  function notify(kind: 'authenticated' | 'signed_out', sid: string) {
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: 'new-api:auth-session:event',
        newValue: JSON.stringify({
          kind,
          sid,
          source: 'other-owned-tab',
          nonce: 'owned-event',
          timestamp: Date.now(),
        }),
      })
    )
  }

  function observeReload() {
    const reload = vi.fn()
    const realWindow = window
    vi.stubGlobal('BroadcastChannel', undefined)
    vi.stubGlobal(
      'window',
      new Proxy(realWindow, {
        get(target, property) {
          if (property === 'location') return { ...target.location, reload }
          return Reflect.get(target, property, target)
        },
      })
    )
    return reload
  }

  it.each(['login', 'consent'] as const)(
    '%s actual root keeps anonymous input through sign-in notice and resumes only once on explicit click',
    async (phase) => {
      const reload = observeReload()
      useAuthStore.getState().auth.reset('complete')
      await mountPage(phase, undefined, false, true)
      const resume = await screen.findByRole('button', {
        name: 'Continue after signing in',
      })
      act(() => notify('authenticated', 'untrusted-event-sid'))
      expect(reload).not.toHaveBeenCalled()
      expect(useAuthStore.getState().auth.session).toBeNull()
      expect(requests).toHaveLength(0)
      expect(
        refreshTransport.requests.filter(
          (request) => request.url === '/api/user/auth/refresh'
        )
      ).toHaveLength(0)
      expect(window.location.search).toBe('')
      const pending = deferred<AuthBundle>()
      refreshTransport.handler = async (config) =>
        response(config, {
          success: true,
          data: await pending.promise,
        })
      act(() => {
        resume.click()
        resume.click()
      })
      await waitFor(() =>
        expect(
          refreshTransport.requests.filter(
            (request) => request.url === '/api/user/auth/refresh'
          )
        ).toHaveLength(1)
      )
      expect(requests).toHaveLength(0)
      const signedIn = bundle(
        'fresh-real-session-token',
        'fresh-real-session-sid'
      )
      await act(async () => {
        pending.resolve(signedIn)
        await pending.promise
      })
      const approve = await screen.findByRole('button', {
        name: phase === 'login' ? 'Continue' : 'Approve',
      })
      expect(screen.getByText('Synthetic account')).toBeVisible()
      expect(requests).toHaveLength(1)
      expect(requests[0].headers.get('Authorization')).toBe(
        'Bearer fresh-real-session-token'
      )
      expect(useAuthStore.getState().auth.session?.sid).toBe(
        'fresh-real-session-sid'
      )
      expect(navigate).not.toHaveBeenCalled()
      await userEvent.click(approve)
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(requests).toHaveLength(2)
      expect(requests[1].headers.get('Authorization')).toBe(
        'Bearer fresh-real-session-token'
      )
      for (const storage of [localStorage, sessionStorage]) {
        for (let index = 0; index < storage.length; index++) {
          const key = storage.key(index)
          expect(key ? storage.getItem(key) : '').not.toContain(capability)
        }
      }
    }
  )

  it('still-anonymous retry cannot extend the five-minute boundary even when timers are throttled', async () => {
    useAuthStore.getState().auth.reset('complete')
    let now = Date.now()
    const entered = now
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    await mountPage('login')
    await screen.findByRole('button', { name: 'Continue after signing in' })
    now = entered + 299_999
    await userEvent.click(
      screen.getByRole('button', { name: 'Continue after signing in' })
    )
    await screen.findByRole('button', { name: 'Continue after signing in' })
    expect(refreshTransport.requests).toHaveLength(1)
    now = entered + 300_000
    await userEvent.click(
      screen.getByRole('button', { name: 'Continue after signing in' })
    )
    await screen.findByText('Authorization could not be completed.')
    expect(refreshTransport.requests).toHaveLength(1)
    expect(requests).toHaveLength(0)
  })

  it.each(['expiry', 'unmount', 'new input'] as const)(
    'pending real refresh cannot preview after %s invalidation',
    async (change) => {
      useAuthStore.getState().auth.reset('complete')
      const entered = Date.now()
      const clock = vi.spyOn(Date, 'now').mockReturnValue(entered)
      const view = await mountPage('login')
      const resume = await screen.findByRole('button', {
        name: 'Continue after signing in',
      })
      const pending = deferred<AuthBundle>()
      refreshTransport.handler = async (config) =>
        response(config, { success: true, data: await pending.promise })
      await userEvent.click(resume)
      await waitFor(() => expect(refreshTransport.requests).toHaveLength(1))
      if (change === 'expiry') {
        clock.mockReturnValue(entered + 300_000)
      } else if (change === 'unmount') {
        view.unmount()
        await act(async () => {
          await Promise.resolve()
        })
      } else {
        window.history.replaceState(
          null,
          '',
          '/oauth/provider/login?login_challenge=fresh-input'
        )
        const validate = LoginRoute.options.validateSearch
        if (typeof validate !== 'function') {
          throw new Error('route_validator_missing')
        }
        validate({})
      }
      await act(async () => {
        pending.resolve(bundle())
        await pending.promise
      })
      if (change !== 'unmount') {
        await screen.findByText('Authorization could not be completed.')
      }
      expect(requests).toHaveLength(0)
      expect(navigate).not.toHaveBeenCalled()
    }
  )

  it.each(['transient refresh', 'out-of-sync refresh', 'preview'] as const)(
    '%s failure is terminal without producer replay or raw cause display',
    async (failure) => {
      useAuthStore.getState().auth.reset('complete')
      await mountPage('consent')
      const resume = await screen.findByRole('button', {
        name: 'Continue after signing in',
      })
      refreshTransport.handler = async (config) =>
        failure === 'preview'
          ? response(config, { success: true, data: bundle() })
          : {
              ...response(config, { code: 'RAW-CAUSE-CANARY' }),
              status: failure === 'transient refresh' ? 503 : 403,
            }
      if (failure === 'preview') {
        providerHTTP.defaults.adapter = async (config) => {
          requests.push(config)
          throw new Error('RAW-CAUSE-CANARY')
        }
      }
      await userEvent.click(resume)
      await screen.findByText('Authorization could not be completed.')
      expect(requests).toHaveLength(failure === 'preview' ? 1 : 0)
      expect(refreshTransport.requests).toHaveLength(1)
      expect(
        screen.queryByRole('button', { name: 'Continue after signing in' })
      ).not.toBeInTheDocument()
      expect(document.body.textContent).not.toContain('RAW-CAUSE-CANARY')
      expect(navigate).not.toHaveBeenCalled()
    }
  )

  it.each(['token', 'sid', 'user'] as const)(
    'refresh outcome must match the current %s before the first binding',
    async (change) => {
      useAuthStore.getState().auth.reset('complete')
      await mountPage('login')
      const resume = await screen.findByRole('button', {
        name: 'Continue after signing in',
      })
      refreshTransport.handler = async (config) =>
        response(config, { success: true, data: bundle('refresh-result') })
      let replaced = false
      const unsubscribe = useAuthStore.subscribe((state) => {
        if (!replaced && state.auth.accessToken === 'refresh-result') {
          replaced = true
          useAuthStore
            .getState()
            .auth.setBundle(
              bundle(
                change === 'token' ? 'replacement' : 'refresh-result',
                change === 'sid' ? 'replacement' : undefined,
                change === 'user' ? 23 : undefined
              )
            )
        }
      })
      try {
        await userEvent.click(resume)
        await screen.findByText('Authorization could not be completed.')
        expect(replaced).toBe(true)
        expect(requests).toHaveLength(0)
        expect(navigate).not.toHaveBeenCalled()
      } finally {
        unsubscribe()
      }
    }
  )

  it('cancel discards the anonymous input and removes all continuation actions', async () => {
    useAuthStore.getState().auth.reset('complete')
    await mountPage('login')
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await screen.findByText('Authorization could not be completed.')
    expect(
      screen.queryByRole('link', { name: 'Sign in' })
    ).not.toBeInTheDocument()
    expect(refreshTransport.requests).toHaveLength(0)
    expect(requests).toHaveLength(0)
  })

  it.each(['/ordinary', '/oauth/provider/login/'])(
    'actual root preserves anonymous authenticated-notice reload outside the two exact paths: %s',
    async (path) => {
      const reload = observeReload()
      useAuthStore.getState().auth.reset('complete')
      const view = await mountPage('login', undefined, false, true)
      await screen.findByRole('button', { name: 'Continue after signing in' })
      await act(async () => {
        await view.router.navigate({ href: '/ordinary' })
      })
      window.history.replaceState(null, '', path)
      act(() => notify('authenticated', 'another-session'))
      expect(reload).toHaveBeenCalledTimes(1)
      expect(useAuthStore.getState().auth.session).toBeNull()
      expect(requests).toHaveLength(0)
    }
  )

  it.each(['authenticated', 'signed_out'] as const)(
    'actual root preserves bound provider handling of a %s notice',
    async (kind) => {
      const reload = observeReload()
      await mountPage('login', undefined, false, true)
      await screen.findByRole('button', { name: 'Continue' })
      act(() =>
        notify(
          kind,
          kind === 'authenticated' ? 'replacement-sid' : 'synthetic-sid'
        )
      )
      if (kind === 'authenticated') {
        expect(reload).toHaveBeenCalledTimes(1)
        await screen.findByText('Authorization could not be completed.')
      } else {
        expect(reload).not.toHaveBeenCalled()
        await screen.findByText('Normal sign in')
      }
      expect(useAuthStore.getState().auth.session).toBeNull()
      expect(requests).toHaveLength(1)
      expect(navigate).not.toHaveBeenCalled()
    }
  )
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

describe('public OIDC consent', () => {
  it.each(['unselected', 'selected', 'unticked', 'denied'])(
    'balance consent %s is explicit and scoped',
    async (choice) => {
      const user = userEvent.setup()
      providerHTTP.defaults.adapter = async (config) => {
        requests.push(config)
        const value = preview('consent')
        value.requested_scopes = [
          'openid',
          'profile',
          'email',
          'offline_access',
          'balance:read',
        ]
        value.allowed_scopes = [...value.requested_scopes]
        return response(
          config,
          config.url?.endsWith('/preview')
            ? value
            : {
                redirect_to:
                  'https://issuer.example/oauth2/auth?consent_verifier=synthetic',
              }
        )
      }
      await mountPage('consent')
      const balance = await screen.findByRole('checkbox', {
        name: 'Personal wallet balance and account usage (optional)',
      })
      expect(balance).not.toBeChecked()
      expect(balance).toHaveAccessibleDescription(
        /including subscription usage/
      )
      expect(balance).toHaveAccessibleDescription(
        /ends when this sign-in session ends/
      )
      if (choice !== 'unselected') {
        balance.focus()
        await user.keyboard(' ')
        expect(balance).toBeChecked()
      }
      if (choice === 'unticked') await user.click(balance)
      await user.click(
        screen.getByRole('button', {
          name: choice === 'denied' ? 'Deny' : 'Approve',
        })
      )
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(JSON.parse(String(requests[1].data)).selected_scopes).toEqual(
        choice === 'denied'
          ? []
          : [
              'profile',
              'openid',
              ...(choice === 'selected' ? ['balance:read'] : []),
            ]
      )
    }
  )

  it('does not display or grant balance when it is not allowed', async () => {
    const user = userEvent.setup()
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      return response(
        config,
        config.url?.endsWith('/preview')
          ? preview('consent')
          : {
              redirect_to:
                'https://issuer.example/oauth2/auth?consent_verifier=synthetic',
            }
      )
    }
    await mountPage('consent')
    await screen.findByRole('button', { name: 'Approve' })
    expect(
      screen.queryByRole('checkbox', {
        name: 'Personal wallet balance and account usage (optional)',
      })
    ).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
    expect(JSON.parse(String(requests[1].data)).selected_scopes).toEqual([
      'profile',
    ])
  })

  it('rejects a balance preview when the client did not request balance', async () => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      const value = preview('consent')
      value.allowed_scopes.push('balance:read')
      return response(config, value)
    }
    await mountPage('consent')
    await screen.findByText('Authorization could not be completed.')
    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument()
    expect(requests).toHaveLength(1)
  })

  it.each([false, true])(
    'offline choice %s preserves requested identity scope',
    async (offlineSelected) => {
      const user = userEvent.setup()
      providerHTTP.defaults.adapter = async (config) => {
        requests.push(config)
        const value = preview('consent')
        value.requested_scopes = [
          'openid',
          'profile',
          'email',
          'offline_access',
        ]
        value.allowed_scopes = [...value.requested_scopes]
        return response(
          config,
          config.url?.endsWith('/preview')
            ? value
            : {
                redirect_to:
                  'https://issuer.example/oauth2/auth?consent_verifier=synthetic',
              }
        )
      }
      await mountPage('consent')
      const offline = await screen.findByRole('checkbox', {
        name: 'Offline access for up to seven days (optional)',
      })
      expect(offline).not.toBeChecked()
      expect(
        screen.getByRole('checkbox', { name: 'Identity sign-in (required)' })
      ).toBeChecked()
      if (offlineSelected) await user.click(offline)
      await user.click(screen.getByRole('button', { name: 'Approve' }))
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(JSON.parse(String(requests[1].data)).selected_scopes).toEqual([
        'profile',
        'openid',
        ...(offlineSelected ? ['offline_access'] : []),
      ])
    }
  )
})

describe('encrypted issuer challenge capture', () => {
  it.each(['YWJjZA==', 'YWJjZGU=', 'a'.repeat(4096)])(
    'retains a supported encrypted capability in memory',
    (challenge) => {
      window.history.replaceState(
        null,
        '',
        `/oauth/provider/login?login_challenge=${encodeURIComponent(challenge)}`
      )
      const entry = createAuthorizationEntry('login')
      entry.capture()
      expect(entry.read()).toEqual({ phase: 'login', challenge, active: true })
      expect(window.location.search).toBe('')
    }
  )
  it.each(['YW=JjZA=', 'YWJjZA===', 'YWJjZA='])(
    'rejects malformed encrypted capability %s',
    (challenge) => {
      window.history.replaceState(
        null,
        '',
        `/oauth/provider/login?login_challenge=${encodeURIComponent(challenge)}`
      )
      const entry = createAuthorizationEntry('login')
      entry.capture()
      expect(entry.read()).toBeNull()
      expect(window.location.search).toBe('')
    }
  )
})

describe('explicit recorded-history consent', () => {
  it.each(['unselected', 'selected', 'unticked', 'denied'])(
    'usage choice %s grants only explicit requested history access',
    async (choice) => {
      const user = userEvent.setup()
      providerHTTP.defaults.adapter = async (config) => {
        requests.push(config)
        const value = preview('consent')
        value.requested_scopes = ['profile', 'usage:read']
        value.allowed_scopes = [...value.requested_scopes]
        return response(
          config,
          config.url?.endsWith('/preview')
            ? value
            : {
                redirect_to:
                  'https://issuer.example/oauth2/auth?consent_verifier=synthetic',
              }
        )
      }
      await mountPage('consent')
      const usage = await screen.findByRole('checkbox', {
        name: 'Recorded call history (optional)',
      })
      expect(usage).not.toBeChecked()
      expect(usage).toHaveAccessibleDescription(/including deleted tokens/)
      expect(usage).toHaveAccessibleDescription(/may be incomplete/)
      expect(usage).toHaveAccessibleDescription(/not a wallet statement/)
      expect(usage).toHaveAccessibleDescription(
        /do not include organization usage/
      )
      if (choice !== 'unselected') {
        usage.focus()
        await user.keyboard(' ')
        expect(usage).toBeChecked()
      }
      if (choice === 'unticked') await user.click(usage)
      await user.click(
        screen.getByRole('button', {
          name: choice === 'denied' ? 'Deny' : 'Approve',
        })
      )
      await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
      expect(JSON.parse(String(requests[1].data)).selected_scopes).toEqual(
        choice === 'denied'
          ? []
          : ['profile', ...(choice === 'selected' ? ['usage:read'] : [])]
      )
      expect(requests).toHaveLength(2)
    }
  )

  it('does not offer requested history when registration excludes it', async () => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      const value = preview('consent')
      value.requested_scopes = ['profile', 'usage:read']
      value.allowed_scopes = ['profile']
      return response(
        config,
        config.url?.endsWith('/preview')
          ? value
          : {
              redirect_to:
                'https://issuer.example/oauth2/auth?consent_verifier=synthetic',
            }
      )
    }
    await mountPage('consent')
    await screen.findByRole('button', { name: 'Approve' })
    expect(
      screen.queryByRole('checkbox', {
        name: 'Recorded call history (optional)',
      })
    ).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1))
    expect(JSON.parse(String(requests[1].data)).selected_scopes).toEqual([
      'profile',
    ])
  })

  it('rejects a history allowance that was never requested', async () => {
    providerHTTP.defaults.adapter = async (config) => {
      requests.push(config)
      const value = preview('consent')
      value.allowed_scopes.push('usage:read')
      return response(config, value)
    }
    await mountPage('consent')
    await screen.findByText('Authorization could not be completed.')
    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument()
    expect(requests).toHaveLength(1)
  })

  it.each(['requested', 'allowed'] as const)(
    'a removed %s history scope cannot be sent by a stale checked decision',
    async (removed) => {
      window.history.replaceState(null, '', '/oauth/provider/consent')
      const identity = currentAuthorizationIdentity()
      expect(identity).not.toBeNull()
      if (!identity) throw new Error('fixture_identity_missing')
      const value = preview('consent')
      value.requested_scopes =
        removed === 'requested' ? ['profile'] : ['profile', 'usage:read']
      value.allowed_scopes =
        removed === 'allowed' ? ['profile'] : ['profile', 'usage:read']
      await requestAuthorization(
        identity,
        'consent',
        new AbortController().signal,
        capability,
        {
          preview: value,
          approve: true,
          email: false,
          offline: false,
          balance: false,
          usage: true,
        }
      )
      expect(JSON.parse(String(requests[0].data)).selected_scopes).toEqual([
        'profile',
      ])
    }
  )
})
