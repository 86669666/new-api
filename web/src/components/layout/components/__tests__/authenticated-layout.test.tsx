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
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
  type AnyRoute,
} from '@tanstack/react-router'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import axios from 'axios'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { logout } from '@/features/auth/api'
import {
  applyAuthBundle,
  bootstrapAuthentication,
  clearAuthenticatedClientState,
  clearAuthentication,
  refreshAuthentication,
} from '@/lib/auth-session'
import { Route as ProtectedRoute } from '@/routes/_authenticated/route'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { AuthenticatedLayout } from '../authenticated-layout'

// Only unrelated shell UI is replaced; layout, providers, outlet, route guard,
// query observers and authentication state/operations remain real.
vi.mock('../app-header', () => ({ AppHeader: () => null }))
vi.mock('../app-sidebar', () => ({ AppSidebar: () => null }))
vi.mock('@/components/command-menu', () => ({ CommandMenu: () => null }))

const bundle: AuthBundle = {
  access_token: 'synthetic-layout-token',
  token_type: 'Bearer',
  access_expires_at: 9999999999,
  user: { id: 42, username: 'layout-user', role: 1 },
  session: {
    sid: 'synthetic-layout-session',
    current: true,
    login_method: 'password',
    ip: '',
    user_agent: 'test',
    created_at: 1,
    last_active_at: 1,
    expires_at: 9999999999,
  },
}
let client: QueryClient
const readPage = vi.fn(async (page: string) => `${page} private data`)

function PrivatePage(props: { page: string }) {
  const query = useQuery({
    queryKey: ['layout-test', props.page],
    queryFn: () => readPage(props.page),
  })
  return <h1>{query.data ?? 'Loading private page'}</h1>
}

beforeEach(() => {
  clearAuthentication(false, 'idle')
  localStorage.clear()
  sessionStorage.clear()
  document.cookie = 'new_api_has_session=; Max-Age=0; Path=/'
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
  vi.spyOn(axios.Axios.prototype, 'request').mockImplementation(
    async (config) => {
      throw new Error(`Unexpected request: ${JSON.stringify(config)}`)
    }
  )
})

afterEach(() => {
  cleanup()
  client.clear()
  clearAuthentication(false, 'idle')
  localStorage.clear()
  sessionStorage.clear()
})

it.each(['logout', 'expiry'] as const)(
  '%s unmounts private query consumers before navigation and restoration remounts them',
  async (trigger) => {
    applyAuthBundle(bundle, false)
    render(
      <QueryClientProvider client={client}>
        <AuthenticatedLayout>
          <PrivatePage page='overview' />
        </AuthenticatedLayout>
      </QueryClientProvider>
    )
    await screen.findByRole('heading', { name: 'overview private data' })
    const query = client
      .getQueryCache()
      .find({ queryKey: ['layout-test', 'overview'] })
    expect(query?.getObserversCount()).toBe(1)

    await act(async () => {
      if (trigger === 'logout') {
        vi.mocked(axios.Axios.prototype.request).mockResolvedValueOnce({
          status: 200,
          data: { success: true },
        })
        expect((await logout()).success).toBe(true)
        // The same successful-logout cleanup used by SignOutDialog; deliberately
        // do not navigate, so a redirect cannot hide a broken layout guard.
        clearAuthenticatedClientState(client)
      } else {
        vi.mocked(axios.Axios.prototype.request).mockResolvedValueOnce({
          status: 401,
          data: { success: false, code: 'AUTH_SESSION_EXPIRED' },
        })
        expect(await refreshAuthentication()).toEqual({ kind: 'anonymous' })
      }
    })
    expect(useAuthStore.getState().auth.user).toBeNull()
    expect(screen.queryByRole('heading')).not.toBeInTheDocument()
    expect(query?.getObserversCount()).toBe(0)
    readPage.mockClear()
    await act(async () => {
      await client.invalidateQueries({ queryKey: ['layout-test'] })
    })
    expect(readPage).not.toHaveBeenCalled()

    act(() => applyAuthBundle(bundle, false))
    await screen.findByRole('heading', { name: 'overview private data' })
    await waitFor(() => expect(readPage).toHaveBeenCalledWith('overview'))
    expect(
      client
        .getQueryCache()
        .find({ queryKey: ['layout-test', 'overview'] })
        ?.getObserversCount()
    ).toBe(1)
  }
)

function mountProtectedRouter() {
  const root = createRootRoute()
  const protectedRoute = createRoute({
    getParentRoute: () => root,
    id: '_authenticated',
    // Rebind the production file-route guard to this minimal test route tree.
    beforeLoad: ProtectedRoute.options
      .beforeLoad as AnyRoute['options']['beforeLoad'],
    component: ProtectedRoute.options.component,
  })
  const overview = createRoute({
    getParentRoute: () => protectedRoute,
    path: 'dashboard',
    component: () => <PrivatePage page='overview' />,
  })
  const settings = createRoute({
    getParentRoute: () => protectedRoute,
    path: 'keys',
    component: () => <PrivatePage page='settings' />,
  })
  const signIn = createRoute({
    getParentRoute: () => root,
    path: 'sign-in',
    component: () => <h1>Sign in fixture</h1>,
  })
  const router = createRouter({
    routeTree: root.addChildren([
      protectedRoute.addChildren([overview, settings]),
      signIn,
    ]),
    history: createMemoryHistory({ initialEntries: ['/dashboard'] }),
  })
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return router
}

it('protected navigation switches query consumers and redirects after sign-out without remounting private pages', async () => {
  applyAuthBundle(bundle, false)
  const router = mountProtectedRouter()
  await screen.findByRole('heading', { name: 'overview private data' })
  const overview = client
    .getQueryCache()
    .find({ queryKey: ['layout-test', 'overview'] })
  await act(async () => {
    await router.navigate({ to: '/keys' })
  })
  await screen.findByRole('heading', { name: 'settings private data' })
  expect(
    screen.queryByRole('heading', { name: 'overview private data' })
  ).not.toBeInTheDocument()
  expect(overview?.getObserversCount()).toBe(0)
  const settings = client
    .getQueryCache()
    .find({ queryKey: ['layout-test', 'settings'] })
  act(() => clearAuthenticatedClientState(client, false))
  expect(screen.queryByRole('heading')).not.toBeInTheDocument()
  expect(settings?.getObserversCount()).toBe(0)
  readPage.mockClear()
  await act(async () => {
    await router.navigate({ to: '/dashboard' })
  })
  await screen.findByRole('heading', { name: 'Sign in fixture' })
  expect(router.state.location.pathname).toBe('/sign-in')
  expect(router.state.location.search).toEqual({ redirect: '/dashboard' })
  expect(readPage).not.toHaveBeenCalled()
})

it('cold protected navigation waits for server restoration with an empty store and no session hint', async () => {
  expect(useAuthStore.getState().auth.user).toBeNull()
  expect(await bootstrapAuthentication()).toEqual({ kind: 'anonymous' })
  expect(axios.Axios.prototype.request).not.toHaveBeenCalled()
  let restoreSession!: (value: {
    status: number
    data: { success: boolean; data: AuthBundle }
  }) => void
  const response = new Promise<{
    status: number
    data: { success: boolean; data: AuthBundle }
  }>((resolve) => {
    restoreSession = resolve
  })
  vi.mocked(axios.Axios.prototype.request).mockReturnValueOnce(response)
  mountProtectedRouter()
  await waitFor(() =>
    expect(axios.Axios.prototype.request).toHaveBeenCalledWith(
      expect.objectContaining({ url: '/api/user/auth/refresh', method: 'post' })
    )
  )
  expect(useAuthStore.getState().auth.bootstrapState).toBe('checking')
  expect(screen.queryByRole('heading')).not.toBeInTheDocument()
  expect(readPage).not.toHaveBeenCalled()
  await act(async () => {
    restoreSession({ status: 200, data: { success: true, data: bundle } })
    await response
  })
  await screen.findByRole('heading', { name: 'overview private data' })
  expect(useAuthStore.getState().auth.user?.id).toBe(42)
  expect(
    client
      .getQueryCache()
      .find({ queryKey: ['layout-test', 'overview'] })
      ?.getObserversCount()
  ).toBe(1)
})
