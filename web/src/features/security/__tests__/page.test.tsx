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
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import {
  cleanup,
  act,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AxiosError,
  type AxiosAdapter,
  type AxiosRequestTransformer,
  type InternalAxiosRequestConfig,
} from 'axios'
import { toast } from 'sonner'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { Profile } from '@/features/profile'
import type { UserProfile } from '@/features/profile/types'
import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

import { Security } from '../index'

const originalAdapter = api.defaults.adapter
const originalTransformRequest = api.defaults.transformRequest
const pageClients: QueryClient[] = []

const profile: UserProfile = {
  id: 1,
  username: 'alice',
  display_name: 'Alice',
  role: 1,
  group: 'default',
  quota: 1000000,
  used_quota: 0,
  request_count: 0,
  status: 1,
  aff_count: 0,
  aff_quota: 0,
  aff_history_quota: 0,
  created_time: 0,
  setting: JSON.stringify({
    notify_type: 'email',
    quota_warning_threshold: 500000,
  }),
}

beforeEach(() => {
  vi.stubGlobal('localStorage', {
    getItem: () => null,
    setItem: () => undefined,
    removeItem: () => undefined,
  })
  vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined)
  useAuthStore
    .getState()
    .auth.setUser({ ...profile, permissions: { sidebar_settings: false } })
  vi.spyOn(api, 'get').mockImplementation(async (url) => {
    if (url === '/api/user/access_tokens') {
      return { data: { success: true, data: { items: [], legacy: null } } }
    }
    if (url === '/api/user/access_tokens/catalog') {
      return {
        data: {
          success: true,
          data: { groups: [], max_tokens: 20, default_expiry_days: 30 },
        },
      }
    }
    if (url === '/api/user/self') {
      return { data: { success: true, data: profile } }
    }
    if (url === '/api/user/passkey') {
      return { data: { success: true, data: { enabled: false } } }
    }
    if (url === '/api/user/2fa/status') {
      return {
        data: {
          success: true,
          data: { enabled: false, locked: false, backup_codes_remaining: 0 },
        },
      }
    }
    if (url === '/api/user/sessions') {
      return { data: { success: true, data: [] } }
    }
    throw new Error(`Unexpected GET ${url}`)
  })
})

afterEach(() => {
  cleanup()
  for (const client of pageClients.splice(0)) client.clear()
  vi.unstubAllGlobals()
  useAuthStore.getState().auth.reset()
  vi.restoreAllMocks()
  api.defaults.adapter = originalAdapter
  api.defaults.transformRequest = originalTransformRequest
})

async function renderPage(path = '/security') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  pageClients.push(client)
  client.setQueryData(['status'], {
    checkin_enabled: false,
    wechat_login: true,
    github_oauth: true,
    oidc_enabled: true,
    custom_oauth_providers: [
      {
        id: 1,
        name: 'Gitea',
        slug: 'gitea',
        client_id: 'test-client',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        scopes: 'openid',
      },
    ],
  })
  const root = createRootRoute()
  const security = createRoute({
    getParentRoute: () => root,
    path: '/security',
    component: Security,
  })
  const personal = createRoute({
    getParentRoute: () => root,
    path: '/profile',
    component: Profile,
  })
  const router = createRouter({
    routeTree: root.addChildren([security, personal]),
    history: createMemoryHistory({ initialEntries: [path] }),
  })
  await router.load()
  const rendered = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { ...rendered, router, client }
}

function signInSessionActor(userId = 1, sid = 'current-session') {
  const now = Math.floor(Date.now() / 1000)
  const session = {
    sid,
    current: true,
    login_method: 'password',
    ip: '127.0.0.1',
    user_agent: 'test',
    created_at: now - 60,
    last_active_at: now,
    expires_at: now + 3600,
  }
  useAuthStore.getState().auth.setBundle({
    access_token: 's1-session-access',
    token_type: 'Bearer',
    access_expires_at: now + 600,
    user: { id: userId, username: 'alice', role: 1 },
    session,
  })
  return session
}

function sessionCeremonyAdapter(
  options: {
    beforeProof?: () => Promise<void>
    beforeWrite?: () => Promise<void>
    writeStatus?: number
    pendingData?: Record<string, unknown>
  } = {}
) {
  const session = signInSessionActor()
  const writes: InternalAxiosRequestConfig[] = []
  const proofs: Record<string, unknown>[] = []
  const proofResponses = vi.fn()
  vi.mocked(api.get).mockRestore()
  const adapter: AxiosAdapter = vi.fn(async (config) => {
    let data: unknown
    if (config.url === '/api/user/self') {
      data = profile
    } else if (config.url === '/api/user/sessions') {
      data = [session, { ...session, sid: 'other-session', current: false }]
    } else if (config.url === '/api/user/access_tokens') {
      data = { items: [], legacy: null }
    } else if (config.url === '/api/user/access_tokens/catalog') {
      data = { groups: [], max_tokens: 20, default_expiry_days: 30 }
    } else if (config.url === '/api/user/passkey') {
      data = { enabled: false }
    } else if (config.url === '/api/user/2fa/status') {
      data = { enabled: false, locked: false, backup_codes_remaining: 0 }
    } else if (config.url === '/api/user/oauth/bindings') {
      data = []
    } else if (config.url === '/api/verify/methods') {
      data = {
        scope: config.params.scope,
        methods: [{ method: '2fa', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      }
    } else if (config.url === '/api/verify') {
      const body = JSON.parse(config.data) as Record<string, unknown>
      proofs.push(body)
      await options.beforeProof?.()
      data = {
        proof_token: 'session-proof',
        scope: body.scope,
        method: '2fa',
        expires_at: Math.floor(Date.now() / 1000) + 60,
      }
      proofResponses()
    } else if (config.url?.startsWith('/api/user/sessions/')) {
      writes.push(config)
      await options.beforeWrite?.()
      if (options.writeStatus) {
        throw new AxiosError(
          'private session failure',
          'ERR_BAD_RESPONSE',
          config,
          undefined,
          {
            data: {
              success: false,
              code:
                options.writeStatus === 401
                  ? 'AUTH_UNAUTHORIZED'
                  : 'AUTH_SESSION_REVOCATION_PENDING',
              data: {
                ...options.pendingData,
                auth_bundle: { access_token: 'unusable-response-canary' },
              },
            },
            status: options.writeStatus,
            statusText: 'controlled failure',
            headers: {},
            config,
          }
        )
      }
      data = {
        revoked_sid: config.url.split('/').at(-1),
        current: config.url.endsWith('/current-session'),
        revoked_count: 1,
      }
    } else throw new Error(`Unexpected controlled route ${config.url}`)
    return {
      data: { success: true, data },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }
  })
  api.defaults.adapter = adapter
  return { adapter, writes, proofs, proofResponses }
}

it.each([
  {
    name: 'one other SID',
    action: 'Revoke',
    confirm: 'Revoke',
    scope: 'session.revoke',
    context: { sid: 'other-session' },
    url: '/api/user/sessions/other-session',
  },
  {
    name: 'all other SIDs',
    action: 'Sign out other sessions',
    confirm: 'Sign out others',
    scope: 'session.revoke_others',
    context: undefined,
    url: '/api/user/sessions/revoke-others',
  },
])(
  'verifies $name once before sending its exact session action',
  async (scenario) => {
    const controlled = sessionCeremonyAdapter()
    const user = userEvent.setup()
    const view = await renderPage()
    await user.click(
      await screen.findByRole('button', { name: scenario.action })
    )
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: scenario.confirm,
      })
    )
    const code = await screen.findByLabelText(
      'Authenticator code or backup code',
      { selector: 'input' }
    )
    expect(controlled.writes).toHaveLength(0)
    await user.type(code, '123456')
    await user.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => expect(controlled.writes).toHaveLength(1))
    expect(controlled.proofs).toEqual([
      {
        method: '2fa',
        scope: scenario.scope,
        ...(scenario.context ? { context: scenario.context } : {}),
        code: '123456',
      },
    ])
    expect(controlled.writes[0].url).toBe(scenario.url)
    expect(controlled.writes[0].headers.get('X-Security-Proof')).toBe(
      'session-proof'
    )
    expect(controlled.writes[0].singleUseAuthorization).toBe(true)
    expect(controlled.writes[0].skipAuthRefresh).toBe(true)
    await waitFor(() =>
      expect(
        view.client
          .getMutationCache()
          .getAll()
          .every((item) => item.state.status !== 'pending')
      ).toBe(true)
    )
    view.client.clear()
  }
)

describe('security page migration', () => {
  it('places account management on the left and verification and privacy on the right', async () => {
    await renderPage()
    const login = await screen.findByRole('region', {
      name: 'Login & Authentication',
    })
    expect(
      screen
        .getAllByRole('region')
        .map((region) => within(region).getAllByRole('heading')[0].textContent)
    ).toEqual([
      'Login & Authentication',
      'Sessions & Access',
      'Account Actions',
      'Privacy',
    ])
    expect(
      within(login).getByRole('button', { name: 'Change Password' })
    ).toBeVisible()
    expect(within(login).getByText('Account Bindings')).toBeVisible()
    const verification = screen.getByRole('complementary', {
      name: 'Security verification',
    })
    expect(await within(verification).findByText('Passkey Login')).toBeVisible()
    expect(
      await within(verification).findByText('Two-Factor Authentication')
    ).toBeVisible()
    expect(
      within(verification).getByRole('switch', { name: 'Record IP Address' })
    ).toBeVisible()
    expect(verification).toHaveClass('xl:sticky', 'xl:top-0')
    expect(verification.parentElement).toHaveClass(
      'grid',
      'xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.46fr)]'
    )
    const access = screen.getByRole('region', { name: 'Sessions & Access' })
    expect(within(access).getByText('Access tokens')).toBeVisible()
    expect(
      await within(access).findByText('No active login sessions')
    ).toBeVisible()
    expect(
      screen.getByRole('switch', { name: 'Record IP Address' })
    ).toBeVisible()
    expect(
      within(screen.getByRole('region', { name: 'Account Actions' })).getByRole(
        'button',
        { name: 'Delete Account' }
      )
    ).toBeVisible()
  })

  it('built-in and custom bindings share one compact responsive grid', async () => {
    await renderPage()
    const bindings = await screen.findByRole('list', {
      name: 'Account Bindings',
    })
    expect(within(bindings).getAllByRole('listitem')).toHaveLength(5)
    expect(within(bindings).getByText('Gitea')).toBeVisible()
    expect(bindings).toHaveClass(
      'grid-cols-1',
      'sm:grid-cols-2',
      'lg:grid-cols-3',
      'gap-2'
    )
    expect(screen.queryByText('Custom OAuth')).not.toBeInTheDocument()
  })

  it('the password action opens the existing dialog by keyboard and Escape closes it', async () => {
    const user = userEvent.setup()
    await renderPage()
    const action = await screen.findByRole('button', {
      name: 'Change Password',
    })
    action.focus()
    await user.keyboard('{Enter}')
    const dialog = await screen.findByRole('dialog', {
      name: 'Change Password',
    })
    expect(within(dialog).getByLabelText('Current Password')).toBeVisible()
    expect(
      within(dialog).getByLabelText('New Password', { exact: true })
    ).toBeVisible()
    await user.keyboard('{Escape}')
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    )
  })

  it('Profile retains preferences and no longer mounts security controls or requests', async () => {
    await renderPage('/profile')
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Save Settings' })
      ).toBeVisible()
    )
    expect(
      screen.queryByRole('button', { name: 'Change Password' })
    ).not.toBeInTheDocument()
    expect(screen.queryByText('Account Bindings')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('switch', { name: 'Record IP Address' })
    ).not.toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalledWith('/api/user/passkey')
    expect(api.get).not.toHaveBeenCalledWith('/api/user/2fa/status')
    expect(api.get).not.toHaveBeenCalledWith('/api/user/sessions')
  })

  it('a failed profile load offers retry before exposing account actions', async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ data: { success: false } })
    const user = userEvent.setup()
    await renderPage()
    expect(await screen.findByText('Failed to load profile')).toBeVisible()
    expect(
      screen.queryByRole('button', { name: 'Delete Account' })
    ).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(
      await screen.findByRole('button', { name: 'Delete Account' })
    ).toBeVisible()
  })
})

async function beginOtherSessionAction(
  user: ReturnType<typeof userEvent.setup>
) {
  await user.click(await screen.findByRole('button', { name: 'Revoke' }))
  await user.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Revoke',
    })
  )
}

async function submitSessionFactor(user: ReturnType<typeof userEvent.setup>) {
  await user.type(
    await screen.findByLabelText('Authenticator code or backup code', {
      selector: 'input',
    }),
    '123456'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
}

it('keeps current-session sign out on its ordinary policy without a factor', async () => {
  const controlled = sessionCeremonyAdapter()
  const user = userEvent.setup()
  await renderPage()
  await user.click(await screen.findByRole('button', { name: 'Sign out' }))
  await user.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Sign out',
    })
  )
  await waitFor(() => expect(controlled.writes).toHaveLength(1))
  expect(controlled.writes[0].url).toBe('/api/user/sessions/current-session')
  expect(controlled.writes[0].headers.has('X-Security-Proof')).toBe(false)
  expect(controlled.proofs).toHaveLength(0)
  await waitFor(() => expect(useAuthStore.getState().auth.user).toBeFalsy())
})

it.each(['close', 'actor', 'sid', 'unmount'] as const)(
  'cancels %s while a factor response is pending and never sends the late proof',
  async (change) => {
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const controlled = sessionCeremonyAdapter({ beforeProof: () => gate })
    const success = vi.spyOn(toast, 'success')
    const user = userEvent.setup()
    const view = await renderPage()
    await beginOtherSessionAction(user)
    await submitSessionFactor(user)
    await waitFor(() => expect(controlled.proofs).toHaveLength(1))
    if (change === 'close') await user.keyboard('{Escape}')
    else if (change === 'unmount') view.unmount()
    else {
      await act(() => {
        signInSessionActor(change === 'actor' ? 2 : 1, 'replacement-session')
      })
    }
    await act(async () => {
      release?.()
    })
    await waitFor(() =>
      expect(controlled.proofResponses).toHaveBeenCalledTimes(1)
    )
    await waitFor(() =>
      expect(
        view.client
          .getMutationCache()
          .getAll()
          .map((item) => item.state.status)
      ).toEqual(['error'])
    )
    expect(controlled.writes).toHaveLength(0)
    expect(success).not.toHaveBeenCalled()
    expect(
      view.client.getMutationCache().getAll()[0].state.error
    ).toMatchObject({ code: 'AUTH_CANCELLED' })
  }
)

it('does not let a cancelled late factor revive the old target or close a new confirmation', async () => {
  let release: (() => void) | undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const controlled = sessionCeremonyAdapter({ beforeProof: () => gate })
  const user = userEvent.setup()
  const view = await renderPage()
  await beginOtherSessionAction(user)
  await submitSessionFactor(user)
  await waitFor(() => expect(controlled.proofs).toHaveLength(1))
  await user.keyboard('{Escape}')
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  await act(async () => {
    release?.()
  })
  await waitFor(() =>
    expect(view.client.getMutationCache().getAll()[0].state.status).toBe(
      'error'
    )
  )
  expect(await screen.findByRole('alertdialog')).toHaveAccessibleName(
    'Sign out this device?'
  )
  expect(controlled.writes).toHaveLength(0)
})

it.each([
  { name: '401', status: 401, pendingData: {}, committed: undefined },
  {
    name: 'committed503',
    status: 503,
    pendingData: {
      session_revocation_complete: false,
      credential_change_committed: true,
    },
    committed: true,
  },
  { name: 'unknown503', status: 503, pendingData: {}, committed: undefined },
])(
  'does not replay or report success for $name after consuming one factor',
  async (scenario) => {
    const controlled = sessionCeremonyAdapter({
      writeStatus: scenario.status,
      pendingData: scenario.pendingData,
    })
    const success = vi.spyOn(toast, 'success')
    const user = userEvent.setup()
    const view = await renderPage()
    await beginOtherSessionAction(user)
    await submitSessionFactor(user)
    await waitFor(() =>
      expect(view.client.getMutationCache().getAll()[0].state.status).toBe(
        'error'
      )
    )
    expect(controlled.proofs).toHaveLength(1)
    expect(controlled.writes).toHaveLength(1)
    expect(controlled.writes[0].skipAuthRefresh).toBe(true)
    expect(success).not.toHaveBeenCalled()
    expect(useAuthStore.getState().auth.accessToken).toBe('s1-session-access')
    const error = view.client.getMutationCache().getAll()[0].state.error
    expect(error).toMatchObject({ status: scenario.status })
    if (scenario.committed === undefined) {
      expect(error).not.toHaveProperty('credential_change_committed')
    } else expect(error).toHaveProperty('credential_change_committed', true)
  }
)

it('rejects a late session write response after an actor change without reporting success', async () => {
  let release: (() => void) | undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const controlled = sessionCeremonyAdapter({ beforeWrite: () => gate })
  const success = vi.spyOn(toast, 'success')
  const user = userEvent.setup()
  const view = await renderPage()
  await beginOtherSessionAction(user)
  await submitSessionFactor(user)
  await waitFor(() => expect(controlled.writes).toHaveLength(1))
  await act(() => {
    signInSessionActor(2, 'replacement-session')
  })
  await act(async () => {
    release?.()
  })
  await waitFor(() =>
    expect(view.client.getMutationCache().getAll()[0].state.status).toBe(
      'error'
    )
  )
  expect(view.client.getMutationCache().getAll()[0].state.error).toMatchObject({
    code: 'AUTH_CANCELLED',
  })
  expect(controlled.proofs).toHaveLength(1)
  expect(controlled.writes).toHaveLength(1)
  expect(success).not.toHaveBeenCalled()
  expect(useAuthStore.getState().auth.user?.id).toBe(2)
})

it('uses the captured identity guard when the actor changes after transformRequest but before adapter dispatch', async () => {
  const controlled = sessionCeremonyAdapter()
  const transformed = vi.fn()
  const swap: AxiosRequestTransformer = function (data) {
    if (this.url === '/api/user/sessions/other-session') {
      transformed()
      signInSessionActor(2, 'replacement-session')
    }
    return data
  }
  api.defaults.transformRequest = [
    ...[originalTransformRequest ?? []].flat(),
    swap,
  ]
  const success = vi.spyOn(toast, 'success')
  const user = userEvent.setup()
  const view = await renderPage()
  await beginOtherSessionAction(user)
  await submitSessionFactor(user)
  await waitFor(() =>
    expect(view.client.getMutationCache().getAll()[0].state.status).toBe(
      'error'
    )
  )
  expect(transformed).toHaveBeenCalledTimes(1)
  expect(controlled.writes).toHaveLength(0)
  expect(success).not.toHaveBeenCalled()
  expect(view.client.getMutationCache().getAll()[0].state.error).toMatchObject({
    code: 'AUTH_CANCELLED',
  })
})
