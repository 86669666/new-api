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
  act,
  cleanup,
  render,
  renderHook,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AxiosError,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from 'axios'
import { createInstance } from 'i18next'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import {
  changeAccountPassword,
  getLoginSessions,
  revokeLoginSession,
} from '@/features/profile/api'
import en from '@/i18n/locales/en.json'
import zh from '@/i18n/locales/zh.json'
import { api } from '@/lib/api'
import { STATUS_QUERY_KEY } from '@/lib/status-query'
import { useAuthStore } from '@/stores/auth-store'

import { ChangePasswordDialog } from '../components/dialogs/change-password-dialog'
import { DeleteAccountDialog } from '../components/dialogs/delete-account-dialog'
import { EmailBindDialog } from '../components/dialogs/email-bind-dialog'
import { TwoFABackupDialog } from '../components/dialogs/two-fa-backup-dialog'
import { TwoFADisableDialog } from '../components/dialogs/two-fa-disable-dialog'
import { TwoFASetupDialog } from '../components/dialogs/two-fa-setup-dialog'
import { LoginSessionsCard } from '../components/login-sessions-card'
import { useAccountSecurity } from '../hooks/use-account-security'

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }))
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  useNavigate: () => navigate,
}))

let client: QueryClient
const originalAdapter = api.defaults.adapter
beforeEach(() => {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  client.setQueryData(STATUS_QUERY_KEY, { passkey_rp_ids: ['localhost'] })
})

afterEach(() => {
  cleanup()
  client.clear()
  api.defaults.adapter = originalAdapter
  navigate.mockReset()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  useAuthStore.getState().auth.reset('idle')
})

function signInAccountFixture() {
  const now = Math.floor(Date.now() / 1000)
  useAuthStore.getState().auth.setBundle({
    access_token: 's1-bearer-canary',
    token_type: 'Bearer',
    access_expires_at: now + 600,
    user: { id: 1, username: 'user', role: 1 },
    session: {
      sid: 'account-session',
      current: true,
      login_method: 'password',
      ip: '127.0.0.1',
      user_agent: 'test',
      created_at: now - 60,
      last_active_at: now,
      expires_at: now + 3600,
    },
  })
}

// Account failures must not make request credentials reachable from retained
// application state, including hidden/symbol properties or the original objects.
function expectNoAccountSecrets(
  roots: unknown[],
  originals: object[],
  secrets: string[]
) {
  const queue = [...roots]
  const seen = new Set<object>()
  for (let index = 0; index < queue.length; index++) {
    const value = queue[index]
    if (typeof value === 'string') {
      for (const secret of secrets) expect(value).not.toContain(secret)
    }
    if (
      (typeof value !== 'object' || value === null) &&
      typeof value !== 'function'
    ) {
      continue
    }
    const object = value as object
    expect(originals).not.toContain(object)
    if (seen.has(object)) continue
    seen.add(object)
    for (const key of Reflect.ownKeys(object)) {
      const property = Object.getOwnPropertyDescriptor(object, key)
      if (property && 'value' in property) queue.push(property.value)
    }
  }
}

function accountFailureAdapter(status: number, body: Record<string, unknown>) {
  const originals: object[] = []
  const secrets = [
    's1-password-canary',
    's1-original-password-canary',
    's1-proof-canary',
    's1-totp-canary',
    's1-flow-canary',
    's1-email-code-canary',
    's1-bundle-canary',
    's1-refresh-canary',
    's1-bearer-canary',
  ]
  const adapter: AxiosAdapter = vi.fn(
    async (config: InternalAxiosRequestConfig) => {
      const credentials = {
        password: secrets[0],
        original_password: secrets[1],
        proof: secrets[2],
        totp: secrets[3],
        flow_token: secrets[4],
        email_code: secrets[5],
        auth_bundle: secrets[6],
        refresh: secrets[7],
      }
      const response = {
        data: {
          ...body,
          message_params: credentials,
          private_data: credentials,
        },
        status,
        statusText: 'controlled failure',
        headers: { 'retry-after': '1' },
        config,
      }
      const raw = new AxiosError(
        `unsafe ${secrets[0]}`,
        'ERR_BAD_RESPONSE',
        config,
        credentials,
        response
      )
      const cause = Object.assign(new Error(`nested ${secrets[3]}`), {
        credentials,
      })
      Object.defineProperty(raw, 'cause', { value: cause })
      Object.defineProperty(raw, 'hidden', { value: credentials })
      Object.defineProperty(raw, Symbol('credentials'), { value: credentials })
      originals.push(
        raw,
        cause,
        credentials,
        response,
        response.data,
        config,
        config.headers
      )
      throw raw
    }
  )
  api.defaults.adapter = adapter
  return { adapter, originals, secrets }
}

it.each([
  {
    name: 'committed pending',
    status: 503,
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    data: {
      session_revocation_complete: false,
      credential_change_committed: true,
      revoked_count: 2,
    },
  },
  {
    name: 'unknown pending',
    status: 503,
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    data: { session_revocation_complete: false },
  },
  {
    name: 'unknown storage failure',
    status: 500,
    code: 'AUTH_INTERNAL_ERROR',
    data: {},
  },
])(
  'keeps $name safe in mutation cache before reset or garbage collection',
  async (scenario) => {
    signInAccountFixture()
    const failure = accountFailureAdapter(scenario.status, {
      success: false,
      code: scenario.code,
      message: '',
      data: scenario.data,
    })
    const mutation = client.getMutationCache().build(client, {
      mutationFn: () =>
        changeAccountPassword(
          {
            password: 's1-password-canary',
            original_password: 's1-original-password-canary',
          },
          's1-proof-canary',
          new AbortController().signal
        ),
      retry: false,
    })
    await expect(mutation.execute(undefined)).rejects.toMatchObject({
      code: scenario.code,
    })
    expect(failure.adapter).toHaveBeenCalledTimes(1)
    const retained = mutation.state.error as Error & {
      credential_change_committed?: boolean
      revoked_count?: number
    }
    if ('credential_change_committed' in scenario.data) {
      expect(retained).toMatchObject({
        credential_change_committed: true,
        revoked_count: 2,
      })
    } else {
      expect(retained).not.toHaveProperty('credential_change_committed')
      expect(retained).not.toHaveProperty('revoked_count')
    }
    expectNoAccountSecrets(
      [
        ...client
          .getMutationCache()
          .getAll()
          .map((item) => item.state),
        ...client
          .getQueryCache()
          .getAll()
          .map((item) => item.state),
      ],
      failure.originals,
      failure.secrets
    )
    expect(useAuthStore.getState().auth.accessToken).toBe('s1-bearer-canary')
  }
)

it('projects session GET failures before query error and failureReason retain credentials', async () => {
  signInAccountFixture()
  const failure = accountFailureAdapter(500, {
    success: false,
    code: 'AUTH_INTERNAL_ERROR',
  })
  await expect(
    client.fetchQuery({
      queryKey: ['s1-sessions'],
      queryFn: () => getLoginSessions(),
    })
  ).rejects.toMatchObject({ code: 'AUTH_INTERNAL_ERROR' })
  expectNoAccountSecrets(
    client
      .getQueryCache()
      .getAll()
      .map((item) => item.state),
    failure.originals,
    failure.secrets
  )
})

it('keeps the public account hook pending error safe without treating it as success', async () => {
  signInAccountFixture()
  const failure = accountFailureAdapter(503, {
    success: false,
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    data: {
      session_revocation_complete: false,
      credential_change_committed: true,
    },
  })
  const { result } = renderHook(() => useAccountSecurity())
  let outcome: unknown
  await act(async () => {
    outcome = await result.current.run((signal) =>
      changeAccountPassword(
        {
          password: 's1-password-canary',
          original_password: 's1-original-password-canary',
        },
        's1-proof-canary',
        signal
      )
    )
  })
  expect(outcome).toBeUndefined()
  expect(result.current.pending).toBe(false)
  expect(result.current.error).toMatchObject({
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    credential_change_committed: true,
  })
  expectNoAccountSecrets(
    [
      result.current.error,
      ...client
        .getMutationCache()
        .getAll()
        .map((item) => item.state),
      ...client
        .getQueryCache()
        .getAll()
        .map((item) => item.state),
    ],
    failure.originals,
    failure.secrets
  )
  expect(failure.adapter).toHaveBeenCalledTimes(1)
})

it('projects an ordinary initial-password verification failure before the account hook retains it', async () => {
  signInAccountFixture()
  const failure = accountFailureAdapter(403, {
    success: false,
    code: 'SECURITY_VERIFICATION_FAILED',
  })
  const failedAdapter = failure.adapter
  api.defaults.adapter = async (config) => {
    if (config.url !== '/api/verify/methods') return failedAdapter(config)
    return {
      data: {
        success: true,
        data: {
          scope: 'account.password.change',
          methods: [{ method: 'password', available: true }],
          oauth_providers: [],
          password_encryption_enabled: false,
        },
      },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }
  }
  const { result } = renderHook(() => useAccountSecurity())
  await act(async () => {
    await result.current.run((signal) =>
      result.current.verify(
        { scope: 'account.password.change' },
        signal,
        's1-original-password-canary'
      )
    )
  })
  expect(failedAdapter).toHaveBeenCalledTimes(1)
  expect(result.current.error).toMatchObject({
    code: 'SECURITY_VERIFICATION_FAILED',
    status: 403,
  })
  expect(result.current.verificationDialogProps.state.phase).toBe('idle')
  expectNoAccountSecrets(
    [
      result.current.error,
      result.current.verificationDialogProps.state,
      ...client
        .getMutationCache()
        .getAll()
        .map((item) => item.state),
      ...client
        .getQueryCache()
        .getAll()
        .map((item) => item.state),
    ],
    failure.originals,
    failure.secrets
  )
})

it.each(['requirements', 'factor', 'initialPassword'] as const)(
  'projects untrusted %s failures before any account verification state retains them',
  async (stage) => {
    signInAccountFixture()
    const failure = accountFailureAdapter(403, {
      success: false,
      code: 'UNKNOWN_ACCOUNT_FAILURE',
      message: 'Untrusted s1-password-canary',
      message_key: 'Audit failure {{password}}',
    })
    const failedAdapter = failure.adapter
    const methods = vi.fn()
    api.defaults.adapter = async (config) => {
      if (stage !== 'requirements' && config.url === '/api/verify/methods') {
        methods()
        return {
          data: {
            success: true,
            data: {
              scope: 'session.revoke',
              methods: [
                {
                  method: stage === 'initialPassword' ? 'password' : '2fa',
                  available: true,
                },
              ],
              oauth_providers: [],
              password_encryption_enabled: false,
            },
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }
      }
      return failedAdapter(config)
    }
    const states: unknown[] = []
    const { result } = renderHook(() => {
      const security = useAccountSecurity()
      states.push(security.verificationDialogProps.state)
      return security
    })
    const mutation = client.getMutationCache().build(client, {
      mutationFn: () =>
        result.current.run(
          (signal) =>
            result.current.verify(
              { scope: 'session.revoke', context: { sid: 'other-session' } },
              signal,
              stage === 'initialPassword'
                ? 's1-original-password-canary'
                : undefined
            ),
          { throwOnError: true }
        ),
      retry: false,
    })
    let operation: Promise<unknown> | undefined
    act(() => {
      operation = mutation.execute(undefined).catch((error) => error)
    })
    if (stage === 'factor') {
      await waitFor(() =>
        expect(result.current.verificationDialogProps.state.phase).toBe('ready')
      )
      act(() =>
        result.current.verificationDialogProps.onInputChange({
          method: '2fa',
          code: '123456',
        })
      )
      await act(async () => {
        await result.current.verificationDialogProps.onVerify()
      })
    }
    if (stage === 'initialPassword') {
      await act(async () => {
        await operation
      })
      expect(mutation.state.status).toBe('error')
      expect(result.current.error?.message).toBe('Request failed')
    } else {
      await waitFor(() =>
        expect(result.current.verificationDialogProps.state).toHaveProperty(
          'error',
          'Request failed'
        )
      )
      expect(mutation.state.status).toBe('pending')
    }
    expect(failedAdapter).toHaveBeenCalledTimes(1)
    if (stage === 'requirements') {
      act(() => result.current.verificationDialogProps.onRetry())
      await waitFor(() => expect(failedAdapter).toHaveBeenCalledTimes(2))
      await waitFor(() =>
        expect(result.current.verificationDialogProps.state).toHaveProperty(
          'error',
          'Request failed'
        )
      )
    }
    expectNoAccountSecrets(
      [
        states,
        result.current.error,
        result.current.verificationDialogProps.state,
        ...client
          .getMutationCache()
          .getAll()
          .map((item) => item.state),
        ...client
          .getQueryCache()
          .getAll()
          .map((item) => item.state),
      ],
      failure.originals,
      failure.secrets
    )
    const staleRetry = result.current.verificationDialogProps.onRetry
    const calls = vi.mocked(failedAdapter).mock.calls.length
    act(() => result.current.cancel())
    act(() => staleRetry())
    await act(async () => {
      await operation
    })
    expect(result.current.verificationDialogProps.state.phase).toBe('idle')
    expect(failedAdapter).toHaveBeenCalledTimes(calls)
    expect(methods).toHaveBeenCalledTimes(stage === 'requirements' ? 0 : 1)
    expectNoAccountSecrets(
      [
        states,
        result.current.error,
        ...client
          .getMutationCache()
          .getAll()
          .map((item) => item.state),
        ...client
          .getQueryCache()
          .getAll()
          .map((item) => item.state),
      ],
      failure.originals,
      failure.secrets
    )
    expect(useAuthStore.getState().auth.accessToken).toBe('s1-bearer-canary')
  }
)

it.each([
  { stage: 'requirements', change: 'cancel' },
  { stage: 'factor', change: 'actor' },
  { stage: 'factor', change: 'sid' },
  { stage: 'requirements', change: 'unmount' },
] as const)(
  'discards late untrusted $stage errors after $change without reviving the ceremony',
  async ({ stage, change }) => {
    signInAccountFixture()
    const failure = accountFailureAdapter(403, {
      success: false,
      code: 'UNKNOWN_ACCOUNT_FAILURE',
      message_key: 'Audit failure {{password}}',
    })
    const failedAdapter = failure.adapter
    let release: (() => void) | undefined
    let delivered: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const delivery = new Promise<void>((resolve) => {
      delivered = resolve
    })
    const started = vi.fn()
    api.defaults.adapter = async (config) => {
      if (stage === 'factor' && config.url === '/api/verify/methods') {
        return {
          data: {
            success: true,
            data: {
              scope: 'session.revoke',
              methods: [{ method: '2fa', available: true }],
              oauth_providers: [],
              password_encryption_enabled: false,
            },
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }
      }
      started()
      await gate
      try {
        return await failedAdapter(config)
      } finally {
        delivered?.()
      }
    }
    const states: unknown[] = []
    const view = renderHook(() => {
      const security = useAccountSecurity()
      states.push(security.verificationDialogProps.state)
      return security
    })
    const write = vi.fn()
    const mutation = client.getMutationCache().build(client, {
      mutationFn: () =>
        view.result.current.run(
          async (signal) => {
            await view.result.current.verify(
              { scope: 'session.revoke', context: { sid: 'other-session' } },
              signal
            )
            write()
          },
          { throwOnError: true }
        ),
      retry: false,
    })
    let operation: Promise<unknown> | undefined
    let verification: Promise<void> | undefined
    act(() => {
      operation = mutation.execute(undefined).catch((error) => error)
    })
    if (stage === 'factor') {
      await waitFor(() =>
        expect(view.result.current.verificationDialogProps.state.phase).toBe(
          'ready'
        )
      )
      act(() =>
        view.result.current.verificationDialogProps.onInputChange({
          method: '2fa',
          code: '123456',
        })
      )
      act(() => {
        verification = view.result.current.verificationDialogProps.onVerify()
      })
    }
    await waitFor(() => expect(started).toHaveBeenCalledTimes(1))
    if (change === 'unmount') view.unmount()
    else if (change === 'cancel') act(() => view.result.current.cancel())
    else {
      const auth = useAuthStore.getState().auth
      const { user, session, accessExpiresAt } = auth
      if (!user || !session || typeof accessExpiresAt !== 'number') {
        throw new Error('Missing account fixture')
      }
      act(() =>
        auth.setBundle({
          access_token: 'replacement-access',
          token_type: 'Bearer',
          access_expires_at: accessExpiresAt,
          user: { ...user, id: change === 'actor' ? 2 : user.id },
          session: {
            ...session,
            sid: change === 'sid' ? 'replacement-session' : session.sid,
          },
        })
      )
    }
    await act(async () => {
      release?.()
      await delivery
      await verification
      await operation
    })
    expect(mutation.state.status).toBe('error')
    expect(mutation.state.error).toMatchObject({ code: 'AUTH_CANCELLED' })
    expect(write).not.toHaveBeenCalled()
    expect(failedAdapter).toHaveBeenCalledTimes(1)
    expectNoAccountSecrets(
      [
        states,
        view.result.current.error,
        ...client
          .getMutationCache()
          .getAll()
          .map((item) => item.state),
        ...client
          .getQueryCache()
          .getAll()
          .map((item) => item.state),
      ],
      failure.originals,
      failure.secrets
    )
  }
)

it('requires verification after username confirmation and cancels without deleting the account', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.delete',
        methods: [{ method: '2fa', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const remove = vi.spyOn(api, 'delete').mockResolvedValue({
    data: { success: true, data: {} },
  })
  const user = userEvent.setup()
  render(<DeleteAccountDialog open username='user' onOpenChange={vi.fn()} />)
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled()
  await user.type(screen.getByRole('textbox'), 'user')
  await user.click(screen.getByRole('button', { name: 'Delete Account' }))
  expect(
    await screen.findByRole('textbox', {
      name: 'Authenticator code or backup code',
    })
  ).toBeVisible()
  expect(remove).not.toHaveBeenCalled()
  await user.keyboard('{Escape}')
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Delete Account' })).toBeVisible()
  )
  expect(remove).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

it.each(['2fa', 'passkey'])(
  'deletes the account only after %s verification and clears authentication',
  async (method) => {
    useAuthStore.getState().auth.setUser({ id: 1, username: 'user', role: 1 })
    vi.stubGlobal('PublicKeyCredential', class {})
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockResolvedValue({
          id: 'passkey',
          rawId: new ArrayBuffer(1),
          type: 'public-key',
          response: {
            authenticatorData: new ArrayBuffer(1),
            clientDataJSON: new ArrayBuffer(1),
            signature: new ArrayBuffer(1),
            userHandle: null,
          },
          getClientExtensionResults: () => ({}),
        }),
      },
    })
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          scope: 'account.delete',
          methods: [
            { method: '2fa', available: true },
            { method: 'passkey', available: true },
          ],
          oauth_providers: [],
          password_encryption_enabled: false,
        },
      },
    })
    const post = vi.spyOn(api, 'post').mockImplementation(async (url) => {
      if (url === '/api/user/passkey/verify/begin') {
        return {
          data: {
            success: true,
            data: {
              flow_token: 'passkey-flow',
              options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
            },
          },
        }
      }
      return {
        data: {
          success: true,
          data: {
            proof_token: 'delete-proof',
            scope: 'account.delete',
            method,
            expires_at: Math.floor(Date.now() / 1000) + 60,
          },
        },
      }
    })
    const remove = vi
      .spyOn(api, 'delete')
      .mockResolvedValue({ data: { success: true, data: {} } })
    const close = vi.fn()
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={client}>
        <DeleteAccountDialog open username='user' onOpenChange={close} />
      </QueryClientProvider>
    )
    await user.type(screen.getByRole('textbox'), 'user')
    await user.click(screen.getByRole('button', { name: 'Delete Account' }))
    expect(await screen.findByRole('tab', { name: 'Passkey' })).toHaveAttribute(
      'aria-selected',
      'true'
    )
    if (method === '2fa') {
      await user.click(screen.getByRole('tab', { name: 'Authenticator code' }))
      await user.type(
        screen.getByRole('textbox', {
          name: 'Authenticator code or backup code',
        }),
        '123456'
      )
    }
    expect(remove).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({ to: '/sign-in' })
    )
    expect(remove).toHaveBeenCalledExactlyOnceWith(
      '/api/user/self',
      expect.objectContaining({
        headers: { 'X-Security-Proof': 'delete-proof' },
        singleUseAuthorization: true,
        signal: expect.any(AbortSignal),
      })
    )
    expect(close).toHaveBeenCalledWith(false)
    expect(useAuthStore.getState().auth.user).toBeNull()
    expect(post.mock.calls.map(([url]) => url)).not.toContain(
      '/api/user/logout'
    )
  }
)

it.each(['unmount', 'account change'])(
  'ignores a late deletion response after %s and prevents duplicate requests',
  async (reason) => {
    useAuthStore.getState().auth.setUser({ id: 1, username: 'user', role: 1 })
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          scope: 'account.delete',
          methods: [{ method: 'password', available: true }],
          oauth_providers: [],
          password_encryption_enabled: false,
        },
      },
    })
    vi.spyOn(api, 'post').mockResolvedValue({
      data: {
        success: true,
        data: {
          scope: 'account.delete',
          method: 'password',
          proof_token: 'delete-proof',
          expires_at: Math.floor(Date.now() / 1000) + 60,
        },
      },
    })
    const response = { data: { success: true, data: {} } }
    let resolveDeletion!: (result: typeof response) => void
    const remove = vi.spyOn(api, 'delete').mockReturnValue(
      new Promise<typeof response>((resolve) => {
        resolveDeletion = resolve
      })
    )
    const user = userEvent.setup()
    const view = render(
      <DeleteAccountDialog open username='user' onOpenChange={vi.fn()} />
    )
    await user.type(screen.getByRole('textbox'), 'user')
    await user.click(screen.getByRole('button', { name: 'Delete Account' }))
    await user.type(
      await screen.findByLabelText('Password', { selector: 'input' }),
      'account-password'
    )
    await user.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => expect(remove).toHaveBeenCalledOnce())
    const submit = await screen.findByRole('button', { name: 'Deleting...' })
    expect(submit).toBeDisabled()
    await user.dblClick(submit)
    if (reason === 'unmount') {
      view.unmount()
    } else {
      act(() =>
        useAuthStore
          .getState()
          .auth.setUser({ id: 2, username: 'second-user', role: 1 })
      )
      expect(screen.getByRole('textbox')).toHaveValue('')
    }
    expect(remove.mock.calls[0][1]?.signal?.aborted).toBe(true)
    await act(async () => resolveDeletion(response))
    expect(remove).toHaveBeenCalledOnce()
    expect(navigate).not.toHaveBeenCalled()
    expect(useAuthStore.getState().auth.user?.id).toBe(
      reason === 'unmount' ? 1 : 2
    )
  }
)

it('disables 2FA through a Passkey proof without asking for an authenticator code', async () => {
  vi.stubGlobal('PublicKeyCredential', class {})
  const credential = {
    id: 'passkey',
    rawId: new ArrayBuffer(1),
    type: 'public-key',
    response: {
      authenticatorData: new ArrayBuffer(1),
      clientDataJSON: new ArrayBuffer(1),
      signature: new ArrayBuffer(1),
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
  }
  vi.stubGlobal('navigator', {
    credentials: { get: vi.fn().mockResolvedValue(credential) },
  })
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: '2fa.disable',
        methods: [
          { method: '2fa', available: true },
          { method: 'passkey', available: true },
        ],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const post = vi.spyOn(api, 'post').mockImplementation(async (url) => {
    if (url === '/api/user/passkey/verify/begin') {
      return {
        data: {
          success: true,
          data: {
            flow_token: 'passkey-flow',
            options: { publicKey: { challenge: 'Y2hhbGxlbmdl' } },
          },
        },
      }
    }
    if (url === '/api/user/passkey/verify/finish') {
      return {
        data: {
          success: true,
          data: {
            proof_token: 'disable-proof',
            scope: '2fa.disable',
            method: 'passkey',
            expires_at: Math.floor(Date.now() / 1000) + 60,
          },
        },
      }
    }
    return { data: { success: true, data: {} } }
  })
  const close = vi.fn()
  const success = vi.fn()
  const user = userEvent.setup()
  render(
    <QueryClientProvider client={client}>
      <TwoFADisableDialog open onOpenChange={close} onSuccess={success} />
    </QueryClientProvider>
  )
  await user.click(screen.getByRole('checkbox'))
  await user.click(screen.getByRole('button', { name: 'Disable 2FA' }))
  expect(await screen.findByRole('tab', { name: 'Passkey' })).toHaveAttribute(
    'aria-selected',
    'true'
  )
  expect(
    screen.queryByLabelText('Authenticator code or backup code')
  ).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  await waitFor(() => expect(success).toHaveBeenCalledTimes(1))
  expect(post).toHaveBeenLastCalledWith(
    '/api/user/2fa/disable',
    {},
    expect.objectContaining({
      headers: { 'X-Security-Proof': 'disable-proof' },
      signal: expect.any(AbortSignal),
      acceptAuthRotation: true,
    })
  )
  expect(close).toHaveBeenCalledWith(false)
})

it('regenerates backup codes through scoped verification and keeps the result visible until dismissed', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: '2fa.backup_codes.regenerate',
        methods: [{ method: '2fa', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const post = vi.spyOn(api, 'post').mockImplementation(async (url) => {
    if (url === '/api/verify') {
      return {
        data: {
          success: true,
          data: {
            proof_token: 'backup-proof',
            scope: '2fa.backup_codes.regenerate',
            method: '2fa',
            expires_at: Math.floor(Date.now() / 1000) + 60,
          },
        },
      }
    }
    return {
      data: {
        success: true,
        data: { backup_codes: ['ABCD-1234', 'EFGH-5678'] },
      },
    }
  })
  const close = vi.fn()
  const success = vi.fn()
  const user = userEvent.setup()
  render(<TwoFABackupDialog open onOpenChange={close} onSuccess={success} />)
  await user.click(screen.getByRole('button', { name: 'Generate New Codes' }))
  const input = await screen.findByRole('textbox', {
    name: 'Authenticator code',
  })
  expect(input).toHaveAttribute('maxlength', '6')
  expect(
    screen.queryByLabelText('Authenticator code or backup code')
  ).not.toBeInTheDocument()
  await user.type(input, '123456')
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  expect(await screen.findByText('ABCD-1234')).toBeVisible()
  expect(
    screen.getByRole('button', { name: 'Copy all backup codes' })
  ).toBeEnabled()
  expect(post).toHaveBeenLastCalledWith(
    '/api/user/2fa/backup_codes',
    {},
    expect.objectContaining({
      headers: { 'X-Security-Proof': 'backup-proof' },
      acceptAuthRotation: true,
    })
  )
  expect(success).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Done' }))
  expect(close).toHaveBeenCalledWith(false)
  expect(success).toHaveBeenCalledTimes(1)
})

it('allows a common new password after verifying the current password once', async () => {
  const get = vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.password.change',
        methods: [{ method: 'password', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.password.change',
        method: 'password',
        proof_token: 'password-proof',
        expires_at: Math.floor(Date.now() / 1000) + 60,
      },
    },
  })
  const put = vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, data: { has_password: true } },
  })
  const user = userEvent.setup()
  const onOpenChange = vi.fn()
  render(
    <ChangePasswordDialog open username='user' onOpenChange={onOpenChange} />
  )
  expect(screen.getByText('Use 8–128 characters.')).toBeVisible()
  await user.type(screen.getByLabelText('Current Password'), 'current-password')
  await user.type(screen.getByLabelText('New Password'), 'password123')
  await user.type(screen.getByLabelText('Confirm New Password'), 'password123')
  await user.click(screen.getByRole('button', { name: 'Change Password' }))
  await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  expect(get).toHaveBeenCalledWith(
    '/api/verify/methods',
    expect.objectContaining({ params: { scope: 'account.password.change' } })
  )
  expect(post).toHaveBeenCalledWith(
    '/api/verify',
    expect.objectContaining({
      method: 'password',
      password: 'current-password',
      scope: 'account.password.change',
    }),
    expect.anything()
  )
  expect(put).toHaveBeenCalledWith(
    '/api/user/self',
    expect.objectContaining({
      original_password: 'current-password',
      password: 'password123',
    }),
    expect.objectContaining({
      headers: { 'X-Security-Proof': 'password-proof' },
      singleUseAuthorization: true,
    })
  )
})

it.each(['button', 'escape'])(
  'cancels additional verification and restores focus using %s',
  async (method) => {
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          scope: 'account.password.change',
          methods: [{ method: '2fa', available: true }],
          oauth_providers: [],
          password_encryption_enabled: false,
        },
      },
    })
    const put = vi
      .spyOn(api, 'put')
      .mockResolvedValue({ data: { success: true } })
    const user = userEvent.setup()
    render(<ChangePasswordDialog open username='user' onOpenChange={vi.fn()} />)
    await user.type(
      screen.getByLabelText('Current Password'),
      'current-password'
    )
    await user.type(
      screen.getByLabelText('New Password'),
      'account-password!42'
    )
    await user.type(
      screen.getByLabelText('Confirm New Password'),
      'account-password!42'
    )
    await user.click(screen.getByRole('button', { name: 'Change Password' }))
    const verification = await screen.findByRole('dialog', {
      name: 'Security verification',
    })
    if (method === 'button') {
      await user.click(
        within(verification).getByRole('button', { name: 'Cancel' })
      )
    } else {
      await user.keyboard('{Escape}')
    }
    expect(await screen.findByLabelText('Current Password')).toBeVisible()
    await waitFor(() =>
      expect(
        screen.getByRole('dialog', { name: 'Change Password' })
      ).toContainElement(document.activeElement as HTMLElement)
    )
    expect(put).not.toHaveBeenCalled()
  }
)

it.each(['unmount', 'account change'])(
  'aborts a pending password operation on %s without duplicate submission',
  async (reason) => {
    useAuthStore
      .getState()
      .auth.setUser({ id: 1, username: 'first-user', role: 1 })
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          scope: 'account.password.change',
          methods: [{ method: 'password', available: true }],
          oauth_providers: [],
          password_encryption_enabled: false,
        },
      },
    })
    const proofResponse = {
      data: {
        success: true,
        data: {
          scope: 'account.password.change',
          method: 'password',
          proof_token: 'pending-proof',
          expires_at: Math.floor(Date.now() / 1000) + 60,
        },
      },
    }
    let resolveProof!: (response: typeof proofResponse) => void
    const pending = new Promise<typeof proofResponse>((resolve) => {
      resolveProof = resolve
    })
    const post = vi.spyOn(api, 'post').mockReturnValue(pending)
    const put = vi
      .spyOn(api, 'put')
      .mockResolvedValue({ data: { success: true, data: {} } })
    const user = userEvent.setup()
    const view = render(
      <ChangePasswordDialog open username='user' onOpenChange={vi.fn()} />
    )
    await user.type(
      screen.getByLabelText('Current Password'),
      'current-password'
    )
    await user.type(
      screen.getByLabelText('New Password'),
      'account-password!42'
    )
    await user.type(
      screen.getByLabelText('Confirm New Password'),
      'account-password!42'
    )
    const submit = screen.getByRole('button', { name: 'Change Password' })
    await user.click(submit)
    await waitFor(() => expect(post).toHaveBeenCalledOnce())
    expect(submit).toBeDisabled()
    await user.dblClick(submit)
    if (reason === 'unmount') {
      view.unmount()
    } else {
      act(() =>
        useAuthStore
          .getState()
          .auth.setUser({ id: 2, username: 'second-user', role: 1 })
      )
      expect(screen.getByLabelText('Current Password')).toHaveValue('')
      expect(screen.getByLabelText('New Password')).toHaveValue('')
    }
    expect(post.mock.calls[0][2]?.signal?.aborted).toBe(true)
    await act(async () => {
      resolveProof(proofResponse)
    })
    expect(post).toHaveBeenCalledOnce()
    expect(put).not.toHaveBeenCalled()
  }
)

it('sets a first password after verifying an existing factor without asking for a current password', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.password.set',
        methods: [{ method: '2fa', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.password.set',
        method: '2fa',
        proof_token: 'first-password-proof',
        expires_at: Math.floor(Date.now() / 1000) + 60,
      },
    },
  })
  const put = vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, data: { has_password: true } },
  })
  const user = userEvent.setup()
  render(
    <ChangePasswordDialog
      open
      username='user'
      hasPassword={false}
      onOpenChange={vi.fn()}
    />
  )
  expect(screen.queryByLabelText('Current Password')).not.toBeInTheDocument()
  await user.type(
    screen.getByLabelText('New Password'),
    'first-account-password!42'
  )
  await user.type(
    screen.getByLabelText('Confirm New Password'),
    'first-account-password!42'
  )
  await user.click(screen.getByRole('button', { name: 'Set Password' }))
  await user.type(
    await screen.findByLabelText('Authenticator code or backup code', {
      selector: 'input',
    }),
    '123456'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
  expect(post).toHaveBeenCalledTimes(1)
  expect(put.mock.calls[0][1]).toEqual({
    password: 'first-account-password!42',
  })
})

it('confirms both email addresses after identity verification and freezes the submitted address', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'account.binding.bind',
        methods: [{ method: 'password', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const post = vi.spyOn(api, 'post').mockImplementation(async (url) => {
    if (url === '/api/verify') {
      return {
        data: {
          success: true,
          data: {
            scope: 'account.binding.bind',
            method: 'password',
            proof_token: 'email-proof',
            expires_at: Math.floor(Date.now() / 1000) + 60,
          },
        },
      }
    }
    if (url === '/api/oauth/email/bind/start') {
      return {
        data: {
          success: true,
          data: {
            flow_token: 'email-flow',
            email: 'new@example.com',
            current_email: 'o***@example.com',
            old_email_required: true,
            expires_at: Math.floor(Date.now() / 1000) + 600,
            resend_at: Math.floor(Date.now() / 1000) + 60,
          },
        },
      }
    }
    return { data: { success: true, data: {} } }
  })
  const onSuccess = vi.fn()
  const user = userEvent.setup()
  render(
    <EmailBindDialog
      open
      currentEmail='old@example.com'
      onOpenChange={vi.fn()}
      onSuccess={onSuccess}
    />
  )
  await user.type(screen.getByLabelText('Email Address'), 'new@example.com')
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  await user.type(
    await screen.findByLabelText('Password', { selector: 'input' }),
    'current-password'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  expect(await screen.findByLabelText('Email Address')).toBeDisabled()
  await user.type(
    await screen.findByLabelText('New email verification code'),
    '123456'
  )
  await user.type(
    screen.getByLabelText('Current email verification code'),
    '654321'
  )
  await user.click(screen.getByRole('button', { name: 'Confirm email' }))
  await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
  expect(post).toHaveBeenCalledWith(
    '/api/oauth/email/bind',
    { flow_token: 'email-flow', new_code: '123456', old_code: '654321' },
    expect.objectContaining({ singleUseAuthorization: true })
  )
})

it('translates the delete confirmation as a sentence and preserves the literal username on language change', async () => {
  const i18n = createInstance()
  await i18n.use(initReactI18next).init({
    lng: 'zh',
    fallbackLng: false,
    nsSeparator: false,
    resources: { en, zh },
    interpolation: { escapeValue: false },
  })
  const username = 'admin <b>name</b>'
  render(
    <I18nextProvider i18n={i18n}>
      <DeleteAccountDialog open username={username} onOpenChange={vi.fn()} />
    </I18nextProvider>
  )
  expect(
    screen.getByRole('textbox', { name: `输入 ${username} 以确认` })
  ).toBeVisible()
  await act(() => i18n.changeLanguage('en'))
  expect(
    screen.getByRole('textbox', { name: `Type ${username} to confirm` })
  ).toBeVisible()
  expect(screen.getByRole('button', { name: 'Delete Account' })).toBeDisabled()
})

it('shows complete translated 2FA step descriptions and updates every step on language change', async () => {
  const i18n = createInstance()
  await i18n.use(initReactI18next).init({
    lng: 'zh',
    fallbackLng: false,
    nsSeparator: false,
    resources: { en, zh },
    interpolation: { escapeValue: false },
  })
  const user = userEvent.setup()
  render(
    <I18nextProvider i18n={i18n}>
      <TwoFASetupDialog
        open
        setupData={{
          secret: 'EXAMPLE',
          qr_code_data: 'otpauth://totp/example',
          backup_codes: ['EXAMPLE-CODE'],
          flow_token: 'example-flow',
          expires_at: 1234567890,
        }}
        loading={false}
        initializing={false}
        onCancel={vi.fn()}
        onEnable={vi.fn()}
      />
    </I18nextProvider>
  )
  const descriptions = [
    ['第 1 步，共 3 步：扫描二维码', 'Step 1 of 3: Scan QR Code'],
    ['第 2 步，共 3 步：保存备份代码', 'Step 2 of 3: Save Backup Codes'],
    ['第 3 步，共 3 步：验证设置', 'Step 3 of 3: Verify Setup'],
  ]
  for (const [chinese, english] of descriptions) {
    await act(() => i18n.changeLanguage('zh'))
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription(chinese)
    await act(() => i18n.changeLanguage('en'))
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription(english)
    const next = screen.queryByRole('button', { name: 'Next' })
    if (next) await user.click(next)
  }
})

it('rejects an old session intent after the real asynchronous header turn even without React cancellation', async () => {
  signInAccountFixture()
  const failure = accountFailureAdapter(503, {
    success: false,
    code: 'AUTH_SESSION_REVOCATION_PENDING',
  })
  const previous = useAuthStore.getState().auth
  const { accessExpiresAt, session: previousSession } = previous
  if (!previousSession || typeof accessExpiresAt !== 'number') {
    throw new Error('Missing signed-in account fixture')
  }
  const request = revokeLoginSession(
    'other-session',
    's1-proof-canary',
    new AbortController().signal
  )
  queueMicrotask(() => {
    useAuthStore.getState().auth.setBundle({
      access_token: 'replacement-access',
      token_type: 'Bearer',
      access_expires_at: accessExpiresAt,
      user: { id: 2, username: 'replacement', role: 1 },
      session: { ...previousSession, sid: 'replacement-session' },
    })
  })
  await expect(request).rejects.toMatchObject({ code: 'AUTH_CANCELLED' })
  expect(failure.adapter).not.toHaveBeenCalled()
})

it('keeps the real session card mutation and every retained cache state free of pending Axios credentials', async () => {
  signInAccountFixture()
  const session = useAuthStore.getState().auth.session
  if (!session) throw new Error('Missing signed-in account fixture')
  const failure = accountFailureAdapter(503, {
    success: false,
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    data: {
      session_revocation_complete: false,
      credential_change_committed: false,
      revoked_count: 0,
    },
  })
  const failedAdapter = failure.adapter
  api.defaults.adapter = async (config) => {
    let data: unknown
    if (config.url === '/api/user/sessions') {
      data = [session, { ...session, sid: 'other-session', current: false }]
    } else if (config.url === '/api/verify/methods') {
      data = {
        scope: 'session.revoke_others',
        methods: [{ method: '2fa', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      }
    } else if (config.url === '/api/verify') {
      data = {
        scope: 'session.revoke_others',
        method: '2fa',
        proof_token: 's1-proof-canary',
        expires_at: Math.floor(Date.now() / 1000) + 60,
      }
    } else return failedAdapter(config)
    return {
      data: { success: true, data },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }
  }
  const user = userEvent.setup()
  render(
    <QueryClientProvider client={client}>
      <LoginSessionsCard />
    </QueryClientProvider>
  )
  await user.click(
    await screen.findByRole('button', {
      name: 'Sign out other sessions',
    })
  )
  await user.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Sign out others',
    })
  )
  await user.type(
    await screen.findByLabelText('Authenticator code or backup code', {
      selector: 'input',
    }),
    '123456'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  await waitFor(() =>
    expect(client.getMutationCache().getAll()[0].state.status).toBe('error')
  )
  expect(client.getMutationCache().getAll()[0].state.error).toMatchObject({
    code: 'AUTH_SESSION_REVOCATION_PENDING',
    credential_change_committed: false,
    revoked_count: 0,
  })
  expectNoAccountSecrets(
    [
      ...client
        .getMutationCache()
        .getAll()
        .map((item) => item.state),
      ...client
        .getQueryCache()
        .getAll()
        .map((item) => item.state),
    ],
    failure.originals,
    failure.secrets
  )
  expect(failedAdapter).toHaveBeenCalledTimes(1)
})
