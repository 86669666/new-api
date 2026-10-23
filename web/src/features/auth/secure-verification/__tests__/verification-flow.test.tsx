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
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { useEffect, useState } from 'react'
import { afterEach, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'
import { AuthOperationError } from '@/lib/secure-verification'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { OAUTH_POPUP_CALLBACK_MESSAGE } from '../../constants'
import { SecureVerificationDialog } from '../components/secure-verification-dialog'
import { useSecureVerification } from '../hooks/use-secure-verification'
import type {
  RequestVerificationOptions,
  SecurityProof,
  VerificationRequirements,
} from '../types'

const originalAdapter = api.defaults.adapter

const passwordRequirements: VerificationRequirements = {
  scope: 'passkey.register',
  methods: [{ method: 'password', available: true }],
  oauth_providers: [],
  password_encryption_enabled: false,
}

const linkedAccountRequirements: VerificationRequirements = {
  scope: '2fa.setup',
  methods: [{ method: 'oauth', available: true }],
  oauth_providers: [{ slug: 'linuxdo', name: 'Linux DO' }],
  password_encryption_enabled: false,
}

function stubOAuthPopup() {
  const popup = {
    closed: false,
    location: { replace: vi.fn() },
    sessionStorage: window.sessionStorage,
    close: vi.fn(),
    postMessage: vi.fn(),
  }
  vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)
  return popup
}

function Harness(props: {
  onResult: (proof: SecurityProof | null) => void
  operation?: RequestVerificationOptions
}) {
  const verification = useSecureVerification()
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
  )
  return (
    <QueryClientProvider client={client}>
      <button
        type='button'
        onClick={async () =>
          props.onResult(
            await verification.requestVerification(
              props.operation ?? {
                scope: 'passkey.register',
              }
            )
          )
        }
      >
        Protected action
      </button>
      <SecureVerificationDialog {...verification.dialogProps} />
    </QueryClientProvider>
  )
}

function pendingResponse<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((finish) => {
    resolve = finish
  })
  return { promise, resolve }
}

afterEach(() => {
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset('idle')
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.sessionStorage.clear()
})

function LoginHarness(props: {
  onResult: (bundle: AuthBundle | null) => void
}) {
  const verification = useSecureVerification()
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
  )
  return (
    <QueryClientProvider client={client}>
      <button
        type='button'
        onClick={async () =>
          props.onResult(
            await verification.requestLoginVerification({
              require_verification: true,
              flow_token: 'pending-login',
              expires_at: Math.floor(Date.now() / 1000) + 300,
              methods: [
                { method: '2fa', available: true },
                { method: 'passkey', available: true },
              ],
            })
          )
        }
      >
        Continue sign-in
      </button>
      <SecureVerificationDialog {...verification.dialogProps} />
    </QueryClientProvider>
  )
}

it('lets a pending login switch from Passkey to 2FA without using authenticated verification endpoints', async () => {
  const get = vi
    .spyOn(api, 'get')
    .mockResolvedValue({ data: { success: true, data: {} } })
  vi.stubGlobal('PublicKeyCredential', class {})
  const bundle: AuthBundle = {
    access_token: 'verified-login',
    token_type: 'Bearer',
    access_expires_at: Math.floor(Date.now() / 1000) + 900,
    user: { id: 42, username: 'user', role: 1 },
    session: {
      sid: 'new-session',
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    },
  }
  const post = vi
    .spyOn(api, 'post')
    .mockResolvedValue({ data: { success: true, data: bundle } })
  const result = vi.fn()
  const user = userEvent.setup()
  render(<LoginHarness onResult={result} />)
  await user.click(screen.getByRole('button', { name: 'Continue sign-in' }))
  expect(await screen.findByRole('tab', { name: 'Passkey' })).toHaveAttribute(
    'aria-selected',
    'true'
  )
  expect(result).not.toHaveBeenCalled()
  await user.click(screen.getByRole('tab', { name: 'Authenticator code' }))
  await user.type(
    screen.getByLabelText('Authenticator code or backup code'),
    '123456'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  await waitFor(() => expect(result).toHaveBeenCalledExactlyOnceWith(bundle))
  expect(post).toHaveBeenCalledExactlyOnceWith(
    '/api/user/login/verify',
    { flow_token: 'pending-login', method: '2fa', code: '123456' },
    expect.objectContaining({
      skipAuthRefresh: true,
      signal: expect.any(AbortSignal),
    })
  )
  expect(get.mock.calls.every(([url]) => url === '/api/status')).toBe(true)
})

it.each(['success', 'cancel', 'retry'] as const)(
  'automatically obtains the first-enrollment session proof and handles %s',
  async (outcome) => {
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          ...passwordRequirements,
          methods: [{ method: 'session', available: true }],
        },
      },
    })
    const proof: SecurityProof = {
      proof_token: 'session-proof',
      method: 'session',
      scope: 'passkey.register',
      expires_at: Math.floor(Date.now() / 1000) + 300,
    }
    const reply = pendingResponse<{
      data: { success: boolean; data: SecurityProof }
    }>()
    const post = vi.spyOn(api, 'post').mockReturnValue(reply.promise)
    if (outcome === 'retry') {
      post.mockRejectedValueOnce(new Error('Session check failed'))
    }
    const result = vi.fn()
    const user = userEvent.setup()
    render(<Harness onResult={result} />)
    await user.click(screen.getByText('Protected action'))
    if (outcome === 'retry') {
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Session check failed'
      )
      await user.click(screen.getByRole('button', { name: 'Retry' }))
    }
    await waitFor(() =>
      expect(post).toHaveBeenCalledTimes(outcome === 'retry' ? 2 : 1)
    )
    expect(post).toHaveBeenLastCalledWith(
      '/api/verify',
      { method: 'session', scope: 'passkey.register' },
      expect.objectContaining({ signal: expect.any(AbortSignal) })
    )
    expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
    if (outcome === 'cancel') {
      await user.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(post.mock.calls[0][2]?.signal?.aborted).toBe(true)
    }
    await act(async () => {
      reply.resolve({ data: { success: true, data: proof } })
      await reply.promise
    })
    await waitFor(() =>
      expect(result).toHaveBeenCalledExactlyOnceWith(
        outcome === 'cancel' ? null : proof
      )
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  }
)

it('keeps the requested channel context fixed while verification is open', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'channel.key.read',
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
        proof_token: 'channel-proof',
        scope: 'channel.key.read',
        method: '2fa',
        expires_at: Math.floor(Date.now() / 1000) + 60,
      },
    },
  })
  const operation: RequestVerificationOptions = {
    scope: 'channel.key.read',
    context: { channel_id: 123 },
  }
  const user = userEvent.setup()
  const result = vi.fn()
  render(<Harness operation={operation} onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  await user.type(
    await screen.findByLabelText('Authenticator code or backup code'),
    '123456'
  )
  operation.context.channel_id = 456
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  await waitFor(() => expect(result).toHaveBeenCalledTimes(1))
  expect(post).toHaveBeenCalledWith(
    '/api/verify',
    {
      scope: 'channel.key.read',
      context: { channel_id: 123 },
      method: '2fa',
      code: '123456',
    },
    expect.anything()
  )
})

it('shows query errors and reloads requirements only when the user retries', async () => {
  const requests = vi
    .spyOn(api, 'get')
    .mockRejectedValueOnce(new Error('Unable to load methods'))
    .mockResolvedValue({ data: { success: true, data: passwordRequirements } })
  const result = vi.fn()
  const user = userEvent.setup()
  render(<Harness onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Unable to load methods'
  )
  expect(
    screen.queryByText('No verification method is available for this action.')
  ).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Retry' }))
  expect(
    await screen.findByLabelText('Password', { selector: 'input' })
  ).toBeVisible()
  expect(requests).toHaveBeenCalledTimes(2)
  await user.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(result).toHaveBeenCalledWith(null))
})

it('returns a proof only after successful verification and clears a rejected password', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: { success: true, data: passwordRequirements },
  })
  const proof: SecurityProof = {
    proof_token: 'proof',
    method: 'password',
    scope: 'passkey.register',
    expires_at: Math.floor(Date.now() / 1000) + 300,
  }
  const posts = vi
    .spyOn(api, 'post')
    .mockResolvedValueOnce({
      data: { success: false, message: 'Wrong password' },
    })
    .mockResolvedValueOnce({ data: { success: true, data: proof } })
  const result = vi.fn()
  const user = userEvent.setup()
  render(<Harness onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  await user.type(
    await screen.findByLabelText('Password', { selector: 'input' }),
    'incorrect'
  )
  await user.click(screen.getByRole('button', { name: 'Verify' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Wrong password')
  expect(screen.getByLabelText('Password', { selector: 'input' })).toHaveValue(
    ''
  )
  expect(result).not.toHaveBeenCalled()
  await user.type(
    screen.getByLabelText('Password', { selector: 'input' }),
    'correct'
  )
  await user.keyboard('{Enter}')
  await waitFor(() => expect(result).toHaveBeenCalledWith(proof))
  expect(posts).toHaveBeenLastCalledWith(
    '/api/verify',
    { method: 'password', scope: 'passkey.register', password: 'correct' },
    expect.objectContaining({ signal: expect.any(AbortSignal) })
  )
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('discards a late proof after cancellation and prevents a duplicate submission', async () => {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: { success: true, data: passwordRequirements },
  })
  const reply = pendingResponse<{
    data: { success: boolean; data: SecurityProof }
  }>()
  const posts = vi.spyOn(api, 'post').mockReturnValue(reply.promise)
  const result = vi.fn()
  const user = userEvent.setup()
  render(<Harness onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  await user.type(
    await screen.findByLabelText('Password', { selector: 'input' }),
    'password'
  )
  const submit = screen.getByRole('button', { name: 'Verify' })
  fireEvent.click(submit)
  fireEvent.click(submit)
  await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
  expect(submit).toBeDisabled()
  await user.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(result).toHaveBeenCalledExactlyOnceWith(null))
  await act(async () => {
    reply.resolve({
      data: {
        success: true,
        data: {
          proof_token: 'late-proof',
          method: 'password',
          scope: 'passkey.register',
          expires_at: Math.floor(Date.now() / 1000) + 300,
        },
      },
    })
    await reply.promise
  })
  expect(result).toHaveBeenCalledTimes(1)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('does not reopen after a cancelled method query finishes', async () => {
  const reply = pendingResponse<{
    data: { success: boolean; data: VerificationRequirements }
  }>()
  vi.spyOn(api, 'get').mockReturnValue(reply.promise)
  const result = vi.fn()
  const user = userEvent.setup()
  render(<Harness onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  expect(screen.getByRole('status')).toHaveTextContent(
    'Loading verification methods...'
  )
  await user.click(screen.getByRole('button', { name: 'Cancel' }))
  await act(async () => {
    reply.resolve({ data: { success: true, data: passwordRequirements } })
    await reply.promise
  })
  expect(result).toHaveBeenCalledExactlyOnceWith(null)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('keeps an enrolled Passkey unavailable when this browser cannot use it', async () => {
  vi.stubGlobal('PublicKeyCredential', undefined)
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        ...passwordRequirements,
        methods: [{ method: 'passkey', available: true }],
      },
    },
  })
  const user = userEvent.setup()
  render(<Harness onResult={vi.fn()} />)
  await user.click(screen.getByText('Protected action'))
  expect(
    await screen.findByText(
      'This device does not support Passkey verification.'
    )
  ).toBeVisible()
  expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
  expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
})

it('starts linked-account verification from the provider button without a separate Verify button', async () => {
  const popup = stubOAuthPopup()
  const proof: SecurityProof = {
    proof_token: 'oauth-proof',
    method: 'oauth',
    scope: '2fa.setup',
    expires_at: Math.floor(Date.now() / 1000) + 300,
  }
  vi.spyOn(api, 'get').mockImplementation((url) => {
    if (url === '/api/verify/methods') {
      return Promise.resolve({
        data: { success: true, data: linkedAccountRequirements },
      })
    }
    if (url === '/api/oauth/linuxdo') {
      return Promise.resolve({ data: { success: true, data: proof } })
    }
    return Promise.resolve({ data: { success: true, data: {} } })
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: {
        flow_token: 'verification-state',
        authorization_url: 'https://connect.linux.do/oauth2/authorize?s=1',
      },
    },
  })
  const result = vi.fn()
  const user = userEvent.setup()
  render(<Harness operation={{ scope: '2fa.setup' }} onResult={result} />)
  await user.click(screen.getByText('Protected action'))
  const providerButton = await screen.findByRole('button', {
    name: 'Continue with Linux DO',
  })
  expect(
    screen.queryByRole('button', { name: 'Verify' })
  ).not.toBeInTheDocument()
  expect(window.open).not.toHaveBeenCalled()
  await user.click(providerButton)
  expect(window.open).toHaveBeenCalledTimes(1)
  expect(providerButton).toBeDisabled()
  await waitFor(() =>
    expect(popup.location.replace).toHaveBeenCalledWith(
      'https://connect.linux.do/oauth2/authorize?s=1'
    )
  )
  expect(post).toHaveBeenCalledExactlyOnceWith(
    '/api/oauth/state',
    expect.objectContaining({
      provider: 'linuxdo',
      intent: 'verify',
      scope: '2fa.setup',
    }),
    expect.anything()
  )
  const event = new MessageEvent('message', {
    origin: window.location.origin,
    data: {
      type: OAUTH_POPUP_CALLBACK_MESSAGE,
      intent: 'verify',
      provider: 'linuxdo',
      state: 'verification-state',
      code: 'code',
    },
  })
  Object.defineProperty(event, 'source', { value: popup })
  window.dispatchEvent(event)
  await waitFor(() => expect(result).toHaveBeenCalledExactlyOnceWith(proof))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('verifies with the clicked provider when several linked accounts are available', async () => {
  const popup = stubOAuthPopup()
  vi.spyOn(api, 'get').mockImplementation((url) =>
    url === '/api/verify/methods'
      ? Promise.resolve({
          data: {
            success: true,
            data: {
              ...linkedAccountRequirements,
              oauth_providers: [
                { slug: 'linuxdo', name: 'Linux DO' },
                { slug: 'github', name: 'GitHub' },
              ],
            },
          },
        })
      : Promise.resolve({ data: { success: true, data: {} } })
  )
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: {
        flow_token: 'github-state',
        authorization_url: 'https://github.com/login/oauth/authorize?s=1',
      },
    },
  })
  const user = userEvent.setup()
  render(<Harness operation={{ scope: '2fa.setup' }} onResult={vi.fn()} />)
  await user.click(screen.getByText('Protected action'))
  await user.click(
    await screen.findByRole('button', { name: 'Continue with GitHub' })
  )
  await waitFor(() =>
    expect(popup.location.replace).toHaveBeenCalledWith(
      'https://github.com/login/oauth/authorize?s=1'
    )
  )
  expect(post).toHaveBeenCalledExactlyOnceWith(
    '/api/oauth/state',
    expect.objectContaining({ provider: 'github' }),
    expect.anything()
  )
  expect(
    screen.getByRole('button', { name: 'Continue with Linux DO' })
  ).toBeDisabled()
})

const orgOperation = {
  scope: 'organization.change_role',
  context: {
    schema_version: 1,
    command: {
      organization_id: '9007199254740993',
      target_user_id: '9007199254740995',
      revision: '9007199254740997',
      role: 'admin',
    },
    snapshot: {},
  },
} as const

function OrganizationHarness(props: {
  initialPassword?: string
  onFailure: (error: unknown) => void
  onResult: (proof: SecurityProof | null) => void
  onState: (state: unknown) => void
}) {
  const verification = useSecureVerification()
  const state = verification.dialogProps.state
  const onState = props.onState
  useEffect(() => onState(state), [onState, state])
  return (
    <>
      <button
        type='button'
        onClick={() =>
          void verification
            .requestVerification(orgOperation, props.initialPassword)
            .then(props.onResult, props.onFailure)
        }
      >
        Organization action
      </button>
      <SecureVerificationDialog {...verification.dialogProps} />
    </>
  )
}

function setOrganizationSession() {
  const now = Math.floor(Date.now() / 1000)
  const bundle: AuthBundle = {
    access_token: 'hook-access-canary',
    token_type: 'Bearer',
    access_expires_at: now + 600,
    user: { id: 42, username: 'user', role: 1 },
    session: {
      sid: 'hook-source-sid',
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: now - 1,
      last_active_at: now - 1,
      expires_at: now + 3600,
    },
  }
  useAuthStore.getState().auth.setBundle(bundle)
  return bundle
}

function assertSafeOrganizationState(value: unknown) {
  const pending: unknown[] = [value]
  const seen = new Set<unknown>()
  while (pending.length) {
    const item = pending.pop()
    if (typeof item === 'string') {
      for (const secret of [
        'hook-password-canary',
        'hook-access-canary',
        'hook-proof-canary',
        'hook-response-access-canary',
        '123456',
      ]) {
        expect(item).not.toContain(secret)
      }
    }
    if (
      !item ||
      (typeof item !== 'object' && typeof item !== 'function') ||
      seen.has(item)
    ) {
      continue
    }
    seen.add(item)
    for (const key of Reflect.ownKeys(item)) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key)
      if (descriptor && 'value' in descriptor) pending.push(descriptor.value)
    }
  }
}

it.each(['login', 'organization'] as const)(
  'keeps the %s error contract when an optional operation projector is supplied',
  async (kind) => {
    if (kind === 'organization') setOrganizationSession()
    const projector = vi.fn(() => new AuthOperationError('Request failed'))
    api.defaults.adapter = async (config) => {
      throw new AxiosError(
        'Existing non-account failure',
        'ERR_BAD_RESPONSE',
        config,
        undefined,
        {
          config,
          status: 403,
          statusText: 'Forbidden',
          headers: {},
          data: {
            success: false,
            code: 'UNKNOWN_NON_ACCOUNT_FAILURE',
            message: 'Existing non-account failure',
          },
        }
      )
    }
    const { result } = renderHook(() => useSecureVerification(projector))
    let operation: Promise<unknown> | undefined
    act(() => {
      operation =
        kind === 'organization'
          ? result.current.requestVerification(orgOperation)
          : result.current.requestLoginVerification({
              require_verification: true,
              flow_token: 'pending-login',
              expires_at: Math.floor(Date.now() / 1000) + 300,
              methods: [{ method: '2fa', available: true }],
            })
    })
    if (kind === 'login') {
      await waitFor(() =>
        expect(result.current.dialogProps.state.phase).toBe('ready')
      )
      act(() =>
        result.current.dialogProps.onInputChange({
          method: '2fa',
          code: '123456',
        })
      )
      await act(async () => {
        await result.current.dialogProps.onVerify()
      })
    }
    await waitFor(() =>
      expect(result.current.dialogProps.state).toHaveProperty('error')
    )
    expect(projector).not.toHaveBeenCalled()
    expect(result.current.dialogProps.state).toHaveProperty(
      'error',
      kind === 'login'
        ? 'Existing non-account failure'
        : 'Verification failed. Please try again.'
    )
    act(() => result.current.cancel())
    await expect(operation).resolves.toBeNull()
  }
)

it.each([true, false])(
  'organization hook errors expose no credential references in initial-password shortcut: %s',
  async (shortcut) => {
    setOrganizationSession()
    const failure = vi.fn()
    const state = vi.fn()
    const result = vi.fn()
    api.defaults.adapter = async (config) => {
      if (config.method === 'get') {
        return {
          config,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            success: true,
            data: {
              scope: orgOperation.scope,
              methods: [
                { method: shortcut ? 'password' : '2fa', available: true },
              ],
              oauth_providers: [],
              password_encryption_enabled: false,
            },
          },
        }
      }
      throw new AxiosError(
        'hook-password-canary',
        'ERR_BAD_REQUEST',
        config,
        { proof: 'hook-proof-canary' },
        {
          config,
          status: 403,
          statusText: 'Rejected',
          headers: {},
          data: {
            code: 'SECURITY_VERIFICATION_FAILED',
            auth_bundle: { access_token: 'hook-response-access-canary' },
          },
        }
      )
    }
    const user = userEvent.setup()
    render(
      <OrganizationHarness
        initialPassword={shortcut ? 'hook-password-canary' : undefined}
        onFailure={failure}
        onState={state}
        onResult={result}
      />
    )
    await user.click(
      screen.getByRole('button', { name: 'Organization action' })
    )
    if (shortcut) {
      await waitFor(() => expect(failure).toHaveBeenCalledTimes(1))
      expect(failure.mock.calls[0][0]).not.toHaveProperty('cause')
      assertSafeOrganizationState(failure.mock.calls[0][0])
    } else {
      const code = await screen.findByRole('textbox', {
        name: 'Authenticator code',
      })
      expect(code).toHaveAttribute('maxLength', '6')
      expect(
        screen.queryByText('Authenticator code or backup code')
      ).not.toBeInTheDocument()
      await user.type(code, 'ABCDEF')
      expect(screen.getByRole('button', { name: 'Verify' })).toBeDisabled()
      await user.clear(code)
      await user.type(code, '123456')
      await user.click(screen.getByRole('button', { name: 'Verify' }))
      await screen.findByRole('alert')
      expect(code).toHaveValue('')
      expect(failure).not.toHaveBeenCalled()
      expect(
        screen.queryByRole('tab', { name: 'Linked account' })
      ).not.toBeInTheDocument()
    }
    assertSafeOrganizationState(state.mock.calls.at(-1)?.[0])
    expect(result).not.toHaveBeenCalled()
  }
)

it('cancels an organization hook on identity change and discards a late proof without installing it', async () => {
  const bundle = setOrganizationSession()
  const result = vi.fn()
  const state = vi.fn()
  const failure = vi.fn()
  let finish!: () => void
  let started!: () => void
  const sent = new Promise<void>((resolve) => {
    started = resolve
  })
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    if (config.method === 'get') {
      return {
        config,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          success: true,
          data: {
            scope: orgOperation.scope,
            methods: [{ method: 'password', available: true }],
            oauth_providers: [],
            password_encryption_enabled: false,
          },
        },
      }
    }
    started()
    return new Promise((resolve) => {
      finish = () =>
        resolve({
          config,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            success: true,
            data: {
              proof_token: 'hook-proof-canary',
              scope: orgOperation.scope,
              method: 'password',
              expires_at: Math.floor(Date.now() / 1000) + 30,
              auth_bundle: {
                access_token: 'hook-response-access-canary',
                token_type: 'Bearer',
                access_expires_at: bundle.access_expires_at,
                session: { ...bundle.session, sid: 'returned-sid' },
              },
            },
          },
        })
    })
  }
  const user = userEvent.setup()
  render(
    <OrganizationHarness
      initialPassword='hook-password-canary'
      onFailure={failure}
      onState={state}
      onResult={result}
    />
  )
  await user.click(screen.getByRole('button', { name: 'Organization action' }))
  await sent
  act(() =>
    useAuthStore.getState().auth.setBundle({
      ...bundle,
      user: { ...bundle.user, id: 84 },
      session: { ...bundle.session, sid: 'external-sid' },
    })
  )
  await waitFor(() => expect(result).toHaveBeenCalledWith(null))
  await act(async () => {
    finish()
  })
  expect(result).toHaveBeenCalledTimes(1)
  expect(failure).not.toHaveBeenCalled()
  expect(useAuthStore.getState().auth.session?.sid).toBe('external-sid')
  assertSafeOrganizationState(state.mock.calls.at(-1)?.[0])
})
