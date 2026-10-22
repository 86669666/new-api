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
  createDecipheriv,
  generateKeyPairSync,
  privateDecrypt,
  webcrypto,
} from 'node:crypto'

import { waitFor } from '@testing-library/react'
import { AxiosError, isCancel, type InternalAxiosRequestConfig } from 'axios'
import { afterEach, expect, it, vi } from 'vitest'

import { api, organizationRequestOptions } from '@/lib/api'
import { AuthOperationError, authResult } from '@/lib/secure-verification'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { createOAuthFlow } from '../../api'
import { OAUTH_POPUP_CALLBACK_MESSAGE } from '../../constants'
import {
  clearPasswordEncryptionCache,
  encryptPassword,
} from '../../lib/password-encryption'
import { checkVerificationMethods, verify } from '../api'
import type { SecurityProof } from '../types'

const organizationOperation = {
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

function expectCredentialFree(value: unknown, secrets: string[]) {
  const pending: unknown[] = [value]
  const seen = new Set<unknown>()
  while (pending.length) {
    const item = pending.pop()
    if (typeof item === 'string') {
      for (const secret of secrets) expect(item).not.toContain(secret)
    }
    if (!item || (typeof item !== 'object' && typeof item !== 'function')) {
      continue
    }
    if (seen.has(item)) continue
    seen.add(item)
    for (const key of Reflect.ownKeys(item)) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key)
      if (descriptor && 'value' in descriptor) pending.push(descriptor.value)
    }
  }
}

const originalAdapter = api.defaults.adapter
const originalLocation = window.location.href

it('allows a security key when the browser has WebAuthn but no platform authenticator', async () => {
  vi.stubGlobal(
    'PublicKeyCredential',
    class {
      static isUserVerifyingPlatformAuthenticatorAvailable() {
        return Promise.resolve(false)
      }
    }
  )
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: {
        scope: 'passkey.delete',
        methods: [{ method: 'passkey', available: true }],
        oauth_providers: [],
        password_encryption_enabled: false,
      },
    },
  })
  const requirements = await checkVerificationMethods('passkey.delete')
  expect(requirements.methods).toEqual([{ method: 'passkey', available: true }])
})

it.each([false, true])(
  'retains the Telegram verification request after popup close and honors caller cancellation: %s',
  async (cancel) => {
    const popup = {
      closed: false,
      location: { replace: vi.fn() },
      sessionStorage: window.sessionStorage,
      close: vi.fn(),
      postMessage: vi.fn(),
    }
    vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)
    vi.spyOn(api, 'post').mockResolvedValue({
      data: {
        success: true,
        data: {
          flow_token: 'verification-state',
          authorization_url: 'https://oauth.telegram.org/auth?server=pkce',
        },
      },
    })
    const proof: SecurityProof = {
      proof_token: 'telegram-proof',
      method: 'oauth',
      scope: '2fa.setup',
      expires_at: Math.floor(Date.now() / 1000) + 300,
    }
    let resolve!: (response: {
      data: { success: boolean; data: SecurityProof }
    }) => void
    const response = new Promise<{
      data: { success: boolean; data: SecurityProof }
    }>((done) => {
      resolve = done
    })
    const get = vi
      .spyOn(api, 'get')
      .mockImplementation((url) =>
        url === '/api/status'
          ? Promise.resolve({ data: { success: true, data: {} } })
          : response
      )
    const controller = new AbortController()
    const result = verify(
      { method: 'oauth', provider: 'telegram' },
      { scope: '2fa.setup' },
      false,
      controller.signal
    )
    const outcome = cancel
      ? expect(result).rejects.toMatchObject({ code: 'AUTH_CANCELLED' })
      : expect(result).resolves.toEqual(proof)
    await waitFor(() =>
      expect(popup.location.replace).toHaveBeenCalledWith(
        'https://oauth.telegram.org/auth?server=pkce'
      )
    )
    const event = new MessageEvent('message', {
      origin: window.location.origin,
      data: {
        type: OAUTH_POPUP_CALLBACK_MESSAGE,
        intent: 'verify',
        provider: 'telegram',
        state: 'verification-state',
        code: 'code',
      },
    })
    Object.defineProperty(event, 'source', { value: popup })
    window.dispatchEvent(event)
    popup.closed = true
    await waitFor(() =>
      expect(get).toHaveBeenCalledWith(
        '/api/oauth/telegram',
        expect.objectContaining({ singleUseAuthorization: true })
      )
    )
    const signal = get.mock.calls.find(
      ([url]) => url === '/api/oauth/telegram'
    )?.[1]?.signal
    expect(signal?.aborted).toBe(false)
    if (cancel) {
      controller.abort(new AuthOperationError('Cancelled', 'AUTH_CANCELLED'))
    }
    expect(signal?.aborted).toBe(cancel)
    resolve({ data: { success: true, data: proof } })
    await outcome
  }
)
const sessionBundle = {
  access_token: 'access-token',
  token_type: 'Bearer' as const,
  access_expires_at: Math.floor(Date.now() / 1000) + 600,
  user: { id: 42, username: 'user', role: 1 },
  session: {
    sid: 'session',
    current: true,
    login_method: 'password',
    ip: '127.0.0.1',
    user_agent: 'test',
    created_at: 1,
    last_active_at: 1,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
  },
}

function mockRefreshResponse(bundle: AuthBundle, onRequest?: () => void) {
  const requests = vi.fn()
  vi.stubGlobal(
    'XMLHttpRequest',
    class {
      status = 200
      statusText = 'OK'
      readyState = 4
      responseText = JSON.stringify({ success: true, data: bundle })
      onloadend: (() => void) | null = null
      url = ''
      open(_method: string, url: string) {
        this.url = url
      }
      setRequestHeader() {}
      getAllResponseHeaders() {
        return 'content-type: application/json'
      }
      abort() {}
      send() {
        requests(this.url)
        onRequest?.()
        queueMicrotask(() => this.onloadend?.())
      }
    }
  )
  return requests
}

afterEach(() => {
  clearPasswordEncryptionCache()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset('idle')
  window.history.replaceState(null, '', originalLocation)
})

it.each([true, false])(
  'encrypts short and 128-character Unicode passwords with Web Crypto enabled: %s',
  async (useWebCrypto) => {
    vi.stubGlobal(
      'crypto',
      useWebCrypto
        ? webcrypto
        : { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) }
    )
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    })
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: {
          kid: 'test-encryption-key',
          public_key: publicKey
            .export({ type: 'spki', format: 'pem' })
            .toString(),
        },
      },
    })
    for (const password of ['legacy-password', '🔒'.repeat(128)]) {
      const encrypted = await encryptPassword(password)
      const parts = encrypted.password_encrypted.split('.')
      let decrypted: Buffer
      if (parts[0] === 'v2') {
        const key = privateDecrypt(
          {
            key: privateKey,
            oaepHash: 'sha256',
            oaepLabel: Buffer.from('password-v2'),
          },
          Buffer.from(parts[1], 'base64')
        )
        const ciphertext = Buffer.from(parts[3], 'base64')
        const decipher = createDecipheriv(
          'aes-256-gcm',
          key,
          Buffer.from(parts[2], 'base64')
        )
        decipher.setAAD(Buffer.from('password-v2:test-encryption-key'))
        decipher.setAuthTag(ciphertext.subarray(-16))
        decrypted = Buffer.concat([
          decipher.update(ciphertext.subarray(0, -16)),
          decipher.final(),
        ])
      } else {
        decrypted = privateDecrypt(
          { key: privateKey, oaepHash: 'sha256' },
          Buffer.from(encrypted.password_encrypted, 'base64')
        )
      }
      expect(decrypted.toString('utf8')).toBe(password)
    }
  }
)

it.each(['proof', 'flow'] as const)(
  'never replays a %s request after a 401 response',
  async (kind) => {
    window.history.replaceState(null, '', '/sign-in')
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const refresh = mockRefreshResponse(sessionBundle)
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError(
        'Unauthorized',
        'ERR_BAD_REQUEST',
        config,
        undefined,
        {
          status: 401,
          statusText: 'Unauthorized',
          config,
          headers: {},
          data: { code: 'AUTH_SESSION_REVOKED' },
        }
      )
    })
    api.defaults.adapter = adapter
    await expect(
      api.post(
        '/protected',
        {},
        {
          skipErrorHandler: true,
          ...(kind === 'proof'
            ? { headers: { 'X-Security-Proof': 'one-use-proof' } }
            : { singleUseAuthorization: true }),
        }
      )
    ).rejects.toThrow('Unauthorized')
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(refresh).not.toHaveBeenCalled()
  }
)

it('refreshes an expiring login token before submitting a one-time proof', async () => {
  useAuthStore.getState().auth.setBundle({
    ...sessionBundle,
    access_expires_at: Math.floor(Date.now() / 1000) + 10,
  })
  const order: string[] = []
  mockRefreshResponse({ ...sessionBundle, access_token: 'fresh-access' }, () =>
    order.push('refresh')
  )
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
    order.push('action')
    return {
      status: 200,
      statusText: 'OK',
      config,
      headers: {},
      data: { success: true },
    }
  })
  api.defaults.adapter = adapter
  await api.post(
    '/protected',
    {},
    { headers: { 'X-Security-Proof': 'one-use-proof' } }
  )
  expect(order).toEqual(['refresh', 'action'])
  expect(adapter).toHaveBeenCalledTimes(1)
  expect(adapter.mock.calls[0]?.[0].headers.Authorization).toBe(
    'Bearer fresh-access'
  )
})

it('binds a channel verification to the requested channel context', async () => {
  const proof = {
    proof_token: 'channel-proof',
    method: '2fa',
    scope: 'channel.key.read',
    expires_at: Math.floor(Date.now() / 1000) + 60,
  }
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: proof },
  })
  await expect(
    verify(
      { method: '2fa', code: '123456' },
      { scope: 'channel.key.read', context: { channel_id: 123 } },
      false,
      new AbortController().signal
    )
  ).resolves.toEqual(proof)
  expect(post).toHaveBeenCalledWith(
    '/api/verify',
    {
      method: '2fa',
      code: '123456',
      scope: 'channel.key.read',
      context: { channel_id: 123 },
    },
    expect.anything()
  )
})

it('passes the operation context to Passkey begin and completes with only its flow and assertion', async () => {
  vi.stubGlobal('navigator', {
    credentials: {
      get: vi.fn().mockResolvedValue({
        id: 'credential',
        rawId: new Uint8Array([1, 2, 3]).buffer,
        type: 'public-key',
        response: {
          clientDataJSON: new Uint8Array([1]).buffer,
          authenticatorData: new Uint8Array([2]).buffer,
          signature: new Uint8Array([3]).buffer,
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
      }),
    },
  })
  const proof = {
    proof_token: 'passkey-proof',
    scope: 'channel.key.read',
    method: 'passkey',
    expires_at: Math.floor(Date.now() / 1000) + 60,
  }
  const post = vi
    .spyOn(api, 'post')
    .mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          flow_token: 'flow',
          options: { publicKey: { challenge: 'AQID', allowCredentials: [] } },
        },
      },
    })
    .mockResolvedValueOnce({ data: { success: true, data: proof } })
  await expect(
    verify(
      { method: 'passkey' },
      { scope: 'channel.key.read', context: { channel_id: 123 } },
      false,
      new AbortController().signal
    )
  ).resolves.toEqual(proof)
  expect(post).toHaveBeenNthCalledWith(
    1,
    '/api/user/passkey/verify/begin',
    {
      scope: 'channel.key.read',
      context: { channel_id: 123 },
    },
    expect.anything()
  )
  expect(post.mock.calls[1]?.[1]).toEqual({
    flow_token: 'flow',
    credential: expect.anything(),
  })
})

it('passes an enrollment operation through OAuth state creation', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { flow_token: 'oauth-flow' } },
  })
  await expect(
    createOAuthFlow('github', 'verify', {
      scope: 'passkey.register',
      context: {},
    })
  ).resolves.toBe('oauth-flow')
  expect(post).toHaveBeenCalledWith(
    '/api/oauth/state',
    expect.objectContaining({
      provider: 'github',
      intent: 'verify',
      scope: 'passkey.register',
      context: {},
    }),
    expect.anything()
  )
})

it.each([
  [
    'SECURITY_PROOF_CONSUMED',
    'This verification has already been used. Please verify again.',
  ],
  [
    'SECURITY_PROOF_CONTEXT_MISMATCH',
    "Verification does not match this action's details. Please verify again.",
  ],
])('provides a re-verification message for %s', async (code, message) => {
  await expect(
    authResult(
      Promise.resolve({
        data: { success: false, code, message: 'untranslated backend text' },
      })
    )
  ).rejects.toMatchObject({ code, message })
})

it('reports a failed method query instead of treating the account as unenrolled', async () => {
  vi.spyOn(api, 'get').mockRejectedValue(
    new Error('Unable to load verification methods')
  )
  await expect(checkVerificationMethods('passkey.register')).rejects.toThrow(
    'Unable to load verification methods'
  )
})

it('displays a generic internal error even if the server includes database details', async () => {
  await expect(
    authResult(
      Promise.resolve({
        data: {
          success: false,
          code: 'AUTH_INTERNAL_ERROR',
          message: 'SELECT private_table at private-db-host',
        },
      })
    )
  ).rejects.toThrow('Please try again later.')
  const failure = AuthOperationError.from({
    isAxiosError: true,
    response: {
      status: 500,
      data: { message: 'SELECT private_table at private-db-host' },
    },
  })
  expect(failure.message).toBe('Please try again later.')
})

it('projects organization producer failures into fresh credential-free errors', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  const password = 'organization-password-canary'
  const responseSecret = 'organization-response-proof-canary'
  api.defaults.adapter = async (config) => {
    throw new AxiosError(
      password,
      'ERR_BAD_REQUEST',
      config,
      { secret: responseSecret },
      {
        config,
        status: 429,
        statusText: password,
        headers: { 'retry-after': '12' },
        data: {
          code: 'SECURITY_VERIFICATION_RATE_LIMITED',
          message: password,
          auth_bundle: { access_token: responseSecret },
        },
      }
    )
  }
  const error = await verify(
    { method: 'password', password },
    organizationOperation,
    false,
    new AbortController().signal
  ).catch((failure: unknown) => failure)
  expect(error).toMatchObject({
    code: 'SECURITY_VERIFICATION_RATE_LIMITED',
    status: 429,
    retryAfter: 12,
  })
  expect(error).not.toHaveProperty('cause')
  expectCredentialFree(error, [
    password,
    responseSecret,
    sessionBundle.access_token,
  ])
})

it('does not send an opt-in action after refresh replaces its expected identity', async () => {
  useAuthStore
    .getState()
    .auth.setBundle({ ...sessionBundle, access_expires_at: 1 })
  mockRefreshResponse({
    ...sessionBundle,
    user: { ...sessionBundle.user, id: 84 },
    session: { ...sessionBundle.session, sid: 'other-session' },
  })
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => ({
    config,
    status: 200,
    statusText: 'OK',
    headers: {},
    data: { success: true },
  }))
  api.defaults.adapter = adapter
  const error = await api
    .delete('/api/organizations/7/members/9', {
      data: { revision: '1' },
      singleUseAuthorization: true,
      expectedAuthIdentity: { userId: 42, sid: 'session' },
    })
    .catch((failure: unknown) => failure)
  expect(isCancel(error)).toBe(true)
  expect(adapter).not.toHaveBeenCalled()
})

function organizationResult(method: 'password' | '2fa' | 'passkey' = '2fa') {
  const now = Math.floor(Date.now() / 1000)
  return {
    proof_token: 'organization-proof-canary',
    scope: organizationOperation.scope,
    method,
    expires_at: now + 30,
    auth_bundle: {
      access_token: 'organization-new-access-canary',
      token_type: 'Bearer',
      access_expires_at: now + 600,
      session: {
        ...sessionBundle.session,
        sid: 'organization-new-sid',
        created_at: now,
        last_active_at: now,
      },
    },
  }
}

it('returns a typed organization result without automatically adopting the new SID', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  const result = organizationResult()
  const requests: InternalAxiosRequestConfig[] = []
  api.defaults.adapter = async (config) => {
    requests.push(config)
    return {
      config,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: {
        success: true,
        data: { ...result, ignored: 'not-an-error-or-state-field' },
      },
    }
  }
  const proof = await verify(
    { method: '2fa', code: '123456' },
    organizationOperation,
    false,
    new AbortController().signal
  )
  expect(proof.auth_bundle.session.sid).toBe('organization-new-sid')
  expect(proof).not.toHaveProperty('ignored')
  expect(useAuthStore.getState().auth.session?.sid).toBe('session')
  expect(JSON.parse(requests[0].data)).toEqual({
    method: '2fa',
    code: '123456',
    ...organizationOperation,
  })
  expect(requests[0]).toMatchObject({
    singleUseAuthorization: true,
    skipAuthRefresh: true,
    expectedAuthIdentity: { userId: 42, sid: 'session' },
  })
})

it.each(['password', '2fa'] as const)(
  'does not replay the organization %s producer on 401',
  async (method) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const refresh = mockRefreshResponse(sessionBundle)
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError(
        'credential-canary',
        'ERR_BAD_REQUEST',
        config,
        undefined,
        {
          config,
          status: 401,
          statusText: 'Unauthorized',
          headers: {},
          data: { code: 'AUTH_SESSION_REVOKED' },
        }
      )
    })
    api.defaults.adapter = adapter
    const error = await verify(
      method === 'password'
        ? { method, password: 'credential-canary' }
        : { method, code: '123456' },
      organizationOperation,
      false,
      new AbortController().signal
    ).catch((failure: unknown) => failure)
    expect(error).toMatchObject({ code: 'AUTH_SESSION_REVOKED', status: 401 })
    expectCredentialFree(error, [
      'credential-canary',
      '123456',
      sessionBundle.access_token,
    ])
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(refresh).not.toHaveBeenCalled()
  }
)

it.each(['post', 'patch', 'delete'] as const)(
  'the shared organization request options prevent %s replay even without proof',
  async (method) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const refresh = mockRefreshResponse(sessionBundle)
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError(
        'Unauthorized',
        'ERR_BAD_REQUEST',
        config,
        undefined,
        {
          config,
          status: 401,
          statusText: 'Unauthorized',
          headers: {},
          data: { code: 'AUTH_SESSION_REVOKED' },
        }
      )
    })
    api.defaults.adapter = adapter
    const options = organizationRequestOptions(
      { userId: 42, sid: 'session' },
      new AbortController().signal
    )
    const request =
      method === 'delete'
        ? api.delete('/organization-contract', {
            ...options,
            data: { revision: '1' },
          })
        : api[method]('/organization-contract', { revision: '1' }, options)
    await expect(request).rejects.toMatchObject({ response: { status: 401 } })
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(refresh).not.toHaveBeenCalled()
  }
)

it.each([200, 403])(
  'discards an opt-in %s response after the identity changes',
  async (status) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    api.defaults.adapter = async (config) => {
      useAuthStore.getState().auth.setBundle({
        ...sessionBundle,
        user: { ...sessionBundle.user, id: 84 },
        session: { ...sessionBundle.session, sid: 'another-sid' },
      })
      const response = {
        config,
        status,
        statusText: 'Controlled',
        headers: {},
        data: { code: 'ORG_FORBIDDEN', secret: 'response-secret-canary' },
      }
      if (status === 403) {
        throw new AxiosError(
          'response-secret-canary',
          'ERR_BAD_REQUEST',
          config,
          undefined,
          response
        )
      }
      return response
    }
    const error = await api
      .get(
        '/organization-contract',
        organizationRequestOptions({ userId: 42, sid: 'session' })
      )
      .catch((failure: unknown) => failure)
    expect(isCancel(error)).toBe(true)
    expectCredentialFree(error, [
      'response-secret-canary',
      sessionBundle.access_token,
    ])
  }
)

it.each([
  { method: 'oauth' as const, provider: 'provider-canary' },
  { method: 'session' as const },
  { method: '2fa' as const, code: 'backup-code-canary' },
  { method: '2fa' as const, code: '1234567' },
])(
  'rejects an unsupported organization verification input before transport: $method $code',
  async (input) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const adapter = vi.fn()
    api.defaults.adapter = adapter
    const error = await verify(
      input,
      organizationOperation,
      false,
      new AbortController().signal
    ).catch((failure: unknown) => failure)
    expect(error).toBeInstanceOf(AuthOperationError)
    expectCredentialFree(error, [
      'provider-canary',
      'backup-code-canary',
      '1234567',
    ])
    expect(adapter).not.toHaveBeenCalled()
  }
)

it.each(['numeric-id', 'owner-role', 'extra-field'] as const)(
  'rejects a malformed organization context before transport: %s',
  async (kind) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const operation = structuredClone(organizationOperation)
    let command: unknown = {
      ...operation.context.command,
      secret: 'context-secret-canary',
    }
    if (kind === 'numeric-id') {
      command = {
        ...operation.context.command,
        target_user_id: 9007199254740992,
      }
    } else if (kind === 'owner-role') {
      command = { ...operation.context.command, role: 'owner' }
    }
    const invalid = {
      ...operation,
      context: { ...operation.context, command },
    } as unknown as typeof organizationOperation
    const adapter = vi.fn()
    api.defaults.adapter = adapter
    const error = await verify(
      { method: 'password', password: 'password-canary' },
      invalid,
      false,
      new AbortController().signal
    ).catch((failure: unknown) => failure)
    expectCredentialFree(error, ['context-secret-canary', 'password-canary'])
    expect(adapter).not.toHaveBeenCalled()
  }
)

it.each(['wrong-scope', 'missing-bundle', 'extended-expiry'] as const)(
  'projects malformed organization result errors without rejected input: %s',
  async (kind) => {
    useAuthStore.getState().auth.setBundle(sessionBundle)
    const result = organizationResult()
    let invalid: unknown = {
      ...result,
      auth_bundle: {
        ...result.auth_bundle,
        session: {
          ...result.auth_bundle.session,
          expires_at: sessionBundle.session.expires_at + 1,
        },
      },
    }
    if (kind === 'wrong-scope') {
      invalid = { ...result, scope: 'organization.remove' }
    } else if (kind === 'missing-bundle') {
      invalid = { ...result, auth_bundle: undefined }
    }
    api.defaults.adapter = async (config) => ({
      config,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: { success: true, data: invalid },
    })
    const error = await verify(
      { method: '2fa', code: '123456' },
      organizationOperation,
      false,
      new AbortController().signal
    ).catch((failure: unknown) => failure)
    expect(error).toMatchObject({ code: 'SECURITY_PROOF_INVALID' })
    expectCredentialFree(error, [
      result.proof_token,
      result.auth_bundle.access_token,
      '123456',
      sessionBundle.access_token,
    ])
    expect(error).not.toHaveProperty('cause')
  }
)

it('keeps cancellation safe even when an abort reason contains credentials', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  const controller = new AbortController()
  controller.abort(new Error('abort-credential-canary'))
  const error = await verify(
    { method: 'password', password: 'password-canary' },
    organizationOperation,
    false,
    controller.signal
  ).catch((failure: unknown) => failure)
  expect(isCancel(error)).toBe(true)
  expect(error).toMatchObject({ cancelled: true, code: 'AUTH_CANCELLED' })
  expectCredentialFree(error, ['abort-credential-canary', 'password-canary'])
})

it('checks expected identity at the adapter boundary after request transformation', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => ({
    config,
    status: 200,
    statusText: 'OK',
    headers: {},
    data: { success: true },
  }))
  api.defaults.adapter = adapter
  const error = await api
    .post(
      '/organization-contract',
      { revision: '1' },
      {
        ...organizationRequestOptions({ userId: 42, sid: 'session' }),
        transformRequest: [
          (data) => {
            useAuthStore.getState().auth.setBundle({
              ...sessionBundle,
              user: { ...sessionBundle.user, id: 84 },
              session: { ...sessionBundle.session, sid: 'transformed-sid' },
            })
            return JSON.stringify(data)
          },
        ],
      }
    )
    .catch((failure: unknown) => failure)
  expect(isCancel(error)).toBe(true)
  expect(adapter).not.toHaveBeenCalled()
})

it('keeps the admin-removal operation bound to its exact server context', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  const operation = {
    scope: 'organization.remove',
    context: {
      schema_version: 1,
      command: {
        organization_id: '9007199254740993',
        target_user_id: '9007199254740995',
        revision: '9007199254740997',
      },
      snapshot: { target_role: 'admin' },
    },
  } as const
  api.defaults.adapter = async (config) => {
    expect(JSON.parse(config.data)).toEqual({
      method: 'password',
      password: 'organization-password-canary',
      ...operation,
    })
    return {
      config,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: {
        success: true,
        data: { ...organizationResult('password'), scope: operation.scope },
      },
    }
  }
  const proof = await verify(
    { method: 'password', password: 'organization-password-canary' },
    operation,
    false,
    new AbortController().signal
  )
  expect(proof.scope).toBe('organization.remove')
  expect(proof.auth_bundle.session.sid).toBe('organization-new-sid')
})

it('uses the existing encrypted-password producer fields for organization verification', async () => {
  useAuthStore.getState().auth.setBundle(sessionBundle)
  vi.stubGlobal('crypto', webcrypto)
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
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
            kid: 'org-encryption-key',
            public_key: publicKey
              .export({ type: 'spki', format: 'pem' })
              .toString(),
          },
        },
      }
    }
    const input = JSON.parse(config.data)
    expect(input).toMatchObject({
      scope: organizationOperation.scope,
      context: organizationOperation.context,
      method: 'password',
      encryption_key_id: 'org-encryption-key',
    })
    expect(input.password_encrypted).toEqual(expect.any(String))
    expect(input).not.toHaveProperty('password')
    expect(config.data).not.toContain('organization-password-canary')
    return {
      config,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: { success: true, data: organizationResult('password') },
    }
  }
  await expect(
    verify(
      { method: 'password', password: 'organization-password-canary' },
      organizationOperation,
      true,
      new AbortController().signal
    )
  ).resolves.toMatchObject({ method: 'password' })
})
