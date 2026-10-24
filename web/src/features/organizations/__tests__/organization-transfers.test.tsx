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
  focusManager,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AxiosError,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import { createInstance, type i18n } from 'i18next'
import { I18nextProvider } from 'react-i18next'
import { afterEach, beforeEach, expect, test } from 'vitest'

import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

import { getMyOrganizationTransfers, OrganizationRequestFailure } from '../api'
import { OrganizationTransfersCard } from '../organization-transfers-card'

const originalAdapter = api.defaults.adapter
let client: QueryClient
let language: i18n
let calls: InternalAxiosRequestConfig[]
let handler: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>

function login(id: number, sid = `session-${id}`) {
  useAuthStore.getState().auth.setBundle({
    user: { id, username: `user-${id}`, role: 1 },
    access_token: `fixture-${id}`,
    token_type: 'Bearer',
    access_expires_at: 1900000000,
    session: {
      sid,
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: 1900000000,
    },
  })
}
function response(
  config: InternalAxiosRequestConfig,
  data: unknown,
  status = 200
): AxiosResponse {
  const result = {
    data,
    status,
    statusText: String(status),
    headers: {},
    config,
  }
  if (status >= 400) {
    throw new AxiosError(
      'secret fixture response',
      undefined,
      config,
      undefined,
      result
    )
  }
  return result
}
function transfer(objectId = '9007199254740993', target = '1') {
  return {
    organization_id: '9007199254740997',
    organization_name: '<script>Transfer A</script>',
    organization_revision: '9007199254740995',
    object_id: objectId,
    generation: '1',
    kind: 'transfer',
    target_user_id: target,
    status: 'pending',
    expires_at: 1900000000,
  }
}
function page(items = [transfer()], next: string | null = null) {
  return { success: true, data: { items, limit: 20, next_after_id: next } }
}
function show() {
  render(
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={client}>
        <OrganizationTransfersCard />
      </QueryClientProvider>
    </I18nextProvider>
  )
}
beforeEach(async () => {
  language = createInstance()
  await language.init({
    lng: 'en',
    fallbackLng: 'en',
    resources: { en: { translation: {} } },
    interpolation: { escapeValue: false },
  })
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  login(1)
  calls = []
  handler = async (config) => response(config, page())
  api.defaults.adapter = async (config) => {
    calls.push(config)
    return handler(config)
  }
})
afterEach(() => {
  cleanup()
  client.clear()
  focusManager.setFocused(undefined)
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset()
})

test('projects only own pending transfer data and escapes names without mutation controls', async () => {
  const raw = {
    ...transfer(),
    secret: 'not retained',
    target_username: 'not retained',
    role: null,
    from_username: 'not retained',
    reason_code: 'not retained',
  }
  handler = async (config) => response(config, page([raw]))
  const result = await getMyOrganizationTransfers(
    1,
    'session-1',
    '0',
    new AbortController().signal
  )
  expect(result.items).toEqual([transfer()])
  show()
  expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
  expect(screen.getByText('Pending')).toBeVisible()
  expect(
    screen.queryByRole('button', { name: /accept|decline|join|switch|spend/i })
  ).not.toBeInTheDocument()
  for (const call of calls) {
    expect(call.url).toBe('/api/organization-ownership-transfers')
    expect(call.method).toBe('get')
    expect(call.params).toEqual({ after_id: '0', limit: 20 })
    expect(call.data).toBeUndefined()
    expect(call.headers.has('X-Organization-Id')).toBe(false)
    expect(call.disableDuplicate).toBe(true)
    expect(call.expectedAuthIdentity).toEqual({ userId: 1, sid: 'session-1' })
  }
})

test.each([
  ['foreign target', { target_user_id: '2' }],
  ['numeric target', { target_user_id: 1 }],
  ['wrong kind', { kind: 'invitation' }],
  ['resolved', { status: 'accepted' }],
  ['empty name', { organization_name: '' }],
  ['unsafe time', { expires_at: Number.MAX_SAFE_INTEGER + 1 }],
  ['negative time', { expires_at: -1 }],
  ['fractional time', { expires_at: 1.5 }],
  ['noncanonical id', { object_id: '01' }],
  ['overflow id', { object_id: '9223372036854775808' }],
  ['newline id', { object_id: '1\n' }],
  ['missing revision', { organization_revision: null }],
])(
  'rejects %s instead of showing rows or empty success',
  async (_name, patch) => {
    handler = async (config) =>
      response(
        config,
        page([{ ...transfer(), ...patch } as ReturnType<typeof transfer>])
      )
    show()
    expect(
      await screen.findByText('Unable to load ownership transfers')
    ).toBeVisible()
    expect(
      screen.queryByText('No pending ownership transfers')
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText('<script>Transfer A</script>')
    ).not.toBeInTheDocument()
    expect(calls).toHaveLength(1)
  }
)

test('rejects malformed page, duplicate rows and nonprogressing or inconsistent cursor', async () => {
  const full = Array.from({ length: 20 }, (_, i) => transfer(String(10 + i)))
  const invalid = [
    { success: false, data: page().data },
    { success: true, data: null },
    { success: true, data: { ...page().data, limit: 100 } },
    page([transfer('10'), transfer('10')]),
    page([transfer('10'), transfer('9')]),
    page([transfer('9')]),
    page(full, '28'),
    page(full, null),
    page([], '9223372036854775808'),
  ]
  for (const value of invalid) {
    handler = async (config) => response(config, value)
    await expect(
      getMyOrganizationTransfers(
        1,
        'session-1',
        '9',
        new AbortController().signal
      )
    ).rejects.toBeInstanceOf(OrganizationRequestFailure)
  }
})

test('keyset pagination preserves IDs above 2^53 and keyboard focus across loading', async () => {
  const first = Array.from({ length: 20 }, (_, i) => ({
    ...transfer(String(9007199254740993n + BigInt(i))),
    organization_name: `Page one ${i}`,
  }))
  const last = {
    ...transfer('9007199254741013'),
    organization_name: 'Last transfer',
  }
  handler = async (config) =>
    response(
      config,
      config.params.after_id === '0'
        ? page(first, '9007199254741012')
        : page([last])
    )
  show()
  expect(await screen.findByText('Page one 0')).toBeVisible()
  const next = screen.getByRole('button', { name: 'Next' })
  next.focus()
  await userEvent.keyboard('{Enter}')
  expect(await screen.findByText('Last transfer')).toBeVisible()
  expect(next).toHaveFocus()
  expect(next).toHaveAttribute('aria-disabled', 'true')
  expect(screen.queryByText('Page one 0')).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Previous' }))
  expect(await screen.findByText('Page one 0')).toBeVisible()
  expect(calls.map((call) => call.params.after_id)).toEqual([
    '0',
    '9007199254741012',
    '0',
  ])
})

test.each(['caller abort', 'A-B-A', 'new SID'] as const)(
  'late response after %s cannot revive an invalid operation',
  async (kind) => {
    let finish!: () => void
    handler = (config) =>
      new Promise((resolve) => {
        finish = () => resolve(response(config, page()))
      })
    const abort = new AbortController()
    const pending = getMyOrganizationTransfers(
      1,
      'session-1',
      '0',
      abort.signal
    )
    const rejected = expect(pending).rejects.toMatchObject({ cancelled: true })
    await waitFor(() => expect(calls).toHaveLength(1))
    if (kind === 'caller abort') abort.abort()
    else if (kind === 'A-B-A') {
      login(2)
      login(1)
    } else login(1, 'new-session')
    finish()
    await rejected
  }
)

test('an identity or SID change hides previous rows and discards a late foreign response', async () => {
  show()
  expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
  let finish!: () => void
  handler = (config) =>
    new Promise((resolve) => {
      finish = () =>
        resolve(
          response(
            config,
            page([{ ...transfer('2', '2'), organization_name: 'Late B' }])
          )
        )
    })
  act(() => login(2))
  expect(
    screen.queryByText('<script>Transfer A</script>')
  ).not.toBeInTheDocument()
  await waitFor(() => expect(calls).toHaveLength(2))
  const lateB = finish
  handler = async (config) =>
    response(config, page([{ ...transfer(), organization_name: 'Fresh A' }]))
  act(() => login(1, 'new-session'))
  expect(await screen.findByText('Fresh A')).toBeVisible()
  await act(async () => lateB())
  expect(screen.queryByText('Late B')).not.toBeInTheDocument()
  expect(calls[2].expectedAuthIdentity).toEqual({
    userId: 1,
    sid: 'new-session',
  })
})

test('focus revalidation and failures hide previously protected rows; refresh can recover to empty', async () => {
  show()
  expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
  let finish!: () => void
  handler = (config) =>
    new Promise((resolve) => {
      finish = () =>
        resolve(response(config, { success: false, message: 'secret-body' }))
    })
  act(() => {
    focusManager.setFocused(false)
    focusManager.setFocused(true)
  })
  await waitFor(() => expect(calls).toHaveLength(2))
  await waitFor(() =>
    expect(
      screen.queryByText('<script>Transfer A</script>')
    ).not.toBeInTheDocument()
  )
  finish()
  expect(
    await screen.findByText('Unable to load ownership transfers')
  ).toBeVisible()
  expect(
    screen.queryByText('<script>Transfer A</script>')
  ).not.toBeInTheDocument()
  expect(screen.queryByText('secret-body')).not.toBeInTheDocument()
  handler = async (config) => response(config, page([]))
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  expect(
    await screen.findByText('No pending ownership transfers')
  ).toBeVisible()
})

test('HTTP failures expose only safe projected errors, with no Axios credentials in query cache', async () => {
  handler = async (config) =>
    response(
      config,
      { success: false, code: 'ORG_FORBIDDEN', message: 'secret-body' },
      403
    )
  show()
  expect(
    await screen.findByText('Unable to load ownership transfers')
  ).toBeVisible()
  const error = client.getQueryCache().getAll()[0].state.error
  expect(error).toBeInstanceOf(OrganizationRequestFailure)
  expect(error).toMatchObject({ code: 'ORG_FORBIDDEN', status: 403 })
  expect(error).not.toHaveProperty('config')
  expect(error).not.toHaveProperty('cause')
  expect(JSON.stringify(error)).not.toMatch(
    /fixture-1|secret-body|Authorization|access_token/
  )
  expect(calls).toHaveLength(1)
})

test('logout removes protected rows and does not issue an unauthenticated inbox read', async () => {
  show()
  expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
  act(() => useAuthStore.getState().auth.reset())
  expect(
    screen.queryByText('<script>Transfer A</script>')
  ).not.toBeInTheDocument()
  expect(calls).toHaveLength(1)
})

test.each([401, 403, 409, 500])(
  'HTTP %i during refresh hides old rows without retry or exposing response data',
  async (status) => {
    show()
    expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
    handler = async (config) =>
      response(config, { message: 'private failure' }, status)
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(
      await screen.findByText('Unable to load ownership transfers')
    ).toBeVisible()
    expect(
      screen.queryByText('<script>Transfer A</script>')
    ).not.toBeInTheDocument()
    expect(screen.queryByText('private failure')).not.toBeInTheDocument()
    expect(calls).toHaveLength(2)
  }
)

test('language changes update the inbox while preserving escaped organization names', async () => {
  language.addResourceBundle('zh', 'translation', {
    'Ownership transfers': '所有权转移',
    Pending: '待处理',
  })
  show()
  expect(await screen.findByText('<script>Transfer A</script>')).toBeVisible()
  await act(async () => {
    await language.changeLanguage('zh')
  })
  expect(screen.getByRole('list', { name: '所有权转移' })).toBeVisible()
  expect(screen.getByText('待处理')).toBeVisible()
  expect(screen.getByText('<script>Transfer A</script>')).toBeVisible()
})
