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

import { MyOrganizationsCard } from '../my-organizations-card'

const originalAdapter = api.defaults.adapter
let client: QueryClient
let language: i18n
let calls: InternalAxiosRequestConfig[]
let handler: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>

function login(id: number, sid = `session-${id}`, role = 1) {
  useAuthStore.getState().auth.setBundle({
    user: { id, username: `user-${id}`, role },
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
      'fixture rejected',
      undefined,
      config,
      undefined,
      result
    )
  }
  return result
}

function page(names: string[], next: string | null = null) {
  return {
    success: true,
    data: {
      items: names.map((name, index) => ({
        org_id: String(index + 1),
        name,
        my_role: ['owner', 'admin', 'member'][index % 3],
      })),
      limit: 20,
      next_after_id: next,
    },
  }
}

function show() {
  render(
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={client}>
        <MyOrganizationsCard />
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
  handler = async (config) => response(config, page(['Org A']))
  api.defaults.adapter = async (config) => {
    calls.push(config)
    return handler(config)
  }
})

afterEach(() => {
  cleanup()
  client.clear()
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset()
})

test('lists only server memberships, roles and keyset pages without a global organization selector', async () => {
  const names = [
    'Owner org',
    'Admin org',
    'Member org',
    ...Array.from({ length: 17 }, (_, i) => `Other ${i}`),
  ]
  handler = async (config) =>
    response(
      config,
      config.params.after_id === '0' ? page(names, '20') : page(['Last org'])
    )
  show()
  expect(await screen.findByText('Owner org')).toBeVisible()
  for (const role of [
    'Organization owner',
    'Organization administrator',
    'Organization member',
  ]) {
    expect(screen.getAllByText(role).length).toBeGreaterThan(0)
  }
  expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(await screen.findByText('Last org')).toBeVisible()
  expect(screen.queryByText('Owner org')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  await userEvent.click(screen.getByRole('button', { name: 'Previous' }))
  expect(await screen.findByText('Owner org')).toBeVisible()
  expect(calls.map((call) => call.params.after_id)).toEqual(['0', '20', '0'])
  for (const call of calls) {
    expect(call.url).toBe('/api/organizations')
    expect(call.params.limit).toBe(20)
    expect(call.params.org_id).toBeUndefined()
    expect(call.headers.has('X-Organization-Id')).toBe(false)
    expect(call.method).toBe('get')
    expect(call.data).toBeUndefined()
  }
})

test('a root with no memberships sees an empty member directory instead of a global directory', async () => {
  login(1, 'root-session', 100)
  handler = async (config) => response(config, page([]))
  show()
  expect(await screen.findByText('No accessible organizations')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  expect(
    screen.queryByRole('button', { name: /spend|create|switch/i })
  ).not.toBeInTheDocument()
})

test.each(['403', 'business', 'malformed', 'cursor'] as const)(
  'a %s response is unavailable and never interpreted as membership',
  async (kind) => {
    handler = async (config) => {
      if (kind === '403') {
        return response(
          config,
          { success: false, code: 'ORG_FORBIDDEN', message: 'fixture' },
          403
        )
      }
      if (kind === 'business') {
        return response(config, { success: false, message: 'fixture' })
      }
      if (kind === 'cursor') return response(config, page(['Org A'], '0'))
      return response(config, {
        success: true,
        data: {
          items: [{ org_id: '1', name: 'forbidden', my_role: 'root' }],
          limit: 20,
          next_after_id: null,
        },
      })
    }
    show()
    expect(
      await screen.findByText('Unable to load organizations')
    ).toBeVisible()
    expect(
      screen.queryByText('No accessible organizations')
    ).not.toBeInTheDocument()
    expect(screen.queryByText('forbidden')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled()
  }
)

test('an old HTTP response cannot populate another actor or a later return to the original actor', async () => {
  let release: (() => void) | undefined
  let first = true
  handler = async (config) => {
    const actor = useAuthStore.getState().auth.user?.id
    if (first) {
      first = false
      await new Promise<void>((resolve) => {
        release = resolve
      })
      return response(config, page(['Old actor A']))
    }
    return response(config, page([actor === 2 ? 'Actor B' : 'Fresh actor A']))
  }
  show()
  await waitFor(() => expect(release).toBeDefined())
  act(() => login(2))
  expect(await screen.findByText('Actor B')).toBeVisible()
  act(() => login(1))
  expect(await screen.findByText('Fresh actor A')).toBeVisible()
  await act(async () => {
    release?.()
  })
  expect(screen.queryByText('Old actor A')).not.toBeInTheDocument()
  expect(screen.queryByText('Actor B')).not.toBeInTheDocument()
  expect(
    JSON.stringify(client.getQueriesData({ queryKey: ['organizations'] }))
  ).not.toContain('Old actor A')
})

test('logout removes visible memberships and the new session restarts at the first cursor', async () => {
  handler = async (config) =>
    response(
      config,
      config.params.after_id === '0'
        ? page(['First org'], '20')
        : page(['Later org'])
    )
  show()
  await screen.findByText('First org')
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  await screen.findByText('Later org')
  act(() => useAuthStore.getState().auth.reset())
  expect(screen.queryByText('Later org')).not.toBeInTheDocument()
  expect(screen.queryByText('My organizations')).not.toBeInTheDocument()
  act(() => login(1, 'new-session'))
  expect(await screen.findByText('First org')).toBeVisible()
  expect(calls.at(-1)?.params.after_id).toBe('0')
})

test('a denied refresh hides previously visible memberships while pending and after failure', async () => {
  show()
  await screen.findByText('Org A')
  let release: (() => void) | undefined
  handler = async (config) => {
    await new Promise<void>((resolve) => {
      release = resolve
    })
    return response(
      config,
      { success: false, code: 'ORG_FORBIDDEN', message: 'fixture' },
      403
    )
  }
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  await waitFor(() => expect(release).toBeDefined())
  expect(screen.queryByText('Org A')).not.toBeInTheDocument()
  await act(async () => {
    release?.()
  })
  expect(await screen.findByText('Unable to load organizations')).toBeVisible()
  expect(screen.queryByText('Org A')).not.toBeInTheDocument()
})

test('no dashboard session makes no directory request', () => {
  useAuthStore.getState().auth.reset()
  show()
  expect(calls).toHaveLength(0)
  expect(screen.queryByText('My organizations')).not.toBeInTheDocument()
})

test('keyboard refresh and locale changes preserve the organization name', async () => {
  handler = async (config) => response(config, page(['🌍'.repeat(64)]))
  language.addResourceBundle('zh', 'translation', {
    'My organizations': '我的组织',
  })
  show()
  expect(await screen.findByText('🌍'.repeat(64))).toBeVisible()
  const refresh = screen.getByRole('button', { name: 'Refresh' })
  refresh.focus()
  await userEvent.keyboard('{Enter}')
  await waitFor(() => expect(calls.length).toBe(2))
  await act(async () => {
    await language.changeLanguage('zh')
  })
  expect(screen.getAllByText('我的组织').length).toBeGreaterThan(0)
  expect(screen.getByText('🌍'.repeat(64))).toBeVisible()
})

test('audit: refocusing hides stale memberships and publishes a refreshed empty directory', async () => {
  show()
  await screen.findByText('Org A')
  let release: (() => void) | undefined
  handler = async (config) => {
    await new Promise<void>((resolve) => {
      release = resolve
    })
    return response(config, page([]))
  }
  act(() => focusManager.setFocused(false))
  act(() => focusManager.setFocused(true))
  await waitFor(() => expect(release).toBeDefined())
  expect(screen.queryByText('Org A')).not.toBeInTheDocument()
  await act(async () => release?.())
  expect(await screen.findByText('No accessible organizations')).toBeVisible()
  focusManager.setFocused(undefined)
})

test('audit: network failure remains unavailable and keyboard retry can recover', async () => {
  handler = async (config) => {
    throw new AxiosError('network unavailable', 'ERR_NETWORK', config)
  }
  show()
  expect(await screen.findByText('Unable to load organizations')).toBeVisible()
  expect(
    screen.queryByText('No accessible organizations')
  ).not.toBeInTheDocument()
  handler = async (config) => response(config, page(['Recovered organization']))
  screen.getByRole('button', { name: 'Retry' }).focus()
  await userEvent.keyboard('{Enter}')
  expect(await screen.findByText('Recovered organization')).toBeVisible()
})

test('audit: a same-actor new session cannot receive a delayed old-session directory', async () => {
  let release: (() => void) | undefined
  let first = true
  handler = async (config) => {
    if (first) {
      first = false
      await new Promise<void>((resolve) => {
        release = resolve
      })
      return response(config, page(['Old session membership']))
    }
    return response(config, page(['New session membership']))
  }
  show()
  await waitFor(() => expect(release).toBeDefined())
  act(() => login(1, 'replacement-session'))
  expect(await screen.findByText('New session membership')).toBeVisible()
  await act(async () => release?.())
  expect(screen.queryByText('Old session membership')).not.toBeInTheDocument()
  expect(
    JSON.stringify(client.getQueriesData({ queryKey: ['organizations'] }))
  ).not.toContain('Old session membership')
})

test('audit: long Chinese and unspaced English names retain wrapping and row reflow contracts', async () => {
  const chinese = '组织'.repeat(32)
  const english = 'W'.repeat(64)
  handler = async (config) => response(config, page([chinese, english]))
  show()
  for (const name of [chinese, english]) {
    const text = await screen.findByText(name)
    expect(text).toBeVisible()
    expect(text).toHaveClass('min-w-0', 'break-all')
    expect(text.closest('li')).toHaveClass('min-w-0', 'flex-wrap')
  }
})
