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
import {
  act,
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
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
import {
  getServerErrorSources,
  getServerErrorStatus,
} from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

import { getOrganizationDetails, getOrganizationMembers } from '../api'
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
  handler = async (config) => response(config, payload(config))
  api.defaults.adapter = async (config) => {
    calls.push(config)
    return handler(config)
  }
})

afterEach(() => {
  focusManager.setFocused(undefined)
  cleanup()
  client.clear()
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset()
})

const orgId = '9007199254740993'
const secondOrgId = '9007199254740994'
const firstMemberId = 9007199254741100n
function detail(id = orgId, role = 'member', name = 'Fresh organization') {
  return {
    success: true,
    data: {
      org_id: id,
      name,
      my_role: role,
      revision: '9007199254741201',
      my_member_revision: '9007199254741202',
      capabilities: { members_read: true },
      email: 'secret@example.invalid',
    },
  }
}
function members(names = ['alice'], next: string | null = null) {
  return {
    success: true,
    data: {
      items: names.map((name, i) => ({
        member_id: String(firstMemberId + BigInt(i)),
        user_id: String(firstMemberId + 1000n + BigInt(i)),
        username: name,
        role: ['owner', 'admin', 'member'][i % 3],
        revision: '9007199254741301',
        joined_at: 1234567890,
        email: 'secret@example.invalid',
        removal_reason: 'internal-secret',
      })),
      limit: 20,
      next_after_id: next,
    },
  }
}
function payload(config: InternalAxiosRequestConfig) {
  if (config.url === '/api/organizations') {
    return {
      success: true,
      data: {
        items: [
          { org_id: orgId, name: 'Org A', my_role: 'member' },
          { org_id: secondOrgId, name: 'Org B', my_role: 'admin' },
        ],
        limit: 20,
        next_after_id: null,
      },
    }
  }
  if (config.url?.endsWith('/members')) return members()
  return detail(config.url?.split('/').at(-1))
}
async function openOrganization(name = 'Org A') {
  await userEvent.click(
    await screen.findByRole('button', { name: `View ${name}` })
  )
  return screen.findByRole('dialog', {
    name: 'Organization details',
  })
}
function defer() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

test.each(['owner', 'admin', 'member'])(
  'an active %s can read detail and members without capability-based grants',
  async (role) => {
    handler = async (config) =>
      response(
        config,
        config.url === `/api/organizations/${orgId}`
          ? detail(orgId, role)
          : payload(config)
      )
    show()
    await screen.findByText('Org A')
    expect(calls).toHaveLength(1)
    const dialog = await openOrganization()
    expect(
      await within(dialog).findByRole('heading', { name: 'Fresh organization' })
    ).toBeVisible()
    const list = within(dialog).getByRole('list', {
      name: 'Organization members',
    })
    expect(within(list).getByText('alice')).toBeVisible()
    expect(within(list).getByText('Organization owner')).toBeVisible()
    expect(
      within(dialog).queryByText('secret@example.invalid')
    ).not.toBeInTheDocument()
    expect(
      JSON.stringify(client.getQueriesData({ queryKey: ['organizations'] }))
    ).not.toContain('internal-secret')
    expect(
      calls
        .filter((c) => c.url !== '/api/organizations')
        .every((c) => c.method === 'get' && !c.headers.has('X-Organization-Id'))
    ).toBe(true)
    expect(
      calls.find((c) => c.url === `/api/organizations/${orgId}`)?.params
    ).toBeUndefined()
  }
)

test('member cursor remains exact through next and previous pages', async () => {
  const next = String(firstMemberId + 19n)
  const names = Array.from({ length: 20 }, (_, i) => `member-${i}`)
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      if (config.params.after_id === '0') {
        return response(config, members(names, next))
      }
      const last = members(['last member'])
      last.data.items[0].member_id = String(firstMemberId + 20n)
      return response(config, last)
    }
    return response(config, payload(config))
  }

  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('member-0')
  expect(
    within(dialog).getByRole('button', { name: 'Previous' })
  ).toHaveAttribute('aria-disabled', 'true')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Next' }))
  expect(await within(dialog).findByText('last member')).toBeVisible()
  expect(within(dialog).getByRole('button', { name: 'Next' })).toHaveAttribute(
    'aria-disabled',
    'true'
  )
  expect(
    calls.filter((c) => c.url?.endsWith('/members')).map((c) => c.params)
  ).toEqual([
    { after_id: '0', limit: 20 },
    { after_id: next, limit: 20 },
  ])
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Previous' })
  )
  expect(await within(dialog).findByText('member-0')).toBeVisible()
})

test('large IDs/revisions remain strings and non-display fields are stripped', async () => {
  const signal = new AbortController().signal
  expect(await getOrganizationDetails(1, 'session-1', orgId, signal)).toEqual({
    org_id: orgId,
    name: 'Fresh organization',
    my_role: 'member',
    revision: '9007199254741201',
    my_member_revision: '9007199254741202',
  })
  const page = await getOrganizationMembers(1, 'session-1', orgId, '0', signal)
  expect(page.items[0]).toEqual({
    member_id: String(firstMemberId),
    user_id: String(firstMemberId + 1000n),
    username: 'alice',
    role: 'owner',
    revision: '9007199254741301',
  })
})

test.each([
  [404, 'ORG_NOT_FOUND', 'root nonmember'],
  [404, 'ORG_NOT_FOUND', 'removed membership'],
  [404, 'ORG_NOT_FOUND', 'disabled organization'],
  [403, 'ORG_FORBIDDEN', 'forbidden'],
  [409, 'ORG_STATE_CHANGED', 'state changed'],
] as const)(
  '%s/%s hides all protected data for %s',
  async (status, code, reason) => {
    if (reason === 'root nonmember') login(1, 'session-1', 100)
    handler = async (config) =>
      config.url === '/api/organizations'
        ? response(config, payload(config))
        : response(
            config,
            { success: false, code, message: 'Organization is unavailable.' },
            status
          )
    show()
    const dialog = await openOrganization()
    expect(
      await within(dialog).findByText('Unable to load organization')
    ).toBeVisible()
    expect(
      within(dialog).queryByText('Fresh organization')
    ).not.toBeInTheDocument()
    expect(
      within(dialog).queryByRole('list', { name: 'Organization members' })
    ).not.toBeInTheDocument()
  }
)

test('exhausted HTTP401 follows shared auth policy and removes the open directory', async () => {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('alice')
  const previousPath = window.location.pathname
  window.history.replaceState({}, '', '/sign-in')
  handler = async (config) => {
    if (config.url === '/api/organizations') {
      return response(config, payload(config))
    }
    Object.assign(config, { authRetry: true }) // transport boundary models an exhausted refresh attempt
    return response(
      config,
      { success: false, code: 'AUTH_SESSION_REVOKED' },
      401
    )
  }
  await userEvent.click(within(dialog).getByRole('button', { name: 'Refresh' }))
  await waitFor(() =>
    expect(screen.queryByText('alice')).not.toBeInTheDocument()
  )
  expect(useAuthStore.getState().auth.user).toBeNull()
  window.history.replaceState({}, '', previousPath)
})

test.each([
  null,
  { success: true, data: null },
  { success: true, data: { ...detail().data, org_id: secondOrgId } },
  { success: true, data: { ...detail().data, revision: 2 ** 54 } },
  { success: true, data: { ...detail().data, my_member_revision: '01' } },
])('malformed detail %j fails closed', async (value) => {
  handler = async (config) => response(config, value)
  await expect(
    getOrganizationDetails(1, 'session-1', orgId, new AbortController().signal)
  ).rejects.toThrow()
})

test.each([
  null,
  { success: true, data: null },
  { success: true, data: { ...members().data, items: null } },
  {
    success: true,
    data: {
      ...members().data,
      items: [{ ...members().data.items[0], member_id: 2 ** 54 }],
    },
  },
  { success: true, data: { ...members().data, next_after_id: '01' } },
  {
    success: true,
    data: { ...members().data, next_after_id: '9007199254740993' },
  },
])('malformed members %j fail instead of empty success', async (value) => {
  handler = async (config) => response(config, value)
  await expect(
    getOrganizationMembers(
      1,
      'session-1',
      orgId,
      '9007199254740993',
      new AbortController().signal
    )
  ).rejects.toThrow()
})

test('business failure preserves the server code', async () => {
  handler = async (config) =>
    response(config, {
      success: false,
      code: 'ORG_NOT_FOUND',
      message: 'Organization is unavailable.',
    })
  try {
    await getOrganizationMembers(
      1,
      'session-1',
      orgId,
      '0',
      new AbortController().signal
    )
    throw new Error('unexpected success')
  } catch (error) {
    expect(
      getServerErrorSources(error).some(
        (source) => source.code === 'ORG_NOT_FOUND'
      )
    ).toBe(true)
  }
})

test('HTTP409 preserves actual status and server code', async () => {
  handler = async (config) =>
    response(
      config,
      {
        success: false,
        code: 'ORG_STATE_CHANGED',
        message: 'Organization state changed. Retry the request.',
      },
      409
    )
  try {
    await getOrganizationDetails(
      1,
      'session-1',
      orgId,
      new AbortController().signal
    )
    throw new Error('unexpected success')
  } catch (error) {
    expect(getServerErrorStatus(error)).toBe(409)
    expect(
      getServerErrorSources(error).some(
        (source) => source.code === 'ORG_STATE_CHANGED'
      )
    ).toBe(true)
  }
})

test('closing A then opening B ignores a late A detail response', async () => {
  const gate = defer()
  handler = async (config) => {
    if (config.url === `/api/organizations/${orgId}`) {
      await gate.promise
      return response(config, detail(orgId, 'owner', 'Late A detail'))
    }
    return response(
      config,
      config.url === `/api/organizations/${secondOrgId}`
        ? detail(secondOrgId, 'admin', 'Current B detail')
        : payload(config)
    )
  }
  show()
  const first = await openOrganization()
  await within(first).findByText('Loading...')
  await userEvent.click(within(first).getByRole('button', { name: 'Close' }))
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  const second = await openOrganization('Org B')
  await within(second).findByText('Current B detail')
  await act(async () => gate.resolve())
  expect(screen.queryByText('Late A detail')).not.toBeInTheDocument()
  expect(within(second).getByText('Current B detail')).toBeVisible()
})

test.each(['account', 'session'] as const)(
  '%s changes during slow read discard the old result',
  async (change) => {
    const gate = defer()
    let first = true
    handler = async (config) => {
      if (config.url === `/api/organizations/${orgId}`) {
        if (first) {
          first = false
          await gate.promise
          return response(config, detail(orgId, 'owner', 'Old identity detail'))
        }
        return response(config, detail(orgId, 'member', 'New identity detail'))
      }
      return response(config, payload(config))
    }
    show()
    await openOrganization()
    await waitFor(() => expect(first).toBe(false))
    act(() => {
      useAuthStore.getState().auth.reset()
      login(change === 'account' ? 2 : 1, 'new-session')
    })
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    )
    const dialog = await openOrganization()
    await within(dialog).findByText('New identity detail')
    await act(async () => gate.resolve())
    expect(screen.queryByText('Old identity detail')).not.toBeInTheDocument()
    await waitFor(() =>
      expect(
        JSON.stringify(client.getQueriesData({ queryKey: ['organizations'] }))
      ).not.toContain('Old identity detail')
    )
  }
)

test('slow API response is cancelled on SID replacement without a component', async () => {
  const gate = defer()
  handler = async (config) => {
    await gate.promise
    return response(config, detail())
  }
  const request = getOrganizationDetails(
    1,
    'session-1',
    orgId,
    new AbortController().signal
  )
  const rejected = expect(request).rejects.toMatchObject({
    name: 'CanceledError',
  })
  await waitFor(() => expect(calls.length).toBe(1))
  login(1, 'replacement-session')
  gate.resolve()
  await rejected
})

test('refetch failure hides old detail/members and keyboard retry can recover', async () => {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('alice')
  const gate = defer()
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      await gate.promise
      return response(
        config,
        {
          success: false,
          code: 'ORG_NOT_FOUND',
          message: 'Organization is unavailable.',
        },
        404
      )
    }
    return response(config, payload(config))
  }
  await userEvent.click(within(dialog).getByRole('button', { name: 'Refresh' }))
  expect(
    within(dialog).queryByText('Fresh organization')
  ).not.toBeInTheDocument()
  expect(within(dialog).queryByText('alice')).not.toBeInTheDocument()
  await act(async () => gate.resolve())
  await within(dialog).findByText('Unable to load organization')
  handler = async (config) => response(config, payload(config))
  within(dialog).getByRole('button', { name: 'Retry' }).focus()
  await userEvent.keyboard('{Enter}')
  expect(await within(dialog).findByText('alice')).toBeVisible()
})

test('reopening fetches fresh data without exposing the previous successful members', async () => {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('alice')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  const gate = defer()
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      await gate.promise
      return response(config, members(['fresh member']))
    }
    return response(config, payload(config))
  }
  const reopened = await openOrganization()
  await within(reopened).findByText('Loading...')
  expect(within(reopened).queryByText('alice')).not.toBeInTheDocument()
  await act(async () => gate.resolve())
  expect(await within(reopened).findByText('fresh member')).toBeVisible()
})

test('focus refetch preserves dialog, hides stale rows and shows an empty member page', async () => {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('alice')
  const gate = defer()
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      await gate.promise
      return response(config, members([]))
    }
    return response(config, payload(config))
  }
  act(() => {
    focusManager.setFocused(false)
    focusManager.setFocused(true)
  })
  await within(dialog).findByText('Loading...')
  expect(within(dialog).queryByText('alice')).not.toBeInTheDocument()
  await act(async () => gate.resolve())
  expect(await within(dialog).findByText('No members to display')).toBeVisible()
  act(() => focusManager.setFocused(undefined))
})

test('keyboard opens and escapes the dialog, returning focus to its entry button', async () => {
  show()
  const entry = await screen.findByRole('button', { name: 'View Org A' })
  entry.focus()
  await userEvent.keyboard('{Enter}')
  const dialog = await screen.findByRole('dialog', {
    name: 'Organization details',
  })
  await within(dialog).findByText('alice')
  await userEvent.keyboard('{Escape}')
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  expect(entry).toHaveFocus()
})

test('long EN/ZH text wraps and missing usernames use the public empty style', async () => {
  const longName = '组'.repeat(64),
    longUsername = 'U'.repeat(64),
    rows = members([longUsername, 'temporary']).data
  handler = async (config) => {
    if (config.url === `/api/organizations/${orgId}`) {
      return response(config, detail(orgId, 'member', longName))
    }
    if (config.url?.endsWith('/members')) {
      return response(config, {
        success: true,
        data: {
          ...rows,
          items: [rows.items[0], { ...rows.items[1], username: null }],
        },
      })
    }
    return response(config, payload(config))
  }
  show()
  const dialog = await openOrganization()
  const name = await within(dialog).findByRole('heading', { name: longName })
  expect(name).toHaveClass('min-w-0', 'break-all')
  expect(within(dialog).getByText(longUsername)).toHaveClass('break-all')
  expect(within(dialog).getByText('—')).toHaveClass('text-muted-foreground')
  expect(
    within(dialog).getByRole('list', { name: 'Organization members' })
      .firstElementChild
  ).toHaveClass('flex-wrap', 'min-w-0')
  language.addResourceBundle(
    'zh',
    'translation',
    { 'Organization details': '组织详情', 'Organization members': '组织成员' },
    true,
    true
  )
  await act(async () => {
    await language.changeLanguage('zh')
  })
  expect(screen.getByRole('dialog', { name: '组织详情' })).toBeVisible()
  expect(within(dialog).getByRole('list', { name: '组织成员' })).toBeVisible()
})

test('a full last member page may lead to empty next page and still allow Previous', async () => {
  const next = String(firstMemberId + 19n),
    names = Array.from({ length: 20 }, (_, i) => `full-${i}`)
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      return response(
        config,
        config.params.after_id === '0' ? members(names, next) : members([])
      )
    }
    return response(config, payload(config))
  }
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('full-0')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Next' }))
  await within(dialog).findByText('No members to display')
  expect(within(dialog).getByRole('button', { name: 'Next' })).toHaveAttribute(
    'aria-disabled',
    'true'
  )
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Previous' })
  )
  expect(await within(dialog).findByText('full-0')).toBeVisible()
})

test('closing after a directory focus refetch returns focus to the replacement entry button', async () => {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('alice')
  const gate = defer()
  handler = async (config) => {
    if (config.url === '/api/organizations') await gate.promise
    return response(config, payload(config))
  }
  act(() => {
    focusManager.setFocused(false)
    focusManager.setFocused(true)
  })
  await waitFor(() =>
    expect(screen.queryByText('Org A')).not.toBeInTheDocument()
  )
  await act(async () => gate.resolve())
  await screen.findByText('Org A')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  expect(screen.getByRole('button', { name: 'View Org A' })).toHaveFocus()
})

test.each(['Next', 'Refresh'])(
  'keyboard %s keeps focus inside details while loading and after the response',
  async (action) => {
    handler = async (config) =>
      response(
        config,
        config.url?.endsWith('/members')
          ? members(['first page member'], String(firstMemberId))
          : payload(config)
      )
    show()
    const dialog = await openOrganization()
    await within(dialog).findByText('first page member')
    const gate = defer()
    handler = async (config) => {
      if (config.url?.endsWith('/members')) {
        await gate.promise
        return response(config, members(['new page member']))
      }
      return response(config, payload(config))
    }
    const control = within(dialog).getByRole('button', { name: action })
    control.focus()
    await userEvent.keyboard('{Enter}')
    await within(dialog).findByText('Loading...')
    expect(
      within(dialog).queryByText('first page member')
    ).not.toBeInTheDocument()
    await waitFor(() => expect(control).toHaveFocus())
    expect(control).toHaveAttribute('aria-disabled', 'true')
    const pendingCalls = calls.length
    await userEvent.keyboard('{Enter}')
    expect(calls).toHaveLength(pendingCalls)
    await act(async () => gate.resolve())
    await within(dialog).findByText('new page member')
    await waitFor(() => expect(control).toHaveFocus())
    if (action === 'Next') {
      expect(control).toHaveAttribute('aria-disabled', 'true')
      const completedCalls = calls.length
      await userEvent.keyboard('{Enter}')
      expect(calls).toHaveLength(completedCalls)
    }
    await userEvent.keyboard('{Tab}')
    expect(dialog.contains(document.activeElement)).toBe(true)
  }
)

test.each(['empty', 'pending'])(
  'closing with a disconnected organization entry and %s directory returns focus to Refresh',
  async (state) => {
    show()
    const dialog = await openOrganization()
    await within(dialog).findByText('alice')
    const entry = screen.getByRole('button', {
      name: 'View Org A',
      hidden: true,
    })
    const gate = defer()
    handler = async (config) => {
      if (config.url === '/api/organizations') {
        if (state === 'pending') await gate.promise
        return response(config, {
          success: true,
          data: { items: [], limit: 20, next_after_id: null },
        })
      }
      return response(config, payload(config))
    }
    let directoryRequest!: Promise<void>
    act(() => {
      directoryRequest = client.refetchQueries({
        queryKey: ['organizations', 1, 'session-1', 'personal', 'directory'],
      })
    })
    await waitFor(() => expect(entry.isConnected).toBe(false))
    if (state === 'empty') await act(async () => directoryRequest)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    )
    const refresh = screen.getByRole('button', { name: 'Refresh' })
    await waitFor(() => expect(refresh).toHaveFocus())
    expect(refresh.isConnected).toBe(true)
    if (state === 'pending') {
      expect(refresh).toHaveAttribute('aria-disabled', 'true')
      const pendingCalls = calls.length
      await userEvent.keyboard('{Enter}')
      expect(calls).toHaveLength(pendingCalls)
      await act(async () => {
        gate.resolve()
        await directoryRequest
      })
      await screen.findByText('No accessible organizations')
      expect(refresh).toHaveFocus()
    }
  }
)
