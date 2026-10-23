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
  MutationCache,
  onlineManager,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
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
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import { createInstance, type i18n } from 'i18next'
import { I18nextProvider } from 'react-i18next'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'
import {
  getServerErrorSources,
  getServerErrorStatus,
} from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

import {
  getMyOrganizations,
  getOrganizationDetails,
  getOrganizationMembers,
  removeOrganizationMember,
  projectOrganizationRequestFailure,
  canRemoveOrganizationMember,
  type OrganizationDetail,
  type OrganizationMember,
} from '../api'
import { MyOrganizationsCard } from '../my-organizations-card'
import { useRemoveMember } from '../use-remove-member'

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
  vi.unstubAllGlobals()
  onlineManager.setOnline(true)
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
    cancelled: true,
    __CANCEL__: true,
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

test('organization GET failures discard original credential-bearing objects before QueryCache', async () => {
  let raw: unknown
  handler = async (config) => {
    raw = new AxiosError(
      'raw-password-canary',
      'ERR_BAD_REQUEST',
      config,
      { flow: 'flow-canary' },
      {
        config,
        status: 403,
        statusText: 'Rejected',
        headers: {},
        data: {
          success: false,
          code: 'ORG_FORBIDDEN',
          message_params: { secret: 'raw-password-canary' },
          proof_token: 'proof-canary',
        },
      }
    )
    throw raw
  }
  await client
    .fetchQuery({
      queryKey: ['organizations', 'safe-failure'],
      queryFn: ({ signal }) => getMyOrganizations(1, 'session-1', '0', signal),
    })
    .catch(() => undefined)
  const failure = client.getQueryCache().getAll()[0].state.error
  expect(failure).not.toBe(raw)
  expect(failure).not.toHaveProperty('cause')
  expect(getServerErrorStatus(failure)).toBe(403)
})

test('an owner has a Remove action only for another ordinary member', async () => {
  handler = async (config) => {
    if (config.url === `/api/organizations/${orgId}`) {
      return response(config, detail(orgId, 'owner'))
    }
    if (config.url?.endsWith('/members')) {
      return response(config, members(['owner', 'admin', 'ordinary']))
    }
    return response(config, payload(config))
  }
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('ordinary')
  const buttons = within(dialog).getAllByRole('button', { name: /Remove/ })
  expect(buttons).toHaveLength(1)
})

const ordinaryPage = () => {
  const page = members(['ordinary'])
  page.data.items[0].role = 'member'
  return page
}
const removalIntent = {
  orgId,
  memberId: String(firstMemberId),
  targetUserId: String(firstMemberId + 1000n),
  revision: '9007199254741201',
}
function receipt() {
  return {
    success: true,
    data: {
      organization_id: orgId,
      revision: '9007199254741202',
      action: 'remove',
      event_id: '9007199254741400',
      object_kind: 'member',
      object_id: removalIntent.memberId,
      generation: null,
      status: null,
      access_token: 'access-canary',
    },
  }
}
function selection() {
  return {
    detail: detail(orgId, 'owner').data as OrganizationDetail,
    member: ordinaryPage().data.items[0] as OrganizationMember,
    afterId: '0',
  }
}
function hook() {
  return renderHook(() => useRemoveMember(1, 'session-1', orgId), {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  })
}
function installRemovalHandler(
  write: (
    config: InternalAxiosRequestConfig
  ) => Promise<AxiosResponse> = async (config) => response(config, receipt())
) {
  handler = async (config) => {
    if (config.method === 'delete') return write(config)
    if (config.url === `/api/organizations/${orgId}`) {
      return response(config, detail(orgId, 'owner'))
    }
    if (config.url?.endsWith('/members')) {
      return response(config, ordinaryPage())
    }
    return response(config, payload(config))
  }
}
async function openRemoval() {
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('ordinary')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
  return screen.findByRole('alertdialog', { name: 'Remove member' })
}
const canaries = [
  'fixture-1',
  'password-canary',
  'flow-canary',
  'proof-canary',
  'access-canary',
  'refresh-canary',
  'params-canary',
]
/** Walk live object identities, including nonenumerable and symbol properties. */
function assertSafeGraph(root: unknown, forbidden: unknown[] = []) {
  const seen = new Set<unknown>()
  function visit(value: unknown) {
    expect(forbidden.includes(value)).toBe(false)
    if (typeof value === 'string') {
      for (const canary of canaries) expect(value).not.toContain(canary)
    }
    if (
      !value ||
      (typeof value !== 'object' && typeof value !== 'function') ||
      seen.has(value)
    ) {
      return
    }
    seen.add(value)
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor) continue
      if ('value' in descriptor) visit(descriptor.value)
      else {
        if (descriptor.get) visit(descriptor.get)
        if (descriptor.set) visit(descriptor.set)
      }
    }
  }
  visit(root)
}
function cacheStates() {
  return [
    ...client
      .getQueryCache()
      .getAll()
      .map((query) => query.state),
    ...client
      .getMutationCache()
      .getAll()
      .map((mutation) => mutation.state),
  ]
}
function poisonedError(
  config: InternalAxiosRequestConfig,
  status: number,
  code: string,
  retry: string | number = '12'
) {
  const body = {
    success: false,
    code,
    message: 'password-canary',
    message_key: 'proof-canary',
    message_params: { token: 'params-canary' },
    access_token: 'access-canary',
    refresh_token: 'refresh-canary',
  }
  const request = { flow: 'flow-canary' }
  const headers = { 'Retry-After': retry }
  const rawResponse = {
    data: body,
    config,
    status,
    statusText: 'Rejected',
    headers,
  }
  const raw = new AxiosError(
    'password-canary',
    undefined,
    config,
    request,
    rawResponse
  )
  Object.defineProperty(raw, 'private', { value: request })
  Object.defineProperty(raw, Symbol('secret'), { value: body })
  return {
    raw,
    refs: [
      raw,
      config,
      config.headers,
      request,
      body,
      body.message_params,
      headers,
      rawResponse,
    ],
  }
}

test.each(['owner', 'admin', 'member'] as const)(
  'only fresh %s eligibility permits a nonself ordinary target',
  (role) => {
    const selected = selection()
    selected.detail.my_role = role
    expect(
      canRemoveOrganizationMember(1, selected.detail, selected.member)
    ).toBe(role !== 'member')
    selected.member.user_id = '1'
    expect(
      canRemoveOrganizationMember(1, selected.detail, selected.member)
    ).toBe(false)
    selected.member.user_id = removalIntent.targetUserId
    for (const targetRole of ['owner', 'admin'] as const) {
      selected.member.role = targetRole
      expect(
        canRemoveOrganizationMember(1, selected.detail, selected.member)
      ).toBe(false)
    }
  }
)

test.each([0, -1, 1.1, Number.MAX_SAFE_INTEGER + 1, Number.NaN])(
  'invalid actor %s cannot reach the adapter',
  async (actorId) => {
    await expect(
      removeOrganizationMember(
        actorId,
        'session-1',
        removalIntent,
        new AbortController().signal
      )
    ).rejects.toMatchObject({
      message: 'Unable to complete organization operation.',
    })
    expect(calls).toHaveLength(0)
  }
)

test.each(['0', '01', '1\n', '9223372036854775808', '1e3'])(
  'noncanonical write id %s never reaches adapter',
  async (id) => {
    await expect(
      removeOrganizationMember(
        1,
        'session-1',
        { ...removalIntent, orgId: id },
        new AbortController().signal
      )
    ).rejects.toBeInstanceOf(Error)
    expect(calls).toHaveLength(0)
  }
)

test('DELETE uses exact string target user, revision-only body and whitelisted member receipt', async () => {
  installRemovalHandler()
  const result = await removeOrganizationMember(
    1,
    'session-1',
    removalIntent,
    new AbortController().signal
  )
  const config = calls[0]
  expect(config.url).toBe(
    `/api/organizations/${orgId}/members/${removalIntent.targetUserId}`
  )
  expect(config.url).not.toContain(`/members/${removalIntent.memberId}`)
  expect(JSON.parse(config.data)).toEqual({ revision: removalIntent.revision })
  expect(config.headers.has('X-Security-Proof')).toBe(false)
  expect(config.headers.has('Idempotency-Key')).toBe(false)
  expect(config.expectedAuthIdentity).toEqual({ userId: 1, sid: 'session-1' })
  expect(config.singleUseAuthorization).toBe(true)
  expect(config.skipAuthRefresh).toBe(true)
  expect(result).toEqual(
    Object.fromEntries(
      Object.entries(receipt().data).filter(([key]) => key !== 'access_token')
    )
  )
  assertSafeGraph(result)
})

test.each([
  ['organization_id', secondOrgId],
  ['object_id', removalIntent.targetUserId],
  ['action', 'update'],
  ['object_kind', 'organization'],
  ['revision', removalIntent.revision],
  ['event_id', '01'],
  ['generation', '1'],
  ['status', 'active'],
  ['revision', '9223372036854775808'],
])('receipt with wrong %s is never successful', async (field, value) => {
  installRemovalHandler(async (config) =>
    response(config, {
      success: true,
      data: { ...receipt().data, [field]: value },
    })
  )
  const { result } = hook()
  let output: unknown
  await act(async () => {
    output = await result.current.remove(selection())
  })
  expect(output).toMatchObject({ kind: 'failure', unconfirmed: true })
  expect(client.getMutationCache().getAll()[0].state.status).toBe('error')
  assertSafeGraph([cacheStates(), result.current, output])
  expect(calls.filter((call) => call.method === 'delete')).toHaveLength(1)
})

test.each([
  [403, 'ORG_FORBIDDEN'],
  [403, 'SECURITY_PROOF_REQUIRED'],
  [404, 'ORG_NOT_FOUND'],
  [409, 'ORG_STATE_CHANGED'],
  [401, 'AUTH_UNAUTHORIZED'],
  [429, 'UNKNOWN'],
  [500, 'ORG_INTERNAL_ERROR'],
])(
  'DELETE %i %s is projected before live MutationCache and public hook results',
  async (status, code) => {
    let refs: unknown[] = []
    installRemovalHandler(async (config) => {
      const poison = poisonedError(config, status as number, code as string)
      refs = poison.refs
      throw poison.raw
    })
    const { result } = hook()
    let output: unknown
    await act(async () => {
      output = await result.current.remove(selection())
    })
    expect(output).toMatchObject({
      kind: 'failure',
      error: { status, retryAfter: 12 },
    })
    const mutation = client.getMutationCache().getAll()[0]
    expect(mutation.state.error).not.toBe(refs[0])
    expect(mutation.state.context).toBeUndefined()
    expect(mutation.state.variables).toEqual(removalIntent)
    expect(mutation.options.retry).toBe(false)
    expect(mutation.options.networkMode).toBe('always')
    expect(mutation.state.isPaused).toBe(false)
    assertSafeGraph(
      [
        cacheStates(),
        result.current,
        output,
        mutation.options.mutationKey,
        mutation.meta,
      ],
      refs
    )
    expect(calls.filter((call) => call.method === 'delete')).toHaveLength(1)
    expect(
      calls.filter(
        (call) =>
          call.url?.includes('authorization-context') ||
          call.url?.includes('verification')
      )
    ).toHaveLength(0)
  }
)

test.each(['directory', 'detail', 'members'] as const)(
  'all %s GET failure states discard raw error references',
  async (kind) => {
    let refs: unknown[] = []
    handler = async (config) => {
      const poison = poisonedError(config, 403, 'ORG_FORBIDDEN')
      refs = poison.refs
      throw poison.raw
    }
    const queryFn = async ({
      signal,
    }: {
      signal: AbortSignal
    }): Promise<unknown> => {
      if (kind === 'directory') {
        return getMyOrganizations(1, 'session-1', '0', signal)
      }
      if (kind === 'detail') {
        return getOrganizationDetails(1, 'session-1', orgId, signal)
      }
      return getOrganizationMembers(1, 'session-1', orgId, '0', signal)
    }
    await client
      .fetchQuery({ queryKey: ['organizations', kind], queryFn })
      .catch(() => undefined)
    expect(client.getQueryCache().getAll()[0].state.error).toMatchObject({
      code: 'ORG_FORBIDDEN',
      status: 403,
    })
    assertSafeGraph(cacheStates(), refs)
  }
)

test.each(['business', 'dto', 'cursor', 'network'] as const)(
  'GET %s failures are projected before cache',
  async (mode) => {
    let raw: unknown
    handler = async (config) => {
      if (mode === 'network') {
        raw = Object.assign(new Error('password-canary'), {
          request: { flow: 'flow-canary' },
        })
        throw raw
      }
      if (mode === 'business') {
        raw = {
          success: false,
          code: 'ORG_NOT_FOUND',
          message: 'password-canary',
          message_params: { proof: 'proof-canary' },
        }
      } else if (mode === 'cursor') {
        raw = {
          ...ordinaryPage(),
          data: { ...ordinaryPage().data, next_after_id: '1' },
        }
      } else {
        raw = { success: true, data: { items: 'password-canary' } }
      }
      return response(config, raw)
    }
    await client
      .fetchQuery({
        queryKey: ['organizations', mode],
        queryFn: ({ signal }) =>
          getOrganizationMembers(
            1,
            'session-1',
            orgId,
            mode === 'cursor' ? '2' : '0',
            signal
          ),
      })
      .catch(() => undefined)
    expect(client.getQueryCache().getAll()[0].state.status).toBe('error')
    assertSafeGraph(cacheStates(), [raw])
  }
)

test.each([
  '0',
  '86400',
  12,
  '-1',
  '01',
  '86401',
  'Thu, 01 Jan 2099 00:00:00 GMT',
  'params-canary',
])('Retry-After %s retains only bounded canonical delta seconds', (retry) => {
  const error = projectOrganizationRequestFailure({
    response: {
      status: 429,
      headers: { 'Retry-After': retry },
      data: { code: 'UNKNOWN', message: 'password-canary' },
    },
  })
  expect(error.retryAfter).toBe(
    ['0', '86400', 12].includes(retry) ? Number(retry) : undefined
  )
  expect(error.code).toBeUndefined()
  assertSafeGraph(error)
})

test('source getters and symbol metadata are not evaluated or retained', () => {
  const source = Object.create(null)
  Object.defineProperty(source, 'response', {
    get() {
      throw new Error('password-canary')
    },
  })
  source[Symbol('secret')] = { token: 'access-canary' }
  const error = projectOrganizationRequestFailure(source)
  expect(error.message).toBe('Unable to complete organization operation.')
  assertSafeGraph(error, [source])
})

test.each([
  'revision',
  'role',
  'memberRevision',
  'row',
  'user',
  'missing',
  'actorRole',
] as const)('preflight %s change stops without DELETE', async (change) => {
  installRemovalHandler()
  const confirm = await openRemoval()
  const base = handler
  handler = async (config) => {
    if (config.url === `/api/organizations/${orgId}`) {
      const value = detail(orgId, change === 'actorRole' ? 'member' : 'owner')
      if (change === 'revision') value.data.revision = '9007199254741202'
      return response(config, value)
    }
    if (config.url?.endsWith('/members')) {
      const value = ordinaryPage()
      if (change === 'missing') value.data.items = []
      else if (change === 'role') value.data.items[0].role = 'admin'
      else if (change === 'row') value.data.items[0].member_id = '999'
      else if (change === 'user') value.data.items[0].user_id = '999'
      else if (change === 'memberRevision') value.data.items[0].revision = '999'
      return response(config, value)
    }
    return base(config)
  }
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  await screen.findByText(
    'Organization state changed. Refresh the organization state before retrying.'
  )
  expect(calls.some((call) => call.method === 'delete')).toBe(false)
  expect(screen.queryByText('ordinary')).not.toBeInTheDocument()
})

test('SECURITY_PROOF_REQUIRED uses fixed state changed copy without opening proof', async () => {
  installRemovalHandler(async (config) =>
    response(
      config,
      {
        success: false,
        code: 'SECURITY_PROOF_REQUIRED',
        message: 'password-canary',
      },
      403
    )
  )
  const confirm = await openRemoval()
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  await screen.findByText(
    'Organization state changed. Refresh the organization state before retrying.'
  )
  expect(
    screen.queryByText('Additional verification required')
  ).not.toBeInTheDocument()
  expect(
    screen.queryByText('Organization member removed')
  ).not.toBeInTheDocument()
})

test('single flight covers double click, Enter and Space while Cancel stays enabled', async () => {
  const gate = defer()
  installRemovalHandler(async (config) => {
    await gate.promise
    return response(config, receipt())
  })
  const confirm = await openRemoval()
  const remove = within(confirm).getByRole('button', { name: 'Remove' })
  await userEvent.dblClick(remove)
  await userEvent.keyboard('{Enter} ')
  await waitFor(() =>
    expect(calls.filter((call) => call.method === 'delete')).toHaveLength(1)
  )
  const cancel = within(confirm).getByRole('button', { name: 'Cancel' })
  expect(cancel).toBeEnabled()
  await userEvent.click(cancel)
  await screen.findByText(
    'The result could not be confirmed. Refresh the organization before trying again.'
  )
  await act(async () => {
    gate.resolve()
  })
  await waitFor(() =>
    expect(client.getMutationCache().getAll()[0].state.status).toBe('error')
  )
  expect(
    screen.queryByText('Organization member removed')
  ).not.toBeInTheDocument()
  assertSafeGraph(cacheStates())
})

test('Cancel during preflight aborts before any mutation is scheduled', async () => {
  installRemovalHandler()
  const confirm = await openRemoval()
  const gate = defer()
  const base = handler
  handler = async (config) => {
    if (config.url?.endsWith('/members')) await gate.promise
    return base(config)
  }
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }))
  await act(async () => {
    gate.resolve()
  })
  expect(calls.some((call) => call.method === 'delete')).toBe(false)
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(
    screen.queryByText('Organization member removed')
  ).not.toBeInTheDocument()
})

test.each(['sid', 'actor', 'unmount'] as const)(
  '%s change invalidates a submitted ticket and late receipt',
  async (change) => {
    const gate = defer()
    installRemovalHandler(async (config) => {
      await gate.promise
      return response(config, receipt())
    })
    const view = hook()
    let pending: Promise<unknown> | undefined
    act(() => {
      pending = view.result.current.remove(selection())
    })
    await waitFor(() =>
      expect(calls.some((call) => call.method === 'delete')).toBe(true)
    )
    act(() => {
      if (change === 'unmount') view.unmount()
      else login(change === 'actor' ? 2 : 1, 'new-session')
    })
    let output: unknown
    await act(async () => {
      gate.resolve()
      output = await pending
    })
    expect(output).toBeUndefined()
    expect(client.getMutationCache().getAll()[0].state.status).toBe('error')
    assertSafeGraph(cacheStates())
  }
)

test('transformRequest identity change is stopped before the actual DELETE adapter', async () => {
  installRemovalHandler()
  const original = api.defaults.transformRequest
  const transforms = original ? [original].flat() : []
  api.defaults.transformRequest = [
    ...transforms,
    function (data) {
      login(1, 'replaced-sid')
      return data
    },
  ]
  try {
    await expect(
      removeOrganizationMember(
        1,
        'session-1',
        removalIntent,
        new AbortController().signal
      )
    ).rejects.toMatchObject({ cancelled: true })
    expect(calls).toHaveLength(0)
  } finally {
    api.defaults.transformRequest = original
  }
})

test.each([false, true])(
  'matched write receipt stays successful when refreshed GET fails=%s',
  async (readFails) => {
    let deleted = false
    const refs: unknown[] = []
    installRemovalHandler(async (config) => {
      deleted = true
      return response(config, receipt())
    })
    const base = handler
    handler = async (config) => {
      if (
        deleted &&
        config.method !== 'delete' &&
        config.url?.includes(orgId)
      ) {
        if (readFails) {
          const poison = poisonedError(config, 403, 'ORG_FORBIDDEN')
          refs.push(...poison.refs)
          throw poison.raw
        }
        if (config.url.endsWith('/members')) {
          return response(config, members([]))
        }
      }
      return base(config)
    }
    const confirm = await openRemoval()
    const memberReads = calls.filter((call) =>
      call.url?.endsWith('/members')
    ).length
    const directoryReads = calls.filter(
      (call) => call.url === '/api/organizations'
    ).length
    await userEvent.click(
      within(confirm).getByRole('button', { name: 'Remove' })
    )
    await screen.findByText('Organization member removed')
    await screen.findByText(
      readFails ? 'Unable to load organization' : 'No members to display'
    )
    expect(screen.queryByText('ordinary')).not.toBeInTheDocument()
    const mutation = client.getMutationCache().getAll()[0]
    expect(mutation.state.status).toBe('success')
    expect(mutation.state.error).toBeNull()
    expect(mutation.state.data).toHaveProperty(
      'object_id',
      removalIntent.memberId
    )
    const newReads = calls.filter((call) => call.url?.endsWith('/members'))
    expect(newReads.length).toBeGreaterThan(memberReads + 1)
    expect(newReads.at(-1)?.params).toEqual({ after_id: '0', limit: 20 })
    expect(
      calls.filter((call) => call.url === '/api/organizations').length
    ).toBeGreaterThan(directoryReads)
    const dialog = screen.getByRole('dialog', { name: 'Organization details' })
    const refresh = within(dialog).getByRole('button', { name: 'Refresh' })
    await waitFor(() => expect(refresh).toHaveFocus())
    assertSafeGraph(cacheStates(), refs)
  }
)

test.each(['network', 'business', 'malformed', '202'] as const)(
  'DELETE %s failure remains unconfirmed and credential free',
  async (mode) => {
    let raw: unknown
    installRemovalHandler(async (config) => {
      if (mode === 'network') {
        raw = Object.assign(new Error('password-canary'), { config })
        throw raw
      }
      if (mode === 'business') {
        raw = {
          success: false,
          message: 'password-canary',
          message_params: { proof: 'proof-canary' },
        }
      } else if (mode === 'malformed') {
        raw = { success: true, data: 'password-canary' }
      } else {
        raw = receipt()
      }
      return response(config, raw, mode === '202' ? 202 : 200)
    })
    const view = hook()
    let output: unknown
    await act(async () => {
      output = await view.result.current.remove(selection())
    })
    expect(output).toMatchObject({ kind: 'failure', unconfirmed: true })
    expect(calls.filter((call) => call.method === 'delete')).toHaveLength(1)
    assertSafeGraph([cacheStates(), view.result.current, output], [raw])
  }
)

test('offline status does not retain a paused DELETE for reconnect replay', async () => {
  installRemovalHandler(async (config) => {
    throw poisonedError(config, 500, 'ORG_INTERNAL_ERROR').raw
  })
  onlineManager.setOnline(false)
  const view = hook()
  await act(async () => {
    await view.result.current.remove(selection())
  })
  expect(client.getMutationCache().getAll()[0].state.isPaused).toBe(false)
  const count = calls.length
  await act(async () => {
    onlineManager.setOnline(true)
    await client.resumePausedMutations()
  })
  expect(calls).toHaveLength(count)
  expect(calls.filter((call) => call.method === 'delete')).toHaveLength(1)
})

test('a cancelled scheduled mutation cannot borrow the next preflight ticket', async () => {
  const mutationGate = defer()
  client = new QueryClient({
    mutationCache: new MutationCache({ onMutate: () => mutationGate.promise }),
  })
  installRemovalHandler()
  const view = hook()
  let first: Promise<unknown> | undefined
  act(() => {
    first = view.result.current.remove(selection())
  })
  await waitFor(() =>
    expect(client.getMutationCache().getAll()).toHaveLength(1)
  )
  act(() => {
    view.result.current.cancel()
  })
  const readGate = defer()
  const base = handler
  handler = async (config) => {
    if (config.url?.endsWith('/members')) await readGate.promise
    return base(config)
  }
  let second: Promise<unknown> | undefined
  act(() => {
    second = view.result.current.remove(selection())
  })
  await waitFor(() =>
    expect(calls.filter((call) => call.url?.endsWith('/members'))).toHaveLength(
      2
    )
  )
  await act(async () => {
    mutationGate.resolve()
    await first
  })
  expect(calls.some((call) => call.method === 'delete')).toBe(false)
  act(() => {
    view.result.current.cancel()
  })
  await act(async () => {
    readGate.resolve()
    await second
  })
  expect(calls.some((call) => call.method === 'delete')).toBe(false)
  assertSafeGraph(cacheStates())
})

test('expiring headers that replace identity never send the DELETE', async () => {
  const bundle = useAuthStore.getState().auth
  if (!bundle.user || !bundle.session || !bundle.accessToken) {
    throw new Error('Fixture requires authentication')
  }
  useAuthStore.getState().auth.setBundle({
    user: bundle.user,
    session: bundle.session,
    access_token: bundle.accessToken,
    token_type: 'Bearer',
    access_expires_at: 1,
  })
  const refresh = vi.fn()
  vi.stubGlobal(
    'XMLHttpRequest',
    class {
      status = 200
      statusText = 'OK'
      readyState = 4
      responseText = JSON.stringify({
        success: true,
        data: {
          user: { id: 2, username: 'other', role: 1 },
          session: { ...bundle.session, sid: 'other-sid' },
          access_token: 'access-canary',
          token_type: 'Bearer',
          access_expires_at: 1900000000,
        },
      })
      onloadend: (() => void) | null = null
      open(_method: string, url: string) {
        refresh(url)
      }
      setRequestHeader() {}
      getAllResponseHeaders() {
        return 'content-type: application/json'
      }
      abort() {}
      send() {
        queueMicrotask(() => this.onloadend?.())
      }
    }
  )
  const failure = await removeOrganizationMember(
    1,
    'session-1',
    removalIntent,
    new AbortController().signal
  ).catch((error: unknown) => error)
  expect(refresh).toHaveBeenCalledWith('/api/user/auth/refresh')
  expect(failure).toMatchObject({ cancelled: true })
  expect(calls).toHaveLength(0)
  assertSafeGraph(failure)
})

test.each([false, true])(
  'late DELETE success/rejection=%s is discarded after SID changes',
  async (reject) => {
    const gate = defer()
    let raw: unknown
    installRemovalHandler(async (config) => {
      await gate.promise
      if (reject) {
        raw = poisonedError(config, 403, 'ORG_FORBIDDEN').raw
        throw raw
      }
      raw = receipt()
      return response(config, raw)
    })
    const operation = removeOrganizationMember(
      1,
      'session-1',
      removalIntent,
      new AbortController().signal
    ).catch((error: unknown) => error)
    await waitFor(() => expect(calls).toHaveLength(1))
    login(1, 'replacement-sid')
    gate.resolve()
    const failure = await operation
    expect(failure).toMatchObject({ cancelled: true })
    assertSafeGraph(failure, [raw])
  }
)

test('a successful removal on a later page resets to a fresh first page and stable Refresh focus', async () => {
  let deleted = false
  installRemovalHandler(async (config) => {
    deleted = true
    return response(config, receipt())
  })
  const base = handler
  handler = async (config) => {
    if (config.url?.endsWith('/members')) {
      if (deleted) return response(config, members([]))
      if (config.params.after_id === '0') {
        return response(config, members(['first-page'], '9007199254741101'))
      }
      return response(config, ordinaryPage())
    }
    return base(config)
  }
  show()
  const dialog = await openOrganization()
  await within(dialog).findByText('first-page')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Next' }))
  await within(dialog).findByText('ordinary')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
  const confirm = await screen.findByRole('alertdialog')
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  await within(dialog).findByText('No members to display')
  expect(
    [...calls].reverse().find((call) => call.url?.endsWith('/members'))?.params
      .after_id
  ).toBe('0')
  expect(
    within(dialog).getByRole('button', { name: 'Previous' })
  ).toHaveAttribute('aria-disabled', 'true')
  await waitFor(() =>
    expect(
      within(dialog).getByRole('button', { name: 'Refresh' })
    ).toHaveFocus()
  )
  expect(
    client
      .getQueryCache()
      .getAll()
      .some((query) => query.queryKey.includes('9007199254741101'))
  ).toBe(false)
})

test('receipt success hides old protected rows while refreshed reads are pending', async () => {
  const gate = defer()
  let deleted = false
  installRemovalHandler(async (config) => {
    deleted = true
    return response(config, receipt())
  })
  const base = handler
  handler = async (config) => {
    if (deleted && config.method !== 'delete' && config.url?.includes(orgId)) {
      await gate.promise
    }
    return base(config)
  }
  const confirm = await openRemoval()
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  await screen.findByText('Organization member removed')
  const dialog = screen.getByRole('dialog')
  await within(dialog).findByText('Loading...')
  expect(within(dialog).queryByText('ordinary')).not.toBeInTheDocument()
  expect(
    within(dialog).queryByText('Fresh organization')
  ).not.toBeInTheDocument()
  const refresh = within(dialog).getByRole('button', { name: 'Refresh' })
  expect(refresh).toHaveAttribute('aria-disabled', 'true')
  await waitFor(() => expect(refresh).toHaveFocus())
  expect(client.getMutationCache().getAll()[0].state.status).toBe('success')
  await act(async () => {
    gate.resolve()
  })
})

test.each(['en', 'zh'] as const)(
  'confirmation in %s wraps long names and falls back to the target user ID',
  async (locale) => {
    if (locale === 'zh') {
      const zh = await import('@/i18n/locales/zh.json')
      language.addResourceBundle('zh', 'translation', zh.default.translation)
    }
    await language.changeLanguage(locale)
    const name = '组'.repeat(64)
    installRemovalHandler()
    const base = handler
    handler = async (config) => {
      if (config.url === `/api/organizations/${orgId}`) {
        return response(config, detail(orgId, 'owner', name))
      }
      if (config.url?.endsWith('/members')) {
        const page = ordinaryPage()
        page.data.items[0].username = ''
        return response(config, page)
      }
      return base(config)
    }
    show()
    await userEvent.click(
      await screen.findByRole('button', {
        name: language.t('View {{name}}', { name: 'Org A' }),
      })
    )
    const dialog = await screen.findByRole('dialog', {
      name: language.t('Organization details'),
    })
    await within(dialog).findByText(name)
    await userEvent.click(
      within(dialog).getByRole('button', { name: language.t('Remove') })
    )
    const confirm = await screen.findByRole('alertdialog', {
      name: language.t('Remove member'),
    })
    const targetLabel = language.t('User ID: {{id}}', {
      id: removalIntent.targetUserId,
    })
    const description = within(confirm).getByText(
      language.t('Remove {{member}} from {{organization}}?', {
        member: targetLabel,
        organization: name,
      })
    )
    expect(description.parentElement).toHaveClass('break-all')
    expect(within(confirm).getByText(targetLabel)).toBeVisible()
    await userEvent.click(
      within(confirm).getByRole('button', { name: language.t('Cancel') })
    )
    expect(calls.some((call) => call.method === 'delete')).toBe(false)
  }
)

test('organization replacement unmounts the old submitted operation without late feedback', async () => {
  const gate = defer()
  installRemovalHandler(async (config) => {
    await gate.promise
    return response(config, receipt())
  })
  const view = renderHook(
    ({ organization }) => useRemoveMember(1, 'session-1', organization),
    {
      initialProps: { organization: orgId },
      wrapper: ({ children }) => (
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      ),
    }
  )
  let operation: Promise<unknown> | undefined
  act(() => {
    operation = view.result.current.remove(selection())
  })
  await waitFor(() =>
    expect(calls.some((call) => call.method === 'delete')).toBe(true)
  )
  view.rerender({ organization: secondOrgId })
  let output: unknown
  await act(async () => {
    gate.resolve()
    output = await operation
  })
  expect(output).toBeUndefined()
  expect(client.getMutationCache().getAll()[0].state.status).toBe('error')
  assertSafeGraph([cacheStates(), view.result.current])
})

test('closing details during preflight aborts the intent and preserves the existing directory focus fallback', async () => {
  installRemovalHandler()
  const confirm = await openRemoval()
  const gate = defer()
  const base = handler
  handler = async (config) => {
    if (config.url?.endsWith('/members')) await gate.promise
    return base(config)
  }
  await userEvent.click(within(confirm).getByRole('button', { name: 'Remove' }))
  // The explicit confirmation Cancel remains reachable, then details can close.
  await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }))
  await userEvent.click(
    within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' })
  )
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'View Org A' })).toHaveFocus()
  )
  await act(async () => {
    gate.resolve()
  })
  expect(calls.some((call) => call.method === 'delete')).toBe(false)
})

test.each([1, 10])(
  'global user role %s with only ordinary organization membership has no Remove button',
  async (globalRole) => {
    login(1, 'session-1', globalRole)
    show()
    const dialog = await openOrganization()
    await within(dialog).findByText('alice')
    expect(
      within(dialog).queryByRole('button', { name: 'Remove' })
    ).not.toBeInTheDocument()
  }
)

test('mixed-case HTTP Retry-After headers retain only their primitive delta', () => {
  const headers = { 'rEtRy-AfTeR': '12', password: 'password-canary' }
  const error = projectOrganizationRequestFailure({
    response: { status: 429, headers },
  })
  expect(error.retryAfter).toBe(12)
  assertSafeGraph(error, [headers])
})
