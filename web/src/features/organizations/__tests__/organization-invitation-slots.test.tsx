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
  onlineManager,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import {
  act,
  cleanup,
  fireEvent,
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
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

import {
  getOrganizationInvitationSlots,
  revokeOrganizationInvitation,
  OrganizationRequestFailure,
  type OrganizationInvitationSlot,
} from '../api'
import { OrganizationDetailsDialog } from '../organization-details-dialog'
import { OrganizationInvitationSlotsCard } from '../organization-invitation-slots-card'

// Adapter fixtures only: no live service, account, credential or authentication chain.
const originalAdapter = api.defaults.adapter
const orgId = '9007199254740997'
const secondOrgId = '9007199254740998'
const successMessage = 'Organization invitation revoked.'
const unconfirmedMessage =
  'Revocation was not confirmed. Review the refreshed invitation status before trying again.'
let client: QueryClient
let language: i18n
let calls: InternalAxiosRequestConfig[]
let handler: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>

function login(id = 1, sid = `session-${id}`) {
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
      'private response detail',
      undefined,
      config,
      undefined,
      result
    )
  }
  return result
}
function slot(
  patch: Partial<OrganizationInvitationSlot> = {}
): OrganizationInvitationSlot {
  return {
    organization_id: orgId,
    organization_name: 'Organization A',
    organization_revision: '9007199254740995',
    object_id: '9007199254740993',
    generation: '2',
    kind: 'invitation',
    target_user_id: '42',
    target_username: '<script>Recipient</script>',
    role: 'member',
    status: 'pending',
    expires_at: 1900000000,
    ...patch,
  }
}
function page(items = [slot()], next: string | null = null) {
  return { success: true, data: { items, limit: 20, next_after_id: next } }
}
function receipt(patch = {}) {
  return {
    success: true,
    data: {
      organization_id: orgId,
      revision: '9007199254740996',
      action: 'invitation_revoke',
      event_id: '9007199254741000',
      object_kind: 'invitation',
      object_id: slot().object_id,
      generation: slot().generation,
      status: 'revoked',
      ...patch,
    },
  }
}
function view(id = orgId) {
  return (
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={client}>
        <OrganizationInvitationSlotsCard
          actorId={1}
          sid='session-1'
          orgId={id}
        />
      </QueryClientProvider>
    </I18nextProvider>
  )
}
function show() {
  return render(view())
}
async function openConfirmation() {
  await userEvent.click(
    await screen.findByRole('button', { name: 'Revoke invitation' })
  )
  return screen.getByRole('alertdialog')
}
function readSlots(signal = new AbortController().signal) {
  return getOrganizationInvitationSlots(1, 'session-1', orgId, '0', signal)
}
function revoke(selected = slot(), signal = new AbortController().signal) {
  return revokeOrganizationInvitation(1, 'session-1', orgId, selected, signal)
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
  login()
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
  onlineManager.setOnline(true)
  api.defaults.adapter = originalAdapter
  useAuthStore.getState().auth.reset()
})

test('slots project recipient fields, escape names and leave expired slots read-only', async () => {
  const expired = slot({
    object_id: '9007199254740994',
    target_username: 'Expired recipient',
    status: 'expired',
    organization_revision: null,
    organization_name: null,
  })
  const raw = {
    ...slot(),
    from_username: 'not retained',
    secret: 'not retained',
  }
  handler = async (config) => response(config, page([raw, expired]))
  expect((await readSlots()).items).toEqual([slot(), expired])
  show()
  expect(await screen.findByText(slot().target_username)).toBeVisible()
  const expiredRow = screen
    .getByText('Expired recipient')
    .closest('li') as HTMLElement
  expect(within(expiredRow).getByText('Expired')).toBeVisible()
  expect(within(expiredRow).queryByRole('button')).not.toBeInTheDocument()
  expect(
    screen.getAllByRole('button', { name: 'Revoke invitation' })
  ).toHaveLength(1)
  expect(
    screen.queryByRole('button', { name: /accept|decline|reissue|create/i })
  ).not.toBeInTheDocument()
  for (const call of calls) {
    expect(call.url).toBe(`/api/organizations/${orgId}/invitations`)
    expect(call.method).toBe('get')
    expect(call.params).toEqual({ after_id: '0', limit: 20 })
    expect(call.expectedAuthIdentity).toEqual({ userId: 1, sid: 'session-1' })
    expect(call.disableDuplicate).toBe(true)
    expect(call.headers.has('X-Organization-Id')).toBe(false)
  }
})

test('a full resolved page stays empty but preserves the server cursor for keyboard pagination', async () => {
  const resolved = Array.from({ length: 20 }, (_, index) =>
    slot({
      object_id: String(9007199254740993n + BigInt(index)),
      status: 'revoked',
      organization_name: null,
      organization_revision: null,
    })
  )
  const next = resolved[19].object_id
  handler = async (config) =>
    response(
      config,
      config.params.after_id === '0'
        ? page(resolved, next)
        : page([
            slot({
              object_id: '9007199254741013',
              target_username: 'Next recipient',
            }),
          ])
    )
  show()
  expect(
    await screen.findByText('No pending organization invitations')
  ).toBeVisible()
  expect(screen.queryByText(slot().target_username)).not.toBeInTheDocument()
  const button = screen.getByRole('button', { name: 'Next invitation slots' })
  button.focus()
  await userEvent.keyboard('{Enter}')
  expect(await screen.findByText('Next recipient')).toBeVisible()
  expect(button).toHaveFocus()
  expect(button).toHaveAttribute('aria-disabled', 'true')
  await userEvent.click(
    screen.getByRole('button', { name: 'Previous invitation slots' })
  )
  expect(
    await screen.findByText('No pending organization invitations')
  ).toBeVisible()
  expect(calls.map((call) => call.params.after_id)).toEqual(['0', next, '0'])
})

test.each([
  { organization_id: '7' },
  { object_id: '01' },
  { object_id: '1\n' },
  { object_id: '9223372036854775808' },
  { generation: 2 },
  { kind: 'transfer' },
  { status: 'unknown' },
  { role: 'owner' },
  { organization_revision: '0' },
  { target_user_id: 42 },
  { target_username: null },
  { expires_at: Number.MAX_SAFE_INTEGER },
])('malformed or foreign slot %j fails closed', async (patch) => {
  handler = async (config) =>
    response(
      config,
      page([{ ...slot(), ...patch } as OrganizationInvitationSlot])
    )
  await expect(readSlots()).rejects.toBeInstanceOf(OrganizationRequestFailure)
})

test('malformed envelopes, duplicate IDs and inconsistent cursors are unavailable rather than empty', async () => {
  const full = Array.from({ length: 20 }, (_, index) =>
    slot({ object_id: String(index + 1) })
  )
  for (const data of [
    { success: false, data: page().data },
    { success: true, data: null },
    { success: true, data: { ...page().data, limit: 100 } },
    page([slot(), slot()]),
    page([slot({ object_id: '2' }), slot({ object_id: '1' })]),
    page(full, null),
    page(full, '19'),
    page([], '1'),
  ]) {
    handler = async (config) => response(config, data)
    await expect(readSlots()).rejects.toBeInstanceOf(OrganizationRequestFailure)
  }
})

test('refresh hides protected rows on failure and can recover to an empty list', async () => {
  show()
  await screen.findByText(slot().target_username)
  handler = async (config) =>
    response(
      config,
      { success: false, code: 'ORG_FORBIDDEN', message: 'private denial' },
      403
    )
  await userEvent.click(
    screen.getByRole('button', { name: 'Refresh organization invitations' })
  )
  expect(
    await screen.findByText('Unable to load organization invitations')
  ).toBeVisible()
  expect(screen.queryByText(slot().target_username)).not.toBeInTheDocument()
  const error = client.getQueryCache().getAll()[0].state.error
  expect(error).toMatchObject({ code: 'ORG_FORBIDDEN', status: 403 })
  expect(error).not.toHaveProperty('config')
  expect(error).not.toHaveProperty('cause')
  expect(JSON.stringify(error)).not.toMatch(/private|fixture-1|Authorization/)
  handler = async (config) => response(config, page([]))
  await userEvent.click(
    screen.getByRole('button', { name: 'Refresh organization invitations' })
  )
  expect(
    await screen.findByText('No pending organization invitations')
  ).toBeVisible()
})

test.each(['owner', 'admin', 'member'] as const)(
  'details mounts server-filtered slots only for %s management view',
  async (role) => {
    handler = async (config) => {
      if (config.url?.endsWith('/invitations')) {
        return response(
          config,
          page([slot({ role: role === 'owner' ? 'admin' : 'member' })])
        )
      }
      if (config.url?.endsWith('/members')) return response(config, page([]))
      return response(config, {
        success: true,
        data: {
          org_id: orgId,
          name: 'Organization A',
          my_role: role,
          revision: '5',
          my_member_revision: '1',
        },
      })
    }
    render(
      <I18nextProvider i18n={language}>
        <QueryClientProvider client={client}>
          <OrganizationDetailsDialog
            actorId={1}
            sid='session-1'
            orgId={orgId}
            open
            onOpenChange={() => {}}
          />
        </QueryClientProvider>
      </I18nextProvider>
    )
    await screen.findByText('Organization A')
    if (role === 'member') {
      expect(
        screen.queryByText('Organization invitation slots')
      ).not.toBeInTheDocument()
      expect(calls.some((call) => call.url?.endsWith('/invitations'))).toBe(
        false
      )
    } else {
      expect(
        await screen.findByRole('button', { name: 'Revoke invitation' })
      ).toBeVisible()
      expect(
        calls.filter((call) => call.url?.endsWith('/invitations'))
      ).toHaveLength(1)
    }
  }
)

test('cancel sends nothing; explicit confirmation posts the selected generation and validates the HTTP receipt', async () => {
  let resolved = false
  handler = async (config) => {
    if (config.method === 'post') {
      resolved = true
      return response(config, receipt())
    }
    return response(config, page(resolved ? [] : [slot()]))
  }
  show()
  const trigger = await screen.findByRole('button', {
    name: 'Revoke invitation',
  })
  trigger.focus()
  await userEvent.keyboard('{Enter}')
  let dialog = screen.getByRole('alertdialog', {
    name: 'Revoke organization invitation?',
  })
  expect(
    within(dialog).getByText(
      /no longer be able to join using this version of the invitation/
    )
  ).toBeVisible()
  expect(within(dialog).getByText('User ID: 42')).toBeVisible()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
  dialog = await openConfirmation()
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Revoke invitation' })
  )
  expect(await screen.findByText(successMessage)).toBeVisible()
  expect(
    await screen.findByText('No pending organization invitations')
  ).toBeVisible()
  const posts = calls.filter((call) => call.method === 'post')
  expect(posts).toHaveLength(1)
  expect(posts[0].url).toBe(
    `/api/organizations/${orgId}/invitations/${slot().object_id}/revoke`
  )
  expect(JSON.parse(posts[0].data)).toEqual({
    revision: slot().organization_revision,
    generation: '2',
  })
  expect(posts[0].singleUseAuthorization).toBe(true)
  expect(posts[0].skipAuthRefresh).toBe(true)
  expect(posts[0].withCredentials).toBe(true)
  expect(posts[0].expectedAuthIdentity).toEqual({ userId: 1, sid: 'session-1' })
  expect(posts[0].headers.get('Content-Type')).toBe('application/json')
  expect(posts[0].headers.has('X-Security-Proof')).toBe(false)
  expect(posts[0].headers.has('Idempotency-Key')).toBe(false)
  expect(posts[0].headers.has('X-Organization-Id')).toBe(false)
})

test('synchronous double click sends once and neither pending nor successful receipt optimistically removes the row', async () => {
  let finish!: () => void
  handler = async (config) => {
    if (config.method === 'post') {
      return new Promise((resolve) => {
        finish = () => resolve(response(config, receipt()))
      })
    }
    // Only a GET decides which rows remain, even after a valid receipt.
    return response(config, page())
  }
  show()
  const dialog = await openConfirmation()
  const button = within(dialog).getByRole('button', {
    name: 'Revoke invitation',
  })
  act(() => {
    fireEvent.click(button)
    fireEvent.click(button)
  })
  await waitFor(() =>
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
  )
  expect(screen.getByText(slot().target_username)).toBeInTheDocument()
  expect(button).toBeDisabled()
  expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled()
  await act(async () => finish())
  expect(await screen.findByText(successMessage)).toBeVisible()
  expect(await screen.findByText(slot().target_username)).toBeVisible()
  expect(calls.filter((call) => call.method === 'get')).toHaveLength(2)
})

test.each([
  [403, 'ORG_FORBIDDEN'],
  [401, 'AUTH_SESSION_REVOKED'],
  [409, 'ORG_STATE_CHANGED'],
  [409, 'ORG_REQUEST_RESOLVED'],
  [410, 'ORG_REQUEST_EXPIRED'],
  [500, 'ORG_INTERNAL_ERROR'],
])(
  'server rejection %s %s remains unconfirmed even after an empty refresh',
  async (status, code) => {
    let sent = false
    handler = async (config) => {
      if (config.method === 'post') {
        sent = true
        return response(
          config,
          { success: false, code, message: 'private denial' },
          status
        )
      }
      return response(config, page(sent ? [] : [slot()]))
    }
    show()
    const dialog = await openConfirmation()
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Revoke invitation' })
    )
    expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
    expect(
      await screen.findByText('No pending organization invitations')
    ).toBeVisible()
    expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
    expect(calls.some((call) => call.url?.includes('/auth/'))).toBe(false)
    expect(
      JSON.stringify(client.getMutationCache().getAll()[0].state.error)
    ).not.toMatch(/private|fixture-1|Authorization/)
  }
)

test.each(['network loss', 'business failure', 'wrong receipt'] as const)(
  '%s never becomes success based on refreshed state and never replays',
  async (kind) => {
    let sent = false
    handler = async (config) => {
      if (config.method === 'post') {
        sent = true
        if (kind === 'network loss') throw new AxiosError('private loss')
        return response(
          config,
          kind === 'business failure'
            ? { ...receipt(), success: false }
            : receipt({ action: 'invite_revoke' })
        )
      }
      return response(config, page(sent ? [] : [slot()]))
    }
    show()
    const dialog = await openConfirmation()
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Revoke invitation' })
    )
    expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
    expect(
      await screen.findByText('No pending organization invitations')
    ).toBeVisible()
    expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
  }
)

test.each([
  { organization_id: '7' },
  { object_id: '7' },
  { generation: '1' },
  { revision: '9007199254740995' },
  { revision: '9007199254740994' },
  { action: 'invite_revoke' },
  { action: 'invitation_decline' },
  { status: 'pending' },
  { status: 'accepted' },
  { object_kind: 'member' },
  { event_id: 123 },
  { revision: '9223372036854775808' },
])('revoke rejects mismatched receipt %j', async (patch) => {
  handler = async (config) => response(config, receipt(patch))
  await expect(revoke()).rejects.toBeInstanceOf(OrganizationRequestFailure)
  expect(calls).toHaveLength(1)
})

test('offline loss cannot queue a revoke or re-enable stale rows when refresh fails', async () => {
  let sent = false
  handler = async (config) => {
    if (config.method === 'post') {
      sent = true
      throw new AxiosError('private offline loss')
    }
    if (sent) throw new AxiosError('private refresh loss')
    return response(config, page())
  }
  show()
  const dialog = await openConfirmation()
  act(() => onlineManager.setOnline(false))
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Revoke invitation' })
  )
  expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
  expect(
    await screen.findByText('Unable to load organization invitations')
  ).toBeVisible()
  expect(screen.queryByText(slot().target_username)).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Revoke invitation' })
  ).not.toBeInTheDocument()
  await act(async () => onlineManager.setOnline(true))
  expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
  expect(calls.filter((call) => call.method === 'get')).toHaveLength(2)
})

test.each([
  { organization_id: secondOrgId },
  { organization_revision: null },
  { organization_revision: '0' },
  { status: 'expired' as const },
  { status: 'revoked' as const },
  { expires_at: 1 },
  { generation: '0' },
])('invalid selection %j sends no command', async (patch) => {
  await expect(revoke(slot(patch))).rejects.toBeInstanceOf(
    OrganizationRequestFailure
  )
  expect(calls).toHaveLength(0)
})

test('a pending slot with no server revision is read-only', async () => {
  handler = async (config) =>
    response(
      config,
      page([slot({ organization_revision: null, organization_name: null })])
    )
  show()
  expect(
    await screen.findByRole('button', { name: 'Revoke invitation' })
  ).toBeDisabled()
  expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
})

test('expiry while confirmation is open sends nothing and requests fresh state', async () => {
  const expiresAt = Math.floor(Date.now() / 1000) + 60
  handler = async (config) =>
    response(config, page([slot({ expires_at: expiresAt })]))
  show()
  const dialog = await openConfirmation()
  vi.spyOn(Date, 'now').mockReturnValue((expiresAt + 1) * 1000)
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Revoke invitation' })
  )
  expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
  expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
  expect(calls.filter((call) => call.method === 'get')).toHaveLength(2)
})

test.each(['logout', 'new SID', 'A-B-A', 'org change', 'unmount'] as const)(
  'confirmation invalidated by %s cannot send',
  async (change) => {
    const mounted = show()
    const dialog = await openConfirmation()
    const button = within(dialog).getByRole('button', {
      name: 'Revoke invitation',
    })
    act(() => {
      if (change === 'logout') useAuthStore.getState().auth.reset()
      else if (change === 'new SID') login(1, 'replacement')
      else if (change === 'A-B-A') {
        login(2)
        login()
      } else if (change === 'org change') mounted.rerender(view(secondOrgId))
      else mounted.unmount()
    })
    fireEvent.click(button)
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
  }
)

test.each(['logout', 'new SID', 'A-B-A', 'org change', 'unmount'] as const)(
  'pending mutation aborts and discards a late receipt after %s',
  async (change) => {
    let finish!: () => void
    handler = async (config) => {
      if (config.method === 'post') {
        return new Promise((resolve) => {
          finish = () => resolve(response(config, receipt()))
        })
      }
      return response(
        config,
        config.url === `/api/organizations/${orgId}/invitations`
          ? page()
          : page([])
      )
    }
    const mounted = show()
    const dialog = await openConfirmation()
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Revoke invitation' })
    )
    await waitFor(() =>
      expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
    )
    act(() => {
      if (change === 'logout') useAuthStore.getState().auth.reset()
      else if (change === 'new SID') login(1, 'replacement')
      else if (change === 'A-B-A') {
        login(2)
        login()
      } else if (change === 'org change') mounted.rerender(view(secondOrgId))
      else mounted.unmount()
    })
    const reads = calls.filter(
      (call) => call.url === `/api/organizations/${orgId}/invitations`
    ).length
    await act(async () => finish())
    expect(calls.find((call) => call.method === 'post')?.signal?.aborted).toBe(
      true
    )
    expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
    expect(screen.queryByText(unconfirmedMessage)).not.toBeInTheDocument()
    expect(
      calls.filter(
        (call) => call.url === `/api/organizations/${orgId}/invitations`
      )
    ).toHaveLength(reads)
  }
)

test.each(['caller abort', 'A-B-A', 'new SID'] as const)(
  'slots read drops a late response after %s',
  async (change) => {
    let finish!: () => void
    handler = (config) =>
      new Promise((resolve) => {
        finish = () => resolve(response(config, page()))
      })
    const controller = new AbortController()
    const pending = readSlots(controller.signal)
    const rejected = expect(pending).rejects.toMatchObject({ cancelled: true })
    await waitFor(() => expect(calls).toHaveLength(1))
    if (change === 'caller abort') controller.abort()
    else if (change === 'new SID') login(1, 'replacement')
    else {
      login(2)
      login()
    }
    finish()
    await rejected
  }
)

test('changing organization during a read aborts its signal and hides its late rows', async () => {
  let finish!: () => void
  handler = (config) => {
    if (config.url === `/api/organizations/${orgId}/invitations`) {
      return new Promise((resolve) => {
        finish = () => resolve(response(config, page()))
      })
    }
    return Promise.resolve(response(config, page([])))
  }
  const mounted = show()
  await waitFor(() => expect(calls).toHaveLength(1))
  mounted.rerender(view(secondOrgId))
  expect(
    await screen.findByText('No pending organization invitations')
  ).toBeVisible()
  await act(async () => finish())
  expect(calls[0].signal?.aborted).toBe(true)
  expect(screen.queryByText(slot().target_username)).not.toBeInTheDocument()
})

test('confirmation keeps its original generation if focus revalidation observes a newer generation', async () => {
  let generation = '2'
  handler = async (config) =>
    config.method === 'post'
      ? response(config, { success: false, code: 'ORG_STATE_CHANGED' }, 409)
      : response(config, page([slot({ generation })]))
  show()
  const dialog = await openConfirmation()
  generation = '3'
  act(() => {
    focusManager.setFocused(false)
    focusManager.setFocused(true)
  })
  await waitFor(() =>
    expect(calls.filter((call) => call.method === 'get')).toHaveLength(2)
  )
  await waitFor(() =>
    expect(
      within(dialog).getByRole('button', { name: 'Revoke invitation' })
    ).toBeEnabled()
  )
  await userEvent.click(
    within(dialog).getByRole('button', { name: 'Revoke invitation' })
  )
  expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
  const post = calls.find((call) => call.method === 'post')
  expect(JSON.parse(post?.data).generation).toBe('2')
})

test.each(['en', 'zh', 'zh-TW', 'fr', 'ja', 'ru', 'vi'])(
  '%s renders translated revoke controls and confirmation after language change',
  async (locale) => {
    const resources = await import(`../../../i18n/locales/${locale}.json`)
    const translations = resources.default.translation
    language.addResourceBundle(locale, 'translation', translations)
    show()
    await screen.findByRole('button', { name: 'Revoke invitation' })
    await act(async () => {
      await language.changeLanguage(locale)
    })
    await userEvent.click(
      screen.getByRole('button', { name: translations['Revoke invitation'] })
    )
    const dialog = screen.getByRole('alertdialog', {
      name: translations['Revoke organization invitation?'],
    })
    expect(
      within(dialog).getByRole('button', {
        name: translations['Revoke invitation'],
      })
    ).toBeVisible()
    expect(
      within(dialog).getByText(/<script>Recipient<\/script>/)
    ).toBeVisible()
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
  }
)
