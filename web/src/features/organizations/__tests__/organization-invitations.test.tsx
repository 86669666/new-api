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
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

import {
  acceptOrganizationInvitation,
  declineOrganizationInvitation,
  getMyOrganizationInvitations,
  OrganizationRequestFailure,
} from '../api'
import { MyOrganizationsCard } from '../my-organizations-card'
import { OrganizationInvitationsCard } from '../organization-invitations-card'

// HTTP is simulated at the Axios adapter; this is not a live authentication chain.
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
function invitation(objectId = '9007199254740993', target = '1') {
  return {
    organization_id: '9007199254740997',
    organization_name: '<script>Invitation A</script>',
    organization_revision: '9007199254740995',
    object_id: objectId,
    generation: '1',
    kind: 'invitation',
    target_user_id: target,
    from_username: 'Inviter',
    role: 'member',
    status: 'pending',
    expires_at: 1900000000,
  }
}
function page(items = [invitation()], next: string | null = null) {
  return { success: true, data: { items, limit: 20, next_after_id: next } }
}
function show(withDirectory = false) {
  render(
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={client}>
        <OrganizationInvitationsCard />
        {withDirectory && <MyOrganizationsCard />}
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

test('projects only own pending invitation data and escapes names with explicit invitation actions', async () => {
  const raw = {
    ...invitation(),
    secret: 'not retained',
    target_username: 'not retained',
    reason_code: 'not retained',
  }
  handler = async (config) => response(config, page([raw]))
  const result = await getMyOrganizationInvitations(
    1,
    'session-1',
    '0',
    new AbortController().signal
  )
  expect(result.items).toEqual([invitation()])
  show()
  expect(await screen.findByText('<script>Invitation A</script>')).toBeVisible()
  expect(screen.getByText('Invited by Inviter')).toBeVisible()
  expect(screen.getByText('Organization member')).toBeVisible()
  expect(
    screen.getByRole('button', { name: 'Decline invitation' })
  ).toBeVisible()
  expect(
    screen.getByRole('button', { name: 'Accept invitation' })
  ).toBeVisible()
  expect(
    screen.queryByRole('button', { name: /switch|spend/i })
  ).not.toBeInTheDocument()
  for (const call of calls) {
    expect(call.url).toBe('/api/organization-invitations')
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
  ['wrong kind', { kind: 'transfer' }],
  ['resolved', { status: 'accepted' }],
  ['owner role', { role: 'owner' }],
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
        page([{ ...invitation(), ...patch } as ReturnType<typeof invitation>])
      )
    show()
    expect(
      await screen.findByText('Unable to load organization invitations')
    ).toBeVisible()
    expect(
      screen.queryByText('No pending organization invitations')
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText('<script>Invitation A</script>')
    ).not.toBeInTheDocument()
    expect(calls).toHaveLength(1)
  }
)

test('rejects malformed page, duplicate rows and nonprogressing or inconsistent cursor', async () => {
  const full = Array.from({ length: 20 }, (_, i) => invitation(String(10 + i)))
  const invalid = [
    { success: false, data: page().data },
    { success: true, data: null },
    { success: true, data: { ...page().data, limit: 100 } },
    page([invitation('10'), invitation('10')]),
    page([invitation('10'), invitation('9')]),
    page([invitation('9')]),
    page(full, '28'),
    page(full, null),
    page([], '9223372036854775808'),
  ]
  for (const value of invalid) {
    handler = async (config) => response(config, value)
    await expect(
      getMyOrganizationInvitations(
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
    ...invitation(String(9007199254740993n + BigInt(i))),
    organization_name: `Page one ${i}`,
  }))
  const last = {
    ...invitation('9007199254741013'),
    organization_name: 'Last invitation',
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
  expect(await screen.findByText('Last invitation')).toBeVisible()
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
    const pending = getMyOrganizationInvitations(
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
  expect(await screen.findByText('<script>Invitation A</script>')).toBeVisible()
  let finish!: () => void
  handler = (config) =>
    new Promise((resolve) => {
      finish = () =>
        resolve(
          response(
            config,
            page([{ ...invitation('2', '2'), organization_name: 'Late B' }])
          )
        )
    })
  act(() => login(2))
  expect(
    screen.queryByText('<script>Invitation A</script>')
  ).not.toBeInTheDocument()
  await waitFor(() => expect(calls).toHaveLength(2))
  const lateB = finish
  handler = async (config) =>
    response(config, page([{ ...invitation(), organization_name: 'Fresh A' }]))
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
  expect(await screen.findByText('<script>Invitation A</script>')).toBeVisible()
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
      screen.queryByText('<script>Invitation A</script>')
    ).not.toBeInTheDocument()
  )
  finish()
  expect(
    await screen.findByText('Unable to load organization invitations')
  ).toBeVisible()
  expect(
    screen.queryByText('<script>Invitation A</script>')
  ).not.toBeInTheDocument()
  expect(screen.queryByText('secret-body')).not.toBeInTheDocument()
  handler = async (config) => response(config, page([]))
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  expect(
    await screen.findByText('No pending organization invitations')
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
    await screen.findByText('Unable to load organization invitations')
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

describe.each([
  {
    action: 'decline',
    command: declineOrganizationInvitation,
    status: 'declined',
    label: 'Decline invitation',
    title: 'Decline organization invitation?',
    description:
      'Decline the invitation to <script>Invitation A</script>? You will not join the organization.',
    successMessage: 'Organization invitation declined.',
    unconfirmedMessage:
      'Decline was not confirmed. Review the refreshed invitation status before trying again.',
  },
  {
    action: 'accept',
    command: acceptOrganizationInvitation,
    status: 'accepted',
    label: 'Accept invitation',
    title: 'Accept organization invitation?',
    description:
      'Accept the invitation to <script>Invitation A</script>? You will join this organization.',
    successMessage:
      'Organization invitation accepted. You have joined the organization.',
    unconfirmedMessage:
      'Acceptance was not confirmed. Review the refreshed invitation status before trying again.',
  },
])(
  '$action invitation',
  ({
    action,
    command,
    status,
    label,
    title,
    description,
    successMessage,
    unconfirmedMessage,
  }) => {
    function receipt(overrides = {}) {
      return {
        success: true,
        data: {
          organization_id: invitation().organization_id,
          revision: '9007199254740996',
          action: `invitation_${action}`,
          event_id: '9007199254740998',
          object_kind: 'invitation',
          object_id: invitation().object_id,
          generation: '1',
          status,
          ...overrides,
        },
      }
    }
    async function openConfirmation() {
      await userEvent.click(await screen.findByRole('button', { name: label }))
      return screen.getByRole('alertdialog')
    }

    test('cancelled confirmation sends no mutation; confirmed action uses exact string versions and refreshes', async () => {
      let resolved = false
      handler = async (config) => {
        if (config.method === 'post') {
          resolved = true
          return response(config, receipt())
        }
        return response(config, page(resolved ? [] : [invitation()]))
      }
      show()
      const trigger = await screen.findByRole('button', {
        name: label,
      })
      trigger.focus()
      await userEvent.keyboard('{Enter}')
      let dialog = screen.getByRole('alertdialog')
      expect(dialog).toHaveAccessibleName(title)
      expect(within(dialog).getByText(description)).toBeVisible()
      expect(calls.filter((c) => c.method === 'post')).toHaveLength(0)
      await userEvent.click(
        within(dialog).getByRole('button', { name: 'Cancel' })
      )
      expect(calls.filter((c) => c.method === 'post')).toHaveLength(0)
      dialog = await openConfirmation()
      await userEvent.click(within(dialog).getByRole('button', { name: label }))
      expect(await screen.findByText(successMessage)).toBeVisible()
      expect(
        await screen.findByText('No pending organization invitations')
      ).toBeVisible()
      const posts = calls.filter((c) => c.method === 'post')
      expect(posts).toHaveLength(1)
      expect(posts[0].url).toBe(
        `/api/organizations/9007199254740997/invitations/9007199254740993/${action}`
      )
      expect(JSON.parse(posts[0].data)).toEqual({
        revision: '9007199254740995',
        generation: '1',
      })
      expect(posts[0].singleUseAuthorization).toBe(true)
      expect(posts[0].skipAuthRefresh).toBe(true)
      expect(posts[0].withCredentials).toBe(true)
      expect(posts[0].headers.has('Idempotency-Key')).toBe(false)
      expect(posts[0].headers.get('Content-Type')).toBe('application/json')
      expect(posts[0].expectedAuthIdentity).toEqual({
        userId: 1,
        sid: 'session-1',
      })
      expect(posts[0].headers.has('X-Security-Proof')).toBe(false)
      expect(posts[0].headers.has('X-Organization-Id')).toBe(false)
    })

    test.each([
      [403, 'ORG_FORBIDDEN'],
      [401, 'AUTH_SESSION_REVOKED'],
      [409, 'ORG_STATE_CHANGED'],
      [409, 'ORG_REQUEST_RESOLVED'],
      [410, 'ORG_REQUEST_EXPIRED'],
      [403, 'SECURITY_PROOF_REQUIRED'],
      [403, 'SECURITY_PROOF_INVALID'],
      [500, 'ORG_INTERNAL_ERROR'],
    ])(
      'failure %s %s never retries or declares success and refreshes server state',
      async (status, code) => {
        let sent = false
        handler = async (config) => {
          if (config.method === 'post') {
            sent = true
            return response(
              config,
              { success: false, code, message: 'sensitive backend detail' },
              status
            )
          }
          return response(config, page(sent ? [] : [invitation()]))
        }
        show()
        const dialog = await openConfirmation()
        await userEvent.click(
          within(dialog).getByRole('button', { name: label })
        )
        expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
        expect(
          await screen.findByText('No pending organization invitations')
        ).toBeVisible()
        expect(calls.filter((c) => c.method === 'post')).toHaveLength(1)
        expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
        expect(
          screen.queryByText('sensitive backend detail')
        ).not.toBeInTheDocument()
      }
    )

    test.each(['switch', 'logout', 'A-B-A', 'new SID'])(
      'confirmation invalidated by %s cannot send',
      async (change) => {
        show()
        const dialog = await openConfirmation()
        const confirm = within(dialog).getByRole('button', {
          name: label,
        })
        act(() => {
          if (change === 'logout') useAuthStore.getState().auth.reset()
          else if (change === 'new SID') login(1, 'replacement')
          else {
            login(2)
            if (change === 'A-B-A') login(1)
          }
          fireEvent.click(confirm)
        })
        expect(calls.filter((c) => c.method === 'post')).toHaveLength(0)
        await waitFor(() =>
          expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
        )
      }
    )

    test.each(['switch', 'logout', 'A-B-A', 'new SID', 'unmount'])(
      'duplicate confirmation is one-shot and late response after %s gives no feedback',
      async (change) => {
        let finish: (() => void) | undefined
        handler = async (config) => {
          if (config.method === 'post') {
            return new Promise((resolve) => {
              finish = () => resolve(response(config, receipt()))
            })
          }
          return response(
            config,
            page(
              useAuthStore.getState().auth.user?.id === 1 ? [invitation()] : []
            )
          )
        }
        show()
        const dialog = await openConfirmation()
        const button = within(dialog).getByRole('button', {
          name: label,
        })
        act(() => {
          fireEvent.click(button)
          fireEvent.click(button)
        })
        await waitFor(() =>
          expect(calls.filter((c) => c.method === 'post')).toHaveLength(1)
        )
        expect(button).toBeDisabled()
        expect(
          within(dialog).getByRole('button', { name: 'Cancel' })
        ).toBeDisabled()
        act(() => {
          if (change === 'unmount') cleanup()
          else if (change === 'logout') useAuthStore.getState().auth.reset()
          else if (change === 'new SID') login(1, 'replacement')
          else {
            login(2)
            if (change === 'A-B-A') login(1)
          }
        })
        await act(async () => finish?.())
        expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
        expect(screen.queryByText(unconfirmedMessage)).not.toBeInTheDocument()
        expect(calls.find((c) => c.method === 'post')?.signal?.aborted).toBe(
          true
        )
      }
    )

    test.each([
      { organization_id: '7' },
      { object_id: '7' },
      { generation: '2' },
      { revision: '9007199254740995' },
      { status: action === 'accept' ? 'declined' : 'accepted' },
      {
        action:
          action === 'accept' ? 'invitation_decline' : 'invitation_accept',
      },
      { action: `invite_${action}` },
      { object_kind: 'transfer' },
      { event_id: 123 },
    ])('action refuses mismatched receipt %j', async (patch) => {
      handler = async (config) => response(config, receipt(patch))
      await expect(
        command(
          1,
          'session-1',
          invitation() as Parameters<typeof command>[2],
          new AbortController().signal
        )
      ).rejects.toBeInstanceOf(OrganizationRequestFailure)
      expect(calls).toHaveLength(1)
    })

    test.each([
      { target_user_id: '2' },
      { expires_at: 1 },
      { organization_revision: '0' },
    ])('invalid selection sends nothing %j', async (patch) => {
      await expect(
        command(
          1,
          'session-1',
          { ...invitation(), ...patch } as Parameters<typeof command>[2],
          new AbortController().signal
        )
      ).rejects.toBeInstanceOf(OrganizationRequestFailure)
      expect(calls).toHaveLength(0)
    })

    test.each(['business failure', 'malformed receipt', 'network loss'])(
      '%s never declares success or replays the command even when refresh is empty',
      async (failure) => {
        let sent = false
        handler = async (config) => {
          if (config.method === 'post') {
            sent = true
            if (failure === 'network loss') {
              throw new AxiosError('private network detail')
            }
            return response(
              config,
              failure === 'business failure'
                ? {
                    success: false,
                    message: 'private business detail',
                    data: receipt().data,
                  }
                : { success: true, data: null }
            )
          }
          return response(config, page(sent ? [] : [invitation()]))
        }
        show()
        const dialog = await openConfirmation()
        await userEvent.click(
          within(dialog).getByRole('button', { name: label })
        )
        expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
        expect(
          await screen.findByText('No pending organization invitations')
        ).toBeVisible()
        expect(screen.queryByText(successMessage)).not.toBeInTheDocument()
        expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
        const error = client.getMutationCache().getAll()[0].state.error
        expect(error).toBeInstanceOf(OrganizationRequestFailure)
        expect(JSON.stringify(error)).not.toMatch(
          /fixture-1|private|Authorization|access_token/
        )
      }
    )

    test('a stale invitation expires while confirmation is open and sends no command', async () => {
      const expiresAt = Math.floor(Date.now() / 1000) + 60
      handler = async (config) =>
        response(config, page([{ ...invitation(), expires_at: expiresAt }]))
      show()
      const dialog = await openConfirmation()
      vi.spyOn(Date, 'now').mockReturnValue((expiresAt + 1) * 1000)
      await userEvent.click(within(dialog).getByRole('button', { name: label }))
      expect(await screen.findByText(unconfirmedMessage)).toBeVisible()
      expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
    })

    test.each(['en', 'zh', 'zh-TW', 'fr', 'ja', 'ru', 'vi'])(
      '%s translates action controls and confirmation using the shipped locale',
      async (locale) => {
        const resources = await import(`../../../i18n/locales/${locale}.json`)
        const translations = resources.default.translation
        language.addResourceBundle(locale, 'translation', translations)
        show()
        await screen.findByRole('button', { name: label })
        await act(async () => {
          await language.changeLanguage(locale)
        })
        await userEvent.click(
          screen.getByRole('button', { name: translations[label] })
        )
        const dialog = screen.getByRole('alertdialog', {
          name: translations[title],
        })
        expect(
          within(dialog).getByRole('button', {
            name: translations[label],
          })
        ).toBeVisible()
        expect(
          within(dialog).getByText(/<script>Invitation A<\/script>/)
        ).toBeVisible()
        expect(calls.filter((call) => call.method === 'post')).toHaveLength(0)
      }
    )
  }
)

test.each(['confirmed', 'lost'])(
  'acceptance with a %s response refreshes membership from the server',
  async (result) => {
    let joined = false
    handler = async (config) => {
      if (config.method === 'post') {
        joined = true
        if (result === 'lost') throw new AxiosError('response lost')
        return response(config, {
          success: true,
          data: {
            organization_id: invitation().organization_id,
            revision: '9007199254740996',
            action: 'invitation_accept',
            event_id: '9007199254740998',
            object_kind: 'invitation',
            object_id: invitation().object_id,
            generation: '1',
            status: 'accepted',
          },
        })
      }
      if (config.url === '/api/organizations') {
        return response(config, {
          success: true,
          data: {
            items: joined
              ? [
                  {
                    org_id: invitation().organization_id,
                    name: 'Joined organization',
                    my_role: 'member',
                  },
                ]
              : [],
            limit: 20,
            next_after_id: null,
          },
        })
      }
      return response(config, page(joined ? [] : [invitation()]))
    }
    show(true)
    expect(await screen.findByText('No accessible organizations')).toBeVisible()
    await userEvent.click(
      await screen.findByRole('button', { name: 'Accept invitation' })
    )
    expect(screen.queryByText('Joined organization')).not.toBeInTheDocument()
    await userEvent.click(
      within(screen.getByRole('alertdialog')).getByRole('button', {
        name: 'Accept invitation',
      })
    )
    expect(await screen.findByText('Joined organization')).toBeVisible()
    expect(
      await screen.findByText('No pending organization invitations')
    ).toBeVisible()
    if (result === 'lost') {
      expect(screen.getByText(/Acceptance was not confirmed/)).toBeVisible()
      expect(
        screen.queryByText(
          'Organization invitation accepted. You have joined the organization.'
        )
      ).not.toBeInTheDocument()
    } else {
      expect(
        screen.getByText(
          'Organization invitation accepted. You have joined the organization.'
        )
      ).toBeVisible()
    }
    expect(calls.filter((call) => call.method === 'post')).toHaveLength(1)
  }
)
