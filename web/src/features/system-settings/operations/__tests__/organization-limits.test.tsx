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
  Link,
  RouterProvider,
} from '@tanstack/react-router'
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AxiosError,
  AxiosHeaders,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import { useState } from 'react'
import { afterEach, beforeEach, expect, test } from 'vitest'

import { api } from '@/lib/http-client'
import { useAuthStore } from '@/stores/auth-store'

import { SettingsPageProvider } from '../../components/settings-page-context'
import { OrganizationLimitsSection } from '../organization-limits-section'

const readPath = '/api/organizations/limits'
const writePath = '/api/option/organization_limits'
const ownedLabel = 'Maximum owned organizations per user'
const joinedLabel = 'Maximum joined organizations per user'
const oldAdapter = api.defaults.adapter
let reads = 0
let writes: unknown[] = []
let handler: (config: InternalAxiosRequestConfig) => Promise<AxiosResponse>

function response(
  config: InternalAxiosRequestConfig,
  data: unknown,
  status = 200
): Promise<AxiosResponse> {
  const value = {
    data,
    status,
    statusText: String(status),
    config,
    headers: new AxiosHeaders(),
  }
  if (status >= 400) {
    return Promise.reject(
      new AxiosError('Request failed', undefined, config, undefined, value)
    )
  }
  return Promise.resolve(value)
}

function limits(created = 30, joined = 40) {
  return {
    success: true,
    data: {
      max_organizations_created: created,
      max_organizations_joined: joined,
    },
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

function Fixture() {
  const [actions, setActions] = useState<HTMLDivElement | null>(null)
  const [status, setStatus] = useState<HTMLSpanElement | null>(null)
  return (
    <>
      <div ref={setActions} />
      <span ref={setStatus} />
      <SettingsPageProvider
        actionsContainer={actions}
        titleStatusContainer={status}
      >
        <OrganizationLimitsSection />
      </SettingsPageProvider>
      <Link to='/about'>Another page</Link>
    </>
  )
}

async function setup() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const root = createRootRoute({ component: Fixture })
  const other = createRoute({ getParentRoute: () => root, path: '/about' })
  const router = createRouter({
    routeTree: root.addChildren([
      createRoute({ getParentRoute: () => root, path: '/' }),
      other,
    ]),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { client, router }
}

beforeEach(() => {
  reads = 0
  writes = []
  useAuthStore.getState().auth.setBundle({
    access_token: 'test-session',
    token_type: 'Bearer',
    access_expires_at: Date.now() / 1000 + 3600,
    user: { id: 1, username: 'root', role: 100 },
    session: {
      sid: 'limits-test',
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: Date.now() / 1000 + 3600,
    },
  })
  handler = (config) =>
    response(config, config.method === 'put' ? { success: true } : limits())
  // Keep the real HTTP client, interceptors and deduplication. Only transport is replaced.
  api.defaults.adapter = async (config) => {
    if (config.url === readPath) reads++
    if (config.url === writePath) writes.push(JSON.parse(String(config.data)))
    return handler(config)
  }
})
afterEach(() => {
  api.defaults.adapter = oldAdapter
  useAuthStore.getState().auth.reset()
})

test.each(['', '01', '-1', '1e0', '9007199254740992'])(
  'invalid canonical input %s has an accessible error and sends no PUT',
  async (text) => {
    await setup()
    const input = await screen.findByRole('textbox', { name: ownedLabel })
    await waitFor(() => expect(input).toHaveValue('30'))
    fireEvent.change(input, { target: { value: text } })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() => expect(input).toHaveAttribute('aria-invalid', 'true'))
    expect(writes).toHaveLength(0)
  }
)

test('zero and safe-integer maximum are submitted once as complete strings', async () => {
  handler = (config) =>
    response(
      config,
      config.method === 'put'
        ? { success: true }
        : limits(reads > 1 ? 0 : 30, reads > 1 ? Number.MAX_SAFE_INTEGER : 40)
    )
  await setup()
  const owned = await screen.findByRole('textbox', { name: ownedLabel })
  await waitFor(() => expect(owned).toHaveValue('30'))
  fireEvent.change(owned, { target: { value: '0' } })
  fireEvent.change(screen.getByRole('textbox', { name: joinedLabel }), {
    target: { value: '9007199254740991' },
  })
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
  await waitFor(() =>
    expect(writes).toEqual([
      {
        max_organizations_created: '0',
        max_organizations_joined: '9007199254740991',
      },
    ])
  )
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
  )
  expect(owned).toHaveValue('0')
})

test.each([
  {},
  { max_organizations_created: 0 },
  { max_organizations_created: null, max_organizations_joined: 0 },
  { max_organizations_created: '0', max_organizations_joined: 0 },
  { max_organizations_created: -1, max_organizations_joined: 0 },
])('unknown wire policy %j never defaults to unlimited', async (data) => {
  handler = (config) => response(config, { success: true, data })
  await setup()
  expect(
    await screen.findByText('Organization limits are unavailable.')
  ).toBeInTheDocument()
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  expect(writes).toHaveLength(0)
})

test.each([200, 404, 503])(
  'failed GET %s shows unavailable instead of a zero form',
  async (status) => {
    handler = (config) =>
      response(config, { success: false, message: 'Unavailable' }, status)
    await setup()
    expect(
      await screen.findByText('Organization limits are unavailable.')
    ).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  }
)

test('a changed background response preserves dirty edits and navigation cancel', async () => {
  const { client, router } = await setup()
  const input = await screen.findByRole('textbox', { name: ownedLabel })
  await waitFor(() => expect(input).toHaveValue('30'))
  fireEvent.change(input, { target: { value: '55' } })
  handler = (config) => response(config, limits(70, 80))
  await act(() =>
    client.invalidateQueries({ queryKey: ['organization-limits'] })
  )
  expect(input).toHaveValue('55')
  await userEvent.click(screen.getByRole('link', { name: 'Another page' }))
  const dialog = await screen.findByRole('alertdialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Stay' }))
  expect(router.state.location.pathname).toBe('/')
  expect(input).toHaveValue('55')
  expect(writes).toHaveLength(0)
})

test('post-save GET bypasses an older Axios-deduplicated GET and resets to new authoritative values', async () => {
  const { client } = await setup()
  const input = await screen.findByRole('textbox', { name: ownedLabel })
  await waitFor(() => expect(input).toHaveValue('30'))
  const old = deferred<AxiosResponse>()
  let oldConfig: InternalAxiosRequestConfig | undefined
  const put = deferred<AxiosResponse>()
  let putConfig: InternalAxiosRequestConfig | undefined
  const events: string[] = []
  handler = (config) => {
    if (config.method === 'put') {
      events.push('put')
      putConfig = config
      return put.promise
    }
    if (!oldConfig) {
      oldConfig = config
      events.push('old-get')
      return old.promise
    }
    events.push('new-get')
    return response(config, limits(90, 91))
  }
  const pendingOld = api.get(readPath)
  await waitFor(() => expect(oldConfig).toBeDefined())
  fireEvent.change(input, { target: { value: '45' } })
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
  await waitFor(() => expect(putConfig).toBeDefined())
  expect(input).toBeDisabled()
  expect(screen.getByRole('textbox', { name: joinedLabel })).toBeDisabled()
  expect(events).toEqual(['old-get', 'put'])
  if (!putConfig || !oldConfig) throw new Error('Expected pending requests')
  put.resolve(await response(putConfig, { success: true }))
  await waitFor(() => expect(input).toHaveValue('90'))
  expect(events).toEqual(['old-get', 'put', 'new-get'])
  // Refetch while the unrelated deduplicated GET is still pending must also
  // perform a fresh transport read, rather than resubscribing to its old promise.
  act(() => {
    void client.invalidateQueries({ queryKey: ['organization-limits'] })
  })
  await waitFor(() =>
    expect(events).toEqual(['old-get', 'put', 'new-get', 'new-get'])
  )
  expect(input).toHaveValue('90')
  old.resolve(await response(oldConfig, limits(30, 40)))
  await act(() => pendingOld)
  expect(input).toHaveValue('90')
  expect(screen.getByRole('textbox', { name: joinedLabel })).toHaveValue('91')
  expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
  expect(writes).toHaveLength(1)
})

test('save success followed by failed authoritative GET keeps dirty edits until explicit reload', async () => {
  await setup()
  const input = await screen.findByRole('textbox', { name: ownedLabel })
  await waitFor(() => expect(input).toHaveValue('30'))
  fireEvent.change(input, { target: { value: '52' } })
  handler = (config) =>
    response(
      config,
      config.method === 'put' ? { success: true } : { success: false },
      config.method === 'put' ? 200 : 503
    )
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
  expect(
    await screen.findByText(
      'Saved, but refreshing settings failed. Your edits are kept until you reload saved limits.'
    )
  ).toBeInTheDocument()
  expect(input).toHaveValue('52')
  expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
  const before = reads
  await userEvent.click(
    screen.getAllByRole('button', { name: 'Reload saved limits' })[0]
  )
  await userEvent.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Cancel',
    })
  )
  expect(reads).toBe(before)
  expect(input).toHaveValue('52')
  handler = (config) => response(config, limits(53, 54))
  await userEvent.click(
    screen.getAllByRole('button', { name: 'Reload saved limits' })[0]
  )
  await userEvent.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Reload saved limits',
    })
  )
  await waitFor(() => expect(input).toHaveValue('53'))
  expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument()
  expect(writes).toHaveLength(1)
})

test.each(['timeout', '503', '401', 'business'])(
  'uncertain PUT %s is never replayed and retains the draft',
  async (failure) => {
    await setup()
    const input = await screen.findByRole('textbox', { name: ownedLabel })
    await waitFor(() => expect(input).toHaveValue('30'))
    fireEvent.change(input, { target: { value: '60' } })
    const calls: string[] = []
    handler = (config) => {
      calls.push(config.url ?? '')
      if (failure === 'timeout') {
        return Promise.reject(new AxiosError('timeout', 'ECONNABORTED', config))
      }
      return response(
        config,
        { success: false },
        failure === 'business' ? 200 : Number(failure)
      )
    }
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(
      await screen.findByText(
        'The save result is uncertain. Reload saved limits before trying again; your edits have been kept.'
      )
    ).toBeInTheDocument()
    expect(calls).toEqual([writePath])
    expect(writes).toHaveLength(1)
    expect(input).toHaveValue('60')
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
  }
)

test('nonroot cannot load or edit the root limits form', async () => {
  useAuthStore.getState().auth.setUser({ id: 2, username: 'member', role: 1 })
  await setup()
  expect(
    await screen.findByText(
      'A root dashboard session is required to manage organization limits.'
    )
  ).toBeInTheDocument()
  expect(reads).toBe(0)
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
})

test('loading stays unknown and labeled inputs support keyboard focus and discard', async () => {
  const ready = deferred<AxiosResponse>()
  let config: InternalAxiosRequestConfig | undefined
  handler = (request) => {
    config = request
    return ready.promise
  }
  await setup()
  expect(
    await screen.findByText('Loading organization limits...')
  ).toBeInTheDocument()
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  await waitFor(() => expect(config).toBeDefined())
  if (!config) throw new Error('Expected loading request')
  ready.resolve(await response(config, limits()))
  const input = await screen.findByRole('textbox', { name: ownedLabel })
  await waitFor(() => expect(input).toHaveValue('30'))
  input.focus()
  await userEvent.keyboard('{Control>}a{/Control}66')
  expect(input).toHaveValue('66')
  await userEvent.tab()
  expect(screen.getByRole('textbox', { name: joinedLabel })).toHaveFocus()
  handler = (request) => response(request, limits())
  await userEvent.click(
    screen.getByRole('button', { name: 'Reload saved limits' })
  )
  await userEvent.click(
    within(await screen.findByRole('alertdialog')).getByRole('button', {
      name: 'Reload saved limits',
    })
  )
  await waitFor(() => expect(input).toHaveValue('30'))
  expect(writes).toHaveLength(0)
})
