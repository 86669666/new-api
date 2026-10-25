import { QueryClientProvider } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
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
import { useReactTable, getCoreRowModel } from '@tanstack/react-table'
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { SidebarMenu, SidebarProvider } from '@/components/ui/sidebar'
import {
  CHERRY_V2_TEMPLATE,
  BOXNAI_V2_TEMPLATE,
  CHERRY_V2_ERROR,
} from '@/features/chat/lib/chat-links'
import { ApiKeysProvider } from '@/features/keys/components/api-keys-provider'
import { DataTableRowActions } from '@/features/keys/components/data-table-row-actions'
import { api } from '@/lib/api'
import { createAppQueryClient } from '@/lib/query-client'
import { Route as ChatRoute } from '@/routes/_authenticated/chat/$chatId'
import { Route as Chat2LinkRoute } from '@/routes/_authenticated/chat2link'
import { useAuthStore } from '@/stores/auth-store'

import { ChatPresetsItem } from '../chat-presets-item'

const site = {
  instance_id: '12345678-1234-4234-8234-123456789abc',
  system_name: 'Fixture',
  server_address: 'https://gateway.example',
}
const clients: ReturnType<typeof createAppQueryClient>[] = []
function login(sid = 'fixture-session') {
  useAuthStore.getState().auth.setBundle({
    access_token: 'synthetic-dashboard',
    token_type: 'Bearer',
    access_expires_at: 9999999999,
    user: { id: 1, username: 'fixture', role: 1 },
    session: {
      sid,
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: 9999999999,
    },
  })
}
beforeEach(() => {
  login()
  localStorage.clear()
  vi.spyOn(window, 'open').mockReturnValue(null)
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
})
afterEach(() => {
  cleanup()
  clients.splice(0).forEach((client) => client.clear())
  useAuthStore.getState().auth.reset()
  localStorage.clear()
})

function KeyRows() {
  const table = useReactTable({
    data: [7, 9].map((id) => ({
      id,
      name: `Key ${id}`,
      key: 'masked',
      status: 1,
      remain_quota: 100,
      used_quota: 0,
      unlimited_quota: false,
      expired_time: -1,
      created_time: 1,
      accessed_time: 1,
      group: 'named',
      model_limits_enabled: false,
    })),
    columns: [],
    getCoreRowModel: getCoreRowModel(),
  })
  return (
    <ApiKeysProvider>
      {table.getRowModel().rows.map((row) => (
        <div key={row.id} aria-label={`Key ${row.original.id}`}>
          <DataTableRowActions row={row} />
        </div>
      ))}
    </ApiKeysProvider>
  )
}

async function mount(presets: Array<Record<string, string>>, entry = '/test') {
  const client = createAppQueryClient()
  clients.push(client)
  const status = { ...site, chats: presets }
  client.setQueryData(['status'], status)
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
    if (url === '/api/status') return { data: { success: true, data: status } }
    if (url.startsWith('/api/token/?') || url === '/api/token/') {
      return {
        data: {
          success: true,
          data: {
            items: [
              { id: 4, status: 2 },
              { id: 7, status: 1 },
              { id: 9, status: 1 },
            ],
          },
        },
      }
    }
    if (url === '/api/token/7' || url === '/api/token/9') {
      return {
        data: {
          success: true,
          data: {
            id: Number(url.split('/').at(-1)),
            status: 1,
            expired_time: -1,
            group: 'named',
          },
        },
      }
    }
    throw new Error('unexpected network')
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { key: 'synthetic-only' } },
  })
  const root = createRootRoute()
  const auth = createRoute({ getParentRoute: () => root, id: '_authenticated' })
  const sidebar = createRoute({
    getParentRoute: () => auth,
    path: 'test',
    component: () => (
      <SidebarProvider defaultOpen={false}>
        <SidebarMenu>
          <ChatPresetsItem item={{ title: 'Clients', type: 'chat-presets' }} />
        </SidebarMenu>
      </SidebarProvider>
    ),
  })
  const chat = createRoute({
    getParentRoute: () => auth,
    path: 'chat/$chatId',
    component: ChatRoute.options.component,
  })
  const automatic = createRoute({
    getParentRoute: () => auth,
    path: 'chat2link',
    component: Chat2LinkRoute.options.component,
  })
  const keys = createRoute({
    getParentRoute: () => auth,
    path: 'keys',
    component: () => <div>Select a key fixture</div>,
  })
  const keyActions = createRoute({
    getParentRoute: () => auth,
    path: 'key-actions',
    component: KeyRows,
  })
  const router = createRouter({
    routeTree: root.addChildren([
      auth.addChildren([sidebar, chat, automatic, keys, keyActions]),
    ]),
    history: createMemoryHistory({ initialEntries: [entry] }),
  })
  await router.load()
  const view = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { ...view, client, get, post }
}

it.each(['/chat2link', '/chat/0'])(
  'blocks a mixed HTTPS v2 template in the actual %s consumer before key access',
  async (entry) => {
    const { get, post } = await mount(
      [{ Malicious: 'https://evil.example/?key={key}&data={cherryConfigV2}' }],
      entry
    )
    if (entry.startsWith('/chat/')) {
      await screen.findByText('Use sidebar shortcut')
    } else {
      await screen.findByText('Redirecting to chat page...')
    }
    expect(
      get.mock.calls.some((call) => call[0].startsWith('/api/token/'))
    ).toBe(false)
    expect(post).not.toHaveBeenCalled()
    expect(document.querySelector('iframe')).toBeNull()
    expect(window.open).not.toHaveBeenCalled()
  }
)

it('does not fetch a key when a valid v2 preset is visited directly as a chat route', async () => {
  const { post } = await mount([{ Cherry: CHERRY_V2_TEMPLATE }], '/chat/0')
  await screen.findByText('Use sidebar shortcut')
  expect(post).not.toHaveBeenCalled()
  expect(document.querySelector('iframe')).toBeNull()
})

it('preserves the actual legacy web chat iframe and its selected first-enabled key', async () => {
  const { post } = await mount(
    [{ Legacy: 'https://legacy.example/?key={key}' }],
    '/chat/0'
  )
  await waitFor(() =>
    expect(document.querySelector('iframe')?.getAttribute('src')).toBe(
      'https://legacy.example/?key=sk-synthetic-only'
    )
  )
  expect(post).toHaveBeenCalledExactlyOnceWith('/api/token/7/key')
})

it('only reveals after explicit activation and excludes synchronous duplicate activation', async () => {
  const user = userEvent.setup()
  const { get, post } = await mount([{ Cherry: CHERRY_V2_TEMPLATE }])
  expect(post).not.toHaveBeenCalled()
  let release!: (value: {
    data: { success: boolean; data: typeof site }
  }) => void
  const gate = new Promise<{ data: { success: boolean; data: typeof site } }>(
    (resolve) => {
      release = resolve
    }
  )
  const original = get.getMockImplementation()
  if (!original) {
    throw new Error('Expected API mock implementation')
  }
  get.mockImplementation(async (...args) =>
    args[0] === '/api/status' ? gate : original(...args)
  )
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  const item = await screen.findByRole('menuitem', { name: 'Cherry' })
  act(() => {
    fireEvent.click(item)
    fireEvent.click(item)
  })
  expect(post).not.toHaveBeenCalled()
  await act(async () => {
    release({ data: { success: true, data: site } })
    await gate
  })
  await waitFor(() => expect(window.open).toHaveBeenCalledTimes(1))
  expect(post).toHaveBeenCalledExactlyOnceWith(
    '/api/token/7/key',
    undefined,
    expect.any(Object)
  )
  const opened = String(vi.mocked(window.open).mock.calls[0][0])
  expect(opened.startsWith('cherrystudio://providers/api-keys?v=2&data=')).toBe(
    true
  )
  expect(document.body.textContent).not.toContain('synthetic-only')
  expect(JSON.stringify(localStorage)).not.toContain('synthetic-only')
})

it.each(['session', 'unmount'])(
  'discards a key already in flight after %s and never opens the client',
  async (change) => {
    const user = userEvent.setup()
    const { post, unmount } = await mount([{ Cherry: CHERRY_V2_TEMPLATE }])
    let release!: (value: {
      data: { success: boolean; data: { key: string } }
    }) => void
    const gate = new Promise<{
      data: { success: boolean; data: { key: string } }
    }>((resolve) => {
      release = resolve
    })
    post.mockReturnValueOnce(gate)
    await user.click(screen.getByRole('button', { name: 'Clients' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Cherry' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    act(() => {
      if (change === 'unmount') unmount()
      else login('replacement-session')
    })
    await act(async () => {
      release({ data: { success: true, data: { key: 'obsolete-synthetic' } } })
      await gate
    })
    expect(window.open).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain('obsolete-synthetic')
  }
)

it('cancels before reveal when the account changes during the fresh status read', async () => {
  const user = userEvent.setup()
  const { get, post } = await mount([{ Cherry: CHERRY_V2_TEMPLATE }])
  let release!: (value: {
    data: { success: boolean; data: typeof site }
  }) => void
  const gate = new Promise<{ data: { success: boolean; data: typeof site } }>(
    (resolve) => {
      release = resolve
    }
  )
  get.mockReturnValueOnce(gate)
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Cherry' }))
  act(() =>
    useAuthStore.getState().auth.setUser({ id: 2, username: 'other', role: 1 })
  )
  await act(async () => {
    release({ data: { success: true, data: site } })
    await gate
  })
  expect(post).not.toHaveBeenCalled()
  expect(window.open).not.toHaveBeenCalled()
})

it('shows only a fixed failure with a real mounted status observer and app QueryCache', async () => {
  const user = userEvent.setup()
  const { get, post } = await mount([{ Cherry: CHERRY_V2_TEMPLATE }])
  const error = vi.spyOn(toast, 'error')
  const log = vi.spyOn(console, 'error').mockImplementation(() => {})
  get.mockRejectedValueOnce({
    response: { data: { message: 'SENSITIVE-SERVER-CANARY' } },
    cause: new Error('SENSITIVE-SERVER-CANARY'),
  })
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Cherry' }))
  await waitFor(() => expect(error).toHaveBeenCalledWith(CHERRY_V2_ERROR))
  expect(JSON.stringify(error.mock.calls)).not.toContain(
    'SENSITIVE-SERVER-CANARY'
  )
  expect(JSON.stringify(log.mock.calls)).not.toContain(
    'SENSITIVE-SERVER-CANARY'
  )
  expect(document.body.textContent).not.toContain('SENSITIVE-SERVER-CANARY')
  expect(post).not.toHaveBeenCalled()
  expect(window.open).not.toHaveBeenCalled()
})

it('requires user selection on the keys page instead of exporting the first token from the Boxnai sidebar', async () => {
  const user = userEvent.setup()
  const { get, post } = await mount([{ Boxnai: BOXNAI_V2_TEMPLATE }])
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Boxnai' }))
  await screen.findByText('Select a key fixture')
  expect(get.mock.calls.some((call) => call[0].startsWith('/api/token/'))).toBe(
    false
  )
  expect(post).not.toHaveBeenCalled()
  expect(window.open).not.toHaveBeenCalled()
})

it.each(['/chat/0', '/chat2link'])(
  'never automatically exports or launches Boxnai on %s',
  async (entry) => {
    const { get, post } = await mount([{ Boxnai: BOXNAI_V2_TEMPLATE }], entry)
    await screen.findByText(
      entry === '/chat/0'
        ? 'Use sidebar shortcut'
        : 'Redirecting to chat page...'
    )
    expect(
      get.mock.calls.some((call) => call[0].startsWith('/api/token/'))
    ).toBe(false)
    expect(post).not.toHaveBeenCalled()
    expect(window.open).not.toHaveBeenCalled()
  }
)

it('exports the selected second row to Boxnai only after its explicit menu action', async () => {
  const user = userEvent.setup()
  const { post } = await mount([{ Boxnai: BOXNAI_V2_TEMPLATE }], '/key-actions')
  expect(post).not.toHaveBeenCalled()
  const row = await screen.findByLabelText('Key 9')
  await user.click(
    row.querySelector('button[aria-label="Open menu"]') as HTMLButtonElement
  )
  const chat = await screen.findByRole('menuitem', { name: 'Chat' })
  act(() => chat.focus())
  await user.keyboard('{ArrowRight}')
  const boxnai = await screen.findByRole('menuitem', { name: 'Boxnai' })
  act(() => boxnai.focus())
  await user.keyboard('{Enter}')
  await waitFor(() => expect(window.open).toHaveBeenCalledTimes(1))
  expect(post).toHaveBeenCalledExactlyOnceWith(
    '/api/token/9/key',
    undefined,
    expect.any(Object)
  )
  expect(String(vi.mocked(window.open).mock.calls[0][0])).toMatch(
    /^boxnai:\/\/providers\/api-keys\?v=2&data=[A-Za-z0-9_-]+$/
  )
  expect(document.body.textContent).not.toContain('synthetic-only')
  expect(JSON.stringify(localStorage)).not.toContain('synthetic-only')
})

it.each(['session', 'unmount'])(
  'discards selected Boxnai export after %s while reveal is in flight',
  async (change) => {
    const user = userEvent.setup()
    const { post, unmount } = await mount(
      [{ Boxnai: BOXNAI_V2_TEMPLATE }],
      '/key-actions'
    )
    let release!: (value: {
      data: { success: boolean; data: { key: string } }
    }) => void
    const gate = new Promise<{
      data: { success: boolean; data: { key: string } }
    }>((resolve) => {
      release = resolve
    })
    post.mockReturnValueOnce(gate)
    const row = await screen.findByLabelText('Key 9')
    await user.click(
      row.querySelector('button[aria-label="Open menu"]') as HTMLButtonElement
    )
    const chat = await screen.findByRole('menuitem', { name: 'Chat' })
    act(() => chat.focus())
    await user.keyboard('{ArrowRight}')
    const boxnai = await screen.findByRole('menuitem', { name: 'Boxnai' })
    act(() => boxnai.focus())
    await user.keyboard('{Enter}')
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    act(() => {
      if (change === 'unmount') unmount()
      else login('new-session')
    })
    await act(async () => {
      release({ data: { success: true, data: { key: 'obsolete-synthetic' } } })
      await gate
    })
    expect(window.open).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain('obsolete-synthetic')
    expect(JSON.stringify(localStorage)).not.toContain('obsolete-synthetic')
  }
)
