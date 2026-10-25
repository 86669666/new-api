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
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import {
  act,
  cleanup,
  render,
  renderHook,
  screen,
  waitFor,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createInstance, type i18n } from 'i18next'
import { useState } from 'react'
import { I18nextProvider } from 'react-i18next'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ChatPresetsItem } from '@/components/layout/components/chat-presets-item'
import { SidebarMenu, SidebarProvider } from '@/components/ui/sidebar'
import {
  BOXO_V2_TEMPLATE,
  BOXNAI_V2_TEMPLATE,
} from '@/features/chat/lib/chat-links'
import { api } from '@/lib/api'

import { SettingsPageProvider } from '../components/settings-page-context'
import { ChatSettingsSection } from '../content/chat-settings-section'
import { useUpdateOption } from '../hooks/use-update-option'

let testI18n: i18n

function Fixture(props: {
  value: string
  client?: QueryClient
  children?: React.ReactNode
}) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  const [client] = useState(
    () =>
      props.client ??
      new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  )
  return (
    <I18nextProvider i18n={testI18n}>
      <QueryClientProvider client={client}>
        <div ref={setContainer} />
        <SettingsPageProvider actionsContainer={container}>
          <ChatSettingsSection defaultValue={props.value} />
        </SettingsPageProvider>
        {props.children}
      </QueryClientProvider>
    </I18nextProvider>
  )
}

beforeEach(async () => {
  testI18n = createInstance()
  await testI18n.init({
    lng: 'en',
    fallbackLng: 'en',
    resources: { en: { translation: {} } },
    interpolation: { escapeValue: false },
  })
})

describe('Boxo chat preset', () => {
  it('adds the exact Boxo v2 template once from chat settings', async () => {
    const user = userEvent.setup()
    render(
      <Fixture value='[{"Cherry Studio":"cherrystudio://providers/api-keys?v=1&data={cherryConfig}"}]' />
    )
    expect(screen.getByText(BOXO_V2_TEMPLATE)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add Boxo preset' }))
    expect(screen.getByText('Boxo')).toBeInTheDocument()
    expect(screen.getAllByText(BOXO_V2_TEMPLATE)).toHaveLength(2)
    await user.click(screen.getByRole('button', { name: 'Add Boxo preset' }))
    expect(screen.getAllByText('Boxo')).toHaveLength(1)
  })

  it('keeps invalid chat JSON in place when Boxo cannot be added', async () => {
    const user = userEvent.setup()
    render(<Fixture value='not-json' />)
    await user.click(screen.getByRole('button', { name: 'Add Boxo preset' }))
    expect(screen.getByText('Invalid JSON string.')).toBeInTheDocument()
    expect(screen.queryByText('Boxo')).not.toBeInTheDocument()
  })
})

it('adds Boxnai once and preserves Cherry v1 and Boxo', async () => {
  const user = userEvent.setup()
  render(
    <Fixture
      value={JSON.stringify([
        {
          'Cherry Studio':
            'cherrystudio://providers/api-keys?v=1&data={cherryConfig}',
        },
        { Boxo: BOXO_V2_TEMPLATE },
      ])}
    />
  )
  await user.click(screen.getByRole('button', { name: 'Add Boxnai preset' }))
  await user.click(screen.getByRole('button', { name: 'Add Boxnai preset' }))
  expect(screen.getAllByText('Boxnai')).toHaveLength(1)
  expect(screen.getAllByText(BOXNAI_V2_TEMPLATE)).toHaveLength(2)
  expect(screen.getByText('Cherry Studio')).toBeInTheDocument()
  expect(screen.getByText('Boxo')).toBeInTheDocument()
})

it('preserves invalid JSON when adding Boxnai fails', async () => {
  const user = userEvent.setup()
  render(<Fixture value='not-json' />)
  await user.click(screen.getByRole('button', { name: 'Add Boxnai preset' }))
  expect(screen.getByText('Invalid JSON string.')).toBeInTheDocument()
  expect(screen.queryByText('Boxnai')).not.toBeInTheDocument()
})

const saveClients: QueryClient[] = []
afterEach(() => {
  cleanup()
  saveClients.splice(0).forEach((client) => client.clear())
  localStorage.removeItem('status')
})

async function mountSaveConsumer() {
  const initial = [{ Boxo: BOXO_V2_TEMPLATE }]
  const initialStatus = {
    chats: initial,
    server_address: 'https://gateway.example',
  }
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  saveClients.push(client)
  client.setQueryData(['status'], initialStatus)
  localStorage.setItem('status', JSON.stringify(initialStatus))
  let savedChats = initial
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
    if (url !== '/api/status') throw new Error('Unexpected request')
    return {
      data: { success: true, data: { ...initialStatus, chats: savedChats } },
    }
  })
  const put = vi.spyOn(api, 'put').mockImplementation(async (_url, body) => {
    savedChats = JSON.parse((body as { value: string }).value)
    return { data: { success: true } }
  })
  const root = createRootRoute({
    component: () => (
      <Fixture value={JSON.stringify(initial)} client={client}>
        <SidebarProvider defaultOpen={false}>
          <SidebarMenu>
            <ChatPresetsItem
              item={{ title: 'Clients', type: 'chat-presets' }}
            />
          </SidebarMenu>
        </SidebarProvider>
      </Fixture>
    ),
  })
  const router = createRouter({
    routeTree: root,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  await router.load()
  render(<RouterProvider router={router} />)
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  await screen.findByRole('menuitem', { name: 'Boxo' })
  expect(
    screen.queryByRole('menuitem', { name: 'Boxnai' })
  ).not.toBeInTheDocument()
  expect(get).not.toHaveBeenCalled()
  await user.keyboard('{Escape}')
  return { client, get, put, user, initialStatus }
}

it('publishes saved Chats to the already mounted client menu after Save without reloading', async () => {
  const { client, get, put, user } = await mountSaveConsumer()
  await user.click(screen.getByRole('button', { name: 'Add Boxnai preset' }))
  expect(put).not.toHaveBeenCalled()
  expect(get).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Save chat settings' }))
  await waitFor(() =>
    expect(put).toHaveBeenCalledExactlyOnceWith('/api/option/', {
      key: 'Chats',
      value: JSON.stringify([
        { Boxo: BOXO_V2_TEMPLATE },
        { Boxnai: BOXNAI_V2_TEMPLATE },
      ]),
    })
  )
  await user.click(screen.getByRole('button', { name: 'Clients' }))
  await screen.findByRole('menuitem', { name: 'Boxnai' })
  expect(screen.getByRole('menuitem', { name: 'Boxo' })).toBeInTheDocument()
  expect(get).toHaveBeenCalledExactlyOnceWith('/api/status')
  expect(client.getQueryData(['status'])).toEqual(
    expect.objectContaining({
      chats: [{ Boxo: BOXO_V2_TEMPLATE }, { Boxnai: BOXNAI_V2_TEMPLATE }],
    })
  )
  expect(JSON.parse(localStorage.getItem('status') ?? '{}').chats).toEqual([
    { Boxo: BOXO_V2_TEMPLATE },
    { Boxnai: BOXNAI_V2_TEMPLATE },
  ])
})

it.each(['network', 'business'] as const)(
  'does not publish unsaved Chats after a %s save failure',
  async (failure) => {
    const { client, get, put, user, initialStatus } = await mountSaveConsumer()
    await user.click(screen.getByRole('button', { name: 'Add Boxnai preset' }))
    if (failure === 'network') {
      put.mockRejectedValueOnce(new Error('Save unavailable'))
    } else {
      put.mockResolvedValueOnce({
        data: { success: false, message: 'Save unavailable' },
      })
    }
    // Await the actual mutation's rejection. The production form also uses
    // mutateAsync; no cache callback or mutation hook is replaced here.
    const mutation = renderHook(() => useUpdateOption(), {
      wrapper: ({ children }) => (
        <QueryClientProvider client={client}>{children}</QueryClientProvider>
      ),
    })
    await act(async () => {
      await expect(
        mutation.result.current.mutateAsync({
          key: 'Chats',
          value: JSON.stringify([
            { Boxo: BOXO_V2_TEMPLATE },
            { Boxnai: BOXNAI_V2_TEMPLATE },
          ]),
        })
      ).rejects.toBeDefined()
    })
    await user.click(screen.getByRole('button', { name: 'Clients' }))
    await screen.findByRole('menuitem', { name: 'Boxo' })
    expect(
      screen.queryByRole('menuitem', { name: 'Boxnai' })
    ).not.toBeInTheDocument()
    expect(put).toHaveBeenCalledTimes(1)
    expect(get).not.toHaveBeenCalled()
    expect(client.getQueryData(['status'])).toEqual(initialStatus)
    expect(JSON.parse(localStorage.getItem('status') ?? '{}')).toEqual(
      initialStatus
    )
  }
)
