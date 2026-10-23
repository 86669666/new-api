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
  Outlet,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { Profiler } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'
import { formatQuota } from '@/lib/format'
import { useAuthStore } from '@/stores/auth-store'
import { useSystemConfigStore } from '@/stores/system-config-store'

import { Dashboard } from '..'
import { getUserQuotaDates } from '../api'
import { LogStatCards } from '../components/models/log-stat-cards'
import { SummaryCards } from '../components/overview/summary-cards'

// jsdom cannot render the third-party canvas. Parent, stat cards, chart
// components and processing stay real; only the external renderer is replaced.
vi.mock('@visactor/react-vchart', () => ({
  VChart: () => <div role='img' aria-label='Usage chart' />,
}))
vi.mock('@visactor/vchart', () => ({
  ThemeManager: { setCurrentTheme: vi.fn() },
}))

const params = { start_timestamp: 1700000000, end_timestamp: 1700003600 }
const rows = [
  { created_at: 1700000000, quota: 250000, count: 2, token_used: 15 },
]
const invalidMeasurements = (['quota', 'count', 'token_used'] as const).flatMap(
  (field) => {
    const { [field]: _missing, ...otherMeasurements } = rows[0]
    return [
      { name: `missing ${field}`, row: otherMeasurements },
      { name: `null ${field}`, row: { ...rows[0], [field]: null } },
    ]
  }
)
const current = {
  success: true,
  data: rows,
  granularity: 'hour',
  quota_per_unit: 123456.75,
  data_complete: false,
  enable_data_export: true,
}
const offText = 'Collection is off; saved history may still be shown.'
const incompleteText = 'Historical usage may be incomplete.'
const unknownText = 'Historical usage completeness is unknown.'
const clients: QueryClient[] = []
const getAnimationsDescriptor = Object.getOwnPropertyDescriptor(
  Element.prototype,
  'getAnimations'
)

function identity(id = 1, sid = 'session-1', role = 1) {
  useAuthStore.getState().auth.setBundle({
    access_token: 'fixture-access',
    token_type: 'Bearer',
    access_expires_at: 2000000000,
    user: {
      id,
      username: `user-${id}`,
      role,
      quota: 1000000,
      used_quota: 100,
      request_count: 3,
    },
    session: {
      sid,
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: 2000000000,
    },
  })
}

function deferred() {
  let resolve!: (value: { data: unknown }) => void
  const promise = new Promise<{ data: unknown }>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

function renderSummary() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  clients.push(client)
  const router = createRouter({
    routeTree: createRootRoute({ component: SummaryCards }),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  return {
    ...render(
      <QueryClientProvider client={client}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    ),
    client,
  }
}

async function renderModelDashboard() {
  vi.spyOn(window, 'scrollTo').mockImplementation(() => {})
  const frames: string[] = []
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  clients.push(client)
  const root = createRootRoute({ component: Outlet })
  const authenticated = createRoute({
    getParentRoute: () => root,
    id: '_authenticated',
    component: Outlet,
  })
  const models = createRoute({
    getParentRoute: () => authenticated,
    path: 'dashboard/$section',
    component: () => (
      <Profiler
        id='model-dashboard'
        onRender={() => {
          frames.push(document.body.textContent ?? '')
        }}
      >
        <Dashboard />
      </Profiler>
    ),
  })
  const router = createRouter({
    routeTree: root.addChildren([authenticated.addChildren([models])]),
    history: createMemoryHistory({ initialEntries: ['/dashboard/models'] }),
  })
  await router.load()
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { frames }
}

async function applyModelFilters(changeRange = false) {
  fireEvent.click(screen.getByRole('button', { name: 'Filter' }))
  const dialog = await screen.findByRole('dialog')
  if (changeRange) {
    fireEvent.click(within(dialog).getByRole('button', { name: '7 Days' }))
  }
  fireEvent.click(within(dialog).getByRole('button', { name: 'Apply Filters' }))
}

function renderHourlyCards(view: 'log' | 'summary') {
  if (view === 'summary') {
    const { client } = renderSummary()
    return {
      updated: undefined,
      refresh: () =>
        client.refetchQueries({
          queryKey: ['dashboard', 'overview', 'summary-sparklines'],
        }),
    }
  }
  const updated = vi.fn()
  const filters = {
    start_timestamp: new Date(1700000000000),
    end_timestamp: new Date(1700003600000),
  }
  const mounted = render(
    <LogStatCards filters={filters} onDataUpdate={updated} />
  )
  return {
    updated,
    refresh: () =>
      mounted.rerender(
        <LogStatCards filters={{ ...filters }} onDataUpdate={updated} />
      ),
  }
}

beforeEach(() => {
  Object.defineProperty(Element.prototype, 'getAnimations', {
    configurable: true,
    value: () => [],
  })
  window.localStorage.clear()
  useAuthStore.setState(useAuthStore.getInitialState(), true)
  useSystemConfigStore.setState(useSystemConfigStore.getInitialState(), true)
  identity()
})

afterEach(() => {
  cleanup()
  if (getAnimationsDescriptor) {
    Object.defineProperty(
      Element.prototype,
      'getAnimations',
      getAnimationsDescriptor
    )
  } else {
    Reflect.deleteProperty(Element.prototype, 'getAnimations')
  }
  clients.splice(0).forEach((client) => client.clear())
  vi.restoreAllMocks()
  useAuthStore.setState(useAuthStore.getInitialState(), true)
  useSystemConfigStore.setState(useSystemConfigStore.getInitialState(), true)
  window.localStorage.clear()
})

describe('personal hourly series response contract', () => {
  it('retains raw quota and a nondefault quota unit without converting records', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: current })
    const result = await getUserQuotaDates(params)
    expect(result.data).toEqual(rows)
    expect(result.quota_per_unit).toBe(123456.75)
    expect(result.data_complete).toBe(false)
    expect(result.enable_data_export).toBe(true)
  })

  it('binds the existing request to actor and SID with its own cancellation signal', async () => {
    const request = vi.spyOn(api, 'get').mockResolvedValue({ data: current })
    const controller = new AbortController()
    await getUserQuotaDates(params, false, controller.signal)
    expect(request).toHaveBeenCalledWith(
      '/api/data/self',
      expect.objectContaining({
        signal: controller.signal,
        disableDuplicate: true,
        expectedAuthIdentity: { userId: 1, sid: 'session-1' },
      })
    )
  })

  it('rejects a result if its request identity changed before completion', async () => {
    const pending = deferred()
    vi.spyOn(api, 'get').mockReturnValue(pending.promise)
    const result = getUserQuotaDates(params)
    identity(2, 'new-session')
    pending.resolve({ data: current })
    await expect(result).rejects.toMatchObject({ name: 'AbortError' })
  })

  it('accepts a legacy array without fabricating collection or completeness', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({
      data: { success: true, data: rows },
    })
    const result = await getUserQuotaDates(params)
    expect(result.data).toEqual(rows)
    expect(result.enable_data_export).toBeUndefined()
    expect(result.data_complete).toBeUndefined()
  })

  it.each([
    ['missing data', { success: true }],
    ['null data', { ...current, data: null }],
    ['invalid row', { ...current, data: [{ created_at: '1700000000' }] }],
    ['false success', { ...current, success: false }],
    ['string collection switch', { ...current, enable_data_export: 'false' }],
    ['incorrect completeness', { ...current, data_complete: true }],
    ['invalid granularity', { ...current, granularity: 'day' }],
    ['zero quota unit', { ...current, quota_per_unit: 0 }],
    ['nonfinite quota unit', { ...current, quota_per_unit: Infinity }],
  ])(
    'rejects %s instead of accepting an empty or misleading success',
    async (_name, data) => {
      vi.spyOn(api, 'get').mockResolvedValue({ data })
      await expect(getUserQuotaDates(params)).rejects.toThrow()
    }
  )

  it.each(invalidMeasurements)(
    'rejects a payload containing $name without filtering its row',
    async ({ row }) => {
      vi.spyOn(api, 'get').mockResolvedValue({
        data: { ...current, data: [rows[0], row] },
      })
      await expect(getUserQuotaDates(params)).rejects.toThrow()
    }
  )

  it.each(['quota', 'count', 'token_used'] as const)(
    'rejects nonfinite %s measurements',
    async (field) => {
      vi.spyOn(api, 'get').mockResolvedValue({
        data: { ...current, data: [{ ...rows[0], [field]: Infinity }] },
      })
      await expect(getUserQuotaDates(params)).rejects.toThrow()
    }
  )

  it('preserves previously accepted finite numeric boundaries without coercion', async () => {
    const data = [{ ...rows[0], quota: -0.5, count: 0.5, token_used: 0 }]
    vi.spyOn(api, 'get').mockResolvedValue({ data: { ...current, data } })
    expect((await getUserQuotaDates(params)).data).toEqual(data)
  })

  it('keeps the admin array contract independent of personal metadata', async () => {
    const request = vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: [{ created_at: rows[0].created_at }],
        enable_data_export: 'not-personal',
      },
    })
    const result = await getUserQuotaDates(params, true)
    expect(result.data).toEqual([{ created_at: rows[0].created_at }])
    expect(request.mock.calls[0]?.[0]).toBe('/api/data')
  })
})

describe('hourly usage cards', () => {
  it.each([
    ['collection on', current, incompleteText],
    [
      'collection off with history',
      { ...current, enable_data_export: false },
      offText,
    ],
    [
      'collection off with no history',
      { ...current, data: [], enable_data_export: false },
      offText,
    ],
    ['legacy metadata', { success: true, data: rows }, unknownText],
  ])('shows %s without losing valid records', async (_name, data, notice) => {
    vi.spyOn(api, 'get').mockResolvedValue({ data })
    const updated = vi.fn()
    render(<LogStatCards onDataUpdate={updated} />)
    await screen.findByText(notice)
    expect(updated).toHaveBeenLastCalledWith(data.data, false)
    if (data.data.length === 0) {
      expect(screen.getAllByText('--')).toHaveLength(5)
    }
    expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
  })

  it('shows an error for null data without publishing a successful empty chart', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: { ...current, data: null } })
    const updated = vi.fn()
    render(<LogStatCards onDataUpdate={updated} />)
    await screen.findByText('Failed to load')
    expect(updated).not.toHaveBeenCalledWith([], false)
  })

  it('does not apply the personal collection banner to admin data', async () => {
    identity(1, 'session-1', 10)
    vi.spyOn(api, 'get').mockResolvedValue({
      data: { success: true, data: rows },
    })
    const updated = vi.fn()
    render(<LogStatCards onDataUpdate={updated} />)
    await waitFor(() => expect(updated).toHaveBeenLastCalledWith(rows, false))
    expect(screen.queryByText(offText)).not.toBeInTheDocument()
    expect(screen.queryByText(unknownText)).not.toBeInTheDocument()
  })

  it.each(['actor', 'SID', 'filters'])(
    'ignores a late response after the %s changes',
    async (change) => {
      const first = deferred(),
        second = deferred()
      const request = vi
        .spyOn(api, 'get')
        .mockReturnValueOnce(first.promise)
        .mockReturnValueOnce(second.promise)
      const updated = vi.fn()
      const filters = {
        start_timestamp: new Date(1700000000000),
        end_timestamp: new Date(1700003600000),
      }
      const view = render(
        <LogStatCards filters={filters} onDataUpdate={updated} />
      )
      await waitFor(() => expect(request).toHaveBeenCalledTimes(1))
      if (change === 'actor') act(() => identity(2))
      if (change === 'SID') act(() => identity(1, 'session-2'))
      if (change === 'filters') {
        view.rerender(
          <LogStatCards
            filters={{ ...filters, end_timestamp: new Date(1700007200000) }}
            onDataUpdate={updated}
          />
        )
      }
      await waitFor(() => expect(request).toHaveBeenCalledTimes(2))
      await act(async () => {
        second.resolve({ data: { ...current, enable_data_export: false } })
        await second.promise
      })
      await screen.findByText(offText)
      const staleRows = [{ ...rows[0], quota: 999 }]
      await act(async () => {
        first.resolve({ data: { ...current, data: staleRows } })
        await first.promise
      })
      expect(updated).not.toHaveBeenCalledWith(staleRows, false)
      expect(screen.getByText(offText)).toBeInTheDocument()
    }
  )

  it('does not publish a late response after unmount', async () => {
    const pending = deferred()
    vi.spyOn(api, 'get').mockReturnValue(pending.promise)
    const updated = vi.fn()
    const view = render(<LogStatCards onDataUpdate={updated} />)
    view.unmount()
    await act(async () => {
      pending.resolve({ data: current })
      await pending.promise
    })
    expect(updated).not.toHaveBeenCalledWith(rows, false)
  })

  it.each(['actor', 'SID'])(
    'keeps summary query data and notices within the current %s',
    async (change) => {
      const first = deferred(),
        second = deferred()
      let count = 0
      vi.spyOn(api, 'get').mockImplementation((url) => {
        if (url === '/api/status') {
          return Promise.resolve({ data: { success: true, data: {} } })
        }
        count++
        return count === 1 ? first.promise : second.promise
      })
      renderSummary()
      await waitFor(() => expect(count).toBe(1))
      act(() => identity(change === 'actor' ? 2 : 1, 'session-2'))
      await waitFor(() => expect(count).toBe(2))
      await act(async () => {
        second.resolve({ data: { ...current, enable_data_export: false } })
        await second.promise
      })
      await screen.findByText(offText)
      await act(async () => {
        first.resolve({ data: current })
        await first.promise
      })
      expect(screen.getByText(offText)).toBeInTheDocument()
      expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
    }
  )

  it('shows summary data errors without a no-usage or zero-completeness claim', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (url) => ({
      data:
        url === '/api/status'
          ? { success: true, data: {} }
          : { ...current, data: null },
    }))
    renderSummary()
    await screen.findByText('Failed to load')
    expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
  })
  it('keeps previous validated records when the same conditions return null', async () => {
    const request = vi
      .spyOn(api, 'get')
      .mockResolvedValueOnce({ data: current })
      .mockResolvedValueOnce({ data: { ...current, data: null } })
    const updated = vi.fn()
    const filters = {
      start_timestamp: new Date(1700000000000),
      end_timestamp: new Date(1700003600000),
    }
    const view = render(
      <LogStatCards filters={filters} onDataUpdate={updated} />
    )
    await waitFor(() => expect(updated).toHaveBeenLastCalledWith(rows, false))
    view.rerender(
      <LogStatCards filters={{ ...filters }} onDataUpdate={updated} />
    )
    await screen.findByText('Failed to load')
    expect(request).toHaveBeenCalledTimes(2)
    expect(updated).toHaveBeenLastCalledWith(rows, false, true)
    expect(updated).not.toHaveBeenCalledWith([], false)
  })

  it('does not infer historical completeness from collection being on', async () => {
    const { data_complete: _complete, ...partial } = current
    vi.spyOn(api, 'get').mockResolvedValue({ data: partial })
    render(<LogStatCards />)
    await screen.findByText(unknownText)
    expect(screen.queryByText(offText)).not.toBeInTheDocument()
  })

  it.each([
    ['off with history', { ...current, enable_data_export: false }, offText],
    [
      'off without history',
      { ...current, enable_data_export: false, data: [] },
      offText,
    ],
    ['legacy', { success: true, data: rows }, unknownText],
  ])(
    'keeps summary %s distinct from complete zero usage',
    async (_name, response, notice) => {
      vi.spyOn(api, 'get').mockImplementation(async (url) => ({
        data: url === '/api/status' ? { success: true, data: {} } : response,
      }))
      renderSummary()
      await screen.findByText(notice)
      expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
      if (response.data.length === 0) {
        expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(2)
      }
    }
  )

  it('hides a completed previous-session summary while the new session fails', async () => {
    const pending = deferred()
    let count = 0
    vi.spyOn(api, 'get').mockImplementation((url) => {
      if (url === '/api/status') {
        return Promise.resolve({ data: { success: true, data: {} } })
      }
      count++
      return count === 1
        ? Promise.resolve({ data: { ...current, enable_data_export: false } })
        : pending.promise
    })
    renderSummary()
    await screen.findByText(offText)
    act(() => identity(1, 'new-session'))
    expect(screen.queryByText(offText)).not.toBeInTheDocument()
    await act(async () => {
      pending.resolve({ data: { ...current, data: null } })
      await pending.promise
    })
    await screen.findByText('Failed to load')
    expect(screen.queryByText(offText)).not.toBeInTheDocument()
  })
})

describe.each(['log', 'summary'] as const)(
  '%s measurement validity',
  (view) => {
    it.each(invalidMeasurements)(
      'shows unknown and an error for $name rather than zero',
      async ({ row }) => {
        vi.spyOn(api, 'get').mockImplementation(async (url) => ({
          data:
            url === '/api/status'
              ? { success: true, data: {} }
              : { ...current, data: [row] },
        }))
        const { updated } = renderHourlyCards(view)
        await screen.findByText('Failed to load')
        expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(2)
        expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
        if (updated) {
          expect(updated).not.toHaveBeenCalledWith([row], false)
        }
      }
    )

    it.each(invalidMeasurements)(
      'retains same-context trusted history when refreshing with $name',
      async ({ row }) => {
        let response: unknown = current
        vi.spyOn(api, 'get').mockImplementation(async (url) => ({
          data: url === '/api/status' ? { success: true, data: {} } : response,
        }))
        const { updated, refresh } = renderHourlyCards(view)
        await screen.findByText(incompleteText)
        expect(screen.getAllByText(formatQuota(250000))).toHaveLength(
          view === 'summary' ? 2 : 1
        )
        response = { ...current, data: [row] }
        await act(async () => {
          await refresh()
        })
        await screen.findByText('Failed to load')
        expect(screen.getAllByText(formatQuota(250000))).toHaveLength(
          view === 'summary' ? 2 : 1
        )
        if (updated) {
          expect(updated).toHaveBeenLastCalledWith(rows, false, true)
          expect(updated).not.toHaveBeenCalledWith([row], false)
        }
        expect(screen.queryByText('No recent usage')).not.toBeInTheDocument()
      }
    )

    it.each([
      {
        name: 'incomplete',
        response: { ...current, enable_data_export: false },
        notice: incompleteText,
      },
      {
        name: 'legacy unknown',
        response: { success: true, data: rows },
        notice: unknownText,
      },
    ])(
      'keeps $name coverage visible alongside a refresh error and trusted history',
      async ({ response: trusted, notice }) => {
        let response: unknown = trusted
        vi.spyOn(api, 'get').mockImplementation(async (url) => ({
          data: url === '/api/status' ? { success: true, data: {} } : response,
        }))
        const { refresh } = renderHourlyCards(view)
        await screen.findByText(notice)
        response = { ...current, success: false }
        await act(async () => {
          await refresh()
        })
        await screen.findByText('Failed to load')
        expect(screen.getByText(notice)).toBeInTheDocument()
        expect(screen.getAllByText(formatQuota(250000))).toHaveLength(
          view === 'summary' ? 2 : 1
        )
        if ('enable_data_export' in trusted) {
          expect(screen.getByText(offText)).toBeInTheDocument()
        }
      }
    )

    it('displays explicit zero measurements without treating them as missing', async () => {
      const zeroRows = [{ ...rows[0], quota: 0, count: 0, token_used: 0 }]
      vi.spyOn(api, 'get').mockImplementation(async (url) => ({
        data:
          url === '/api/status'
            ? { success: true, data: {} }
            : { ...current, data: zeroRows },
      }))
      const { updated } = renderHourlyCards(view)
      await screen.findByText(incompleteText)
      // Summary also displays the independently loaded account's tiny historical
      // total as zero at the existing precision; the second zero is this series.
      expect(screen.getAllByText(formatQuota(0))).toHaveLength(
        view === 'summary' ? 2 : 1
      )
      expect(screen.queryByText('Failed to load')).not.toBeInTheDocument()
      if (updated) {
        expect(updated).toHaveBeenLastCalledWith(zeroRows, false)
      }
    })

    it.each(['actor', 'SID'] as const)(
      'does not reuse completed history after an invalid response in another %s',
      async (change) => {
        let response: unknown = { ...current, enable_data_export: false }
        vi.spyOn(api, 'get').mockImplementation(async (url) => ({
          data: url === '/api/status' ? { success: true, data: {} } : response,
        }))
        const { updated } = renderHourlyCards(view)
        await screen.findByText(offText)
        expect(screen.getAllByText(formatQuota(250000))).toHaveLength(
          view === 'summary' ? 2 : 1
        )
        updated?.mockClear()
        response = { ...current, data: [invalidMeasurements[0].row] }
        act(() => identity(change === 'actor' ? 2 : 1, 'session-2'))
        await screen.findByText('Failed to load')
        expect(screen.queryAllByText(formatQuota(250000))).toHaveLength(0)
        expect(screen.queryByText(offText)).not.toBeInTheDocument()
        expect(screen.getAllByText('--').length).toBeGreaterThanOrEqual(2)
        if (updated) {
          expect(updated).not.toHaveBeenCalledWith(rows, false)
        }
      }
    )
  }
)

describe('model dashboard parent chart lifecycle', () => {
  it.each([
    'network',
    'false success',
    'missing data',
    'null data',
    'missing actor',
  ] as const)(
    'ends parent loading and shows failure rather than empty charts on %s',
    async (failure) => {
      if (failure === 'missing actor') {
        useAuthStore.setState(useAuthStore.getInitialState(), true)
      }
      vi.spyOn(api, 'get').mockImplementation(async () => {
        if (failure === 'network') {
          throw new Error('private fixture network failure')
        }
        if (failure === 'false success') {
          return { data: { ...current, success: false } }
        }
        if (failure === 'missing data') return { data: { success: true } }
        return { data: { ...current, data: null } }
      })
      await renderModelDashboard()
      await waitFor(() =>
        expect(screen.getAllByText('Failed to load').length).toBeGreaterThan(1)
      )
      const charts = screen.getByRole('region', {
        name: 'Model Call Analytics',
      })
      expect(charts).toHaveAttribute('aria-busy', 'false')
      expect(within(charts).getByText('Failed to load')).toBeInTheDocument()
      expect(screen.queryByText('Quota Distribution')).not.toBeInTheDocument()
      expect(
        screen.queryByRole('img', { name: 'Usage chart' })
      ).not.toBeInTheDocument()
    }
  )

  it('retains trusted parent chart history and ends loading when the same query refresh fails', async () => {
    const request = vi
      .spyOn(api, 'get')
      .mockResolvedValueOnce({ data: current })
      .mockResolvedValue({ data: { ...current, data: null } })
    await renderModelDashboard()
    await screen.findByText('Quota Distribution')
    const charts = screen.getByRole('region', { name: 'Model Call Analytics' })
    expect(within(charts).getByText('$0.50')).toBeInTheDocument()
    await applyModelFilters()
    await screen.findByText('Failed to load')
    expect(charts).toHaveAttribute('aria-busy', 'false')
    expect(within(charts).getByText('$0.50')).toBeInTheDocument()
    expect(request).toHaveBeenCalledTimes(2)
    expect(request.mock.calls[1][1]?.params).toEqual(
      request.mock.calls[0][1]?.params
    )
  })

  it.each(['actor', 'SID', 'query'] as const)(
    'hides old charts in the first %s frame and ignores a late previous request',
    async (change) => {
      const old = deferred(),
        next = deferred()
      const request = vi
        .spyOn(api, 'get')
        .mockResolvedValueOnce({ data: current })
        .mockReturnValueOnce(old.promise)
        .mockReturnValueOnce(next.promise)
      const { frames } = await renderModelDashboard()
      await screen.findByText('Quota Distribution')
      await applyModelFilters()
      await waitFor(() => expect(request).toHaveBeenCalledTimes(2))
      if (change === 'query') {
        fireEvent.click(screen.getByRole('button', { name: 'Filter' }))
        const dialog = await screen.findByRole('dialog')
        fireEvent.click(within(dialog).getByRole('button', { name: '7 Days' }))
        frames.length = 0
        fireEvent.click(
          within(dialog).getByRole('button', { name: 'Apply Filters' })
        )
      } else {
        frames.length = 0
        act(() => identity(change === 'actor' ? 2 : 1, 'session-2'))
      }
      expect(frames.length).toBeGreaterThan(0)
      expect(frames[0]).not.toContain('$0.50')
      expect(screen.queryByText('Quota Distribution')).not.toBeInTheDocument()
      await waitFor(() => expect(request).toHaveBeenCalledTimes(3))
      await act(async () => {
        next.resolve({
          data: { ...current, data: [{ ...rows[0], quota: 500000 }] },
        })
        await next.promise
      })
      await screen.findByText('Quota Distribution')
      await act(async () => {
        old.resolve({
          data: { ...current, data: [{ ...rows[0], quota: 750000 }] },
        })
        await old.promise
      })
      const charts = screen.getByRole('region', {
        name: 'Model Call Analytics',
      })
      expect(within(charts).getByText('$1.00')).toBeInTheDocument()
      expect(within(charts).queryByText('$1.50')).not.toBeInTheDocument()
      expect(charts).toHaveAttribute('aria-busy', 'false')
    }
  )

  it.each([
    ['empty', []],
    ['explicit zero', [{ ...rows[0], quota: 0, count: 0, token_used: 0 }]],
  ])(
    'shows successful %s charts separately from failure, without claiming complete history',
    async (_name, data) => {
      vi.spyOn(api, 'get').mockResolvedValue({ data: { ...current, data } })
      await renderModelDashboard()
      await screen.findByText('Quota Distribution')
      const charts = screen.getByRole('region', {
        name: 'Model Call Analytics',
      })
      expect(charts).toHaveAttribute('aria-busy', 'false')
      expect(within(charts).getByText('$0.00')).toBeInTheDocument()
      expect(screen.queryByText('Failed to load')).not.toBeInTheDocument()
      expect(screen.getByText(incompleteText)).toBeInTheDocument()
    }
  )
})
