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
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createInstance, type i18n } from 'i18next'
import { useState } from 'react'
import { I18nextProvider } from 'react-i18next'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'

import { getSystemOptions } from '../../api'
import { SettingsPageProvider } from '../../components/settings-page-context'
import { ClientEventsSettingsSection } from '../client-events-settings-section'

let language: i18n
const initial = {
  enabled: false,
  retention_days: 30,
  rate_limit: 60,
  source: 'option',
  valid: true,
}
let server = { ...initial }
let readFails = false
let client: QueryClient

function Fixture() {
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  return (
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={client}>
        <div ref={setContainer} />
        <SettingsPageProvider actionsContainer={container}>
          <ClientEventsSettingsSection />
        </SettingsPageProvider>
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
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  server = { ...initial }
  readFails = false
  vi.spyOn(api, 'get').mockImplementation(async () => {
    if (readFails) throw new Error('fixture unavailable')
    return {
      data: {
        success: true,
        data: [{ key: 'ClientEventsConfig', value: JSON.stringify(server) }],
      },
    }
  })
  vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, message: '' },
  })
})
afterEach(() => {
  cleanup()
  client.clear()
  vi.restoreAllMocks()
})

async function renderReady() {
  render(<Fixture />)
  return await screen.findByRole('spinbutton', {
    name: 'Client event retention (days)',
  })
}

describe('Client event settings', () => {
  it('preserves dirty edits when background options change', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    server = { ...server, retention_days: 90 }
    await act(async () => {
      await client.refetchQueries({ queryKey: ['system-options'] })
    })
    expect(retention).toHaveValue(45)
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled()
  })

  it('uses authoritative refetched values as the saved baseline', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    vi.mocked(api.put).mockImplementation(async () => {
      server = { ...server, retention_days: 90 }
      return { data: { success: true, message: '' } }
    })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() => expect(retention).toHaveValue(90))
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
    expect(api.put).toHaveBeenCalledWith('/api/option/', {
      key: 'ClientEventsConfig',
      value: JSON.stringify({
        enabled: false,
        retention_days: 45,
        rate_limit: 60,
      }),
    })
  })

  it('keeps edits and reports saved but unconfirmed state after refetch failure', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    vi.mocked(api.put).mockImplementation(async () => {
      readFails = true
      return { data: { success: true, message: '' } }
    })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(
      await screen.findByText(
        'Settings were saved, but the latest values could not be loaded. Your edits have been kept.'
      )
    ).toBeVisible()
    expect(retention).toHaveValue(45)
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled()
  })

  it('cancels shorter retention without saving or discarding dirty values', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '14' } })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(await screen.findByRole('alertdialog')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() =>
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    )
    expect(api.put).not.toHaveBeenCalled()
    expect(retention).toHaveValue(14)
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled()
  })

  it('confirms shorter retention once and sends only the three writable fields', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '14' } })
    vi.mocked(api.put).mockImplementation(async () => {
      server = { ...server, retention_days: 14 }
      return { data: { success: true, message: '' } }
    })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await userEvent.click(
      await screen.findByRole('button', { name: 'Continue' })
    )
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Save Changes' })
      ).toBeDisabled()
    )
    expect(api.put).toHaveBeenCalledTimes(1)
    expect(retention).toHaveValue(14)
  })

  it('allows keyboard switching and editing while collection is disabled', async () => {
    await renderReady()
    const control = screen.getByRole('switch', {
      name: 'Enable client event collection',
    })
    control.focus()
    await userEvent.keyboard(' ')
    expect(control).toBeChecked()
    expect(
      screen.getByRole('spinbutton', {
        name: 'Collection requests per token per minute',
      })
    ).toBeEnabled()
  })

  it('rejects invalid numbers without sending a mutation', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '7' } })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(
      await screen.findByText('Enter a whole number from 8 to 365')
    ).toBeVisible()
    expect(retention).toHaveAttribute('aria-invalid', 'true')
    expect(api.put).not.toHaveBeenCalled()
  })

  it('keeps dirty values when saving fails', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    vi.mocked(api.put).mockRejectedValue(new Error('fixture save rejected'))
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled()
    )
    expect(retention).toHaveValue(45)
    expect(
      screen.queryByText(
        'Settings were saved, but the latest values could not be loaded. Your edits have been kept.'
      )
    ).not.toBeInTheDocument()
  })

  it('shows a retryable error instead of fabricated defaults when the option is missing', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { success: true, data: [] } })
    render(<Fixture />)
    expect(await screen.findByText('Failed to load settings')).toBeVisible()
    expect(
      screen.queryByRole('button', { name: 'Save Changes' })
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled()
  })
})

describe('Client event settings HTTP ordering', () => {
  const oldAdapter = api.defaults.adapter
  let heldRead: (() => void) | undefined
  let holdNextRead: boolean
  let putCount: number
  let readsAfterPut: number
  let confirmFailure: 'network' | 'business' | 'invalid' | null

  beforeEach(() => {
    vi.mocked(api.get).mockRestore()
    vi.mocked(api.put).mockRestore()
    heldRead = undefined
    holdNextRead = false
    putCount = 0
    readsAfterPut = 0
    confirmFailure = null
    api.defaults.adapter = async (config) => {
      if (config.method === 'put') {
        putCount++
        server = { ...server, retention_days: 90 }
        return {
          data: { success: true },
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        }
      }
      const captured = { ...server }
      if (putCount > 0) {
        readsAfterPut++
        if (confirmFailure === 'network') throw new Error('fresh read failed')
        if (confirmFailure === 'business') {
          return {
            data: { success: false, message: 'Unavailable' },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
          }
        }
        if (confirmFailure === 'invalid') captured.valid = false
      }
      if (holdNextRead) {
        holdNextRead = false
        await new Promise<void>((resolve) => {
          heldRead = resolve
        })
      }
      return {
        data: {
          success: true,
          data: [
            { key: 'ClientEventsConfig', value: JSON.stringify(captured) },
          ],
        },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      }
    }
  })
  afterEach(async () => {
    heldRead?.()
    await Promise.resolve()
    api.defaults.adapter = oldAdapter
  })

  it('confirms a fresh post-PUT response even when an older GET completes last', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    holdNextRead = true
    let oldRead = Promise.resolve()
    act(() => {
      oldRead = client.refetchQueries({ queryKey: ['system-options'] })
    })
    await waitFor(() => expect(heldRead).toBeDefined())
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    try {
      await waitFor(() => expect(retention).toHaveValue(90))
      expect(readsAfterPut).toBeGreaterThan(0)
    } finally {
      await act(async () => {
        heldRead?.()
        await oldRead
      })
    }
    expect(retention).toHaveValue(90)
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
    expect(client.getQueryData(['system-options'])).toMatchObject({
      data: [{ value: JSON.stringify(server) }],
    })
    expect(putCount).toBe(1)
  })

  it('ordinary option reads observe current values while an older HTTP request is pending', async () => {
    holdNextRead = true
    const oldRead = getSystemOptions()
    await waitFor(() => expect(heldRead).toBeDefined())
    server = { ...server, retention_days: 90 }
    const currentRead = getSystemOptions()
    try {
      // Release after starting the second read: even if it joins the old
      // promise, the assertion fails without leaving a pending test request.
      heldRead?.()
      expect(await currentRead).toMatchObject({
        data: [{ value: JSON.stringify(server) }],
      })
      expect(await oldRead).toMatchObject({
        data: [{ value: JSON.stringify(initial) }],
      })
    } finally {
      heldRead?.()
      await oldRead
    }
  })

  it('keeps the confirmed cache and clean form when a later refetch precedes an old HTTP completion', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    holdNextRead = true
    let oldRead = Promise.resolve()
    act(() => {
      oldRead = client.refetchQueries({ queryKey: ['system-options'] })
    })
    await waitFor(() => expect(heldRead).toBeDefined())
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() => expect(retention).toHaveValue(90))
    let laterRead = Promise.resolve()
    act(() => {
      laterRead = client.refetchQueries({ queryKey: ['system-options'] })
    })
    await act(async () => {
      heldRead?.()
      await Promise.all([oldRead, laterRead])
    })
    expect(retention).toHaveValue(90)
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeDisabled()
    expect(putCount).toBe(1)
    await waitFor(() => {
      expect(client.getQueryData(['system-options'])).toMatchObject({
        data: [{ value: JSON.stringify(server) }],
      })
      expect(retention).toHaveValue(90)
      expect(
        screen.getByRole('button', { name: 'Save Changes' })
      ).toBeDisabled()
    })
  })

  it.each(['network', 'business', 'invalid'] as const)(
    'keeps the draft after a fresh %s failure instead of accepting an old GET',
    async (failure) => {
      const retention = await renderReady()
      fireEvent.change(retention, { target: { value: '45' } })
      holdNextRead = true
      let oldRead = Promise.resolve()
      act(() => {
        oldRead = client.refetchQueries({ queryKey: ['system-options'] })
      })
      await waitFor(() => expect(heldRead).toBeDefined())
      confirmFailure = failure
      await userEvent.click(
        screen.getByRole('button', { name: 'Save Changes' })
      )
      try {
        expect(
          await screen.findByText(
            'Settings were saved, but the latest values could not be loaded. Your edits have been kept.'
          )
        ).toBeVisible()
      } finally {
        await act(async () => {
          heldRead?.()
          await oldRead
        })
      }
      expect(retention).toHaveValue(45)
      expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled()
      expect(putCount).toBe(1)
    }
  )

  it('confirms against background policy90 while preserving draft45 and cancellation', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '45' } })
    server = { ...server, retention_days: 90 }
    await act(async () => {
      await client.refetchQueries({ queryKey: ['system-options'] })
    })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(putCount).toBe(0)
    expect(await screen.findByRole('alertdialog')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(retention).toHaveValue(45)
    expect(putCount).toBe(0)
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await userEvent.click(
      await screen.findByRole('button', { name: 'Continue' })
    )
    await waitFor(() => expect(retention).toHaveValue(90))
    expect(putCount).toBe(1)
  })

  it('requires a new confirmation when policy changes while the dialog is open', async () => {
    const retention = await renderReady()
    fireEvent.change(retention, { target: { value: '14' } })
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(await screen.findByRole('alertdialog')).toBeVisible()
    server = { ...server, retention_days: 90 }
    await act(async () => {
      await client.refetchQueries({ queryKey: ['system-options'] })
    })
    await waitFor(() =>
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    )
    expect(putCount).toBe(0)
    expect(retention).toHaveValue(14)
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(await screen.findByRole('alertdialog')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(putCount).toBe(0)
    expect(retention).toHaveValue(14)
  })
})
