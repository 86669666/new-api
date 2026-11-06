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
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { afterEach, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'

import { SettingsPageProvider } from '../../components/settings-page-context'
import { ModelRatioForm } from '../model-ratio-form'

const emptyMaps = {
  ModelPrice: '{}',
  ModelRatio: '{}',
  CacheRatio: '{}',
  CreateCacheRatio: '{}',
  CompletionRatio: '{}',
  ImageRatio: '{}',
  AudioRatio: '{}',
  AudioCompletionRatio: '{}',
  BillingMode: '{}',
  BillingExpr: '{}',
  PluginBillingExpr: '{}',
  ExposeRatioEnabled: false,
}

let client: QueryClient | undefined

afterEach(() => {
  client?.clear()
  localStorage.clear()
  vi.restoreAllMocks()
})

function PriceFormFixture(props: {
  saved: typeof emptyMaps
  draft: typeof emptyMaps
  onSave: (values: typeof emptyMaps) => Promise<void>
}) {
  const [actions, setActions] = useState<HTMLDivElement | null>(null)
  const form = useForm({ defaultValues: props.draft })
  return (
    <SettingsPageProvider actionsContainer={actions}>
      <header>
        <div ref={setActions} />
      </header>
      <ModelRatioForm
        form={form}
        savedValues={props.saved}
        onSave={props.onSave}
        onReset={() => undefined}
        isSaving={false}
        isResetting={false}
      />
    </SettingsPageProvider>
  )
}

async function renderForm(saved: typeof emptyMaps, draft: typeof emptyMaps) {
  vi.spyOn(api, 'get').mockImplementation(async () => ({
    data: { success: true, data: [], vendors: [] },
  }))
  vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { effective: {} } },
  })
  const onSave = vi.fn(async (_values: typeof emptyMaps) => undefined)
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const queryClient = client
  render(
    <QueryClientProvider client={queryClient}>
      <PriceFormFixture saved={saved} draft={draft} onSave={onSave} />
    </QueryClientProvider>
  )
  await waitFor(() => expect(queryClient.isFetching()).toBe(0))
  return { onSave }
}

async function openJsonSave(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Switch to JSON' }))
  return screen.getByRole('button', { name: 'Save model prices' })
}

const changedDraft = {
  ...emptyMaps,
  ModelPrice: '{"stable-model":1}',
  ModelRatio: '{"token-model":0.15}',
  CompletionRatio: '{"token-model":4}',
  BillingMode: '{"fresh-model":"tiered_expr"}',
  BillingExpr: '{"fresh-model":"tier(\\"base\\", p * 2)"}',
  'billing_setting.billing_mode': '{}',
  'billing_setting.billing_expr': '{}',
  'billing_setting.plugin_billing_expr': '{}',
}

const changedSaved = {
  ...emptyMaps,
  ModelPrice: '{"image-model":0.04,"stable-model":1}',
  ModelRatio: '{"token-model":0.135}',
  CompletionRatio: '{"token-model":4}',
}

it('lists added, deleted, and modified rates and hides unchanged models', async () => {
  const user = userEvent.setup()
  const { onSave } = await renderForm(changedSaved, changedDraft)

  await user.click(await openJsonSave(user))

  const dialog = await screen.findByRole('alertdialog', {
    name: 'Confirm price changes',
  })
  expect(dialog).toHaveTextContent(
    'New prices apply to requests as soon as you save. 3 models change.'
  )
  expect(within(dialog).queryByText('stable-model')).not.toBeInTheDocument()

  const added = within(dialog).getByRole('row', { name: /fresh-model/ })
  expect(within(added).getByText('Added')).toBeVisible()
  expect(within(added).getByText('Unset price')).toBeVisible()
  expect(within(added).getByText('tier("base", p * 2)')).toBeVisible()

  const deleted = within(dialog).getByRole('row', { name: /image-model/ })
  expect(within(deleted).getByText('Pending deletion')).toBeVisible()
  expect(within(deleted).getByText('$0.04')).toBeVisible()
  expect(within(deleted).getByText('Remove saved price')).toBeVisible()

  const modified = within(dialog).getByRole('row', { name: /token-model/ })
  expect(within(modified).getByText('Modified')).toBeVisible()
  expect(within(modified).getByText('$0.27')).toBeVisible()
  expect(within(modified).getByText('$0.3')).toBeVisible()
  expect(within(modified).getByText('$1.08')).toBeVisible()
  expect(within(modified).getByText('$1.2')).toBeVisible()
  expect(onSave).not.toHaveBeenCalled()
})

it('saves the reviewed draft only after the price changes are confirmed', async () => {
  const user = userEvent.setup()
  const { onSave } = await renderForm(changedSaved, changedDraft)

  await user.click(await openJsonSave(user))
  const dialog = await screen.findByRole('alertdialog', {
    name: 'Confirm price changes',
  })
  await user.click(
    within(dialog).getByRole('button', { name: 'Confirm Changes' })
  )

  await waitFor(() => expect(onSave).toHaveBeenCalledOnce())
  const saved = onSave.mock.calls[0][0]
  expect(JSON.parse(saved.ModelPrice)).toEqual({ 'stable-model': 1 })
  expect(JSON.parse(saved.ModelRatio)).toEqual({ 'token-model': 0.15 })
  expect(JSON.parse(saved.BillingExpr)).toEqual({
    'fresh-model': 'tier("base", p * 2)',
  })
})

it('saves without a confirmation dialog when no model price changed', async () => {
  const user = userEvent.setup()
  const { onSave } = await renderForm(emptyMaps, emptyMaps)

  await user.click(await openJsonSave(user))

  expect(
    screen.queryByRole('alertdialog', { name: 'Confirm price changes' })
  ).not.toBeInTheDocument()
  await waitFor(() => expect(onSave).toHaveBeenCalledOnce())
})

it('still reviews other price changes when the open editor edit is reverted', async () => {
  const user = userEvent.setup()
  const saved = {
    ...emptyMaps,
    ModelPrice: '{"request-model":0.04}',
    ModelRatio: '{"token-model":0.135}',
    CompletionRatio: '{"token-model":4}',
  }
  const draft = {
    ...saved,
    ModelRatio: '{"token-model":0.15}',
  }
  const { onSave } = await renderForm(saved, draft)

  const row = await screen.findByRole('row', { name: /request-model/ })
  await user.click(within(row).getByRole('button', { name: 'Edit' }))
  const price = await screen.findByRole('textbox', { name: 'Fixed price' })
  await user.clear(price)
  await user.type(price, '0.09')
  await user.clear(price)
  await user.type(price, '0.04')
  await user.click(screen.getByRole('button', { name: 'Save model prices' }))

  const dialog = await screen.findByRole('alertdialog', {
    name: 'Confirm price changes',
  })
  expect(within(dialog).getByRole('row', { name: /token-model/ })).toBeVisible()
  expect(
    within(dialog).queryByRole('row', { name: /request-model/ })
  ).not.toBeInTheDocument()
  expect(dialog).toHaveTextContent('1 models change.')
  expect(onSave).not.toHaveBeenCalled()
})

it('reviews an expression edit even when loaded option keys are unchanged', async () => {
  const user = userEvent.setup()
  const saved = emptyMaps
  const draft = {
    ...emptyMaps,
    'billing_setting.billing_mode': '{}',
    'billing_setting.billing_expr': '{}',
    BillingMode: '{"example":"tiered_expr"}',
    BillingExpr: '{"example":"tier(\\"base\\", p * 3)"}',
  }
  const { onSave } = await renderForm(saved, draft)

  await user.click(await openJsonSave(user))

  const dialog = await screen.findByRole('alertdialog', {
    name: 'Confirm price changes',
  })
  const row = within(dialog).getByRole('row', { name: /example/ })
  expect(within(row).getByText('Added')).toBeVisible()
  expect(within(row).getByText('tier("base", p * 3)')).toBeVisible()
  expect(onSave).not.toHaveBeenCalled()
})
