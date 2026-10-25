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
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createInstance, type i18n } from 'i18next'
import { useState } from 'react'
import { I18nextProvider } from 'react-i18next'
import { beforeEach, describe, expect, it } from 'vitest'

import {
  BOXO_V2_TEMPLATE,
  BOXNAI_V2_TEMPLATE,
} from '@/features/chat/lib/chat-links'

import { SettingsPageProvider } from '../components/settings-page-context'
import { ChatSettingsSection } from '../content/chat-settings-section'

let testI18n: i18n

function Fixture(props: { value: string }) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  )
  return (
    <I18nextProvider i18n={testI18n}>
      <QueryClientProvider client={client}>
        <div ref={setContainer} />
        <SettingsPageProvider actionsContainer={container}>
          <ChatSettingsSection defaultValue={props.value} />
        </SettingsPageProvider>
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
