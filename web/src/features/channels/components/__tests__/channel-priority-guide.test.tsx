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
import { afterEach, expect, test } from 'vitest'

import { ChannelsPrimaryButtons } from '../channels-primary-buttons'
import { ChannelsProvider } from '../channels-provider'

const STEPPER_COPY =
  'The plus control raises the priority by 1. The minus control lowers it by 1. You can also type a whole number, down to -999.'
const ROUTING_COPY =
  'Among enabled channels for the same group and model, the highest priority is selected first. Channels that share a number stay on that step. Weight splits requests among them; when every weight is 0, they share requests equally. A later retry uses the next lower priority, and further retries stay on the lowest one.'

function renderChannelControls() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ChannelsProvider>
        <ChannelsPrimaryButtons />
      </ChannelsProvider>
    </QueryClientProvider>
  )
}

afterEach(() => {
  localStorage.clear()
})

test('the actions menu opens a static priority guide for the number control', async () => {
  const user = userEvent.setup()
  renderChannelControls()

  expect(screen.getByRole('switch', { name: 'Sort by ID' })).not.toBeChecked()
  expect(screen.getByRole('switch', { name: 'Tag Mode' })).not.toBeChecked()

  const trigger = document.querySelector('[data-slot="dropdown-menu-trigger"]')
  expect(trigger).toBeInstanceOf(HTMLElement)
  await user.click(trigger as HTMLElement)

  await user.click(
    screen.getByRole('menuitem', { name: 'How to set channel priority' })
  )

  const dialog = screen.getByRole('dialog', {
    name: 'How to set channel priority',
  })
  expect(dialog).toHaveTextContent(STEPPER_COPY)
  expect(dialog).toHaveTextContent(ROUTING_COPY)
  expect(dialog).toHaveTextContent(
    'On a tag row, the same control asks before applying the number to every channel in the tag.'
  )
  expect(dialog).not.toHaveTextContent(/drag/i)

  await user.click(screen.getAllByRole('button', { name: 'Close' })[0])
  expect(
    screen.queryByRole('dialog', { name: 'How to set channel priority' })
  ).not.toBeInTheDocument()
  expect(screen.getByRole('switch', { name: 'Sort by ID' })).not.toBeChecked()
  expect(screen.getByRole('switch', { name: 'Tag Mode' })).not.toBeChecked()
  expect(localStorage.getItem('channels-id-sort')).toBeNull()
  expect(localStorage.getItem('enable-tag-mode')).toBeNull()
})
