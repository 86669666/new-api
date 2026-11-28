import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createInstance } from 'i18next'
import { I18nextProvider } from 'react-i18next'
import { afterEach, expect, test, vi } from 'vitest'

import {
  getMyOrganizations,
  getOrganizationTaskLogs,
} from '@/features/organizations/api'
import { useAuthStore } from '@/stores/auth-store'

import { OrganizationTaskScope } from '../components/organization-task-scope'

vi.mock('@/features/organizations/api', () => ({
  getMyOrganizations: vi.fn(),
  getOrganizationTaskLogs: vi.fn(),
}))

afterEach(() => {
  cleanup()
  useAuthStore.getState().auth.reset()
  vi.resetAllMocks()
})

test('switching personal and organization task scope displays only the selected data', async () => {
  const language = createInstance()
  await language.init({ lng: 'en', resources: { en: { translation: {} } } })
  useAuthStore.getState().auth.setBundle({
    user: { id: 12, username: 'tester', role: 1 },
    access_token: 'fixture',
    token_type: 'Bearer',
    access_expires_at: 1900000000,
    session: {
      sid: 'fixture-session',
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: 1900000000,
    },
  })
  vi.mocked(getMyOrganizations).mockResolvedValue({
    items: [{ org_id: '16', name: 'Example studio', my_role: 'owner' }],
    limit: 20,
    next_after_id: null,
  })
  vi.mocked(getOrganizationTaskLogs).mockResolvedValue({
    total: 1,
    items: [
      {
        task_row_id: '24',
        task_id: 'studio-task',
        status: 'SUCCESS',
        submit_time: 1,
      },
    ],
  })
  const queryClient = new QueryClient()
  render(
    <I18nextProvider i18n={language}>
      <QueryClientProvider client={queryClient}>
        <OrganizationTaskScope>
          <span>personal-task</span>
        </OrganizationTaskScope>
      </QueryClientProvider>
    </I18nextProvider>
  )
  const selector = await screen.findByRole('combobox', { name: 'View scope' })
  expect(screen.getByText('personal-task')).toBeVisible()
  await userEvent.click(selector)
  await userEvent.click(
    await screen.findByRole('option', { name: 'Example studio' })
  )
  expect(await screen.findByText('studio-task')).toBeVisible()
  expect(screen.queryByText('personal-task')).not.toBeInTheDocument()
  expect(getOrganizationTaskLogs).toHaveBeenCalledWith(
    12,
    'fixture-session',
    '16',
    1,
    expect.any(AbortSignal)
  )
  await userEvent.click(selector)
  await userEvent.click(await screen.findByRole('option', { name: 'Personal' }))
  expect(await screen.findByText('personal-task')).toBeVisible()
  expect(screen.queryByText('studio-task')).not.toBeInTheDocument()
  queryClient.clear()
})
