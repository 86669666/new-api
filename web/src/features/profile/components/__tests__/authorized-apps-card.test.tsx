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
import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthorizedAppsCard } from '../authorized-apps-card'

const requestVerification = vi.fn()
const getAuthorizedOAuthApps = vi.fn()
const revokeAuthorizedOAuthApp = vi.fn()

vi.mock('@/features/auth/secure-verification', () => ({
  useSecureVerification: () => ({
    requestVerification,
    isActive: false,
    dialogProps: { open: false },
  }),
  SecureVerificationDialog: () => null,
}))

vi.mock('@/features/system-settings/auth/public-oauth/api', () => ({
  getAuthorizedOAuthApps: (...args: unknown[]) =>
    getAuthorizedOAuthApps(...args),
  revokeAuthorizedOAuthApp: (...args: unknown[]) =>
    revokeAuthorizedOAuthApp(...args),
}))

function Fixture() {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
  )
  return (
    <QueryClientProvider client={client}>
      <AuthorizedAppsCard />
    </QueryClientProvider>
  )
}

describe('AuthorizedAppsCard', () => {
  beforeEach(() => {
    requestVerification.mockReset()
    requestVerification.mockResolvedValue({ proof_token: 'proof-1' })
    getAuthorizedOAuthApps.mockReset()
    getAuthorizedOAuthApps.mockResolvedValue({
      success: true,
      data: [
        {
          client_id: 'boxnai-desktop-test',
          name: 'Boxnai Desktop',
          scopes: ['openid', 'profile'],
          grant_count: 1,
          approved_at: 1_700_000_000,
          expires_at: 1_700_003_600,
        },
      ],
    })
    revokeAuthorizedOAuthApp.mockReset()
    revokeAuthorizedOAuthApp.mockResolvedValue({
      success: true,
      message: 'Authorized application revoked',
    })
  })

  it('lists an authorized app and revokes it after step-up', async () => {
    const user = userEvent.setup()
    render(<Fixture />)

    expect(await screen.findByText('boxnai-desktop-test')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    const confirm = screen.getAllByRole('button', { name: 'Revoke' }).at(-1)
    if (!confirm) throw new Error('missing revoke confirmation')
    await user.click(confirm)

    expect(requestVerification).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: 'oauth.app.revoke',
        context: { client_id: 'boxnai-desktop-test' },
      })
    )
    expect(revokeAuthorizedOAuthApp).toHaveBeenCalledWith(
      'boxnai-desktop-test',
      'proof-1'
    )
  })
})
