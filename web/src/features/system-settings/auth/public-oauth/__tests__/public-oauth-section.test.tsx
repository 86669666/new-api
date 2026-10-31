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

import { PublicOAuthSection } from '../public-oauth-section'

const requestVerification = vi.fn()
const getPublicOAuthClients = vi.fn()
const getPublicOAuthClientPresets = vi.fn()
const createPublicOAuthClient = vi.fn()

vi.mock('@/features/auth/secure-verification', () => ({
  useSecureVerification: () => ({
    requestVerification,
    isActive: false,
    dialogProps: { open: false },
  }),
  SecureVerificationDialog: () => null,
}))

vi.mock('../api', () => ({
  getPublicOAuthClients: (...args: unknown[]) => getPublicOAuthClients(...args),
  getPublicOAuthClientPresets: (...args: unknown[]) =>
    getPublicOAuthClientPresets(...args),
  createPublicOAuthClient: (...args: unknown[]) =>
    createPublicOAuthClient(...args),
  updatePublicOAuthClient: vi.fn(),
  deletePublicOAuthClient: vi.fn(),
}))

function Fixture() {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
  )
  return (
    <QueryClientProvider client={client}>
      <PublicOAuthSection />
    </QueryClientProvider>
  )
}

describe('PublicOAuthSection', () => {
  beforeEach(() => {
    requestVerification.mockReset()
    requestVerification.mockResolvedValue({ proof_token: 'proof-1' })
    getPublicOAuthClients.mockReset()
    getPublicOAuthClients.mockResolvedValue({
      success: true,
      data: [
        {
          id: 1,
          client_id: 'existing-client',
          name: 'Existing',
          redirect_uris: ['https://client.example/callback'],
          scopes: ['profile'],
          grant_types: ['authorization_code', 'refresh_token'],
          token_endpoint_auth_method: 'none',
          enabled: true,
          created_at: '',
          updated_at: '',
        },
      ],
    })
    getPublicOAuthClientPresets.mockReset()
    getPublicOAuthClientPresets.mockResolvedValue({
      success: true,
      data: [
        {
          key: 'boxnai-desktop',
          name: 'Boxnai Desktop',
          redirect_uris: [
            'http://127.0.0.1/oauth/callback',
            'boxnai://oauth/callback',
          ],
          scopes: ['openid', 'profile', 'offline_access', 'tokens:write'],
          grant_types: ['authorization_code', 'refresh_token'],
        },
      ],
    })
    createPublicOAuthClient.mockReset()
    createPublicOAuthClient.mockResolvedValue({
      success: true,
      message: 'Public OAuth client created',
    })
  })

  it('fills a preset without a client id and creates the client after step-up', async () => {
    const user = userEvent.setup()
    render(<Fixture />)

    expect(await screen.findByText('existing-client')).toBeInTheDocument()
    expect(
      screen.getByText(
        'Saving a client here records it in this console. When the public OAuth provider is enabled, the same client is registered with the authorization server. If that registration fails, the save fails and the console record stays unchanged.'
      )
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add client' }))
    await user.click(screen.getByRole('button', { name: 'Boxnai Desktop' }))

    expect(screen.getByLabelText(/Client ID/)).toHaveValue('')
    expect(screen.getByLabelText(/Name/)).toHaveValue('Boxnai Desktop')
    expect(screen.getByLabelText(/Redirect URIs/)).toHaveValue(
      'http://127.0.0.1/oauth/callback\nboxnai://oauth/callback'
    )
    expect(screen.getByText('Write tokens')).toBeInTheDocument()

    await user.type(screen.getByLabelText(/Client ID/), 'boxnai-desktop-test')
    await user.click(screen.getByRole('button', { name: 'Create' }))

    expect(requestVerification).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: 'oauth.public_client.manage',
        context: { action: 'create', client_id: 'boxnai-desktop-test' },
      })
    )
    expect(createPublicOAuthClient).toHaveBeenCalledWith(
      expect.not.objectContaining({ client_secret: expect.anything() }),
      'proof-1'
    )
    const body = createPublicOAuthClient.mock.calls[0][0]
    expect(body).toMatchObject({
      client_id: 'boxnai-desktop-test',
      name: 'Boxnai Desktop',
      enabled: true,
      redirect_uris: [
        'http://127.0.0.1/oauth/callback',
        'boxnai://oauth/callback',
      ],
    })
    expect(body.scopes).toEqual(
      expect.arrayContaining([
        'openid',
        'profile',
        'offline_access',
        'tokens:write',
      ])
    )
  })
})
