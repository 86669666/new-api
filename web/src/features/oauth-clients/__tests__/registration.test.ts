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
import { describe, expect, test } from 'vitest'

import { oauthProviderScopes } from '@/features/auth/oauth-provider/api'

import {
  OAUTH_CLIENT_KNOWN_SCOPES,
  OAUTH_CLIENT_PRESETS,
  oauthClientManageContext,
  validOAuthClientRedirect,
} from '../registration'

describe('oauth client registration', () => {
  test('uses the consent scope catalog and the documented presets', () => {
    expect(OAUTH_CLIENT_KNOWN_SCOPES).toEqual(oauthProviderScopes)
    expect(OAUTH_CLIENT_PRESETS.boxo.redirects).toEqual([
      'http://127.0.0.1/oauth/callback',
    ])
    expect(OAUTH_CLIENT_PRESETS.cherry_studio.redirects).toEqual([
      'http://127.0.0.1:29873/oauth/callback',
    ])
  })

  test('builds a step-up context for a public client', () => {
    const created = oauthClientManageContext({
      action: 'create',
      name: ' Boxo ',
      preset: 'boxo',
      redirects: ['https://evil.example/steal'],
      scopes: [],
    })
    expect(created).toEqual({
      action: 'create',
      name: 'Boxo',
      redirects: ['http://127.0.0.1/oauth/callback'],
      scopes: [...OAUTH_CLIENT_KNOWN_SCOPES],
    })
    expect(Object.keys(created)).toEqual([
      'action',
      'name',
      'redirects',
      'scopes',
    ])
    expect(created).toMatchObject({ action: 'create' })
    const updated = oauthClientManageContext({
      action: 'update',
      clientRowId: 4,
      name: 'App',
      redirects: [
        'https://app.example/oauth/callback',
        'boxo://oauth/callback',
      ],
      scopes: ['tokens:read', 'profile'],
    })
    expect(updated).toEqual({
      action: 'update',
      client_row_id: 4,
      name: 'App',
      redirects: [
        'boxo://oauth/callback',
        'https://app.example/oauth/callback',
      ],
      scopes: ['profile', 'tokens:read'],
    })
    expect(
      oauthClientManageContext({ action: 'delete', clientRowId: 4 })
    ).toEqual({ action: 'delete', client_row_id: 4 })
  })

  test('rejects dangerous and non-loopback redirects', () => {
    expect(validOAuthClientRedirect('javascript:alert(1)')).toBe(false)
    expect(validOAuthClientRedirect('data:text/html,hi')).toBe(false)
    expect(validOAuthClientRedirect('file:///tmp/x')).toBe(false)
    expect(validOAuthClientRedirect('http://evil.example/oauth/callback')).toBe(
      false
    )
    expect(validOAuthClientRedirect('http://127.0.0.1/oauth/callback')).toBe(
      true
    )
    expect(
      validOAuthClientRedirect('http://127.0.0.1:29873/oauth/callback')
    ).toBe(true)
    expect(validOAuthClientRedirect('https://app.example/oauth/callback')).toBe(
      true
    )
    expect(validOAuthClientRedirect('boxo://oauth/callback')).toBe(true)
    expect(validOAuthClientRedirect('boxo://oauth/callback?next=1')).toBe(false)
  })
})
