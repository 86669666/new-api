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
import { api } from '@/lib/api'
import { authRequestOptions } from '@/lib/secure-verification'

import type {
  AuthorizedOAuthApp,
  PublicOAuthClient,
  PublicOAuthClientInput,
  PublicOAuthClientPreset,
} from './types'

interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
}

function proofOptions(proof: string) {
  return {
    ...authRequestOptions,
    headers: { 'X-Security-Proof': proof },
    singleUseAuthorization: true,
  }
}

export async function getPublicOAuthClientPresets(): Promise<
  ApiResponse<PublicOAuthClientPreset[]>
> {
  const res = await api.get('/api/oauth/public-clients/presets')
  return res.data
}

export async function getPublicOAuthClients(): Promise<
  ApiResponse<PublicOAuthClient[]>
> {
  const res = await api.get('/api/oauth/public-clients/')
  return res.data
}

export async function createPublicOAuthClient(
  data: PublicOAuthClientInput & { client_id: string },
  proof: string
): Promise<ApiResponse<PublicOAuthClient>> {
  const res = await api.post(
    '/api/oauth/public-clients/',
    data,
    proofOptions(proof)
  )
  return res.data
}

export async function updatePublicOAuthClient(
  id: number,
  data: PublicOAuthClientInput,
  proof: string
): Promise<ApiResponse<PublicOAuthClient>> {
  const res = await api.put(
    `/api/oauth/public-clients/${id}`,
    {
      name: data.name,
      redirect_uris: data.redirect_uris,
      scopes: data.scopes,
      enabled: data.enabled,
    },
    proofOptions(proof)
  )
  return res.data
}

export async function deletePublicOAuthClient(
  id: number,
  proof: string
): Promise<ApiResponse> {
  const res = await api.delete(
    `/api/oauth/public-clients/${id}`,
    proofOptions(proof)
  )
  return res.data
}

export async function getAuthorizedOAuthApps(): Promise<
  ApiResponse<AuthorizedOAuthApp[]>
> {
  const res = await api.get('/api/user/oauth/apps')
  return res.data
}

export async function revokeAuthorizedOAuthApp(
  clientId: string,
  proof: string
): Promise<ApiResponse> {
  const res = await api.delete(
    `/api/user/oauth/apps/${encodeURIComponent(clientId)}`,
    proofOptions(proof)
  )
  return res.data
}
