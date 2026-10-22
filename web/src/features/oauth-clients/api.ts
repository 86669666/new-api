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
import axios from 'axios'

import { api } from '@/lib/api'

export interface OAuthClientRecord {
  id: number
  client_id: string
  name: string
  redirects: string[]
  scopes: string[]
  enabled: boolean
}

export interface OAuthAuthorizationRecord {
  client_id: string
  name: string
  scopes: string[]
}

interface ApiResponse<T> {
  success: boolean
  message?: string
  data?: T
}

async function readOrUnavailable<T>(
  request: Promise<{ data: ApiResponse<T> }>
): Promise<ApiResponse<T> | null> {
  try {
    const res = await request
    return res.data
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null
    throw error
  }
}

export function listOAuthClients() {
  return readOrUnavailable(
    api.get<ApiResponse<OAuthClientRecord[]>>('/api/oauth/clients', {
      skipErrorHandler: true,
    })
  )
}

export function createOAuthClient(
  body: {
    name: string
    preset?: string
    redirects?: string[]
    scopes: string[]
  },
  proof: string
) {
  return api.post<ApiResponse<OAuthClientRecord>>('/api/oauth/clients', body, {
    headers: { 'X-Security-Proof': proof },
  })
}

export function updateOAuthClient(
  id: number,
  body: {
    name: string
    preset?: string
    redirects?: string[]
    scopes: string[]
    enabled: boolean
  },
  proof: string
) {
  return api.put<ApiResponse<OAuthClientRecord>>(
    `/api/oauth/clients/${id}`,
    body,
    { headers: { 'X-Security-Proof': proof } }
  )
}

export function deleteOAuthClient(id: number, proof: string) {
  return api.delete<ApiResponse<{ client_id: string }>>(
    `/api/oauth/clients/${id}`,
    { headers: { 'X-Security-Proof': proof } }
  )
}

export function listOAuthAuthorizations() {
  return readOrUnavailable(
    api.get<ApiResponse<OAuthAuthorizationRecord[]>>(
      '/api/oauth/authorizations',
      { skipErrorHandler: true }
    )
  )
}

export function revokeOAuthAuthorization(clientId: string) {
  return api.delete<ApiResponse<{ client_id: string }>>(
    `/api/oauth/authorizations/${encodeURIComponent(clientId)}`
  )
}
