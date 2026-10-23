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
import { t } from 'i18next'
import { z } from 'zod'

import { api } from '@/lib/api'
import { requireServerSuccess } from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

import type {
  FlowQuotaDataItem,
  QuotaDataItem,
  QuotaDataResponse,
  UptimeGroupResult,
} from './types'

// ============================================================================
// Dashboard APIs
// ============================================================================

// ----------------------------------------------------------------------------
// Quota & Usage Data
// ----------------------------------------------------------------------------

// Get user quota data within a time range
// Admin users get all users' data by default.
const quotaDataResponseSchema = z.object({
  success: z.literal(true),
  message: z.string().optional(),
  data: z.array(
    z
      .object({
        created_at: z.number().finite(),
        quota: z.number().finite().optional(),
        count: z.number().finite().optional(),
        token_used: z.number().finite().optional(),
        id: z.number().finite().optional(),
        user_id: z.number().finite().optional(),
        username: z.string().optional(),
        model_name: z.string().optional(),
      })
      .passthrough()
  ),
})

const personalQuotaDataResponseSchema = quotaDataResponseSchema.extend({
  // Personal statistics require complete measurements; legacy metadata may
  // still be absent. This is a consumption check, not a wire-schema promise.
  data: z.array(
    quotaDataResponseSchema.shape.data.element.required({
      quota: true,
      count: true,
      token_used: true,
    })
  ),
  granularity: z.literal('hour').optional(),
  quota_per_unit: z.number().finite().positive().optional(),
  data_complete: z.literal(false).optional(),
  enable_data_export: z.boolean().optional(),
})

export async function getUserQuotaDates(
  params: {
    start_timestamp: number
    end_timestamp: number
    default_time?: string
    username?: string
  },
  isAdmin = false,
  signal?: AbortSignal
): Promise<QuotaDataResponse> {
  const endpoint = isAdmin ? '/api/data' : '/api/data/self'
  const auth = useAuthStore.getState().auth
  const userId = auth.user?.id
  const sid = auth.session?.sid
  const res = await api.get<unknown>(endpoint, {
    params,
    signal,
    // Each existing consumer owns its cancellation lifetime. Do not share a
    // promise controlled by another view's signal or an anonymous SID key.
    disableDuplicate: true,
    expectedAuthIdentity: userId && sid ? { userId, sid } : undefined,
  })
  const current = useAuthStore.getState().auth
  if (
    signal?.aborted ||
    current.user?.id !== userId ||
    current.session?.sid !== sid
  ) {
    throw new DOMException('The usage request was cancelled', 'AbortError')
  }
  const response = requireServerSuccess(res.data)
  const parsed = (
    isAdmin ? quotaDataResponseSchema : personalQuotaDataResponseSchema
  ).safeParse(response)
  if (!parsed.success) throw new Error(t('Failed to load'))
  return parsed.data
}

// ----------------------------------------------------------------------------
// System Monitoring
// ----------------------------------------------------------------------------

export async function getUserQuotaDataByUsers(params: {
  start_timestamp: number
  end_timestamp: number
}) {
  const res = await api.get<{ success: boolean; data: QuotaDataItem[] }>(
    '/api/data/users',
    { params }
  )
  return res.data
}

export async function getFlowQuotaDates(
  params: {
    start_timestamp: number
    end_timestamp: number
    default_time?: string
    username?: string
  },
  isAdmin = false
) {
  const endpoint = isAdmin ? '/api/data/flow' : '/api/data/flow/self'
  const res = await api.get<{
    success: boolean
    data?: FlowQuotaDataItem[]
    message?: string
  }>(endpoint, { params })
  return res.data
}

// Get uptime monitoring status for all services
export async function getUptimeStatus() {
  const res = await api.get<{ success: boolean; data: UptimeGroupResult[] }>(
    '/api/uptime/status'
  )
  return res.data
}
