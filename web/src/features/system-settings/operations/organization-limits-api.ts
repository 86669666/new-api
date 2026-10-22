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
import { api } from '@/lib/http-client'
import {
  createServerError,
  requireServerSuccess,
} from '@/lib/server-error-message'

import {
  organizationLimitsResponseSchema,
  type OrganizationLimitsForm,
} from './lib/organization-limits-schema'

export async function getOrganizationLimits(signal?: AbortSignal) {
  // Never reuse an earlier in-flight read after a committed write. Query handles
  // ordinary observer sharing; this bypasses the separate Axios GET dedup map.
  const response = await api.get<unknown>('/api/organizations/limits', {
    signal,
    disableDuplicate: true,
    skipErrorHandler: true,
  })
  const parsed = organizationLimitsResponseSchema.safeParse(
    requireServerSuccess(response.data)
  )
  if (!parsed.success) {
    throw createServerError({
      message_key: 'Organization limits are unavailable.',
    })
  }
  return parsed.data.data
}

export async function updateOrganizationLimits(values: OrganizationLimitsForm) {
  const response = await api.put<unknown>(
    '/api/option/organization_limits',
    values,
    {
      // A lost response may follow a commit. Even an authentication refresh must
      // not replay this PUT; the user resolves uncertainty with an explicit GET.
      skipAuthRefresh: true,
      skipErrorHandler: true,
    }
  )
  const data = requireServerSuccess(response.data)
  if (
    !data ||
    typeof data !== 'object' ||
    !('success' in data) ||
    data.success !== true
  ) {
    throw createServerError({
      message_key: 'Unable to confirm organization limits were saved.',
    })
  }
}
