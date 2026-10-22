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
import { CanceledError } from 'axios'
import { z } from 'zod'

import { api } from '@/lib/api'
import { requireServerSuccess } from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

const idSchema = z.string().regex(/^[1-9][0-9]{0,18}$(?![\s\S])/)
const directorySchema = z.object({
  items: z
    .array(
      z.object({
        org_id: idSchema,
        name: z
          .string()
          .min(1)
          .refine((value) => [...value].length <= 64),
        my_role: z.enum(['owner', 'admin', 'member']),
      })
    )
    .max(20),
  limit: z.literal(20),
  next_after_id: idSchema.nullable(),
})

export async function getMyOrganizations(
  actorId: number,
  sid: string,
  afterId: string,
  signal: AbortSignal
) {
  const response = await api.get('/api/organizations', {
    params: { after_id: afterId, limit: 20 },
    signal,
    disableDuplicate: true,
  })
  const auth = useAuthStore.getState().auth
  if (auth.user?.id !== actorId || auth.session?.sid !== sid) {
    throw new CanceledError('Organization directory identity changed')
  }
  const result = requireServerSuccess(response.data)
  const page = directorySchema.parse(result.data)
  if (page.next_after_id && BigInt(page.next_after_id) <= BigInt(afterId)) {
    throw new Error('Invalid organization directory cursor')
  }
  return page
}
