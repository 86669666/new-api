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
const roleSchema = z.enum(['owner', 'admin', 'member'])
const nameSchema = z
  .string()
  .min(1)
  .refine((value) => [...value].length <= 64)
const organizationSchema = z.object({
  org_id: idSchema,
  name: nameSchema,
  my_role: roleSchema,
})
const detailSchema = organizationSchema.extend({
  revision: idSchema,
  my_member_revision: idSchema,
})
const directorySchema = z.object({
  items: z.array(organizationSchema).max(20),
  limit: z.literal(20),
  next_after_id: idSchema.nullable(),
})
const membersSchema = z.object({
  items: z
    .array(
      z.object({
        member_id: idSchema,
        user_id: idSchema,
        username: z.string().max(64).nullish(),
        role: roleSchema,
        revision: idSchema,
      })
    )
    .max(20),
  limit: z.literal(20),
  next_after_id: idSchema.nullable(),
})

// All organization reads share the subject/session and cancellation boundary.
async function readOrganizationData(
  actorId: number,
  sid: string,
  path: string,
  signal: AbortSignal,
  params?: { after_id: string; limit: number }
): Promise<unknown> {
  const assertIdentity = () => {
    const auth = useAuthStore.getState().auth
    if (
      signal.aborted ||
      auth.user?.id !== actorId ||
      auth.session?.sid !== sid
    ) {
      throw new CanceledError('Organization read identity changed')
    }
  }
  assertIdentity()
  const response = await api.get(path, {
    params,
    signal,
    disableDuplicate: true,
  })
  assertIdentity()
  const result = requireServerSuccess(response.data)
  // A malformed/null envelope is unavailable, never an empty successful list.
  return z.object({ success: z.literal(true), data: z.unknown() }).parse(result)
    .data
}

function validateCursor(next: string | null, afterId: string) {
  if (next && BigInt(next) <= BigInt(afterId)) {
    throw new Error('Invalid organization cursor')
  }
}

export async function getMyOrganizations(
  actorId: number,
  sid: string,
  afterId: string,
  signal: AbortSignal
) {
  const page = directorySchema.parse(
    await readOrganizationData(actorId, sid, '/api/organizations', signal, {
      after_id: afterId,
      limit: 20,
    })
  )
  validateCursor(page.next_after_id, afterId)
  return page
}

export async function getOrganizationDetails(
  actorId: number,
  sid: string,
  orgId: string,
  signal: AbortSignal
) {
  idSchema.parse(orgId)
  const detail = detailSchema.parse(
    await readOrganizationData(
      actorId,
      sid,
      `/api/organizations/${orgId}`,
      signal
    )
  )
  if (detail.org_id !== orgId) {
    throw new Error('Organization response identity mismatch')
  }
  return detail
}

export async function getOrganizationMembers(
  actorId: number,
  sid: string,
  orgId: string,
  afterId: string,
  signal: AbortSignal
) {
  idSchema.parse(orgId)
  z.union([z.literal('0'), idSchema]).parse(afterId)
  const page = membersSchema.parse(
    await readOrganizationData(
      actorId,
      sid,
      `/api/organizations/${orgId}/members`,
      signal,
      { after_id: afterId, limit: 20 }
    )
  )
  validateCursor(page.next_after_id, afterId)
  return page
}
