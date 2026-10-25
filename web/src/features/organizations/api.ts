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

import { api, organizationRequestOptions } from '@/lib/api'
import { AuthOperationError } from '@/lib/secure-verification'
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

export type OrganizationDetail = z.infer<typeof detailSchema>
export type OrganizationMember = z.infer<typeof membersSchema>['items'][number]
export type RemoveMemberIntent = {
  orgId: string
  targetUserId: string
  memberId: string
  revision: string
}

const failureMessages: Record<string, readonly [number, string]> = {
  ORG_REQUEST_INVALID: [400, 'Invalid organization request.'],
  AUTH_SESSION_REVOKED: [401, 'The login session is no longer active.'],
  AUTH_UNAUTHORIZED: [401, 'Session expired!'],
  AUTH_SESSION_REQUIRED: [403, 'A dashboard session is required.'],
  AUTH_ORIGIN_FORBIDDEN: [403, 'request origin is not allowed'],
  ORG_FORBIDDEN: [403, 'Organization operation is forbidden.'],
  ORG_NOT_FOUND: [404, 'Organization is unavailable.'],
  ORG_STATE_CHANGED: [
    409,
    'Organization state changed. Refresh the organization state before retrying.',
  ],
  ORG_DISABLED: [409, 'Organization is disabled.'],
  ORG_REQUEST_RESOLVED: [409, 'Organization request is already resolved.'],
  ORG_INTERNAL_ERROR: [500, 'Unable to complete organization operation.'],
  SECURITY_PROOF_REQUIRED: [
    403,
    'Organization state changed. Refresh the organization state before retrying.',
  ],
  REQUEST_TOO_LARGE: [413, 'Unable to complete organization operation.'],
  UNSUPPORTED_MEDIA_TYPE: [415, 'Unable to complete organization operation.'],
}

/** Only primitive, fixed messages cross the feature's public/cache boundary. */
export class OrganizationRequestFailure extends AuthOperationError {
  readonly __CANCEL__?: true
  constructor(
    code?: string,
    readonly status?: number,
    readonly retryAfter?: number,
    readonly cancelled = false
  ) {
    const entry =
      code && Object.hasOwn(failureMessages, code)
        ? failureMessages[code]
        : undefined
    let safeCode = entry ? code : undefined
    if (cancelled) safeCode = 'AUTH_CANCELLED'
    super(
      entry && entry[0] === status
        ? entry[1]
        : 'Unable to complete organization operation.',
      safeCode
    )
    if (cancelled) this.__CANCEL__ = true
  }
}

// Do not evaluate source getters or copy any source object (including causes).
function own(value: unknown, key: string): unknown {
  try {
    if (!value || typeof value !== 'object') return undefined
    return Object.getOwnPropertyDescriptor(value, key)?.value
  } catch {
    return undefined
  }
}

export function projectOrganizationRequestFailure(
  error: unknown,
  signal?: AbortSignal
): OrganizationRequestFailure {
  let status: number | undefined
  let code: string | undefined
  let retryAfter: number | undefined
  let cancelled = signal?.aborted === true
  const pending = [error]
  const seen = new Set<unknown>()
  for (let i = 0; i < pending.length && i < 16; i++) {
    const value = pending[i]
    if (!value || typeof value !== 'object' || seen.has(value)) continue
    seen.add(value)
    const candidate = own(value, 'status')
    if (
      typeof candidate === 'number' &&
      Number.isInteger(candidate) &&
      candidate >= 100 &&
      candidate <= 599 &&
      status === undefined
    ) {
      status = candidate
    }
    const candidateCode = own(value, 'code')
    if (
      typeof candidateCode === 'string' &&
      Object.hasOwn(failureMessages, candidateCode)
    ) {
      code ??= candidateCode
    }
    cancelled ||=
      own(value, '__CANCEL__') === true ||
      candidateCode === 'ERR_CANCELED' ||
      candidateCode === 'AUTH_CANCELLED' ||
      own(value, 'name') === 'AbortError'
    const headers = own(value, 'headers')
    let headerRetry: unknown
    try {
      if (headers && typeof headers === 'object') {
        const key = Object.getOwnPropertyNames(headers).find(
          (name) => name.toLowerCase() === 'retry-after'
        )
        if (key) headerRetry = own(headers, key)
      }
    } catch {
      // Exotic headers still project to the fixed fallback without references.
    }
    const retry = own(value, 'retryAfter') ?? headerRetry
    let seconds: number | undefined
    if (typeof retry === 'number') {
      seconds = retry
    } else if (
      typeof retry === 'string' &&
      /^(0|[1-9][0-9]{0,4})$(?![\s\S])/.test(retry)
    ) {
      seconds = Number(retry)
    }
    if (
      seconds !== undefined &&
      Number.isSafeInteger(seconds) &&
      seconds >= 0 &&
      seconds <= 86400
    ) {
      retryAfter ??= seconds
    }
    pending.push(
      own(value, 'response'),
      own(value, 'data'),
      own(value, 'cause'),
      own(value, 'error')
    )
  }
  return new OrganizationRequestFailure(code, status, retryAfter, cancelled)
}

const wireIdSchema = idSchema.refine(
  (value) => BigInt(value) <= 9223372036854775807n
)
export function canRemoveOrganizationMember(
  actorId: number,
  detail: OrganizationDetail,
  member: OrganizationMember
) {
  return (
    Number.isSafeInteger(actorId) &&
    actorId > 0 &&
    (detail.my_role === 'owner' || detail.my_role === 'admin') &&
    member.role === 'member' &&
    member.user_id !== String(actorId) &&
    [
      detail.org_id,
      detail.revision,
      detail.my_member_revision,
      member.member_id,
      member.user_id,
      member.revision,
    ].every((id) => wireIdSchema.safeParse(id).success)
  )
}

const receiptSchema = z.object({
  organization_id: wireIdSchema,
  revision: wireIdSchema,
  action: z.literal('remove'),
  event_id: wireIdSchema,
  object_kind: z.literal('member'),
  object_id: wireIdSchema,
  generation: z.null(),
  status: z.null(),
})

export async function removeOrganizationMember(
  actorId: number,
  sid: string,
  intent: RemoveMemberIntent,
  signal: AbortSignal
) {
  try {
    if (
      !Number.isSafeInteger(actorId) ||
      actorId <= 0 ||
      intent.targetUserId === String(actorId)
    ) {
      throw new Error()
    }
    for (const id of [
      intent.orgId,
      intent.targetUserId,
      intent.memberId,
      intent.revision,
    ]) {
      wireIdSchema.parse(id)
    }
    const response = await api.delete(
      `/api/organizations/${intent.orgId}/members/${intent.targetUserId}`,
      {
        ...organizationRequestOptions({ userId: actorId, sid }, signal),
        data: { revision: intent.revision },
      }
    )
    if (response.status !== 200) throw new Error()
    const receipt = receiptSchema.parse(
      z
        .object({ success: z.literal(true), data: z.unknown() })
        .parse(requireServerSuccess(response.data)).data
    )
    if (
      receipt.organization_id !== intent.orgId ||
      receipt.object_id !== intent.memberId ||
      BigInt(receipt.revision) <= BigInt(intent.revision)
    ) {
      throw new Error()
    }
    return receipt
  } catch (error) {
    throw projectOrganizationRequestFailure(error, signal)
  }
}

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
    expectedAuthIdentity: { userId: actorId, sid },
    skipErrorHandler: true,
    skipBusinessError: true,
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
  try {
    const page = directorySchema.parse(
      await readOrganizationData(actorId, sid, '/api/organizations', signal, {
        after_id: afterId,
        limit: 20,
      })
    )
    validateCursor(page.next_after_id, afterId)
    return page
  } catch (error) {
    throw projectOrganizationRequestFailure(error, signal)
  }
}

export async function getOrganizationDetails(
  actorId: number,
  sid: string,
  orgId: string,
  signal: AbortSignal
) {
  try {
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
  } catch (error) {
    throw projectOrganizationRequestFailure(error, signal)
  }
}

export async function getOrganizationMembers(
  actorId: number,
  sid: string,
  orgId: string,
  afterId: string,
  signal: AbortSignal
) {
  try {
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
  } catch (error) {
    throw projectOrganizationRequestFailure(error, signal)
  }
}

const invitationSchema = z.object({
  organization_id: wireIdSchema,
  organization_name: z.string().min(1),
  organization_revision: wireIdSchema,
  object_id: wireIdSchema,
  generation: wireIdSchema,
  kind: z.literal('invitation'),
  target_user_id: wireIdSchema,
  from_username: z.string(),
  role: z.enum(['member', 'admin']),
  status: z.literal('pending'),
  expires_at: z.number().int().min(0).max(8640000000000),
})
const invitationsSchema = z.object({
  items: z.array(invitationSchema).max(20),
  limit: z.literal(20),
  next_after_id: wireIdSchema.nullable(),
})

export async function getMyOrganizationInvitations(
  actorId: number,
  sid: string,
  afterId: string,
  signal: AbortSignal
) {
  // An identity change invalidates this operation permanently, including A→B→A
  // before React renders again. Do not revive a request under a reused SID.
  const identityChanged = new AbortController()
  const unsubscribe = useAuthStore.subscribe((state) => {
    if (state.auth.user?.id !== actorId || state.auth.session?.sid !== sid) {
      identityChanged.abort()
    }
  })
  const boundSignal = AbortSignal.any([signal, identityChanged.signal])
  try {
    if (!Number.isSafeInteger(actorId) || actorId <= 0 || !sid) {
      throw new Error()
    }
    z.union([z.literal('0'), wireIdSchema]).parse(afterId)
    const page = invitationsSchema.parse(
      await readOrganizationData(
        actorId,
        sid,
        '/api/organization-invitations',
        boundSignal,
        { after_id: afterId, limit: 20 }
      )
    )
    let previous = BigInt(afterId)
    for (const invitation of page.items) {
      if (
        invitation.target_user_id !== String(actorId) ||
        BigInt(invitation.object_id) <= previous
      ) {
        throw new Error()
      }
      previous = BigInt(invitation.object_id)
    }
    const expectedNext =
      page.items.length === 20 ? page.items.at(-1)?.object_id : null
    if (page.next_after_id !== expectedNext) throw new Error()
    return page
  } catch (error) {
    throw projectOrganizationRequestFailure(error, boundSignal)
  } finally {
    unsubscribe()
  }
}

// Q02 intentionally has no invitation role or inviter-name contract.
const transferSchema = z.object({
  organization_id: wireIdSchema,
  organization_name: z.string().min(1),
  organization_revision: wireIdSchema,
  object_id: wireIdSchema,
  generation: wireIdSchema,
  kind: z.literal('transfer'),
  target_user_id: wireIdSchema,
  status: z.literal('pending'),
  expires_at: z.number().int().min(0).max(8640000000000),
})
const transfersSchema = z.object({
  items: z.array(transferSchema).max(20),
  limit: z.literal(20),
  next_after_id: wireIdSchema.nullable(),
})

export async function getMyOrganizationTransfers(
  actorId: number,
  sid: string,
  afterId: string,
  signal: AbortSignal
) {
  // An identity change invalidates this operation permanently, including A→B→A
  // before React renders again. Do not revive a request under a reused SID.
  const identityChanged = new AbortController()
  const unsubscribe = useAuthStore.subscribe((state) => {
    if (state.auth.user?.id !== actorId || state.auth.session?.sid !== sid) {
      identityChanged.abort()
    }
  })
  const boundSignal = AbortSignal.any([signal, identityChanged.signal])
  try {
    if (!Number.isSafeInteger(actorId) || actorId <= 0 || !sid) {
      throw new Error()
    }
    z.union([z.literal('0'), wireIdSchema]).parse(afterId)
    const page = transfersSchema.parse(
      await readOrganizationData(
        actorId,
        sid,
        '/api/organization-ownership-transfers',
        boundSignal,
        { after_id: afterId, limit: 20 }
      )
    )
    let previous = BigInt(afterId)
    for (const transfer of page.items) {
      if (
        transfer.target_user_id !== String(actorId) ||
        BigInt(transfer.object_id) <= previous
      ) {
        throw new Error()
      }
      previous = BigInt(transfer.object_id)
    }
    const expectedNext =
      page.items.length === 20 ? page.items.at(-1)?.object_id : null
    if (page.next_after_id !== expectedNext) throw new Error()
    return page
  } catch (error) {
    throw projectOrganizationRequestFailure(error, boundSignal)
  } finally {
    unsubscribe()
  }
}

export type OrganizationTransfer = z.infer<typeof transferSchema>

const declinedTransferSchema = z.object({
  organization_id: wireIdSchema,
  revision: wireIdSchema,
  action: z.literal('transfer_decline'),
  event_id: wireIdSchema,
  object_kind: z.literal('transfer'),
  object_id: wireIdSchema,
  generation: wireIdSchema,
  status: z.literal('declined'),
})

/** Decline is session-authorized, not a proof-bearing ownership acceptance. */
export async function declineOrganizationTransfer(
  actorId: number,
  sid: string,
  selected: OrganizationTransfer,
  signal: AbortSignal
) {
  const identityChanged = new AbortController()
  const unsubscribe = useAuthStore.subscribe((state) => {
    if (state.auth.user?.id !== actorId || state.auth.session?.sid !== sid) {
      identityChanged.abort()
    }
  })
  const boundSignal = AbortSignal.any([signal, identityChanged.signal])
  const assertIdentity = () => {
    const auth = useAuthStore.getState().auth
    if (
      boundSignal.aborted ||
      auth.user?.id !== actorId ||
      auth.session?.sid !== sid
    ) {
      throw new CanceledError('Organization identity changed')
    }
  }
  try {
    assertIdentity()
    const intent = transferSchema.parse(selected)
    if (
      !Number.isSafeInteger(actorId) ||
      actorId <= 0 ||
      !sid ||
      intent.target_user_id !== String(actorId) ||
      intent.expires_at <= Date.now() / 1000
    ) {
      throw new Error()
    }
    const response = await api.post(
      `/api/organizations/${intent.organization_id}/ownership-transfers/${intent.object_id}/decline`,
      { revision: intent.organization_revision, generation: intent.generation },
      organizationRequestOptions({ userId: actorId, sid }, boundSignal)
    )
    assertIdentity()
    if (response.status !== 200) throw new Error()
    const receipt = declinedTransferSchema.parse(
      z
        .object({ success: z.literal(true), data: z.unknown() })
        .parse(requireServerSuccess(response.data)).data
    )
    if (
      receipt.organization_id !== intent.organization_id ||
      receipt.object_id !== intent.object_id ||
      receipt.generation !== intent.generation ||
      BigInt(receipt.revision) <= BigInt(intent.organization_revision)
    ) {
      throw new Error()
    }
    return receipt
  } catch (error) {
    throw projectOrganizationRequestFailure(error, boundSignal)
  } finally {
    unsubscribe()
  }
}
