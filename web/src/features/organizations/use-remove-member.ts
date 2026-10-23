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
import { useMutation } from '@tanstack/react-query'
import { useCallback, useEffect, useRef, useState } from 'react'

import { useAuthStore } from '@/stores/auth-store'

import {
  canRemoveOrganizationMember,
  getOrganizationDetails,
  getOrganizationMembers,
  OrganizationRequestFailure,
  projectOrganizationRequestFailure,
  removeOrganizationMember,
  type OrganizationDetail,
  type OrganizationMember,
  type RemoveMemberIntent,
} from './api'

type Selection = {
  detail: OrganizationDetail
  member: OrganizationMember
  afterId: string
}
type Ticket = {
  controller: AbortController
  invoked: boolean
  intent?: RemoveMemberIntent
}

/** A ticket lives only in this actor/SID/org keyed details instance. */
export function useRemoveMember(actorId: number, sid: string, orgId: string) {
  const active = useRef<Ticket | null>(null)
  const [pending, setPending] = useState(false)
  const mutation = useMutation({
    mutationKey: ['organizations', 'remove-member', actorId, orgId],
    mutationFn: async (intent: RemoveMemberIntent) => {
      const ticket = active.current
      try {
        assertCurrent(ticket)
        if (ticket.intent !== intent) {
          throw new OrganizationRequestFailure(
            undefined,
            undefined,
            undefined,
            true
          )
        }
        ticket.invoked = true
        const receipt = await removeOrganizationMember(
          actorId,
          sid,
          intent,
          ticket.controller.signal
        )
        assertCurrent(ticket)
        return receipt
      } catch (error) {
        throw projectOrganizationRequestFailure(
          error,
          ticket?.controller.signal
        )
      }
    },
    retry: false,
    networkMode: 'always',
    throwOnError: false,
    meta: { errorToast: false },
  })

  function assertCurrent(ticket: Ticket | null): asserts ticket is Ticket {
    const auth = useAuthStore.getState().auth
    if (
      !ticket ||
      active.current !== ticket ||
      ticket.controller.signal.aborted ||
      auth.user?.id !== actorId ||
      auth.session?.sid !== sid
    ) {
      throw new OrganizationRequestFailure(
        undefined,
        undefined,
        undefined,
        true
      )
    }
  }

  const cancel = useCallback(() => {
    const ticket = active.current
    active.current = null
    ticket?.controller.abort()
    setPending(false)
    return ticket?.invoked === true
  }, [])

  useEffect(() => {
    const unsubscribe = useAuthStore.subscribe((state) => {
      if (state.auth.user?.id !== actorId || state.auth.session?.sid !== sid) {
        cancel()
      }
    })
    return () => {
      unsubscribe()
      const ticket = active.current
      active.current = null
      ticket?.controller.abort()
    }
  }, [actorId, sid, orgId, cancel])

  async function remove(selection: Selection) {
    if (active.current) return
    // Synchronous ref lock precedes both preflight reads and mutation scheduling.
    const ticket: Ticket = { controller: new AbortController(), invoked: false }
    active.current = ticket
    setPending(true)
    try {
      assertCurrent(ticket)
      if (
        selection.detail.org_id !== orgId ||
        !canRemoveOrganizationMember(
          actorId,
          selection.detail,
          selection.member
        )
      ) {
        throw new OrganizationRequestFailure('ORG_STATE_CHANGED', 409)
      }
      const [detail, members] = await Promise.all([
        getOrganizationDetails(actorId, sid, orgId, ticket.controller.signal),
        getOrganizationMembers(
          actorId,
          sid,
          orgId,
          selection.afterId,
          ticket.controller.signal
        ),
      ])
      assertCurrent(ticket)
      const target = members.items.find(
        (member) => member.member_id === selection.member.member_id
      )
      if (
        detail.revision !== selection.detail.revision ||
        detail.my_role !== selection.detail.my_role ||
        detail.my_member_revision !== selection.detail.my_member_revision ||
        !target ||
        target.user_id !== selection.member.user_id ||
        target.revision !== selection.member.revision ||
        target.role !== selection.member.role ||
        !canRemoveOrganizationMember(actorId, detail, target)
      ) {
        throw new OrganizationRequestFailure('ORG_STATE_CHANGED', 409)
      }
      ticket.intent = {
        orgId,
        targetUserId: target.user_id,
        memberId: target.member_id,
        revision: detail.revision,
      }
      const receipt = await mutation.mutateAsync(ticket.intent)
      assertCurrent(ticket)
      return { kind: 'success' as const, receipt }
    } catch (error) {
      // An invalidated ticket never produces feedback in a new view or identity.
      if (active.current !== ticket) return
      const failure = projectOrganizationRequestFailure(
        error,
        ticket.controller.signal
      )
      return {
        kind: 'failure' as const,
        error: failure,
        unconfirmed:
          ticket.invoked &&
          (!failure.status || failure.status >= 500 || failure.cancelled),
      }
    } finally {
      if (active.current === ticket) {
        active.current = null
        setPending(false)
      }
    }
  }

  return { pending, remove, cancel }
}
