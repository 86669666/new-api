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
import { useEffect, useRef, useState } from 'react'

import { useAuthStore } from '@/stores/auth-store'

import {
  revokeOrganizationInvitation,
  OrganizationRequestFailure,
  type OrganizationInvitationSlot,
} from './api'

type Confirmation = {
  invitation: OrganizationInvitationSlot
  controller: AbortController
  invoked: boolean
}

export function useRevokeInvitation(
  actorId: number,
  sid: string,
  orgId: string,
  refresh: () => void
) {
  const active = useRef<Confirmation | null>(null)
  const [selected, setSelected] = useState<OrganizationInvitationSlot | null>(
    null
  )
  const [pending, setPending] = useState(false)
  const [outcome, setOutcome] = useState<'success' | 'unconfirmed' | null>(null)
  const mutation = useMutation({
    mutationKey: ['organizations', actorId, sid, orgId, 'revoke-invitation'],
    mutationFn: (ticket: Confirmation) => {
      if (active.current !== ticket || ticket.controller.signal.aborted) {
        throw new OrganizationRequestFailure(
          undefined,
          undefined,
          undefined,
          true
        )
      }
      return revokeOrganizationInvitation(
        actorId,
        sid,
        orgId,
        ticket.invitation,
        ticket.controller.signal
      )
    },
    retry: false,
    networkMode: 'always',
    throwOnError: false,
    meta: { errorToast: false },
  })

  useEffect(() => {
    const unsubscribe = useAuthStore.subscribe((state) => {
      if (state.auth.user?.id !== actorId || state.auth.session?.sid !== sid) {
        active.current?.controller.abort()
        active.current = null
        setSelected(null)
        setPending(false)
        setOutcome(null)
      }
    })
    return () => {
      unsubscribe()
      active.current?.controller.abort()
      active.current = null
    }
  }, [actorId, sid, orgId])

  function select(invitation: OrganizationInvitationSlot) {
    if (active.current?.invoked || invitation.organization_id !== orgId) return
    active.current?.controller.abort()
    const snapshot = { ...invitation }
    active.current = {
      invitation: snapshot,
      controller: new AbortController(),
      invoked: false,
    }
    setSelected(snapshot)
    setOutcome(null)
  }

  function cancel() {
    if (active.current?.invoked) return
    active.current?.controller.abort()
    active.current = null
    setSelected(null)
  }

  async function confirm() {
    const ticket = active.current
    const auth = useAuthStore.getState().auth
    if (
      !ticket ||
      ticket.invoked ||
      ticket.invitation.organization_id !== orgId ||
      ticket.controller.signal.aborted ||
      auth.user?.id !== actorId ||
      auth.session?.sid !== sid
    ) {
      return
    }
    // Lock synchronously before scheduling the mutation, including double clicks.
    ticket.invoked = true
    setPending(true)
    setOutcome(null)
    try {
      await mutation.mutateAsync(ticket)
      if (active.current !== ticket || ticket.controller.signal.aborted) return
      setOutcome('success')
    } catch {
      if (active.current !== ticket || ticket.controller.signal.aborted) return
      // A failed or lost response does not prove that the command did not commit.
      setOutcome('unconfirmed')
    } finally {
      if (active.current === ticket && !ticket.controller.signal.aborted) {
        active.current = null
        setSelected(null)
        refresh()
        setPending(false)
      }
    }
  }

  return { selected, pending, outcome, select, cancel, confirm }
}
