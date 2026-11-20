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
  declineOrganizationInvitation,
  OrganizationRequestFailure,
  type OrganizationInvitation,
} from './api'

type Confirmation = {
  invitation: OrganizationInvitation
  controller: AbortController
  invoked: boolean
}

export function useDeclineInvitation(
  actorId: number,
  sid: string,
  refresh: () => void
) {
  const active = useRef<Confirmation | null>(null)
  const [selected, setSelected] = useState<OrganizationInvitation | null>(null)
  const [pending, setPending] = useState(false)
  const [outcome, setOutcome] = useState<'success' | 'unconfirmed' | null>(null)
  const mutation = useMutation({
    mutationKey: ['organizations', actorId, sid, 'decline-invitation'],
    mutationFn: (ticket: Confirmation) => {
      if (active.current !== ticket || ticket.controller.signal.aborted) {
        throw new OrganizationRequestFailure(
          undefined,
          undefined,
          undefined,
          true
        )
      }
      return declineOrganizationInvitation(
        actorId,
        sid,
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
  }, [actorId, sid])

  function select(invitation: OrganizationInvitation) {
    if (active.current?.invoked) return
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
