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
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { TitledCard } from '@/components/ui/titled-card'
import { formatTimestamp } from '@/lib/format'
import { useAuthStore } from '@/stores/auth-store'

import { getOrganizationInvitationSlots } from './api'
import { useRevokeInvitation } from './use-revoke-invitation'

type InvitationSlotsProps = {
  actorId: number
  sid: string
  orgId: string
}

export function OrganizationInvitationSlotsCard(props: InvitationSlotsProps) {
  const actorId = useAuthStore((state) => state.auth.user?.id)
  const sid = useAuthStore((state) => state.auth.session?.sid)
  if (actorId !== props.actorId || sid !== props.sid) return null
  return (
    <InvitationSlots
      key={`${props.actorId}:${props.sid}:${props.orgId}`}
      {...props}
    />
  )
}

function InvitationSlots(props: InvitationSlotsProps) {
  const { t } = useTranslation()
  const [cursors, setCursors] = useState(['0'])
  const afterId = cursors.at(-1) ?? '0'
  const query = useQuery({
    queryKey: [
      'organizations',
      props.actorId,
      props.sid,
      'personal',
      'invitation-slots',
      props.orgId,
      afterId,
    ],
    queryFn: ({ signal }) =>
      getOrganizationInvitationSlots(
        props.actorId,
        props.sid,
        props.orgId,
        afterId,
        signal
      ),
    staleTime: 0,
    gcTime: 0,
    retry: false,
    networkMode: 'always',
    refetchOnWindowFocus: 'always',
    meta: { errorToast: false },
  })
  const revoke = useRevokeInvitation(
    props.actorId,
    props.sid,
    props.orgId,
    () => {
      void query.refetch()
    }
  )
  const busy = query.isFetching || query.isPending || revoke.pending
  const confirming = revoke.selected !== null
  let content
  if (query.isFetching || query.isPending) {
    content = <LoadingState />
  } else if (query.isError || !query.data) {
    content = (
      <ErrorState
        title={t('Unable to load organization invitations')}
        onRetry={() => void query.refetch()}
      />
    )
  } else if (query.data.items.length === 0) {
    content = <EmptyState title={t('No pending organization invitations')} />
  } else {
    content = (
      <ul className='divide-y' aria-label={t('Organization invitation slots')}>
        {query.data.items.map((slot) => (
          <li key={slot.object_id} className='min-w-0 space-y-2 py-3'>
            <div className='flex min-w-0 flex-wrap items-center justify-between gap-2'>
              <span className='min-w-0 break-all'>
                {slot.target_username ||
                  t('User ID: {{id}}', { id: slot.target_user_id })}
              </span>
              <div className='flex flex-wrap gap-2'>
                <Badge variant='secondary'>
                  {slot.role === 'admin'
                    ? t('Organization administrator')
                    : t('Organization member')}
                </Badge>
                <Badge variant='secondary'>
                  {slot.status === 'expired' ? t('Expired') : t('Pending')}
                </Badge>
              </div>
            </div>
            <p className='text-muted-foreground text-sm'>
              {t('Expires at {{time}}', {
                time: formatTimestamp(slot.expires_at),
              })}
            </p>
            {slot.status === 'pending' && (
              <Button
                variant='destructive'
                size='sm'
                disabled={
                  busy ||
                  confirming ||
                  !slot.organization_revision ||
                  !slot.organization_name ||
                  slot.expires_at <= Date.now() / 1000
                }
                onClick={() => revoke.select(slot)}
              >
                {t('Revoke invitation')}
              </Button>
            )}
          </li>
        ))}
      </ul>
    )
  }
  return (
    <TitledCard
      title={t('Organization invitation slots')}
      action={
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          aria-label={t('Refresh organization invitations')}
          disabled={busy || confirming}
          onClick={() => void query.refetch()}
        >
          {t('Refresh')}
        </Button>
      }
    >
      {revoke.outcome && (
        <p role='status' className='mb-3 text-sm'>
          {revoke.outcome === 'success'
            ? t('Organization invitation revoked.')
            : t(
                'Revocation was not confirmed. Review the refreshed invitation status before trying again.'
              )}
        </p>
      )}
      <div aria-busy={busy}>{content}</div>
      <ConfirmDialog
        open={confirming}
        onOpenChange={(open) => {
          if (!open) revoke.cancel()
        }}
        title={t('Revoke organization invitation?')}
        desc={
          <div className='space-y-2 break-all'>
            <p>
              {t(
                'Revoke the invitation for {{user}} to {{organization}}? The recipient will no longer be able to join using this version of the invitation.',
                {
                  user:
                    revoke.selected?.target_username ||
                    t('User ID: {{id}}', {
                      id: revoke.selected?.target_user_id ?? '',
                    }),
                  organization: revoke.selected?.organization_name ?? '',
                }
              )}
            </p>
            <p>
              {t('User ID: {{id}}', {
                id: revoke.selected?.target_user_id ?? '',
              })}
            </p>
          </div>
        }
        confirmText={t('Revoke invitation')}
        destructive
        disabled={query.isFetching || query.isError}
        isLoading={revoke.pending}
        handleConfirm={() => void revoke.confirm()}
      />
      <div className='mt-3 flex flex-wrap justify-between gap-2'>
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          aria-label={t('Previous invitation slots')}
          disabled={cursors.length === 1 || busy || confirming}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}
        >
          {t('Previous')}
        </Button>
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          aria-label={t('Next invitation slots')}
          disabled={
            busy || confirming || query.isError || !query.data?.next_after_id
          }
          onClick={() => {
            const next = query.data?.next_after_id
            if (next) setCursors((previous) => [...previous, next])
          }}
        >
          {t('Next')}
        </Button>
      </div>
    </TitledCard>
  )
}
