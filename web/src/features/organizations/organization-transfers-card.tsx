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

import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { TitledCard } from '@/components/ui/titled-card'
import { formatTimestamp } from '@/lib/format'
import { useAuthStore } from '@/stores/auth-store'

import { getMyOrganizationTransfers } from './api'

export function OrganizationTransfersCard() {
  const actorId = useAuthStore((state) => state.auth.user?.id)
  const sid = useAuthStore((state) => state.auth.session?.sid)
  if (!actorId || !sid) return null
  return <TransferInbox key={`${actorId}:${sid}`} actorId={actorId} sid={sid} />
}

function TransferInbox(props: { actorId: number; sid: string }) {
  const { t } = useTranslation()
  const [cursors, setCursors] = useState(['0'])
  const afterId = cursors.at(-1) ?? '0'
  const query = useQuery({
    queryKey: [
      'organizations',
      props.actorId,
      props.sid,
      'personal',
      'transfers',
      afterId,
    ],
    queryFn: ({ signal }) =>
      getMyOrganizationTransfers(props.actorId, props.sid, afterId, signal),
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: 'always',
    meta: { errorToast: false },
  })
  const busy = query.isFetching || query.isPending
  let content
  if (busy) {
    content = <LoadingState />
  } else if (query.isError || !query.data) {
    content = (
      <ErrorState
        title={t('Unable to load ownership transfers')}
        onRetry={() => void query.refetch()}
      />
    )
  } else if (query.data.items.length === 0) {
    content = <EmptyState title={t('No pending ownership transfers')} />
  } else {
    content = (
      <ul className='divide-y' aria-label={t('Ownership transfers')}>
        {query.data.items.map((transfer) => (
          <li key={transfer.object_id} className='min-w-0 space-y-2 py-3'>
            <div className='flex min-w-0 flex-wrap items-center justify-between gap-2'>
              <span className='min-w-0 break-all'>
                {transfer.organization_name}
              </span>
              <Badge variant='secondary'>{t('Pending')}</Badge>
            </div>
            <p className='text-muted-foreground text-sm'>
              {t('Expires at {{time}}', {
                time: formatTimestamp(transfer.expires_at),
              })}
            </p>
          </li>
        ))}
      </ul>
    )
  }
  return (
    <TitledCard
      title={t('Ownership transfers')}
      description={t(
        'Pending ownership transfers to you. This view is read-only.'
      )}
      action={
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          disabled={busy}
          onClick={() => void query.refetch()}
        >
          {t('Refresh')}
        </Button>
      }
    >
      <div aria-busy={busy}>{content}</div>
      <div className='mt-3 flex flex-wrap justify-between gap-2'>
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          disabled={cursors.length === 1 || busy}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}
        >
          {t('Previous')}
        </Button>
        <Button
          variant='outline'
          size='sm'
          focusableWhenDisabled
          disabled={busy || query.isError || !query.data?.next_after_id}
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
