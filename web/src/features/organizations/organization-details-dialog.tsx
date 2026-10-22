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

import { Dialog } from '@/components/dialog'
import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  getServerErrorMessage,
  getServerErrorStatus,
} from '@/lib/server-error-message'

import { getOrganizationDetails, getOrganizationMembers } from './api'

type OrganizationDetailsProps = {
  actorId: number
  sid: string
  orgId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function OrganizationDetailsDialog(props: OrganizationDetailsProps) {
  const { t } = useTranslation()
  return (
    <Dialog
      open={props.open}
      onOpenChange={props.onOpenChange}
      title={t('Organization details')}
      showCloseButton={false}
      footer={
        <Button variant='outline' onClick={() => props.onOpenChange(false)}>
          {t('Close')}
        </Button>
      }
      contentClassName='sm:max-w-lg'
    >
      {props.open && (
        <OrganizationDetails
          key={`${props.actorId}:${props.sid}:${props.orgId}`}
          {...props}
        />
      )}
    </Dialog>
  )
}

function OrganizationDetails(props: OrganizationDetailsProps) {
  const { t } = useTranslation()
  const [cursors, setCursors] = useState(['0'])
  const afterId = cursors.at(-1) ?? '0'
  const query = useQuery({
    queryKey: [
      'organizations',
      props.actorId,
      props.sid,
      'personal',
      'detail',
      props.orgId,
      afterId,
    ],
    queryFn: async ({ signal }) => {
      const [detail, members] = await Promise.all([
        getOrganizationDetails(props.actorId, props.sid, props.orgId, signal),
        getOrganizationMembers(
          props.actorId,
          props.sid,
          props.orgId,
          afterId,
          signal
        ),
      ])
      return { detail, members }
    },
    staleTime: 0,
    gcTime: 0,
    retry: false,
    refetchOnWindowFocus: 'always',
    meta: { errorToast: false },
  })
  const data = query.isFetching || query.isError ? undefined : query.data
  const roles = {
    owner: t('Organization owner'),
    admin: t('Organization administrator'),
    member: t('Organization member'),
  }
  let content
  if (query.isFetching || query.isPending) {
    content = <LoadingState />
  } else if (query.isError || !query.data) {
    content = (
      <ErrorState
        title={t('Unable to load organization')}
        description={
          getServerErrorStatus(query.error)
            ? getServerErrorMessage(query.error)
            : undefined
        }
        onRetry={() => void query.refetch()}
      />
    )
  } else {
    const { members } = query.data
    content =
      members.items.length === 0 ? (
        <EmptyState title={t('No members to display')} />
      ) : (
        <ul className='divide-y' aria-label={t('Organization members')}>
          {members.items.map((member) => (
            <li
              key={member.member_id}
              className='flex min-w-0 flex-wrap items-center justify-between gap-2 py-3'
            >
              {member.username ? (
                <span className='min-w-0 break-all'>{member.username}</span>
              ) : (
                <span className='text-muted-foreground text-sm'>—</span>
              )}
              <Badge variant='secondary'>{roles[member.role]}</Badge>
            </li>
          ))}
        </ul>
      )
  }
  return (
    <div className='space-y-4' aria-busy={query.isFetching} aria-live='polite'>
      {data && (
        <div className='flex min-w-0 flex-wrap items-center justify-between gap-2'>
          <h3 className='min-w-0 font-medium break-all'>{data.detail.name}</h3>
          <Badge variant='secondary'>{roles[data.detail.my_role]}</Badge>
        </div>
      )}
      <div className='flex flex-wrap items-center justify-between gap-2'>
        <h4 className='font-medium'>{t('Organization members')}</h4>
        <Button
          variant='outline'
          size='sm'
          className='data-disabled:opacity-50'
          focusableWhenDisabled
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
        >
          {t('Refresh')}
        </Button>
      </div>
      {content}
      <div className='flex flex-wrap justify-between gap-2'>
        <Button
          variant='outline'
          size='sm'
          className='data-disabled:opacity-50'
          focusableWhenDisabled
          disabled={cursors.length === 1 || !data}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}
        >
          {t('Previous')}
        </Button>
        <Button
          variant='outline'
          size='sm'
          className='data-disabled:opacity-50'
          focusableWhenDisabled
          disabled={!data?.members.next_after_id}
          onClick={() => {
            const next = data?.members.next_after_id
            if (next) setCursors((previous) => [...previous, next])
          }}
        >
          {t('Next')}
        </Button>
      </div>
    </div>
  )
}
