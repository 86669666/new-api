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
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ConfirmDialog } from '@/components/confirm-dialog'
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
import { useAuthStore } from '@/stores/auth-store'

import {
  canRemoveOrganizationMember,
  getOrganizationDetails,
  getOrganizationMembers,
  OrganizationRequestFailure,
  projectOrganizationRequestFailure,
  type OrganizationDetail,
  type OrganizationMember,
} from './api'
import { useRemoveMember } from './use-remove-member'

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
  const client = useQueryClient()
  const removal = useRemoveMember(props.actorId, props.sid, props.orgId)
  const refreshButton = useRef<HTMLButtonElement>(null)
  const mounted = useRef(true)
  const [selection, setSelection] = useState<{
    detail: OrganizationDetail
    member: OrganizationMember
    afterId: string
  } | null>(null)
  const [blocked, setBlocked] = useState(false)
  const [readFailure, setReadFailure] =
    useState<OrganizationRequestFailure | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [cursors, setCursors] = useState(['0'])
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  function isCurrentView() {
    const auth = useAuthStore.getState().auth
    return (
      mounted.current &&
      auth.user?.id === props.actorId &&
      auth.session?.sid === props.sid
    )
  }

  function refresh() {
    setBlocked(false)
    setReadFailure(null)
    setNotice(null)
    void query.refetch()
  }

  async function refreshAfterWrite() {
    const detailKey = [
      'organizations',
      props.actorId,
      props.sid,
      'personal',
      'detail',
      props.orgId,
    ]
    try {
      await client.cancelQueries({ queryKey: detailKey })
      if (!isCurrentView()) return
      client.removeQueries({ queryKey: detailKey })
      setCursors(['0'])
      // fetchQuery explicitly reads page zero even when page zero was already open.
      const freshRead = client.fetchQuery({
        queryKey: [...detailKey, '0'],
        queryFn: async ({ signal }) => {
          const [detail, members] = await Promise.all([
            getOrganizationDetails(
              props.actorId,
              props.sid,
              props.orgId,
              signal
            ),
            getOrganizationMembers(
              props.actorId,
              props.sid,
              props.orgId,
              '0',
              signal
            ),
          ])
          return { detail, members }
        },
        staleTime: 0,
        gcTime: 0,
        retry: false,
        meta: { errorToast: false },
      })
      void client.invalidateQueries({
        queryKey: [
          'organizations',
          props.actorId,
          props.sid,
          'personal',
          'directory',
        ],
      })
      await freshRead
      if (isCurrentView()) setBlocked(false)
    } catch (error) {
      if (isCurrentView()) {
        setReadFailure(projectOrganizationRequestFailure(error))
      }
    }
  }

  async function confirmRemoval() {
    if (!selection) return
    const result = await removal.remove(selection)
    if (!result || !isCurrentView()) return
    setSelection(null)
    setBlocked(true)
    if (result.kind === 'success') {
      setNotice('Organization member removed')
      // This GET work is outside mutationFn and all mutation lifecycle callbacks.
      void refreshAfterWrite()
    } else {
      setNotice(
        result.unconfirmed
          ? 'The result could not be confirmed. Refresh the organization before trying again.'
          : result.error.message
      )
    }
    if (refreshButton.current?.isConnected) refreshButton.current.focus()
  }

  function closeConfirmation() {
    const invoked = removal.cancel()
    setSelection(null)
    if (invoked) {
      setBlocked(true)
      setNotice(
        'The result could not be confirmed. Refresh the organization before trying again.'
      )
    }
    if (refreshButton.current?.isConnected) refreshButton.current.focus()
  }
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
  const data =
    blocked || query.isFetching || query.isError ? undefined : query.data
  const roles = {
    owner: t('Organization owner'),
    admin: t('Organization administrator'),
    member: t('Organization member'),
  }
  let readErrorMessage: string | undefined
  if (query.error instanceof OrganizationRequestFailure) {
    readErrorMessage = t(query.error.message)
  } else if (getServerErrorStatus(query.error)) {
    readErrorMessage = getServerErrorMessage(query.error)
  }
  let content
  if (query.isFetching || query.isPending) {
    content = <LoadingState />
  } else if (blocked || query.isError || !query.data) {
    content = (
      <ErrorState
        title={t('Unable to load organization')}
        description={readFailure ? t(readFailure.message) : readErrorMessage}
        onRetry={refresh}
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
              <div className='flex flex-wrap items-center gap-2'>
                <Badge variant='secondary'>{roles[member.role]}</Badge>
                {canRemoveOrganizationMember(
                  props.actorId,
                  query.data.detail,
                  member
                ) && (
                  <Button
                    variant='destructive'
                    size='sm'
                    disabled={removal.pending}
                    onClick={() =>
                      setSelection({
                        detail: query.data.detail,
                        member,
                        afterId,
                      })
                    }
                  >
                    {t('Remove')}
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )
  }
  return (
    <div className='space-y-4' aria-busy={query.isFetching} aria-live='polite'>
      {notice && (
        <p role='status' className='break-words'>
          {t(notice)}
        </p>
      )}
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
          ref={refreshButton}
          disabled={query.isFetching || removal.pending}
          onClick={refresh}
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
      <ConfirmDialog
        open={selection !== null}
        onOpenChange={(open) => {
          if (!open) closeConfirmation()
        }}
        title={t('Remove member')}
        desc={
          selection ? (
            <div className='space-y-2 break-all'>
              <p>
                {t('Remove {{member}} from {{organization}}?', {
                  member:
                    selection.member.username ||
                    t('User ID: {{id}}', { id: selection.member.user_id }),
                  organization: selection.detail.name,
                })}
              </p>
              <p>{t('User ID: {{id}}', { id: selection.member.user_id })}</p>
              <p>{t('This member will lose access to the organization.')}</p>
            </div>
          ) : (
            ''
          )
        }
        confirmText={t('Remove')}
        destructive
        disabled={removal.pending}
        handleConfirm={() => void confirmRemoval()}
      >
        {removal.pending && <LoadingState />}
      </ConfirmDialog>
    </div>
  )
}
