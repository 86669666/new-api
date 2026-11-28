import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { StatusBadge } from '@/components/status-badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  getMyOrganizations,
  getOrganizationTaskLogs,
} from '@/features/organizations/api'
import { formatTimestampToDate } from '@/lib/format'
import { useAuthStore } from '@/stores/auth-store'

import { taskStatusMapper } from '../lib/mappers'

type ScopeProps = { actorId: number; sid: string; children: ReactNode }
type OrganizationTasksProps = { actorId: number; sid: string; orgId: string }

export function OrganizationTaskScope({ children }: { children: ReactNode }) {
  const actorId = useAuthStore((state) => state.auth.user?.id)
  const sid = useAuthStore((state) => state.auth.session?.sid)
  if (!actorId || !sid) return children
  return (
    <TaskScope key={`${actorId}:${sid}`} actorId={actorId} sid={sid}>
      {children}
    </TaskScope>
  )
}

function TaskScope(props: ScopeProps) {
  const { t } = useTranslation()
  const [selected, setSelected] = useState('personal')
  const directory = useInfiniteQuery({
    queryKey: ['organizations', props.actorId, props.sid, 'task-directory'],
    queryFn: ({ pageParam, signal }) =>
      getMyOrganizations(props.actorId, props.sid, pageParam, signal),
    initialPageParam: '0',
    getNextPageParam: (last) => last.next_after_id ?? undefined,
    gcTime: 0,
    retry: false,
  })
  const organizations =
    directory.data?.pages.flatMap((page) => page.items) ?? []
  const selectedOrg = organizations.find((org) => org.org_id === selected)
  const scopeOptions = [
    { value: 'personal', label: t('Personal') },
    ...organizations.map((org) => ({ value: org.org_id, label: org.name })),
  ]

  return (
    <div className='flex h-full min-h-0 flex-col gap-3'>
      {organizations.length > 0 && (
        <div className='flex flex-wrap items-center gap-2'>
          <Select
            items={scopeOptions}
            value={selectedOrg?.org_id ?? 'personal'}
            onValueChange={(value) => setSelected(value ?? 'personal')}
          >
            <SelectTrigger aria-label={t('View scope')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {scopeOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {directory.hasNextPage && (
            <Button
              variant='outline'
              size='sm'
              disabled={directory.isFetchingNextPage}
              onClick={() => void directory.fetchNextPage()}
            >
              {t('Load more organizations')}
            </Button>
          )}
        </div>
      )}
      <div className='min-h-0 flex-1'>
        {selectedOrg ? (
          <OrganizationTasks
            key={selectedOrg.org_id}
            actorId={props.actorId}
            sid={props.sid}
            orgId={selectedOrg.org_id}
          />
        ) : (
          props.children
        )}
      </div>
    </div>
  )
}

function OrganizationTasks(props: OrganizationTasksProps) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const tasks = useQuery({
    queryKey: [
      'organizations',
      props.actorId,
      props.sid,
      props.orgId,
      'task-logs',
      page,
    ],
    queryFn: ({ signal }) =>
      getOrganizationTaskLogs(
        props.actorId,
        props.sid,
        props.orgId,
        page,
        signal
      ),
    gcTime: 0,
    retry: false,
    meta: { errorToast: false },
  })

  if (tasks.isPending) return <LoadingState />
  if (tasks.isError) {
    return (
      <ErrorState
        title={t('Unable to load organization tasks')}
        onRetry={() => void tasks.refetch()}
      />
    )
  }
  if (tasks.data.items.length === 0 && page === 1) {
    return <EmptyState title={t('No results found')} />
  }

  return (
    <div className='h-full overflow-auto'>
      <Table aria-label={t('Task Logs')}>
        <TableHeader>
          <TableRow>
            <TableHead>{t('Task ID')}</TableHead>
            <TableHead>{t('Submit Time')}</TableHead>
            <TableHead>{t('Status')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tasks.data.items.map((task) => (
            <TableRow key={task.task_row_id}>
              <TableCell className='break-all whitespace-normal'>
                {task.task_id}
              </TableCell>
              <TableCell>{formatTimestampToDate(task.submit_time)}</TableCell>
              <TableCell>
                <StatusBadge
                  label={t(taskStatusMapper.getLabel(task.status, task.status))}
                  variant={taskStatusMapper.getVariant(task.status)}
                  size='sm'
                  copyable={false}
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {(page > 1 || tasks.data.total > 20) && (
        <div className='flex justify-between gap-2 py-2'>
          <Button
            variant='outline'
            size='sm'
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            {t('Previous')}
          </Button>
          <Button
            variant='outline'
            size='sm'
            disabled={page * 20 >= tasks.data.total || page >= 100}
            onClick={() => setPage(page + 1)}
          >
            {t('Next')}
          </Button>
        </div>
      )}
    </div>
  )
}
