import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { formatQuota } from '@/lib/format'

import { getOrganizationWallet } from './api'

type OrganizationWalletProps = {
  actorId: number
  sid: string
  orgId: string
}

export function OrganizationWalletSummary(props: OrganizationWalletProps) {
  const { t } = useTranslation()
  const wallet = useQuery({
    queryKey: [
      'organizations',
      props.actorId,
      props.sid,
      props.orgId,
      'wallet',
    ],
    queryFn: ({ signal }) =>
      getOrganizationWallet(props.actorId, props.sid, props.orgId, signal),
    gcTime: 0,
    retry: false,
    meta: { errorToast: false },
  })

  return (
    <section aria-label={t('Organization wallet')} className='space-y-2'>
      <h4 className='font-medium'>{t('Organization wallet')}</h4>
      {wallet.isPending && <LoadingState />}
      {wallet.isError && (
        <ErrorState
          title={t('Unable to load organization wallet')}
          onRetry={() => void wallet.refetch()}
        />
      )}
      {wallet.isSuccess && (
        <dl className='grid grid-cols-3 gap-2 text-sm'>
          <div>
            <dt className='text-muted-foreground'>{t('Balance')}</dt>
            <dd>{formatQuota(Number(wallet.data.balance))}</dd>
          </div>
          <div>
            <dt className='text-muted-foreground'>{t('Reserved')}</dt>
            <dd>{formatQuota(Number(wallet.data.reserved))}</dd>
          </div>
          <div>
            <dt className='text-muted-foreground'>{t('Available')}</dt>
            <dd>{formatQuota(Number(wallet.data.available))}</dd>
          </div>
        </dl>
      )}
    </section>
  )
}
