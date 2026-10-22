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
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  listOAuthAuthorizations,
  revokeOAuthAuthorization,
  type OAuthAuthorizationRecord,
} from '@/features/oauth-clients/api'
import { handleServerError } from '@/lib/handle-server-error'

const authorizationQueryKey = ['oauth-authorizations'] as const

export function AuthorizedAppsCard() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<OAuthAuthorizationRecord | null>(null)
  const authorizationsQuery = useQuery({
    queryKey: authorizationQueryKey,
    queryFn: () => listOAuthAuthorizations(),
  })
  const revokeMutation = useMutation({
    mutationFn: async (clientId: string) => {
      const res = await revokeOAuthAuthorization(clientId)
      return res.data
    },
    onSuccess: (result) => {
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(t('Authorized app revoked'))
      setTarget(null)
      void queryClient.invalidateQueries({ queryKey: authorizationQueryKey })
    },
    onError: (error: Error) => {
      handleServerError(error)
    },
  })

  if (authorizationsQuery.isSuccess && authorizationsQuery.data == null) {
    return null
  }
  const rows = authorizationsQuery.data?.data ?? []
  let list
  if (authorizationsQuery.isError) {
    list = <p className='text-sm'>{t('Failed to load authorized apps')}</p>
  } else if (rows.length === 0) {
    list = (
      <p className='text-muted-foreground text-sm'>{t('No authorized apps')}</p>
    )
  } else {
    list = (
      <ul className='flex flex-col gap-3'>
        {rows.map((row) => (
          <li
            key={row.client_id}
            className='flex flex-wrap items-center justify-between gap-2'
          >
            <div>
              <p className='font-medium'>{row.name || row.client_id}</p>
              <p className='text-muted-foreground text-sm'>
                {row.scopes.join(' ')}
              </p>
            </div>
            <Button
              type='button'
              size='sm'
              variant='destructive'
              onClick={() => setTarget(row)}
            >
              {t('Revoke')}
            </Button>
          </li>
        ))}
      </ul>
    )
  }

  return (
    <>
      <Card data-card-hover='false'>
        <CardHeader>
          <CardTitle>{t('Authorized apps')}</CardTitle>
          <CardDescription>
            {t(
              'Apps you approved. Revoking an app disables the relay keys it created.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>{list}</CardContent>
      </Card>
      <ConfirmDialog
        open={target != null}
        onOpenChange={(open) => {
          if (!open) setTarget(null)
        }}
        title={t('Revoke app')}
        desc={t('Revoke this app? Relay keys it created stop working.')}
        destructive
        handleConfirm={() => {
          if (target) revokeMutation.mutate(target.client_id)
        }}
        isLoading={revokeMutation.isPending}
      />
    </>
  )
}
