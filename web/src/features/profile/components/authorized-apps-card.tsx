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
import { KeyRound } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty'
import { TitledCard } from '@/components/ui/titled-card'
import {
  SecureVerificationDialog,
  useSecureVerification,
} from '@/features/auth/secure-verification'
import {
  getAuthorizedOAuthApps,
  revokeAuthorizedOAuthApp,
} from '@/features/system-settings/auth/public-oauth/api'
import type { AuthorizedOAuthApp } from '@/features/system-settings/auth/public-oauth/types'
import { toIntlLocale } from '@/i18n/languages'
import { formatNumber, formatTimestampRelative } from '@/lib/format'
import { handleServerError } from '@/lib/handle-server-error'
import { requireServerSuccess } from '@/lib/server-error-message'

const appsKey = ['oauth-authorized-apps'] as const

export function AuthorizedAppsCard() {
  const { t, i18n } = useTranslation()
  const locale = toIntlLocale(i18n.resolvedLanguage || i18n.language)
  const queryClient = useQueryClient()
  const verification = useSecureVerification()
  const [target, setTarget] = useState<AuthorizedOAuthApp | null>(null)
  const [pending, setPending] = useState(false)
  const appsQuery = useQuery({
    queryKey: appsKey,
    queryFn: async () => {
      const response = requireServerSuccess(await getAuthorizedOAuthApps())
      return response.data ?? []
    },
  })

  const revoke = async () => {
    if (!target) return
    setPending(true)
    try {
      const proof = await verification.requestVerification({
        scope: 'oauth.app.revoke',
        context: { client_id: target.client_id },
        title: t('Verify to revoke this application'),
        description: t('Confirm your identity before revoking {{name}}.', {
          name: target.name,
        }),
      })
      if (!proof) return
      const response = await revokeAuthorizedOAuthApp(
        target.client_id,
        proof.proof_token
      )
      if (!response.success) {
        handleServerError(response)
        return
      }
      toast.success(t('Authorized application revoked'))
      setTarget(null)
      await queryClient.invalidateQueries({ queryKey: appsKey })
    } catch (error) {
      handleServerError(error)
    } finally {
      setPending(false)
    }
  }

  const apps = appsQuery.data ?? []

  return (
    <TitledCard
      title={t('Authorized applications')}
      description={t(
        'Applications you approved can call this account until you revoke them.'
      )}
      icon={<KeyRound />}
    >
      {appsQuery.isLoading ? (
        <p className='text-muted-foreground text-sm'>{t('Loading...')}</p>
      ) : null}
      {!appsQuery.isLoading && apps.length === 0 ? (
        <Empty className='border-0 py-6'>
          <EmptyHeader>
            <EmptyMedia variant='icon'>
              <KeyRound />
            </EmptyMedia>
            <EmptyTitle>{t('No authorized applications.')}</EmptyTitle>
            <EmptyDescription>
              {t(
                'Applications you approved can call this account until you revoke them.'
              )}
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : null}
      <div className='space-y-3'>
        {apps.map((app) => (
          <div
            key={app.client_id}
            className='flex flex-col gap-3 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between'
          >
            <div className='min-w-0 space-y-1'>
              <p className='font-medium'>{app.name}</p>
              <p className='text-muted-foreground truncate font-mono text-xs'>
                {app.client_id}
              </p>
              <p className='text-muted-foreground text-xs'>
                {t('Grants')}: {formatNumber(app.grant_count, locale)}
                {' · '}
                {t('Approved')}:{' '}
                {formatTimestampRelative(app.approved_at, 'seconds', locale)}
                {' · '}
                {t('Expires')}:{' '}
                {formatTimestampRelative(app.expires_at, 'seconds', locale)}
              </p>
            </div>
            <Button variant='outline' size='sm' onClick={() => setTarget(app)}>
              {t('Revoke')}
            </Button>
          </div>
        ))}
      </div>
      <ConfirmDialog
        open={target !== null && !verification.isActive}
        onOpenChange={(open) => {
          if (!open) setTarget(null)
        }}
        title={t('Revoke authorized application')}
        desc={t(
          'Revoke access for "{{name}}"? This removes the local authorization. The authorization server drops its tokens only when cleanup is enabled.',
          { name: target?.name ?? '' }
        )}
        confirmText={t('Revoke')}
        destructive
        isLoading={pending}
        handleConfirm={() => {
          void revoke()
        }}
      />
      <SecureVerificationDialog {...verification.dialogProps} />
    </TitledCard>
  )
}
