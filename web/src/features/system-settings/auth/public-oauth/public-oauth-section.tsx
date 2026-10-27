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
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  SecureVerificationDialog,
  useSecureVerification,
} from '@/features/auth/secure-verification'
import { handleServerError } from '@/lib/handle-server-error'
import { requireServerSuccess } from '@/lib/server-error-message'

import { SettingsSection } from '../../components/settings-section'
import {
  createPublicOAuthClient,
  deletePublicOAuthClient,
  getPublicOAuthClientPresets,
  getPublicOAuthClients,
  updatePublicOAuthClient,
} from './api'
import { PublicOAuthFormDialog } from './components/public-oauth-form-dialog'
import { PublicOAuthTable } from './components/public-oauth-table'
import type { PublicOAuthClient, PublicOAuthClientInput } from './types'

const clientsKey = ['oauth-public-clients'] as const

export function PublicOAuthSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const verification = useSecureVerification()
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<PublicOAuthClient | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<PublicOAuthClient | null>(
    null
  )
  const [pending, setPending] = useState(false)
  const clientsQuery = useQuery({
    queryKey: clientsKey,
    queryFn: async () => {
      const response = requireServerSuccess(await getPublicOAuthClients())
      return response.data ?? []
    },
  })
  const presetsQuery = useQuery({
    queryKey: ['oauth-public-client-presets'],
    queryFn: async () => {
      const response = requireServerSuccess(await getPublicOAuthClientPresets())
      return response.data ?? []
    },
  })

  const verify = (action: 'create' | 'update' | 'delete', clientId: string) =>
    verification.requestVerification({
      scope: 'oauth.public_client.manage',
      context: { action, client_id: clientId },
      title: t('Verify to manage this OAuth client'),
      description: t(
        'Confirm your identity before changing public OAuth client {{client_id}}.',
        { client_id: clientId }
      ),
    })

  const refresh = () => queryClient.invalidateQueries({ queryKey: clientsKey })

  const submit = async (input: PublicOAuthClientInput) => {
    const clientId = editing?.client_id ?? input.client_id ?? ''
    setPending(true)
    try {
      const proof = await verify(editing ? 'update' : 'create', clientId)
      if (!proof) return
      const response = editing
        ? await updatePublicOAuthClient(editing.id, input, proof.proof_token)
        : await createPublicOAuthClient(
            { ...input, client_id: clientId },
            proof.proof_token
          )
      if (!response.success) {
        handleServerError(response)
        return
      }
      toast.success(
        t(
          editing
            ? 'Public OAuth client updated'
            : 'Public OAuth client created'
        )
      )
      setFormOpen(false)
      setEditing(null)
      await refresh()
    } catch (error) {
      handleServerError(error)
    } finally {
      setPending(false)
    }
  }

  const remove = async () => {
    if (!deleteTarget) return
    setPending(true)
    try {
      const proof = await verify('delete', deleteTarget.client_id)
      if (!proof) return
      const response = await deletePublicOAuthClient(
        deleteTarget.id,
        proof.proof_token
      )
      if (!response.success) {
        handleServerError(response)
        return
      }
      toast.success(t('Public OAuth client deleted'))
      setDeleteTarget(null)
      await refresh()
    } catch (error) {
      handleServerError(error)
    } finally {
      setPending(false)
    }
  }

  return (
    <SettingsSection title={t('Public OAuth clients')}>
      <Alert>
        <AlertTitle>{t('Public OAuth clients')}</AlertTitle>
        <AlertDescription>
          {t(
            'Saving a client here records it for this console. It does not register the client with the authorization server.'
          )}
        </AlertDescription>
      </Alert>
      {clientsQuery.isLoading ? (
        <p className='text-muted-foreground py-8 text-center text-sm'>
          {t('Loading...')}
        </p>
      ) : (
        <PublicOAuthTable
          clients={clientsQuery.data ?? []}
          onCreate={() => {
            setEditing(null)
            setFormOpen(true)
          }}
          onEdit={(client) => {
            setEditing(client)
            setFormOpen(true)
          }}
          onDelete={setDeleteTarget}
        />
      )}
      <PublicOAuthFormDialog
        open={formOpen && !verification.isActive}
        client={editing}
        presets={presetsQuery.data ?? []}
        pending={pending}
        onOpenChange={(open) => {
          setFormOpen(open)
          if (!open) setEditing(null)
        }}
        onSubmit={(input) => {
          void submit(input)
        }}
      />
      <ConfirmDialog
        open={deleteTarget !== null && !verification.isActive}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
        title={t('Delete public OAuth client')}
        desc={t('Delete "{{name}}"? This removes the console record only.', {
          name: deleteTarget?.name ?? '',
        })}
        confirmText={t('Delete')}
        destructive
        isLoading={pending}
        handleConfirm={() => {
          void remove()
        }}
      />
      <SecureVerificationDialog {...verification.dialogProps} />
    </SettingsSection>
  )
}
