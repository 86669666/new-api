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

import { CopyButton } from '@/components/copy-button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import {
  SecureVerificationDialog,
  useSecureVerification,
} from '@/features/auth/secure-verification'
import {
  createOAuthClient,
  deleteOAuthClient,
  listOAuthClients,
  updateOAuthClient,
  type OAuthClientRecord,
} from '@/features/oauth-clients/api'
import {
  OAUTH_CLIENT_KNOWN_SCOPES,
  oauthClientManageContext,
  validOAuthClientRedirect,
  type OAuthClientPresetName,
} from '@/features/oauth-clients/registration'
import { handleServerError } from '@/lib/handle-server-error'

import { SettingsSection } from '../../components/settings-section'

const clientQueryKey = ['oauth-clients'] as const

export function OAuthClientsSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const verification = useSecureVerification()
  const [name, setName] = useState('')
  const [preset, setPreset] = useState<'' | OAuthClientPresetName>('')
  const [redirectText, setRedirectText] = useState('')
  const [scopes, setScopes] = useState<string[]>([...OAUTH_CLIENT_KNOWN_SCOPES])
  const [enabled, setEnabled] = useState(true)
  const [editing, setEditing] = useState<OAuthClientRecord | null>(null)

  const clientsQuery = useQuery({
    queryKey: clientQueryKey,
    queryFn: () => listOAuthClients(),
  })

  const saveMutation = useMutation({
    mutationFn: async () => {
      const redirects = redirectText
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line !== '')
      if (
        preset === '' &&
        (redirects.length === 0 ||
          redirects.some((redirect) => !validOAuthClientRedirect(redirect)))
      ) {
        throw new Error(
          t('Enter a canonical https, loopback, or custom-scheme redirect.')
        )
      }
      const context = oauthClientManageContext({
        action: editing ? 'update' : 'create',
        clientRowId: editing?.id,
        name,
        preset,
        redirects,
        scopes,
      })
      const proof = await verification.requestVerification({
        scope: 'oauth.client.manage',
        context,
        title: t('Confirm OAuth client'),
        description: t(
          'Public clients have no secret. Confirm this client before it is saved.'
        ),
      })
      if (!proof) return null
      if (context.action === 'create') {
        const res = await createOAuthClient(
          {
            name: context.name,
            preset: preset || undefined,
            redirects: context.redirects,
            scopes: context.scopes,
          },
          proof.proof_token
        )
        return res.data
      }
      if (context.action !== 'update' || editing == null) return null
      const res = await updateOAuthClient(
        editing.id,
        {
          name: context.name,
          preset: preset || undefined,
          redirects: context.redirects,
          scopes: context.scopes,
          enabled,
        },
        proof.proof_token
      )
      return res.data
    },
    onSuccess: (result) => {
      if (result == null) return
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(
        editing ? t('OAuth client updated') : t('OAuth client created')
      )
      setEditing(null)
      setName('')
      setPreset('')
      setRedirectText('')
      void queryClient.invalidateQueries({ queryKey: clientQueryKey })
    },
    onError: (error: Error) => {
      handleServerError(error)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (row: OAuthClientRecord) => {
      const context = oauthClientManageContext({
        action: 'delete',
        clientRowId: row.id,
      })
      const proof = await verification.requestVerification({
        scope: 'oauth.client.manage',
        context,
        title: t('Delete OAuth client'),
        description: t(
          'Deleting this client disables the relay keys it created.'
        ),
      })
      if (!proof) return null
      const res = await deleteOAuthClient(row.id, proof.proof_token)
      return res.data
    },
    onSuccess: (result) => {
      if (result == null) return
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(t('OAuth client deleted'))
      void queryClient.invalidateQueries({ queryKey: clientQueryKey })
    },
    onError: (error: Error) => {
      handleServerError(error)
    },
  })

  const clients = clientsQuery.data
  let body
  if (clients == null && clientsQuery.isSuccess) {
    body = (
      <Alert>
        <AlertTitle>{t('OAuth clients')}</AlertTitle>
        <AlertDescription>
          {t(
            'OAuth clients are unavailable until the userinfo resource is enabled.'
          )}
        </AlertDescription>
      </Alert>
    )
  } else if (clientsQuery.isError) {
    body = (
      <Alert variant='destructive'>
        <AlertTitle>{t('OAuth clients')}</AlertTitle>
        <AlertDescription>{t('Failed to load OAuth clients')}</AlertDescription>
      </Alert>
    )
  } else {
    const rows = clients?.data ?? []
    body = (
      <div className='flex flex-col gap-4'>
        <p className='text-muted-foreground text-sm'>
          {t(
            'Create a public client for a desktop app. It has no client secret. The client id is generated by the server.'
          )}
        </p>
        <div className='flex flex-wrap gap-2'>
          <Button
            type='button'
            size='sm'
            variant={preset === 'boxo' ? 'default' : 'outline'}
            onClick={() => setPreset('boxo')}
          >
            {t('Boxo')}
          </Button>
          <Button
            type='button'
            size='sm'
            variant={preset === 'cherry_studio' ? 'default' : 'outline'}
            onClick={() => setPreset('cherry_studio')}
          >
            {t('Cherry Studio')}
          </Button>
          <Button
            type='button'
            size='sm'
            variant={preset === '' ? 'default' : 'outline'}
            onClick={() => setPreset('')}
          >
            {t('Custom redirects')}
          </Button>
        </div>
        <div className='grid gap-3'>
          <Label htmlFor='oauth-client-name'>{t('Name')}</Label>
          <Input
            id='oauth-client-name'
            value={name}
            maxLength={64}
            onChange={(event) => setName(event.target.value)}
          />
          {preset === '' ? (
            <>
              <Label htmlFor='oauth-client-redirects'>
                {t('Redirect URLs')}
              </Label>
              <Textarea
                id='oauth-client-redirects'
                value={redirectText}
                onChange={(event) => setRedirectText(event.target.value)}
                placeholder={t(
                  'One redirect per line. Loopback URLs match any port on that path.'
                )}
              />
            </>
          ) : (
            <p className='text-sm'>
              {preset === 'boxo'
                ? 'http://127.0.0.1/oauth/callback'
                : 'http://127.0.0.1:29873/oauth/callback'}
            </p>
          )}
          <fieldset className='grid gap-2'>
            <legend className='text-sm font-medium'>{t('Scopes')}</legend>
            {OAUTH_CLIENT_KNOWN_SCOPES.map((scope) => (
              <div key={scope} className='flex items-center gap-2'>
                <Checkbox
                  id={`oauth-client-scope-${scope.replaceAll(':', '-')}`}
                  checked={scope === 'profile' || scopes.includes(scope)}
                  disabled={scope === 'profile'}
                  onCheckedChange={(checked) => {
                    setScopes((current) => {
                      const next = new Set(current)
                      if (checked === true) next.add(scope)
                      else next.delete(scope)
                      next.add('profile')
                      return OAUTH_CLIENT_KNOWN_SCOPES.filter((item) =>
                        next.has(item)
                      )
                    })
                  }}
                />
                <Label
                  htmlFor={`oauth-client-scope-${scope.replaceAll(':', '-')}`}
                >
                  {scope}
                </Label>
              </div>
            ))}
          </fieldset>
          {editing ? (
            <div className='flex items-center gap-2'>
              <Switch
                id='oauth-client-enabled'
                checked={enabled}
                onCheckedChange={setEnabled}
              />
              <Label htmlFor='oauth-client-enabled'>{t('Enabled')}</Label>
            </div>
          ) : null}
          <div className='flex flex-wrap gap-2'>
            <Button
              type='button'
              disabled={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
            >
              {editing ? t('Save changes') : t('Create client')}
            </Button>
            {editing ? (
              <Button
                type='button'
                variant='outline'
                onClick={() => {
                  setEditing(null)
                  setName('')
                  setPreset('')
                  setRedirectText('')
                }}
              >
                {t('Cancel')}
              </Button>
            ) : null}
          </div>
        </div>
        {rows.length === 0 ? (
          <p className='text-muted-foreground text-sm'>
            {t('No OAuth clients')}
          </p>
        ) : (
          <ul className='flex flex-col gap-3'>
            {rows.map((row) => (
              <li key={row.id} className='rounded-lg border p-3'>
                <div className='flex flex-wrap items-center justify-between gap-2'>
                  <div>
                    <p className='font-medium'>{row.name}</p>
                    <p className='text-muted-foreground text-sm'>
                      {t('Client ID')} {row.client_id}
                    </p>
                  </div>
                  <div className='flex gap-2'>
                    <CopyButton value={row.client_id} />
                    <Button
                      type='button'
                      size='sm'
                      variant='outline'
                      onClick={() => {
                        setEditing(row)
                        setName(row.name)
                        setPreset('')
                        setRedirectText(row.redirects.join('\n'))
                        setScopes(row.scopes)
                        setEnabled(row.enabled)
                      }}
                    >
                      {t('Edit')}
                    </Button>
                    <Button
                      type='button'
                      size='sm'
                      variant='destructive'
                      disabled={deleteMutation.isPending}
                      onClick={() => deleteMutation.mutate(row)}
                    >
                      {t('Delete')}
                    </Button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    )
  }

  return (
    <SettingsSection title={t('OAuth clients')}>
      {body}
      <SecureVerificationDialog {...verification.dialogProps} />
    </SettingsSection>
  )
}
