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
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'

import {
  PUBLIC_OAUTH_SCOPES,
  publicOAuthScopeLabel,
  type PublicOAuthClient,
  type PublicOAuthClientInput,
  type PublicOAuthClientPreset,
} from '../types'

type PublicOAuthFormDialogProps = {
  open: boolean
  client: PublicOAuthClient | null
  presets: PublicOAuthClientPreset[]
  pending: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (input: PublicOAuthClientInput) => void
}

export function PublicOAuthFormDialog(props: PublicOAuthFormDialogProps) {
  const { t } = useTranslation()
  const editing = props.client !== null
  const [clientId, setClientId] = useState('')
  const [name, setName] = useState('')
  const [redirects, setRedirects] = useState('')
  const [scopes, setScopes] = useState<string[]>(['profile'])
  const [enabled, setEnabled] = useState(true)

  useEffect(() => {
    if (!props.open) return
    setClientId(props.client?.client_id ?? '')
    setName(props.client?.name ?? '')
    setRedirects(props.client?.redirect_uris.join('\n') ?? '')
    setScopes(
      props.client?.scopes.includes('profile')
        ? props.client.scopes
        : ['profile']
    )
    setEnabled(props.client?.enabled ?? true)
  }, [props.open, props.client])

  const applyPreset = (preset: PublicOAuthClientPreset) => {
    setName(preset.name)
    setRedirects(preset.redirect_uris.join('\n'))
    setScopes(preset.scopes.includes('profile') ? preset.scopes : ['profile'])
  }

  const toggleScope = (scope: string, checked: boolean) => {
    if (scope === 'profile') return
    setScopes((current) => {
      if (checked) {
        return current.includes(scope) ? current : [...current, scope]
      }
      return current.filter((item) => item !== scope)
    })
  }

  const submit = () => {
    const redirectURIs = redirects
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '')
    const trimmedClientId = clientId.trim()
    const input: PublicOAuthClientInput = {
      client_id: trimmedClientId,
      name: name.trim(),
      redirect_uris: redirectURIs,
      scopes,
      enabled,
    }
    if (!editing && trimmedClientId.length < 8) {
      toast.error(t('Invalid OAuth client ID'))
      return
    }
    if (
      input.name === '' ||
      redirectURIs.length === 0 ||
      !scopes.includes('profile')
    ) {
      toast.error(t('Invalid parameters'))
      return
    }
    props.onSubmit(input)
  }

  return (
    <Dialog
      open={props.open}
      onOpenChange={props.onOpenChange}
      title={
        editing
          ? t('Edit public OAuth client')
          : t('Create public OAuth client')
      }
      description={t(
        'Client ID is chosen here and is not a secret. Presets do not assign one.'
      )}
      footer={
        <>
          <Button
            variant='outline'
            onClick={() => props.onOpenChange(false)}
            disabled={props.pending}
          >
            {t('Cancel')}
          </Button>
          <Button onClick={submit} disabled={props.pending}>
            {editing ? t('Save') : t('Create')}
          </Button>
        </>
      }
    >
      <div className='space-y-4'>
        <div className='flex flex-wrap gap-2'>
          {props.presets.map((preset) => (
            <Button
              key={preset.key}
              type='button'
              size='sm'
              variant='outline'
              onClick={() => applyPreset(preset)}
            >
              {t(preset.name)}
            </Button>
          ))}
        </div>
        <div className='space-y-2'>
          <Label htmlFor='public-oauth-client-id' required>
            {t('Client ID')}
          </Label>
          <Input
            id='public-oauth-client-id'
            value={clientId}
            disabled={editing || props.pending}
            onChange={(event) => setClientId(event.target.value)}
          />
        </div>
        <div className='space-y-2'>
          <Label htmlFor='public-oauth-name' required>
            {t('Name')}
          </Label>
          <Input
            id='public-oauth-name'
            value={name}
            disabled={props.pending}
            onChange={(event) => setName(event.target.value)}
          />
        </div>
        <div className='space-y-2'>
          <Label htmlFor='public-oauth-redirects' required>
            {t('Redirect URIs')}
          </Label>
          <Textarea
            id='public-oauth-redirects'
            value={redirects}
            disabled={props.pending}
            rows={4}
            onChange={(event) => setRedirects(event.target.value)}
          />
          <p className='text-muted-foreground text-xs'>
            {t(
              'One redirect URI per line. A loopback address without a port matches any ephemeral port on that host and the same path.'
            )}
          </p>
        </div>
        <fieldset className='space-y-2'>
          <legend className='text-sm font-medium'>{t('Scopes')}</legend>
          <div className='grid gap-2 sm:grid-cols-2'>
            {PUBLIC_OAUTH_SCOPES.map((scope) => (
              <label key={scope} className='flex items-center gap-2 text-sm'>
                <Checkbox
                  checked={scopes.includes(scope)}
                  disabled={scope === 'profile' || props.pending}
                  onCheckedChange={(checked) =>
                    toggleScope(scope, checked === true)
                  }
                />
                <span>{publicOAuthScopeLabel(t, scope)}</span>
              </label>
            ))}
          </div>
          <p className='text-muted-foreground text-xs'>
            {t('Profile scope is required.')}
          </p>
        </fieldset>
        <div className='flex items-center justify-between gap-3'>
          <Label htmlFor='public-oauth-enabled'>{t('Enabled')}</Label>
          <Switch
            id='public-oauth-enabled'
            checked={enabled}
            disabled={props.pending}
            onCheckedChange={(checked) => setEnabled(checked)}
          />
        </div>
      </div>
    </Dialog>
  )
}
