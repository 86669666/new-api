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
import { Link } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { AuthLayout } from '@/features/auth/auth-layout'

import { useProviderAuthorization } from './hooks/use-provider-authorization'
import type { AuthorizationEntry } from './lib/authorization'

export function ProviderAuthorizationPage(props: {
  entry: AuthorizationEntry
}) {
  const { t } = useTranslation()
  const authorization = useProviderAuthorization(props.entry)
  const state = authorization.state
  if (state.kind === 'loading' || state.kind === 'submitting') {
    return <LoadingState message={t('Preparing authorization...')} />
  }
  if (state.kind === 'anonymous') {
    return (
      <AuthLayout>
        <ErrorState
          title={t('Sign in to continue authorization')}
          description={t(
            'Sign in in a new tab, then return here and continue within five minutes.'
          )}
          action={
            <div className='flex flex-wrap justify-center gap-3'>
              <Button
                role='link'
                render={
                  <Link
                    to='/sign-in'
                    target='_blank'
                    rel='noopener noreferrer'
                  />
                }
              >
                {t('Sign in')}
              </Button>
              <Button
                variant='outline'
                onClick={() => {
                  void authorization.resume()
                }}
              >
                {t('Continue after signing in')}
              </Button>
              <Button variant='ghost' onClick={authorization.cancel}>
                {t('Cancel')}
              </Button>
            </div>
          }
        />
      </AuthLayout>
    )
  }
  if (state.kind === 'terminal') {
    return (
      <AuthLayout>
        <ErrorState
          title={t('Authorization could not be completed.')}
          description={t(
            'Start authorization again from your client. Do not retry this request.'
          )}
        />
      </AuthLayout>
    )
  }
  return (
    <AuthLayout>
      <main className='space-y-6' aria-label={t('Authorize client')}>
        <h1 className='text-2xl font-semibold'>{t('Authorize client')}</h1>
        <dl className='space-y-2 break-words'>
          <dt className='text-muted-foreground'>{t('Client')}</dt>
          <dd>{state.preview.client_name || state.preview.client_id}</dd>
          <dt className='text-muted-foreground'>{t('Client ID')}</dt>
          <dd>{state.preview.client_id}</dd>
          <dt className='text-muted-foreground'>{t('Account')}</dt>
          <dd>{state.preview.username}</dd>
          <dt className='text-muted-foreground'>{t('Audience')}</dt>
          <dd>{state.preview.audience}</dd>
        </dl>
        <p>{t('Only approve a client you recognize.')}</p>
        {props.entry.phase === 'consent' && (
          <fieldset className='space-y-3'>
            <legend className='mb-2 font-medium'>
              {t('Requested access')}
            </legend>
            <div className='flex items-center gap-2'>
              <Checkbox id='provider-profile' checked disabled />
              <Label htmlFor='provider-profile'>
                {t('Profile (required)')}
              </Label>
            </div>
            {state.preview.allowed_scopes.includes('openid') && (
              <div className='flex items-center gap-2'>
                <Checkbox id='provider-openid' checked disabled />
                <Label htmlFor='provider-openid'>
                  {t('Identity sign-in (required)')}
                </Label>
              </div>
            )}
            {state.preview.allowed_scopes.includes('offline_access') && (
              <div className='flex items-center gap-2'>
                <Checkbox
                  id='provider-offline'
                  checked={authorization.offline}
                  onCheckedChange={(checked) =>
                    authorization.setOffline(checked === true)
                  }
                />
                <Label htmlFor='provider-offline'>
                  {t('Offline access for up to seven days (optional)')}
                </Label>
              </div>
            )}
            {state.preview.allowed_scopes.includes('email') && (
              <div className='flex items-center gap-2'>
                <Checkbox
                  id='provider-email'
                  checked={authorization.email}
                  onCheckedChange={(checked) =>
                    authorization.setEmail(checked === true)
                  }
                />
                <Label htmlFor='provider-email'>
                  {t('Email address (optional)')}
                </Label>
              </div>
            )}
            {state.preview.allowed_scopes.includes('balance:read') && (
              <div className='space-y-2'>
                <div className='flex items-center gap-2'>
                  <Checkbox
                    id='provider-balance'
                    checked={authorization.balance}
                    aria-describedby='provider-balance-description'
                    onCheckedChange={(checked) =>
                      authorization.setBalance(checked === true)
                    }
                  />
                  <Label htmlFor='provider-balance'>
                    {t('Personal wallet balance and account usage (optional)')}
                  </Label>
                </div>
                <div
                  id='provider-balance-description'
                  className='text-muted-foreground space-y-1 text-sm'
                >
                  <p>
                    {t(
                      'Allow this client to read your personal wallet balance and accumulated account usage, including subscription usage.'
                    )}
                  </p>
                  <p>
                    {t(
                      'This does not include organization balances, remaining subscription quotas, or usage history.'
                    )}
                  </p>
                  <p>
                    {t(
                      'Access lasts up to seven days and ends when this sign-in session ends.'
                    )}
                  </p>
                </div>
              </div>
            )}
            {state.preview.allowed_scopes.includes('usage:read') && (
              <div className='space-y-2'>
                <div className='flex items-center gap-2'>
                  <Checkbox
                    id='provider-usage'
                    checked={authorization.usage}
                    aria-describedby='provider-usage-description'
                    onCheckedChange={(checked) =>
                      authorization.setUsage(checked === true)
                    }
                  />
                  <Label htmlFor='provider-usage'>
                    {t('Recorded call history (optional)')}
                  </Label>
                </div>
                <div
                  id='provider-usage-description'
                  className='text-muted-foreground space-y-1 text-sm'
                >
                  <p>
                    {t(
                      'Allow this client to read this account’s stored call history across API tokens, including deleted tokens.'
                    )}
                  </p>
                  <p>
                    {t(
                      'These records may be incomplete. They are not a wallet statement and do not include organization usage.'
                    )}
                  </p>
                  <p>
                    {t(
                      'Access lasts up to seven days and ends when this sign-in session ends.'
                    )}
                  </p>
                </div>
              </div>
            )}
            {state.preview.allowed_scopes.includes('tokens:read') && (
              <div className='space-y-2'>
                <div className='flex items-center gap-2'>
                  <Checkbox
                    id='provider-tokens'
                    checked={authorization.tokens}
                    aria-describedby='provider-tokens-description'
                    onCheckedChange={(checked) =>
                      authorization.setTokens(checked === true)
                    }
                  />
                  <Label htmlFor='provider-tokens'>
                    {t('API key metadata (optional)')}
                  </Label>
                </div>
                <div
                  id='provider-tokens-description'
                  className='text-muted-foreground space-y-1 text-sm'
                >
                  <p>
                    {t(
                      'Allow this client to read API key metadata for this authorization only.'
                    )}
                  </p>
                  <p>
                    {t('This does not create API keys or reveal secret keys.')}
                  </p>
                  <p>
                    {t(
                      'Access lasts up to seven days and ends when this sign-in session ends.'
                    )}
                  </p>
                </div>
              </div>
            )}
          </fieldset>
        )}
        <div className='flex flex-wrap gap-3'>
          <Button
            onClick={() => {
              void authorization.decide(true)
            }}
          >
            {props.entry.phase === 'login' ? t('Continue') : t('Approve')}
          </Button>
          <Button
            variant='outline'
            onClick={() => {
              void authorization.decide(false)
            }}
          >
            {t('Deny')}
          </Button>
        </div>
      </main>
    </AuthLayout>
  )
}
