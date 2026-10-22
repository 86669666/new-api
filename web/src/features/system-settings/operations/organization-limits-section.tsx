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
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { handleServerError } from '@/lib/handle-server-error'
import { ROLE } from '@/lib/roles'
import { useAuthStore } from '@/stores/auth-store'

import { FormDirtyIndicator } from '../components/form-dirty-indicator'
import { FormNavigationGuard } from '../components/form-navigation-guard'
import {
  SettingsForm,
  SettingsFormGrid,
} from '../components/settings-form-layout'
import { SettingsPageFormActions } from '../components/settings-page-context'
import { SettingsSection } from '../components/settings-section'
import {
  organizationLimitsFormSchema,
  organizationLimitsFormValues,
  type OrganizationLimitsForm,
} from './lib/organization-limits-schema'
import {
  getOrganizationLimits,
  updateOrganizationLimits,
} from './organization-limits-api'

export function OrganizationLimitsSection() {
  const { t } = useTranslation()
  const role = useAuthStore((state) => state.auth.user?.role)
  const sid = useAuthStore((state) => state.auth.session?.sid)
  if (role !== ROLE.SUPER_ADMIN || !sid) {
    return (
      <ErrorState
        title={t(
          'A root dashboard session is required to manage organization limits.'
        )}
      />
    )
  }
  return <OrganizationLimitsFormSection key={sid} sessionId={sid} />
}

function OrganizationLimitsFormSection(props: { sessionId: string }) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const [phase, setPhase] = useState<'idle' | 'saving' | 'reloading'>('idle')
  const [notice, setNotice] = useState<
    'saved-unconfirmed' | 'uncertain' | 'reload-failed' | null
  >(null)
  const [confirmReload, setConfirmReload] = useState(false)
  const operation = useRef(false)
  const busy = phase !== 'idle'
  const queryKey = ['organization-limits', props.sessionId]
  const query = useQuery({
    queryKey,
    queryFn: ({ signal }) => getOrganizationLimits(signal),
    enabled: !busy && !notice,
    // Revalidate on entry/focus, not again when the post-save read enables the query.
    staleTime: Infinity,
    refetchOnMount: 'always',
    refetchOnWindowFocus: 'always',
    gcTime: 0,
    retry: false,
    meta: { errorToast: false },
  })
  const mutation = useMutation({
    mutationFn: updateOrganizationLimits,
    retry: false,
    meta: { errorToast: false },
  })
  const form = useForm<OrganizationLimitsForm>({
    resolver: zodResolver(
      organizationLimitsFormSchema(
        t(
          'Organization limits must be integers between 0 and 9007199254740991.'
        )
      )
    ),
    defaultValues: {
      max_organizations_created: '',
      max_organizations_joined: '',
    },
  })
  const dirty = form.formState.isDirty
  useEffect(() => {
    if (query.data && !query.isError && !dirty && !busy && !notice) {
      form.reset(organizationLimitsFormValues(query.data))
    }
  }, [query.data, query.isError, dirty, busy, notice, form])

  const reload = async () => {
    if (operation.current) return
    operation.current = true
    setConfirmReload(false)
    setPhase('reloading')
    try {
      await client.cancelQueries({ queryKey })
      const current = await getOrganizationLimits()
      client.setQueryData(queryKey, current)
      form.reset(organizationLimitsFormValues(current))
      setNotice(null)
    } catch (error) {
      setNotice('reload-failed')
      handleServerError(error)
    } finally {
      operation.current = false
      setPhase('idle')
    }
  }

  const save = form.handleSubmit(async (values) => {
    if (operation.current || !dirty || notice || query.isError || !query.data) {
      return
    }
    operation.current = true
    setPhase('saving')
    let committed = false
    try {
      await client.cancelQueries({ queryKey })
      await mutation.mutateAsync(values)
      committed = true
      // A new direct GET, begun strictly after PUT completion. Cancelled query
      // results cannot publish over this snapshot, even if their adapter ignores abort.
      const current = await getOrganizationLimits()
      client.setQueryData(queryKey, current)
      form.reset(organizationLimitsFormValues(current))
      setNotice(null)
    } catch (error) {
      setNotice(committed ? 'saved-unconfirmed' : 'uncertain')
      handleServerError(error)
    } finally {
      operation.current = false
      setPhase('idle')
    }
  })

  if (!query.data && !notice) {
    if (query.isError) {
      return (
        <ErrorState
          title={t('Organization limits are unavailable.')}
          onRetry={() => void reload()}
        />
      )
    }
    return <LoadingState message={t('Loading organization limits...')} />
  }

  return (
    <>
      <FormNavigationGuard when={dirty || busy || notice !== null} />
      <SettingsSection title={t('Organization limits')}>
        <Form {...form}>
          <SettingsForm onSubmit={save}>
            <SettingsPageFormActions
              onSave={() => void save()}
              onReset={() => setConfirmReload(true)}
              resetLabel='Reload saved limits'
              isSaving={busy}
              isSaveDisabled={
                !dirty || !query.data || query.isError || notice !== null
              }
              isResetDisabled={busy}
            />
            <FormDirtyIndicator isDirty={dirty} />
            <p className='text-muted-foreground text-sm'>
              {t(
                '0 means unlimited. Lowering a limit only restricts new additions; existing organizations and memberships are kept.'
              )}
            </p>
            {(notice || query.isError) && (
              <Alert>
                <AlertDescription>
                  {notice === 'saved-unconfirmed' &&
                    t(
                      'Saved, but refreshing settings failed. Your edits are kept until you reload saved limits.'
                    )}
                  {notice === 'uncertain' &&
                    t(
                      'The save result is uncertain. Reload saved limits before trying again; your edits have been kept.'
                    )}
                  {(notice === 'reload-failed' || (!notice && query.isError)) &&
                    t(
                      'Organization limits are unavailable. Your edits have been kept.'
                    )}
                  <Button
                    type='button'
                    variant='outline'
                    className='mt-3 w-fit max-w-full whitespace-normal'
                    disabled={busy}
                    onClick={() => setConfirmReload(true)}
                  >
                    {t('Reload saved limits')}
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            <SettingsFormGrid>
              <FormField
                control={form.control}
                name='max_organizations_created'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('Maximum owned organizations per user')}
                    </FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        inputMode='numeric'
                        autoComplete='off'
                        disabled={busy || !query.data}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'Counts currently owned, non-dissolved organizations, including disabled organizations.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name='max_organizations_joined'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('Maximum joined organizations per user')}
                    </FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        inputMode='numeric'
                        autoComplete='off'
                        disabled={busy || !query.data}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'Counts active memberships, including owned and disabled organizations. Pending invitations do not count.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </SettingsFormGrid>
          </SettingsForm>
        </Form>
      </SettingsSection>
      <ConfirmDialog
        open={confirmReload}
        onOpenChange={setConfirmReload}
        title={t('Reload saved limits?')}
        desc={t(
          'This replaces your draft with the latest saved limits. Unsaved edits will be discarded only after the reload succeeds.'
        )}
        confirmText={t('Reload saved limits')}
        handleConfirm={() => void reload()}
        isLoading={busy}
      />
    </>
  )
}
