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
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { z } from 'zod'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { ErrorState } from '@/components/error-state'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { requireServerSuccess } from '@/lib/server-error-message'

import { getSystemOptions } from '../api'
import {
  SettingsForm,
  SettingsSwitchField,
} from '../components/settings-form-layout'
import { SettingsPageFormActions } from '../components/settings-page-context'
import { SettingsSection } from '../components/settings-section'
import { useSystemOptions } from '../hooks/use-system-options'
import { useUpdateOption } from '../hooks/use-update-option'
import { safeNumberFieldProps } from '../utils/numeric-field'

const configSchema = z.object({
  enabled: z.boolean(),
  retention_days: z.number().int().min(8).max(365),
  rate_limit: z.number().int().min(1).max(600),
})
const snapshotSchema = configSchema
  .extend({
    source: z.enum(['environment', 'option']),
    valid: z.boolean(),
  })
  .strict()
type ClientEventsConfig = z.infer<typeof configSchema>

function parseSnapshot(value: string | undefined) {
  if (!value) return null
  try {
    const result = snapshotSchema.safeParse(JSON.parse(value))
    return result.success ? result.data : null
  } catch {
    return null
  }
}

export function ClientEventsSettingsSection() {
  const { t } = useTranslation()
  const options = useSystemOptions()
  const queryClient = useQueryClient()
  const update = useUpdateOption()
  const raw = options.data?.data.find(
    (option) => option.key === 'ClientEventsConfig'
  )?.value
  const snapshot = useMemo(() => parseSnapshot(raw), [raw])
  const validation = useMemo(
    () =>
      configSchema.extend({
        retention_days: z
          .number({ error: t('Enter a whole number from 8 to 365') })
          .int(t('Enter a whole number from 8 to 365'))
          .min(8, t('Enter a whole number from 8 to 365'))
          .max(365, t('Enter a whole number from 8 to 365')),
        rate_limit: z
          .number({ error: t('Enter a whole number from 1 to 600') })
          .int(t('Enter a whole number from 1 to 600'))
          .min(1, t('Enter a whole number from 1 to 600'))
          .max(600, t('Enter a whole number from 1 to 600')),
      }),
    [t]
  )
  const form = useForm<ClientEventsConfig>({
    resolver: zodResolver(validation),
    defaultValues: snapshot ? configSchema.parse(snapshot) : undefined,
  })
  const saving = useRef(false)
  const [isSaving, setIsSaving] = useState(false)
  const [refreshFailed, setRefreshFailed] = useState(false)
  const [pending, setPending] = useState<{
    values: ClientEventsConfig
    retentionDays: number
  } | null>(null)
  const { isDirty } = form.formState

  // The common settings hook resets dirty forms on refetch and resets submitted
  // values after mutation. This section requires an authoritative read instead.
  useEffect(() => {
    if (snapshot && !isDirty && !saving.current && !refreshFailed) {
      const confirmed = configSchema.parse(snapshot)
      form.reset(confirmed)
    }
  }, [snapshot, isDirty, form, refreshFailed])

  // A confirmation applies only to the policy observed when it was opened.
  // A changed server policy requires the user to submit and confirm again.
  useEffect(() => {
    if (pending && snapshot?.retention_days !== pending.retentionDays) {
      setPending(null)
    }
  }, [pending, snapshot?.retention_days])

  async function save(values: ClientEventsConfig) {
    if (saving.current) return
    saving.current = true
    setIsSaving(true)
    setPending(null)
    setRefreshFailed(false)
    try {
      await update.mutateAsync({
        key: 'ClientEventsConfig',
        value: JSON.stringify(values),
      })
      try {
        // Detach old query results, but do not claim to abort their HTTP requests:
        // the shared query does not pass an AbortSignal.
        await queryClient.cancelQueries({
          queryKey: ['system-options'],
          exact: true,
        })
        const result = requireServerSuccess(await getSystemOptions())
        const confirmed = parseSnapshot(
          result.data?.find((option) => option.key === 'ClientEventsConfig')
            ?.value
        )
        if (!confirmed?.valid) {
          throw new Error('Unconfirmed client event settings')
        }
        const values = configSchema.parse(confirmed)
        // Also detach any background fetch started during the confirmation read
        // before publishing its validated response to the shared cache.
        await queryClient.cancelQueries({
          queryKey: ['system-options'],
          exact: true,
        })
        queryClient.setQueryData(['system-options'], result)
        form.reset(values)
      } catch {
        setRefreshFailed(true)
      }
    } catch {
      // useUpdateOption owns the shared server-error presentation.
    } finally {
      saving.current = false
      setIsSaving(false)
    }
  }

  function submit(values: ClientEventsConfig) {
    if (snapshot && values.retention_days < snapshot.retention_days) {
      setPending({ values, retentionDays: snapshot.retention_days })
      return
    }
    return save(values)
  }

  if (!snapshot) {
    return (
      <ErrorState
        title={t('Failed to load settings')}
        onRetry={() => void options.refetch()}
      />
    )
  }

  return (
    <SettingsSection title={t('Client event collection')}>
      <p className='text-muted-foreground text-sm'>
        {t(
          'Collect authenticated client self-reports. Disabling collection keeps existing history. Changes reach other servers after synchronization.'
        )}
      </p>
      {!snapshot.valid && (
        <Alert variant='destructive'>
          <AlertDescription>
            {t(
              'Collection and cleanup are paused because the saved settings are invalid. Save a valid configuration to resume.'
            )}
          </AlertDescription>
        </Alert>
      )}
      {refreshFailed && (
        <Alert variant='destructive'>
          <AlertDescription>
            {t(
              'Settings were saved, but the latest values could not be loaded. Your edits have been kept.'
            )}
          </AlertDescription>
        </Alert>
      )}
      <Form {...form}>
        <SettingsForm onSubmit={form.handleSubmit(submit)}>
          <FormField
            control={form.control}
            name='enabled'
            render={({ field }) => (
              <SettingsSwitchField
                controlId='client-events-enabled'
                label={t('Enable client event collection')}
                checked={field.value}
                onCheckedChange={field.onChange}
                disabled={isSaving}
              />
            )}
          />
          <FormField
            control={form.control}
            name='retention_days'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Client event retention (days)')}</FormLabel>
                <FormControl>
                  <Input
                    type='number'
                    min={8}
                    max={365}
                    step={1}
                    disabled={isSaving}
                    {...safeNumberFieldProps(field)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name='rate_limit'
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  {t('Collection requests per token per minute')}
                </FormLabel>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    max={600}
                    step={1}
                    disabled={isSaving}
                    {...safeNumberFieldProps(field)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </SettingsForm>
      </Form>
      <SettingsPageFormActions
        onSave={() => void form.handleSubmit(submit)()}
        isSaving={isSaving}
        isSaveDisabled={!isDirty && snapshot.valid && !refreshFailed}
      />
      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open) setPending(null)
        }}
        title={t('Shorten client event retention?')}
        desc={t(
          'Future cleanup will permanently delete older events. Increasing retention later cannot restore deleted history.'
        )}
        destructive
        handleConfirm={() => {
          if (!pending) return
          if (snapshot.retention_days !== pending.retentionDays) {
            setPending(null)
            return
          }
          void save(pending.values)
        }}
        isLoading={isSaving}
      />
    </SettingsSection>
  )
}
