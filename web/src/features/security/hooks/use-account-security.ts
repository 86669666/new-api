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
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import {
  useSecureVerification,
  type RequestVerificationOptions,
} from '@/features/auth/secure-verification'
import type { ExpectedAuthIdentity } from '@/lib/api'
import { handleServerError } from '@/lib/handle-server-error'
import { AuthOperationError } from '@/lib/secure-verification'
import { useAuthStore } from '@/stores/auth-store'

import {
  projectAccountOperationError,
  type AccountOperationError,
} from '../account-operation-error'

// Account operations compose the shared verification ceremony with the
// subsequent mutation. Both must be cancelled when the account/session changes.
export function useAccountSecurity() {
  const { t } = useTranslation()
  const userId = useAuthStore((state) => state.auth.user?.id)
  const sessionId = useAuthStore((state) => state.auth.session?.sid)
  const sessionKey = `${userId ?? ''}:${sessionId ?? ''}`
  const verification = useSecureVerification(projectAccountOperationError)
  const cancelVerification = verification.cancel
  const requestVerification = verification.requestVerification
  const current = useRef<AbortController | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<AccountOperationError | null>(null)

  const cancel = useCallback(() => {
    current.current?.abort()
    current.current = null
    cancelVerification()
    setPending(false)
    setError(null)
  }, [cancelVerification])

  useEffect(() => cancel, [cancel])
  useEffect(
    () =>
      useAuthStore.subscribe((state, previous) => {
        if (
          state.auth.user?.id !== previous.auth.user?.id ||
          state.auth.session?.sid !== previous.auth.session?.sid
        ) {
          cancel()
        }
      }),
    [cancel]
  )

  const run = useCallback(
    async <T>(
      action: (signal: AbortSignal) => Promise<T>,
      options: {
        expectedAuthIdentity?: ExpectedAuthIdentity
        throwOnError?: boolean
      } = {}
    ): Promise<T | undefined> => {
      const auth = useAuthStore.getState().auth
      const expected = options.expectedAuthIdentity
      if (
        current.current ||
        (expected &&
          (auth.user?.id !== expected.userId ||
            auth.session?.sid !== expected.sid))
      ) {
        if (options.throwOnError) {
          throw projectAccountOperationError({ code: 'AUTH_CANCELLED' })
        }
        return undefined
      }
      const controller = new AbortController()
      current.current = controller
      setPending(true)
      setError(null)
      try {
        const result = await action(controller.signal)
        controller.signal.throwIfAborted()
        if (
          result !== null &&
          typeof result === 'object' &&
          'notification_warning' in result &&
          result.notification_warning === true
        ) {
          toast.warning(
            t(
              'The change succeeded, but the notification email could not be sent.'
            )
          )
        }
        return result
      } catch (error) {
        const failure = projectAccountOperationError(
          controller.signal.aborted ? { code: 'AUTH_CANCELLED' } : error
        )
        if (!controller.signal.aborted && current.current === controller) {
          if (failure.code !== 'AUTH_CANCELLED') {
            setError(failure)
            if (!options.throwOnError) handleServerError(failure)
          }
        }
        if (options.throwOnError) throw failure
        return undefined
      } finally {
        if (current.current === controller) {
          current.current = null
          setPending(false)
        }
      }
    },
    [t]
  )

  const verify = useCallback(
    async (
      operation: RequestVerificationOptions,
      signal: AbortSignal,
      initialPassword?: string
    ) => {
      try {
        signal.throwIfAborted()
        const proof = await requestVerification(operation, initialPassword)
        signal.throwIfAborted()
        if (!proof) {
          throw new AuthOperationError(
            'Verification cancelled',
            'AUTH_CANCELLED'
          )
        }
        return proof.proof_token
      } catch (error) {
        throw projectAccountOperationError(
          signal.aborted ? { code: 'AUTH_CANCELLED' } : error
        )
      }
    },
    [requestVerification]
  )

  const showVerification =
    verification.dialogProps.state.phase !== 'idle' &&
    verification.dialogProps.state.phase !== 'loading'
  return {
    run,
    verify,
    cancel,
    pending,
    error,
    sessionKey,
    showVerification,
    verificationDialogProps: verification.dialogProps,
  }
}
