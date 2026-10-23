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
import { Logout01Icon, SmartPhone01Icon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { SecureVerificationDialog } from '@/features/auth/secure-verification'
import {
  getLoginSessions,
  revokeLoginSession,
  revokeOtherLoginSessions,
} from '@/features/profile/api'
import {
  clearAuthenticatedClientState,
  type ExpectedAuthIdentity,
} from '@/lib/api'
import { handleServerError } from '@/lib/handle-server-error'
import { useAuthStore, type LoginSession } from '@/stores/auth-store'

import {
  projectAccountOperationError,
  type AccountOperationError,
} from '../account-operation-error'
import { useAccountSecurity } from '../hooks/use-account-security'
import { LoginSessionDialogs } from './login-session-dialogs'
import { LoginSessionItem } from './login-session-item'

const sessionQueryKey = ['profile', 'login-sessions'] as const

interface SessionRevocationIntent {
  actor: ExpectedAuthIdentity
  sid: string | null
}

function currentAccountActor(): ExpectedAuthIdentity | undefined {
  const auth = useAuthStore.getState().auth
  return auth.user && auth.session
    ? { userId: auth.user.id, sid: auth.session.sid }
    : undefined
}

function isCurrentAccountActor(expected: ExpectedAuthIdentity): boolean {
  const actor = currentAccountActor()
  return actor?.userId === expected.userId && actor.sid === expected.sid
}

export function LoginSessionsCard() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const security = useAccountSecurity()
  const intent = useRef<SessionRevocationIntent | undefined>(undefined)
  const [revokeTarget, setRevokeTarget] = useState<LoginSession | null>(null)
  const [confirmOthers, setConfirmOthers] = useState(false)

  useEffect(() => {
    intent.current = undefined
    setRevokeTarget(null)
    setConfirmOthers(false)
  }, [security.sessionKey])

  const cancelIntent = () => {
    intent.current = undefined
    security.cancel()
    setRevokeTarget(null)
    setConfirmOthers(false)
  }

  const openIntent = (target: LoginSession | null) => {
    cancelIntent()
    const actor = currentAccountActor()
    if (!actor) return
    intent.current = { actor, sid: target?.sid ?? null }
    setRevokeTarget(target)
    setConfirmOthers(!target)
  }

  const sessionsQuery = useQuery({
    queryKey: [...sessionQueryKey, security.sessionKey],
    queryFn: async ({ signal }) => {
      const response = await getLoginSessions(signal)
      if (!response.success) {
        throw projectAccountOperationError(response)
      }
      return response.data ?? []
    },
  })

  const revokeMutation = useMutation({
    mutationFn: async (request: SessionRevocationIntent) => {
      const sid = request.sid
      if (!sid || intent.current !== request) {
        throw projectAccountOperationError({ code: 'AUTH_CANCELLED' })
      }
      const response = await security.run(
        async (signal) => {
          const proof =
            sid === request.actor.sid
              ? undefined
              : await security.verify(
                  { scope: 'session.revoke', context: { sid } },
                  signal
                )
          return revokeLoginSession(sid, proof, signal)
        },
        { expectedAuthIdentity: request.actor, throwOnError: true }
      )
      if (!response) {
        throw projectAccountOperationError({ code: 'AUTH_CANCELLED' })
      }
      if (!response.success) throw projectAccountOperationError(response)
      return request
    },
    onSuccess: async (request) => {
      if (intent.current !== request || !isCurrentAccountActor(request.actor)) {
        return
      }
      intent.current = undefined
      setRevokeTarget(null)
      if (request.sid === request.actor.sid) {
        clearAuthenticatedClientState(queryClient)
        void navigate({ to: '/sign-in', replace: true })
        return
      }
      toast.success(t('Session signed out'))
      await queryClient.invalidateQueries({ queryKey: sessionQueryKey })
    },
    onError: (error: AccountOperationError) => {
      if (error.code !== 'AUTH_CANCELLED') handleServerError(error)
    },
  })

  const revokeOthersMutation = useMutation({
    mutationFn: async (request: SessionRevocationIntent) => {
      if (request.sid !== null || intent.current !== request) {
        throw projectAccountOperationError({ code: 'AUTH_CANCELLED' })
      }
      const response = await security.run(
        async (signal) => {
          const proof = await security.verify(
            { scope: 'session.revoke_others' },
            signal
          )
          return revokeOtherLoginSessions(proof, signal)
        },
        { expectedAuthIdentity: request.actor, throwOnError: true }
      )
      if (!response) {
        throw projectAccountOperationError({ code: 'AUTH_CANCELLED' })
      }
      if (!response.success) throw projectAccountOperationError(response)
      return request
    },
    onSuccess: async (request) => {
      if (intent.current !== request || !isCurrentAccountActor(request.actor)) {
        return
      }
      intent.current = undefined
      setConfirmOthers(false)
      toast.success(t('Other sessions signed out'))
      await queryClient.invalidateQueries({ queryKey: sessionQueryKey })
    },
    onError: (error: AccountOperationError) => {
      if (error.code !== 'AUTH_CANCELLED') handleServerError(error)
    },
  })

  const sessions = sessionsQuery.data ?? []
  const hasOtherSessions = sessions.some((session) => !session.current)
  let sessionsContent: ReactNode
  if (sessionsQuery.isLoading) {
    sessionsContent = (
      <div className='flex flex-col gap-3'>
        <Skeleton className='h-20 w-full' />
        <Skeleton className='h-20 w-full' />
      </div>
    )
  } else if (sessionsQuery.isError) {
    sessionsContent = (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant='icon'>
            <HugeiconsIcon icon={SmartPhone01Icon} strokeWidth={2} />
          </EmptyMedia>
          <EmptyTitle>{t('Unable to load login sessions')}</EmptyTitle>
          <EmptyDescription>
            {t('Refresh the list and try again.')}
          </EmptyDescription>
        </EmptyHeader>
        <Button
          type='button'
          variant='outline'
          onClick={() => sessionsQuery.refetch()}
        >
          {t('Retry')}
        </Button>
      </Empty>
    )
  } else if (sessions.length === 0) {
    sessionsContent = (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant='icon'>
            <HugeiconsIcon icon={SmartPhone01Icon} strokeWidth={2} />
          </EmptyMedia>
          <EmptyTitle>{t('No active login sessions')}</EmptyTitle>
        </EmptyHeader>
      </Empty>
    )
  } else {
    sessionsContent = (
      <div className='flex flex-col'>
        {sessions.map((session, index) => (
          <div key={session.sid}>
            {index > 0 && <Separator />}
            <LoginSessionItem session={session} onRevoke={openIntent} />
          </div>
        ))}
      </div>
    )
  }

  return (
    <>
      <Card data-card-hover='false'>
        <CardHeader>
          <CardTitle>{t('Login sessions')}</CardTitle>
          <CardDescription>
            {t('Review and sign out devices currently using your account.')}
          </CardDescription>
          <CardAction>
            <Button
              type='button'
              variant='outline'
              size='sm'
              disabled={
                !hasOtherSessions ||
                revokeOthersMutation.isPending ||
                revokeMutation.isPending
              }
              onClick={() => openIntent(null)}
            >
              <HugeiconsIcon
                icon={Logout01Icon}
                data-icon='inline-start'
                strokeWidth={2}
              />
              {t('Sign out other sessions')}
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>{sessionsContent}</CardContent>
      </Card>

      <LoginSessionDialogs
        revokeTarget={revokeTarget}
        confirmOthers={confirmOthers}
        revoking={revokeMutation.isPending}
        revokingOthers={revokeOthersMutation.isPending}
        onRevokeTargetChange={(target) => {
          if (!target) cancelIntent()
        }}
        onConfirmOthersChange={(open) => {
          if (!open) cancelIntent()
        }}
        onRevoke={() => {
          const request = intent.current
          if (request && request.sid && revokeTarget?.sid === request.sid) {
            setRevokeTarget(null)
            revokeMutation.mutate(request)
          }
        }}
        onRevokeOthers={() => {
          const request = intent.current
          if (request && request.sid === null && confirmOthers) {
            setConfirmOthers(false)
            revokeOthersMutation.mutate(request)
          }
        }}
      />
      <SecureVerificationDialog
        {...security.verificationDialogProps}
        onCancel={cancelIntent}
      />
    </>
  )
}
