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
import {
  type QueryClient,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { t } from 'i18next'
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { fetchTokenKey, getApiKeys } from '@/features/keys/api'
import { API_KEY_STATUS } from '@/features/keys/constants'
import { api } from '@/lib/api'
import {
  requireServerSuccess,
  createServerError,
} from '@/lib/server-error-message'
import { statusQueryOptions } from '@/lib/status-query'
import { useAuthStore } from '@/stores/auth-store'

import {
  buildCherryV2Url,
  CHERRY_V2_ERROR,
  validateCherryV2Site,
  validateCherryV2Template,
} from '../lib/chat-links'

export async function fetchActiveChatKey() {
  const result = await getApiKeys({ p: 1, size: 50 })
  if (!result.success) {
    throw createServerError(result, t('Failed to load API keys'))
  }

  const items = result.data?.items ?? []
  const active = items.find((item) => item.status === API_KEY_STATUS.ENABLED)
  if (!active) {
    throw new Error('No enabled API keys found. Create or enable one first.')
  }

  const keyResult = await fetchTokenKey(active.id)
  if (!keyResult.success || !keyResult.data?.key) {
    throw createServerError(keyResult, t('Failed to load API keys'))
  }

  return `sk-${keyResult.data.key}`
}

/**
 * Get the currently active API key for chat links
 */
export function useActiveChatKey(enabled: boolean) {
  const userId = useAuthStore((state) => state.auth.user?.id)

  return useQuery({
    queryKey: ['chat-active-key', userId],
    queryFn: async () => requireServerSuccess(await fetchActiveChatKey()),
    enabled: enabled && Boolean(userId),
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  })
}

class CherryImportCancelled extends Error {}

function cherryResponseData(body: unknown): Record<string, unknown> {
  if (
    !body ||
    typeof body !== 'object' ||
    !('success' in body) ||
    body.success !== true ||
    !('data' in body) ||
    !body.data ||
    typeof body.data !== 'object' ||
    Array.isArray(body.data)
  ) {
    throw new Error(CHERRY_V2_ERROR)
  }
  return body.data as Record<string, unknown>
}

// The key and resulting URL live only in this operation, never in query or UI
// state. The callback additionally binds the operation to its mounted menu/row.
export async function prepareCherryV2Import(
  queryClient: QueryClient,
  template: string,
  tokenId?: number,
  isCurrent: () => boolean = () => true
): Promise<{ url: string; usedOrigin: boolean }> {
  validateCherryV2Template(template)
  const initial = useAuthStore.getState().auth
  const userId = initial.user?.id
  const sid = initial.session?.sid
  const checkCurrent = () => {
    const auth = useAuthStore.getState().auth
    if (
      !isCurrent() ||
      auth.user?.id !== userId ||
      auth.session?.sid !== sid ||
      !auth.accessToken
    ) {
      throw new CherryImportCancelled()
    }
  }
  if (
    !userId ||
    !sid ||
    !initial.accessToken ||
    (tokenId !== undefined && (!Number.isSafeInteger(tokenId) || tokenId <= 0))
  ) {
    throw new Error(CHERRY_V2_ERROR)
  }
  try {
    checkCurrent()
    const fetchStatus = queryClient.getQueryState(
      statusQueryOptions.queryKey
    )?.fetchStatus
    // Joining an earlier retryer would inherit its error/retry policy.
    if (fetchStatus === 'fetching' || fetchStatus === 'paused') {
      throw new Error(CHERRY_V2_ERROR)
    }
    const status = await queryClient.fetchQuery({
      ...statusQueryOptions,
      staleTime: 0,
      retry: false,
      meta: { errorToast: false },
      queryFn: async (context) => {
        try {
          if (typeof statusQueryOptions.queryFn !== 'function') {
            throw new Error(CHERRY_V2_ERROR)
          }
          return await statusQueryOptions.queryFn(context)
        } catch {
          // Even another mounted status observer cannot expose a raw error
          // if it replaces the shared query's notification metadata mid-flight.
          throw new Error(CHERRY_V2_ERROR)
        }
      },
    })
    checkCurrent()
    const site = {
      instance_id: status?.instance_id,
      system_name: status?.system_name,
      server_address: status?.server_address,
    }
    validateCherryV2Site(site, window.location.origin)
    // These existing authenticated endpoints use no secret-bearing query and
    // cannot retry a failed business request or show a server-controlled error.
    const config = {
      skipErrorHandler: true,
      skipAuthRefresh: true,
      disableDuplicate: true,
    }
    let selectedId = tokenId
    if (selectedId === undefined) {
      const listed = cherryResponseData(
        (
          await api.get('/api/token/', {
            ...config,
            params: { p: 1, size: 50 },
          })
        ).data
      )
      checkCurrent()
      if (!Array.isArray(listed.items)) throw new Error(CHERRY_V2_ERROR)
      const selected = listed.items.find(
        (item: unknown) =>
          item &&
          typeof item === 'object' &&
          'status' in item &&
          item.status === API_KEY_STATUS.ENABLED
      )
      if (
        !selected ||
        typeof selected !== 'object' ||
        !('id' in selected) ||
        !Number.isSafeInteger(selected.id) ||
        (selected.id as number) <= 0
      ) {
        throw new Error(CHERRY_V2_ERROR)
      }
      selectedId = selected.id as number
    }
    checkCurrent()
    const token = cherryResponseData(
      (await api.get(`/api/token/${selectedId}`, config)).data
    )
    checkCurrent()
    const expires = token.expired_time
    if (
      token.id !== selectedId ||
      token.status !== API_KEY_STATUS.ENABLED ||
      typeof expires !== 'number' ||
      !Number.isSafeInteger(expires) ||
      (expires !== -1 && expires <= Date.now() / 1000)
    ) {
      throw new Error(CHERRY_V2_ERROR)
    }
    let group = token.group
    if (group == null || group === '') {
      const self = cherryResponseData(
        (await api.get('/api/user/self', config)).data
      )
      checkCurrent()
      if (self.id !== userId) throw new Error(CHERRY_V2_ERROR)
      group = self.group
    }
    if (typeof group !== 'string' || !group.trim()) {
      throw new Error(CHERRY_V2_ERROR)
    }
    checkCurrent()
    const revealed = cherryResponseData(
      (await api.post(`/api/token/${selectedId}/key`, undefined, config)).data
    )
    checkCurrent()
    if (
      typeof revealed.key !== 'string' ||
      (expires !== -1 && expires <= Date.now() / 1000)
    ) {
      throw new Error(CHERRY_V2_ERROR)
    }
    return buildCherryV2Url(site, revealed.key, group, window.location.origin)
  } catch (error) {
    if (error instanceof CherryImportCancelled) throw error
    // Do not propagate a raw server response, Axios config, key or cause.
    throw new Error(CHERRY_V2_ERROR)
  }
}

// A synchronous ref excludes duplicate activation. Only an opaque operation
// marker enters React state; account/session/selection changes revoke its life.
export function useCherryStudioV2Import(selection: string): {
  openV2: (template: string, tokenId?: number) => Promise<void>
  isOpening: boolean
} {
  const queryClient = useQueryClient()
  const { t: translate } = useTranslation()
  const userId = useAuthStore((state) => state.auth.user?.id)
  const sid = useAuthStore((state) => state.auth.session?.sid)
  const lifetime = useMemo(
    () => ({ selection, userId, sid, marker: Symbol() }),
    [selection, userId, sid]
  )
  const active = useRef<object | null>(null)
  const [opening, setOpening] = useState<symbol | null>(null)
  useLayoutEffect(
    () => () => {
      active.current = null
    },
    [lifetime]
  )

  const openV2 = useCallback(
    async (template: string, tokenId?: number) => {
      if (active.current) return
      const operation = {}
      active.current = operation
      setOpening(lifetime.marker)
      const isCurrent = () =>
        active.current === operation &&
        useAuthStore.getState().auth.user?.id === userId &&
        useAuthStore.getState().auth.session?.sid === sid
      try {
        const result = await prepareCherryV2Import(
          queryClient,
          template,
          tokenId,
          isCurrent
        )
        if (!isCurrent()) return
        if (result.usedOrigin) {
          toast.warning(
            translate(
              'Server address is not configured. Using this page’s origin; ask the administrator to configure the API address.'
            )
          )
        }
        if (!isCurrent()) return
        window.open(result.url, '_blank', 'noopener,noreferrer')
      } catch (error) {
        if (isCurrent() && !(error instanceof CherryImportCancelled)) {
          toast.error(
            translate(
              'Unable to prepare Cherry Studio v2 import. Check the site configuration and selected API key.'
            )
          )
        }
      } finally {
        if (active.current === operation) {
          active.current = null
          setOpening(null)
        }
      }
    },
    [lifetime, queryClient, sid, translate, userId]
  )
  return { openV2, isOpening: opening === lifetime.marker }
}
