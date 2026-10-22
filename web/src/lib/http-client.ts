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
import axios, { type AxiosRequestConfig } from 'axios'
import { t } from 'i18next'

import {
  applyAuthRotation,
  clearAuthentication,
  getFreshAuthHeaders,
  refreshAuthentication,
  type ExpectedAuthIdentity,
} from '@/lib/auth-session'
import { getAppBasePath, appPath } from '@/lib/deployment-path'
import { handleServerError } from '@/lib/handle-server-error'
import {
  getServerErrorMessage,
  safeServerErrorMessage,
} from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

declare module 'axios' {
  export interface AxiosRequestConfig {
    skipBusinessError?: boolean
    skipErrorHandler?: boolean
    disableDuplicate?: boolean
    skipAuthRefresh?: boolean
    authRetry?: boolean
    acceptAuthRotation?: boolean
    singleUseAuthorization?: boolean
    expectedAuthIdentity?: ExpectedAuthIdentity
  }
}

export type ApiRequestConfig = AxiosRequestConfig

/** Required opt-in for organization previews, producers and future member writes. */
export function organizationRequestOptions(
  expected: ExpectedAuthIdentity,
  signal?: AbortSignal
): ApiRequestConfig {
  return {
    expectedAuthIdentity: { ...expected },
    singleUseAuthorization: true,
    skipErrorHandler: true,
    skipBusinessError: true,
    disableDuplicate: true,
    signal,
  }
}

export const api = axios.create({
  baseURL: getAppBasePath(),
  withCredentials: true,
  headers: {
    // no-store forbids storage; no-cache also revalidates any older cached response.
    'Cache-Control': 'no-cache, no-store',
  },
})

const inFlightGet = new Map<string, Promise<unknown>>()
const originalGet = api.get.bind(api)

api.get = ((url: string, config: ApiRequestConfig = {}) => {
  if (config.disableDuplicate || config.expectedAuthIdentity) {
    return originalGet(url, config)
  }

  const params = config.params ? JSON.stringify(config.params) : '{}'
  const sessionSID = useAuthStore.getState().auth.session?.sid || 'anonymous'
  const key = `${sessionSID}:${url}?${params}`
  const existingRequest = inFlightGet.get(key)
  if (existingRequest) return existingRequest

  const request = originalGet(url, config).finally(() => {
    inFlightGet.delete(key)
  })
  inFlightGet.set(key, request)
  return request
}) as typeof api.get

function redirectToSignIn(): void {
  if (
    typeof window !== 'undefined' &&
    window.location.pathname !== appPath('/sign-in')
  ) {
    window.location.replace(appPath('/sign-in'))
  }
}

function assertExpectedAuthIdentity(config?: ApiRequestConfig): void {
  const expected = config?.expectedAuthIdentity
  if (!expected) return
  const auth = useAuthStore.getState().auth
  if (
    config?.signal?.aborted ||
    !Number.isSafeInteger(expected.userId) ||
    expected.userId <= 0 ||
    !expected.sid ||
    auth.user?.id !== expected.userId ||
    auth.session?.sid !== expected.sid
  ) {
    throw new axios.CanceledError('Authentication identity changed')
  }
}

api.interceptors.response.use(
  (response) => {
    assertExpectedAuthIdentity(response.config)
    if (response.config.acceptAuthRotation && response.data?.success === true) {
      applyAuthRotation(response.data.data)
    }

    return response
  },
  async (error) => {
    const config = error?.config as ApiRequestConfig | undefined
    assertExpectedAuthIdentity(config)
    const skipErrorHandler = config?.skipErrorHandler
    const status = error?.response?.status

    if (status === 401) {
      if (config && !config.skipAuthRefresh && !config.authRetry) {
        config.authRetry = true
        const outcome = await refreshAuthentication()
        if (outcome.kind === 'authenticated') {
          const token = useAuthStore.getState().auth.accessToken
          if (token) {
            config.headers = {
              ...config.headers,
              Authorization: `Bearer ${token}`,
            }
          }
          return api.request(config)
        }

        if (outcome.kind === 'anonymous' || outcome.kind === 'out_of_sync') {
          if (!skipErrorHandler) {
            handleServerError({
              message: t('Session expired!'),
              [safeServerErrorMessage]: true,
              cause: error,
            })
          }
          redirectToSignIn()
        }
      } else if (config?.authRetry) {
        clearAuthentication(false)
        if (!skipErrorHandler) {
          handleServerError({
            message: t('Session expired!'),
            [safeServerErrorMessage]: true,
            cause: error,
          })
        }
        redirectToSignIn()
      } else if (!skipErrorHandler) {
        handleServerError({
          message: t('Session expired!'),
          [safeServerErrorMessage]: true,
          cause: error,
        })
      }
    }
    if (axios.isAxiosError(error)) error.message = getServerErrorMessage(error)
    throw error
  }
)

api.interceptors.request.use(async (config) => {
  assertExpectedAuthIdentity(config)
  if (config.expectedAuthIdentity) {
    const adapter = axios.getAdapter(config.adapter ?? api.defaults.adapter)
    config.adapter = (request) => {
      // Axios transforms and promise callbacks run after request interceptors.
      assertExpectedAuthIdentity(request)
      return adapter(request)
    }
  }
  if (config.singleUseAuthorization || config.headers.has('X-Security-Proof')) {
    // Refresh before spending a proof/flow, never by replaying its request.
    config.skipAuthRefresh = true
    try {
      const headers = await getFreshAuthHeaders()
      for (const [name, value] of Object.entries(headers)) {
        config.headers.set(name, value)
      }
    } catch (error) {
      assertExpectedAuthIdentity(config)
      throw axios.AxiosError.from(error, undefined, config)
    }
    assertExpectedAuthIdentity(config)
    return config
  }
  const accessToken = useAuthStore.getState().auth.accessToken
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  assertExpectedAuthIdentity(config)
  return config
})
