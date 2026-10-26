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
  createMemoryHistory,
  createRootRoute,
  createRouter,
  redirect,
} from '@tanstack/react-router'
import axios from 'axios'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { providerHTTP } from '@/features/auth/oauth-provider/api'

import {
  appPath,
  publicAppHref,
  getAppBasePath,
  normalizeBasePath,
} from '../deployment-path'

vi.mock('@/lib/api', async () => {
  const { default: axios } = await import('axios')
  return { api: axios.create(), getFreshAuthHeaders: async () => ({}) }
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('fixed deployment paths', () => {
  test.each([
    [undefined, '/'],
    ['', '/'],
    ['/', '/'],
    ['/gateway/', '/gateway'],
    ['/tenant/gateway', '/tenant/gateway'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeBasePath(input)).toBe(expected)
  })
  test.each([
    'gateway',
    '//host',
    '/a//b',
    '/a/../b',
    '/a%2fb',
    '/a?b',
    '/a#b',
    '/a b',
    '/a\\b',
    'https://host/a',
  ])('rejects invalid build prefix %s', (input) => {
    expect(() => normalizeBasePath(input)).toThrow()
  })
  test.each(['/', '/gateway', '/tenant/gateway'])(
    'keeps router and HTTP addresses under %s',
    (basepath) => {
      vi.stubEnv('VITE_REACT_APP_BASE_PATH', basepath)
      const prefix = basepath === '/' ? '' : basepath
      const router = createRouter({
        routeTree: createRootRoute(),
        history: createMemoryHistory({ initialEntries: [`${prefix}/wallet`] }),
        basepath,
      })
      expect(
        router.resolveRedirect(redirect({ to: '/pricing' })).options.href
      ).toBe(`${prefix}/pricing`)
      expect(providerHTTP.getUri({ url: '/api/oauth/provider/login' })).toBe(
        '/api/oauth/provider/login'
      )
      const client = axios.create({ baseURL: getAppBasePath() })
      expect(client.getUri({ url: '/api/status' })).toBe(`${prefix}/api/status`)
      expect(client.getUri({ url: '/api/user/auth/refresh' })).toBe(
        `${prefix}/api/user/auth/refresh`
      )
      expect(appPath('/logo.png')).toBe(`${prefix}/logo.png`)
      expect(publicAppHref(`${prefix}/wallet?q=1#balance`)).toBe(
        `${prefix}/wallet?q=1#balance`
      )
      expect(appPath('https://images.example/icon.svg')).toBe(
        'https://images.example/icon.svg'
      )
    }
  )
})

test.each(['/', '/gateway'])(
  'requests canonical admin logs and user logs under %s with filters intact',
  async (basepath) => {
    vi.stubEnv('VITE_REACT_APP_BASE_PATH', basepath)
    const { api } = await import('@/lib/api')
    const { getAllLogs, getUserLogs } = await import('@/features/usage-logs/api')
    const previousBaseURL = api.defaults.baseURL
    const previousAdapter = api.defaults.adapter
    const urls: string[] = []
    api.defaults.baseURL = getAppBasePath()
    api.defaults.adapter = async (config) => {
      urls.push(api.getUri(config))
      return {
        data: { success: true, data: { items: [], total: 0 } },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      }
    }
    try {
      const params = { p: 2, page_size: 10, model_name: 'model/a b' }
      await getAllLogs(params)
      await getUserLogs(params)
      const prefix = basepath === '/' ? '' : basepath
      expect(urls).toHaveLength(2)
      for (const [index, route] of ['/api/log/', '/api/log/self'].entries()) {
        const url = new URL(urls[index], 'https://console.example')
        expect(url.pathname).toBe(`${prefix}${route}`)
        expect(Object.fromEntries(url.searchParams)).toEqual({
          p: '2',
          page_size: '10',
          model_name: 'model/a b',
        })
      }
    } finally {
      api.defaults.baseURL = previousBaseURL
      api.defaults.adapter = previousAdapter
    }
  }
)

test('log export beneath /api requests /api/api before ingress stripping', async () => {
  vi.stubEnv('VITE_REACT_APP_BASE_PATH', '/api')
  const fetchMock = vi.fn<
    (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  >(async () => new Response('{"success":true,"data":{"count":0}}\n'))
  vi.stubGlobal('fetch', fetchMock)
  const { exportLogs } = await import('@/features/usage-logs/api')
  await exportLogs({}, false, {
    signal: new AbortController().signal,
    onLog: vi.fn(),
  })
  expect(fetchMock.mock.calls[0][0]).toMatch(/^\/api\/api\/log\/self\/export\?/)
})

test('a 401 beneath /sign-in redirects to the logical sign-in page within that mount', async () => {
  vi.stubEnv('VITE_REACT_APP_BASE_PATH', '/sign-in')
  const replace = vi.fn()
  vi.stubGlobal('window', {
    location: { pathname: '/sign-in/wallet', replace },
    localStorage: window.localStorage,
  })
  const { api } = await import('@/lib/http-client')
  await expect(
    api.get('/api/user/self', {
      authRetry: true,
      skipErrorHandler: true,
      adapter: async (config) => {
        throw new axios.AxiosError(
          'unauthorized',
          'ERR_BAD_REQUEST',
          config,
          undefined,
          {
            status: 401,
            statusText: 'Unauthorized',
            data: {},
            headers: {},
            config,
          }
        )
      },
    })
  ).rejects.toThrow()
  expect(replace).toHaveBeenCalledWith('/sign-in/sign-in')
})
