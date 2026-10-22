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

import { appPath, getAppBasePath, normalizeBasePath } from '../deployment-path'

afterEach(() => vi.unstubAllEnvs())

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
      expect(appPath(`${prefix}/wallet?q=1#balance`)).toBe(
        `${prefix}/wallet?q=1#balance`
      )
      expect(appPath('https://images.example/icon.svg')).toBe(
        'https://images.example/icon.svg'
      )
    }
  )
})
