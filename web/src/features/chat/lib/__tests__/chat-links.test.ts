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
import { onlineManager } from '@tanstack/react-query'
import { toast } from 'sonner'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'
import { createAppQueryClient } from '@/lib/query-client'
import { statusQueryOptions } from '@/lib/status-query'
import { useAuthStore } from '@/stores/auth-store'

import { prepareCherryV2Import } from '../../hooks/use-active-chat-key'
import {
  CHERRY_V2_TEMPLATE,
  CHERRY_V2_ERROR,
  buildCherryV2Url,
  detectChatLinkType,
  parseChatConfig,
  resolveChatUrl,
} from '../chat-links'

const site = {
  instance_id: '12345678-1234-4234-8234-123456789abc',
  system_name: '站点 🦋',
  server_address: 'https://gateway.example/prefix/v1/',
}

describe('Cherry Studio explicit v2 contract', () => {
  it('encodes UTF8 identity and one selected key as unpadded base64url', () => {
    const result = buildCherryV2Url(
      site,
      'selected-synthetic-key',
      '分组',
      'http://localhost'
    )
    const url = new URL(result.url)
    const encoded = url.searchParams.get('data') ?? ''
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(
      JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
    ).toEqual({
      v: 2,
      site_id: site.instance_id,
      type: 'new-api',
      name: site.system_name,
      baseUrl: 'https://gateway.example/prefix',
      apiKey: 'sk-selected-synthetic-key',
      group: '分组',
      recommended_models: [],
      default_model: '',
    })
    expect(result.usedOrigin).toBe(false)
    expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
      'cherrystudio://providers/api-keys'
    )
    expect(url.searchParams.get('v')).toBe('2')
  })

  it('keeps all v2 attempts non-web without filtering or reindexing presets', () => {
    const presets = parseChatConfig([
      { First: 'https://legacy.example/?key={key}' },
      { Unsafe: 'https://evil.example/?data={cherryConfigV2}&key={key}' },
      { Cherry: CHERRY_V2_TEMPLATE },
    ])
    expect(presets.map((p) => [p.id, p.type])).toEqual([
      ['0', 'web'],
      ['1', 'custom-protocol'],
      ['2', 'custom-protocol'],
    ])
    expect(
      detectChatLinkType('https://evil.example/?x=%7BcherryConfigV2%7D')
    ).toBe('custom-protocol')
    expect(
      resolveChatUrl({
        template: presets[1].url,
        apiKey: 'never-send',
        serverAddress: 'https://site.example',
      })
    ).toBe('')
  })

  it('retains v1 encoding and legacy web substitutions exactly', () => {
    const legacy = resolveChatUrl({
      template: 'cherrystudio://providers/api-keys?v=1&data={cherryConfig}',
      apiKey: 'synthetic',
      serverAddress: 'https://site.example/v1/',
    })
    const expectedPayload = encodeURIComponent(
      btoa(
        JSON.stringify({
          id: 'new-api',
          baseUrl: 'https://site.example/v1/',
          apiKey: 'sk-synthetic',
        })
      )
    )
    expect(legacy).toBe(
      `cherrystudio://providers/api-keys?v=1&data=${expectedPayload}`
    )
    expect(
      resolveChatUrl({
        template: 'https://legacy.example/?key={key}&base={address}',
        apiKey: 'synthetic',
        serverAddress: 'https://site.example',
      })
    ).toBe(
      'https://legacy.example/?key=sk-synthetic&base=https%3A%2F%2Fsite.example'
    )
  })
})

const clients: ReturnType<typeof createAppQueryClient>[] = []
beforeEach(() => {
  useAuthStore.getState().auth.setBundle({
    access_token: 'synthetic-dashboard',
    token_type: 'Bearer',
    access_expires_at: 9999999999,
    user: { id: 1, username: 'fixture', role: 1 },
    session: {
      sid: 'fixture-session',
      current: true,
      login_method: 'password',
      ip: '',
      user_agent: '',
      created_at: 1,
      last_active_at: 1,
      expires_at: 9999999999,
    },
  })
})
afterEach(() => {
  clients.splice(0).forEach((client) => client.clear())
  useAuthStore.getState().auth.reset()
  localStorage.clear()
})

function importFixture(group: unknown = 'named') {
  const client = createAppQueryClient()
  clients.push(client)
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
    if (url === '/api/status') return { data: { success: true, data: site } }
    if (url === '/api/token/') {
      return {
        data: {
          success: true,
          data: {
            items: [
              { id: 4, status: 2 },
              { id: 7, status: 1 },
              { id: 9, status: 1 },
            ],
          },
        },
      }
    }
    if (url === '/api/token/7') {
      return {
        data: {
          success: true,
          data: { id: 7, status: 1, expired_time: -1, group },
        },
      }
    }
    if (url === '/api/user/self') {
      return { data: { success: true, data: { id: 1, group: 'inherited' } } }
    }
    throw new Error('unexpected network endpoint')
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { key: 'selected-synthetic-key' } },
  })
  return { client, get, post }
}

it.each(['named', '', 'auto'])(
  'prepares the same first-enabled token ID with truthful %s group and no invented models',
  async (group) => {
    const { client, get, post } = importFixture(group)
    const result = await prepareCherryV2Import(client, CHERRY_V2_TEMPLATE)
    const payload = JSON.parse(
      Buffer.from(
        new URL(result.url).searchParams.get('data') ?? '',
        'base64url'
      ).toString('utf8')
    )
    expect(payload.group).toBe(group || 'inherited')
    expect(payload.recommended_models).toEqual([])
    expect(payload.default_model).toBe('')
    expect(post).toHaveBeenCalledExactlyOnceWith(
      '/api/token/7/key',
      undefined,
      expect.objectContaining({ skipErrorHandler: true, skipAuthRefresh: true })
    )
    expect(get.mock.calls.map((call) => call[0])).not.toContain(
      '/api/user/models'
    )
    expect(get.mock.calls.some((call) => call[0] === '/api/user/self')).toBe(
      group === ''
    )
  }
)

it.each([
  'https://attacker.example/?data={cherryConfigV2}&key={key}',
  'other://providers/api-keys?v=2&data={cherryConfigV2}',
  `${CHERRY_V2_TEMPLATE}&redirect=https://attacker.example`,
  `${CHERRY_V2_TEMPLATE}#fragment`,
  'cherrystudio://attacker/api-keys?v=2&data={cherryConfigV2}',
  `https://attacker.example/?next=${encodeURIComponent(CHERRY_V2_TEMPLATE)}`,
])(
  'rejects noncanonical v2 template before any key or metadata access: %s',
  async (template) => {
    const { client, get, post } = importFixture()
    await expect(prepareCherryV2Import(client, template, 7)).rejects.toThrow(
      CHERRY_V2_ERROR
    )
    expect(get).not.toHaveBeenCalled()
    expect(post).not.toHaveBeenCalled()
    expect(detectChatLinkType(template)).toBe('custom-protocol')
  }
)

it.each([
  '/relative',
  '//example.com',
  'javascript:alert(1)',
  'https://user:pass@example.com',
  'https://@example.com',
  'https://example.com:',
  'https://example.com?x=1',
  'https://example.com#fragment',
  'https://example.com\\path',
  'https://example.com/a/../b',
  'https://example.com/%2e%2e/',
  'https://example.com/a%2fb',
  'https://example.com/%252f',
  'https://example.com:0',
  'https://example.com:99999',
  'https://example.com/\n',
])(
  'rejects unsafe raw configured base without falling back or revealing key: %s',
  async (server_address) => {
    const { client, get, post } = importFixture()
    get.mockResolvedValueOnce({
      data: { success: true, data: { ...site, server_address } },
    })
    await expect(
      prepareCherryV2Import(client, CHERRY_V2_TEMPLATE, 7)
    ).rejects.toThrow(CHERRY_V2_ERROR)
    expect(get).toHaveBeenCalledTimes(1)
    expect(post).not.toHaveBeenCalled()
  }
)

it('uses a validated current origin only when the server address is genuinely empty', async () => {
  const result = buildCherryV2Url(
    { ...site, server_address: '' },
    'synthetic',
    'named',
    'http://127.0.0.1:3000'
  )
  expect(result.usedOrigin).toBe(true)
  expect(
    JSON.parse(
      Buffer.from(
        new URL(result.url).searchParams.get('data') ?? '',
        'base64url'
      ).toString()
    ).baseUrl
  ).toBe('http://127.0.0.1:3000')
  expect(() =>
    buildCherryV2Url(
      { ...site, instance_id: '' },
      'synthetic',
      'named',
      'http://localhost'
    )
  ).toThrow(CHERRY_V2_ERROR)
  const first = JSON.parse(
    Buffer.from(
      new URL(result.url).searchParams.get('data') ?? '',
      'base64url'
    ).toString()
  ).site_id
  expect(first).toBe(site.instance_id)
  const other = buildCherryV2Url(
    { ...site, instance_id: '12345678-1234-4234-8234-123456789abd' },
    'synthetic',
    'named',
    'http://localhost'
  )
  expect(other.url).not.toBe(result.url)
})

it('does not expose a failed fresh status or use its cached predecessor with the real app QueryCache', async () => {
  const { client, get, post } = importFixture()
  client.setQueryData(['status'], site)
  const errorToast = vi.spyOn(toast, 'error')
  const log = vi.spyOn(console, 'error').mockImplementation(() => {})
  get.mockRejectedValueOnce({
    response: { data: { message: 'SERVER-SECRET-CANARY' } },
    cause: new Error('SERVER-SECRET-CANARY'),
  })
  await expect(
    prepareCherryV2Import(client, CHERRY_V2_TEMPLATE, 7)
  ).rejects.toThrow(CHERRY_V2_ERROR)
  expect(get).toHaveBeenCalledTimes(1)
  expect(post).not.toHaveBeenCalled()
  expect(errorToast).not.toHaveBeenCalled()
  expect(log).not.toHaveBeenCalled()
  expect(JSON.stringify(client.getQueryState(['status'])?.error)).not.toContain(
    'SERVER-SECRET-CANARY'
  )
})

it.each(['fetching', 'paused'] as const)(
  'rejects an already %s shared status request without joining or cancelling it',
  async (fetchStatus) => {
    const { client, get, post } = importFixture()
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    const wasOnline = onlineManager.isOnline()
    let release!: (value: {
      data: { success: boolean; data: typeof site }
    }) => void
    const gate = new Promise<{ data: { success: boolean; data: typeof site } }>(
      (resolve) => {
        release = resolve
      }
    )
    get.mockImplementationOnce(() => gate)
    client.mount()
    onlineManager.setOnline(fetchStatus !== 'paused')
    const earlier = client.fetchQuery(statusQueryOptions)
    try {
      expect(client.getQueryState(['status'])?.fetchStatus).toBe(fetchStatus)
      await expect(
        prepareCherryV2Import(client, CHERRY_V2_TEMPLATE, 7)
      ).rejects.toThrow(CHERRY_V2_ERROR)
      expect(get).toHaveBeenCalledTimes(fetchStatus === 'fetching' ? 1 : 0)
      expect(post).not.toHaveBeenCalled()
      expect(open).not.toHaveBeenCalled()
      expect(client.getQueryState(['status'])?.fetchStatus).toBe(fetchStatus)

      release({ data: { success: true, data: site } })
      onlineManager.setOnline(true)
      await expect(earlier).resolves.toEqual(site)
      expect(get).toHaveBeenCalledExactlyOnceWith('/api/status')
      expect(post).not.toHaveBeenCalled()
      expect(open).not.toHaveBeenCalled()
    } finally {
      release({ data: { success: true, data: site } })
      onlineManager.setOnline(true)
      await earlier
      client.unmount()
      onlineManager.setOnline(wasOnline)
    }
  }
)

it.each(['metadata', 'self', 'key'])(
  'returns only fixed errors when %s response contains a canary',
  async (stage) => {
    const { client, get, post } = importFixture(stage === 'self' ? '' : 'named')
    if (stage === 'key') {
      post.mockResolvedValueOnce({
        data: { success: false, message: 'SECRET-CANARY' },
      })
    } else {
      const original = get.getMockImplementation()
      if (!original) {
        throw new Error('Expected API mock implementation')
      }
      get.mockImplementation(async (...args) =>
        args[0] === (stage === 'self' ? '/api/user/self' : '/api/token/7')
          ? { data: { success: false, message: 'SECRET-CANARY' } }
          : original(...args)
      )
    }
    await expect(
      prepareCherryV2Import(client, CHERRY_V2_TEMPLATE, 7)
    ).rejects.toThrow(CHERRY_V2_ERROR)
    if (stage !== 'key') expect(post).not.toHaveBeenCalled()
  }
)

it.each([{ id: 9 }, { status: 2 }, { expired_time: 1 }])(
  'rejects mismatched or unusable selected token metadata before reveal',
  async (fields) => {
    const { client, get, post } = importFixture()
    const original = get.getMockImplementation()
    if (!original) {
      throw new Error('Expected API mock implementation')
    }
    get.mockImplementation(async (...args) =>
      args[0] === '/api/token/7'
        ? {
            data: {
              success: true,
              data: {
                id: 7,
                status: 1,
                expired_time: -1,
                group: 'named',
                ...fields,
              },
            },
          }
        : original(...args)
    )
    await expect(
      prepareCherryV2Import(client, CHERRY_V2_TEMPLATE, 7)
    ).rejects.toThrow(CHERRY_V2_ERROR)
    expect(post).not.toHaveBeenCalled()
  }
)
