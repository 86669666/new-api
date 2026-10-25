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
import { API_KEY_STATUS } from '@/features/keys/constants'

export type ChatLinkType = 'web' | 'custom-protocol' | 'fluent'

export type ChatPreset = {
  id: string
  name: string
  url: string
  type: ChatLinkType
}

export type RawChatConfig =
  | string
  | Record<string, unknown>
  | Array<Record<string, unknown>>
  | null
  | undefined

export type ResolveChatUrlParams = {
  template: string
  apiKey?: string
  serverAddress: string
}

export type ActiveApiKey = {
  key: string
  status: number
}

export const CHERRY_V2_TEMPLATE =
  'cherrystudio://providers/api-keys?v=2&data={cherryConfigV2}'
export const BOXO_V2_TEMPLATE =
  'boxo://providers/api-keys?v=2&data={cherryConfigV2}'
export const BOXNAI_V2_TEMPLATE =
  'boxnai://providers/api-keys?v=2&data={cherryConfigV2}'
export const CHERRY_V2_ERROR =
  'Unable to prepare Cherry Studio v2 import. Check the site configuration and selected API key.'
export const BOXO_V2_ERROR =
  'Unable to prepare Boxo v2 import. Check the site configuration and selected API key.'
export const CHERRY_V2_ORIGIN_WARNING =
  'Server address is not configured. Using this page’s origin; ask the administrator to configure the API address.'

// Exact templates only. Any other scheme that mentions the v2 placeholder is
// still detected as an attempt so the legacy resolver cannot send the key.
export function v2ImportScheme(
  template: string
): 'cherrystudio' | 'boxo' | 'boxnai' | null {
  if (template === CHERRY_V2_TEMPLATE) return 'cherrystudio'
  if (template === BOXO_V2_TEMPLATE) return 'boxo'
  if (template === BOXNAI_V2_TEMPLATE) return 'boxnai'
  return null
}

export function isCherryV2Attempt(template: string): boolean {
  // Recognize encoded/nested attempts for classification too. Only the exact
  // unencoded canonical templates are accepted by the explicit export path.
  let decoded = template
  for (let depth = 0; depth < 3; depth++) {
    if (/cherryconfigv2/i.test(decoded)) return true
    decoded = decoded.replaceAll(/%([0-9a-f]{2})/gi, (_, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16))
    )
  }
  return false
}

export function validateCherryV2Template(template: string): void {
  if (v2ImportScheme(template) == null) throw new Error(CHERRY_V2_ERROR)
}

// Adds an exact client preset an administrator saves in chat settings. It does not
// replace a different preset that already uses the name, and it does not
// accept any other scheme.
export function withBoxoV2Preset(raw: string): string {
  return withV2Preset(raw, 'Boxo', BOXO_V2_TEMPLATE)
}

export function withBoxnaiV2Preset(raw: string): string {
  return withV2Preset(raw, 'Boxnai', BOXNAI_V2_TEMPLATE)
}

function withV2Preset(raw: string, client: string, template: string): string {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw.trim() === '' ? '[]' : raw)
  } catch {
    throw new Error(BOXO_V2_ERROR)
  }
  if (!Array.isArray(parsed)) throw new Error(BOXO_V2_ERROR)
  const names = new Set<string>()
  for (const item of parsed) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error(BOXO_V2_ERROR)
    }
    const entries = Object.entries(item)
    if (entries.length !== 1 || typeof entries[0][1] !== 'string') {
      throw new Error(BOXO_V2_ERROR)
    }
    if (entries[0][1] === template) return raw
    names.add(entries[0][0])
  }
  let name = client
  if (names.has(name)) {
    let suffix = 2
    while (names.has(`${client} ${suffix}`)) suffix += 1
    name = `${client} ${suffix}`
  }
  return JSON.stringify([...parsed, { [name]: template }], null, 2)
}

export type CherryV2Site = {
  instance_id: unknown
  system_name: unknown
  server_address: unknown
}

export function cherryV2BaseUrl(
  configured: unknown,
  origin: string
): { baseUrl: string; usedOrigin: boolean } {
  if (configured != null && typeof configured !== 'string') {
    throw new Error(CHERRY_V2_ERROR)
  }
  const usedOrigin = configured == null || configured === ''
  const raw = usedOrigin ? origin : (configured as string)
  if (/[\s\\?#]|\p{Cc}/u.test(raw)) {
    throw new Error(CHERRY_V2_ERROR)
  }
  // Check before URL normalizes away dot segments or escaped separators.
  const match = /^https?:\/\/([^/]+)(\/.*)?$/i.exec(raw)
  if (!match || match[1].includes('@') || match[1].endsWith(':')) {
    throw new Error(CHERRY_V2_ERROR)
  }
  let path: string
  try {
    path = decodeURIComponent(match[2] ?? '')
  } catch {
    throw new Error(CHERRY_V2_ERROR)
  }
  if (
    /%|[\\?#]|\p{Cc}/u.test(path) ||
    /%2f|%5c/i.test(match[2] ?? '') ||
    path.includes('//') ||
    path.split('/').some((segment) => segment === '.' || segment === '..')
  ) {
    throw new Error(CHERRY_V2_ERROR)
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error(CHERRY_V2_ERROR)
  }
  if (
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.host.endsWith(':') ||
    url.port === '0'
  ) {
    throw new Error(CHERRY_V2_ERROR)
  }
  url.pathname = url.pathname.replace(/\/+$/, '').replace(/\/v1$/, '')
  return { baseUrl: url.toString().replace(/\/+$/, ''), usedOrigin }
}

export function validateCherryV2Site(
  site: CherryV2Site,
  origin: string
): { baseUrl: string; usedOrigin: boolean } {
  if (
    typeof site.instance_id !== 'string' ||
    !/^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      site.instance_id
    ) ||
    site.instance_id.length !== 36 ||
    typeof site.system_name !== 'string' ||
    !site.system_name.trim()
  ) {
    throw new Error(CHERRY_V2_ERROR)
  }
  return cherryV2BaseUrl(site.server_address, origin)
}

export function buildCherryV2Url(
  site: CherryV2Site,
  apiKey: string,
  group: string,
  origin: string,
  template: string = CHERRY_V2_TEMPLATE
): { url: string; usedOrigin: boolean } {
  const scheme = v2ImportScheme(template)
  if (scheme == null) throw new Error(CHERRY_V2_ERROR)
  const { baseUrl, usedOrigin } = validateCherryV2Site(site, origin)
  const key = normalizeApiKey(apiKey)
  if (!key || /\s|\p{Cc}/u.test(key) || !group.trim()) {
    throw new Error(CHERRY_V2_ERROR)
  }
  const payload = JSON.stringify({
    v: 2,
    site_id: site.instance_id,
    type: 'new-api',
    name: site.system_name,
    baseUrl,
    apiKey: key,
    group,
    recommended_models: [],
    default_model: '',
  })
  const bytes = new TextEncoder().encode(payload)
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('')
  const encoded = btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
  return {
    url: `${scheme}://providers/api-keys?v=2&data=${encoded}`,
    usedOrigin,
  }
}

const HTTP_REGEX = /^https?:\/\//i

function toBase64(value: string) {
  if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    return window.btoa(value)
  }

  type BufferConstructorLike = {
    from(data: string, encoding: string): { toString(encoding: string): string }
  }

  const globalObj =
    typeof globalThis !== 'undefined'
      ? (globalThis as Record<string, unknown>)
      : undefined
  const bufferCtor = globalObj?.Buffer

  if (
    typeof bufferCtor === 'function' &&
    typeof (bufferCtor as unknown as BufferConstructorLike).from === 'function'
  ) {
    return (bufferCtor as unknown as BufferConstructorLike)
      .from(value, 'utf-8')
      .toString('base64')
  }

  return ''
}

export function detectChatLinkType(url: string): ChatLinkType {
  if (isCherryV2Attempt(url)) return 'custom-protocol'
  if (HTTP_REGEX.test(url)) {
    return 'web'
  }
  if (url.toLowerCase().startsWith('fluent')) {
    return 'fluent'
  }
  return 'custom-protocol'
}

export function chatLinkRequiresApiKey(url: string): boolean {
  return (
    isCherryV2Attempt(url) ||
    url.includes('{key}') ||
    url.includes('{cherryConfig}') ||
    url.includes('{aionuiConfig}') ||
    url.includes('{deepchatConfig}') ||
    url.includes('{aqbotConfig}')
  )
}

export function parseChatConfig(raw: RawChatConfig): ChatPreset[] {
  let parsed: unknown = raw

  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw)
    } catch {
      return []
    }
  }

  if (!Array.isArray(parsed)) {
    return []
  }

  return parsed
    .map((entry, index) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        Array.isArray(entry) ||
        Object.keys(entry).length !== 1
      ) {
        return null
      }

      const [name, value] = Object.entries(entry)[0]
      if (typeof value !== 'string' || typeof name !== 'string') {
        return null
      }

      const url = value.trim()
      if (!url) {
        return null
      }

      return {
        id: String(index),
        name,
        url,
        type: detectChatLinkType(url),
      } satisfies ChatPreset
    })
    .filter((item): item is ChatPreset => item !== null)
}

function replaceToken(source: string, token: string, value: string) {
  return source.split(token).join(value)
}

function normalizeApiKey(apiKey: string): string {
  const trimmed = apiKey.trim()
  if (!trimmed) return ''
  return trimmed.startsWith('sk-') ? trimmed : `sk-${trimmed}`
}

export function resolveChatUrl({
  template,
  apiKey,
  serverAddress,
}: ResolveChatUrlParams): string {
  // V2 is explicit-action only; never use this legacy/automatic resolver.
  if (isCherryV2Attempt(template)) return ''
  let url = template
  const safeServerAddress = serverAddress || ''

  const safeApiKey = normalizeApiKey(apiKey || '')

  if (url.includes('{cherryConfig}')) {
    const payload = {
      id: 'new-api',
      baseUrl: safeServerAddress,
      apiKey: safeApiKey,
    }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{cherryConfig}', encoded)
  }

  if (url.includes('{aionuiConfig}')) {
    const payload = {
      platform: 'new-api',
      baseUrl: safeServerAddress,
      apiKey: safeApiKey,
    }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{aionuiConfig}', encoded)
  }

  if (url.includes('{deepchatConfig}')) {
    const payload = {
      id: 'new-api',
      baseUrl: safeServerAddress,
      apiKey: safeApiKey,
    }
    const encoded = encodeURIComponent(toBase64(JSON.stringify(payload)))
    return replaceToken(url, '{deepchatConfig}', encoded)
  }

  if (url.includes('{aqbotConfig}')) {
    const query = [
      `name=${encodeURIComponent('New API')}`,
      `baseurl=${encodeURIComponent(safeServerAddress)}`,
      `apikey=${encodeURIComponent(safeApiKey)}`,
      'type=openai',
    ].join('&')
    return replaceToken(url, '{aqbotConfig}', query)
  }

  if (safeServerAddress) {
    const encodedAddress = encodeURIComponent(safeServerAddress)
    url = replaceToken(url, '{address}', encodedAddress)
  }

  if (safeApiKey) {
    url = replaceToken(url, '{key}', safeApiKey)
  }

  return url
}

export function getFirstActiveKey(
  keys: ActiveApiKey[] | undefined
): ActiveApiKey | undefined {
  if (!Array.isArray(keys)) return undefined
  return keys.find((item) => item.status === API_KEY_STATUS.ENABLED)
}
