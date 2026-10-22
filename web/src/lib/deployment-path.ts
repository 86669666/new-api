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
/// <reference types="@rsbuild/core/types" />
/** Fixed build-time mount point; shared with Rsbuild without reading browser globals. */
export function normalizeBasePath(value: string | undefined): string {
  if (value === undefined || value === '' || value === '/') return '/'
  if (!/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*\/?$/.test(value)) {
    throw new Error(
      'VITE_REACT_APP_BASE_PATH must be an absolute path of simple segments'
    )
  }
  return value.endsWith('/') ? value.slice(0, -1) : value
}

export function getAppBasePath(): string {
  return normalizeBasePath(import.meta.env.VITE_REACT_APP_BASE_PATH)
}

/** Convert root-relative browser URLs once; absolute external URLs stay unchanged. */
export function appPath(value: string, basePath = getAppBasePath()): string {
  if (!value.startsWith('/') || value.startsWith('//') || basePath === '/') {
    return value
  }
  const pathname = value.split(/[?#]/, 1)[0]
  if (pathname === basePath || pathname.startsWith(`${basePath}/`)) return value
  return `${basePath}${value}`
}
