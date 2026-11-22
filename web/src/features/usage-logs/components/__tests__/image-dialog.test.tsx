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
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { ImageDialog } from '../dialogs/image-dialog'

const session = vi.hoisted(() => ({
  headers: { Authorization: 'Bearer local-media-fixture' },
  sid: 'private-media-session',
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}))

vi.mock('@/lib/api', () => ({
  getFreshAuthHeaders: async () => session.headers,
}))

vi.mock('@/stores/auth-store', () => {
  const state = { auth: { session: { sid: session.sid } } }
  return {
    useAuthStore: Object.assign(
      (select: (value: typeof state) => unknown) => select(state),
      { getState: () => state }
    ),
  }
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const props = {
  isAdmin: false,
  imageUrl: 'https://provider.invalid/old-image',
  rowId: 27,
  open: true,
  onOpenChange: () => {},
}

describe('personal MJ image dialog', () => {
  test('keeps the original source visible in the administrator view', () => {
    const fetchImage = vi.fn()
    vi.stubGlobal('fetch', fetchImage)
    render(<ImageDialog {...props} isAdmin />)
    expect(screen.getByText(props.imageUrl)).toBeVisible()
    expect(
      screen.getByRole('img', { name: 'Generated image' })
    ).toHaveAttribute('src', props.imageUrl)
    expect(fetchImage).not.toHaveBeenCalled()
  })

  test('delivers the same authenticated image to preview and download, then releases it on close', async () => {
    const fetchImage = vi.fn(async () => {
      return new Response('bounded fixture image', {
        headers: { 'Content-Type': 'image/png' },
      })
    })
    vi.stubGlobal('fetch', fetchImage)
    const create = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValue('blob:private-fixture')
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const view = render(<ImageDialog {...props} />)
    const image = await screen.findByRole('img', { name: 'Generated image' })
    expect(image).toHaveAttribute('src', 'blob:private-fixture')
    expect(screen.queryByText(props.imageUrl)).not.toBeInTheDocument()
    fireEvent.load(image)
    expect(
      await screen.findByRole('button', { name: 'Download' })
    ).toHaveAttribute('href', 'blob:private-fixture')
    expect(fetchImage).toHaveBeenCalledWith(
      new URL('/api/mj/media/27/image', window.location.origin),
      expect.objectContaining({
        headers: session.headers,
        redirect: 'error',
        credentials: 'same-origin',
      })
    )
    expect(create.mock.calls[0]?.[0]).toBeInstanceOf(Blob)
    view.rerender(<ImageDialog {...props} open={false} />)
    expect(revoke).toHaveBeenCalledWith('blob:private-fixture')
  })

  test.each([
    { status: 403, mime: 'application/json' },
    { status: 200, mime: 'image/svg+xml' },
  ])(
    'does not fall back for status $status and type $mime',
    async ({ status, mime }) => {
      const fetchImage = vi.fn(
        async () =>
          new Response('not a private raster', {
            status,
            headers: { 'Content-Type': mime },
          })
      )
      vi.stubGlobal('fetch', fetchImage)
      const create = vi.spyOn(URL, 'createObjectURL')
      render(<ImageDialog {...props} />)
      await waitFor(() =>
        expect(screen.getByText('Failed to load image')).toBeVisible()
      )
      expect(screen.queryByRole('img')).not.toBeInTheDocument()
      expect(
        screen.queryByRole('button', { name: 'Download' })
      ).not.toBeInTheDocument()
      expect(fetchImage).toHaveBeenCalledTimes(1)
      expect(create).not.toHaveBeenCalled()
    }
  )
})
