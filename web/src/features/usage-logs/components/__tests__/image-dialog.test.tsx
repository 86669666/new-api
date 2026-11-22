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
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { ImageDialog } from '../dialogs/image-dialog'

const session = vi.hoisted(() => ({
  headers: { Authorization: 'Bearer local-media-fixture' },
  sid: 'private-media-session',
  userId: 7,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}))

vi.mock('@/lib/api', () => ({
  api: { post: vi.fn() },
  getFreshAuthHeaders: async () => session.headers,
}))

vi.mock('@/stores/auth-store', () => {
  const state = {
    auth: { session: { sid: session.sid }, user: { id: session.userId } },
  }
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

  test('requires an explicit save before loading a missing personal task version', async () => {
    const { api } = await import('@/lib/api')
    const post = vi.mocked(api.post)
    post.mockResolvedValueOnce({} as never)
    const fetchImage = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(
        new Response('ordinary task image', {
          headers: { 'Content-Type': 'image/webp' },
        })
      )
      .mockResolvedValueOnce(
        new Response('fixed task image', {
          headers: { 'Content-Type': 'image/png' },
        })
      )
    vi.stubGlobal('fetch', fetchImage)
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:task-fixture')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})

    render(
      <ImageDialog
        {...props}
        imageUrl='https://provider.invalid/task-image'
        privateImagePath='/api/task/media/27/artifacts/image-1/versions/1'
        privateImageFallbackPath='/api/task/media/27/artifacts/image-1/content'
        fixedImage
        pinPath='/api/task/media/27/artifacts/image-1/versions'
      />
    )

    const saveButton = await screen.findByRole('button', {
      name: 'Save preview',
    })
    expect(
      await screen.findByRole('img', { name: 'Generated image' })
    ).toHaveAttribute('src', 'blob:task-fixture')
    fireEvent.click(saveButton)
    expect(post).toHaveBeenCalledWith(
      '/api/task/media/27/artifacts/image-1/versions',
      undefined,
      expect.objectContaining({
        expectedAuthIdentity: { userId: session.userId, sid: session.sid },
        singleUseAuthorization: true,
        signal: expect.any(AbortSignal),
      })
    )
    expect(
      await screen.findByRole('img', { name: 'Generated image' })
    ).toHaveAttribute('src', 'blob:task-fixture')
    await waitFor(() => expect(fetchImage).toHaveBeenCalledTimes(3))
    expect(fetchImage.mock.calls[1]?.[0]).toEqual(
      new URL(
        '/api/task/media/27/artifacts/image-1/content',
        window.location.origin
      )
    )
    expect(fetchImage.mock.calls[2]?.[0]).toEqual(
      new URL(
        '/api/task/media/27/artifacts/image-1/versions/1',
        window.location.origin
      )
    )
  })

  test('closing the task image dialog cancels its pending save and ignores the late completion', async () => {
    const { api } = await import('@/lib/api')
    const post = vi.mocked(api.post)
    let resolveSave: () => void = () => {}
    post.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveSave = () => resolve({} as never)
        })
    )
    const fetchImage = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(
        new Response('ordinary image', {
          headers: { 'Content-Type': 'image/png' },
        })
      )
    vi.stubGlobal('fetch', fetchImage)
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:pending-fixture')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const taskProps = {
      ...props,
      privateImagePath: '/api/task/media/27/artifacts/image-1/versions/1',
      privateImageFallbackPath: '/api/task/media/27/artifacts/image-1/content',
      pinPath: '/api/task/media/27/artifacts/image-1/versions',
      fixedImage: true,
    }
    const view = render(<ImageDialog {...taskProps} />)
    await screen.findByRole('img', { name: 'Generated image' })
    fireEvent.click(screen.getByRole('button', { name: 'Save preview' }))
    const operation = post.mock.lastCall?.[2]
    expect(operation?.signal?.aborted).toBe(false)
    view.rerender(<ImageDialog {...taskProps} open={false} />)
    expect(operation?.signal?.aborted).toBe(true)
    await act(async () => {
      resolveSave()
    })
    expect(fetchImage).toHaveBeenCalledTimes(2)
  })
})
