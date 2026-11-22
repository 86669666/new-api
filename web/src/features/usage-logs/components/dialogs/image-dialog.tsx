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
import { Download01Icon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { getFreshAuthHeaders } from '@/lib/api'
import { appPath } from '@/lib/deployment-path'
import { useAuthStore } from '@/stores/auth-store'

import { getPersonalMidjourneyImagePath } from '../../lib/task-artifacts'

const privateImageTypes = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'image/avif',
])

interface ImageDialogProps {
  isAdmin: boolean
  imageUrl: string
  rowId: number
  taskId?: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ImageDialog({
  isAdmin,
  imageUrl,
  rowId,
  taskId,
  open,
  onOpenChange,
}: ImageDialogProps) {
  const { t } = useTranslation()
  const [isLoading, setIsLoading] = useState(true)
  const [hasError, setHasError] = useState(false)
  const [loadedImage, setLoadedImage] = useState<{
    url: string
    source: string
    sid: string
  } | null>(null)
  const sessionSid = useAuthStore((state) => state.auth.session?.sid ?? '')
  const privateImagePath =
    !isAdmin && rowId ? getPersonalMidjourneyImagePath(rowId) : undefined
  const privateImageUrl = privateImagePath
    ? appPath(privateImagePath)
    : undefined

  const objectUrl =
    open &&
    loadedImage?.source === privateImageUrl &&
    loadedImage?.sid === sessionSid
      ? loadedImage.url
      : null

  const handleOpenChange = (newOpen: boolean) => {
    onOpenChange(newOpen)
  }

  useEffect(() => {
    let disposed = false
    let nextObjectUrl: string | null = null

    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoadedImage(null)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsLoading(open)
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHasError(false)
    if (!open || isAdmin) {
      return () => {
        disposed = true
      }
    }
    if (!privateImageUrl || !sessionSid) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsLoading(false)
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setHasError(true)
      return () => {
        disposed = true
      }
    }

    const controller = new AbortController()
    const loadImage = async () => {
      const url = new URL(privateImageUrl, window.location.origin)
      if (url.origin !== window.location.origin) {
        throw new Error('invalid private image origin')
      }
      const headers = await getFreshAuthHeaders()
      if (
        !headers.Authorization ||
        useAuthStore.getState().auth.session?.sid !== sessionSid
      ) {
        throw new Error('private image session changed')
      }
      const response = await fetch(url, {
        credentials: 'same-origin',
        headers,
        redirect: 'error',
        signal: controller.signal,
      })
      if (!response.ok) {
        throw new Error(`image request failed: ${response.status}`)
      }
      const contentType = response.headers
        .get('content-type')
        ?.split(';', 1)[0]
        .trim()
        .toLowerCase()
      const maxBytes = 16 * 1024 * 1024
      const contentLength = Number(response.headers.get('content-length'))
      if (
        !contentType ||
        !privateImageTypes.has(contentType) ||
        (Number.isFinite(contentLength) && contentLength > maxBytes)
      ) {
        throw new Error('image response is not a bounded image')
      }
      if (!response.body) throw new Error('image response has no body')

      const reader = response.body.getReader()
      const chunks: BlobPart[] = []
      let totalBytes = 0
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        totalBytes += value.byteLength
        if (totalBytes > maxBytes) {
          controller.abort()
          throw new Error('image response exceeds the size limit')
        }
        const chunk = new ArrayBuffer(value.byteLength)
        new Uint8Array(chunk).set(value)
        chunks.push(chunk)
      }
      const blob = new Blob(chunks, { type: contentType })
      if (disposed) return
      nextObjectUrl = URL.createObjectURL(blob)
      setLoadedImage({
        url: nextObjectUrl,
        source: privateImageUrl,
        sid: sessionSid,
      })
    }

    void loadImage().catch(() => {
      controller.abort()
      if (disposed) return
      setIsLoading(false)
      setHasError(true)
    })

    return () => {
      disposed = true
      controller.abort()
      if (nextObjectUrl) URL.revokeObjectURL(nextObjectUrl)
    }
  }, [isAdmin, open, privateImageUrl, sessionSid])

  const handleImageLoad = () => {
    setIsLoading(false)
    setHasError(false)
  }

  const handleImageError = () => {
    setIsLoading(false)
    setHasError(true)
    if (objectUrl) {
      URL.revokeObjectURL(objectUrl)
      setLoadedImage(null)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={handleOpenChange}
      title={t('Image Preview')}
      description={
        taskId ? `${t('Task ID:')} ${taskId}` : t('View the generated image')
      }
      contentClassName='sm:max-w-3xl'
      contentHeight='auto'
      bodyClassName='space-y-4'
    >
      <ScrollArea className='max-h-[600px]'>
        <div className='py-4'>
          <div className='bg-muted/50 relative flex min-h-[300px] items-center justify-center rounded-lg border'>
            {/* Skeleton - show when loading or error */}
            {(isLoading || hasError) && (
              <Skeleton className='absolute inset-0 h-full w-full rounded-lg' />
            )}

            {/* Actual Image */}
            {(isAdmin ? imageUrl : objectUrl) ? (
              <img
                src={isAdmin ? imageUrl : (objectUrl ?? undefined)}
                alt={t('Generated image')}
                className={`max-h-[550px] w-full rounded-lg object-contain ${
                  isLoading || hasError ? 'opacity-0' : 'opacity-100'
                }`}
                onLoad={handleImageLoad}
                onError={handleImageError}
                loading='lazy'
              />
            ) : null}

            {/* Error text overlay (shown on skeleton) */}
            {hasError && (
              <div className='absolute inset-0 flex items-center justify-center'>
                <p className='text-muted-foreground text-sm'>
                  {t('Failed to load image')}
                </p>
              </div>
            )}
          </div>

          {!isAdmin && objectUrl && !isLoading && !hasError ? (
            <Button
              variant='outline'
              size='sm'
              nativeButton={false}
              render={<a href={objectUrl} download='generated-image' />}
            >
              <HugeiconsIcon
                icon={Download01Icon}
                strokeWidth={2}
                data-icon='inline-start'
              />
              {t('Download')}
            </Button>
          ) : null}

          {isAdmin ? (
            <div className='bg-muted mt-4 rounded-md p-3'>
              <p className='text-muted-foreground font-mono text-xs break-all'>
                {imageUrl}
              </p>
            </div>
          ) : null}
        </div>
      </ScrollArea>
    </Dialog>
  )
}
