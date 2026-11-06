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
import { useTranslation } from 'react-i18next'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'

type ChannelPriorityGuideDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ChannelPriorityGuideDialog(
  props: ChannelPriorityGuideDialogProps
) {
  const { t } = useTranslation()

  return (
    <Dialog
      open={props.open}
      onOpenChange={props.onOpenChange}
      title={t('How to set channel priority')}
      description={t(
        'The Priority column uses a number control. A higher number is tried before a lower one.'
      )}
      contentClassName='sm:max-w-lg'
      footer={
        <Button type='button' onClick={() => props.onOpenChange(false)}>
          {t('Close')}
        </Button>
      }
    >
      <div className='text-muted-foreground space-y-3 text-sm leading-5'>
        <p>
          {t(
            'The plus control raises the priority by 1. The minus control lowers it by 1. You can also type a whole number, down to -999.'
          )}
        </p>
        <p>
          {t(
            'Among enabled channels for the same group and model, the highest priority is selected first. Channels that share a number stay on that step. Weight splits requests among them; when every weight is 0, they share requests equally. A later retry uses the next lower priority, and further retries stay on the lowest one.'
          )}
        </p>
        <p>
          {t(
            'On a tag row, the same control asks before applying the number to every channel in the tag.'
          )}
        </p>
      </div>
    </Dialog>
  )
}
