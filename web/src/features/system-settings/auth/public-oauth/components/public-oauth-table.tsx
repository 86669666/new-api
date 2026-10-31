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
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { BadgeCell } from '@/components/data-table/core/badge-cell'
import { StaticDataTable } from '@/components/data-table/static/static-data-table'
import { StaticRowActions } from '@/components/data-table/static/static-row-actions'
import { StatusBadge } from '@/components/status-badge'
import { Button } from '@/components/ui/button'

import type { PublicOAuthClient } from '../types'

type PublicOAuthTableProps = {
  clients: PublicOAuthClient[]
  onCreate: () => void
  onEdit: (client: PublicOAuthClient) => void
  onDelete: (client: PublicOAuthClient) => void
}

export function PublicOAuthTable(props: PublicOAuthTableProps) {
  const { t } = useTranslation()

  return (
    <>
      <div className='flex items-center justify-between gap-3'>
        <p className='text-muted-foreground text-sm'>
          {t('Manage public OAuth clients for native applications.')}
        </p>
        <Button size='sm' onClick={props.onCreate}>
          <Plus className='mr-1.5 h-4 w-4' />
          {t('Add client')}
        </Button>
      </div>
      <StaticDataTable
        data={props.clients}
        getRowKey={(client) => client.id}
        emptyClassName='text-sm'
        emptyContent={t('No public OAuth clients yet.')}
        columns={[
          {
            id: 'name',
            header: t('Name'),
            cellClassName: 'font-medium',
            cell: (client) => client.name,
          },
          {
            id: 'client-id',
            header: t('Client ID'),
            cellClassName: 'max-w-[180px] truncate font-mono text-xs',
            cell: (client) => client.client_id,
          },
          {
            id: 'status',
            header: t('Status'),
            cell: (client) => (
              <BadgeCell>
                <StatusBadge
                  label={client.enabled ? t('Enabled') : t('Disabled')}
                  variant={client.enabled ? 'success' : 'neutral'}
                  copyable={false}
                />
              </BadgeCell>
            ),
          },
          {
            id: 'actions',
            header: t('Actions'),
            className: 'text-right',
            cellClassName: 'text-right',
            cell: (client) => (
              <StaticRowActions
                editLabel={t('Edit')}
                deleteLabel={t('Delete')}
                menuLabel={t('Open menu')}
                onEdit={() => props.onEdit(client)}
                onDelete={() => props.onDelete(client)}
              />
            ),
          },
        ]}
      />
    </>
  )
}
