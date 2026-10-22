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
import { z } from 'zod'

const limit = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)

export const organizationLimitsResponseSchema = z.object({
  success: z.literal(true),
  data: z
    .object({
      max_organizations_created: limit,
      max_organizations_joined: limit,
    })
    .strict(),
})

export type OrganizationLimits = z.infer<
  typeof organizationLimitsResponseSchema
>['data']
export type OrganizationLimitsForm = {
  max_organizations_created: string
  max_organizations_joined: string
}

export function organizationLimitsFormSchema(message: string) {
  const value = z
    .string()
    .refine(
      (text) =>
        /^(0|[1-9][0-9]*)$/.test(text) &&
        Number(text) <= Number.MAX_SAFE_INTEGER,
      message
    )
  return z
    .object({
      max_organizations_created: value,
      max_organizations_joined: value,
    })
    .strict()
}

export function organizationLimitsFormValues(
  limits: OrganizationLimits
): OrganizationLimitsForm {
  return {
    max_organizations_created: String(limits.max_organizations_created),
    max_organizations_joined: String(limits.max_organizations_joined),
  }
}
