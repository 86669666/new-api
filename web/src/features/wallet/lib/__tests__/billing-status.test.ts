import { expect, test } from 'vitest'

import { getStatusConfig } from '../billing'

test('a failed recharge displays a failure instead of waiting for payment', () => {
  expect(getStatusConfig('failed')).toMatchObject({
    label: 'Failed',
    variant: 'danger',
  })
})
