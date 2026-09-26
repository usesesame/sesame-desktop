import { expect, test } from 'vitest'

import { NARROW_LAYOUT_QUERY, paneGridTemplate } from './vault-layout'

test('sizes the three columns from the stored list width when the layout is wide', () => {
  expect(paneGridTemplate(340, true)).toBe('grid-template-columns: 340px auto minmax(0, 1fr)')
})

test('leaves the narrow layout to the stylesheet single-column rule', () => {
  expect(paneGridTemplate(340, false)).toBeUndefined()
  expect(NARROW_LAYOUT_QUERY).toBe('(max-width: 960px)')
})
