import { describe, expect, it } from 'vitest'
import { itemTags, parseTags, uniqueTags, type VaultItem } from './vault-items'

describe('tag helpers', () => {
  it('drops blanks and case-insensitive duplicates', () => {
    expect(uniqueTags(['work', 'Work', '', ' home ', 'home'])).toEqual(['work', 'home'])
  })

  it('parses a comma list into unique tags', () => {
    expect(parseTags('work, Home, work,')).toEqual(['work', 'Home'])
  })

  it('aggregates item tags once per spelling', () => {
    const items = [
      { tags: ['Work', 'home'] },
      { tags: ['work', 'travel'] },
    ] as unknown as VaultItem[]
    expect(itemTags(items)).toEqual(['home', 'travel', 'Work'])
  })
})
