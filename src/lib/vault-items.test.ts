import { describe, expect, it } from 'vitest'
import { itemMatchesQuery, itemTags, parseTags, uniqueTags, type VaultItem } from './vault-items'

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

describe('local search', () => {
  const item = { title: 'Café Northwind', subtitle: 'ana@example.test', folder: 'Work', tags: ['payroll'] } as unknown as VaultItem

  it('matches words in any order', () => {
    expect(itemMatchesQuery(item, 'work northwind')).toBe(true)
    expect(itemMatchesQuery(item, 'ana payroll')).toBe(true)
  })

  it('needs every word to match', () => {
    expect(itemMatchesQuery(item, 'northwind contoso')).toBe(false)
  })

  it('ignores accents and case in the item and in the query', () => {
    expect(itemMatchesQuery(item, 'cafe')).toBe(true)
    expect(itemMatchesQuery({ ...item, title: 'Cafe' } as VaultItem, 'CAFÉ')).toBe(true)
  })

  it('matches everything for an empty or blank query', () => {
    expect(itemMatchesQuery(item, '')).toBe(true)
    expect(itemMatchesQuery(item, '   ')).toBe(true)
  })
})
