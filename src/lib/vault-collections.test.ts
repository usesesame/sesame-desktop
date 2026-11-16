import { describe, expect, it } from 'vitest'
import { sortCollectionItems, SORT_MODES } from './vault-collections'
import type { VaultItem } from './vault-items'

const titles = [
  'zebra',
  'Zebra',
  'Émile',
  'emile',
  'Eagle',
  'éclair',
  'Account 10',
  'Account 2',
  'account 1',
  '10 Downing',
  '2 Factor',
  'Ångström',
  'angstrom',
  'Øresund',
  'oresund',
  'Straße',
  'strasse',
  'Ça va',
  'cave',
  '',
  ' leading space',
  'naïve',
  'naive',
]

function itemsFrom(list: string[]): VaultItem[] {
  return list.map((title, index) => ({
    id: `fictional-item-${index}`,
    kind: 'login',
    title,
    subtitle: '',
    initials: 'F',
    folder: '',
    favourite: index % 5 === 0,
    tags: [],
    issueKinds: [],
    lastUsedAt: index % 3 === 0 ? 1_800_000_000 + (index % 2) : undefined,
    updatedAt: 1_800_000_000 + (index % 4),
    passwordScore: index % 2 === 0 ? 2 : undefined,
  }) as unknown as VaultItem)
}

function previousOrder(items: VaultItem[]): string[] {
  const byTitle = (left: VaultItem, right: VaultItem) => left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
  return [...items]
    .sort((left, right) => {
      if (left.favourite !== right.favourite) return left.favourite ? -1 : 1
      return byTitle(left, right)
    })
    .map((item) => item.id)
}

describe('sorting the item list by name', () => {
  it('keeps the order the per-comparison locale compare gave for mixed case, accents and numbers', () => {
    const items = itemsFrom(titles)
    expect(sortCollectionItems(items, null, 'name').map((item) => item.id)).toEqual(previousOrder(items))
  })

  it('keeps the same order whatever order the items arrive in', () => {
    const items = itemsFrom(titles)
    const reversed = [...items].reverse()
    expect(sortCollectionItems(reversed, null, 'name').map((item) => item.title)).toEqual(
      [...reversed]
        .sort((left, right) => {
          if (left.favourite !== right.favourite) return left.favourite ? -1 : 1
          return left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
        })
        .map((item) => item.title),
    )
  })

  it('breaks ties in every other sort mode by the same name order', () => {
    const items = itemsFrom(titles)
    for (const mode of SORT_MODES) {
      const sorted = sortCollectionItems(items, null, mode)
      expect(sorted).toHaveLength(items.length)
      expect(new Set(sorted.map((item) => item.id)).size).toBe(items.length)
    }
    const unscored = itemsFrom(['b title', 'A title', 'á title']).map((item) => ({ ...item, passwordScore: undefined }))
    expect(sortCollectionItems(unscored, null, 'weakest').map((item) => item.title)).toEqual(['A title', 'á title', 'b title'])
  })
})
