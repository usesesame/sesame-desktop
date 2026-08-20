import type { VaultItem } from './vault-items'

export const FAVOURITES_FILTER = '$favourites'
export const RECENT_FILTER = '$recent'
export const UNFILED_FILTER = ''
const TAG_FILTER_PREFIX = 'tag:'

export function tagFilter(tag: string): string {
  return `${TAG_FILTER_PREFIX}${tag}`
}

export function tagFromFilter(filter: string | null): string | null {
  return filter?.startsWith(TAG_FILTER_PREFIX) ? filter.slice(TAG_FILTER_PREFIX.length) : null
}

export function itemMatchesCollection(item: VaultItem, filter: string | null): boolean {
  if (filter === null) return true
  if (filter === FAVOURITES_FILTER) return item.favourite
  if (filter === RECENT_FILTER) return Boolean(item.lastUsedAt)
  const tag = tagFromFilter(filter)
  if (tag !== null) return item.tags.some((candidate) => candidate.toLowerCase() === tag.toLowerCase())
  if (filter === UNFILED_FILTER) return !item.folderId
  return item.folderId === filter
}

/** Orders the snapshot already carries; choosing one never widens what the webview holds. */
export const SORT_MODES = ['name', 'recent', 'updated', 'weakest'] as const
export type SortMode = (typeof SORT_MODES)[number]
export const DEFAULT_SORT_MODE: SortMode = 'name'

export function isSortMode(value: unknown): value is SortMode {
  return typeof value === 'string' && (SORT_MODES as readonly string[]).includes(value)
}

export const sortModeLabels: Record<SortMode, string> = {
  name: 'Name',
  recent: 'Recently used',
  updated: 'Recently changed',
  weakest: 'Weakest first',
}

function byTitle(left: VaultItem, right: VaultItem): number {
  return left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
}

export function sortCollectionItems(
  items: VaultItem[],
  filter: string | null,
  mode: SortMode = DEFAULT_SORT_MODE,
): VaultItem[] {
  const effective: SortMode = filter === RECENT_FILTER ? 'recent' : mode
  return [...items].sort((left, right) => {
    if (effective === 'recent') {
      const recent = (right.lastUsedAt ?? 0) - (left.lastUsedAt ?? 0)
      if (recent) return recent
      return byTitle(left, right)
    }
    if (effective === 'updated') {
      const updated = right.updatedAt - left.updatedAt
      if (updated) return updated
      return byTitle(left, right)
    }
    if (effective === 'weakest') {
      // A record without a password has nothing to score, so it sorts last.
      const weakest = (left.passwordScore ?? 101) - (right.passwordScore ?? 101)
      if (weakest) return weakest
      return byTitle(left, right)
    }
    if (left.favourite !== right.favourite) return left.favourite ? -1 : 1
    return byTitle(left, right)
  })
}

export const MAX_RECENT_ITEMS = 6

/** Ids only: never a second place vault data lives. */
export function rememberRecent(recent: string[], id: string, max = MAX_RECENT_ITEMS): string[] {
  if (!id) return recent
  return [id, ...recent.filter((entry) => entry !== id)].slice(0, max)
}
