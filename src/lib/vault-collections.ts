import type { VaultEntry } from './types'

export const FAVOURITES_FILTER = '$favourites'
export const RECENT_FILTER = '$recent'
export const UNFILED_FILTER = ''

export function entryMatchesCollection(entry: VaultEntry, filter: string | null): boolean {
  if (filter === null) return true
  if (filter === FAVOURITES_FILTER) return entry.favourite
  if (filter === RECENT_FILTER) return Boolean(entry.lastUsedAt)
  if (filter === UNFILED_FILTER) return !entry.folderId
  return entry.folderId === filter
}

/** Orders the snapshot already carries; choosing one never widens what the webview holds. */
export const SORT_MODES = ['name', 'recent', 'weakest'] as const
export type SortMode = (typeof SORT_MODES)[number]
export const DEFAULT_SORT_MODE: SortMode = 'name'

export function isSortMode(value: unknown): value is SortMode {
  return typeof value === 'string' && (SORT_MODES as readonly string[]).includes(value)
}

export const sortModeLabels: Record<SortMode, string> = {
  name: 'Name',
  recent: 'Recently used',
  weakest: 'Weakest first',
}

function byTitle(left: VaultEntry, right: VaultEntry): number {
  return left.title.localeCompare(right.title, undefined, { sensitivity: 'base' })
}

export function sortCollectionEntries(
  entries: VaultEntry[],
  filter: string | null,
  mode: SortMode = DEFAULT_SORT_MODE,
): VaultEntry[] {
  const effective: SortMode = filter === RECENT_FILTER ? 'recent' : mode
  return [...entries].sort((left, right) => {
    if (effective === 'recent') {
      const recent = (right.lastUsedAt ?? 0) - (left.lastUsedAt ?? 0)
      if (recent) return recent
      return byTitle(left, right)
    }
    if (effective === 'weakest') {
      const weakest = left.passwordScore - right.passwordScore
      if (weakest) return weakest
      return byTitle(left, right)
    }
    if (left.favourite !== right.favourite) return left.favourite ? -1 : 1
    return byTitle(left, right)
  })
}

export const MAX_RECENT_ENTRIES = 6

/** Ids only: never a second place vault data lives. */
export function rememberRecent(recent: string[], id: string, max = MAX_RECENT_ENTRIES): string[] {
  if (!id) return recent
  return [id, ...recent.filter((entry) => entry !== id)].slice(0, max)
}
