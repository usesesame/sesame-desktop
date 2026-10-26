import type { VaultEntrySummary } from './types'

const LABEL = /^[\p{L}\p{N}]([\p{L}\p{N}-]*[\p{L}\p{N}])?$/u
const GENERIC_SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'])
const SUGGESTED_TAGS = 5

export function hostOf(input: string): string {
  const text = input.trim()
  if (!text || /\s/.test(text)) return ''
  const withoutScheme = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
  const authority = withoutScheme.split(/[/?#]/)[0] ?? ''
  const afterUser = authority.slice(authority.lastIndexOf('@') + 1)
  const host = afterUser.replace(/:\d+$/, '').toLowerCase().replace(/^www\./, '')
  const labels = host.split('.')
  if (!labels.every((label) => LABEL.test(label))) return ''
  return labels.length > 1 || host === 'localhost' ? host : ''
}

export function sameSite(left: string, right: string): boolean {
  if (!left || !right) return false
  if (left === right) return true
  return left.endsWith(`.${right}`) || right.endsWith(`.${left}`)
}

export function nameFromUrl(input: string): string {
  const host = hostOf(input)
  if (!host || /^\d+(\.\d+){3}$/.test(host)) return ''
  const labels = host.split('.')
  if (labels.length < 2) return ''
  labels.pop()
  const last = labels[labels.length - 1]
  if (labels.length >= 2 && GENERIC_SECOND_LEVEL.has(last)) labels.pop()
  const name = labels[labels.length - 1].replaceAll('-', ' ')
  return name.charAt(0).toUpperCase() + name.slice(1)
}

function recency(entry: VaultEntrySummary): number {
  return Math.max(entry.lastUsedAt ?? 0, entry.updatedAt)
}

export function loginsOnSite(url: string, entries: VaultEntrySummary[], excludeId?: string): VaultEntrySummary[] {
  const host = hostOf(url)
  if (!host) return []
  return entries
    .filter((entry) => entry.id !== excludeId && sameSite(host, hostOf(entry.site)))
    .sort((left, right) => recency(right) - recency(left))
}

export function folderToSuggest(matches: VaultEntrySummary[], chosenFolderId: string | undefined): { id: string; name: string } | null {
  if (chosenFolderId) return null
  const folders = new Map<string, { id: string; name: string; count: number; latest: number }>()
  for (const match of matches) {
    if (!match.folderId) continue
    const known = folders.get(match.folderId)
    if (known) {
      known.count += 1
      known.latest = Math.max(known.latest, recency(match))
    } else {
      folders.set(match.folderId, { id: match.folderId, name: match.folder, count: 1, latest: recency(match) })
    }
  }
  let best: { id: string; name: string; count: number; latest: number } | null = null
  for (const candidate of folders.values()) {
    if (!best || candidate.count > best.count || (candidate.count === best.count && candidate.latest > best.latest)) best = candidate
  }
  return best ? { id: best.id, name: best.name } : null
}

export function tagsToSuggest(matches: VaultEntrySummary[], entries: VaultEntrySummary[], applied: string[], limit = SUGGESTED_TAGS): string[] {
  const taken = new Set(applied.map((tag) => tag.toLowerCase()))
  const chosen: string[] = []
  const add = (tag: string) => {
    const key = tag.toLowerCase()
    if (!tag || taken.has(key)) return
    taken.add(key)
    chosen.push(tag)
  }
  for (const match of matches) for (const tag of match.tags) add(tag)
  const counts = new Map<string, number>()
  for (const entry of entries) for (const tag of entry.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1)
  const ranked = [...counts.entries()].sort((left, right) => right[1] - left[1]).map(([tag]) => tag)
  for (const tag of ranked) add(tag)
  return chosen.slice(0, limit)
}
