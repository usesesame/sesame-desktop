import type { IssueKind, ItemKind, VaultSnapshot } from './types'

export interface VaultItem {
  id: string
  kind: ItemKind
  title: string
  subtitle: string
  initials: string
  folderId?: string
  folder: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
  tags: string[]
  /** Absent for every kind but a login: nothing else stores a password. */
  securityLevel?: 'good' | 'needs-work'
  issueKinds: IssueKind[]
  passwordScore?: number
}

export interface ItemKindMeta {
  id: ItemKind
  label: string
  plural: string
  addLabel: string
  icon: string
}

/** The order the category filters and the Add menu both follow. */
export const ITEM_KINDS: readonly ItemKindMeta[] = [
  { id: 'login', label: 'Login', plural: 'Logins', addLabel: 'Login', icon: 'globe' },
  { id: 'card', label: 'Card', plural: 'Cards', addLabel: 'Card', icon: 'card' },
  { id: 'secure_note', label: 'Note', plural: 'Notes', addLabel: 'Secure note', icon: 'note' },
  { id: 'identity', label: 'Identity', plural: 'Identities', addLabel: 'Identity', icon: 'user' },
  { id: 'wifi_network', label: 'Wi-Fi network', plural: 'Wi-Fi networks', addLabel: 'Wi-Fi network', icon: 'wifi' },
  { id: 'ssh_key', label: 'SSH key', plural: 'SSH keys', addLabel: 'SSH key', icon: 'key' },
  { id: 'software_license', label: 'Licence', plural: 'Licences', addLabel: 'Software licence', icon: 'license' },
  { id: 'document', label: 'Document', plural: 'Documents', addLabel: 'Document', icon: 'id-card' },
  { id: 'custom_record', label: 'Custom record', plural: 'Custom records', addLabel: 'Custom record', icon: 'custom' },
]

const KIND_META = new Map(ITEM_KINDS.map((meta) => [meta.id, meta]))

export function itemKindMeta(kind: ItemKind): ItemKindMeta {
  return KIND_META.get(kind) ?? { id: kind, label: 'Item', plural: 'Items', addLabel: 'Item', icon: 'custom' }
}

export function itemKindLabel(kind: ItemKind): string {
  return itemKindMeta(kind).label
}

export function itemKindIcon(kind: ItemKind): string {
  return itemKindMeta(kind).icon
}

export function vaultItems(snapshot: VaultSnapshot | null): VaultItem[] {
  if (!snapshot) return []
  const logins: VaultItem[] = snapshot.entries.map((entry) => ({
    id: entry.id,
    kind: 'login',
    title: entry.title,
    subtitle: entry.site,
    initials: entry.initials,
    folderId: entry.folderId,
    folder: entry.folder,
    favourite: entry.favourite,
    lastUsedAt: entry.lastUsedAt,
    updatedAt: entry.updatedAt,
    tags: entry.tags ?? [],
    securityLevel: entry.securityLevel,
    issueKinds: entry.issueKinds,
    passwordScore: entry.passwordScore,
  }))
  const records: VaultItem[] = snapshot.items.map((item) => ({
    id: item.id,
    kind: item.kind,
    title: item.title,
    subtitle: item.subtitle,
    initials: item.initials,
    folderId: item.folderId,
    folder: item.folder,
    favourite: item.favourite,
    lastUsedAt: item.lastUsedAt,
    updatedAt: item.updatedAt,
    tags: item.tags ?? [],
    issueKinds: [],
  }))
  return [...logins, ...records]
}

export function itemCounts(items: VaultItem[]): Map<ItemKind, number> {
  const counts = new Map<ItemKind, number>()
  for (const item of items) counts.set(item.kind, (counts.get(item.kind) ?? 0) + 1)
  return counts
}

export function itemTags(items: VaultItem[]): string[] {
  const seen = new Map<string, string>()
  for (const item of items) {
    for (const tag of item.tags) {
      const key = tag.toLowerCase()
      if (!seen.has(key)) seen.set(key, tag)
    }
  }
  return [...seen.values()].sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' }))
}

/** Matches on metadata the snapshot already carries; Rust searches stored fields. */
export function itemMatchesQuery(item: VaultItem, query: string): boolean {
  if (!query) return true
  return `${item.title} ${item.subtitle} ${item.folder} ${item.tags.join(' ')}`.toLowerCase().includes(query)
}
