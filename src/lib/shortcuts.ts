export interface Shortcut {
  keys: string
  label: string
}

export const SHORTCUTS: readonly Shortcut[] = [
  { keys: 'Ctrl L', label: 'Lock the vault' },
  { keys: 'Ctrl K', label: 'Search every item' },
  { keys: 'Ctrl J', label: 'Jump to the search results' },
  { keys: 'Ctrl N', label: 'Add a login' },
  { keys: 'Ctrl C', label: 'Copy the password' },
  { keys: 'Ctrl Shift C', label: 'Copy the username' },
  { keys: 'Ctrl T', label: 'Copy the one-time code' },
  { keys: 'Ctrl O', label: "Open the selected login's site" },
  { keys: 'Ctrl E', label: 'Edit the selected login' },
]
