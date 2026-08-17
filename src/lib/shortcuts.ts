export interface Shortcut {
  keys: string
  label: string
}

export const SHORTCUTS: readonly Shortcut[] = [
  { keys: 'Ctrl L', label: 'Lock the vault' },
  { keys: 'Ctrl N', label: 'Add a login' },
  { keys: 'Ctrl C', label: 'Copy the password' },
  { keys: 'Ctrl Shift C', label: 'Copy the username' },
  { keys: 'Ctrl E', label: 'Edit the selected login' },
]
