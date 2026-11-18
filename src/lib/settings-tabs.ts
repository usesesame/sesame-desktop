export const SETTINGS_TABS = [
  { id: 'general', label: 'General', icon: 'monitor' },
  { id: 'security', label: 'Security', icon: 'lock' },
  { id: 'browser', label: 'Browser', icon: 'browser' },
  { id: 'sync', label: 'Sync', icon: 'refresh' },
  { id: 'extras', label: 'Extras', icon: 'plus' },
  { id: 'data', label: 'Data', icon: 'shield' },
] as const

export type SettingsTabId = (typeof SETTINGS_TABS)[number]['id']
