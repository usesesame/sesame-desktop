import type { Theme } from './types'
import { DEFAULT_SORT_MODE, isSortMode, type SortMode } from './vault-collections'

const KEYS = {
  theme: 'sesame-theme',
  siteIcons: 'sesame-site-icons',
  autoLock: 'sesame-auto-lock',
  clipboardClear: 'sesame-clipboard-clear',
  betaOnboarding: 'sesame-beta-onboarding-v1',
  recoveryVerified: 'sesame-recovery-verified-v1',
  keepInTray: 'sesame-keep-in-tray',
  panelWidths: 'sesame-panel-widths',
  sortMode: 'sesame-sort-mode',
  quickAccessShortcut: 'sesame-quick-access-shortcut',
  switchingChecklist: 'sesame-switching-checklist-v1',
} as const

export const DEFAULT_QUICK_ACCESS_SHORTCUT = 'Ctrl+Alt+S'

const themeOrder: Theme[] = ['auto', 'light', 'dark']
export const autoLockOptions = [1, 5, 15, 30]
const DEFAULT_AUTO_LOCK = 5
export const clipboardClearOptions = [10, 30, 60]
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* storage unavailable */
  }
}

function remove(key: string): void {
  try {
    localStorage.removeItem(key)
  } catch {
    /* storage unavailable */
  }
}

export function readTheme(): Theme | null {
  const value = read(KEYS.theme)
  return value === 'light' || value === 'dark' || value === 'auto' ? value : null
}

export function storeTheme(value: Theme): void {
  write(KEYS.theme, value)
}

export function nextTheme(current: Theme): Theme {
  return themeOrder[(themeOrder.indexOf(current) + 1) % themeOrder.length]
}

export function readSiteIcons(): boolean {
  return read(KEYS.siteIcons) === 'enabled'
}

export function storeSiteIcons(enabled: boolean): void {
  write(KEYS.siteIcons, enabled ? 'enabled' : 'disabled')
}

export function readAutoLock(): number {
  const value = Number(read(KEYS.autoLock))
  return autoLockOptions.includes(value) ? value : DEFAULT_AUTO_LOCK
}

export function storeAutoLock(minutes: number): void {
  write(KEYS.autoLock, String(minutes))
}

export function readClipboardClearSeconds(): number {
  const value = Number(read(KEYS.clipboardClear))
  return clipboardClearOptions.includes(value) ? value : DEFAULT_CLIPBOARD_CLEAR_SECONDS
}

export function storeClipboardClearSeconds(seconds: number): void {
  write(KEYS.clipboardClear, String(seconds))
}

export function readSortMode(): SortMode {
  const value = read(KEYS.sortMode)
  return isSortMode(value) ? value : DEFAULT_SORT_MODE
}

export function storeSortMode(mode: SortMode): void {
  write(KEYS.sortMode, mode)
}

export function readBetaOnboardingDismissed(): boolean {
  return read(KEYS.betaOnboarding) === 'dismissed'
}

export function storeBetaOnboardingDismissed(): void {
  write(KEYS.betaOnboarding, 'dismissed')
}

/// Survives reloads so the recovery kit cannot be skipped between sessions.
export function readRecoveryVerified(): boolean {
  return read(KEYS.recoveryVerified) === 'verified'
}

export function storeRecoveryVerified(): void {
  write(KEYS.recoveryVerified, 'verified')
}

export function resetOnboardingPreferences(): void {
  remove(KEYS.betaOnboarding)
  remove(KEYS.recoveryVerified)
}

export function readKeepInTray(): boolean {
  return read(KEYS.keepInTray) !== 'disabled'
}

export function storeKeepInTray(enabled: boolean): void {
  write(KEYS.keepInTray, enabled ? 'enabled' : 'disabled')
}

export function readQuickAccessShortcut(): string {
  return read(KEYS.quickAccessShortcut) || DEFAULT_QUICK_ACCESS_SHORTCUT
}

export function storeQuickAccessShortcut(value: string): void {
  write(KEYS.quickAccessShortcut, value)
}

export interface PanelWidths {
  list: number
  rail: number
}

export const PANEL_WIDTH_LIMITS = {
  list: { min: 220, max: 460, fallback: 300 },
  rail: { min: 200, max: 360, fallback: 236 },
} as const

function validWidth(value: unknown, limits: { min: number; max: number; fallback: number }): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= limits.min && value <= limits.max
    ? Math.round(value)
    : limits.fallback
}

export function defaultPanelWidths(): PanelWidths {
  return { list: PANEL_WIDTH_LIMITS.list.fallback, rail: PANEL_WIDTH_LIMITS.rail.fallback }
}

export function readPanelWidths(): PanelWidths {
  const raw = read(KEYS.panelWidths)
  if (!raw) return defaultPanelWidths()
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) return defaultPanelWidths()
    const record = parsed as Record<string, unknown>
    return {
      list: validWidth(record.list, PANEL_WIDTH_LIMITS.list),
      rail: validWidth(record.rail, PANEL_WIDTH_LIMITS.rail),
    }
  } catch {
    return defaultPanelWidths()
  }
}

export function storePanelWidths(widths: PanelWidths): void {
  write(KEYS.panelWidths, JSON.stringify({
    list: validWidth(widths.list, PANEL_WIDTH_LIMITS.list),
    rail: validWidth(widths.rail, PANEL_WIDTH_LIMITS.rail),
  }))
}

export interface SwitchingChecklist {
  regularSites: boolean
  recoveryDetails: boolean
  browserFill: boolean
  dualRun: boolean
}

const emptySwitchingChecklist = (): SwitchingChecklist => ({
  regularSites: false,
  recoveryDetails: false,
  browserFill: false,
  dualRun: false,
})

// The dual-run period runs for two weeks, so these ticks outlive the guide that sets them.
export function readSwitchingChecklist(): SwitchingChecklist {
  const raw = read(KEYS.switchingChecklist)
  if (!raw) return emptySwitchingChecklist()
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) return emptySwitchingChecklist()
    const record = parsed as Record<string, unknown>
    return {
      regularSites: record.regularSites === true,
      recoveryDetails: record.recoveryDetails === true,
      browserFill: record.browserFill === true,
      dualRun: record.dualRun === true,
    }
  } catch {
    return emptySwitchingChecklist()
  }
}

export function storeSwitchingChecklist(checklist: SwitchingChecklist): void {
  write(KEYS.switchingChecklist, JSON.stringify(checklist))
}
