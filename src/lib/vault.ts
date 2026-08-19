import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { open, save } from '@tauri-apps/plugin-dialog'
import type { BackupInspection, BackupSelection, BackupVerification, BreachCheckResult, BrowserFillCancelled, BrowserFillRequest, BrowserIdentityFillCancelled, BrowserIdentityFillRequest, BrowserIntegrationStatus, BrowserSaveCancelled, BrowserSaveRequest, Card, CardInput, ChangeMasterPasswordResult, CustomRecord, CustomRecordInput, DeleteCardResult, DeleteCustomRecordResult, DeleteDocumentMetadataResult, DeleteIdentityResult, DeleteLoginResult, DeleteSecureNoteResult, DeleteSoftwareLicenseResult, DeleteSshKeyResult, DeleteWifiNetworkResult, DesktopUpdateProgress, DiagnosticStatus, DocumentMetadata, DocumentMetadataInput, DuplicateGroup, Identity, IdentityInput, ImportPreviewResult, ImportResult, ImportSource, ItemPreview, LoginCard, LoginInput, LoginSummary, MasterPasswordRequest, MergeChoices, MergeComparison, MergeDuplicateLoginsResult, PasswordAnalysis, QuickAccessEntry, QuickAccessSecret, QuickAccessStatus, RecoveryHealth, RestoreBackupResult, RestoreHistoryVersionResult, RestoreTrashedItemResult, SaveCardResult, SaveCustomRecordResult, SaveDocumentMetadataResult, SaveIdentityResult, SaveLoginResult, SaveSecureNoteResult, SaveSoftwareLicenseResult, SaveSshKeyResult, SaveWifiNetworkResult, SecureNote, SecureNoteInput, ServiceConnectionStatus, SoftwareLicense, SoftwareLicenseInput, SshKey, SshKeyInput, TotpRefresh, VaultEntry, VaultSetup, VaultSnapshot, VaultStatus, WebsiteIconCacheStatus, WifiNetwork, WifiNetworkInput } from './types'

const hasTauriInternals = typeof window !== 'undefined' && Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
export const previewMode = !hasTauriInternals

/// Wraps Rust's plain-string errors, which are hand-authored and never carry a path or secret.
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await tauriInvoke<T>(cmd, args)
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error))
  }
}

let previewUnlocked = false
let previewPinUnlockAvailable = false
let previewHelloUnlockAvailable = false
let clipboardEpoch = 0
let clipboardClearMs = 30_000

/// Applies from the next copy onward; does not reschedule a clear already in flight.
export function setClipboardClearSeconds(seconds: number): void {
  clipboardClearMs = Math.max(1, seconds) * 1_000
}

export async function onVaultLocked(handler: () => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen('vault-locked', handler)
}

/// Idle lock about to fire; only real input dismisses the warning.
export async function onIdleWarning(handler: (secondsLeft: number) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<number>('vault-idle-warning', ({ payload }) => handler(payload))
}

export async function onIdleWarningCleared(handler: () => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen('vault-idle-warning-cleared', handler)
}

export async function onDesktopUpdateProgress(handler: (progress: DesktopUpdateProgress) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<DesktopUpdateProgress>('desktop-update-progress', ({ payload }) => handler(payload))
}

async function onBrowserFillRequest(handler: (payload: BrowserFillRequest) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserFillRequest>('browser-fill-request', ({ payload }) => handler(payload))
}

async function onBrowserFillCancelled(handler: (payload: BrowserFillCancelled) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserFillCancelled>('browser-fill-cancelled', ({ payload }) => handler(payload))
}

export async function subscribeBrowserFill(handlers: {
  request: (payload: BrowserFillRequest) => void
  cancelled: (payload: BrowserFillCancelled) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  const [stopRequests, stopCancellations] = await Promise.all([
    onBrowserFillRequest(handlers.request),
    onBrowserFillCancelled(handlers.cancelled),
  ])
  return () => {
    stopRequests()
    stopCancellations()
  }
}

async function onBrowserIdentityFillRequest(handler: (payload: BrowserIdentityFillRequest) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserIdentityFillRequest>('browser-identity-request', ({ payload }) => handler(payload))
}

async function onBrowserIdentityFillCancelled(handler: (payload: BrowserIdentityFillCancelled) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserIdentityFillCancelled>('browser-identity-cancelled', ({ payload }) => handler(payload))
}

export async function subscribeBrowserIdentityFill(handlers: {
  request: (payload: BrowserIdentityFillRequest) => void
  cancelled: (payload: BrowserIdentityFillCancelled) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  const [stopRequests, stopCancellations] = await Promise.all([
    onBrowserIdentityFillRequest(handlers.request),
    onBrowserIdentityFillCancelled(handlers.cancelled),
  ])
  return () => {
    stopRequests()
    stopCancellations()
  }
}

async function onBrowserSaveRequest(handler: (payload: BrowserSaveRequest) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserSaveRequest>('browser-save-request', ({ payload }) => handler(payload))
}

async function onBrowserSaveCancelled(handler: (payload: BrowserSaveCancelled) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserSaveCancelled>('browser-save-cancelled', ({ payload }) => handler(payload))
}

export async function subscribeBrowserSave(handlers: {
  request: (payload: BrowserSaveRequest) => void
  cancelled: (payload: BrowserSaveCancelled) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  const [stopRequests, stopCancellations] = await Promise.all([
    onBrowserSaveRequest(handlers.request),
    onBrowserSaveCancelled(handlers.cancelled),
  ])
  return () => {
    stopRequests()
    stopCancellations()
  }
}

const previewSnapshot: VaultSnapshot = {
  vaultName: 'Preview vault',
  vaultId: 'preview-vault',
  revision: 1,
  folders: [{ id: 'personal', name: 'Personal' }, { id: 'work', name: 'Work' }],
  entries: [
    { id: 'gmail', title: 'Gmail', site: 'mail.google.com', initials: 'G', folderId: 'personal', folder: 'Personal', favourite: true, lastUsedAt: 1_784_025_600, passwordScore: 4, passwordIssues: [], securityLevel: 'good', issueKinds: [] },
    { id: 'github', title: 'GitHub', site: 'github.com', initials: 'GH', folderId: 'work', folder: 'Work', favourite: false, passwordScore: 4, passwordIssues: [], securityLevel: 'needs-work', issueKinds: ['totp', 'recovery'] },
    { id: 'notion', title: 'Notion', site: 'notion.so', initials: 'N', folderId: 'work', folder: 'Work', favourite: false, passwordScore: 2, passwordIssues: [{ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' }], securityLevel: 'needs-work', issueKinds: ['weak-password'] },
  ],
  identities: [],
  secureNotes: [],
  cards: [],
  wifiNetworks: [],
  sshKeys: [],
  softwareLicenses: [],
  documents: [],
  customRecords: [],
  trash: [],
  history: [],
  security: { good: 1, needsAttention: 3, duplicateCandidates: 0, weakOrReused: 1, weakPasswords: 1, commonPasswords: 0, reusedPasswords: 0, compromisedPatterns: 0, oldPasswords: 0, missingUrls: 0, noTotp: 2, missingRecovery: 1 },
}

const previewTrashRecords: Record<string, { kind: string; title: string; record: unknown }> = {}

function trashPreviewItem(kind: string, id: string, title: string, record: unknown) {
  previewTrashRecords[id] = { kind, title, record }
  previewSnapshot.trash.push({ id, kind, deletedAt: Math.floor(Date.now() / 1000) })
}

const previewHistoryRecords: Record<string, { kind: string; title: string; itemId: string; record: unknown }> = {}

function captureHistoryPreview(kind: string, itemId: string, title: string, record: unknown) {
  const historyId = `preview-history-${crypto.randomUUID()}`
  previewHistoryRecords[historyId] = { kind, title, itemId, record }
  previewSnapshot.history.push({ id: historyId, itemId, kind, capturedAt: Math.floor(Date.now() / 1000) })
}

const previewIdentities: Record<string, Identity> = {}
const previewSecureNotes: Record<string, SecureNote> = {}
const previewPaymentCards: Record<string, Card> = {}
const previewWifiNetworks: Record<string, WifiNetwork> = {}
const previewSshKeys: Record<string, SshKey> = {}
const previewSoftwareLicenses: Record<string, SoftwareLicense> = {}
const previewDocuments: Record<string, DocumentMetadata> = {}
const previewCustomRecords: Record<string, CustomRecord> = {}

const previewCards: Record<string, LoginCard> = {
  gmail: {
    id: 'gmail', title: 'Gmail', site: 'mail.google.com', initials: 'G', url: 'https://mail.google.com', username: 'hello@example.test', email: '', password: 'preview-only-not-a-real-password', folderId: 'personal', folder: 'Personal', favourite: true, lastUsedAt: 1_784_025_600, totpCode: '482 914', totpRemaining: 19, backupCodes: ['J8CJ-5TKJ', 'KD8Q-3NZP', 'HF9M-7QNR'], recoveryEmail: 'recovery@example.test', recoveryPhone: '+370 •••• 1298', recoveryNotApplicable: false, notes: 'Personal email. Keep backup codes current.',
  },
  github: { id: 'github', title: 'GitHub', site: 'github.com', initials: 'GH', url: 'https://github.com', username: 'sesame-preview', email: '', password: 'preview-only-not-a-real-password', folderId: 'work', folder: 'Work', favourite: false, recoveryNotApplicable: false, notes: 'Add a TOTP code and recovery details.' },
  notion: { id: 'notion', title: 'Notion', site: 'notion.so', initials: 'N', url: 'https://notion.so', username: 'hello@example.test', email: 'hello@example.test', password: 'preview-only-not-a-real-password', folderId: 'work', folder: 'Work', favourite: false, recoveryNotApplicable: true },
}

export async function getVaultStatus(): Promise<VaultStatus> {
  if (previewMode) return { exists: false, unlocked: previewUnlocked, preview: true, pinUnlockAvailable: previewPinUnlockAvailable, helloUnlockAvailable: previewHelloUnlockAvailable, onboardingRequired: false, revision: 1 }
  return invoke<VaultStatus>('get_vault_status')
}

export async function resumeRecoverySetup(): Promise<string> {
  if (previewMode) return 'F9K4P-7XQ2M-T6V8C-H3R5W-J8L2N'
  return invoke<string>('resume_recovery_setup')
}

export async function completeRecoverySetup(recoveryKit: string): Promise<void> {
  if (previewMode) return
  await invoke('complete_recovery_setup', { request: { recoveryKit } })
}

export async function createVault(request: MasterPasswordRequest): Promise<VaultSetup> {
  if (previewMode) {
    previewUnlocked = true
    return { snapshot: previewSnapshot, recoveryKit: 'F9K4P-7XQ2M-T6V8C-H3R5W-J8L2N' }
  }
  return invoke<VaultSetup>('create_vault', { request })
}

export async function unlockVault(request: MasterPasswordRequest, alreadyUnlocked = false): Promise<VaultSnapshot> {
  if (previewMode) {
    previewUnlocked = true
    return previewSnapshot
  }
  return invoke<VaultSnapshot>(alreadyUnlocked ? 'get_vault_snapshot' : 'unlock_vault', alreadyUnlocked ? undefined : { request })
}

export async function changeMasterPassword(currentPassword: string, newPassword: string): Promise<ChangeMasterPasswordResult> {
  if (previewMode) return { recoveryKit: 'F9K4P-7XQ2M-T6V8C-H3R5W-J8L2N' }
  return invoke<ChangeMasterPasswordResult>('change_master_password', { request: { currentPassword, newPassword } })
}

export async function setNativeAutoLockMinutes(minutes: number): Promise<void> {
  if (previewMode) return
  await invoke('set_auto_lock_minutes', { minutes })
}

export async function unlockWithRecovery(recoveryKit: string): Promise<VaultSnapshot> {
  if (previewMode) {
    previewUnlocked = true
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('unlock_recovery_vault', { request: { recoveryKit } })
}

export async function setUnlockPin(pin: string): Promise<void> {
  if (previewMode) {
    previewPinUnlockAvailable = true
    return
  }
  await invoke('set_unlock_pin', { request: { pin } })
}

export async function removeUnlockPin(): Promise<void> {
  if (previewMode) {
    previewPinUnlockAvailable = false
    return
  }
  await invoke('remove_unlock_pin')
}

export async function unlockWithPin(pin: string): Promise<VaultSnapshot> {
  if (previewMode) {
    previewUnlocked = true
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('unlock_pin_vault', { request: { pin } })
}

export async function enableWindowsHello(): Promise<void> {
  if (previewMode) {
    previewHelloUnlockAvailable = true
    return
  }
  await invoke('enable_windows_hello')
}

export async function disableWindowsHello(): Promise<void> {
  if (previewMode) {
    previewHelloUnlockAvailable = false
    return
  }
  await invoke('disable_windows_hello')
}

export async function unlockWithWindowsHello(): Promise<VaultSnapshot> {
  if (previewMode) {
    previewUnlocked = true
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('unlock_with_windows_hello')
}

export async function setTrayEnabled(enabled: boolean): Promise<void> {
  if (previewMode) return
  await invoke('set_tray_enabled', { enabled })
}

export async function setQuickAccessShortcut(shortcut: string): Promise<void> {
  if (previewMode) return
  await invoke('set_quick_access_shortcut', { shortcut })
}

export async function getAutostartEnabled(): Promise<boolean> {
  if (previewMode) return false
  return invoke<boolean>('get_autostart_enabled')
}

export async function setAutostartEnabled(enabled: boolean): Promise<void> {
  if (previewMode) return
  await invoke('set_autostart_enabled', { enabled })
}

export async function lockVault(): Promise<void> {
  if (previewMode) {
    previewUnlocked = false
    return
  }
  await invoke('lock_vault')
}

export async function getLoginCard(id: string): Promise<LoginCard> {
  if (previewMode) return previewCards[id]
  return invoke<LoginCard>('get_login_card', { id })
}

export async function getQuickAccessStatus(): Promise<QuickAccessStatus> {
  if (previewMode) return { exists: true, unlocked: true }
  return invoke<QuickAccessStatus>('get_quick_access_status')
}

export async function searchQuickAccessEntries(query: string): Promise<QuickAccessEntry[]> {
  if (previewMode) {
    const needle = query.trim().toLowerCase()
    return previewSnapshot.entries
      .filter((entry) => !needle || `${entry.title} ${entry.site}`.toLowerCase().includes(needle))
      .slice(0, 6)
      .map((entry) => ({
        id: entry.id,
        title: entry.title,
        site: entry.site,
        initials: entry.initials,
        hasTotp: Boolean(previewCards[entry.id]?.totpCode),
      }))
  }
  return invoke<QuickAccessEntry[]>('search_quick_access_entries', { query })
}

export async function getQuickAccessSecret(id: string): Promise<QuickAccessSecret> {
  if (previewMode) {
    const card = previewCards[id]
    return { password: card?.password ?? '', totpCode: card?.totpCode }
  }
  return invoke<QuickAccessSecret>('get_quick_access_secret', { id })
}

/// Matched in Rust; usernames never ship into the webview for one filter.
export async function searchEntries(query: string): Promise<string[]> {
  if (previewMode) return []
  return invoke<string[]>('search_entries', { query })
}

/// Bounded disclosure: a short list crosses on focus, never every stored address.
export async function suggestFieldValues(field: 'username' | 'email'): Promise<string[]> {
  if (previewMode) {
    const values = Object.values(previewCards).map((card) => card[field])
      .concat(field === 'email' ? Object.values(previewIdentities).map((identity) => identity.email) : [])
    return [...new Set(values.map((value) => value.trim()).filter(Boolean))].slice(0, 8)
  }
  return invoke<string[]>('suggest_field_values', { field })
}

function previewPasswordAnalysis(password: string): PasswordAnalysis {
  if (!password) return { score: 0, issues: [{ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' }] }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length
  const length = password.length
  let score = length >= 16 ? 3 : length >= 12 ? 2 : length >= 8 ? 1 : 0
  if (length >= 12 && classes >= 3) score = Math.min(4, score + 1)
  const issues: PasswordAnalysis['issues'] = []
  if (score < 3) issues.push({ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' })
  return { score, issues }
}

export async function checkPasswordStrength(password: string): Promise<PasswordAnalysis> {
  if (previewMode) return previewPasswordAnalysis(password)
  return invoke<PasswordAnalysis>('check_password_strength', { password })
}

// Sends only a 5-character hash prefix (k-anonymity); the full hash never leaves this function.
export async function checkPasswordBreach(password: string): Promise<BreachCheckResult> {
  if (previewMode) {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))
    const hex = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('')
    const prefix = hex.slice(0, 5)
    const suffix = hex.slice(5)
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } })
    if (!response.ok) throw new Error('Sesame could not reach the breach-check service. Try again.')
    const body = await response.text()
    const match = body.split('\n').map((line) => line.trim().split(':')).find(([candidate]) => candidate === suffix)
    const count = match ? Number(match[1]) || 0 : 0
    return { breached: count > 0, count }
  }
  return invoke<BreachCheckResult>('check_password_breach', { password })
}

// Purely local keyboard synthesis, no network. Callers give the target window focus first.
export async function autoType(id: string): Promise<void> {
  if (previewMode) throw new Error('Auto-type is not available in the browser preview. Use the installed Windows app.')
  return invoke('auto_type', { id })
}

export async function getLoginSummary(id: string): Promise<LoginSummary> {
  if (previewMode) {
    const card = previewCards[id]
    const normalizedSite = card.site.trim().toLowerCase().replace(/^www\./, '')
    return { id: card.id, title: card.title, site: card.site, username: card.username, initials: card.initials, duplicateKey: `${normalizedSite}:${card.username.trim().toLowerCase()}` }
  }
  return invoke<LoginSummary>('get_login_summary', { id })
}

export async function getDuplicateGroups(): Promise<DuplicateGroup[]> {
  if (previewMode) return []
  return invoke<DuplicateGroup[]>('get_duplicate_groups')
}

export async function refreshTotp(id: string): Promise<TotpRefresh> {
  if (previewMode) {
    const card = previewCards[id]
    return { totpCode: card.totpCode ?? null, totpRemaining: card.totpRemaining ?? null }
  }
  return invoke<TotpRefresh>('refresh_totp', { id })
}

// The export is parsed and held in Rust; its contents never enter the webview.
export async function chooseImportFile(source: ImportSource): Promise<string | null> {
  if (previewMode) return 'preview-export.csv'
  const chosen = await open({
    multiple: false,
    directory: false,
    filters: [source === 'bitwarden-json'
      ? { name: 'JSON export', extensions: ['json'] }
      : { name: 'CSV export', extensions: ['csv'] }],
  })
  return typeof chosen === 'string' ? chosen : null
}

const emptyFidelityCounts = { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 }

export async function previewImportFile(path: string, source: ImportSource): Promise<ImportPreviewResult> {
  if (previewMode) {
    return {
      importId: 'preview-import',
      preview: {
        totalEntries: 3, exactDuplicates: 0, accountConflicts: 1, duplicateEntries: 0, missingUrls: 0, invalidUrls: 0, noTotp: 2, invalidTotp: 1, preservedLegacyFields: 0, secureNotes: 0, cards: 0, identities: 0, sshKeys: 1, passkeysNotImported: 2, intentionallyOmittedItems: 0,
        fidelity: { logins: { ...emptyFidelityCounts, imported: 3 }, secureNotes: { ...emptyFidelityCounts }, cards: { ...emptyFidelityCounts }, identities: { ...emptyFidelityCounts }, sshKeys: { ...emptyFidelityCounts, imported: 2 }, passkeys: { ...emptyFidelityCounts, intentionallyOmitted: 2 }, unsupportedItems: { ...emptyFidelityCounts } },
      },
    }
  }
  return invoke<ImportPreviewResult>('preview_import', { path, source })
}

export async function commitImport(importId: string, skipExactDuplicates: boolean): Promise<ImportResult> {
  if (previewMode) return { snapshot: previewSnapshot, importedEntries: 3, importedSecureNotes: 0, importedCards: 0, importedIdentities: 0, importedSshKeys: 1, skippedExactDuplicates: 0 }
  return invoke<ImportResult>('commit_import', { importId, skipExactDuplicates })
}

export async function cancelImport(): Promise<void> {
  if (previewMode) return
  await invoke('cancel_import')
}

export async function saveLogin(input: LoginInput): Promise<SaveLoginResult> {
  if (previewMode) {
    const id = input.id || `preview-${crypto.randomUUID()}`
    const title = input.title.trim()
    const site = previewSite(input.url)
    const initials = previewInitials(title)
    const card: LoginCard = {
      id,
      title,
      site,
      initials,
      url: previewUrl(input.url),
      username: input.username.trim(),
      email: input.email.trim(),
      password: input.password,
      folderId: input.folderId,
      folder: input.folder.trim(),
      favourite: previewCards[id]?.favourite ?? false,
      backupCodes: input.backupCodes.filter(Boolean),
      recoveryEmail: input.recoveryEmail.trim() || undefined,
      recoveryPhone: input.recoveryPhone.trim() || undefined,
      recoveryNotApplicable: input.recoveryNotApplicable,
      notes: input.notes.trim() || undefined,
    }
    if (input.id && previewCards[id]) captureHistoryPreview('login', id, previewCards[id].title, previewCards[id])
    previewCards[id] = card
    const entry: VaultEntry = { id, title, site, initials, folderId: card.folderId, folder: card.folder, favourite: card.favourite, passwordScore: 2, passwordIssues: [{ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' }], securityLevel: 'needs-work', issueKinds: ['weak-password', 'totp', 'recovery'] }
    const existing = previewSnapshot.entries.findIndex((saved) => saved.id === id)
    if (existing >= 0) previewSnapshot.entries[existing] = entry
    else previewSnapshot.entries.push(entry)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveLoginResult>('save_login', { input })
}

export async function setLoginFolders(ids: string[], folder: string): Promise<VaultSnapshot> {
  const normalizedFolder = folder.trim()
  if (previewMode) {
    for (const id of ids) {
      const entry = previewSnapshot.entries.find((saved) => saved.id === id)
      const card = previewCards[id]
      if (entry) entry.folder = normalizedFolder
      if (card) card.folder = normalizedFolder
    }
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('set_login_folders', { ids, folder: normalizedFolder })
}

export async function bulkAssignFolder(ids: string[], folderId?: string): Promise<VaultSnapshot> {
  if (previewMode) {
    const folder = previewSnapshot.folders.find((candidate) => candidate.id === folderId)
    for (const id of ids) {
      const entry = previewSnapshot.entries.find((saved) => saved.id === id)
      const card = previewCards[id]
      if (entry) { entry.folderId = folder?.id; entry.folder = folder?.name ?? '' }
      if (card) { card.folderId = folder?.id; card.folder = folder?.name ?? '' }
    }
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('bulk_assign_folder', { ids, folderId: folderId || null })
}

export async function createFolder(name: string): Promise<VaultSnapshot> {
  if (previewMode) {
    previewSnapshot.folders.push({ id: crypto.randomUUID(), name: name.trim() })
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('create_folder', { name })
}

export async function renameFolder(folderId: string, name: string): Promise<VaultSnapshot> {
  if (previewMode) {
    const folder = previewSnapshot.folders.find((candidate) => candidate.id === folderId)
    if (folder) folder.name = name.trim()
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('rename_folder', { folderId, name })
}

export async function deleteFolder(folderId: string): Promise<VaultSnapshot> {
  if (previewMode) {
    previewSnapshot.folders = previewSnapshot.folders.filter((folder) => folder.id !== folderId)
    return bulkAssignFolder(previewSnapshot.entries.filter((entry) => entry.folderId === folderId).map((entry) => entry.id))
  }
  return invoke<VaultSnapshot>('delete_folder', { folderId })
}

export async function setLoginFavourite(id: string, favourite: boolean): Promise<VaultSnapshot> {
  if (previewMode) {
    const entry = previewSnapshot.entries.find((saved) => saved.id === id)
    if (entry) entry.favourite = favourite
    if (previewCards[id]) previewCards[id].favourite = favourite
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('set_login_favourite', { id, favourite })
}

export async function recordLoginUse(id: string): Promise<VaultSnapshot> {
  if (previewMode) {
    const lastUsedAt = Math.floor(Date.now() / 1000)
    const entry = previewSnapshot.entries.find((saved) => saved.id === id)
    if (entry) entry.lastUsedAt = lastUsedAt
    if (previewCards[id]) previewCards[id].lastUsedAt = lastUsedAt
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('record_login_use', { id })
}

export async function deleteLogin(id: string): Promise<DeleteLoginResult> {
  if (previewMode) {
    const entryIndex = previewSnapshot.entries.findIndex((entry) => entry.id === id)
    if (entryIndex < 0) throw new Error('That saved login no longer exists.')
    const [removed] = previewSnapshot.entries.splice(entryIndex, 1)
    trashPreviewItem('login', id, removed.title, previewCards[id] ?? removed)
    delete previewCards[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteLoginResult>('delete_login', { id })
}

export async function getIdentity(id: string): Promise<Identity> {
  if (previewMode) {
    const identity = previewIdentities[id]
    if (!identity) throw new Error('That saved identity no longer exists.')
    return identity
  }
  return invoke<Identity>('get_identity', { id })
}

export async function saveIdentity(input: IdentityInput): Promise<SaveIdentityResult> {
  if (previewMode) {
    const id = input.id || `preview-identity-${crypto.randomUUID()}`
    const identity: Identity = { ...input, id, label: input.label.trim() }
    if (input.id && previewIdentities[id]) captureHistoryPreview('identity', id, previewIdentities[id].label, previewIdentities[id])
    previewIdentities[id] = identity
    const existing = previewSnapshot.identities.find((summary) => summary.id === id)
    if (existing) existing.label = identity.label
    else previewSnapshot.identities.push({ id, label: identity.label })
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveIdentityResult>('save_identity', { input })
}

export async function deleteIdentity(id: string): Promise<DeleteIdentityResult> {
  if (previewMode) {
    const index = previewSnapshot.identities.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved identity no longer exists.')
    previewSnapshot.identities.splice(index, 1)
    if (previewIdentities[id]) trashPreviewItem('identity', id, previewIdentities[id].label, previewIdentities[id])
    delete previewIdentities[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteIdentityResult>('delete_identity', { id })
}

export async function getSecureNote(id: string): Promise<SecureNote> {
  if (previewMode) {
    const note = previewSecureNotes[id]
    if (!note) throw new Error('That saved note no longer exists.')
    return note
  }
  return invoke<SecureNote>('get_secure_note', { id })
}

export async function saveSecureNote(input: SecureNoteInput): Promise<SaveSecureNoteResult> {
  if (previewMode) {
    const id = input.id || `preview-note-${crypto.randomUUID()}`
    const note: SecureNote = { ...input, id, title: input.title.trim() }
    if (input.id && previewSecureNotes[id]) captureHistoryPreview('secure_note', id, previewSecureNotes[id].title, previewSecureNotes[id])
    previewSecureNotes[id] = note
    const summary = { id, title: note.title, updatedAt: Date.now() / 1000 }
    const existing = previewSnapshot.secureNotes.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.secureNotes.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveSecureNoteResult>('save_secure_note', { input })
}

export async function deleteSecureNote(id: string): Promise<DeleteSecureNoteResult> {
  if (previewMode) {
    const index = previewSnapshot.secureNotes.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved note no longer exists.')
    previewSnapshot.secureNotes.splice(index, 1)
    if (previewSecureNotes[id]) trashPreviewItem('secure_note', id, previewSecureNotes[id].title, previewSecureNotes[id])
    delete previewSecureNotes[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteSecureNoteResult>('delete_secure_note', { id })
}

export async function getCard(id: string): Promise<Card> {
  if (previewMode) {
    const card = previewPaymentCards[id]
    if (!card) throw new Error('That saved card no longer exists.')
    return card
  }
  return invoke<Card>('get_card', { id })
}

export async function saveCard(input: CardInput): Promise<SaveCardResult> {
  if (previewMode) {
    const id = input.id || `preview-card-${crypto.randomUUID()}`
    const card: Card = { ...input, id, title: input.title.trim() }
    if (input.id && previewPaymentCards[id]) captureHistoryPreview('card', id, previewPaymentCards[id].title, previewPaymentCards[id])
    previewPaymentCards[id] = card
    const summary = { id, title: card.title }
    const existing = previewSnapshot.cards.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.cards.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveCardResult>('save_card', { input })
}

export async function deleteCard(id: string): Promise<DeleteCardResult> {
  if (previewMode) {
    const index = previewSnapshot.cards.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved card no longer exists.')
    previewSnapshot.cards.splice(index, 1)
    if (previewPaymentCards[id]) trashPreviewItem('card', id, previewPaymentCards[id].title, previewPaymentCards[id])
    delete previewPaymentCards[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteCardResult>('delete_card', { id })
}

export async function getWifiNetwork(id: string): Promise<WifiNetwork> {
  if (previewMode) {
    const network = previewWifiNetworks[id]
    if (!network) throw new Error('That saved network no longer exists.')
    return network
  }
  return invoke<WifiNetwork>('get_wifi_network', { id })
}

export async function saveWifiNetwork(input: WifiNetworkInput): Promise<SaveWifiNetworkResult> {
  if (previewMode) {
    const id = input.id || `preview-wifi-${crypto.randomUUID()}`
    const network: WifiNetwork = { ...input, id, title: input.title.trim() }
    if (input.id && previewWifiNetworks[id]) captureHistoryPreview('wifi_network', id, previewWifiNetworks[id].title, previewWifiNetworks[id])
    previewWifiNetworks[id] = network
    const summary = { id, title: network.title }
    const existing = previewSnapshot.wifiNetworks.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.wifiNetworks.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveWifiNetworkResult>('save_wifi_network', { input })
}

export async function deleteWifiNetwork(id: string): Promise<DeleteWifiNetworkResult> {
  if (previewMode) {
    const index = previewSnapshot.wifiNetworks.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved network no longer exists.')
    previewSnapshot.wifiNetworks.splice(index, 1)
    if (previewWifiNetworks[id]) trashPreviewItem('wifi_network', id, previewWifiNetworks[id].title, previewWifiNetworks[id])
    delete previewWifiNetworks[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteWifiNetworkResult>('delete_wifi_network', { id })
}

export async function getSshKey(id: string): Promise<SshKey> {
  if (previewMode) {
    const key = previewSshKeys[id]
    if (!key) throw new Error('That saved key no longer exists.')
    return key
  }
  return invoke<SshKey>('get_ssh_key', { id })
}

export async function saveSshKey(input: SshKeyInput): Promise<SaveSshKeyResult> {
  if (previewMode) {
    const id = input.id || `preview-ssh-key-${crypto.randomUUID()}`
    const key: SshKey = { ...input, id, title: input.title.trim() }
    if (input.id && previewSshKeys[id]) captureHistoryPreview('ssh_key', id, previewSshKeys[id].title, previewSshKeys[id])
    previewSshKeys[id] = key
    const summary = { id, title: key.title }
    const existing = previewSnapshot.sshKeys.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.sshKeys.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveSshKeyResult>('save_ssh_key', { input })
}

export async function deleteSshKey(id: string): Promise<DeleteSshKeyResult> {
  if (previewMode) {
    const index = previewSnapshot.sshKeys.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved key no longer exists.')
    previewSnapshot.sshKeys.splice(index, 1)
    if (previewSshKeys[id]) trashPreviewItem('ssh_key', id, previewSshKeys[id].title, previewSshKeys[id])
    delete previewSshKeys[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteSshKeyResult>('delete_ssh_key', { id })
}

export async function getSoftwareLicense(id: string): Promise<SoftwareLicense> {
  if (previewMode) {
    const license = previewSoftwareLicenses[id]
    if (!license) throw new Error('That saved licence no longer exists.')
    return license
  }
  return invoke<SoftwareLicense>('get_software_license', { id })
}

export async function saveSoftwareLicense(input: SoftwareLicenseInput): Promise<SaveSoftwareLicenseResult> {
  if (previewMode) {
    const id = input.id || `preview-license-${crypto.randomUUID()}`
    const license: SoftwareLicense = { ...input, id, title: input.title.trim() }
    if (input.id && previewSoftwareLicenses[id]) captureHistoryPreview('software_license', id, previewSoftwareLicenses[id].title, previewSoftwareLicenses[id])
    previewSoftwareLicenses[id] = license
    const summary = { id, title: license.title }
    const existing = previewSnapshot.softwareLicenses.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.softwareLicenses.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveSoftwareLicenseResult>('save_software_license', { input })
}

export async function deleteSoftwareLicense(id: string): Promise<DeleteSoftwareLicenseResult> {
  if (previewMode) {
    const index = previewSnapshot.softwareLicenses.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved licence no longer exists.')
    previewSnapshot.softwareLicenses.splice(index, 1)
    if (previewSoftwareLicenses[id]) trashPreviewItem('software_license', id, previewSoftwareLicenses[id].title, previewSoftwareLicenses[id])
    delete previewSoftwareLicenses[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteSoftwareLicenseResult>('delete_software_license', { id })
}

export async function getDocument(id: string): Promise<DocumentMetadata> {
  if (previewMode) {
    const document = previewDocuments[id]
    if (!document) throw new Error('That saved document no longer exists.')
    return document
  }
  return invoke<DocumentMetadata>('get_document', { id })
}

export async function saveDocument(input: DocumentMetadataInput): Promise<SaveDocumentMetadataResult> {
  if (previewMode) {
    const id = input.id || `preview-document-${crypto.randomUUID()}`
    const attachments = previewDocuments[id]?.attachments ?? []
    const document: DocumentMetadata = { ...input, id, title: input.title.trim(), attachments }
    if (input.id && previewDocuments[id]) captureHistoryPreview('document', id, previewDocuments[id].title, previewDocuments[id])
    previewDocuments[id] = document
    const summary = { id, title: document.title, attachmentCount: attachments.length }
    const existing = previewSnapshot.documents.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.documents.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveDocumentMetadataResult>('save_document', { input })
}

const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
const MAX_ATTACHMENTS_PER_DOCUMENT = 5

export async function addDocumentAttachment(
  documentId: string,
  filename: string,
  contentType: string,
  data: string,
): Promise<SaveDocumentMetadataResult> {
  if (previewMode) {
    const document = previewDocuments[documentId]
    if (!document) throw new Error('That saved document no longer exists.')
    if (!filename.trim()) throw new Error('Name this attachment before adding it.')
    if (document.attachments.length >= MAX_ATTACHMENTS_PER_DOCUMENT) {
      throw new Error(`A document can hold up to ${MAX_ATTACHMENTS_PER_DOCUMENT} attachments.`)
    }
    const size = Math.floor((data.length * 3) / 4)
    if (size > MAX_ATTACHMENT_BYTES) {
      throw new Error(`Attachments are limited to ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB.`)
    }
    document.attachments.push({ id: `preview-attachment-${crypto.randomUUID()}`, filename: filename.trim(), contentType, size, data })
    const summary = previewSnapshot.documents.find((entry) => entry.id === documentId)
    if (summary) summary.attachmentCount = document.attachments.length
    return { id: documentId, snapshot: previewSnapshot }
  }
  return invoke<SaveDocumentMetadataResult>('add_document_attachment', { documentId, filename, contentType, data })
}

export async function removeDocumentAttachment(documentId: string, attachmentId: string): Promise<SaveDocumentMetadataResult> {
  if (previewMode) {
    const document = previewDocuments[documentId]
    if (!document) throw new Error('That saved document no longer exists.')
    const before = document.attachments.length
    document.attachments = document.attachments.filter((attachment) => attachment.id !== attachmentId)
    if (document.attachments.length === before) throw new Error('That attachment no longer exists.')
    const summary = previewSnapshot.documents.find((entry) => entry.id === documentId)
    if (summary) summary.attachmentCount = document.attachments.length
    return { id: documentId, snapshot: previewSnapshot }
  }
  return invoke<SaveDocumentMetadataResult>('remove_document_attachment', { documentId, attachmentId })
}

export async function deleteDocument(id: string): Promise<DeleteDocumentMetadataResult> {
  if (previewMode) {
    const index = previewSnapshot.documents.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved document no longer exists.')
    previewSnapshot.documents.splice(index, 1)
    if (previewDocuments[id]) trashPreviewItem('document', id, previewDocuments[id].title, previewDocuments[id])
    delete previewDocuments[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteDocumentMetadataResult>('delete_document', { id })
}

export async function getCustomRecord(id: string): Promise<CustomRecord> {
  if (previewMode) {
    const record = previewCustomRecords[id]
    if (!record) throw new Error('That saved record no longer exists.')
    return record
  }
  return invoke<CustomRecord>('get_custom_record', { id })
}

export async function saveCustomRecord(input: CustomRecordInput): Promise<SaveCustomRecordResult> {
  if (previewMode) {
    const id = input.id || `preview-custom-record-${crypto.randomUUID()}`
    const record: CustomRecord = { ...input, id, title: input.title.trim() }
    if (input.id && previewCustomRecords[id]) captureHistoryPreview('custom_record', id, previewCustomRecords[id].title, previewCustomRecords[id])
    previewCustomRecords[id] = record
    const summary = { id, title: record.title }
    const existing = previewSnapshot.customRecords.find((entry) => entry.id === id)
    if (existing) Object.assign(existing, summary)
    else previewSnapshot.customRecords.push(summary)
    return { id, snapshot: previewSnapshot }
  }
  return invoke<SaveCustomRecordResult>('save_custom_record', { input })
}

export async function deleteCustomRecord(id: string): Promise<DeleteCustomRecordResult> {
  if (previewMode) {
    const index = previewSnapshot.customRecords.findIndex((summary) => summary.id === id)
    if (index < 0) throw new Error('That saved record no longer exists.')
    previewSnapshot.customRecords.splice(index, 1)
    if (previewCustomRecords[id]) trashPreviewItem('custom_record', id, previewCustomRecords[id].title, previewCustomRecords[id])
    delete previewCustomRecords[id]
    return { deletedId: id, snapshot: previewSnapshot }
  }
  return invoke<DeleteCustomRecordResult>('delete_custom_record', { id })
}

export async function previewTrashedItem(id: string): Promise<ItemPreview> {
  if (previewMode) {
    const trashed = previewTrashRecords[id]
    if (!trashed) throw new Error('That deleted item is no longer in trash.')
    return { kind: trashed.kind, title: trashed.title }
  }
  return invoke<ItemPreview>('preview_trashed_item', { id })
}

export async function previewHistoryVersion(id: string): Promise<ItemPreview> {
  if (previewMode) {
    const version = previewHistoryRecords[id]
    if (!version) throw new Error('That version is no longer available.')
    return { kind: version.kind, title: version.title }
  }
  return invoke<ItemPreview>('preview_history_version', { id })
}

export async function restoreTrashedItem(id: string): Promise<RestoreTrashedItemResult> {
  if (previewMode) {
    const trashIndex = previewSnapshot.trash.findIndex((item) => item.id === id)
    const trashed = previewTrashRecords[id]
    if (trashIndex < 0 || !trashed) throw new Error('That deleted item is no longer in trash.')
    previewSnapshot.trash.splice(trashIndex, 1)
    delete previewTrashRecords[id]
    switch (trashed.kind) {
      case 'login': {
        previewCards[id] = trashed.record as LoginCard
        previewSnapshot.entries.push(trashed.record as unknown as VaultEntry)
        break
      }
      case 'identity': {
        previewIdentities[id] = trashed.record as Identity
        previewSnapshot.identities.push({ id, label: trashed.title })
        break
      }
      case 'secure_note': {
        previewSecureNotes[id] = trashed.record as SecureNote
        previewSnapshot.secureNotes.push({ id, title: trashed.title, updatedAt: Math.floor(Date.now() / 1000) })
        break
      }
      case 'card': {
        previewPaymentCards[id] = trashed.record as Card
        previewSnapshot.cards.push({ id, title: trashed.title })
        break
      }
      case 'wifi_network': {
        previewWifiNetworks[id] = trashed.record as WifiNetwork
        previewSnapshot.wifiNetworks.push({ id, title: trashed.title })
        break
      }
      case 'ssh_key': {
        previewSshKeys[id] = trashed.record as SshKey
        previewSnapshot.sshKeys.push({ id, title: trashed.title })
        break
      }
      case 'software_license': {
        previewSoftwareLicenses[id] = trashed.record as SoftwareLicense
        previewSnapshot.softwareLicenses.push({ id, title: trashed.title })
        break
      }
      case 'document': {
        const restored = trashed.record as DocumentMetadata
        previewDocuments[id] = restored
        previewSnapshot.documents.push({ id, title: trashed.title, attachmentCount: restored.attachments.length })
        break
      }
      case 'custom_record': {
        previewCustomRecords[id] = trashed.record as CustomRecord
        previewSnapshot.customRecords.push({ id, title: trashed.title })
        break
      }
    }
    return { restoredId: id, snapshot: previewSnapshot }
  }
  return invoke<RestoreTrashedItemResult>('restore_trashed_item', { id })
}

export async function restoreHistoryVersion(id: string): Promise<RestoreHistoryVersionResult> {
  if (previewMode) {
    const version = previewHistoryRecords[id]
    if (!version) throw new Error('That version is no longer available.')
    const itemId = version.itemId
    switch (version.kind) {
      case 'login': {
        const current = previewCards[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('login', itemId, current.title, current)
        previewCards[itemId] = version.record as LoginCard
        const restoredCard = version.record as LoginCard
        const entryIndex = previewSnapshot.entries.findIndex((entry) => entry.id === itemId)
        if (entryIndex >= 0) previewSnapshot.entries[entryIndex] = { ...previewSnapshot.entries[entryIndex], title: restoredCard.title, site: restoredCard.site, initials: previewInitials(restoredCard.title) }
        break
      }
      case 'identity': {
        const current = previewIdentities[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('identity', itemId, current.label, current)
        previewIdentities[itemId] = version.record as Identity
        const summary = previewSnapshot.identities.find((entry) => entry.id === itemId)
        if (summary) summary.label = (version.record as Identity).label
        break
      }
      case 'secure_note': {
        const current = previewSecureNotes[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('secure_note', itemId, current.title, current)
        previewSecureNotes[itemId] = version.record as SecureNote
        const summary = previewSnapshot.secureNotes.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as SecureNote).title
        break
      }
      case 'card': {
        const current = previewPaymentCards[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('card', itemId, current.title, current)
        previewPaymentCards[itemId] = version.record as Card
        const summary = previewSnapshot.cards.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as Card).title
        break
      }
      case 'wifi_network': {
        const current = previewWifiNetworks[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('wifi_network', itemId, current.title, current)
        previewWifiNetworks[itemId] = version.record as WifiNetwork
        const summary = previewSnapshot.wifiNetworks.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as WifiNetwork).title
        break
      }
      case 'ssh_key': {
        const current = previewSshKeys[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('ssh_key', itemId, current.title, current)
        previewSshKeys[itemId] = version.record as SshKey
        const summary = previewSnapshot.sshKeys.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as SshKey).title
        break
      }
      case 'software_license': {
        const current = previewSoftwareLicenses[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('software_license', itemId, current.title, current)
        previewSoftwareLicenses[itemId] = version.record as SoftwareLicense
        const summary = previewSnapshot.softwareLicenses.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as SoftwareLicense).title
        break
      }
      case 'document': {
        const current = previewDocuments[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('document', itemId, current.title, current)
        previewDocuments[itemId] = version.record as DocumentMetadata
        const summary = previewSnapshot.documents.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as DocumentMetadata).title
        break
      }
      case 'custom_record': {
        const current = previewCustomRecords[itemId]
        if (!current) throw new Error('Restore the item from trash first, then choose a version to restore.')
        captureHistoryPreview('custom_record', itemId, current.title, current)
        previewCustomRecords[itemId] = version.record as CustomRecord
        const summary = previewSnapshot.customRecords.find((entry) => entry.id === itemId)
        if (summary) summary.title = (version.record as CustomRecord).title
        break
      }
    }
    return { restoredId: itemId, snapshot: previewSnapshot }
  }
  return invoke<RestoreHistoryVersionResult>('restore_history_version', { id })
}

export async function getMergeComparison(ids: string[]): Promise<MergeComparison> {
  if (previewMode) {
    return {
      entries: ids.map((id) => ({ id, title: previewCards[id]?.title ?? id, site: previewCards[id]?.site ?? '', username: previewCards[id]?.username ?? '', updatedAt: 0, revision: 1 })),
      fields: [],
    }
  }
  return invoke<MergeComparison>('get_merge_comparison', { ids })
}

export async function mergeDuplicateLogins(keepId: string, removeIds: string[], choices: MergeChoices = {}): Promise<MergeDuplicateLoginsResult> {
  if (previewMode) {
    previewSnapshot.entries = previewSnapshot.entries.filter((entry) => !removeIds.includes(entry.id))
    for (const id of removeIds) delete previewCards[id]
    return { id: keepId, snapshot: previewSnapshot }
  }
  return invoke<MergeDuplicateLoginsResult>('merge_duplicate_logins', { request: { keepId, removeIds, choices } })
}

export async function createBackup(): Promise<string> {
  if (previewMode) return 'preview-vault-2026-07-10.sesame'
  return invoke<string>('create_backup')
}

export async function exportBackup(): Promise<string | null> {
  if (previewMode) return 'sesame-backup-preview.sesame'
  const destination = await save({
    defaultPath: `sesame-backup-${new Date().toISOString().slice(0, 10)}.sesame`,
    filters: [{ name: 'Sesame encrypted backup', extensions: ['sesame'] }],
  })
  if (!destination) return null
  return invoke<string>('export_backup', { destination })
}

export async function exportVaultCsv(): Promise<string[] | null> {
  if (previewMode) return ['sesame-vault-export-preview.csv']
  const destination = await save({
    defaultPath: `sesame-vault-export-${new Date().toISOString().slice(0, 10)}.csv`,
    filters: [{ name: 'Sesame readable export', extensions: ['csv'] }],
  })
  if (!destination) return null
  return invoke<string[]>('export_vault_csv', { destination })
}

export async function deleteLocalVault(masterPassword: string): Promise<void> {
  if (previewMode) {
    previewUnlocked = false
    return
  }
  await invoke('delete_local_vault', { masterPassword })
}

export async function chooseBackupForRestore(): Promise<BackupSelection | null> {
  if (previewMode) {
    return { source: 'preview.sesame', fileName: 'preview.sesame', formatVersion: 3 }
  }
  const source = await open({
    multiple: false,
    directory: false,
    filters: [{ name: 'Sesame encrypted backup', extensions: ['sesame'] }],
  })
  if (!source) return null
  const inspection = await invoke<BackupInspection>('inspect_backup', { source })
  return { source, ...inspection }
}

// The backup must open with its own secret before it can replace the active vault.
export async function restoreBackup(source: string, secret: string): Promise<RestoreBackupResult> {
  if (previewMode) {
    previewUnlocked = false
    return { safetyBackupName: 'sesame-before-restore-preview.sesame', pinUnlockAvailable: false, helloUnlockAvailable: false }
  }
  return invoke<RestoreBackupResult>('restore_backup', { request: { source, secret } })
}

export async function verifyBackup(source: string, secret: string): Promise<BackupVerification> {
  if (previewMode) return { fileName: 'preview.sesame', formatVersion: 4, vaultName: previewSnapshot.vaultName, entryCount: previewSnapshot.entries.length, vaultId: 'preview-vault', revision: 1 }
  return invoke<BackupVerification>('verify_backup', { request: { source, secret } })
}

export async function getRecoveryHealth(): Promise<RecoveryHealth> {
  if (previewMode) return { vaultId: 'preview-vault' }
  return invoke<RecoveryHealth>('get_recovery_health')
}

export async function recordDiagnostic(operation: string, code: string): Promise<void> {
  if (previewMode) return
  try {
    await invoke('record_diagnostic', { input: { operation, code } })
  } catch {
    // Diagnostics must never interrupt vault use or retry with additional data.
  }
}

export async function getDiagnosticStatus(): Promise<DiagnosticStatus> {
  if (previewMode) return { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
  return invoke<DiagnosticStatus>('get_diagnostic_status')
}

export async function exportRecoveryKit(kit: string): Promise<string | null> {
  if (previewMode) return 'sesame-recovery-kit-preview.txt'
  const destination = await save({
    defaultPath: `sesame-recovery-kit-${new Date().toISOString().slice(0, 10)}.txt`,
    filters: [{ name: 'Text file', extensions: ['txt'] }],
  })
  if (!destination) return null
  return invoke<string>('export_recovery_kit', { destination, kit })
}

export async function exportDiagnostics(): Promise<string | null> {
  if (previewMode) return null
  const destination = await save({
    defaultPath: `sesame-diagnostics-${new Date().toISOString().slice(0, 10)}.jsonl`,
    filters: [{ name: 'Sesame diagnostic log', extensions: ['jsonl'] }],
  })
  if (!destination) return null
  return invoke<string>('export_diagnostics', { destination })
}

export async function clearDiagnostics(): Promise<void> {
  if (previewMode) return
  await invoke('clear_diagnostics')
}

export async function getWebsiteIcon(site: string): Promise<string | null> {
  if (previewMode) return null
  return invoke<string | null>('get_website_icon', { site })
}

export async function clearWebsiteIconCache(): Promise<void> {
  if (previewMode) return
  await invoke('clear_website_icon_cache')
}

export async function getWebsiteIconCacheStatus(): Promise<WebsiteIconCacheStatus> {
  if (previewMode) return { entryCount: 0, iconCount: 0, sizeBytes: 0 }
  return invoke<WebsiteIconCacheStatus>('get_website_icon_cache_status')
}

export async function getServiceConnectionStatus(): Promise<ServiceConnectionStatus> {
  if (previewMode) return { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
  return invoke<ServiceConnectionStatus>('get_service_connection_status')
}

export async function linkDesktopService(code: string): Promise<ServiceConnectionStatus> {
  if (previewMode) throw new Error('Account linking is available in the installed Windows app, not preview mode.')
  return invoke<ServiceConnectionStatus>('link_desktop_service', { code })
}

export async function disconnectService(): Promise<void> {
  if (previewMode) return
  await invoke('disconnect_service')
}

export async function checkDesktopUpdate(): Promise<import('./types').DesktopUpdateStatus> {
  if (previewMode) return { available: false }
  return invoke('check_desktop_update')
}

export async function downloadAndInstallDesktopUpdate(): Promise<void> {
  if (previewMode) return
  await invoke('download_and_install_desktop_update')
}

export async function getBrowserIntegrationStatus(): Promise<BrowserIntegrationStatus> {
  if (previewMode) {
    return {
      supported: false,
      hostAvailable: false,
      manifestReady: false,
      chromeRegistered: false,
      edgeRegistered: false,
      ready: false,
      code: 'unsupported',
    }
  }
  return invoke<BrowserIntegrationStatus>('get_browser_integration_status')
}

export async function repairBrowserIntegration(): Promise<BrowserIntegrationStatus> {
  if (previewMode) throw new Error('Browser integration is available in the installed Windows app, not preview mode.')
  return invoke<BrowserIntegrationStatus>('repair_browser_integration')
}

export async function resolveBrowserFill(approvalId: string, loginId: string | null, remember = false): Promise<void> {
  if (previewMode) return
  await invoke('resolve_browser_fill', { approvalId, loginId, remember })
}

export async function getPendingBrowserFill(): Promise<BrowserFillRequest | null> {
  if (previewMode) return null
  return invoke<BrowserFillRequest | null>('get_pending_browser_fill')
}

export async function resolveBrowserIdentityFill(approvalId: string, identityId: string | null): Promise<void> {
  if (previewMode) return
  await invoke('resolve_browser_identity_fill', { approvalId, identityId })
}

export async function getPendingBrowserIdentityFill(): Promise<BrowserIdentityFillRequest | null> {
  if (previewMode) return null
  return invoke<BrowserIdentityFillRequest | null>('get_pending_browser_identity_fill')
}

export async function resolveBrowserSave(
  approvalId: string,
  approved: boolean,
  selectedId?: string
): Promise<SaveLoginResult | null> {
  if (previewMode) return null
  return invoke<SaveLoginResult | null>('resolve_browser_save', { approvalId, approved, selectedId })
}

export async function getPendingBrowserSave(): Promise<BrowserSaveRequest | null> {
  if (previewMode) return null
  return invoke<BrowserSaveRequest | null>('get_pending_browser_save')
}

export async function copyToClipboard(value: string): Promise<void> {
  if (previewMode) {
    await navigator.clipboard.writeText(value)
    const copyEpoch = ++clipboardEpoch
    window.setTimeout(() => {
      void clearPreviewClipboardIfUnchanged(value, copyEpoch)
    }, clipboardClearMs)
    return
  }
  await writeText(value)
  // Read-back and clear run in Rust so the webview never gains clipboard-read permission.
  const epoch = await invoke<number>('arm_clipboard_clear', { value })
  window.setTimeout(() => {
    void invoke('clear_clipboard_if_unchanged', { epoch }).catch(() => {})
  }, clipboardClearMs)
}

export async function openWebsite(url: string, purpose: 'savedLogin' | 'support' = 'savedLogin'): Promise<void> {
  if (previewMode) {
    window.open(url, '_blank', 'noopener,noreferrer')
  } else {
    await invoke('open_external_url', { url, purpose })
  }
}

export async function controlWindow(action: 'minimize' | 'toggle-maximize' | 'close'): Promise<void> {
  if (previewMode) return
  const appWindow = getCurrentWindow()
  if (action === 'minimize') await appWindow.minimize()
  if (action === 'toggle-maximize') await appWindow.toggleMaximize()
  if (action === 'close') await appWindow.close()
}

async function clearPreviewClipboardIfUnchanged(value: string, copyEpoch: number) {
  if (copyEpoch !== clipboardEpoch) return
  try {
    const current = await navigator.clipboard.readText()
    if (current === value) await navigator.clipboard.writeText('')
  } catch {
    // Clipboard access can be denied by the operating system. Never retry or log its contents.
  }
}

function previewUrl(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return ''
  return /^https?:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`
}

function previewSite(value: string) {
  return previewUrl(value).replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0] || 'No website saved'
}

function previewInitials(value: string) {
  return value.split(/\s+/).filter(Boolean).map((word) => word[0]).join('').slice(0, 2).toUpperCase() || '?'
}
