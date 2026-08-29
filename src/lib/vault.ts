import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { open, save } from '@tauri-apps/plugin-dialog'
import type { BackupInspection, BackupSelection, BackupVerification, BreachCheckResult, BrowserCardFillCancelled, BrowserCardFillRequest, BrowserFillCancelled, BrowserFillRequest, BrowserIdentityFillCancelled, BrowserIdentityFillRequest, BrowserIntegrationStatus, BrowserSaveCancelled, BrowserSaveRequest, Card, CardInput, ChangeMasterPasswordResult, CustomRecord, CustomRecordInput, DeleteCardResult, DeleteCustomRecordResult, DeleteDocumentMetadataResult, DeleteIdentityResult, DeleteLoginResult, DeleteSecureNoteResult, DeleteSoftwareLicenseResult, DeleteSshKeyResult, DeleteWifiNetworkResult, DesktopUpdateProgress, DiagnosticStatus, DocumentMetadata, DocumentMetadataInput, DuplicateGroup, Identity, IdentityInput, ImportPreviewResult, ImportResult, ImportSource, ItemPreview, LoginCard, LoginInput, LoginSummary, MasterPasswordRequest, MergeChoices, MergeComparison, MergeDuplicateLoginsResult, PasswordAnalysis, ItemKind, PlatformCapabilities, QuickAccessItem, QuickAccessStatus, QuickAccessValue, RecoveryHealth, RestoreBackupResult, RestoreHistoryVersionResult, RestoreTrashedItemResult, SaveCardResult, SaveCustomRecordResult, SaveDocumentMetadataResult, SaveIdentityResult, SaveLoginResult, SaveSecureNoteResult, SaveSoftwareLicenseResult, SaveSshKeyResult, SaveWifiNetworkResult, SecureNote, SecureNoteInput, ServiceConnectionStatus, SoftwareLicense, SoftwareLicenseInput, SshKey, SshKeyInput, TotpCodeEntry, TotpRefresh, VaultEntry, VaultItemSummary, VaultSetup, VaultSnapshot, VaultStatus, WebsiteIconCacheStatus, WifiNetwork, WifiNetworkInput } from './types'

const hasTauriInternals = typeof window !== 'undefined' && Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
export const previewMode = !hasTauriInternals

export const PRESENCE_REQUIRED = 'presenceRequired'

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

export async function onQuickAccessOpenItem(handler: (id: string) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<string>('quick-access-open-item', ({ payload }) => handler(payload))
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

async function onBrowserCardFillRequest(handler: (payload: BrowserCardFillRequest) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserCardFillRequest>('browser-card-request', ({ payload }) => handler(payload))
}

async function onBrowserCardFillCancelled(handler: (payload: BrowserCardFillCancelled) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<BrowserCardFillCancelled>('browser-card-cancelled', ({ payload }) => handler(payload))
}

export async function subscribeBrowserCardFill(handlers: {
  request: (payload: BrowserCardFillRequest) => void
  cancelled: (payload: BrowserCardFillCancelled) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  const [stopRequests, stopCancellations] = await Promise.all([
    onBrowserCardFillRequest(handlers.request),
    onBrowserCardFillCancelled(handlers.cancelled),
  ])
  return () => { stopRequests(); stopCancellations() }
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
    { id: 'gmail', title: 'Gmail', site: 'mail.google.com', initials: 'G', folderId: 'personal', folder: 'Personal', favourite: true, lastUsedAt: 1_784_025_600, passwordScore: 4, passwordIssues: [], securityLevel: 'good', issueKinds: [], tags: ['email'], updatedAt: 1_784_025_600 },
    { id: 'github', title: 'GitHub', site: 'github.com', initials: 'GH', folderId: 'work', folder: 'Work', favourite: false, passwordScore: 4, passwordIssues: [], securityLevel: 'needs-work', issueKinds: ['totp', 'recovery'], tags: ['dev'], updatedAt: 1_784_025_600 },
    { id: 'notion', title: 'Notion', site: 'notion.so', initials: 'N', folderId: 'work', folder: 'Work', favourite: false, passwordScore: 2, passwordIssues: [{ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' }], securityLevel: 'needs-work', issueKinds: ['weak-password'], tags: [], updatedAt: 1_784_025_600 },
  ],
  items: [],
  trash: [],
  history: [],
  security: { good: 1, needsAttention: 3, duplicateCandidates: 0, weakOrReused: 1, weakPasswords: 1, commonPasswords: 0, reusedPasswords: 0, compromisedPatterns: 0, oldPasswords: 0, missingUrls: 0, noTotp: 2, missingRecovery: 1 },
}

function upsertPreviewItem(kind: ItemKind, id: string, title: string, subtitle: string, tags: string[]): void {
  const updatedAt = Math.floor(Date.now() / 1000)
  const existing = previewSnapshot.items.find((item) => item.id === id)
  if (existing) {
    Object.assign(existing, { title, subtitle, tags, updatedAt })
    return
  }
  const summary: VaultItemSummary = { id, kind, title, subtitle, initials: previewInitials(title), folder: '', favourite: false, updatedAt, tags }
  previewSnapshot.items.push(summary)
}

function removePreviewItem(id: string): void {
  const index = previewSnapshot.items.findIndex((item) => item.id === id)
  if (index >= 0) previewSnapshot.items.splice(index, 1)
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
  previewSnapshot.history.push({ id: historyId, itemId, kind, capturedAt: Math.floor(Date.now() / 1000), operation: 'edit', changed: ['password'] })
}

const previewIdentities: Record<string, Identity> = {}
const previewSecureNotes: Record<string, SecureNote> = {}
const previewPaymentCards: Record<string, Card> = {}
const previewWifiNetworks: Record<string, WifiNetwork> = {}
const previewSshKeys: Record<string, SshKey> = {}
const previewSoftwareLicenses: Record<string, SoftwareLicense> = {}
const previewDocuments: Record<string, DocumentMetadata> = {}
const previewCustomRecords: Record<string, CustomRecord> = {}

type PreviewRecord = { title?: string; label?: string }

const previewRecordStores: Record<string, Record<string, PreviewRecord>> = {
  identity: previewIdentities,
  secure_note: previewSecureNotes,
  card: previewPaymentCards,
  wifi_network: previewWifiNetworks,
  ssh_key: previewSshKeys,
  software_license: previewSoftwareLicenses,
  document: previewDocuments,
  custom_record: previewCustomRecords,
}

function previewRecordTitle(kind: string, id: string): string | null {
  const record: PreviewRecord | undefined = kind === 'login' ? previewCards[id] : previewRecordStores[kind]?.[id]
  if (!record) return null
  return record.label ?? record.title ?? ''
}

function adoptPreviewRecord(kind: string, id: string, record: unknown): void {
  switch (kind) {
    case 'identity': {
      const identity = record as Identity
      previewIdentities[id] = identity
      upsertPreviewItem('identity', id, identity.label, identity.fullName || identity.email, identity.tags ?? [])
      break
    }
    case 'secure_note': {
      const note = record as SecureNote
      previewSecureNotes[id] = note
      upsertPreviewItem('secure_note', id, note.title, '', note.tags ?? [])
      break
    }
    case 'card': {
      const card = record as Card
      previewPaymentCards[id] = card
      upsertPreviewItem('card', id, card.title, card.brand, card.tags ?? [])
      break
    }
    case 'wifi_network': {
      const network = record as WifiNetwork
      previewWifiNetworks[id] = network
      upsertPreviewItem('wifi_network', id, network.title, network.ssid, network.tags ?? [])
      break
    }
    case 'ssh_key': {
      const key = record as SshKey
      previewSshKeys[id] = key
      upsertPreviewItem('ssh_key', id, key.title, key.keyType, key.tags ?? [])
      break
    }
    case 'software_license': {
      const license = record as SoftwareLicense
      previewSoftwareLicenses[id] = license
      upsertPreviewItem('software_license', id, license.title, license.productName, license.tags ?? [])
      break
    }
    case 'document': {
      const document = record as DocumentMetadata
      previewDocuments[id] = document
      upsertPreviewItem('document', id, document.title, document.documentType, document.tags ?? [])
      break
    }
    case 'custom_record': {
      const customRecord = record as CustomRecord
      previewCustomRecords[id] = customRecord
      upsertPreviewItem('custom_record', id, customRecord.title, '', customRecord.tags ?? [])
      break
    }
  }
}

interface TaggedRecord {
  id: string
  tags: string[]
  favourite: boolean
  updatedAt: number
}

interface PreviewRecordApiConfig<TItem extends TaggedRecord, TInput extends { id?: string }> {
  kind: ItemKind
  idPrefix: string
  missingNoun: string
  store: Record<string, TItem>
  titleOf(item: TItem): string
  subtitleOf(item: TItem): string
  buildRecord(input: TInput, id: string, existing: TItem | undefined): TItem
}

/// One shape for every non-login item kind: preview reads/writes an in-memory
/// store and mirrors the summary list; the real path is a single Tauri call.
/// Login stays out, its preview save also rewrites `entries`, a different shape.
function createPreviewRecordApi<TItem extends TaggedRecord, TInput extends { id?: string }>(
  config: PreviewRecordApiConfig<TItem, TInput>,
) {
  return {
    async get(id: string): Promise<TItem> {
      if (previewMode) {
        const item = config.store[id]
        if (!item) throw new Error(`That saved ${config.missingNoun} no longer exists.`)
        return item
      }
      return invoke<TItem>(`get_${config.kind}`, { id })
    },
    async save(input: TInput): Promise<{ id: string; snapshot: VaultSnapshot }> {
      if (previewMode) {
        const id = input.id || `${config.idPrefix}${crypto.randomUUID()}`
        const existing = config.store[id]
        const record = config.buildRecord(input, id, existing)
        if (input.id && existing) captureHistoryPreview(config.kind, id, config.titleOf(existing), existing)
        config.store[id] = record
        upsertPreviewItem(config.kind, id, config.titleOf(record), config.subtitleOf(record), record.tags)
        return { id, snapshot: previewSnapshot }
      }
      return invoke<{ id: string; snapshot: VaultSnapshot }>(`save_${config.kind}`, { input })
    },
    async delete(id: string): Promise<{ deletedId: string; snapshot: VaultSnapshot }> {
      if (previewMode) {
        const existing = config.store[id]
        if (!existing) throw new Error(`That saved ${config.missingNoun} no longer exists.`)
        removePreviewItem(id)
        trashPreviewItem(config.kind, id, config.titleOf(existing), existing)
        delete config.store[id]
        return { deletedId: id, snapshot: previewSnapshot }
      }
      return invoke<{ deletedId: string; snapshot: VaultSnapshot }>(`delete_${config.kind}`, { id })
    },
  }
}

const identityApi = createPreviewRecordApi<Identity, IdentityInput>({
  kind: 'identity',
  idPrefix: 'preview-identity-',
  missingNoun: 'identity',
  store: previewIdentities,
  titleOf: (item) => item.label,
  subtitleOf: (item) => item.fullName || item.email,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    label: input.label.trim(),
    legacyFields: existing?.legacyFields ?? [],
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const secureNoteApi = createPreviewRecordApi<SecureNote, SecureNoteInput>({
  kind: 'secure_note',
  idPrefix: 'preview-note-',
  missingNoun: 'note',
  store: previewSecureNotes,
  titleOf: (item) => item.title,
  subtitleOf: () => '',
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    legacyFields: existing?.legacyFields ?? [],
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const cardApi = createPreviewRecordApi<Card, CardInput>({
  kind: 'card',
  idPrefix: 'preview-card-',
  missingNoun: 'card',
  store: previewPaymentCards,
  titleOf: (item) => item.title,
  subtitleOf: (item) => item.brand,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    legacyFields: existing?.legacyFields ?? [],
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const wifiNetworkApi = createPreviewRecordApi<WifiNetwork, WifiNetworkInput>({
  kind: 'wifi_network',
  idPrefix: 'preview-wifi-',
  missingNoun: 'network',
  store: previewWifiNetworks,
  titleOf: (item) => item.title,
  subtitleOf: (item) => item.ssid,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const sshKeyApi = createPreviewRecordApi<SshKey, SshKeyInput>({
  kind: 'ssh_key',
  idPrefix: 'preview-ssh-key-',
  missingNoun: 'key',
  store: previewSshKeys,
  titleOf: (item) => item.title,
  subtitleOf: (item) => item.keyType,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const softwareLicenseApi = createPreviewRecordApi<SoftwareLicense, SoftwareLicenseInput>({
  kind: 'software_license',
  idPrefix: 'preview-license-',
  missingNoun: 'licence',
  store: previewSoftwareLicenses,
  titleOf: (item) => item.title,
  subtitleOf: (item) => item.productName,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const documentApi = createPreviewRecordApi<DocumentMetadata, DocumentMetadataInput>({
  kind: 'document',
  idPrefix: 'preview-document-',
  missingNoun: 'document',
  store: previewDocuments,
  titleOf: (item) => item.title,
  subtitleOf: (item) => item.documentType,
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    attachments: existing?.attachments ?? [],
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const customRecordApi = createPreviewRecordApi<CustomRecord, CustomRecordInput>({
  kind: 'custom_record',
  idPrefix: 'preview-custom-record-',
  missingNoun: 'record',
  store: previewCustomRecords,
  titleOf: (item) => item.title,
  subtitleOf: () => '',
  buildRecord: (input, id, existing) => ({
    ...input,
    id,
    title: input.title.trim(),
    favourite: existing?.favourite ?? false,
    createdAt: existing?.createdAt ?? Math.floor(Date.now() / 1000),
    updatedAt: Math.floor(Date.now() / 1000),
    revision: (existing?.revision ?? 0) + 1,
  }),
})

const previewCards: Record<string, LoginCard> = {
  gmail: {
    id: 'gmail', title: 'Gmail', site: 'mail.google.com', initials: 'G', url: 'https://mail.google.com', urls: [], tags: ['email'], username: 'hello@example.test', email: '', password: 'preview-only-not-a-real-password', folderId: 'personal', folder: 'Personal', favourite: true, lastUsedAt: 1_784_025_600, hasTotp: true, totpCode: '482 914', totpRemaining: 19, backupCodes: ['J8CJ-5TKJ', 'KD8Q-3NZP', 'HF9M-7QNR'], recoveryEmail: 'recovery@example.test', recoveryPhone: '+370 •••• 1298', recoveryNotApplicable: false, notes: 'Personal email. Keep backup codes current.', legacyFields: [],
  },
  github: { id: 'github', title: 'GitHub', site: 'github.com', initials: 'GH', url: 'https://github.com', urls: [], tags: ['dev'], username: 'sesame-preview', email: '', password: 'preview-only-not-a-real-password', folderId: 'work', folder: 'Work', favourite: false, hasTotp: false, recoveryNotApplicable: false, notes: 'Add a TOTP code and recovery details.', legacyFields: [] },
  notion: { id: 'notion', title: 'Notion', site: 'notion.so', initials: 'N', url: 'https://notion.so', urls: [], tags: [], username: 'hello@example.test', email: 'hello@example.test', password: 'preview-only-not-a-real-password', folderId: 'work', folder: 'Work', favourite: false, hasTotp: false, recoveryNotApplicable: true, legacyFields: [] },
}

const previewCapabilities: PlatformCapabilities = { os: 'windows', pinUnlock: true, biometricUnlock: true, autoType: true, browserIntegration: true, sessionAutoLock: true, quickAccessShortcut: true, accountLinking: true, desktopUpdates: true, windowControls: true }

export async function getPlatformCapabilities(): Promise<PlatformCapabilities> {
  if (previewMode) return previewCapabilities
  return invoke<PlatformCapabilities>('get_platform_capabilities')
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

export async function searchQuickAccessItems(query: string): Promise<QuickAccessItem[]> {
  if (previewMode) {
    const needle = query.trim().toLowerCase()
    return previewSnapshot.entries
      .filter((entry) => !needle || `${entry.title} ${entry.site}`.toLowerCase().includes(needle))
      .slice(0, 8)
      .map((entry) => ({
        id: entry.id,
        kind: 'login' as const,
        title: entry.title,
        subtitle: entry.site,
        initials: entry.initials,
        actions: [
          { field: 'password', label: 'Copy password', guarded: false },
          ...(previewCards[entry.id]?.totpCode ? [{ field: 'totp', label: 'Copy 2FA code', guarded: false }] : []),
        ],
      }))
  }
  return invoke<QuickAccessItem[]>('search_quick_access_items', { query })
}

export async function getQuickAccessField(id: string, field: string, confirmed = false): Promise<QuickAccessValue> {
  if (previewMode) {
    const card = previewCards[id]
    return { value: (field === 'totp' ? card?.totpCode : card?.password) ?? '' }
  }
  return invoke<QuickAccessValue>('get_quick_access_field', { id, field, confirmed })
}

export async function openQuickAccessItem(id: string): Promise<void> {
  if (previewMode) return
  await invoke('open_quick_access_item', { id })
}

/// Matched in Rust; stored fields never ship into the webview for one filter.
export async function searchItems(query: string): Promise<string[]> {
  if (previewMode) return []
  return invoke<string[]>('search_items', { query })
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
  if (previewMode) throw new Error('Auto-type is not available in the browser preview. Use the installed desktop app.')
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

// Browser preview has no Rust side, so the view has something to render.
function previewTotpCodes(): TotpCodeEntry[] {
  const second = new Date().getSeconds()
  const remaining = 30 - (second % 30)
  return [
    { id: 'preview-1', title: 'Gmail', site: 'mail.google.com', initials: 'G', code: '482914', remaining, period: 30 },
    { id: 'preview-2', title: 'GitHub', site: 'github.com', initials: 'GH', code: '205663', remaining, period: 30 },
  ]
}

export async function listTotpCodes(): Promise<TotpCodeEntry[]> {
  if (previewMode) return previewTotpCodes()
  return invoke<TotpCodeEntry[]>('list_totp_codes')
}

export async function refreshTotp(id: string): Promise<TotpRefresh> {
  if (previewMode) {
    const card = previewCards[id]
    return { totpCode: card.totpCode ?? null, totpRemaining: card.totpRemaining ?? null }
  }
  return invoke<TotpRefresh>('refresh_totp', { id })
}

function importFileFilter(source: ImportSource): { name: string; extensions: string[] } {
  if (source === 'otpauth-txt') return { name: 'Authenticator export', extensions: ['txt'] }
  if (source === 'bitwarden-json' || source === 'aegis-json' || source === '2fas-json') {
    return { name: 'JSON export', extensions: ['json'] }
  }
  return { name: 'CSV export', extensions: ['csv'] }
}

// The export is parsed and held in Rust; its contents never enter the webview.
export async function chooseImportFile(source: ImportSource): Promise<string | null> {
  if (previewMode) return 'preview-export.csv'
  const chosen = await open({
    multiple: false,
    directory: false,
    filters: [importFileFilter(source)],
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
      urls: input.urls ?? [],
      tags: input.tags ?? [],
      username: input.username.trim(),
      email: input.email.trim(),
      password: input.password,
      folderId: input.folderId,
      folder: input.folder.trim(),
      favourite: previewCards[id]?.favourite ?? false,
      hasTotp: Boolean(input.totp),
      backupCodes: input.backupCodes.filter(Boolean),
      recoveryEmail: input.recoveryEmail.trim() || undefined,
      recoveryPhone: input.recoveryPhone.trim() || undefined,
      recoveryNotApplicable: input.recoveryNotApplicable,
      notes: input.notes.trim() || undefined,
      legacyFields: previewCards[id]?.legacyFields ?? [],
    }
    if (input.id && previewCards[id]) captureHistoryPreview('login', id, previewCards[id].title, previewCards[id])
    previewCards[id] = card
    const entry: VaultEntry = { id, title, site, initials, folderId: card.folderId, folder: card.folder, favourite: card.favourite, passwordScore: 2, passwordIssues: [{ kind: 'weak-password', explanation: 'This password is short or has too little character variety.' }], securityLevel: 'needs-work', issueKinds: ['weak-password', 'totp', 'recovery'], tags: input.tags ?? [], updatedAt: Math.floor(Date.now() / 1000) }
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
      const item = previewSnapshot.items.find((saved) => saved.id === id)
      const card = previewCards[id]
      if (entry) { entry.folderId = folder?.id; entry.folder = folder?.name ?? '' }
      if (item) { item.folderId = folder?.id; item.folder = folder?.name ?? '' }
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

export async function setItemFavourite(id: string, favourite: boolean): Promise<VaultSnapshot> {
  if (previewMode) {
    const entry = previewSnapshot.entries.find((saved) => saved.id === id)
    if (entry) entry.favourite = favourite
    const item = previewSnapshot.items.find((saved) => saved.id === id)
    if (item) item.favourite = favourite
    if (previewCards[id]) previewCards[id].favourite = favourite
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('set_item_favourite', { id, favourite })
}

export async function recordItemUse(id: string): Promise<VaultSnapshot> {
  if (previewMode) {
    const lastUsedAt = Math.floor(Date.now() / 1000)
    const entry = previewSnapshot.entries.find((saved) => saved.id === id)
    if (entry) entry.lastUsedAt = lastUsedAt
    const item = previewSnapshot.items.find((saved) => saved.id === id)
    if (item) item.lastUsedAt = lastUsedAt
    if (previewCards[id]) previewCards[id].lastUsedAt = lastUsedAt
    return previewSnapshot
  }
  return invoke<VaultSnapshot>('record_item_use', { id })
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
  return identityApi.get(id)
}

export async function saveIdentity(input: IdentityInput): Promise<SaveIdentityResult> {
  return identityApi.save(input)
}

export async function deleteIdentity(id: string): Promise<DeleteIdentityResult> {
  return identityApi.delete(id)
}

export async function getSecureNote(id: string): Promise<SecureNote> {
  return secureNoteApi.get(id)
}

export async function saveSecureNote(input: SecureNoteInput): Promise<SaveSecureNoteResult> {
  return secureNoteApi.save(input)
}

export async function deleteSecureNote(id: string): Promise<DeleteSecureNoteResult> {
  return secureNoteApi.delete(id)
}

export async function getCard(id: string): Promise<Card> {
  return cardApi.get(id)
}

export async function saveCard(input: CardInput): Promise<SaveCardResult> {
  return cardApi.save(input)
}

export async function deleteCard(id: string): Promise<DeleteCardResult> {
  return cardApi.delete(id)
}

export async function getWifiNetwork(id: string): Promise<WifiNetwork> {
  return wifiNetworkApi.get(id)
}

export async function saveWifiNetwork(input: WifiNetworkInput): Promise<SaveWifiNetworkResult> {
  return wifiNetworkApi.save(input)
}

export async function deleteWifiNetwork(id: string): Promise<DeleteWifiNetworkResult> {
  return wifiNetworkApi.delete(id)
}

export async function getSshKey(id: string): Promise<SshKey> {
  return sshKeyApi.get(id)
}

export async function saveSshKey(input: SshKeyInput): Promise<SaveSshKeyResult> {
  return sshKeyApi.save(input)
}

export async function deleteSshKey(id: string): Promise<DeleteSshKeyResult> {
  return sshKeyApi.delete(id)
}

export async function getSoftwareLicense(id: string): Promise<SoftwareLicense> {
  return softwareLicenseApi.get(id)
}

export async function saveSoftwareLicense(input: SoftwareLicenseInput): Promise<SaveSoftwareLicenseResult> {
  return softwareLicenseApi.save(input)
}

export async function deleteSoftwareLicense(id: string): Promise<DeleteSoftwareLicenseResult> {
  return softwareLicenseApi.delete(id)
}

export async function getDocument(id: string): Promise<DocumentMetadata> {
  return documentApi.get(id)
}

export async function saveDocument(input: DocumentMetadataInput): Promise<SaveDocumentMetadataResult> {
  return documentApi.save(input)
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
    return { id: documentId, snapshot: previewSnapshot }
  }
  return invoke<SaveDocumentMetadataResult>('remove_document_attachment', { documentId, attachmentId })
}

export async function deleteDocument(id: string): Promise<DeleteDocumentMetadataResult> {
  return documentApi.delete(id)
}

export async function getCustomRecord(id: string): Promise<CustomRecord> {
  return customRecordApi.get(id)
}

export async function saveCustomRecord(input: CustomRecordInput): Promise<SaveCustomRecordResult> {
  return customRecordApi.save(input)
}

export async function deleteCustomRecord(id: string): Promise<DeleteCustomRecordResult> {
  return customRecordApi.delete(id)
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
    if (trashed.kind === 'login') {
      previewCards[id] = trashed.record as LoginCard
      previewSnapshot.entries.push(trashed.record as unknown as VaultEntry)
    } else {
      adoptPreviewRecord(trashed.kind, id, trashed.record)
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
    const currentTitle = previewRecordTitle(version.kind, itemId)
    if (currentTitle === null) throw new Error('Restore the item from trash first, then choose a version to restore.')
    captureHistoryPreview(version.kind, itemId, currentTitle, version.kind === 'login' ? previewCards[itemId] : previewRecordStores[version.kind]?.[itemId])
    if (version.kind === 'login') {
      const restoredCard = version.record as LoginCard
      previewCards[itemId] = restoredCard
      const entryIndex = previewSnapshot.entries.findIndex((entry) => entry.id === itemId)
      if (entryIndex >= 0) previewSnapshot.entries[entryIndex] = { ...previewSnapshot.entries[entryIndex], title: restoredCard.title, site: restoredCard.site, initials: previewInitials(restoredCard.title) }
    } else {
      adoptPreviewRecord(version.kind, itemId, version.record)
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
    const hadVault = previewUnlocked
    previewUnlocked = false
    return { safetyBackupName: hadVault ? 'sesame-before-restore-preview.sesame' : undefined, pinUnlockAvailable: false, helloUnlockAvailable: false }
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

export async function grantPresence(secret: string): Promise<void> {
  if (previewMode) return
  await invoke('grant_presence', { secret })
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
  if (previewMode) throw new Error('Account linking is available in the installed desktop app, not preview mode.')
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
      firefoxRegistered: false,
      ready: false,
      code: 'unsupported',
    }
  }
  return invoke<BrowserIntegrationStatus>('get_browser_integration_status')
}

export async function repairBrowserIntegration(): Promise<BrowserIntegrationStatus> {
  if (previewMode) throw new Error('Browser integration is available in the installed desktop app, not preview mode.')
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

export async function resolveBrowserCardFill(approvalId: string, cardId: string | null): Promise<void> {
  if (previewMode) return
  await invoke('resolve_browser_card_fill', { approvalId, cardId })
}

export async function getPendingBrowserCardFill(): Promise<BrowserCardFillRequest | null> {
  if (previewMode) return null
  return invoke<BrowserCardFillRequest | null>('get_pending_browser_card_fill')
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
  // The copy runs in Rust so the value crosses once and carries the secret hint
  // that keeps clipboard managers from filing it in their history.
  const epoch = await invoke<number>('copy_secret', { value })
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
