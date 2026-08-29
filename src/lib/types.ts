// Generated from src-tauri (see src/lib/generated/, built by `npm run
// types:generate`) for every type whose Rust struct is a faithful source of
// truth. A type stays hand-written here instead when it has no Rust struct at
// all (a pure frontend concept, or a value Rust only guarantees as a loose
// `&'static str`/`String` where the frontend wants a closed union), or when
// its backing struct has a different name or shape than the frontend type.
//
// `export type { X } from './generated/X'` re-exports X for other modules but
// does not bring it into scope here, so any generated type referenced by a
// hand-written type below (PasswordIssue, BackupInspection, BrowserFillCandidate)
// also needs a plain `import type`.
import type { PasswordIssue } from './generated/PasswordIssue'
import type { BackupInspection } from './generated/BackupInspection'
import type { BrowserFillCandidate } from './generated/BrowserFillCandidate'

export type { LegacyField } from './generated/LegacyField'
export type { Identity } from './generated/Identity'
export type { IdentityInput } from './generated/IdentityInput'
export type { SaveIdentityResult } from './generated/SaveIdentityResult'
export type { DeleteIdentityResult } from './generated/DeleteIdentityResult'
export type { SecureNote } from './generated/SecureNote'
export type { SecureNoteInput } from './generated/SecureNoteInput'
export type { SaveSecureNoteResult } from './generated/SaveSecureNoteResult'
export type { DeleteSecureNoteResult } from './generated/DeleteSecureNoteResult'
export type { Card } from './generated/Card'
export type { CardInput } from './generated/CardInput'
export type { SaveCardResult } from './generated/SaveCardResult'
export type { DeleteCardResult } from './generated/DeleteCardResult'
export type { WifiNetwork } from './generated/WifiNetwork'
export type { WifiNetworkInput } from './generated/WifiNetworkInput'
export type { SaveWifiNetworkResult } from './generated/SaveWifiNetworkResult'
export type { DeleteWifiNetworkResult } from './generated/DeleteWifiNetworkResult'
export type { SshKey } from './generated/SshKey'
export type { SshKeyInput } from './generated/SshKeyInput'
export type { SaveSshKeyResult } from './generated/SaveSshKeyResult'
export type { DeleteSshKeyResult } from './generated/DeleteSshKeyResult'
export type { SoftwareLicense } from './generated/SoftwareLicense'
export type { SoftwareLicenseInput } from './generated/SoftwareLicenseInput'
export type { SaveSoftwareLicenseResult } from './generated/SaveSoftwareLicenseResult'
export type { DeleteSoftwareLicenseResult } from './generated/DeleteSoftwareLicenseResult'
export type { Attachment } from './generated/Attachment'
export type { DocumentMetadata } from './generated/DocumentMetadata'
export type { DocumentMetadataInput } from './generated/DocumentMetadataInput'
export type { SaveDocumentMetadataResult } from './generated/SaveDocumentMetadataResult'
export type { DeleteDocumentMetadataResult } from './generated/DeleteDocumentMetadataResult'
export type { CustomFieldEntry } from './generated/CustomFieldEntry'
export type { CustomRecord } from './generated/CustomRecord'
export type { CustomRecordInput } from './generated/CustomRecordInput'
export type { SaveCustomRecordResult } from './generated/SaveCustomRecordResult'
export type { DeleteCustomRecordResult } from './generated/DeleteCustomRecordResult'
export type { VaultSetup } from './generated/VaultSetup'
export type { ChangeMasterPasswordResult } from './generated/ChangeMasterPasswordResult'
export type { LoginCard } from './generated/LoginCard'
export type { LoginInput } from './generated/LoginInput'
export type { LoginSummary } from './generated/LoginSummary'
export type { TotpRefresh } from './generated/TotpRefresh'
export type { SaveLoginResult } from './generated/SaveLoginResult'
export type { DeleteLoginResult } from './generated/DeleteLoginResult'
export type { FidelityCounts } from './generated/FidelityCounts'
export type { ImportFidelity } from './generated/ImportFidelity'
export type { ImportPreview } from './generated/ImportPreview'
export type { ImportPreviewResult } from './generated/ImportPreviewResult'
export type { ImportResult } from './generated/ImportResult'
export type { MergeCandidate } from './generated/MergeCandidate'
export type { MergeFieldOption } from './generated/MergeFieldOption'
export type { MergeField } from './generated/MergeField'
export type { MergeComparison } from './generated/MergeComparison'
// Hand-written, not generated from Rust's `MergeChoices` (a fixed-field
// struct): the merge modal indexes this by an arbitrary field name chosen at
// render time, which needs a string index signature, not fixed field names.
export type MergeChoices = Record<string, string | undefined>
export type { MergeDuplicateLoginsResult } from './generated/MergeDuplicateLoginsResult'
export type { MasterPasswordRequest } from './generated/MasterPasswordRequest'
export type { TotpCodeEntry } from './generated/TotpCodeEntry'
export type { CleanupEntry } from './generated/CleanupEntry'
export type { DuplicateGroup } from './generated/DuplicateGroup'
export type { BackupInspection } from './generated/BackupInspection'
export type { BackupVerification } from './generated/BackupVerification'
export type { RestoreBackupResult } from './generated/RestoreBackupResult'
export type { PasswordIssue } from './generated/PasswordIssue'
export type { Folder } from './generated/Folder'
export type { VaultSnapshot } from './generated/VaultSnapshot'
export type { TrashSummary } from './generated/TrashSummary'
export type { RestoreTrashedItemResult } from './generated/RestoreTrashedItemResult'
export type { ItemPreview } from './generated/ItemPreview'
export type { HistorySummary } from './generated/HistorySummary'
export type { HistoryOperation } from './generated/HistoryOperation'
export type { RestoreHistoryVersionResult } from './generated/RestoreHistoryVersionResult'
export type { VaultItemSummary } from './generated/VaultItemSummary'
export type { SecuritySummary } from './generated/SecuritySummary'
export type { ServiceConnectionStatus } from './generated/ServiceConnectionStatus'
// Frontend name for backend's `VaultEntrySummary`: the frontend's own name
// `VaultEntry` is not reused here on purpose, it would collide with the full
// secret-bearing login record Rust also calls `VaultEntry` (password, TOTP,
// backup codes, recovery contacts), which is never exposed to the frontend
// under that shape and is deliberately not ts-rs derived.
export type { VaultEntrySummary as VaultEntry } from './generated/VaultEntrySummary'
export type { VaultStatus } from './generated/VaultStatus'

export type { PlatformCapabilities } from './generated/PlatformCapabilities'
export type { QuickAccessStatus } from './generated/QuickAccessStatus'
export type { QuickAccessAction } from './generated/QuickAccessAction'
export type { QuickAccessItem } from './generated/QuickAccessItem'
export type { QuickAccessValue } from './generated/QuickAccessValue'

export type IssueKind = 'duplicate' | 'weak-password' | 'common-password' | 'reused-password' | 'compromised-pattern' | 'old-password' | 'url' | 'totp' | 'recovery'

export type { BreachCheckResult } from './generated/BreachCheckResult'

export type ItemKind =
  | 'login'
  | 'identity'
  | 'secure_note'
  | 'card'
  | 'wifi_network'
  | 'ssh_key'
  | 'software_license'
  | 'document'
  | 'custom_record'

// Hand-written: backed by sesame-core/src/password_analysis.rs, a different
// module than sesame-core/src/types.rs. `PasswordIssue.kind` there is also a
// plain `&'static str`; the frontend keeps the closed union.
export interface PasswordAnalysis {
  score: number
  issues: PasswordIssue[]
}

export type { RecoveryHealth } from './generated/RecoveryHealth'
export type { DiagnosticStatus } from './generated/DiagnosticStatus'
export type { WebsiteIconCacheStatus } from './generated/WebsiteIconCacheStatus'

// Hand-written: no dedicated Rust struct of this shape, a frontend-only
// extension of the generated `BackupInspection` with the file's picked source.
export interface BackupSelection extends BackupInspection {
  source: string
}

export type { DesktopUpdateStatus } from './generated/DesktopUpdateStatus'
export type { DesktopUpdateProgress } from './generated/DesktopUpdateProgress'

export type BrowserIntegrationCode =
  | 'ready'
  | 'hostMissing'
  | 'manifestMissing'
  | 'registrationMissing'
  | 'unsupported'

export type { BrowserIntegrationStatus } from './generated/BrowserIntegrationStatus'

// The other Browser*/*Fill*/*Cancelled types below have no Rust struct of the
// same shape (the frontend types are a derived/flattened view of a
// differently-named, differently-shaped Rust event type) and stay hand-written.
export type { BrowserFillCandidate } from './generated/BrowserFillCandidate'

export interface BrowserFillRequest {
  approvalId: string
  origin: string
  hostname: string
  candidates: BrowserFillCandidate[]
  expiresInSeconds: number
  expiresAtUnixMs: number
}

export interface BrowserFillCancelled {
  approvalId: string
  reason: 'denied' | 'expired' | 'connectionClosed' | 'vaultChanged'
}

export type IdentityFieldKey =
  | 'fullName'
  | 'email'
  | 'phone'
  | 'addressLine1'
  | 'addressLine2'
  | 'city'
  | 'region'
  | 'postalCode'
  | 'country'

export interface BrowserIdentityFillCandidate {
  id: string
  label: string
}

export interface BrowserIdentityFillRequest {
  approvalId: string
  origin: string
  hostname: string
  requestedFields: IdentityFieldKey[]
  candidates: BrowserIdentityFillCandidate[]
  expiresInSeconds: number
  expiresAtUnixMs: number
}

export interface BrowserIdentityFillCancelled {
  approvalId: string
  reason: 'denied' | 'expired' | 'connectionClosed' | 'vaultChanged'
}

export type CardFieldKey = 'cardholderName' | 'number' | 'expiryMonth' | 'expiryYear' | 'securityCode'

export interface BrowserCardFillCandidate {
  id: string
  title: string
  brand: string
  lastFour: string
}

export interface BrowserCardFillRequest {
  approvalId: string
  origin: string
  hostname: string
  requestedFields: CardFieldKey[]
  candidates: BrowserCardFillCandidate[]
  expiresInSeconds: number
  expiresAtUnixMs: number
}

export interface BrowserCardFillCancelled {
  approvalId: string
  reason: 'denied' | 'expired' | 'connectionClosed' | 'vaultChanged'
}

// No password field: it never leaves the Rust broker until the save is approved.
export interface BrowserSaveRequest {
  approvalId: string
  origin: string
  hostname: string
  /// 'new' or 'update', decided by the extension.
  kind: 'new' | 'update'
  title: string
  username: string
  candidates: BrowserFillCandidate[]
  expiresInSeconds: number
  expiresAtUnixMs: number
}

export interface BrowserSaveCancelled {
  approvalId: string
  reason: 'denied' | 'expired' | 'connectionClosed' | 'vaultChanged'
}

export type ImportSource =
  | 'bitwarden-csv'
  | 'bitwarden-json'
  | 'dashlane-csv'
  | 'lastpass-csv'
  | 'onepassword-csv'
  | 'keepass-csv'
  | 'chrome-csv'
  | 'edge-csv'
  | 'brave-csv'
  | 'google-csv'
  | 'apple-csv'
  | 'firefox-csv'
  | 'proton-pass-csv'
  | 'keeper-csv'
  | 'nordpass-csv'
  | 'otpauth-txt'
  | 'aegis-json'
  | '2fas-json'

export type View = 'vault' | 'authenticator' | 'security' | 'tools' | 'trash' | 'history' | 'backups' | 'settings'

export type VaultPane = 'list' | 'detail'

export interface NavigationItem {
  id: View
  label: string
  icon: string
}

export interface NavigationGroup {
  label: string
  items: NavigationItem[]
}

export type Theme = 'auto' | 'light' | 'dark'

export type SecurityFilter = IssueKind | null

export type GeneratorOption = 'lowercase' | 'uppercase' | 'numbers' | 'symbols'

/// Counts and timestamps only; the modal never reveals entries.
export interface SyncConflictSide {
  deviceLabel: string
  revision: number
  changedAt: string
  entryCount: number
}
