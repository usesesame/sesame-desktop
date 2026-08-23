export interface VaultStatus {
  exists: boolean
  unlocked: boolean
  preview: boolean
  pinUnlockAvailable: boolean
  helloUnlockAvailable: boolean
  onboardingRequired?: boolean
  vaultId?: string
  revision: number
}

export interface PlatformCapabilities {
  os: string
  pinUnlock: boolean
  biometricUnlock: boolean
  autoType: boolean
  browserIntegration: boolean
  sessionAutoLock: boolean
  accountLinking: boolean
}

export interface QuickAccessStatus {
  exists: boolean
  unlocked: boolean
}

/** One copyable field quick access offers for a given item kind. */
export interface QuickAccessAction {
  field: string
  label: string
  /** Needs a second, deliberate confirmation before the value is produced. */
  guarded: boolean
}

export interface QuickAccessItem {
  id: string
  kind: ItemKind
  title: string
  subtitle: string
  initials: string
  actions: QuickAccessAction[]
}

export interface QuickAccessValue {
  value: string
}

export type IssueKind = 'duplicate' | 'weak-password' | 'common-password' | 'reused-password' | 'compromised-pattern' | 'old-password' | 'url' | 'totp' | 'recovery'

export interface Folder {
  id: string
  name: string
}

export interface PasswordIssue {
  kind: 'weak-password' | 'common-password' | 'reused-password' | 'compromised-pattern'
  explanation: string
}

export interface PasswordAnalysis {
  score: number
  issues: PasswordIssue[]
}

export interface BreachCheckResult {
  breached: boolean
  count: number
}

export interface VaultEntry {
  id: string
  title: string
  site: string
  initials: string
  folderId?: string
  folder: string
  favourite: boolean
  lastUsedAt?: number
  passwordScore: number
  passwordIssues: PasswordIssue[]
  securityLevel: 'good' | 'needs-work'
  issueKinds: IssueKind[]
  tags: string[]
  updatedAt: number
}

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

/** One list row for a saved record other than a login. Non-secret metadata only. */
export interface VaultItemSummary {
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
}

export interface SecuritySummary {
  good: number
  needsAttention: number
  duplicateCandidates: number
  weakOrReused: number
  weakPasswords: number
  commonPasswords: number
  reusedPasswords: number
  compromisedPatterns: number
  oldPasswords: number
  missingUrls: number
  noTotp: number
  missingRecovery: number
}

export interface VaultSnapshot {
  vaultName: string
  vaultId?: string
  revision: number
  folders: Folder[]
  entries: VaultEntry[]
  items: VaultItemSummary[]
  trash: TrashSummary[]
  history: HistorySummary[]
  security: SecuritySummary
}

/** Metadata only; item titles stay in Rust until explicitly requested. */
export interface TrashSummary {
  id: string
  kind: string
  deletedAt: number
}

export interface RestoreTrashedItemResult {
  restoredId: string
  snapshot: VaultSnapshot
}

/** Non-secret preview for one explicitly chosen id; detail is never a password, key, or note content. */
export interface ItemPreview {
  kind: string
  title: string
  detail?: string
}

/** Metadata only; item titles stay in Rust until explicitly requested. */
export interface HistorySummary {
  id: string
  itemId: string
  kind: string
  capturedAt: number
  changed: string[]
}

export interface RestoreHistoryVersionResult {
  restoredId: string
  snapshot: VaultSnapshot
}

export interface Identity {
  id: string
  label: string
  tags: string[]
  fullName: string
  email: string
  phone: string
  addressLine1: string
  addressLine2: string
  city: string
  region: string
  postalCode: string
  country: string
  legacyFields?: LegacyField[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface IdentityInput {
  id?: string
  label: string
  tags: string[]
  fullName: string
  email: string
  phone: string
  addressLine1: string
  addressLine2: string
  city: string
  region: string
  postalCode: string
  country: string
}

export interface SaveIdentityResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteIdentityResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface SecureNote {
  id: string
  title: string
  content: string
  tags: string[]
  legacyFields?: LegacyField[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface SecureNoteInput {
  id?: string
  title: string
  content: string
  tags: string[]
}

export interface SaveSecureNoteResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteSecureNoteResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface Card {
  id: string
  title: string
  cardholderName: string
  number: string
  expiryMonth: string
  expiryYear: string
  securityCode: string
  brand: string
  notes: string
  tags: string[]
  legacyFields?: LegacyField[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface CardInput {
  id?: string
  title: string
  cardholderName: string
  number: string
  expiryMonth: string
  expiryYear: string
  securityCode: string
  brand: string
  notes: string
  tags: string[]
}

export interface SaveCardResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteCardResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface WifiNetwork {
  id: string
  title: string
  ssid: string
  password: string
  securityType: string
  notes: string
  tags: string[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface WifiNetworkInput {
  id?: string
  title: string
  ssid: string
  password: string
  securityType: string
  notes: string
  tags: string[]
}

export interface SaveWifiNetworkResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteWifiNetworkResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface SshKey {
  id: string
  title: string
  keyType: string
  privateKey: string
  publicKey: string
  passphrase: string
  notes: string
  tags: string[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface SshKeyInput {
  id?: string
  title: string
  keyType: string
  privateKey: string
  publicKey: string
  passphrase: string
  notes: string
  tags: string[]
}

export interface SaveSshKeyResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteSshKeyResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface SoftwareLicense {
  id: string
  title: string
  licenseKey: string
  productName: string
  purchasedFrom: string
  purchaseDate: string
  notes: string
  tags: string[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface SoftwareLicenseInput {
  id?: string
  title: string
  licenseKey: string
  productName: string
  purchasedFrom: string
  purchaseDate: string
  notes: string
  tags: string[]
}

export interface SaveSoftwareLicenseResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteSoftwareLicenseResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface Attachment {
  id: string
  filename: string
  contentType: string
  size: number
  data: string
}

export interface DocumentMetadata {
  id: string
  title: string
  documentType: string
  documentNumber: string
  issuingAuthority: string
  issueDate: string
  expiryDate: string
  notes: string
  tags: string[]
  attachments: Attachment[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface DocumentMetadataInput {
  id?: string
  title: string
  documentType: string
  documentNumber: string
  issuingAuthority: string
  issueDate: string
  expiryDate: string
  notes: string
  tags: string[]
}

export interface SaveDocumentMetadataResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteDocumentMetadataResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface CustomFieldEntry {
  label: string
  value: string
  kind: string
}

export interface CustomRecord {
  id: string
  title: string
  fields: CustomFieldEntry[]
  notes: string
  tags: string[]
  folderId?: string
  favourite: boolean
  lastUsedAt?: number
  updatedAt: number
}

export interface CustomRecordInput {
  id?: string
  title: string
  fields: CustomFieldEntry[]
  notes: string
  tags: string[]
}

export interface SaveCustomRecordResult {
  id: string
  snapshot: VaultSnapshot
}

export interface DeleteCustomRecordResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface VaultSetup {
  snapshot: VaultSnapshot
  recoveryKit: string
}

export interface ChangeMasterPasswordResult {
  recoveryKit: string
}

export interface LoginCard {
  id: string
  title: string
  site: string
  initials: string
  url: string
  urls?: string[]
  tags?: string[]
  username: string
  email: string
  password: string
  folderId?: string
  folder: string
  favourite: boolean
  lastUsedAt?: number
  totp?: string
  totpCode?: string
  totpRemaining?: number
  backupCodes?: string[]
  recoveryEmail?: string
  recoveryPhone?: string
  recoveryNotApplicable: boolean
  notes?: string
  legacyFields?: LegacyField[]
}

export interface LegacyField {
  label: string
  value: string
  secret: boolean
}

export interface LoginInput {
  id?: string
  title: string
  url: string
  urls?: string[]
  tags?: string[]
  username: string
  email: string
  password: string
  folder: string
  folderId?: string
  totp: string
  backupCodes: string[]
  recoveryEmail: string
  recoveryPhone: string
  recoveryNotApplicable: boolean
  notes: string
}

export interface LoginSummary {
  id: string
  title: string
  site: string
  username: string
  initials: string
  duplicateKey: string
}

export interface CleanupEntry {
  id: string
  title: string
  site: string
  username?: string
  initials?: string
  reason?: string
}

export interface DuplicateGroup {
  id: string
  label?: string
  site?: string
  entries: CleanupEntry[]
}

export interface TotpRefresh {
  totpCode: string | null
  totpRemaining: number | null
}

export interface SaveLoginResult {
  id: string
  snapshot: VaultSnapshot
}

/// Counts only; never carries a field value, label, or title.
export interface FidelityCounts {
  imported: number
  transformed: number
  legacy: number
  malformed: number
  intentionallyOmitted: number
}

export interface ImportFidelity {
  logins: FidelityCounts
  secureNotes: FidelityCounts
  cards: FidelityCounts
  identities: FidelityCounts
  sshKeys: FidelityCounts
  passkeys: FidelityCounts
  unsupportedItems: FidelityCounts
}

export interface ImportPreview {
  totalEntries: number
  exactDuplicates: number
  accountConflicts: number
  duplicateEntries: number
  missingUrls: number
  invalidUrls: number
  noTotp: number
  invalidTotp: number
  preservedLegacyFields: number
  secureNotes: number
  cards: number
  identities: number
  sshKeys: number
  passkeysNotImported: number
  intentionallyOmittedItems: number
  fidelity: ImportFidelity
}

/// Rust keeps the parsed entries; the interface receives counts and an id.
export interface ImportPreviewResult {
  importId: string
  preview: ImportPreview
}

export interface MergeCandidate {
  id: string
  title: string
  site: string
  username: string
  updatedAt: number
  revision: number
}

export interface MergeFieldOption {
  entryId: string
  value: string
  present: boolean
}

export interface MergeField {
  field: string
  label: string
  secret: boolean
  differs: boolean
  options: MergeFieldOption[]
}

export interface MergeComparison {
  entries: MergeCandidate[]
  fields: MergeField[]
}

export type MergeChoices = Record<string, string | undefined>

export interface ImportResult {
  snapshot: VaultSnapshot
  importedEntries: number
  importedSecureNotes: number
  importedCards: number
  importedIdentities: number
  importedSshKeys: number
  skippedExactDuplicates: number
  revisionBackupName?: string
}

export interface BackupInspection {
  fileName: string
  formatVersion: number
}

export interface BackupVerification {
  fileName: string
  formatVersion: number
  vaultName: string
  entryCount: number
  vaultId?: string
  revision: number
}

export interface BackupSelection extends BackupInspection {
  source: string
}

export interface RecoveryHealth {
  vaultId: string
  lastExportedRevision?: number
  lastExportedAt?: string
  lastVerifiedRevision?: number
  lastVerifiedAt?: string
}

export interface RestoreBackupResult {
  safetyBackupName?: string
  pinUnlockAvailable: boolean
  helloUnlockAvailable: boolean
}

export interface DiagnosticStatus {
  exists: boolean
  eventCount: number
  errorCount: number
  sizeBytes: number
  localOnly: boolean
  byOperation: { operation: string; count: number; errorCount: number }[]
  byCode: { code: string; count: number; level: string }[]
  recent: { timestamp: number; operation: string; code: string; level: string }[]
}

export interface WebsiteIconCacheStatus {
  entryCount: number
  iconCount: number
  sizeBytes: number
}

export interface ServiceConnectionStatus {
  state: 'disconnected' | 'connected' | 'suspended' | 'revoked' | 'offline' | 'rateLimited' | 'serviceUnavailable' | 'needsAttention'
  connected: boolean
  online: boolean
  deviceName?: string
  syncAvailable: boolean
  browserHelperAvailable: boolean
}

export interface DesktopUpdateStatus {
  available: boolean
  version?: string
  body?: string
}

export interface DesktopUpdateProgress {
  downloadedBytes: number
  totalBytes?: number
}

export type BrowserIntegrationCode =
  | 'ready'
  | 'hostMissing'
  | 'manifestMissing'
  | 'registrationMissing'
  | 'unsupported'

export interface BrowserIntegrationStatus {
  supported: boolean
  hostAvailable: boolean
  manifestReady: boolean
  chromeRegistered: boolean
  edgeRegistered: boolean
  firefoxRegistered: boolean
  ready: boolean
  code: BrowserIntegrationCode
}

export interface BrowserFillCandidate {
  id: string
  title: string
  username: string
  email: string
  savedOrigin: string
  matchKind: 'exact' | 'wwwAlias'
}

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

export interface DeleteLoginResult {
  deletedId: string
  snapshot: VaultSnapshot
}

export interface MergeDuplicateLoginsResult {
  id: string
  snapshot: VaultSnapshot
  revisionBackupName?: string
}

export interface MasterPasswordRequest {
  masterPassword: string
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

export interface TotpCodeEntry {
  id: string
  title: string
  site: string
  initials: string
  code: string
  remaining: number
  period: number
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
