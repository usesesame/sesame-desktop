use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::util::domain_from_url;

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordRequest {
    pub master_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordResult {
    pub recovery_kit: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub preview: bool,
    pub pin_unlock_available: bool,
    pub hello_unlock_available: bool,
    pub onboarding_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    pub revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockPinRequest {
    pub pin: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKitRequest {
    pub recovery_kit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreBackupRequest {
    pub source: String,
    pub secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopLinkResponse {
    pub access_token: String,
    pub device: DesktopServiceDevice,
    pub sync_available: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopServiceDevice {
    pub device_id: String,
    pub device_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopServiceStatusResponse {
    pub connected: bool,
    pub device: DesktopServiceDevice,
    pub sync_available: bool,
    pub browser_helper_available: bool,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConnectionStatus {
    // Rust leaves this a plain `String`; override to keep the frontend's
    // closed literal union instead of widening to `string`.
    #[ts(
        type = "'disconnected' | 'connected' | 'suspended' | 'revoked' | 'offline' | 'rateLimited' | 'serviceUnavailable' | 'needsAttention'"
    )]
    pub state: String,
    pub connected: bool,
    pub online: bool,
    pub device_name: Option<String>,
    pub sync_available: bool,
    pub browser_helper_available: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConnectionFile {
    pub format_version: u8,
    pub api_base_url: String,
    pub protected_token: String,
    pub device_id: String,
    pub device_name: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct VaultSetup {
    pub snapshot: VaultSnapshot,
    pub recovery_kit: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct VaultSnapshot {
    pub vault_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    pub revision: u64,
    pub folders: Vec<Folder>,
    pub entries: Vec<VaultEntrySummary>,
    pub items: Vec<VaultItemSummary>,
    pub trash: Vec<TrashSummary>,
    pub history: Vec<HistorySummary>,
    pub security: SecuritySummary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

// Exported to the frontend as `VaultEntry` (see src/lib/types.ts), not under
// this Rust name: the frontend's `VaultEntry` name is already taken by the
// full secret-bearing login record (this file's other `VaultEntry` struct,
// never exposed to the frontend under that shape). Do not derive TS on that
// other struct.
#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntrySummary {
    pub id: String,
    pub title: String,
    pub site: String,
    pub initials: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub folder: String,
    pub favourite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    pub password_score: u8,
    pub password_issues: Vec<PasswordIssue>,
    // Rust leaves this a plain `&'static str`; override to keep the frontend's
    // closed literal union instead of widening to `string`.
    #[ts(type = "'good' | 'needs-work'")]
    pub security_level: &'static str,
    #[ts(
        type = "Array<'duplicate' | 'weak-password' | 'common-password' | 'reused-password' | 'compromised-pattern' | 'old-password' | 'url' | 'totp' | 'recovery'>"
    )]
    pub issue_kinds: Vec<&'static str>,
    pub tags: Vec<String>,
    pub updated_at: u64,
}

/// Non-secret metadata only; a login is summarised by VaultEntrySummary instead.
#[derive(Serialize, Clone, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct VaultItemSummary {
    pub id: String,
    // Rust leaves this a plain `&'static str`; override to keep the frontend's
    // closed `ItemKind` union (kept in sync by hand, ts-rs cannot import a
    // type from the hand-written barrel file into a generated one).
    #[ts(
        type = "'login' | 'identity' | 'secure_note' | 'card' | 'wifi_network' | 'ssh_key' | 'software_license' | 'document' | 'custom_record'"
    )]
    pub kind: &'static str,
    pub title: String,
    /// Never a stored secret: a domain, an SSID, a card brand, a product name.
    pub subtitle: String,
    pub initials: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub folder: String,
    pub favourite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    pub updated_at: u64,
    pub tags: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct PasswordIssue {
    // Rust leaves this a plain `&'static str` (not an enum), but the frontend
    // relies on the closed literal union for exhaustiveness checks. Override
    // rather than widen to `string` and silently drop that guard.
    #[ts(type = "'weak-password' | 'common-password' | 'reused-password' | 'compromised-pattern'")]
    pub kind: &'static str,
    pub explanation: &'static str,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummary {
    pub good: usize,
    pub needs_attention: usize,
    pub duplicate_candidates: usize,
    pub weak_or_reused: usize,
    pub weak_passwords: usize,
    pub common_passwords: usize,
    pub reused_passwords: usize,
    pub compromised_patterns: usize,
    pub old_passwords: usize,
    pub missing_urls: usize,
    pub no_totp: usize,
    pub missing_recovery: usize,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct LoginCard {
    pub id: String,
    pub title: String,
    pub site: String,
    pub initials: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub folder: String,
    pub favourite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    pub has_totp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_remaining: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_phone: Option<String>,
    pub recovery_not_applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_fields: Vec<LegacyField>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct LoginSummary {
    pub id: String,
    pub title: String,
    pub site: String,
    pub username: String,
    pub initials: String,
    pub duplicate_key: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CleanupEntry {
    pub id: String,
    pub title: String,
    pub site: String,
    pub username: String,
    pub initials: String,
    pub reason: &'static str,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateGroup {
    pub id: String,
    pub label: String,
    pub site: String,
    pub entries: Vec<CleanupEntry>,
}

/// Codes for the authenticator view. Derived values only: the seed stays in Rust.
#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct TotpCodeEntry {
    pub id: String,
    pub title: String,
    pub site: String,
    pub initials: String,
    pub code: String,
    pub remaining: u64,
    /// The full window, so the interface can draw how much of it is left.
    pub period: u64,
}

// No `optional_fields`: these two fields carry no `skip_serializing_if`, so
// Rust always serializes the key and sends `null` for None. That is a real
// `T | null`, not an omittable `T | undefined`; keep it that way.
#[derive(Serialize, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TotpRefresh {
    pub totp_code: Option<String>,
    pub totp_remaining: Option<u64>,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub backup_codes: Vec<String>,
    #[serde(default)]
    pub recovery_email: String,
    #[serde(default)]
    pub recovery_phone: String,
    #[serde(default)]
    pub recovery_not_applicable: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveLoginResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteLoginResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

// Not ts-rs derived: the frontend needs a string index signature here (an
// arbitrary field name chosen at render time), not this struct's fixed
// field names. See src/lib/types.ts's hand-written `MergeChoices`.
#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MergeChoices {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub recovery_email: Option<String>,
    #[serde(default)]
    pub recovery_phone: Option<String>,
    #[serde(default)]
    pub backup_codes: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeDuplicateLoginsRequest {
    pub keep_id: String,
    pub remove_ids: Vec<String>,
    #[serde(default)]
    pub choices: MergeChoices,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MergeCandidate {
    pub id: String,
    pub title: String,
    pub site: String,
    pub username: String,
    pub updated_at: u64,
    pub revision: u32,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MergeFieldOption {
    pub entry_id: String,
    pub value: String,
    pub present: bool,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MergeField {
    pub field: String,
    pub label: String,
    pub secret: bool,
    pub differs: bool,
    pub options: Vec<MergeFieldOption>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MergeComparison {
    pub entries: Vec<MergeCandidate>,
    pub fields: Vec<MergeField>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct MergeDuplicateLoginsResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
    pub revision_backup_name: Option<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub total_entries: usize,
    pub exact_duplicates: usize,
    pub account_conflicts: usize,
    pub duplicate_entries: usize,
    pub missing_urls: usize,
    pub invalid_urls: usize,
    pub no_totp: usize,
    pub invalid_totp: usize,
    pub preserved_legacy_fields: usize,
    pub secure_notes: usize,
    pub cards: usize,
    pub identities: usize,
    pub ssh_keys: usize,
    /// Passkeys are readable in the export but Sesame cannot store them yet.
    pub passkeys_not_imported: usize,
    pub intentionally_omitted_items: usize,
    pub fidelity: ImportFidelity,
}

/// Dispositions mirror the import fidelity report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldDisposition {
    Imported,
    Transformed,
    Legacy,
    Malformed,
    IntentionallyOmitted,
}

#[derive(Default, Clone, Copy, Debug, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct FidelityCounts {
    pub imported: usize,
    pub transformed: usize,
    pub legacy: usize,
    pub malformed: usize,
    pub intentionally_omitted: usize,
}

impl FidelityCounts {
    pub fn record(&mut self, disposition: FieldDisposition) {
        match disposition {
            FieldDisposition::Imported => self.imported += 1,
            FieldDisposition::Transformed => self.transformed += 1,
            FieldDisposition::Legacy => self.legacy += 1,
            FieldDisposition::Malformed => self.malformed += 1,
            FieldDisposition::IntentionallyOmitted => self.intentionally_omitted += 1,
        }
    }
}

#[derive(Default, Clone, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ImportFidelity {
    pub logins: FidelityCounts,
    pub secure_notes: FidelityCounts,
    pub cards: FidelityCounts,
    pub identities: FidelityCounts,
    pub ssh_keys: FidelityCounts,
    pub passkeys: FidelityCounts,
    pub unsupported_items: FidelityCounts,
}

/// Only counts and an opaque id cross to the interface; entries stay in Rust until commit.
#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewResult {
    pub import_id: String,
    pub preview: ImportPreview,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub snapshot: VaultSnapshot,
    pub imported_entries: usize,
    pub imported_secure_notes: usize,
    pub imported_cards: usize,
    pub imported_identities: usize,
    pub imported_ssh_keys: usize,
    pub skipped_exact_duplicates: usize,
    pub revision_backup_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingImportRelation {
    None,
    ExactDuplicate,
    AccountConflict,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BackupInspection {
    pub file_name: String,
    pub format_version: u8,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RestoreBackupResult {
    pub safety_backup_name: Option<String>,
    pub pin_unlock_available: bool,
    pub hello_unlock_available: bool,
}

/// Proves the encrypted payload opens; never replaces the active vault.
#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BackupVerification {
    pub file_name: String,
    pub format_version: u8,
    pub vault_name: String,
    pub entry_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    pub revision: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultFile {
    pub format_version: u8,
    pub kdf: KdfParams,
    pub key_wrap: CipherBlob,
    #[serde(
        default,
        rename = "deviceWrap",
        skip_serializing_if = "Option::is_none"
    )]
    pub legacy_device_wrap: Option<String>,
    // Independent recovery-kit wrap: recovery needs no Sesame service.
    #[serde(default)]
    pub recovery_kdf: Option<KdfParams>,
    #[serde(default)]
    pub recovery_wrap: Option<CipherBlob>,
    #[serde(default)]
    pub pin_wrap: Option<PinWrap>,
    // Released only through a fresh Windows Hello gesture.
    #[serde(default)]
    pub hello_wrap: Option<HelloWrap>,
    // Vaults stay unusable until the Rust host verifies the recovery kit.
    #[serde(default = "setup_complete_by_default")]
    pub setup_complete: bool,
    pub payload: CipherBlob,
}

fn setup_complete_by_default() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinWrap {
    pub kdf: KdfParams,
    pub protected_pepper: String,
    pub key_wrap: CipherBlob,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloWrap {
    /// Device-local Passport-KSP key name; private part cannot be exported.
    pub key_name: String,
    /// Vault key RSA-OAEP-wrapped; only a fresh Hello gesture on this device can decrypt it.
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CipherBlob {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Default)]
pub struct VaultPayload {
    pub vault_name: String,
    pub folders: Vec<Folder>,
    pub entries: Vec<VaultEntry>,
    pub identities: Vec<Identity>,
    pub secure_notes: Vec<SecureNote>,
    pub cards: Vec<Card>,
    pub wifi_networks: Vec<WifiNetwork>,
    pub ssh_keys: Vec<SshKey>,
    pub software_licenses: Vec<SoftwareLicense>,
    pub documents: Vec<DocumentMetadata>,
    pub custom_records: Vec<CustomRecord>,
    pub trash: Vec<TrashedItem>,
    pub history: Vec<HistoryEntry>,
    pub vault_id: Option<String>,
    pub revision: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaggedItem {
    Login(VaultEntry),
    Identity(Identity),
    SecureNote(SecureNote),
    Card(Card),
    WifiNetwork(WifiNetwork),
    SshKey(SshKey),
    SoftwareLicense(SoftwareLicense),
    Document(DocumentMetadata),
    CustomRecord(CustomRecord),
}

impl TaggedItem {
    pub fn id(&self) -> &str {
        match self {
            TaggedItem::Login(item) => &item.id,
            TaggedItem::Identity(item) => &item.id,
            TaggedItem::SecureNote(item) => &item.id,
            TaggedItem::Card(item) => &item.id,
            TaggedItem::WifiNetwork(item) => &item.id,
            TaggedItem::SshKey(item) => &item.id,
            TaggedItem::SoftwareLicense(item) => &item.id,
            TaggedItem::Document(item) => &item.id,
            TaggedItem::CustomRecord(item) => &item.id,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TaggedItem::Login(_) => "login",
            TaggedItem::Identity(_) => "identity",
            TaggedItem::SecureNote(_) => "secure_note",
            TaggedItem::Card(_) => "card",
            TaggedItem::WifiNetwork(_) => "wifi_network",
            TaggedItem::SshKey(_) => "ssh_key",
            TaggedItem::SoftwareLicense(_) => "software_license",
            TaggedItem::Document(_) => "document",
            TaggedItem::CustomRecord(_) => "custom_record",
        }
    }

    pub fn metadata(&self) -> &dyn ItemMetadata {
        match self {
            TaggedItem::Login(item) => item,
            TaggedItem::Identity(item) => item,
            TaggedItem::SecureNote(item) => item,
            TaggedItem::Card(item) => item,
            TaggedItem::WifiNetwork(item) => item,
            TaggedItem::SshKey(item) => item,
            TaggedItem::SoftwareLicense(item) => item,
            TaggedItem::Document(item) => item,
            TaggedItem::CustomRecord(item) => item,
        }
    }

    /// Non-secret preview; never embedded in a bulk snapshot.
    pub fn preview(&self) -> ItemPreview {
        let kind = self.kind().to_string();
        match self {
            TaggedItem::Login(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: non_empty_owned(&item.username)
                    .or_else(|| non_empty_owned(&item.url).map(|url| domain_from_url(&url))),
            },
            TaggedItem::Identity(item) => ItemPreview {
                kind,
                title: item.label.clone(),
                detail: non_empty_owned(&item.full_name).or_else(|| non_empty_owned(&item.email)),
            },
            TaggedItem::SecureNote(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: None,
            },
            TaggedItem::Card(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: card_preview_detail(item),
            },
            TaggedItem::WifiNetwork(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: non_empty_owned(&item.ssid),
            },
            TaggedItem::SshKey(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: non_empty_owned(&item.key_type),
            },
            TaggedItem::SoftwareLicense(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: non_empty_owned(&item.product_name),
            },
            TaggedItem::Document(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: non_empty_owned(&item.document_type),
            },
            TaggedItem::CustomRecord(item) => ItemPreview {
                kind,
                title: item.title.clone(),
                detail: None,
            },
        }
    }
}

pub trait ItemMetadata {
    fn item_title(&self) -> &str;
    fn item_tags(&self) -> &[String];
    fn item_folder_id(&self) -> Option<&str>;
    fn set_item_folder_id(&mut self, folder_id: Option<String>);
    fn item_favourite(&self) -> bool;
    fn set_item_favourite(&mut self, favourite: bool);
    fn item_last_used_at(&self) -> Option<u64>;
    fn set_item_last_used_at(&mut self, last_used_at: Option<u64>);
    fn item_updated_at(&self) -> u64;
    fn mark_item_changed(&mut self, now: u64);
}

macro_rules! impl_item_metadata {
    ($item:ty, $title:ident) => {
        impl ItemMetadata for $item {
            fn item_title(&self) -> &str {
                &self.$title
            }
            fn item_tags(&self) -> &[String] {
                &self.tags
            }
            fn item_folder_id(&self) -> Option<&str> {
                self.folder_id.as_deref()
            }
            fn set_item_folder_id(&mut self, folder_id: Option<String>) {
                self.folder_id = folder_id;
            }
            fn item_favourite(&self) -> bool {
                self.favourite
            }
            fn set_item_favourite(&mut self, favourite: bool) {
                self.favourite = favourite;
            }
            fn item_last_used_at(&self) -> Option<u64> {
                self.last_used_at
            }
            fn set_item_last_used_at(&mut self, last_used_at: Option<u64>) {
                self.last_used_at = last_used_at;
            }
            fn item_updated_at(&self) -> u64 {
                self.updated_at
            }
            fn mark_item_changed(&mut self, now: u64) {
                self.updated_at = now;
                self.revision = self.revision.saturating_add(1);
            }
        }
    };
}

impl_item_metadata!(Identity, label);
impl_item_metadata!(SecureNote, title);
impl_item_metadata!(Card, title);
impl_item_metadata!(WifiNetwork, title);
impl_item_metadata!(SshKey, title);
impl_item_metadata!(SoftwareLicense, title);
impl_item_metadata!(DocumentMetadata, title);
impl_item_metadata!(CustomRecord, title);

impl ItemMetadata for VaultEntry {
    fn item_title(&self) -> &str {
        &self.title
    }
    fn item_tags(&self) -> &[String] {
        &self.tags
    }
    fn item_folder_id(&self) -> Option<&str> {
        self.folder_id.as_deref()
    }
    fn set_item_folder_id(&mut self, folder_id: Option<String>) {
        self.folder_id = folder_id;
        // Only transient imports and pre-migration payloads carry a folder name.
        self.folder.clear();
    }
    fn item_favourite(&self) -> bool {
        self.favourite
    }
    fn set_item_favourite(&mut self, favourite: bool) {
        self.favourite = favourite;
    }
    fn item_last_used_at(&self) -> Option<u64> {
        self.last_used_at
    }
    fn set_item_last_used_at(&mut self, last_used_at: Option<u64>) {
        self.last_used_at = last_used_at;
    }
    fn item_updated_at(&self) -> u64 {
        self.updated_at
    }
    fn mark_item_changed(&mut self, now: u64) {
        self.updated_at = now;
        self.revision = self.revision.saturating_add(1);
    }
}

fn non_empty_owned(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn card_preview_detail(card: &Card) -> Option<String> {
    let digits: String = card.number.chars().filter(|c| c.is_ascii_digit()).collect();
    let last_four = (digits.len() >= 4).then(|| digits[digits.len() - 4..].to_string());
    match (non_empty_owned(&card.brand), last_four) {
        (Some(brand), Some(last_four)) => Some(format!("{brand} •••• {last_four}")),
        (Some(brand), None) => Some(brand),
        (None, Some(last_four)) => Some(format!("•••• {last_four}")),
        (None, None) => None,
    }
}

#[derive(Serialize, Clone, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ItemPreview {
    pub kind: String,
    pub title: String,
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrashedItem {
    pub item: TaggedItem,
    pub deleted_at: u64,
}

#[derive(Serialize, Clone, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct TrashSummary {
    pub id: String,
    pub kind: String,
    pub deleted_at: u64,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RestoreTrashedItemResult {
    pub restored_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryEntry {
    pub id: String,
    pub item: TaggedItem,
    pub captured_at: u64,
    #[serde(default)]
    pub operation: HistoryOperation,
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum HistoryOperation {
    #[default]
    Edit,
    Restore,
}

#[derive(Serialize, Clone, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct HistorySummary {
    pub id: String,
    pub item_id: String,
    pub kind: String,
    pub captured_at: u64,
    pub operation: HistoryOperation,
    /// Field names that differ from whatever replaced this version. Names only.
    pub changed: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RestoreHistoryVersionResult {
    pub restored_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, optional_fields)]
pub struct Identity {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address_line1: String,
    #[serde(default)]
    pub address_line2: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub legacy_fields: Vec<LegacyField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInput {
    #[serde(default)]
    pub id: Option<String>,
    pub label: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub address_line1: String,
    #[serde(default)]
    pub address_line2: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveIdentityResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteIdentityResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecureNote {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub legacy_fields: Vec<LegacyField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveSecureNoteResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSecureNoteResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Card {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub cardholder_name: String,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub expiry_month: String,
    #[serde(default)]
    pub expiry_year: String,
    #[serde(default)]
    pub security_code: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub legacy_fields: Vec<LegacyField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CardInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub cardholder_name: String,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub expiry_month: String,
    #[serde(default)]
    pub expiry_year: String,
    #[serde(default)]
    pub security_code: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveCardResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCardResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WifiNetwork {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub security_type: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct WifiNetworkInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub security_type: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveWifiNetworkResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWifiNetworkResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SshKey {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub passphrase: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub passphrase: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveSshKeyResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSshKeyResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareLicense {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub license_key: String,
    #[serde(default)]
    pub product_name: String,
    #[serde(default)]
    pub purchased_from: String,
    #[serde(default)]
    pub purchase_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareLicenseInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub license_key: String,
    #[serde(default)]
    pub product_name: String,
    #[serde(default)]
    pub purchased_from: String,
    #[serde(default)]
    pub purchase_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveSoftwareLicenseResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSoftwareLicenseResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentMetadata {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub document_type: String,
    #[serde(default)]
    pub document_number: String,
    #[serde(default)]
    pub issuing_authority: String,
    #[serde(default)]
    pub issue_date: String,
    #[serde(default)]
    pub expiry_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

#[derive(Serialize, Deserialize, Clone, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attachment {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    #[serde(with = "attachment_data_base64")]
    #[ts(type = "string")]
    pub data: Vec<u8>,
}

mod attachment_data_base64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadataInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub document_type: String,
    #[serde(default)]
    pub document_number: String,
    #[serde(default)]
    pub issuing_authority: String,
    #[serde(default)]
    pub issue_date: String,
    #[serde(default)]
    pub expiry_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveDocumentMetadataResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDocumentMetadataResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomFieldEntry {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub kind: String,
}

#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomRecord {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub fields: Vec<CustomFieldEntry>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revision: u32,
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CustomRecordInput {
    #[serde(default)]
    pub id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub fields: Vec<CustomFieldEntry>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct SaveCustomRecordResult {
    pub id: String,
    pub snapshot: VaultSnapshot,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCustomRecordResult {
    pub deleted_id: String,
    pub snapshot: VaultSnapshot,
}

// Deliberately not ts-rs derived: this is the full secret-bearing login
// record (password, totp, backup codes, recovery contacts). The frontend
// name `VaultEntry` refers to `VaultEntrySummary` instead, see there.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub username: String,
    #[serde(default)]
    pub email: String,
    pub password: String,
    #[serde(default, skip_serializing)]
    pub folder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favourite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub backup_codes: Vec<String>,
    #[serde(default)]
    pub recovery_email: Option<String>,
    #[serde(default)]
    pub recovery_phone: Option<String>,
    #[serde(default)]
    pub recovery_not_applicable: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub password_updated_at: u64,
    #[serde(default)]
    pub revision: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_fields: Vec<LegacyField>,
}

/// Unknown import values default to `secret`, so the UI never reveals them unprompted.
#[derive(Serialize, Deserialize, Clone, Default, ts_rs::TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export)]
pub struct LegacyField {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedVaultPayloadV8<'a> {
    vault_name: &'a str,
    folders: &'a [Folder],
    items: Vec<TaggedItem>,
    trash: &'a [TrashedItem],
    history: &'a [HistoryEntry],
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: &'a Option<String>,
    revision: u64,
}

/// Private: an older binary is rejected before it can decrypt a v8 payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredVaultPayload {
    vault_name: String,
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    items: Option<Vec<TaggedItem>>,
    #[serde(default)]
    entries: Vec<VaultEntry>,
    #[serde(default)]
    identities: Vec<Identity>,
    #[serde(default)]
    secure_notes: Vec<SecureNote>,
    #[serde(default)]
    cards: Vec<Card>,
    #[serde(default)]
    wifi_networks: Vec<WifiNetwork>,
    #[serde(default)]
    ssh_keys: Vec<SshKey>,
    #[serde(default)]
    software_licenses: Vec<SoftwareLicense>,
    #[serde(default)]
    documents: Vec<DocumentMetadata>,
    #[serde(default)]
    custom_records: Vec<CustomRecord>,
    #[serde(default)]
    trash: Vec<TrashedItem>,
    #[serde(default)]
    history: Vec<HistoryEntry>,
    #[serde(default)]
    vault_id: Option<String>,
    #[serde(default)]
    revision: u64,
}

impl VaultPayload {
    pub fn item_views(&self) -> Vec<TaggedItem> {
        let mut items = Vec::with_capacity(
            self.entries.len()
                + self.identities.len()
                + self.secure_notes.len()
                + self.cards.len()
                + self.wifi_networks.len()
                + self.ssh_keys.len()
                + self.software_licenses.len()
                + self.documents.len()
                + self.custom_records.len(),
        );
        macro_rules! append_item_views {
            ($collection:expr, $variant:ident) => {
                items.extend($collection.iter().cloned().map(TaggedItem::$variant));
            };
        }
        append_item_views!(&self.entries, Login);
        append_item_views!(&self.identities, Identity);
        append_item_views!(&self.secure_notes, SecureNote);
        append_item_views!(&self.cards, Card);
        append_item_views!(&self.wifi_networks, WifiNetwork);
        append_item_views!(&self.ssh_keys, SshKey);
        append_item_views!(&self.software_licenses, SoftwareLicense);
        append_item_views!(&self.documents, Document);
        append_item_views!(&self.custom_records, CustomRecord);
        items
    }

    pub fn item_metadata_mut(&mut self, id: &str) -> Option<&mut dyn ItemMetadata> {
        macro_rules! find_item {
            ($collection:expr) => {
                if let Some(item) = $collection.iter_mut().find(|item| item.id == id) {
                    return Some(item);
                }
            };
        }
        find_item!(self.entries);
        find_item!(self.identities);
        find_item!(self.secure_notes);
        find_item!(self.cards);
        find_item!(self.wifi_networks);
        find_item!(self.ssh_keys);
        find_item!(self.software_licenses);
        find_item!(self.documents);
        find_item!(self.custom_records);
        None
    }

    pub fn active_item(&self, id: &str) -> Option<TaggedItem> {
        self.item_views().into_iter().find(|item| item.id() == id)
    }

    pub fn insert_active_item(&mut self, item: TaggedItem) -> Result<(), String> {
        if self.active_item(item.id()).is_some() {
            return Err("A saved item with that id already exists.".into());
        }
        match item {
            TaggedItem::Login(item) => self.entries.push(item),
            TaggedItem::Identity(item) => self.identities.push(item),
            TaggedItem::SecureNote(item) => self.secure_notes.push(item),
            TaggedItem::Card(item) => self.cards.push(item),
            TaggedItem::WifiNetwork(item) => self.wifi_networks.push(item),
            TaggedItem::SshKey(item) => self.ssh_keys.push(item),
            TaggedItem::SoftwareLicense(item) => self.software_licenses.push(item),
            TaggedItem::Document(item) => self.documents.push(item),
            TaggedItem::CustomRecord(item) => self.custom_records.push(item),
        }
        Ok(())
    }

    pub fn take_active_item(&mut self, id: &str) -> Option<TaggedItem> {
        macro_rules! take_item {
            ($collection:expr, $variant:ident) => {
                if let Some(index) = $collection.iter().position(|item| item.id == id) {
                    return Some(TaggedItem::$variant($collection.remove(index)));
                }
            };
        }
        take_item!(self.entries, Login);
        take_item!(self.identities, Identity);
        take_item!(self.secure_notes, SecureNote);
        take_item!(self.cards, Card);
        take_item!(self.wifi_networks, WifiNetwork);
        take_item!(self.ssh_keys, SshKey);
        take_item!(self.software_licenses, SoftwareLicense);
        take_item!(self.documents, Document);
        take_item!(self.custom_records, CustomRecord);
        None
    }

    fn active_items(&self) -> Result<Vec<TaggedItem>, &'static str> {
        let mut ids = std::collections::HashSet::new();
        let items = self.item_views();
        for item in &items {
            if !ids.insert(item.id().to_string()) {
                return Err("The vault contains duplicate item ids and cannot be migrated safely.");
            }
        }
        Ok(items)
    }

    fn from_stored(stored: StoredVaultPayload) -> Result<Self, &'static str> {
        let mut payload = Self {
            vault_name: stored.vault_name,
            folders: stored.folders,
            entries: stored.entries,
            identities: stored.identities,
            secure_notes: stored.secure_notes,
            cards: stored.cards,
            wifi_networks: stored.wifi_networks,
            ssh_keys: stored.ssh_keys,
            software_licenses: stored.software_licenses,
            documents: stored.documents,
            custom_records: stored.custom_records,
            trash: stored.trash,
            history: stored.history,
            vault_id: stored.vault_id,
            revision: stored.revision,
        };
        let Some(items) = stored.items else {
            return Ok(payload);
        };
        if !payload.entries.is_empty()
            || !payload.identities.is_empty()
            || !payload.secure_notes.is_empty()
            || !payload.cards.is_empty()
            || !payload.wifi_networks.is_empty()
            || !payload.ssh_keys.is_empty()
            || !payload.software_licenses.is_empty()
            || !payload.documents.is_empty()
            || !payload.custom_records.is_empty()
        {
            return Err("The vault mixes legacy collections with v8 items.");
        }
        let mut ids = std::collections::HashSet::new();
        for item in items {
            if !ids.insert(item.id().to_string()) {
                return Err("The vault contains duplicate item ids.");
            }
            match item {
                TaggedItem::Login(item) => payload.entries.push(item),
                TaggedItem::Identity(item) => payload.identities.push(item),
                TaggedItem::SecureNote(item) => payload.secure_notes.push(item),
                TaggedItem::Card(item) => payload.cards.push(item),
                TaggedItem::WifiNetwork(item) => payload.wifi_networks.push(item),
                TaggedItem::SshKey(item) => payload.ssh_keys.push(item),
                TaggedItem::SoftwareLicense(item) => payload.software_licenses.push(item),
                TaggedItem::Document(item) => payload.documents.push(item),
                TaggedItem::CustomRecord(item) => payload.custom_records.push(item),
            }
        }
        Ok(payload)
    }
}

impl TaggedItem {
    pub(crate) fn restored_over(self, current: TaggedItem, now: u64) -> Result<Self, String> {
        macro_rules! restore {
            ($restored:ident, $current:ident, $variant:ident) => {{
                $restored.created_at = $current.created_at;
                $restored.updated_at = now;
                $restored.revision = $current.revision.saturating_add(1);
                Ok(TaggedItem::$variant($restored))
            }};
        }
        match (self, current) {
            (TaggedItem::Login(mut restored), TaggedItem::Login(current)) => {
                restore!(restored, current, Login)
            }
            (TaggedItem::Identity(mut restored), TaggedItem::Identity(current)) => {
                restore!(restored, current, Identity)
            }
            (TaggedItem::SecureNote(mut restored), TaggedItem::SecureNote(current)) => {
                restore!(restored, current, SecureNote)
            }
            (TaggedItem::Card(mut restored), TaggedItem::Card(current)) => {
                restore!(restored, current, Card)
            }
            (TaggedItem::WifiNetwork(mut restored), TaggedItem::WifiNetwork(current)) => {
                restore!(restored, current, WifiNetwork)
            }
            (TaggedItem::SshKey(mut restored), TaggedItem::SshKey(current)) => {
                restore!(restored, current, SshKey)
            }
            (TaggedItem::SoftwareLicense(mut restored), TaggedItem::SoftwareLicense(current)) => {
                restore!(restored, current, SoftwareLicense)
            }
            (TaggedItem::Document(mut restored), TaggedItem::Document(current)) => {
                restore!(restored, current, Document)
            }
            (TaggedItem::CustomRecord(mut restored), TaggedItem::CustomRecord(current)) => {
                restore!(restored, current, CustomRecord)
            }
            _ => Err(
                "The saved item's kind changed, so that version cannot be restored safely.".into(),
            ),
        }
    }
}

impl Serialize for VaultPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let items = self.active_items().map_err(serde::ser::Error::custom)?;
        PersistedVaultPayloadV8 {
            vault_name: &self.vault_name,
            folders: &self.folders,
            items,
            trash: &self.trash,
            history: &self.history,
            vault_id: &self.vault_id,
            revision: self.revision,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VaultPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stored = StoredVaultPayload::deserialize(deserializer)?;
        Self::from_stored(stored).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
pub struct BitwardenCsvEntry {
    #[serde(default)]
    pub folder: String,
    #[serde(default, rename = "type")]
    pub item_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub login_uri: String,
    #[serde(default)]
    pub login_username: String,
    #[serde(default)]
    pub login_password: String,
    #[serde(default)]
    pub login_totp: String,
}

#[derive(Deserialize)]
pub struct LastPassCsvEntry {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub extra: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub grouping: String,
}

#[derive(Deserialize)]
pub struct AegisExport {
    #[serde(default)]
    pub db: AegisDb,
}

#[derive(Deserialize, Default)]
pub struct AegisDb {
    #[serde(default)]
    pub entries: Vec<AegisEntry>,
}

#[derive(Deserialize)]
pub struct AegisEntry {
    #[serde(default, rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub info: AegisInfo,
}

#[derive(Deserialize, Default)]
pub struct AegisInfo {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub algo: String,
    #[serde(default)]
    pub digits: Option<u32>,
    #[serde(default)]
    pub period: Option<u64>,
}

#[derive(Deserialize)]
pub struct TwoFasExport {
    #[serde(default)]
    pub services: Vec<TwoFasService>,
    /// Present when the export was made with a password, in which case services is empty.
    #[serde(default, rename = "servicesEncrypted")]
    pub services_encrypted: String,
}

#[derive(Deserialize)]
pub struct TwoFasService {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub otp: Option<TwoFasOtp>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TwoFasOtp {
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub digits: Option<u32>,
    #[serde(default)]
    pub period: Option<u64>,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Deserialize)]
pub struct BitwardenJsonExport {
    #[serde(default)]
    pub folders: Vec<BitwardenJsonFolder>,
    #[serde(default)]
    pub items: Vec<BitwardenJsonItem>,
}

#[derive(Deserialize)]
pub struct BitwardenJsonFolder {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Deserialize)]
pub struct BitwardenJsonItem {
    #[serde(default, rename = "type")]
    pub item_type: Option<u8>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default, rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub login: Option<BitwardenJsonLogin>,
    #[serde(default)]
    pub card: Option<BitwardenJsonCard>,
    #[serde(default)]
    pub identity: Option<BitwardenJsonIdentity>,
    #[serde(default, rename = "sshKey")]
    pub ssh_key: Option<BitwardenJsonSshKey>,
    #[serde(default)]
    pub fields: Vec<BitwardenJsonField>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenJsonSshKey {
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub key_fingerprint: String,
}

/// Counted, never stored: Sesame has no passkey item yet, and silent loss is worse than a number.
#[derive(Deserialize)]
pub struct BitwardenJsonPasskey {}

#[derive(Deserialize, Default)]
pub struct BitwardenJsonIdentity {
    #[serde(default)]
    pub title: String,
    #[serde(default, rename = "firstName")]
    pub first_name: String,
    #[serde(default, rename = "middleName")]
    pub middle_name: String,
    #[serde(default, rename = "lastName")]
    pub last_name: String,
    #[serde(default)]
    pub address1: String,
    #[serde(default)]
    pub address2: String,
    #[serde(default)]
    pub address3: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state: String,
    #[serde(default, rename = "postalCode")]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub ssn: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, rename = "passportNumber")]
    pub passport_number: String,
    #[serde(default, rename = "licenseNumber")]
    pub license_number: String,
}

#[derive(Deserialize, Default)]
pub struct BitwardenJsonCard {
    #[serde(default, rename = "cardholderName")]
    pub cardholder_name: String,
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub number: String,
    #[serde(default, rename = "expMonth")]
    pub exp_month: String,
    #[serde(default, rename = "expYear")]
    pub exp_year: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Deserialize)]
pub struct BitwardenJsonLogin {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp: String,
    #[serde(default)]
    pub uris: Vec<BitwardenJsonUri>,
    #[serde(default, rename = "fido2Credentials")]
    pub fido2_credentials: Vec<BitwardenJsonPasskey>,
}

#[derive(Deserialize)]
pub struct BitwardenJsonUri {
    #[serde(default)]
    pub uri: String,
}

#[derive(Deserialize)]
pub struct BitwardenJsonField {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default, rename = "type")]
    pub field_type: Option<u8>,
}

#[derive(Debug)]
pub struct StagedVaultFiles {
    pub staging_dir: std::path::PathBuf,
}

impl Zeroize for VaultPayload {
    fn zeroize(&mut self) {
        self.vault_name.zeroize();
        self.folders.zeroize();
        self.entries.zeroize();
        self.identities.zeroize();
        self.secure_notes.zeroize();
        self.cards.zeroize();
        self.wifi_networks.zeroize();
        self.ssh_keys.zeroize();
        self.software_licenses.zeroize();
        self.documents.zeroize();
        self.custom_records.zeroize();
        self.trash.zeroize();
        self.history.zeroize();
    }
}

impl Zeroize for TaggedItem {
    fn zeroize(&mut self) {
        match self {
            TaggedItem::Login(item) => item.zeroize(),
            TaggedItem::Identity(item) => item.zeroize(),
            TaggedItem::SecureNote(item) => item.zeroize(),
            TaggedItem::Card(item) => item.zeroize(),
            TaggedItem::WifiNetwork(item) => item.zeroize(),
            TaggedItem::SshKey(item) => item.zeroize(),
            TaggedItem::SoftwareLicense(item) => item.zeroize(),
            TaggedItem::Document(item) => item.zeroize(),
            TaggedItem::CustomRecord(item) => item.zeroize(),
        }
    }
}

impl Zeroize for TrashedItem {
    fn zeroize(&mut self) {
        self.item.zeroize();
    }
}

impl Zeroize for HistoryEntry {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.item.zeroize();
    }
}

impl Zeroize for SecureNote {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.content.zeroize();
        self.tags.zeroize();
        self.legacy_fields.zeroize();
    }
}

impl Zeroize for Card {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.cardholder_name.zeroize();
        self.number.zeroize();
        self.expiry_month.zeroize();
        self.expiry_year.zeroize();
        self.security_code.zeroize();
        self.brand.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
        self.legacy_fields.zeroize();
    }
}

impl Zeroize for WifiNetwork {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.ssid.zeroize();
        self.password.zeroize();
        self.security_type.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
    }
}

impl Zeroize for SshKey {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.key_type.zeroize();
        self.private_key.zeroize();
        self.public_key.zeroize();
        self.passphrase.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
    }
}

impl Zeroize for SoftwareLicense {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.license_key.zeroize();
        self.product_name.zeroize();
        self.purchased_from.zeroize();
        self.purchase_date.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
    }
}

impl Zeroize for DocumentMetadata {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.document_type.zeroize();
        self.document_number.zeroize();
        self.issuing_authority.zeroize();
        self.issue_date.zeroize();
        self.expiry_date.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
    }
}

impl Zeroize for CustomFieldEntry {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.value.zeroize();
        self.kind.zeroize();
    }
}

impl Zeroize for CustomRecord {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.fields.zeroize();
        self.notes.zeroize();
        self.tags.zeroize();
    }
}

impl Zeroize for Identity {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.label.zeroize();
        self.full_name.zeroize();
        self.email.zeroize();
        self.phone.zeroize();
        self.address_line1.zeroize();
        self.address_line2.zeroize();
        self.city.zeroize();
        self.region.zeroize();
        self.postal_code.zeroize();
        self.country.zeroize();
        self.legacy_fields.zeroize();
    }
}

impl Zeroize for Folder {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
    }
}

impl Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.url.zeroize();
        self.urls.zeroize();
        self.tags.zeroize();
        self.username.zeroize();
        self.email.zeroize();
        self.password.zeroize();
        self.folder.zeroize();
        self.folder_id.zeroize();
        self.totp.zeroize();
        self.backup_codes.zeroize();
        self.recovery_email.zeroize();
        self.recovery_phone.zeroize();
        self.notes.zeroize();
        self.legacy_fields.zeroize();
    }
}

impl Zeroize for LegacyField {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    #![cfg_attr(test, allow(clippy::unwrap_used))]
    use super::*;

    /// Every saved-record editor in the desktop reads these arrays straight off
    /// the record it loads (`draft.tags.join(', ')`), and `src/lib/types.ts`
    /// declares them as always present. A field serde drops when it is empty is
    /// therefore not a smaller payload, it is an editor that throws before it
    /// can paint, so the record looks like it saved nothing.
    #[test]
    fn empty_record_arrays_stay_present_for_the_desktop_editors() {
        fn assert_present(label: &str, value: serde_json::Value, fields: &[&str]) {
            for field in fields {
                assert!(
                    value.get(field).is_some(),
                    "{label}.{field} is missing when empty; the desktop editor reads it directly"
                );
            }
        }

        assert_present(
            "SecureNote",
            serde_json::to_value(SecureNote::default()).unwrap(),
            &["tags"],
        );
        assert_present(
            "Card",
            serde_json::to_value(Card::default()).unwrap(),
            &["tags"],
        );
        assert_present(
            "WifiNetwork",
            serde_json::to_value(WifiNetwork::default()).unwrap(),
            &["tags"],
        );
        assert_present(
            "SshKey",
            serde_json::to_value(SshKey::default()).unwrap(),
            &["tags"],
        );
        assert_present(
            "SoftwareLicense",
            serde_json::to_value(SoftwareLicense::default()).unwrap(),
            &["tags"],
        );
        assert_present(
            "DocumentMetadata",
            serde_json::to_value(DocumentMetadata::default()).unwrap(),
            &["tags", "attachments"],
        );
        assert_present(
            "CustomRecord",
            serde_json::to_value(CustomRecord::default()).unwrap(),
            &["tags"],
        );
    }

    /// Records written before this contract existed have no `tags` key at all.
    #[test]
    fn records_stored_without_the_array_keys_still_load() {
        let note: SecureNote =
            serde_json::from_str(r#"{"id":"a","title":"Wi-Fi","content":"example note body"}"#)
                .unwrap();
        assert!(note.tags.is_empty());
        let document: DocumentMetadata =
            serde_json::from_str(r#"{"id":"b","title":"Passport"}"#).unwrap();
        assert!(document.tags.is_empty());
        assert!(document.attachments.is_empty());
    }
}
