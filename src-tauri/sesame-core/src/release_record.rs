use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{bytes_match, decrypt_bytes, encrypt_bytes};
use crate::platform::open_private_append;
use crate::storage::{atomic_replace, damaged_copy_paths, set_aside_damaged};
use crate::types::CipherBlob;
use crate::util::{fill_secret, read_file_with_limit, unix_timestamp};
use crate::{UnlockedVault, VaultResult};

pub const RECORD_FILE: &str = "release-record.sesame";
pub const DAMAGED_FILE: &str = "release-record.damaged.sesame";
pub const DAMAGED_COPIES: usize = 3;
pub const DEFAULT_RETENTION_DAYS: u32 = 180;
pub const MIN_RETENTION_DAYS: u32 = 7;
pub const MAX_RETENTION_DAYS: u32 = 730;
pub const MAX_ENTRIES: usize = 10_000;
pub const COMPACT_AT: usize = 11_000;
pub const REFUSAL_WINDOW_SECS: u64 = 60;
pub const REFUSALS_PER_HOUR: usize = 120;
pub const LOCKED_QUEUE_LIMIT: usize = 64;
pub const UNWRITTEN_LIMIT: usize = 256;
pub const MAX_HOST_CHARS: usize = 253;
pub const MAX_ITEM_ID_CHARS: usize = 128;
pub const MAX_FIELDS: usize = 12;
pub const PLAINTEXT_BYTES: usize = 896;
pub const MAX_RECORD_FILE_BYTES: u64 = 24 * 1024 * 1024;

const FORMAT_NAME: &str = "sesame-release-record";
const FORMAT_VERSION: u8 = 1;
const KEY_INFO: &[u8] = b"sesame:release-record:v1:entries";
const HEADER_AAD_LABEL: &[u8] = b"sesame:release-record:v1:header";
const ENTRY_AAD_LABEL: &[u8] = b"sesame:release-record:v1:entry";
const CHECK_VALUE: &[u8] = b"sesame:release-record:v1:check";
const DAY_SECS: u64 = 86_400;
const FILE_CHANGED: &str = "fileChanged";
const HOUR_SECS: u64 = 3_600;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    BrowserFill,
    BrowserSave,
    BrowserTotp,
    BrowserCard,
    BrowserIdentity,
    BrowserChange,
    BrowserCreate,
    Reveal,
    Copy,
    AutoType,
    QuickAccess,
    CsvExport,
    JsonExport,
    BackupExport,
    BackupCreated,
    RecoveryKitSaved,
    AttachmentSaved,
    DevicePaired,
    EmailAlias,
    Cleared,
    RetentionShortened,
    Unreadable,
    Interrupted,
    FileChanged,
    LockedOverflow,
    RefusalLimit,
    WritesLost,
}

impl EntryKind {
    pub fn is_browser(self) -> bool {
        matches!(
            self,
            Self::BrowserFill
                | Self::BrowserSave
                | Self::BrowserTotp
                | Self::BrowserCard
                | Self::BrowserIdentity
                | Self::BrowserChange
                | Self::BrowserCreate
        )
    }

    pub fn marks_gap(self) -> bool {
        matches!(
            self,
            Self::Unreadable
                | Self::Interrupted
                | Self::FileChanged
                | Self::LockedOverflow
                | Self::WritesLost
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Released,
    Saved,
    Updated,
    Denied,
    TimedOut,
    ConnectionClosed,
    VaultChanged,
    Withdrawn,
    Lookalike,
    NoMatch,
    Locked,
    Busy,
    Mismatch,
    Replayed,
    NeverSave,
    Noted,
}

impl Outcome {
    pub fn is_refusal(self) -> bool {
        !matches!(
            self,
            Self::Released | Self::Saved | Self::Updated | Self::Noted
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum FieldKind {
    Password,
    Username,
    Email,
    TwoFactorCode,
    BackupCodes,
    CustomField,
    LegacyField,
    CardNumber,
    CardholderName,
    CardExpiry,
    SecurityCode,
    FullName,
    Phone,
    Address,
    PrivateKey,
    PublicKey,
    Passphrase,
    LicenseKey,
    DocumentNumber,
    NoteContent,
    Other,
}

impl FieldKind {
    pub fn from_key(key: &str) -> Self {
        match key.trim() {
            "password" => Self::Password,
            "username" => Self::Username,
            "email" => Self::Email,
            "totp" => Self::TwoFactorCode,
            "backupCodes" => Self::BackupCodes,
            "number" => Self::CardNumber,
            "cardholderName" => Self::CardholderName,
            "expiry" | "expiryMonth" | "expiryYear" => Self::CardExpiry,
            "securityCode" => Self::SecurityCode,
            "fullName" => Self::FullName,
            "phone" => Self::Phone,
            "address" | "addressLine1" | "addressLine2" | "city" | "region" | "postalCode"
            | "country" => Self::Address,
            "privateKey" => Self::PrivateKey,
            "publicKey" => Self::PublicKey,
            "passphrase" => Self::Passphrase,
            "licenseKey" => Self::LicenseKey,
            "documentNumber" => Self::DocumentNumber,
            "content" => Self::NoteContent,
            key if key.starts_with("field:") => Self::CustomField,
            key if key.starts_with("legacy") => Self::LegacyField,
            _ => Self::Other,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum MatchKind {
    Exact,
    WwwAlias,
    Site,
}

impl MatchKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "exact" => Some(Self::Exact),
            "wwwAlias" => Some(Self::WwwAlias),
            "site" => Some(Self::Site),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordEntry {
    pub seq: u64,
    pub at: u64,
    pub kind: EntryKind,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similar_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_kind: Option<MatchKind>,
    pub count: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub late: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseDraft {
    pub kind: EntryKind,
    pub outcome: Outcome,
    pub item_id: Option<String>,
    pub item_kind: Option<String>,
    pub fields: Vec<FieldKind>,
    pub host: Option<String>,
    pub similar_to: Option<String>,
    pub match_kind: Option<MatchKind>,
    pub count: u32,
    pub at: Option<u64>,
}

impl ReleaseDraft {
    pub fn new(kind: EntryKind, outcome: Outcome) -> Self {
        Self {
            kind,
            outcome,
            item_id: None,
            item_kind: None,
            fields: Vec::new(),
            host: None,
            similar_to: None,
            match_kind: None,
            count: 1,
            at: None,
        }
    }

    pub fn item(mut self, id: &str, kind: &str) -> Self {
        self.item_id = Some(id.to_string());
        self.item_kind = Some(kind.to_string());
        self
    }

    pub fn field(mut self, key: &str) -> Self {
        self.fields.push(FieldKind::from_key(key));
        self
    }

    pub fn fields<'a>(mut self, keys: impl IntoIterator<Item = &'a str>) -> Self {
        for key in keys {
            self.fields.push(FieldKind::from_key(key));
        }
        self
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    pub fn similar_to(mut self, host: &str) -> Self {
        self.similar_to = Some(host.to_string());
        self
    }

    pub fn match_kind(mut self, kind: Option<MatchKind>) -> Self {
        self.match_kind = kind;
        self
    }

    pub fn count(mut self, count: u32) -> Self {
        self.count = count.max(1);
        self
    }

    fn into_entry(self, seq: u64, now: u64, late: bool) -> RecordEntry {
        let mut fields = Vec::new();
        for field in self.fields {
            if !fields.contains(&field) && fields.len() < MAX_FIELDS {
                fields.push(field);
            }
        }
        RecordEntry {
            seq,
            at: self.at.unwrap_or(now),
            kind: self.kind,
            outcome: self.outcome,
            item_id: self.item_id.as_deref().and_then(bounded_item_id),
            item_kind: self
                .item_kind
                .as_deref()
                .and_then(|kind| bounded_ascii(kind, 32)),
            fields,
            host: self
                .host
                .as_deref()
                .and_then(|host| bounded_ascii(host, MAX_HOST_CHARS)),
            similar_to: self
                .similar_to
                .as_deref()
                .and_then(|host| bounded_ascii(host, MAX_HOST_CHARS)),
            match_kind: self.match_kind,
            count: self.count.max(1),
            late,
        }
    }

    fn locked_form(self, at: u64) -> Self {
        Self {
            kind: self.kind,
            outcome: self.outcome,
            item_id: None,
            item_kind: None,
            fields: Vec::new(),
            host: self.host,
            similar_to: None,
            match_kind: None,
            count: self.count.max(1),
            at: Some(self.at.unwrap_or(at)),
        }
    }
}

fn bounded_ascii(value: &str, max_chars: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let cleaned: String = value
        .chars()
        .filter(|character| character.is_ascii_graphic() && *character != '"' && *character != '\\')
        .take(max_chars)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn bounded_item_id(id: &str) -> Option<String> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    let plain = id.len() <= MAX_ITEM_ID_CHARS
        && id
            .chars()
            .all(|character| character.is_ascii_graphic() && character != '"' && character != '\\');
    if plain {
        return Some(id.to_string());
    }
    let digest = Sha256::digest(id.as_bytes());
    Some(format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordNotice {
    Unreadable,
    Interrupted,
    FileChanged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordStatus {
    pub open: bool,
    pub entry_count: usize,
    pub starts_at: Option<u64>,
    pub complete_since: Option<u64>,
    pub retention_days: u32,
    pub unwritten: usize,
    pub notice: Option<RecordNotice>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordMark {
    record_id: Option<[u8; 16]>,
    next_seq: u64,
    unwritten: usize,
    unwritten_lost: u32,
    notice: Option<RecordNotice>,
    retention_days: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appended {
    Written,
    Deferred,
    Counted,
    Queued,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    format: String,
    version: u8,
    record_id: String,
    check: CipherBlob,
}

struct OpenRecord {
    path: PathBuf,
    record_id: [u8; 16],
    vault_id: String,
    key: Zeroizing<[u8; 32]>,
    next_seq: u64,
    prev: [u8; 32],
    file_len: u64,
    disk_valid: bool,
    entries: Vec<RecordEntry>,
}

impl Drop for OpenRecord {
    fn drop(&mut self) {
        self.record_id.zeroize();
        self.prev.zeroize();
        self.vault_id.zeroize();
        for entry in &mut self.entries {
            if let Some(host) = entry.host.as_mut() {
                host.zeroize();
            }
            if let Some(id) = entry.item_id.as_mut() {
                id.zeroize();
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Window {
    started: u64,
    last_at: u64,
    repeats: u32,
}

#[derive(Default)]
struct Coalescer {
    windows: HashMap<(EntryKind, String, Outcome), Window>,
    written: VecDeque<u64>,
    over_limit: u32,
    over_limit_at: u64,
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

struct Inner {
    open: Option<OpenRecord>,
    queue: VecDeque<ReleaseDraft>,
    queue_overflow: u32,
    unwritten: VecDeque<(ReleaseDraft, bool)>,
    unwritten_lost: u32,
    coalescer: Coalescer,
    notice: Option<RecordNotice>,
    retention_days: u32,
    clock: Clock,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            open: None,
            queue: VecDeque::new(),
            queue_overflow: 0,
            unwritten: VecDeque::new(),
            unwritten_lost: 0,
            coalescer: Coalescer::default(),
            notice: None,
            retention_days: DEFAULT_RETENTION_DAYS,
            clock: Arc::new(unix_timestamp),
        }
    }
}

#[derive(Default)]
pub struct RecordState {
    inner: Mutex<Inner>,
}

fn recover<T>(guard: std::sync::LockResult<MutexGuard<'_, T>>) -> MutexGuard<'_, T> {
    guard.unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn record_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(RECORD_FILE)
}

pub fn damaged_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(DAMAGED_FILE)
}

pub fn damaged_paths(vault_path: &Path) -> Vec<PathBuf> {
    damaged_copy_paths(
        vault_path.parent().unwrap_or_else(|| Path::new("")),
        "release-record",
        DAMAGED_COPIES,
    )
}

fn derive_key(vault_key: &[u8; 32], record_id: &[u8; 16]) -> VaultResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(record_id), vault_key);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(KEY_INFO, &mut *key)
        .map_err(|_| "Sesame could not prepare the activity record.".to_string())?;
    Ok(key)
}

fn session_key(session: &UnlockedVault, record_id: &[u8; 16]) -> VaultResult<Zeroizing<[u8; 32]>> {
    session.expose_vault_key(|vault_key| derive_key(vault_key, record_id))
}

fn session_vault_id(session: &UnlockedVault) -> String {
    session.vault_id().unwrap_or_default().to_string()
}

fn header_aad(record_id: &[u8; 16], vault_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_AAD_LABEL.len() + 20 + vault_id.len());
    aad.extend_from_slice(HEADER_AAD_LABEL);
    aad.extend_from_slice(record_id);
    aad.extend_from_slice(&(vault_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn entry_aad(record_id: &[u8; 16], vault_id: &str, seq: u64, prev: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_AAD_LABEL.len() + 60 + vault_id.len());
    aad.extend_from_slice(ENTRY_AAD_LABEL);
    aad.extend_from_slice(record_id);
    aad.extend_from_slice(&(vault_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(prev);
    aad
}

fn line_hash(line: &[u8]) -> [u8; 32] {
    Sha256::digest(line).into()
}

fn header_line(key: &[u8; 32], record_id: &[u8; 16], vault_id: &str) -> VaultResult<Vec<u8>> {
    let check = encrypt_bytes(key, CHECK_VALUE, &header_aad(record_id, vault_id))?;
    let header = Header {
        format: FORMAT_NAME.to_string(),
        version: FORMAT_VERSION,
        record_id: URL_SAFE_NO_PAD.encode(record_id),
        check,
    };
    let mut line = serde_json::to_vec(&header)
        .map_err(|_| "Sesame could not prepare the activity record.".to_string())?;
    line.push(b'\n');
    Ok(line)
}

fn entry_line(
    key: &[u8; 32],
    record_id: &[u8; 16],
    vault_id: &str,
    prev: &[u8; 32],
    entry: &RecordEntry,
) -> VaultResult<Vec<u8>> {
    let mut plaintext = Zeroizing::new([b' '; PLAINTEXT_BYTES]);
    let mut cursor = std::io::Cursor::new(&mut plaintext[..]);
    serde_json::to_writer(&mut cursor, entry)
        .map_err(|_| "Sesame could not prepare the activity entry.".to_string())?;
    let blob = encrypt_bytes(
        key,
        &plaintext[..],
        &entry_aad(record_id, vault_id, entry.seq, prev),
    )?;
    let mut line = serde_json::to_vec(&blob)
        .map_err(|_| "Sesame could not prepare the activity entry.".to_string())?;
    line.push(b'\n');
    Ok(line)
}

fn parse_header(line: &[u8]) -> Option<([u8; 16], CipherBlob)> {
    let header: Header = serde_json::from_slice(line).ok()?;
    if header.format != FORMAT_NAME || header.version != FORMAT_VERSION {
        return None;
    }
    let record_id: [u8; 16] = URL_SAFE_NO_PAD
        .decode(header.record_id.as_bytes())
        .ok()?
        .try_into()
        .ok()?;
    Some((record_id, header.check))
}

fn open_entry(
    key: &[u8; 32],
    record_id: &[u8; 16],
    vault_id: &str,
    seq: u64,
    prev: &[u8; 32],
    line: &[u8],
) -> Option<RecordEntry> {
    let blob: CipherBlob = serde_json::from_slice(line).ok()?;
    let plaintext = decrypt_bytes(key, &blob, &entry_aad(record_id, vault_id, seq, prev)).ok()?;
    if plaintext.len() != PLAINTEXT_BYTES {
        return None;
    }
    let end = plaintext
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    let entry: RecordEntry = serde_json::from_slice(&plaintext[..end]).ok()?;
    (entry.seq == seq).then_some(entry)
}

pub struct ReadRecord {
    pub record_id: [u8; 16],
    pub entries: Vec<RecordEntry>,
    pub next_seq: u64,
    pub prev: [u8; 32],
    pub file_len: u64,
    pub damage: Option<Damage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    Unreadable { lost_lines: u32 },
    Interrupted,
}

pub enum ReadOutcome {
    Missing,
    Unavailable,
    Unreadable,
    Read(ReadRecord),
}

pub fn read_record_file(path: &Path, vault_key: &[u8; 32], vault_id: &str) -> ReadOutcome {
    let bytes = match read_file_with_limit(path, MAX_RECORD_FILE_BYTES) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return ReadOutcome::Missing,
        Err(error) if crate::util::read_failure_is_damage(path, &error) => {
            return ReadOutcome::Unreadable
        }
        Err(_) => return ReadOutcome::Unavailable,
    };
    read_record_bytes(&bytes, vault_key, vault_id)
}

pub fn read_record_bytes(bytes: &[u8], vault_key: &[u8; 32], vault_id: &str) -> ReadOutcome {
    let Some(header_end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return ReadOutcome::Unreadable;
    };
    let header_line_bytes = &bytes[..=header_end];
    let Some((record_id, check)) = parse_header(&bytes[..header_end]) else {
        return ReadOutcome::Unreadable;
    };
    let Ok(key) = derive_key(vault_key, &record_id) else {
        return ReadOutcome::Unreadable;
    };
    match decrypt_bytes(&key, &check, &header_aad(&record_id, vault_id)) {
        Ok(value) if bytes_match(&value, CHECK_VALUE) => {}
        _ => return ReadOutcome::Unreadable,
    }
    let mut prev = line_hash(header_line_bytes);
    let mut offset = header_end + 1;
    let mut entries = Vec::new();
    let mut damage = None;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        let Some(line_end) = rest.iter().position(|byte| *byte == b'\n') else {
            damage = Some(Damage::Interrupted);
            break;
        };
        let line = &rest[..=line_end];
        let seq = entries.len() as u64;
        match open_entry(&key, &record_id, vault_id, seq, &prev, &rest[..line_end]) {
            Some(entry) => {
                entries.push(entry);
                prev = line_hash(line);
                offset += line_end + 1;
            }
            None => {
                let lost_lines = rest.iter().filter(|byte| **byte == b'\n').count();
                damage = Some(Damage::Unreadable {
                    lost_lines: u32::try_from(lost_lines).unwrap_or(u32::MAX),
                });
                break;
            }
        }
    }
    ReadOutcome::Read(ReadRecord {
        record_id,
        next_seq: entries.len() as u64,
        entries,
        prev,
        file_len: offset as u64,
        damage,
    })
}

fn write_fresh(
    path: &Path,
    vault_key: &[u8; 32],
    vault_id: &str,
    entries: &mut [RecordEntry],
) -> VaultResult<OpenRecord> {
    let mut record_id = [0_u8; 16];
    fill_secret(&mut record_id)?;
    let key = derive_key(vault_key, &record_id)?;
    let header = header_line(&key, &record_id, vault_id)?;
    let mut prev = line_hash(&header);
    let mut bytes = Zeroizing::new(header);
    for (seq, entry) in entries.iter_mut().enumerate() {
        entry.seq = seq as u64;
        let line = entry_line(&key, &record_id, vault_id, &prev, entry)?;
        prev = line_hash(&line);
        bytes.extend_from_slice(&line);
    }
    atomic_replace(path, &bytes)
        .map_err(|_| "Sesame could not write the activity record.".to_string())?;
    Ok(OpenRecord {
        path: path.to_path_buf(),
        record_id,
        vault_id: vault_id.to_string(),
        key,
        next_seq: entries.len() as u64,
        prev,
        file_len: bytes.len() as u64,
        disk_valid: true,
        entries: entries.to_vec(),
    })
}

fn current_file_len(path: &Path) -> Option<u64> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    metadata.is_file().then_some(metadata.len())
}

fn encode_for(open: &OpenRecord, entry: &RecordEntry) -> VaultResult<Vec<u8>> {
    entry_line(
        &open.key,
        &open.record_id,
        &open.vault_id,
        &open.prev,
        entry,
    )
}

fn append_line(open: &mut OpenRecord, entry: &RecordEntry, line: &[u8]) -> VaultResult<()> {
    if current_file_len(&open.path) != Some(open.file_len) {
        return Err(FILE_CHANGED.into());
    }
    let mut file = open_private_append(&open.path)?;
    let written = file.write_all(line).and_then(|_| file.sync_data());
    if written.is_err() {
        return Err("Sesame could not write the activity record.".into());
    }
    open.prev = line_hash(line);
    open.file_len += line.len() as u64;
    open.next_seq += 1;
    open.entries.push(entry.clone());
    Ok(())
}

impl RecordState {
    pub fn set_clock(&self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) {
        recover(self.inner.lock()).clock = clock;
    }

    pub fn set_retention_days(&self, days: u32) {
        recover(self.inner.lock()).retention_days =
            days.clamp(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS);
    }

    pub fn retention_days(&self) -> u32 {
        recover(self.inner.lock()).retention_days
    }

    pub fn mark(&self) -> RecordMark {
        let inner = recover(self.inner.lock());
        RecordMark {
            record_id: inner.open.as_ref().map(|open| open.record_id),
            next_seq: inner.open.as_ref().map_or(0, |open| open.next_seq),
            unwritten: inner.unwritten.len(),
            unwritten_lost: inner.unwritten_lost,
            notice: inner.notice,
            retention_days: inner.retention_days,
        }
    }

    pub fn discard(&self) {
        let mut inner = recover(self.inner.lock());
        inner.open = None;
        inner.queue.clear();
        inner.queue_overflow = 0;
        inner.unwritten.clear();
        inner.unwritten_lost = 0;
        inner.coalescer = Coalescer::default();
        inner.notice = None;
    }

    pub fn open(&self, session: &UnlockedVault) -> VaultResult<()> {
        let mut inner = recover(self.inner.lock());
        inner.ensure_open(session)?;
        inner.flush(session, false);
        Ok(())
    }

    pub fn append(&self, session: &UnlockedVault, draft: ReleaseDraft) -> Appended {
        let mut inner = recover(self.inner.lock());
        if inner.ensure_open(session).is_err() {
            let now = (inner.clock)();
            return inner.defer(draft, now);
        }
        inner.flush(session, false);
        inner.append_draft(session, draft)
    }

    pub fn append_locked(&self, draft: ReleaseDraft) -> Appended {
        let mut inner = recover(self.inner.lock());
        let now = (inner.clock)();
        inner.enqueue(draft.locked_form(now));
        Appended::Queued
    }

    pub fn close(&self, session: Option<&UnlockedVault>) {
        let mut inner = recover(self.inner.lock());
        if let Some(session) = session {
            if inner.ensure_open(session).is_ok() {
                inner.flush(session, true);
            }
        }
        let now = (inner.clock)();
        let windows: Vec<_> = inner.coalescer.windows.drain().collect();
        for ((kind, host, outcome), window) in windows {
            if window.repeats > 0 {
                let mut draft = ReleaseDraft::new(kind, outcome).count(window.repeats);
                draft.host = Some(host).filter(|host| !host.is_empty());
                draft.at = Some(window.last_at);
                inner.enqueue(draft.locked_form(now));
            }
        }
        inner.open = None;
        inner.notice = None;
    }

    pub fn entries(&self, session: &UnlockedVault) -> VaultResult<Vec<RecordEntry>> {
        let mut inner = recover(self.inner.lock());
        inner.ensure_open(session)?;
        inner.flush(session, false);
        Ok(inner
            .open
            .as_ref()
            .map(|open| open.entries.clone())
            .unwrap_or_default())
    }

    pub fn status(&self) -> RecordStatus {
        let inner = recover(self.inner.lock());
        let (open, entry_count, starts_at, complete_since) = match inner.open.as_ref() {
            Some(open) => {
                let starts_at = open.entries.iter().map(|entry| entry.at).min();
                let gap = open
                    .entries
                    .iter()
                    .filter(|entry| entry.kind.marks_gap())
                    .map(|entry| entry.at)
                    .max();
                let complete_since = match (starts_at, gap) {
                    (Some(start), Some(gap)) => Some(start.max(gap)),
                    (start, None) => start,
                    (None, gap) => gap,
                };
                (true, open.entries.len(), starts_at, complete_since)
            }
            None => (false, 0, None, None),
        };
        RecordStatus {
            open,
            entry_count,
            starts_at,
            complete_since,
            retention_days: inner.retention_days,
            unwritten: inner.unwritten.len() + usize::from(inner.unwritten_lost > 0),
            notice: inner.notice,
        }
    }

    pub fn clear(&self, session: &UnlockedVault) -> VaultResult<()> {
        let mut inner = recover(self.inner.lock());
        inner.ensure_open(session)?;
        inner.flush(session, false);
        let now = (inner.clock)();
        let dropped =
            inner.open.as_ref().map_or(0, |open| open.entries.len()) + inner.unwritten.len();
        let mut entries = vec![ReleaseDraft::new(EntryKind::Cleared, Outcome::Noted)
            .count(u32::try_from(dropped).unwrap_or(u32::MAX))
            .into_entry(0, now, false)];
        let path = record_path(&session.path);
        let vault_id = session_vault_id(session);
        let fresh = session
            .expose_vault_key(|vault_key| write_fresh(&path, vault_key, &vault_id, &mut entries))?;
        for damaged in damaged_paths(&session.path) {
            let _ = crate::platform::securely_delete(&damaged);
        }
        inner.unwritten.clear();
        inner.unwritten_lost = 0;
        inner.coalescer = Coalescer::default();
        inner.notice = None;
        inner.open = Some(fresh);
        Ok(())
    }

    pub fn apply_retention(&self, session: &UnlockedVault) -> VaultResult<()> {
        let mut inner = recover(self.inner.lock());
        inner.ensure_open(session)?;
        inner.trim(session, true);
        Ok(())
    }

    pub fn shorten_retention(&self, session: &UnlockedVault, days: u32) -> VaultResult<usize> {
        let mut inner = recover(self.inner.lock());
        inner.ensure_open(session)?;
        inner.flush(session, false);
        let previous_days = inner.retention_days;
        inner.retention_days = days.clamp(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS);
        let Some((mut kept, removed)) = inner.retained(true) else {
            return Ok(0);
        };
        let now = (inner.clock)();
        kept.push(
            ReleaseDraft::new(EntryKind::RetentionShortened, Outcome::Noted)
                .count(u32::try_from(removed).unwrap_or(u32::MAX))
                .into_entry(0, now, false),
        );
        let Some(open) = inner.open.as_mut() else {
            inner.retention_days = previous_days;
            return Err("Sesame could not open the activity record.".into());
        };
        let previous_entries = std::mem::replace(&mut open.entries, kept);
        if let Err(error) = inner.rewrite(session) {
            if let Some(open) = inner.open.as_mut() {
                open.entries = previous_entries;
            }
            inner.retention_days = previous_days;
            return Err(error);
        }
        Ok(removed)
    }
}

fn is_refusal_entry(entry: &RecordEntry) -> bool {
    entry.kind.is_browser() && entry.outcome.is_refusal()
}

fn evict_over_cap(entries: &mut Vec<RecordEntry>) {
    if entries.len() <= MAX_ENTRIES {
        return;
    }
    let mut excess = entries.len() - MAX_ENTRIES;
    entries.retain(|entry| {
        if excess > 0 && is_refusal_entry(entry) {
            excess -= 1;
            false
        } else {
            true
        }
    });
    if excess > 0 {
        entries.drain(..excess);
    }
}

impl Inner {
    fn ensure_open(&mut self, session: &UnlockedVault) -> VaultResult<()> {
        let path = record_path(&session.path);
        let vault_id = session_vault_id(session);
        if let Some(open) = self.open.as_ref() {
            if open.path != path {
                self.open = None;
            }
        }
        if let Some(open) = self.open.as_mut() {
            let current = session_key(session, &open.record_id)?;
            if bytes_match(&*current, &*open.key) && open.vault_id == vault_id {
                if !open.disk_valid {
                    self.rewrite(session)?;
                }
                return Ok(());
            }
            return self.rewrite(session);
        }
        self.load(session, &path, &vault_id)
    }

    fn load(&mut self, session: &UnlockedVault, path: &Path, vault_id: &str) -> VaultResult<()> {
        let now = (self.clock)();
        let read = session
            .expose_vault_key(|vault_key| Ok(read_record_file(path, vault_key, vault_id)))?;
        let (mut entries, notice_entry, keep_aside) = match read {
            ReadOutcome::Missing => (Vec::new(), None, false),
            ReadOutcome::Unavailable => {
                return Err("Sesame could not open the activity record.".into());
            }
            ReadOutcome::Unreadable => (
                Vec::new(),
                Some(ReleaseDraft::new(EntryKind::Unreadable, Outcome::Noted).count(1)),
                true,
            ),
            ReadOutcome::Read(read) => match read.damage {
                None => {
                    self.open = Some(OpenRecord {
                        path: path.to_path_buf(),
                        record_id: read.record_id,
                        vault_id: vault_id.to_string(),
                        key: session_key(session, &read.record_id)?,
                        next_seq: read.next_seq,
                        prev: read.prev,
                        file_len: read.file_len,
                        disk_valid: true,
                        entries: read.entries,
                    });
                    self.trim(session, false);
                    return Ok(());
                }
                Some(Damage::Interrupted) => (
                    read.entries,
                    Some(ReleaseDraft::new(EntryKind::Interrupted, Outcome::Noted)),
                    false,
                ),
                Some(Damage::Unreadable { lost_lines }) => (
                    read.entries,
                    Some(
                        ReleaseDraft::new(EntryKind::Unreadable, Outcome::Noted).count(lost_lines),
                    ),
                    true,
                ),
            },
        };
        if keep_aside {
            set_aside_damaged(path, &damaged_paths(&session.path));
        }
        if let Some(draft) = notice_entry {
            self.notice = Some(match draft.kind {
                EntryKind::Interrupted => RecordNotice::Interrupted,
                _ => RecordNotice::Unreadable,
            });
            entries.push(draft.into_entry(0, now, false));
        }
        let fresh = session
            .expose_vault_key(|vault_key| write_fresh(path, vault_key, vault_id, &mut entries));
        match fresh {
            Ok(fresh) => {
                self.open = Some(fresh);
                self.trim(session, false);
                Ok(())
            }
            Err(error) => {
                let mut record_id = [0_u8; 16];
                fill_secret(&mut record_id)?;
                self.open = Some(OpenRecord {
                    path: path.to_path_buf(),
                    record_id,
                    vault_id: vault_id.to_string(),
                    key: session_key(session, &record_id)?,
                    next_seq: entries.len() as u64,
                    prev: [0_u8; 32],
                    file_len: 0,
                    disk_valid: false,
                    entries,
                });
                Err(error)
            }
        }
    }

    fn rewrite(&mut self, session: &UnlockedVault) -> VaultResult<()> {
        let Some(open) = self.open.as_mut() else {
            return Err("Sesame could not open the activity record.".into());
        };
        let path = record_path(&session.path);
        let vault_id = session_vault_id(session);
        let mut entries = open.entries.clone();
        let fresh = session
            .expose_vault_key(|vault_key| write_fresh(&path, vault_key, &vault_id, &mut entries));
        match fresh {
            Ok(fresh) => {
                self.open = Some(fresh);
                Ok(())
            }
            Err(error) => {
                let mut record_id = [0_u8; 16];
                fill_secret(&mut record_id)?;
                open.key = session_key(session, &record_id)?;
                open.record_id = record_id;
                open.vault_id = vault_id;
                open.path = path;
                open.disk_valid = false;
                Err(error)
            }
        }
    }

    fn retained(&self, force: bool) -> Option<(Vec<RecordEntry>, usize)> {
        let now = (self.clock)();
        let cutoff = now.saturating_sub(u64::from(self.retention_days) * DAY_SECS);
        let open = self.open.as_ref()?;
        let slack = if force { 0 } else { DAY_SECS };
        let stale = open
            .entries
            .iter()
            .any(|entry| entry.at.saturating_add(slack) < cutoff);
        let over = open.entries.len() >= COMPACT_AT || (force && open.entries.len() > MAX_ENTRIES);
        if !stale && !over {
            return None;
        }
        let mut kept: Vec<RecordEntry> = open
            .entries
            .iter()
            .filter(|entry| entry.at >= cutoff)
            .cloned()
            .collect();
        evict_over_cap(&mut kept);
        let removed = open.entries.len() - kept.len();
        (removed > 0).then_some((kept, removed))
    }

    fn trim(&mut self, session: &UnlockedVault, force: bool) {
        let Some((kept, _)) = self.retained(force) else {
            return;
        };
        if let Some(open) = self.open.as_mut() {
            open.entries = kept;
        }
        let _ = self.rewrite(session);
    }

    fn defer(&mut self, draft: ReleaseDraft, now: u64) -> Appended {
        let mut draft = draft;
        draft.at = Some(draft.at.unwrap_or(now));
        self.push_unwritten(draft, true);
        Appended::Deferred
    }

    fn push_unwritten(&mut self, draft: ReleaseDraft, late: bool) {
        if self.unwritten.len() >= UNWRITTEN_LIMIT {
            self.unwritten_lost = self.unwritten_lost.saturating_add(1);
        } else {
            self.unwritten.push_back((draft, late));
        }
    }

    fn enqueue(&mut self, draft: ReleaseDraft) {
        if let Some(existing) = self.queue.iter_mut().find(|queued| {
            queued.kind == draft.kind
                && queued.host == draft.host
                && queued.outcome == draft.outcome
        }) {
            existing.count = existing.count.saturating_add(draft.count);
            existing.at = existing.at.max(draft.at);
            return;
        }
        if self.queue.len() >= LOCKED_QUEUE_LIMIT {
            self.queue_overflow = self.queue_overflow.saturating_add(draft.count);
            return;
        }
        self.queue.push_back(draft);
    }

    fn append_draft(&mut self, session: &UnlockedVault, draft: ReleaseDraft) -> Appended {
        let now = (self.clock)();
        let mut draft = draft;
        draft.at = Some(draft.at.unwrap_or(now));
        if draft.kind.is_browser() && draft.outcome.is_refusal() && self.coalesce(&draft, now) {
            return Appended::Counted;
        }
        self.push_unwritten(draft, false);
        self.write_pending(session);
        if self.unwritten.is_empty() {
            Appended::Written
        } else {
            Appended::Deferred
        }
    }

    fn coalesce(&mut self, draft: &ReleaseDraft, now: u64) -> bool {
        let key = (
            draft.kind,
            draft.host.clone().unwrap_or_default(),
            draft.outcome,
        );
        if let Some(window) = self.coalescer.windows.get_mut(&key) {
            if now.saturating_sub(window.started) < REFUSAL_WINDOW_SECS {
                window.repeats = window.repeats.saturating_add(draft.count);
                window.last_at = now;
                return true;
            }
        }
        if let Some(expired) = self.coalescer.windows.remove(&key) {
            self.write_out_window(key.clone(), expired);
        }
        while self
            .coalescer
            .written
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= HOUR_SECS)
        {
            self.coalescer.written.pop_front();
        }
        if self.coalescer.written.len() >= REFUSALS_PER_HOUR {
            if self.coalescer.over_limit == 0 {
                self.coalescer.over_limit_at = now;
            }
            self.coalescer.over_limit = self.coalescer.over_limit.saturating_add(draft.count);
            return true;
        }
        self.coalescer.written.push_back(now);
        self.coalescer.windows.insert(
            key,
            Window {
                started: now,
                last_at: now,
                repeats: 0,
            },
        );
        false
    }

    fn flush(&mut self, session: &UnlockedVault, closing: bool) {
        let now = (self.clock)();
        let expired: Vec<_> = self
            .coalescer
            .windows
            .iter()
            .filter(|(_, window)| {
                closing || now.saturating_sub(window.started) >= REFUSAL_WINDOW_SECS
            })
            .map(|(key, window)| (key.clone(), *window))
            .collect();
        for (key, window) in expired {
            self.coalescer.windows.remove(&key);
            self.write_out_window(key, window);
        }
        if self.coalescer.over_limit > 0
            && (closing || now.saturating_sub(self.coalescer.over_limit_at) >= HOUR_SECS)
        {
            let mut draft = ReleaseDraft::new(EntryKind::RefusalLimit, Outcome::Noted)
                .count(self.coalescer.over_limit);
            draft.at = Some(self.coalescer.over_limit_at);
            self.coalescer.over_limit = 0;
            self.push_unwritten(draft, false);
        }
        while let Some(draft) = self.queue.pop_front() {
            self.push_unwritten(draft, true);
        }
        if self.queue_overflow > 0 {
            let mut draft = ReleaseDraft::new(EntryKind::LockedOverflow, Outcome::Noted)
                .count(self.queue_overflow);
            draft.at = Some(now);
            self.queue_overflow = 0;
            self.push_unwritten(draft, false);
        }
        self.write_pending(session);
    }

    fn write_out_window(&mut self, key: (EntryKind, String, Outcome), window: Window) {
        if window.repeats == 0 {
            return;
        }
        let (kind, host, outcome) = key;
        let mut draft = ReleaseDraft::new(kind, outcome).count(window.repeats);
        draft.host = Some(host).filter(|host| !host.is_empty());
        draft.at = Some(window.last_at);
        self.push_unwritten(draft, false);
    }

    fn mark_late(&mut self) {
        for pending in self.unwritten.iter_mut() {
            pending.1 = true;
        }
    }

    fn note_lost(&mut self, now: u64) {
        if self.unwritten_lost > 0 && self.unwritten.len() < UNWRITTEN_LIMIT {
            let mut draft =
                ReleaseDraft::new(EntryKind::WritesLost, Outcome::Noted).count(self.unwritten_lost);
            draft.at = Some(now);
            self.unwritten_lost = 0;
            self.unwritten.push_back((draft, false));
        }
    }

    fn write_pending(&mut self, session: &UnlockedVault) {
        let now = (self.clock)();
        self.note_lost(now);
        if self.open.as_ref().is_some_and(|open| !open.disk_valid) && self.rewrite(session).is_err()
        {
            self.mark_late();
            return;
        }
        let mut rewrote_after_change = false;
        loop {
            let Some((draft, late)) = self.unwritten.pop_front() else {
                if self.unwritten_lost == 0 {
                    break;
                }
                self.note_lost(now);
                continue;
            };
            let Some(open) = self.open.as_mut() else {
                self.unwritten.push_front((draft, late));
                self.mark_late();
                return;
            };
            let entry = draft.clone().into_entry(open.next_seq, now, late);
            let Ok(line) = encode_for(open, &entry) else {
                self.unwritten_lost = self.unwritten_lost.saturating_add(1);
                continue;
            };
            match append_line(open, &entry, &line) {
                Ok(()) => {}
                Err(error) if error == FILE_CHANGED && !rewrote_after_change => {
                    rewrote_after_change = true;
                    self.notice = Some(RecordNotice::FileChanged);
                    let changed = ReleaseDraft::new(EntryKind::FileChanged, Outcome::Noted)
                        .into_entry(open.next_seq, now, false);
                    open.entries.push(changed);
                    open.next_seq += 1;
                    self.unwritten.push_front((draft, late));
                    if self.rewrite(session).is_err() {
                        self.mark_late();
                        return;
                    }
                }
                Err(_) => {
                    open.disk_valid = false;
                    self.unwritten.push_front((draft, true));
                    self.mark_late();
                    return;
                }
            }
        }
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.entries.len() >= COMPACT_AT)
        {
            self.trim(session, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, outcome: Outcome) -> RecordEntry {
        ReleaseDraft::new(EntryKind::BrowserFill, outcome)
            .host("example.com")
            .into_entry(seq, 1_000 + seq, false)
    }

    #[test]
    fn the_cap_removes_the_oldest_refusals_before_any_release() {
        let mut entries: Vec<RecordEntry> = (0..MAX_ENTRIES as u64)
            .map(|seq| {
                let outcome = if seq % 2 == 0 {
                    Outcome::Released
                } else {
                    Outcome::NoMatch
                };
                entry(seq, outcome)
            })
            .collect();
        entries.push(entry(MAX_ENTRIES as u64, Outcome::Released));
        entries.push(entry(MAX_ENTRIES as u64 + 1, Outcome::Denied));

        evict_over_cap(&mut entries);

        assert_eq!(entries.len(), MAX_ENTRIES);
        let released = entries
            .iter()
            .filter(|entry| entry.outcome == Outcome::Released)
            .count();
        assert_eq!(released, MAX_ENTRIES / 2 + 1);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 2);
        assert_eq!(
            entries.last().map(|entry| entry.seq),
            Some(MAX_ENTRIES as u64 + 1)
        );
    }

    #[test]
    fn the_cap_falls_back_to_the_oldest_entries_when_no_refusal_is_left() {
        let mut entries: Vec<RecordEntry> = (0..MAX_ENTRIES as u64 + 2)
            .map(|seq| entry(seq, Outcome::Released))
            .collect();

        evict_over_cap(&mut entries);

        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].seq, 2);
    }

    #[test]
    fn an_entry_line_is_padded_to_the_fixed_size_or_refused() {
        let key = [3_u8; 32];
        let record_id = [4_u8; 16];
        let prev = [5_u8; 32];
        let fits = entry(0, Outcome::Released);
        let line = entry_line(&key, &record_id, "vault", &prev, &fits).expect("encoded");
        let opened = open_entry(&key, &record_id, "vault", 0, &prev, &line[..line.len() - 1]);
        assert_eq!(opened, Some(fits));

        let mut too_long = entry(0, Outcome::Released);
        too_long.host = Some("h".repeat(PLAINTEXT_BYTES));
        assert!(entry_line(&key, &record_id, "vault", &prev, &too_long).is_err());
    }
}
