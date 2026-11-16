use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{bytes_match, decrypt_bytes, encrypt_bytes};
use crate::storage::atomic_replace;
use crate::types::CipherBlob;
use crate::util::{fill_secret, read_file_with_limit};
use crate::{UnlockedVault, VaultResult};

pub const PENDING_FILE: &str = "pending-changes.sesame";
pub const DAMAGED_PENDING_FILE: &str = "pending-changes.damaged.sesame";
pub const MAX_UNRESOLVED: usize = 64;
pub const HANDLE_LIFETIME_SECS: u64 = 86_400;
pub const RESOLVED_KEEP_SECS: u64 = 86_400;
pub const ESCALATE_AFTER_SECS: u64 = 23 * 86_400;
pub const HANDLE_CHARS: usize = 43;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const FORMAT_NAME: &str = "sesame-pending-changes";
const FORMAT_VERSION: u8 = 1;
const KEY_INFO: &[u8] = b"sesame:pending-changes:v1:key";
const AAD_LABEL: &[u8] = b"sesame:pending-changes:v1:list";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum PendingKind {
    Change,
    New,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum FillState {
    Unknown,
    Filled,
    NotFilled,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Resolution {
    Unconfirmed,
    Kept,
    Returned,
    Discarded,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingChange {
    pub id: String,
    pub handle_digest: String,
    pub item_id: String,
    pub history_id: Option<String>,
    pub origin: String,
    pub host: String,
    pub kind: PendingKind,
    pub revision: u32,
    pub created_at: u64,
    pub fill: FillState,
    pub accepted_at: Option<u64>,
    pub resolution: Resolution,
    pub resolved_at: Option<u64>,
    pub username_attached: bool,
}

impl PendingChange {
    pub fn is_unresolved(&self) -> bool {
        self.resolution == Resolution::Unconfirmed
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u8,
    salt: String,
    list: CipherBlob,
}

pub fn pending_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(PENDING_FILE)
}

pub fn damaged_pending_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(DAMAGED_PENDING_FILE)
}

pub fn issue_handle() -> VaultResult<(Zeroizing<String>, String)> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    fill_secret(&mut *bytes)?;
    let handle = Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes));
    let digest = handle_digest(&handle);
    Ok((handle, digest))
}

pub fn handle_digest(handle: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(handle.as_bytes()))
}

pub fn valid_handle(handle: &str) -> bool {
    handle.len() == HANDLE_CHARS
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub fn find_by_handle<'a>(
    changes: &'a mut [PendingChange],
    handle: &str,
    origin: &str,
    now: u64,
) -> Option<&'a mut PendingChange> {
    if !valid_handle(handle) {
        return None;
    }
    let digest = handle_digest(handle);
    changes.iter_mut().find(|change| {
        bytes_match(change.handle_digest.as_bytes(), digest.as_bytes())
            && change.origin == origin
            && now < change.created_at.saturating_add(HANDLE_LIFETIME_SECS)
    })
}

pub fn prune(changes: &mut Vec<PendingChange>, now: u64) {
    changes.retain(|change| {
        change.is_unresolved()
            || change
                .resolved_at
                .is_some_and(|at| now < at.saturating_add(RESOLVED_KEEP_SECS))
    });
}

pub fn has_room(changes: &[PendingChange]) -> bool {
    changes
        .iter()
        .filter(|change| change.is_unresolved())
        .count()
        < MAX_UNRESOLVED
}

fn derive_key(vault_key: &[u8; 32], salt: &[u8; 16]) -> VaultResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), vault_key);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(KEY_INFO, &mut *key)
        .map_err(|_| "Sesame could not prepare the list of new passwords.".to_string())?;
    Ok(key)
}

fn list_aad(salt: &[u8; 16], vault_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + 20 + vault_id.len());
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&(vault_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

pub fn seal(
    vault_key: &[u8; 32],
    vault_id: &str,
    changes: &[PendingChange],
) -> VaultResult<Vec<u8>> {
    let mut salt = [0_u8; 16];
    fill_secret(&mut salt)?;
    let key = derive_key(vault_key, &salt)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(changes)
            .map_err(|_| "Sesame could not prepare the list of new passwords.".to_string())?,
    );
    let list = encrypt_bytes(&key, &plaintext, &list_aad(&salt, vault_id))?;
    serde_json::to_vec(&Envelope {
        format: FORMAT_NAME.to_string(),
        version: FORMAT_VERSION,
        salt: URL_SAFE_NO_PAD.encode(salt),
        list,
    })
    .map_err(|_| "Sesame could not prepare the list of new passwords.".to_string())
}

pub fn open(bytes: &[u8], vault_key: &[u8; 32], vault_id: &str) -> Option<Vec<PendingChange>> {
    let envelope: Envelope = serde_json::from_slice(bytes).ok()?;
    if envelope.format != FORMAT_NAME || envelope.version != FORMAT_VERSION {
        return None;
    }
    let salt: [u8; 16] = URL_SAFE_NO_PAD
        .decode(envelope.salt.as_bytes())
        .ok()?
        .try_into()
        .ok()?;
    let key = derive_key(vault_key, &salt).ok()?;
    let plaintext = decrypt_bytes(&key, &envelope.list, &list_aad(&salt, vault_id)).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

pub fn read_pending(session: &UnlockedVault) -> Vec<PendingChange> {
    let path = pending_path(&session.path);
    let bytes = match read_file_with_limit(&path, MAX_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            set_aside(session);
            return Vec::new();
        }
    };
    let vault_id = session.vault_id().unwrap_or_default().to_string();
    let opened = session
        .expose_vault_key(|vault_key| Ok(open(&bytes, vault_key, &vault_id)))
        .ok()
        .flatten();
    match opened {
        Some(changes) => changes,
        None => {
            set_aside(session);
            Vec::new()
        }
    }
}

fn set_aside(session: &UnlockedVault) {
    let _ = std::fs::rename(
        pending_path(&session.path),
        damaged_pending_path(&session.path),
    );
}

pub fn write_pending(session: &UnlockedVault, changes: &[PendingChange]) -> VaultResult<()> {
    let vault_id = session.vault_id().unwrap_or_default().to_string();
    let bytes = session.expose_vault_key(|vault_key| seal(vault_key, &vault_id, changes))?;
    atomic_replace(&pending_path(&session.path), &bytes)
        .map_err(|_| "Sesame could not save the list of new passwords.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(handle_digest: &str, created_at: u64) -> PendingChange {
        PendingChange {
            id: "change-one".to_string(),
            handle_digest: handle_digest.to_string(),
            item_id: "login-one".to_string(),
            history_id: Some("history-one".to_string()),
            origin: "https://example.com".to_string(),
            host: "example.com".to_string(),
            kind: PendingKind::Change,
            revision: 3,
            created_at,
            fill: FillState::Unknown,
            accepted_at: None,
            resolution: Resolution::Unconfirmed,
            resolved_at: None,
            username_attached: false,
        }
    }

    #[test]
    fn a_sealed_list_opens_with_the_same_key_and_vault() {
        let key = [7_u8; 32];
        let list = vec![change("digest", 100)];
        let bytes = seal(&key, "vault-one", &list).expect("sealed");
        assert_eq!(open(&bytes, &key, "vault-one"), Some(list));
    }

    #[test]
    fn another_key_or_vault_or_a_changed_byte_opens_nothing() {
        let key = [7_u8; 32];
        let bytes = seal(&key, "vault-one", &[change("digest", 100)]).expect("sealed");
        assert_eq!(open(&bytes, &[8_u8; 32], "vault-one"), None);
        assert_eq!(open(&bytes, &key, "vault-two"), None);
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let ciphertext = envelope["list"]["ciphertext"]
            .as_str()
            .expect("text")
            .to_string();
        let flipped = if ciphertext.starts_with('A') {
            "B"
        } else {
            "A"
        };
        envelope["list"]["ciphertext"] =
            serde_json::Value::String(format!("{flipped}{}", &ciphertext[1..]));
        let tampered = serde_json::to_vec(&envelope).expect("json");
        assert_eq!(open(&tampered, &key, "vault-one"), None);
        assert_eq!(open(b"not a list", &key, "vault-one"), None);
    }

    #[test]
    fn the_file_holds_neither_the_handle_nor_its_digest_in_the_clear() {
        let (handle, digest) = issue_handle().expect("handle");
        let bytes = seal(&[7_u8; 32], "vault-one", &[change(&digest, 100)]).expect("sealed");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(handle.as_str()));
        assert!(!text.contains(&digest));
        assert!(!text.contains("example.com"));
    }

    #[test]
    fn a_handle_finds_its_change_only_for_its_origin_and_lifetime() {
        let (handle, digest) = issue_handle().expect("handle");
        assert!(valid_handle(&handle));
        let mut list = vec![change(&digest, 1_000)];
        assert!(find_by_handle(&mut list, &handle, "https://example.com", 1_001).is_some());
        assert!(find_by_handle(&mut list, &handle, "https://other.example.com", 1_001).is_none());
        assert!(find_by_handle(
            &mut list,
            &handle,
            "https://example.com",
            1_000 + HANDLE_LIFETIME_SECS
        )
        .is_none());
        let (foreign, _) = issue_handle().expect("handle");
        assert!(find_by_handle(&mut list, &foreign, "https://example.com", 1_001).is_none());
        assert!(find_by_handle(&mut list, "short", "https://example.com", 1_001).is_none());
        assert!(find_by_handle(&mut list, &digest, "https://example.com", 1_001).is_none());
    }

    #[test]
    fn resolved_changes_leave_after_a_day_and_unresolved_ones_stay() {
        let mut kept = change("one", 0);
        kept.resolution = Resolution::Kept;
        kept.resolved_at = Some(10);
        let mut old = change("two", 0);
        old.resolution = Resolution::Returned;
        old.resolved_at = Some(0);
        let waiting = change("three", 0);
        let mut list = vec![kept, old, waiting];
        prune(&mut list, RESOLVED_KEEP_SECS + 5);
        let digests: Vec<&str> = list
            .iter()
            .map(|item| item.handle_digest.as_str())
            .collect();
        assert_eq!(digests, vec!["one", "three"]);
        prune(&mut list, 400 * 86_400);
        assert_eq!(list.len(), 1);
        assert!(list[0].is_unresolved());
    }

    #[test]
    fn the_list_has_room_until_the_unresolved_limit() {
        let mut list: Vec<PendingChange> = (0..MAX_UNRESOLVED).map(|_| change("d", 0)).collect();
        assert!(!has_room(&list));
        list[0].resolution = Resolution::Kept;
        assert!(has_room(&list));
    }
}
