//! What this device last agreed with the service: the compare-and-swap base and a payload digest for dirty detection.
//! None of it is secret, but it must be treated as untrusted on read: a corrupt file may only cause a conflict.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sync::devicelist::{DeviceList, DeviceListEntry};
use crate::sync::header::Header;
use crate::vault::VaultResult;

pub const STATE_FILE_NAME: &str = "sync-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredReceipt {
    pub signature: String,
    pub accepted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostedCheckpoint {
    pub device_list_index: u64,
    pub header_revision: u64,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncState {
    pub version: u8,
    pub vault_id: String,
    pub device_id: String,
    pub entries: Vec<DeviceListEntry>,
    pub head: Option<Header>,
    pub payload_digest: String,
    pub floor: u64,
    pub receipt: Option<StoredReceipt>,
    pub activated_epoch: u64,
    #[serde(default)]
    pub last_checkpoint: Option<PostedCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_join: Option<crate::sync::pairing::ApproverIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_confirmation: Option<String>,
}

pub const STATE_VERSION: u8 = 3;

pub const CHECKPOINT_INTERVAL_SECS: u64 = 60 * 60;

pub fn checkpoint_due(
    last: Option<&PostedCheckpoint>,
    device_list_index: u64,
    header_revision: u64,
    now: u64,
) -> bool {
    match last {
        None => true,
        Some(last) => {
            last.device_list_index != device_list_index
                || last.header_revision != header_revision
                || now.saturating_sub(last.at) >= CHECKPOINT_INTERVAL_SECS
                || last.at > now
        }
    }
}

impl SyncState {
    pub fn new(vault_id: &str, device_id: &str) -> Self {
        Self {
            version: STATE_VERSION,
            vault_id: vault_id.to_string(),
            device_id: device_id.to_string(),
            entries: Vec::new(),
            head: None,
            payload_digest: String::new(),
            floor: 0,
            receipt: None,
            activated_epoch: 0,
            last_checkpoint: None,
            pending_join: None,
            pending_confirmation: None,
        }
    }

    pub fn list(&self) -> Result<DeviceList, crate::sync::canonical::ProofError> {
        DeviceList::verify(&self.entries)
    }

    pub fn head_revision(&self) -> u64 {
        self.head.as_ref().map_or(0, |header| header.revision)
    }

    pub fn has_local_changes(&self, payload: &[u8]) -> bool {
        self.payload_digest != payload_digest(payload)
    }

    pub fn require_join_complete(&self) -> VaultResult<()> {
        if self.pending_join.is_some() {
            return Err(
                "Finish joining this vault before syncing. Open Sync and try Join again.".into(),
            );
        }
        Ok(())
    }
}

/// Domain-separated; never sent anywhere, only compares this device against its own earlier state.
pub fn payload_digest(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"sesame-sync-payload-v1");
    digest.update(payload);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn state_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(STATE_FILE_NAME)
}

/// DPAPI-protected tag authenticating the state file; edited or foreign files fail to verify.
fn tag_path(path: &Path) -> PathBuf {
    path.with_extension("json.tag")
}

const STATE_TAG_LABEL: &[u8] = b"sesame-sync-state-tag-v1";

fn tag_for(label: &[u8], body: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().to_vec()
}

#[cfg(test)]
fn state_tag(body: &[u8]) -> Vec<u8> {
    tag_for(STATE_TAG_LABEL, body)
}

#[cfg(test)]
fn protect(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(test)]
fn unprotect(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(not(test))]
fn protect(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    crate::vault::platform::protect_for_device(bytes)
        .map_err(|_| "Sesame could not record the Sync state.".to_string())
}

#[cfg(not(test))]
fn unprotect(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    crate::vault::platform::unprotect_for_device(bytes)
}

pub(crate) fn write_tagged(path: &Path, label: &[u8], body: &[u8]) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    }
    let protected = protect(&tag_for(label, body))?;
    crate::vault::storage::atomic_replace(&tag_path(path), &protected)?;
    crate::vault::storage::atomic_replace(path, body)
}

pub(crate) fn read_tagged(path: &Path, label: &[u8]) -> Option<Vec<u8>> {
    let body = std::fs::read(path).ok()?;
    let protected = std::fs::read(tag_path(path)).ok()?;
    let expected = unprotect(&protected).ok()?;
    let actual = tag_for(label, &body);
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected.iter())
            .fold(0_u8, |differences, (left, right)| {
                differences | (left ^ right)
            })
            != 0
    {
        return None;
    }
    Some(body)
}

pub fn write_protected(path: &Path, base: &SyncState) -> VaultResult<()> {
    let body = serde_json::to_vec(base)
        .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    write_tagged(path, STATE_TAG_LABEL, &body)
}

pub fn read_protected(path: &Path) -> Option<SyncState> {
    let body = read_tagged(path, STATE_TAG_LABEL)?;
    let state: SyncState = serde_json::from_slice(&body).ok()?;
    if state.version != STATE_VERSION || state.vault_id.is_empty() || state.device_id.is_empty() {
        return None;
    }
    state.list().ok()?;
    Some(state)
}

pub fn forget_protected(path: &Path) -> VaultResult<()> {
    forget(path)?;
    forget(&tag_path(path))
}

pub fn forget(path: &Path) -> VaultResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the Sync state.".to_string()),
    }
}

/// The decision an upload makes from its own recorded base, never the server head.
#[derive(Debug, PartialEq, Eq)]
pub enum UploadDecision {
    Offer { revision: u64 },
    Conflict { server_revision: u64 },
}

pub fn decide_upload(base_revision: u64, server_revision: u64) -> UploadDecision {
    if server_revision != base_revision {
        return UploadDecision::Conflict { server_revision };
    }
    match base_revision.checked_add(1) {
        Some(revision) => UploadDecision::Offer { revision },
        None => UploadDecision::Conflict { server_revision },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_for(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sesame-sync-state-{name}-{}", std::process::id()))
    }

    fn path_for(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE_NAME)
    }

    fn sample_base(revision: u64) -> SyncState {
        let mut state = SyncState::new("vault-1-0000000000000", "device-1-000000000000");
        state.payload_digest = payload_digest(b"payload-bytes");
        state.floor = revision;
        state
    }

    #[test]
    fn protected_state_round_trips_and_refuses_edits() {
        let dir = dir_for("roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_for(&dir);
        let base = sample_base(3);
        write_protected(&path, &base).unwrap();
        assert_eq!(read_protected(&path), Some(base.clone()));

        let body = std::fs::read(&path).unwrap();
        let mut edited = body.clone();
        edited[0] ^= 0xff;
        std::fs::write(&path, &edited).unwrap();
        assert_eq!(read_protected(&path), None);

        std::fs::write(&path, &body).unwrap();
        std::fs::write(tag_path(&path), b"not-a-real-tag").unwrap();
        assert_eq!(read_protected(&path), None);

        std::fs::write(tag_path(&path), protect(&state_tag(&body)).unwrap()).unwrap();
        assert_eq!(read_protected(&path), Some(base));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticated_garbage_reads_as_absent() {
        let dir = dir_for("garbage");
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_for(&dir);
        write_protected(&path, &sample_base(1)).unwrap();
        let garbage = b"{broken";
        std::fs::write(&path, garbage).unwrap();
        std::fs::write(tag_path(&path), protect(&state_tag(garbage)).unwrap()).unwrap();
        assert_eq!(read_protected(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forget_is_idempotent_and_missing_state_reads_as_absent() {
        let dir = dir_for("forget");
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_for(&dir);
        assert_eq!(read_protected(&path), None);
        write_protected(&path, &sample_base(1)).unwrap();
        forget_protected(&path).unwrap();
        assert_eq!(read_protected(&path), None);
        assert!(!path.exists());
        forget_protected(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_replace_the_recorded_base() {
        let dir = dir_for("replace");
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_for(&dir);
        write_protected(&path, &sample_base(1)).unwrap();
        write_protected(&path, &sample_base(2)).unwrap();
        assert_eq!(read_protected(&path).map(|base| base.floor), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_decisions_compare_against_the_recorded_base() {
        assert_eq!(decide_upload(0, 0), UploadDecision::Offer { revision: 1 });
        assert_eq!(decide_upload(3, 3), UploadDecision::Offer { revision: 4 });
        assert_eq!(
            decide_upload(3, 4),
            UploadDecision::Conflict { server_revision: 4 }
        );
        assert_eq!(
            decide_upload(3, 2),
            UploadDecision::Conflict { server_revision: 2 }
        );
    }
}
