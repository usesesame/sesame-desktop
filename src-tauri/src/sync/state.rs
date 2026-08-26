//! What this device last agreed with the service: the compare-and-swap base and a payload digest for dirty detection.
//! None of it is secret, but it must be treated as untrusted on read: a corrupt file may only cause a conflict.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::VaultResult;

pub const STATE_FILE_NAME: &str = "sync-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncBase {
    pub version: u8,
    pub vault_id: String,
    pub revision: i64,
    pub vault_epoch: i64,
    /// Digest of the payload at that revision; a mismatch means unsynced local edits.
    pub payload_digest: String,
    /// Envelope digest of that revision, the chain predecessor; empty only for a device that never applied one.
    #[serde(default)]
    pub head_digest: String,
    /// The service's signed acceptance, so this device re-checks against the service's attestation.
    #[serde(default)]
    pub receipt: String,
}

impl SyncBase {
    pub fn new(vault_id: &str, revision: i64, vault_epoch: i64, payload: &[u8]) -> Self {
        Self {
            version: 1,
            vault_id: vault_id.to_string(),
            revision,
            vault_epoch,
            payload_digest: payload_digest(payload),
            head_digest: String::new(),
            receipt: String::new(),
        }
    }

    pub fn with_head(mut self, head_digest: &str, receipt: &str) -> Self {
        self.head_digest = head_digest.to_string();
        self.receipt = receipt.to_string();
        self
    }

    pub fn has_local_changes(&self, payload: &[u8]) -> bool {
        self.payload_digest != payload_digest(payload)
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

/// Unreadable or wrongly versioned reads as absent: the failure direction is a conflict, never an overwrite.
#[cfg_attr(not(test), allow(dead_code))]
pub fn read(path: &Path) -> Option<SyncBase> {
    let body = std::fs::read(path).ok()?;
    let base: SyncBase = serde_json::from_slice(&body).ok()?;
    if base.version != 1 || base.vault_id.is_empty() || base.revision < 0 {
        return None;
    }
    Some(base)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn write(path: &Path, base: &SyncBase) -> VaultResult<()> {
    let body = serde_json::to_vec(base)
        .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    }
    crate::vault::storage::atomic_replace(path, &body)
}

/// DPAPI-protected tag authenticating the state file; edited or foreign files fail to verify.
fn tag_path(path: &Path) -> PathBuf {
    path.with_extension("json.tag")
}

fn state_tag(body: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"sesame-sync-state-tag-v1");
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().to_vec()
}

pub fn write_protected(path: &Path, base: &SyncBase) -> VaultResult<()> {
    let body = serde_json::to_vec(base)
        .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    }
    // Tag first: a crash leaves a mismatch that reads as absent, which fails closed.
    let protected = crate::vault::platform::protect_for_device(&state_tag(&body))
        .map_err(|_| "Sesame could not record the Sync state.".to_string())?;
    crate::vault::storage::atomic_replace(&tag_path(path), &protected)?;
    crate::vault::storage::atomic_replace(path, &body)
}

/// Reads only when the tag proves this profile wrote it; a mismatch reads as no state, the safe direction.
pub fn read_protected(path: &Path) -> Option<SyncBase> {
    let body = std::fs::read(path).ok()?;
    let protected = std::fs::read(tag_path(path)).ok()?;
    let expected = crate::vault::platform::unprotect_for_device(&protected).ok()?;
    let actual = state_tag(&body);
    // Constant-time compare: an attacker who can write the state file controls both sides.
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
    let base: SyncBase = serde_json::from_slice(&body).ok()?;
    if base.version != 1 || base.vault_id.is_empty() || base.revision < 0 {
        return None;
    }
    Some(base)
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
    Offer { revision: i64 },
    Conflict { server_revision: i64 },
}

pub fn decide_upload(base_revision: i64, server_revision: i64) -> UploadDecision {
    if server_revision != base_revision {
        return UploadDecision::Conflict { server_revision };
    }
    UploadDecision::Offer {
        revision: base_revision.max(0) + 1,
    }
}
