//! Encrypted local recovery artifacts written before a Sync conflict is resolved.
//! Each is a real `VaultFile`, read back and decrypted before the live vault is touched.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::vault::crypto::encrypt_bytes;
use crate::vault::{UnlockedVault, VaultFile, VaultResult, PAYLOAD_AAD, VAULT_FORMAT_VERSION};
use sesame_core::loader::{AuthenticatedPayload, Credential, VaultLoader};

pub const BACKUP_DIR_NAME: &str = "sync-conflict-backups";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    ThisDevice,
    OtherDevice,
}

impl Side {
    fn slug(self) -> &'static str {
        match self {
            Side::ThisDevice => "this-device",
            Side::OtherDevice => "other-device",
        }
    }
}

pub fn backup_dir(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(BACKUP_DIR_NAME)
}

/// Writes one artifact, then reads it back and decrypts it; an unverifiable file is worse than none.
pub fn write_verified(
    directory: &Path,
    vault: &UnlockedVault,
    side: Side,
    revision: i64,
    payload_bytes: &[u8],
    stamp: &str,
) -> VaultResult<PathBuf> {
    if !vault.setup_complete {
        return Err("Verify your recovery kit before creating recovery copies.".into());
    }
    std::fs::create_dir_all(directory)
        .map_err(|_| "Sesame could not create the recovery copy folder.".to_string())?;

    let encrypted_payload =
        vault.expose_vault_key(|key| encrypt_bytes(key, payload_bytes, PAYLOAD_AAD))?;
    let file = VaultFile {
        format_version: VAULT_FORMAT_VERSION,
        kdf: vault.kdf.clone(),
        key_wrap: vault.key_wrap.clone(),
        legacy_device_wrap: None,
        recovery_kdf: vault.recovery_kdf.clone(),
        recovery_wrap: vault.recovery_wrap.clone(),
        pin_wrap: vault.pin_wrap.clone(),
        hello_wrap: vault.hello_wrap.clone(),
        setup_complete: true,
        payload: encrypted_payload,
    };
    let body = serde_json::to_vec(&file)
        .map_err(|_| "Sesame could not write the recovery copy.".to_string())?;

    let path = create_new_file(directory, side, revision, stamp, &body)?;

    let recovered = vault.expose_vault_key(|key| read_verified(&path, key))?;
    if recovered.payload.bytes() != payload_bytes || recovered.revision != revision {
        // Remove it rather than leave an artifact that claims to hold a vault it does not.
        let _ = std::fs::remove_file(&path);
        return Err("Sesame could not verify the recovery copy.".to_string());
    }
    Ok(path)
}

/// Exclusive creation, retrying with a fresh random name; never truncates an existing file.
fn create_new_file(
    directory: &Path,
    side: Side,
    revision: i64,
    stamp: &str,
    body: &[u8],
) -> VaultResult<PathBuf> {
    use std::io::Write;

    for _ in 0..8 {
        let mut suffix = [0_u8; 8];
        crate::vault::util::fill_random(&mut suffix);
        let name = format!(
            "{stamp}-{}-{revision}-{}.sesame",
            side.slug(),
            URL_SAFE_NO_PAD.encode(suffix)
        );
        let path = directory.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(body)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| "Sesame could not write the recovery copy.".to_string())?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Sesame could not write the recovery copy.".to_string()),
        }
    }
    Err("Sesame could not write the recovery copy.".to_string())
}

/// Read back with the session's raw key; revision comes from the file name, not the payload.
pub struct RecoveredBackup {
    pub revision: i64,
    pub entry_count: usize,
    pub payload: AuthenticatedPayload,
}

/// Fast-path read with the raw session key; the same file opens by master password or kit like any backup.
pub fn read_verified(path: &Path, key: &[u8; 32]) -> VaultResult<RecoveredBackup> {
    let file = VaultLoader::read(path)?;
    let payload = VaultLoader::authenticate(&file, Credential::VaultKey(key))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (_, revision) = parse_file_name(&file_name)
        .ok_or("Sesame could not read the recovery copy.".to_string())?;
    Ok(RecoveredBackup {
        revision,
        entry_count: payload.payload().entries.len(),
        payload,
    })
}

pub struct BackupListing {
    pub file_name: String,
    pub side: String,
    pub revision: i64,
    pub entry_count: usize,
    pub created_at: String,
}

/// Finds a side slug rather than splitting on `-`, which appears inside the slugs themselves.
fn parse_file_name(file_name: &str) -> Option<((&str, Side), i64)> {
    for side in [Side::ThisDevice, Side::OtherDevice] {
        let marker = format!("-{}-", side.slug());
        let Some(index) = file_name.find(&marker) else {
            continue;
        };
        let stamp = &file_name[..index];
        let after = &file_name[index + marker.len()..];
        let revision: i64 = after.split('-').next()?.parse().ok()?;
        return Some(((stamp, side), revision));
    }
    None
}

/// Lists artifacts this key can open, newest first; another key's artifacts are skipped.
pub fn list(directory: &Path, key: &[u8; 32]) -> Vec<BackupListing> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("sesame") {
            continue;
        }
        let Ok(recovered) = read_verified(&path, key) else {
            continue;
        };
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(((stamp, side), _)) = parse_file_name(&file_name) else {
            continue;
        };
        found.push(BackupListing {
            file_name: file_name.clone(),
            side: side.slug().to_string(),
            revision: recovered.revision,
            entry_count: recovered.entry_count,
            created_at: stamp.to_string(),
        });
    }
    found.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    found
}

/// Bounded directory: two copies per resolution near the 10 MiB snapshot limit can fill a disk.
pub const MAX_BACKUPS: usize = 12;
pub const MAX_BACKUP_BYTES: u64 = 256 * 1024 * 1024;

/// Prunes oldest first; the copies for the resolution happening right now are protected.
pub fn prune(directory: &Path, keep: &[PathBuf]) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("sesame") {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            Some((
                metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
                metadata.len(),
                path,
            ))
        })
        .collect();
    // Newest first, so draining from the end removes the oldest.
    files.sort_by(|left, right| right.0.cmp(&left.0));

    let mut kept = 0_usize;
    let mut bytes = 0_u64;
    for (_, size, path) in files {
        let protected = keep.iter().any(|reserved| reserved == &path);
        kept += 1;
        bytes = bytes.saturating_add(size);
        if protected {
            continue;
        }
        if kept > MAX_BACKUPS || bytes > MAX_BACKUP_BYTES {
            let _ = std::fs::remove_file(&path);
        }
    }
}
