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
    create_new_file_with(directory, side, revision, stamp, |file| {
        use std::io::Write;
        file.write_all(body).and_then(|()| file.sync_all())
    })
}

fn create_new_file_with(
    directory: &Path,
    side: Side,
    revision: i64,
    stamp: &str,
    persist: impl Fn(&mut std::fs::File) -> std::io::Result<()>,
) -> VaultResult<PathBuf> {
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
                let durable = persist(&mut file).and_then(|()| {
                    drop(file);
                    sync_directory(directory)
                });
                if durable.is_err() {
                    let _ = std::fs::remove_file(&path);
                    return Err("Sesame could not write the recovery copy.".to_string());
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Sesame could not write the recovery copy.".to_string()),
        }
    }
    Err("Sesame could not write the recovery copy.".to_string())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
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
#[must_use]
pub fn prune(directory: &Path, keep: &[PathBuf]) -> usize {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(_) => return 1,
    };
    let mut failed = 0_usize;
    let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("sesame") {
            continue;
        }
        match entry.metadata() {
            Ok(metadata) => files.push((
                metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
                metadata.len(),
                path,
            )),
            Err(_) => failed += 1,
        }
    }
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
        if (kept > MAX_BACKUPS || bytes > MAX_BACKUP_BYTES) && std::fs::remove_file(&path).is_err()
        {
            failed += 1;
        }
    }
    failed
}

pub fn prune_and_report(app: &tauri::AppHandle, directory: &Path, keep: &[PathBuf]) {
    if prune(directory, keep) > 0 {
        crate::diagnostics::record_backup_io_error(app);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use std::time::{Duration, SystemTime};

    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "sesame-recovery-{name}-{}",
            crate::vault::random_id()
        ));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        directory
    }

    fn copies(directory: &Path) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("listed directory")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sesame"))
            .collect();
        found.sort();
        found
    }

    fn write_aged(directory: &Path, name: &str, age_seconds: u64) -> PathBuf {
        let path = directory.join(name);
        let file = std::fs::File::create(&path).expect("created copy");
        file.set_modified(SystemTime::now() - Duration::from_secs(age_seconds))
            .expect("set age");
        path
    }

    #[test]
    fn a_failed_write_leaves_no_partial_copy_behind() {
        let directory = scratch("partial");

        let result = create_new_file_with(&directory, Side::ThisDevice, 3, "stamp", |file| {
            use std::io::Write;
            file.write_all(b"half a vault")?;
            Err(std::io::Error::other("disk full"))
        });

        assert!(result.is_err());
        assert!(copies(&directory).is_empty());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_copy_that_reaches_the_disk_stays() {
        let directory = scratch("whole");

        let path = create_new_file_with(&directory, Side::OtherDevice, 4, "stamp", |file| {
            use std::io::Write;
            file.write_all(b"a vault").and_then(|()| file.sync_all())
        })
        .expect("written copy");

        assert_eq!(copies(&directory), vec![path.clone()]);
        assert_eq!(std::fs::read(&path).expect("read copy"), b"a vault");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_entry_is_synced_and_a_missing_directory_is_an_error() {
        let directory = scratch("sync");

        assert!(sync_directory(&directory).is_ok());
        assert!(sync_directory(&directory.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_verified_copy_reads_back_with_the_session_key() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let directory = scratch("verified");
        let guard = vault.state.session.lock().expect("session lock");
        let session = guard.as_ref().expect("session");
        let payload =
            serde_json::to_vec(&*session.open_payload().expect("payload")).expect("payload bytes");

        let path = write_verified(&directory, session, Side::ThisDevice, 7, &payload, "stamp")
            .expect("written copy");

        let recovered = session
            .expose_vault_key(|key| read_verified(&path, key))
            .expect("read back");
        assert_eq!(recovered.revision, 7);
        assert_eq!(recovered.entry_count, 1);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_vault_without_a_verified_recovery_kit_writes_no_copy() {
        let vault = TestVault::with_login("login-a", "https://northwind.example");
        let directory = scratch("unverified");
        let mut guard = vault.state.session.lock().expect("session lock");
        let session = guard.as_mut().expect("session");
        session.setup_complete = false;

        let result = write_verified(&directory, session, Side::ThisDevice, 1, b"{}", "stamp");

        assert!(result.is_err());
        assert!(copies(&directory).is_empty());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn pruning_removes_the_oldest_beyond_the_limit_and_keeps_the_protected_copy() {
        let directory = scratch("prune");
        let mut paths = Vec::new();
        for index in 0..MAX_BACKUPS + 3 {
            paths.push(write_aged(
                &directory,
                &format!("copy-{index:02}.sesame"),
                (MAX_BACKUPS as u64 + 3 - index as u64) * 60,
            ));
        }
        let protected = paths[0].clone();

        let failed = prune(&directory, std::slice::from_ref(&protected));

        assert_eq!(failed, 0);
        let left = copies(&directory);
        assert!(left.contains(&protected));
        assert!(!left.contains(&paths[1]));
        assert!(left.contains(&paths[MAX_BACKUPS + 2]));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_that_cannot_be_removed_is_counted_not_hidden() {
        use std::os::unix::fs::PermissionsExt;
        let directory = scratch("locked");
        for index in 0..MAX_BACKUPS + 2 {
            write_aged(
                &directory,
                &format!("copy-{index:02}.sesame"),
                (MAX_BACKUPS as u64 + 2 - index as u64) * 60,
            );
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .expect("locked directory");
        let probe = directory.join("probe");
        let root = std::fs::File::create(&probe).is_ok();
        if root {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
                .expect("restored directory");
            let _ = std::fs::remove_dir_all(&directory);
            return;
        }

        let failed = prune(&directory, &[]);

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("restored directory");
        assert_eq!(failed, 2);
        assert_eq!(copies(&directory).len(), MAX_BACKUPS + 2);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_directory_has_nothing_to_prune() {
        let directory = scratch("missing-prune");
        let missing = directory.join("not-created");
        assert_eq!(prune(&missing, &[]), 0);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_directory_that_cannot_be_listed_counts_as_a_pruning_failure() {
        let directory = scratch("unlistable-prune");
        let not_a_directory = directory.join("plain-file");
        std::fs::write(&not_a_directory, b"x").expect("plain file");
        assert_eq!(prune(&not_a_directory, &[]), 1);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
