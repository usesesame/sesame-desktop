use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::VaultResult;

pub const PEERS_FILE_NAME: &str = "sync-peers.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPeer {
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub approved_here: bool,
}

#[derive(Serialize, Deserialize)]
struct StoredPeers {
    version: u8,
    vault_id: String,
    devices: BTreeMap<String, TrustedPeer>,
}

pub fn peers_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(PEERS_FILE_NAME)
}

fn tag_path(path: &Path) -> PathBuf {
    path.with_extension("json.tag")
}

fn peers_tag(body: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"sesame-sync-peers-tag-v1");
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.finalize().to_vec()
}

fn read_store(path: &Path) -> Option<StoredPeers> {
    let body = std::fs::read(path).ok()?;
    let protected = std::fs::read(tag_path(path)).ok()?;
    let expected = crate::vault::platform::unprotect_for_device(&protected).ok()?;
    let actual = peers_tag(&body);
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
    let store: StoredPeers = serde_json::from_slice(&body).ok()?;
    if store.version != 1 {
        return None;
    }
    Some(store)
}

fn write_store(path: &Path, store: &StoredPeers) -> VaultResult<()> {
    let body = serde_json::to_vec(store)
        .map_err(|_| "Sesame could not record the trusted Sync devices.".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| "Sesame could not record the trusted Sync devices.".to_string())?;
    }
    let protected = crate::vault::platform::protect_for_device(&peers_tag(&body))
        .map_err(|_| "Sesame could not record the trusted Sync devices.".to_string())?;
    crate::vault::storage::atomic_replace(&tag_path(path), &protected)?;
    crate::vault::storage::atomic_replace(path, &body)
}

fn load_or_init(path: &Path, vault_id: &str) -> StoredPeers {
    match read_store(path) {
        Some(store) if store.vault_id == vault_id => store,
        _ => StoredPeers {
            version: 1,
            vault_id: vault_id.to_string(),
            devices: BTreeMap::new(),
        },
    }
}

pub fn record_verified(
    path: &Path,
    vault_id: &str,
    device_id: &str,
    signing_public_key: &str,
) -> VaultResult<()> {
    let mut store = load_or_init(path, vault_id);
    if let Some(existing) = store.devices.get(device_id) {
        if existing.signing_public_key != signing_public_key {
            return Err(
                "The service reported different signing keys for a Sync device this one already verified. Sync is paused for safety; remove and re-add the device."
                    .into(),
            );
        }
        return Ok(());
    }
    store.devices.insert(
        device_id.to_string(),
        TrustedPeer {
            signing_public_key: signing_public_key.to_string(),
            encryption_public_key: String::new(),
            approved_here: false,
        },
    );
    write_store(path, &store)
}

pub fn record_approved(
    path: &Path,
    vault_id: &str,
    device_id: &str,
    signing_public_key: &str,
    encryption_public_key: &str,
) -> VaultResult<()> {
    let mut store = load_or_init(path, vault_id);
    if let Some(existing) = store.devices.get(device_id) {
        if existing.signing_public_key != signing_public_key
            || (existing.approved_here && existing.encryption_public_key != encryption_public_key)
        {
            return Err(
                "The service reported different keys for a Sync device this one already verified. Sync is paused for safety; remove and re-add the device."
                    .into(),
            );
        }
    }
    store.devices.insert(
        device_id.to_string(),
        TrustedPeer {
            signing_public_key: signing_public_key.to_string(),
            encryption_public_key: encryption_public_key.to_string(),
            approved_here: true,
        },
    );
    write_store(path, &store)
}

pub fn require_releasable(
    path: &Path,
    vault_id: &str,
    device_id: &str,
    listing_signing_key: &str,
    listing_encryption_key: &str,
) -> Result<(), String> {
    let substituted = || {
        "The service reported different keys for a Sync device this one already verified. Sync is paused for safety; remove and re-add the device."
    };
    let store = read_store(path).ok_or_else(|| {
        "This device has not verified that device's Sync keys. Remove it from the device that approved it, which also protects the vault key, or turn Sync off on it."
    })?;
    if store.vault_id != vault_id {
        return Err(
            "This device has not verified that device's Sync keys. Remove it from the device that approved it, which also protects the vault key, or turn Sync off on it."
                .into(),
        );
    }
    let pin = store.devices.get(device_id).ok_or_else(|| {
        "This device has not verified that device's Sync keys. Remove it from the device that approved it, which also protects the vault key, or turn Sync off on it."
    })?;
    if pin.signing_public_key != listing_signing_key {
        return Err(substituted().into());
    }
    if !pin.approved_here || pin.encryption_public_key.is_empty() {
        return Err(
            "This device has not verified that device's key in an approval. Remove it from the device that approved it, which also protects the vault key, or turn Sync off on it."
                .into(),
        );
    }
    if pin.encryption_public_key != listing_encryption_key {
        return Err(substituted().into());
    }
    Ok(())
}

pub fn forget(path: &Path) -> VaultResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the trusted Sync devices.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_for(dir: &Path) -> PathBuf {
        dir.join(PEERS_FILE_NAME)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    const VAULT: &str = "vault-1";
    const SIGNING: &str = "signing-key-b64";
    const SIGNING_OTHER: &str = "signing-key-other";
    const ENCRYPTION: &str = "encryption-key-b64";
    const ENCRYPTION_OTHER: &str = "encryption-key-other";

    #[test]
    fn verified_pins_accumulate_and_refuse_substitution() {
        let dir =
            std::env::temp_dir().join(format!("sesame-peers-verified-{}", std::process::id()));
        let path = path_for(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        record_verified(&path, VAULT, "device-a", SIGNING).unwrap();
        record_verified(&path, VAULT, "device-a", SIGNING).unwrap();
        assert!(record_verified(&path, VAULT, "device-a", SIGNING_OTHER).is_err());
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap_err();
        cleanup(&dir);
    }

    #[test]
    fn approved_pins_release_and_detect_key_swaps() {
        let dir =
            std::env::temp_dir().join(format!("sesame-peers-approved-{}", std::process::id()));
        let path = path_for(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap_err();
        record_verified(&path, VAULT, "device-a", SIGNING).unwrap();
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap_err();
        record_approved(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap();
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap();
        require_releasable(&path, VAULT, "device-a", SIGNING_OTHER, ENCRYPTION).unwrap_err();
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION_OTHER).unwrap_err();
        cleanup(&dir);
    }

    #[test]
    fn pins_do_not_carry_between_vaults_or_survive_a_foreign_file() {
        let dir = std::env::temp_dir().join(format!("sesame-peers-vaults-{}", std::process::id()));
        let path = path_for(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        record_approved(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap();
        require_releasable(&path, "other-vault", "device-a", SIGNING, ENCRYPTION).unwrap_err();
        std::fs::write(&path, b"{tampered}").unwrap();
        require_releasable(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap_err();
        record_approved(&path, VAULT, "device-b", SIGNING, ENCRYPTION).unwrap();
        require_releasable(&path, VAULT, "device-b", SIGNING, ENCRYPTION).unwrap();
        cleanup(&dir);
    }

    #[test]
    fn approval_rejects_conflicting_prior_pins() {
        let dir =
            std::env::temp_dir().join(format!("sesame-peers-conflict-{}", std::process::id()));
        let path = path_for(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        record_approved(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap();
        assert!(record_approved(&path, VAULT, "device-a", SIGNING_OTHER, ENCRYPTION).is_err());
        assert!(record_approved(&path, VAULT, "device-a", SIGNING, ENCRYPTION_OTHER).is_err());
        record_approved(&path, VAULT, "device-a", SIGNING, ENCRYPTION).unwrap();
        cleanup(&dir);
    }
}
