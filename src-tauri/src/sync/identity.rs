//! Per-device Sync identity: separate Ed25519 signing and X25519 key-agreement pairs.
//! Secrets are DPAPI-protected under the Windows profile, zeroized after use, never exposed to the webview.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::sync::keys::{EncryptionKeypair, X25519_KEY_BYTES};
use crate::sync::xwing::SecretKey as HybridSecretKey;
use crate::vault::VaultResult;

pub const IDENTITY_FILE_NAME: &str = "sync-identity.sesame";
const SIGNING_SEED_BYTES: usize = 32;
const HYBRID_PACKAGE_MIN_BYTES: usize = 512;
const WRITTEN_BY_NEWER_BUILD: &str = "These device keys were written by a newer Sesame.";
/// 16 random bytes, 22 base64url characters; the server accepts 16 to 128.
const OPAQUE_ID_BYTES: usize = 16;

/// Both secrets are DPAPI-protected before they reach disk.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    device_id: String,
    protected_signing_seed: String,
    protected_encryption_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protected_hybrid_seed: Option<String>,
}

#[cfg(test)]
pub(crate) fn protect_for_device(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(test)]
pub(crate) fn unprotect_for_device(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(not(test))]
pub(crate) use crate::vault::platform::{protect_for_device, unprotect_for_device};

pub(crate) fn ensure_device_protection() -> VaultResult<()> {
    #[cfg(test)]
    {
        Ok(())
    }
    #[cfg(not(test))]
    {
        crate::vault::platform::ensure_device_protection()
    }
}

pub struct DeviceIdentity {
    pub device_id: String,
    signing: SigningKey,
    encryption: EncryptionKeypair,
    hybrid: Option<HybridSecretKey>,
}

impl DeviceIdentity {
    pub fn generate() -> VaultResult<Self> {
        let mut seed = [0u8; SIGNING_SEED_BYTES];
        SysRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| "Sesame could not generate device keys.".to_string())?;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            device_id: random_opaque_id()?,
            signing,
            encryption: EncryptionKeypair::generate()?,
            hybrid: Some(HybridSecretKey::generate()?),
        })
    }

    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    #[cfg(test)]
    pub fn encryption_public_key(&self) -> [u8; X25519_KEY_BYTES] {
        self.encryption.public_key()
    }

    pub fn package_public_key(&self) -> Vec<u8> {
        match &self.hybrid {
            Some(hybrid) => hybrid.public_key().to_vec(),
            None => self.encryption.public_key().to_vec(),
        }
    }

    #[cfg(test)]
    pub fn has_hybrid_key(&self) -> bool {
        self.hybrid.is_some()
    }

    #[cfg(test)]
    pub fn without_hybrid_key(mut self) -> Self {
        self.hybrid = None;
        self
    }

    pub fn sign_entry(
        &self,
        entry: crate::sync::devicelist::DeviceListEntry,
    ) -> crate::sync::devicelist::DeviceListEntry {
        entry.sign(&self.signing)
    }

    pub fn sign_header(&self, header: crate::sync::header::Header) -> crate::sync::header::Header {
        header.sign(&self.signing)
    }

    pub fn sign_checkpoint(
        &self,
        checkpoint: crate::sync::checkpoint::Checkpoint,
    ) -> crate::sync::checkpoint::Checkpoint {
        checkpoint.sign(&self.signing)
    }

    pub fn sign_request(&self, request: &crate::sync::request::RequestSignature<'_>) -> String {
        request.sign(&self.signing)
    }

    pub fn sign_key_package(
        &self,
        package: crate::sync::request::KeyPackageV3,
    ) -> crate::sync::request::KeyPackageV3 {
        package.sign(&self.signing)
    }

    pub fn open_key_package(
        &self,
        sealed: &[u8],
        vault_id: &str,
        epoch: u64,
    ) -> VaultResult<Vec<u8>> {
        if sealed.len() > HYBRID_PACKAGE_MIN_BYTES {
            let hybrid = self
                .hybrid
                .as_ref()
                .ok_or("This device key package could not be read.")?;
            return crate::sync::keys::open_vault_key_hybrid(sealed, hybrid, vault_id, epoch);
        }
        crate::sync::keys::open_vault_key(sealed, &self.encryption, vault_id)
    }

    pub fn save(&self, path: &Path) -> VaultResult<()> {
        ensure_device_protection()?;
        let mut signing_seed = self.signing.to_bytes();
        let protected_signing = protect_for_device(&signing_seed);
        signing_seed.zeroize();

        let mut encryption_secret = self.encryption.secret_bytes();
        let protected_encryption = protect_for_device(&encryption_secret);
        encryption_secret.zeroize();

        let protected_hybrid_seed = match &self.hybrid {
            Some(hybrid) => {
                let mut seed = hybrid.seed_bytes();
                let protected = protect_for_device(&seed);
                seed.zeroize();
                Some(URL_SAFE_NO_PAD.encode(protected?))
            }
            None => None,
        };
        let stored = StoredIdentity {
            version: if protected_hybrid_seed.is_some() {
                2
            } else {
                1
            },
            device_id: self.device_id.clone(),
            protected_signing_seed: URL_SAFE_NO_PAD.encode(protected_signing?),
            protected_encryption_secret: URL_SAFE_NO_PAD.encode(protected_encryption?),
            protected_hybrid_seed,
        };
        let body = serde_json::to_vec(&stored)
            .map_err(|_| "Sesame could not save the device keys.".to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| "Sesame could not save the device keys.".to_string())?;
        }
        // Atomic write: a crash must not destroy the only copy of these approved keys.
        crate::vault::storage::atomic_replace(path, &body)
            .map_err(|_| "Sesame could not save the device keys.".to_string())
    }

    /// A file from another machine or user fails at the DPAPI unprotect, as intended.
    pub fn load(path: &Path) -> VaultResult<Self> {
        let body = std::fs::read(path)
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;
        #[derive(Deserialize)]
        struct StoredVersion {
            version: u8,
        }
        let probe: StoredVersion = serde_json::from_slice(&body)
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;
        if probe.version != 1 && probe.version != 2 {
            return Err(WRITTEN_BY_NEWER_BUILD.to_string());
        }
        let stored: StoredIdentity = serde_json::from_slice(&body)
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;

        let mut signing_seed = unprotect_for_device(
            &URL_SAFE_NO_PAD
                .decode(&stored.protected_signing_seed)
                .map_err(|_| "Sesame could not read the device keys.".to_string())?,
        )?;
        let signing_array: [u8; SIGNING_SEED_BYTES] = signing_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;
        let signing = SigningKey::from_bytes(&signing_array);
        signing_seed.zeroize();

        let mut encryption_secret = unprotect_for_device(
            &URL_SAFE_NO_PAD
                .decode(&stored.protected_encryption_secret)
                .map_err(|_| "Sesame could not read the device keys.".to_string())?,
        )?;
        let encryption_array: [u8; X25519_KEY_BYTES] = encryption_secret
            .as_slice()
            .try_into()
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;
        let encryption = EncryptionKeypair::from_secret_bytes(encryption_array);
        encryption_secret.zeroize();

        let hybrid = match (&stored.protected_hybrid_seed, stored.version) {
            (Some(encoded), 2) => {
                let mut seed = unprotect_for_device(
                    &URL_SAFE_NO_PAD
                        .decode(encoded)
                        .map_err(|_| "Sesame could not read the device keys.".to_string())?,
                )?;
                let array: [u8; crate::sync::xwing::SEED_BYTES] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Sesame could not read the device keys.".to_string())?;
                seed.zeroize();
                Some(HybridSecretKey::from_seed(array))
            }
            (None, 1) => None,
            _ => return Err("Sesame could not read the device keys.".to_string()),
        };

        Ok(Self {
            device_id: stored.device_id,
            signing,
            encryption,
            hybrid,
        })
    }
}

pub fn load_or_create(path: &Path) -> VaultResult<DeviceIdentity> {
    match DeviceIdentity::load(path) {
        Ok(existing) => Ok(existing),
        Err(error) if error == WRITTEN_BY_NEWER_BUILD => Err(error),
        Err(_) => {
            let generated = DeviceIdentity::generate()?;
            generated.save(path)?;
            Ok(generated)
        }
    }
}

/// The keys are useless after revocation and must not linger.
pub fn forget(path: &Path) -> VaultResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the device keys.".to_string()),
    }
}

pub fn identity_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(IDENTITY_FILE_NAME)
}

/// Opaque 16-byte identifier; the service must not relate it to the vault.
pub fn random_opaque_id() -> VaultResult<String> {
    let mut raw = [0u8; OPAQUE_ID_BYTES];
    SysRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| "Sesame could not generate a device identifier.".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

#[cfg(test)]
mod hybrid_tests {
    use super::*;
    use crate::sync::keys::{seal_vault_key, seal_vault_key_hybrid};
    use crate::sync::xwing::PUBLIC_KEY_BYTES;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sesame-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        identity_path(&dir)
    }

    #[test]
    fn a_new_identity_publishes_its_hybrid_key() {
        let identity = DeviceIdentity::generate().expect("identity");
        assert_eq!(identity.package_public_key().len(), PUBLIC_KEY_BYTES);
        assert!(identity.has_hybrid_key());
    }

    #[test]
    fn a_saved_hybrid_identity_loads_with_the_same_public_key_and_opens_packages() {
        let path = scratch("round-trip");
        let identity = DeviceIdentity::generate().expect("identity");
        identity.save(&path).expect("saved");
        let loaded = DeviceIdentity::load(&path).expect("loaded");
        assert_eq!(loaded.package_public_key(), identity.package_public_key());
        let sealed = seal_vault_key_hybrid(
            &[9u8; 32],
            &identity.package_public_key(),
            "vaultAAAAAAAAAAAA01",
            3,
        )
        .expect("sealed");
        assert_eq!(
            loaded
                .open_key_package(&sealed, "vaultAAAAAAAAAAAA01", 3)
                .expect("opened"),
            vec![9u8; 32]
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_older_identity_file_without_a_hybrid_key_still_loads_and_publishes_its_classical_key() {
        let path = scratch("older");
        let identity = DeviceIdentity::generate()
            .expect("identity")
            .without_hybrid_key();
        identity.save(&path).expect("saved");
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(body["version"], 1);
        assert!(body.get("protected_hybrid_seed").is_none());
        let loaded = DeviceIdentity::load(&path).expect("loaded");
        assert!(!loaded.has_hybrid_key());
        assert_eq!(loaded.package_public_key().len(), X25519_KEY_BYTES);
        let sealed = seal_vault_key(
            &[9u8; 32],
            &loaded.encryption_public_key(),
            "vaultAAAAAAAAAAAA01",
        )
        .expect("sealed");
        assert_eq!(
            loaded
                .open_key_package(&sealed, "vaultAAAAAAAAAAAA01", 3)
                .expect("opened"),
            vec![9u8; 32]
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_hybrid_identity_file_is_marked_with_a_newer_version_that_an_older_build_refuses() {
        let path = scratch("version");
        DeviceIdentity::generate()
            .expect("identity")
            .save(&path)
            .expect("saved");
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(body["version"], 2);
        assert!(body.get("protected_hybrid_seed").is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_classical_only_identity_refuses_a_hybrid_package_and_a_hybrid_one_still_reads_a_classical_one(
    ) {
        let classical_only = DeviceIdentity::generate()
            .expect("identity")
            .without_hybrid_key();
        let hybrid = DeviceIdentity::generate().expect("identity");
        let sealed = seal_vault_key_hybrid(
            &[9u8; 32],
            &hybrid.package_public_key(),
            "vaultAAAAAAAAAAAA01",
            1,
        )
        .expect("sealed");
        assert!(classical_only
            .open_key_package(&sealed, "vaultAAAAAAAAAAAA01", 1)
            .is_err());
        let classical = seal_vault_key(
            &[9u8; 32],
            &hybrid.encryption_public_key(),
            "vaultAAAAAAAAAAAA01",
        )
        .expect("sealed");
        assert!(hybrid
            .open_key_package(&classical, "vaultAAAAAAAAAAAA01", 1)
            .is_ok());
    }

    #[test]
    fn a_hybrid_package_for_the_wrong_epoch_does_not_open() {
        let identity = DeviceIdentity::generate().expect("identity");
        let sealed = seal_vault_key_hybrid(
            &[9u8; 32],
            &identity.package_public_key(),
            "vaultAAAAAAAAAAAA01",
            2,
        )
        .expect("sealed");
        assert!(identity
            .open_key_package(&sealed, "vaultAAAAAAAAAAAA01", 3)
            .is_err());
    }

    fn rewritten(path: &Path, change: impl FnOnce(&mut serde_json::Value)) {
        let mut body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        change(&mut body);
        std::fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
    }

    #[test]
    fn an_identity_file_this_build_does_not_understand_is_refused_and_left_untouched() {
        let path = scratch("unknown");
        DeviceIdentity::generate()
            .expect("identity")
            .save(&path)
            .expect("saved");
        rewritten(&path, |body| body["version"] = serde_json::json!(3));
        let before = std::fs::read(&path).unwrap();
        assert!(DeviceIdentity::load(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_version_and_the_hybrid_seed_must_agree() {
        let path = scratch("agree");
        DeviceIdentity::generate()
            .expect("identity")
            .save(&path)
            .expect("saved");
        rewritten(&path, |body| {
            body.as_object_mut()
                .unwrap()
                .remove("protected_hybrid_seed");
        });
        assert!(
            DeviceIdentity::load(&path).is_err(),
            "version 2 without a seed"
        );

        DeviceIdentity::generate()
            .expect("identity")
            .save(&path)
            .expect("saved");
        rewritten(&path, |body| body["version"] = serde_json::json!(1));
        assert!(
            DeviceIdentity::load(&path).is_err(),
            "version 1 with a seed"
        );

        DeviceIdentity::generate()
            .expect("identity")
            .save(&path)
            .expect("saved");
        for seed in ["", "AAAA", "not base64!"] {
            rewritten(&path, |body| {
                body["protected_hybrid_seed"] = serde_json::json!(seed)
            });
            assert!(DeviceIdentity::load(&path).is_err(), "seed {seed:?}");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_copied_identity_file_restores_the_same_device_and_keys() {
        let path = scratch("restore");
        let identity = DeviceIdentity::generate().expect("identity");
        identity.save(&path).expect("saved");
        let restored = path.with_file_name("restored.sesame");
        std::fs::copy(&path, &restored).unwrap();
        forget(&path).expect("forgotten");
        assert!(DeviceIdentity::load(&path).is_err());
        let loaded = DeviceIdentity::load(&restored).expect("restored");
        assert_eq!(loaded.device_id, identity.device_id);
        assert_eq!(loaded.package_public_key(), identity.package_public_key());
        assert_eq!(loaded.signing_public_key(), identity.signing_public_key());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_device_that_forgot_its_keys_and_pairs_again_gets_a_new_device_and_a_new_hybrid_key() {
        let path = scratch("forget");
        let first = DeviceIdentity::generate()
            .expect("identity")
            .without_hybrid_key();
        first.save(&path).expect("saved");
        assert_eq!(
            DeviceIdentity::load(&path)
                .expect("loaded")
                .package_public_key()
                .len(),
            X25519_KEY_BYTES
        );
        forget(&path).expect("forgotten");
        forget(&path).expect("forgetting twice is fine");
        assert!(!path.exists());
        let second = DeviceIdentity::generate().expect("identity");
        second.save(&path).expect("saved");
        let loaded = DeviceIdentity::load(&path).expect("loaded");
        assert_ne!(loaded.device_id, first.device_id);
        assert_ne!(loaded.signing_public_key(), first.signing_public_key());
        assert_eq!(loaded.package_public_key().len(), PUBLIC_KEY_BYTES);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn setup_keeps_a_file_from_a_newer_build_and_replaces_one_it_cannot_read() {
        let path = scratch("load-or-create");
        let created = load_or_create(&path).expect("created");
        assert!(created.has_hybrid_key());
        assert_eq!(
            load_or_create(&path).expect("loaded").device_id,
            created.device_id
        );

        rewritten(&path, |body| body["version"] = serde_json::json!(3));
        let before = std::fs::read(&path).unwrap();
        assert!(load_or_create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);

        std::fs::write(
            &path,
            br#"{"version":3,"keys":"a layout this build does not know"}"#,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            load_or_create(&path).err().as_deref(),
            Some(WRITTEN_BY_NEWER_BUILD)
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);

        std::fs::write(&path, b"damaged").unwrap();
        let replaced = load_or_create(&path).expect("replaced");
        assert_ne!(replaced.device_id, created.device_id);
        assert_eq!(
            DeviceIdentity::load(&path).expect("loads").device_id,
            replaced.device_id
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
