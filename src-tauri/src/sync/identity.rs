//! Per-device Sync identity: separate Ed25519 signing and X25519 key-agreement pairs.
//! Secrets are DPAPI-protected under the Windows profile, zeroized after use, never exposed to the webview.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::sync::keys::{EncryptionKeypair, X25519_KEY_BYTES};
use crate::vault::platform::{protect_for_device, unprotect_for_device};
use crate::vault::VaultResult;

pub const IDENTITY_FILE_NAME: &str = "sync-identity.sesame";
const SIGNING_SEED_BYTES: usize = 32;
/// 16 random bytes, 22 base64url characters; the server accepts 16 to 128.
const OPAQUE_ID_BYTES: usize = 16;

/// Both secrets are DPAPI-protected before they reach disk.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    device_id: String,
    protected_signing_seed: String,
    protected_encryption_secret: String,
}

pub struct DeviceIdentity {
    pub device_id: String,
    signing: SigningKey,
    encryption: EncryptionKeypair,
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
        })
    }

    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn encryption_public_key(&self) -> [u8; X25519_KEY_BYTES] {
        self.encryption.public_key()
    }

    /// Wrapper so commands never hold the signing key; every use stays on this side of IPC.
    pub fn seal_envelope(
        &self,
        draft: &crate::sync::envelope::EnvelopeDraft<'_>,
    ) -> VaultResult<crate::sync::envelope::Envelope> {
        crate::sync::envelope::seal(draft, &self.signing)
    }

    pub fn encryption_keypair(&self) -> &EncryptionKeypair {
        &self.encryption
    }

    /// Binds vault, device, and keys; the challenge is the encoded form the service signs.
    pub fn enrollment_proof(&self, vault_id: &str, challenge: &str) -> VaultResult<String> {
        let payload = enrollment_signing_payload(
            vault_id,
            &self.device_id,
            &URL_SAFE_NO_PAD.encode(self.signing_public_key()),
            &URL_SAFE_NO_PAD.encode(self.encryption_public_key()),
            challenge,
        )?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing.sign(&payload).to_bytes()))
    }

    /// Key access stays off the IPC side; the caller zeroizes the returned key.
    pub fn open_key_package(&self, sealed: &[u8], vault_id: &str) -> VaultResult<Vec<u8>> {
        crate::sync::keys::open_vault_key(sealed, &self.encryption, vault_id)
    }

    /// Signs a sealed package; lives here so no command reaches for the signing key.
    pub fn sign_key_package(
        &self,
        vault_id: &str,
        recipient_device_id: &str,
        encoded_package: &str,
    ) -> VaultResult<String> {
        let payload = key_package_signing_payload(
            vault_id,
            &self.device_id,
            recipient_device_id,
            encoded_package,
        )?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing.sign(&payload).to_bytes()))
    }

    pub fn save(&self, path: &Path) -> VaultResult<()> {
        let mut signing_seed = self.signing.to_bytes();
        let protected_signing = protect_for_device(&signing_seed);
        signing_seed.zeroize();

        let mut encryption_secret = self.encryption.secret_bytes();
        let protected_encryption = protect_for_device(&encryption_secret);
        encryption_secret.zeroize();

        let stored = StoredIdentity {
            version: 1,
            device_id: self.device_id.clone(),
            protected_signing_seed: URL_SAFE_NO_PAD.encode(protected_signing?),
            protected_encryption_secret: URL_SAFE_NO_PAD.encode(protected_encryption?),
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
        let stored: StoredIdentity = serde_json::from_slice(&body)
            .map_err(|_| "Sesame could not read the device keys.".to_string())?;
        if stored.version != 1 {
            return Err("These device keys were written by a newer Sesame.".to_string());
        }

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

        Ok(Self {
            device_id: stored.device_id,
            signing,
            encryption,
        })
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

/// Exact JSON a device signs to prove enrollment; field order is the contract, fixture-asserted against Go in enrollment-signing-payload.json.
pub fn enrollment_signing_payload(
    vault_id: &str,
    device_id: &str,
    signing_public_key: &str,
    encryption_public_key: &str,
    challenge: &str,
) -> VaultResult<Vec<u8>> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        vault_id: &'a str,
        device_id: &'a str,
        signing_public_key: &'a str,
        encryption_public_key: &'a str,
        challenge: &'a str,
    }
    serde_json::to_vec(&Payload {
        vault_id,
        device_id,
        signing_public_key,
        encryption_public_key,
        challenge,
    })
    .map_err(|_| "Sesame could not prepare the device enrollment proof.".to_string())
}

/// Exact JSON signed for a key package; field order is the contract, fixture-asserted against Go in key-package-signing-payload.json.
pub fn key_package_signing_payload(
    vault_id: &str,
    sender_device_id: &str,
    recipient_device_id: &str,
    ciphertext: &str,
) -> VaultResult<Vec<u8>> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        vault_id: &'a str,
        sender_device_id: &'a str,
        recipient_device_id: &'a str,
        ciphertext: &'a str,
    }
    serde_json::to_vec(&Payload {
        vault_id,
        sender_device_id,
        recipient_device_id,
        ciphertext,
    })
    .map_err(|_| "Sesame could not prepare the device key package.".to_string())
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

impl DeviceIdentity {
    /// Signs proof of holding the wrapped package; Go counterpart `syncproto.ActivationPayload`.
    pub fn sign_activation(
        &self,
        vault_id: &str,
        device_epoch: u64,
        encoded_package: &str,
    ) -> VaultResult<String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload<'a> {
            vault_id: &'a str,
            device_id: &'a str,
            device_epoch: u64,
            ciphertext: &'a str,
        }
        let payload = serde_json::to_vec(&Payload {
            vault_id,
            device_id: &self.device_id,
            device_epoch,
            ciphertext: encoded_package,
        })
        .map_err(|_| "Sesame could not confirm this device.".to_string())?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing.sign(&payload).to_bytes()))
    }

    /// Signed by this device: an account token alone must not authorise a removal.
    pub fn sign_revocation_intent(
        &self,
        vault_id: &str,
        target_device_id: &str,
        caller_epoch: u64,
    ) -> VaultResult<String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload<'a> {
            vault_id: &'a str,
            caller_device_id: &'a str,
            target_device_id: &'a str,
            caller_epoch: u64,
        }
        let payload = serde_json::to_vec(&Payload {
            vault_id,
            caller_device_id: &self.device_id,
            target_device_id,
            caller_epoch,
        })
        .map_err(|_| "Sesame could not authorise that removal.".to_string())?;
        Ok(URL_SAFE_NO_PAD.encode(self.signing.sign(&payload).to_bytes()))
    }
}
