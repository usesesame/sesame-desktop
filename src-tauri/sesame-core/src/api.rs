//! Narrow typed operations over an in-memory vault, independent of any transport (IPC, FFI, or direct test calls).

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{default_kdf_params, derive_key, encrypt_bytes, serialize_payload};
use crate::loader::{Credential, MigrationPlan, VaultLoader};
use crate::migration::fresh_vault_id;
use crate::types::{Folder, VaultEntry, VaultFile, VaultPayload};
use crate::util::{fill_random, generate_recovery_kit};
use crate::{
    payload_aad_for_file, VaultResult, PENDING_SETUP_PAYLOAD_AAD, RECOVERY_WRAP_AAD,
    VAULT_FORMAT_VERSION, WRAP_AAD,
};

/// Like `UnlockedVault` but with no `PathBuf`, so FFI callers can hold it; `Drop` zeroizes.
pub struct OpenedVault {
    pub key: Zeroizing<[u8; 32]>,
    pub payload: VaultPayload,
    pub file: VaultFile,
    /// True when opening upgraded file/payload in memory; the caller decides when to persist.
    pub migrated: bool,
    pub migration: MigrationPlan,
}

impl Drop for OpenedVault {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

pub fn parse_vault_file(bytes: &[u8]) -> VaultResult<VaultFile> {
    VaultLoader::parse(bytes).map_err(Into::into)
}

pub fn open_vault(file: &VaultFile, secret: &str) -> VaultResult<OpenedVault> {
    VaultLoader::open(file, Credential::PasswordOrRecoveryKit(secret)).map_err(Into::into)
}

pub fn open_vault_with_password(file: &VaultFile, password: &str) -> VaultResult<OpenedVault> {
    VaultLoader::open(file, Credential::MasterPassword(password)).map_err(Into::into)
}

pub fn open_vault_with_recovery_kit(file: &VaultFile, kit: &str) -> VaultResult<OpenedVault> {
    VaultLoader::open(file, Credential::RecoveryKit(kit)).map_err(Into::into)
}

pub fn unwrap_key_with_password(file: &VaultFile, password: &str) -> VaultResult<[u8; 32]> {
    VaultLoader::unwrap_key(file, Credential::MasterPassword(password))
        .map(|key| *key)
        .map_err(Into::into)
}

pub fn unwrap_key_with_recovery_kit(file: &VaultFile, kit: &str) -> VaultResult<[u8; 32]> {
    VaultLoader::unwrap_key(file, Credential::RecoveryKit(kit))
        .map(|key| *key)
        .map_err(Into::into)
}

pub fn open_vault_with_key(file: &VaultFile, key: [u8; 32]) -> VaultResult<OpenedVault> {
    let key = Zeroizing::new(key);
    VaultLoader::open(file, Credential::VaultKey(&key)).map_err(Into::into)
}

pub fn open_vault_bytes(bytes: &[u8], secret: &str) -> VaultResult<OpenedVault> {
    VaultLoader::load(bytes, Credential::PasswordOrRecoveryKit(secret)).map_err(Into::into)
}

/// Fresh vault; the recovery kit returns in plain text exactly once.
pub fn create_vault(password: &str, vault_name: &str) -> VaultResult<(OpenedVault, String)> {
    if password.chars().count() < 12 {
        return Err("Use a master password with at least 12 characters.".into());
    }
    let mut vault_key = Zeroizing::new([0_u8; 32]);
    fill_random(&mut *vault_key);
    let kdf = default_kdf_params();
    let wrapping_key = Zeroizing::new(derive_key(password, &kdf)?);
    let key_wrap = encrypt_bytes(&wrapping_key, &*vault_key, WRAP_AAD)?;

    let recovery_kit = Zeroizing::new(generate_recovery_kit());
    let recovery_kit_for_display = recovery_kit.to_string();
    let recovery_kdf = default_kdf_params();
    let recovery_wrapping_key = Zeroizing::new(derive_key(&recovery_kit, &recovery_kdf)?);
    let recovery_wrap = encrypt_bytes(&recovery_wrapping_key, &*vault_key, RECOVERY_WRAP_AAD)?;

    let payload = empty_payload(vault_name);
    let encrypted_payload = encrypt_bytes(
        &vault_key,
        &serialize_payload(&payload)?,
        PENDING_SETUP_PAYLOAD_AAD,
    )?;
    let file = VaultFile {
        format_version: crate::VAULT_FORMAT_VERSION,
        kdf,
        key_wrap,
        legacy_device_wrap: None,
        recovery_kdf: Some(recovery_kdf),
        recovery_wrap: Some(recovery_wrap),
        pin_wrap: None,
        hello_wrap: None,
        setup_complete: false,
        payload: encrypted_payload,
    };
    Ok((
        OpenedVault {
            key: vault_key,
            payload,
            file,
            migrated: false,
            migration: MigrationPlan {
                source_format: VAULT_FORMAT_VERSION,
                target_format: VAULT_FORMAT_VERSION,
                envelope_changed: false,
                payload_changed: false,
            },
        },
        recovery_kit_for_display,
    ))
}

fn empty_payload(vault_name: &str) -> VaultPayload {
    VaultPayload {
        vault_name: vault_name.to_string(),
        folders: Vec::<Folder>::new(),
        entries: Vec::<VaultEntry>::new(),
        identities: Vec::new(),
        secure_notes: Vec::new(),
        cards: Vec::new(),
        wifi_networks: Vec::new(),
        ssh_keys: Vec::new(),
        software_licenses: Vec::new(),
        documents: Vec::new(),
        custom_records: Vec::new(),
        trash: Vec::new(),
        history: Vec::new(),
        vault_id: Some(fresh_vault_id()),
        revision: 1,
    }
}

/// Re-encrypts the payload into the file and bumps the revision; the caller writes the bytes.
pub fn seal_vault(opened: &OpenedVault) -> VaultResult<VaultFile> {
    let mut file = opened.file.clone();
    let mut payload = opened.payload.clone();
    payload.revision += 1;
    let payload_aad = payload_aad_for_file(file.format_version, file.setup_complete)?;
    file.payload = encrypt_bytes(&opened.key, &serialize_payload(&payload)?, payload_aad)?;
    Ok(file)
}
