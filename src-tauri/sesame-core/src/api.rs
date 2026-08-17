//! Narrow typed operations over an in-memory vault, independent of any transport (IPC, FFI, or direct test calls).

use zeroize::{Zeroize, Zeroizing};

use crate::backup::unwrap_vault_key;
use crate::crypto::{
    decrypt_bytes, default_kdf_params, derive_key, encrypt_bytes, serialize_payload,
};
use crate::migration::{fresh_vault_id, migrate_payload, migrate_vault_file};
use crate::storage::check_supported_vault_format;
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
}

impl Drop for OpenedVault {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

/// Rejects a format this version cannot safely open, before any key derivation.
pub fn parse_vault_file(bytes: &[u8]) -> VaultResult<VaultFile> {
    let file: VaultFile = serde_json::from_slice(bytes).map_err(|_| {
        "This vault file is not valid. Restore a known-good encrypted backup.".to_string()
    })?;
    check_supported_vault_format(&file)?;
    Ok(file)
}

/// Either secret unlocks; the desktop commands stay strictly single-secret-type.
pub fn open_vault(file: &VaultFile, secret: &str) -> VaultResult<OpenedVault> {
    let key = unwrap_vault_key(file, secret)?;
    open_vault_with_key(file, key_array_from(key.as_slice())?)
}

/// Master password only; never falls back to treating the input as a recovery kit.
pub fn open_vault_with_password(file: &VaultFile, password: &str) -> VaultResult<OpenedVault> {
    open_vault_with_key(file, unwrap_key_with_password(file, password)?)
}

/// Recovery kit only; the format-2 fallback applies only to a genuinely legacy stored format.
pub fn open_vault_with_recovery_kit(
    file: &VaultFile,
    recovery_kit: &str,
) -> VaultResult<OpenedVault> {
    open_vault_with_key(file, unwrap_key_with_recovery_kit(file, recovery_kit)?)
}

/// Unwraps the key without decrypting the payload; avoids a double decrypt in full-open callers.
pub fn unwrap_key_with_password(file: &VaultFile, password: &str) -> VaultResult<[u8; 32]> {
    let wrapping_key = Zeroizing::new(derive_key(password, &file.kdf)?);
    let key = Zeroizing::new(
        decrypt_bytes(&wrapping_key, &file.key_wrap, WRAP_AAD).map_err(|_| {
            "Sesame could not unlock this vault. Check your master password.".to_string()
        })?,
    );
    key_array_from(key.as_slice())
}

pub fn unwrap_key_with_recovery_kit(file: &VaultFile, recovery_kit: &str) -> VaultResult<[u8; 32]> {
    let normalized_kit = recovery_kit.trim().to_ascii_uppercase();
    let (recovery_kdf, recovery_wrap, aad) = match (&file.recovery_kdf, &file.recovery_wrap) {
        (Some(recovery_kdf), Some(recovery_wrap)) => {
            (recovery_kdf, recovery_wrap, RECOVERY_WRAP_AAD)
        }
        // Fallback only for a genuinely legacy envelope; a stripped current-format file must say so.
        _ if file.format_version < VAULT_FORMAT_VERSION => {
            (&file.kdf, &file.key_wrap, WRAP_AAD)
        }
        _ => {
            return Err(
                "This vault file has no recovery wrapper. It has been changed or damaged since Sesame wrote it. Restore a known-good encrypted backup."
                    .into(),
            )
        }
    };
    let wrapping_key = Zeroizing::new(derive_key(&normalized_kit, recovery_kdf)?);
    let key = Zeroizing::new(
        decrypt_bytes(&wrapping_key, recovery_wrap, aad)
            .map_err(|_| "That recovery kit is not correct.".to_string())?,
    );
    key_array_from(key.as_slice())
}

fn key_array_from(key: &[u8]) -> VaultResult<[u8; 32]> {
    key.try_into().map_err(|_| {
        "The local vault key is invalid. Restore a known-good encrypted backup.".to_string()
    })
}

/// For keys already known by some other means, such as a PIN or Hello wrap.
pub fn open_vault_with_key(file: &VaultFile, key: [u8; 32]) -> VaultResult<OpenedVault> {
    let mut file = file.clone();
    let stored_payload_aad = payload_aad_for_file(file.format_version, file.setup_complete)?;
    let file_migrated = migrate_vault_file(&mut file)?;
    let payload_bytes = Zeroizing::new(
        decrypt_bytes(&key, &file.payload, stored_payload_aad).map_err(|_| {
            "The vault data could not be authenticated. Restore a known-good encrypted backup."
                .to_string()
        })?,
    );
    let mut payload: VaultPayload =
        serde_json::from_slice(payload_bytes.as_slice()).map_err(|_| {
            "The vault data could not be read. Restore a known-good encrypted backup.".to_string()
        })?;
    let payload_migrated = migrate_payload(&mut payload);
    Ok(OpenedVault {
        key: Zeroizing::new(key),
        payload,
        file,
        migrated: file_migrated || payload_migrated,
    })
}

pub fn open_vault_bytes(bytes: &[u8], secret: &str) -> VaultResult<OpenedVault> {
    open_vault(&parse_vault_file(bytes)?, secret)
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
