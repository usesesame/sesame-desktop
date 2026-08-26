use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decrypt_bytes, derive_key};
use crate::platform::unprotect_for_device;
use crate::storage::write_vault_file;
use crate::{
    payload_aad_for_file, VaultFile, VaultPayload, VaultResult, MAX_BACKUP_BYTES,
    RECOVERY_WRAP_AAD, VAULT_FORMAT_VERSION, WRAP_AAD,
};
use crate::{
    types::*,
    util::{random_id, unix_timestamp},
};

/// Master password or recovery kit; the format-2 kit-as-primary-wrap case is tried too.
pub fn unwrap_vault_key(file: &VaultFile, secret: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
    let attempts: Vec<(&KdfParams, &CipherBlob, &[u8], String)> = {
        let mut attempts: Vec<(&KdfParams, &CipherBlob, &[u8], String)> =
            vec![(&file.kdf, &file.key_wrap, WRAP_AAD, secret.to_string())];
        let kit = secret.trim().to_ascii_uppercase();
        match (&file.recovery_kdf, &file.recovery_wrap) {
            (Some(recovery_kdf), Some(recovery_wrap)) => {
                attempts.push((recovery_kdf, recovery_wrap, RECOVERY_WRAP_AAD, kit));
            }
            // Gated on the stored format: a stripped current-format file must not guess at the master wrap.
            _ if file.format_version < crate::VAULT_FORMAT_VERSION => {
                attempts.push((&file.kdf, &file.key_wrap, WRAP_AAD, kit))
            }
            _ => {}
        }
        attempts
    };

    for (kdf, wrap, aad, candidate) in attempts {
        let Ok(wrapping_key) = derive_key(&candidate, kdf) else {
            continue;
        };
        let mut wrapping_key = Zeroizing::new(wrapping_key);
        if let Ok(mut vault_key) = decrypt_bytes(&wrapping_key, wrap, aad) {
            let key: Result<[u8; 32], _> = vault_key.as_slice().try_into();
            vault_key.zeroize();
            wrapping_key.zeroize();
            return key
                .map(Zeroizing::new)
                .map_err(|_| "That backup contains an invalid vault key.".to_string());
        }
        wrapping_key.zeroize();
    }
    Err("That master password or recovery kit does not open this backup.".into())
}

/// The secret must unwrap the key, and the key must authenticate the payload.
pub fn authenticate_vault_file(file: &VaultFile, secret: &str) -> VaultResult<()> {
    let key = unwrap_vault_key(file, secret)?;
    let payload_aad = payload_aad_for_file(file.format_version, file.setup_complete)?;
    let payload_bytes = Zeroizing::new(decrypt_bytes(&key, &file.payload, payload_aad).map_err(
        |_| "That backup is damaged. Its contents could not be authenticated.".to_string(),
    )?);
    let mut payload: VaultPayload = serde_json::from_slice(payload_bytes.as_slice())
        .map_err(|_| "That backup is damaged. Its contents could not be read.".to_string())?;
    payload.zeroize();
    Ok(())
}

/// Non-destructive; only display-safe metadata leaves this function.
pub fn verify_backup_file(path: &Path, secret: &str) -> VaultResult<BackupVerification> {
    let file = read_backup_file(path)?;
    let key = unwrap_vault_key(&file, secret)?;
    let payload_aad = payload_aad_for_file(file.format_version, file.setup_complete)?;
    let payload_bytes = Zeroizing::new(decrypt_bytes(&key, &file.payload, payload_aad).map_err(
        |_| "That backup is damaged. Its contents could not be authenticated.".to_string(),
    )?);
    let mut payload: VaultPayload = serde_json::from_slice(payload_bytes.as_slice())
        .map_err(|_| "That backup is damaged. Its contents could not be read.".to_string())?;
    let verification = BackupVerification {
        file_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .ok_or("Sesame could not read the backup file name.")?,
        format_version: file.format_version,
        vault_name: payload.vault_name.clone(),
        entry_count: payload.entries.len(),
        vault_id: payload.vault_id.clone(),
        revision: payload.revision,
    };
    payload.zeroize();
    Ok(verification)
}

/// Device-bound material on another profile can never be used again.
fn usable_on_this_profile(protected: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(protected) else {
        return false;
    };
    match unprotect_for_device(&bytes) {
        Ok(mut plain) => {
            plain.zeroize();
            true
        }
        Err(_) => false,
    }
}

/// A restored vault must never advertise an unlock method that must fail.
pub fn strip_unusable_device_material(file: &mut VaultFile) {
    if file
        .pin_wrap
        .as_ref()
        .is_some_and(|pin_wrap| !usable_on_this_profile(&pin_wrap.protected_pepper))
    {
        file.pin_wrap = None;
    }
    if file
        .legacy_device_wrap
        .as_deref()
        .is_some_and(|wrap| !usable_on_this_profile(wrap))
    {
        file.legacy_device_wrap = None;
    }
    if file
        .hello_wrap
        .as_ref()
        .is_some_and(|wrap| !crate::windows_hello::key_exists(&wrap.key_name))
    {
        file.hello_wrap = None;
    }
}

pub const RECOVERY_HEALTH_FILE: &str = "recovery-health.sesame";

pub fn managed_vault_paths(vault: &Path) -> Vec<PathBuf> {
    let parent = vault.parent().unwrap_or_else(|| Path::new(""));
    vec![
        vault.to_path_buf(),
        vault.with_extension("sesame.prev"),
        vault.with_extension("sesame.tmp"),
        parent.join(crate::storage::PIN_THROTTLE_FILE),
        parent.join(RECOVERY_HEALTH_FILE),
        parent.join("backups"),
    ]
}

pub fn stage_managed_vault_files(vault: &Path, parent: &Path) -> VaultResult<StagedVaultFiles> {
    stage_managed_vault_files_with(vault, parent, |from, to| fs::rename(from, to))
}

pub fn stage_managed_vault_files_with<F>(
    vault: &Path,
    parent: &Path,
    mut move_path: F,
) -> VaultResult<StagedVaultFiles>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let staging_dir = parent.join(format!(".sesame-delete-{}", random_id()));
    fs::create_dir(&staging_dir).map_err(|_| {
        "Sesame could not prepare the local vault for deletion. The vault was left unchanged."
            .to_string()
    })?;

    let mut moved = Vec::new();
    for source in managed_vault_paths(vault) {
        if !source.exists() {
            continue;
        }
        let name = source
            .file_name()
            .ok_or("Sesame could not prepare the local vault for deletion.")?;
        let destination = staging_dir.join(name);
        match move_path(&source, &destination) {
            Ok(()) => moved.push((source, destination)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                let rollback_ok =
                    moved
                        .iter()
                        .rev()
                        .fold(true, |all_restored, (original, staged)| {
                            fs::rename(staged, original).is_ok() && all_restored
                        });
                let _ = fs::remove_dir(&staging_dir);
                if rollback_ok {
                    return Err("Sesame could not prepare every local vault file for deletion. The vault was left unchanged.".into());
                }
                return Err("Sesame could not prepare every local vault file for deletion, and could not fully restore the staged files. Do not restart Sesame; contact support with this error.".into());
            }
        }
    }

    Ok(StagedVaultFiles { staging_dir })
}

pub fn csv_export_bytes(payload: &VaultPayload) -> VaultResult<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "name",
            "url",
            "username",
            "email",
            "password",
            "folder",
            "totp",
            "backup_codes",
            "recovery_email",
            "recovery_phone",
            "recovery_not_applicable",
            "notes",
        ])
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    for entry in &payload.entries {
        let title = safe_csv_cell(&entry.title);
        let url = safe_csv_cell(&entry.url);
        let username = safe_csv_cell(&entry.username);
        let email = safe_csv_cell(&entry.email);
        let password = safe_csv_cell(&entry.password);
        let folder_name = crate::snapshot::folder_name_for(payload, entry);
        let folder = safe_csv_cell(&folder_name);
        let totp = safe_csv_cell(entry.totp.as_deref().unwrap_or_default());
        let joined_backup_codes = entry.backup_codes.join("\n");
        let backup_codes = safe_csv_cell(&joined_backup_codes);
        let recovery_email = safe_csv_cell(entry.recovery_email.as_deref().unwrap_or_default());
        let recovery_phone = safe_csv_cell(entry.recovery_phone.as_deref().unwrap_or_default());
        let notes = safe_csv_cell(entry.notes.as_deref().unwrap_or_default());
        writer
            .write_record([
                title.as_ref(),
                url.as_ref(),
                username.as_ref(),
                email.as_ref(),
                password.as_ref(),
                folder.as_ref(),
                totp.as_ref(),
                backup_codes.as_ref(),
                recovery_email.as_ref(),
                recovery_phone.as_ref(),
                if entry.recovery_not_applicable {
                    "true"
                } else {
                    "false"
                },
                notes.as_ref(),
            ])
            .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    }
    writer
        .into_inner()
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())
}

pub fn identities_csv_bytes(payload: &VaultPayload) -> VaultResult<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "label",
            "full_name",
            "email",
            "phone",
            "address_line1",
            "address_line2",
            "city",
            "region",
            "postal_code",
            "country",
        ])
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    for identity in &payload.identities {
        let label = safe_csv_cell(&identity.label);
        let full_name = safe_csv_cell(&identity.full_name);
        let email = safe_csv_cell(&identity.email);
        let phone = safe_csv_cell(&identity.phone);
        let address_line1 = safe_csv_cell(&identity.address_line1);
        let address_line2 = safe_csv_cell(&identity.address_line2);
        let city = safe_csv_cell(&identity.city);
        let region = safe_csv_cell(&identity.region);
        let postal_code = safe_csv_cell(&identity.postal_code);
        let country = safe_csv_cell(&identity.country);
        writer
            .write_record([
                label.as_ref(),
                full_name.as_ref(),
                email.as_ref(),
                phone.as_ref(),
                address_line1.as_ref(),
                address_line2.as_ref(),
                city.as_ref(),
                region.as_ref(),
                postal_code.as_ref(),
                country.as_ref(),
            ])
            .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    }
    writer
        .into_inner()
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())
}

fn safe_csv_cell(value: &str) -> std::borrow::Cow<'_, str> {
    if value
        .chars()
        .next()
        .is_some_and(|character| matches!(character, '=' | '+' | '-' | '@' | '\t' | '\r' | '\n'))
    {
        std::borrow::Cow::Owned(format!("'{value}"))
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

/// Pre-change encrypted copy; the change can be undone by restoring it.
pub fn snapshot_vault_revision(vault: &Path, label: &str) -> VaultResult<Option<String>> {
    if !vault.exists() {
        return Ok(None);
    }
    let backup_dir = vault
        .parent()
        .ok_or("Sesame could not find the vault folder.")?
        .join("backups");
    fs::create_dir_all(&backup_dir)
        .map_err(|_| "Sesame could not prepare a revision before this change.".to_string())?;
    let name = format!(
        "sesame-before-{label}-{}-{}.sesame",
        unix_timestamp(),
        random_id()
    );
    fs::copy(vault, backup_dir.join(&name))
        .map_err(|_| "Sesame could not create a revision before this change.".to_string())?;
    Ok(Some(name))
}

/// Authenticates before anything is invalidated: a failure must never lock the user out.
pub fn prepare_backup_for_restore(
    source: &Path,
    destination: &Path,
    secret: &str,
) -> VaultResult<VaultFile> {
    let mut file = read_backup_file(source)?;
    if source == destination {
        return Err("Choose an exported backup, not Sesame's active vault file.".into());
    }

    // Prove genuine and openable before anything replaces the working vault.
    authenticate_vault_file(&file, secret)?;
    // Drop unlock material a Windows profile cannot open, so a cross-profile restore offers no doomed PIN.
    strip_unusable_device_material(&mut file);
    Ok(file)
}

/// Caller must hold the lifecycle guard so no concurrent save resurrects the old vault.
#[allow(clippy::type_complexity)]
pub fn apply_restored_vault_file(
    destination: &Path,
    file: &VaultFile,
) -> VaultResult<(Option<String>, bool, bool)> {
    apply_restored_vault_file_with_writer(destination, file, write_vault_file)
}

/// Write closure for fault injection after the safety copy exists.
#[allow(clippy::type_complexity)]
pub fn apply_restored_vault_file_with_writer<F>(
    destination: &Path,
    file: &VaultFile,
    write_file: F,
) -> VaultResult<(Option<String>, bool, bool)>
where
    F: FnOnce(&Path, &VaultFile) -> VaultResult<()>,
{
    let safety_backup_name = if destination.exists() {
        let backup_dir = destination
            .parent()
            .ok_or("Sesame could not find the vault folder.")?
            .join("backups");
        fs::create_dir_all(&backup_dir)
            .map_err(|_| "Sesame could not prepare a pre-restore backup.".to_string())?;
        let name = format!(
            "sesame-before-restore-{}-{}.sesame",
            unix_timestamp(),
            random_id()
        );
        fs::copy(destination, backup_dir.join(&name))
            .map_err(|_| "Sesame could not create the required pre-restore backup.".to_string())?;
        Some(name)
    } else {
        None
    };

    let pin_unlock_available = file.pin_wrap.is_some();
    // A Hello wrap whose KSP key does not exist here is caught at unlock, not hidden here.
    let hello_unlock_available = file.hello_wrap.is_some();
    write_file(destination, file)?;
    Ok((
        safety_backup_name,
        pin_unlock_available,
        hello_unlock_available,
    ))
}

/// Single-step authenticate-and-apply; the restore command splits the phases itself.
#[allow(clippy::type_complexity)]
pub fn restore_backup_to(
    source: &Path,
    destination: &Path,
    secret: &str,
) -> VaultResult<(Option<String>, bool, bool)> {
    let file = prepare_backup_for_restore(source, destination, secret)?;
    apply_restored_vault_file(destination, &file)
}

pub fn read_backup_file(path: &Path) -> VaultResult<VaultFile> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("sesame") {
        return Err("Choose a Sesame backup with a .sesame extension.".into());
    }
    let bytes = crate::util::require_file_with_limit(
        path,
        MAX_BACKUP_BYTES,
        "Sesame could not read that backup file.",
    )?;
    let file: VaultFile = serde_json::from_slice(&bytes)
        .map_err(|_| "That file is not a valid Sesame encrypted backup.".to_string())?;
    validate_backup_file(&file)?;
    Ok(file)
}

pub fn validate_backup_file(file: &VaultFile) -> VaultResult<()> {
    if file.format_version == 0 || file.format_version > VAULT_FORMAT_VERSION {
        return Err("That backup uses a Sesame format this version cannot restore.".into());
    }
    crate::crypto::validate_kdf_params(&file.kdf)
        .map_err(|_| "That backup has invalid key-derivation settings.".to_string())?;
    if let Some(recovery_kdf) = &file.recovery_kdf {
        crate::crypto::validate_kdf_params(recovery_kdf)
            .map_err(|_| "That backup has invalid recovery key-derivation settings.".to_string())?;
    }
    validate_cipher_blob(&file.key_wrap)?;
    if let Some(recovery_wrap) = &file.recovery_wrap {
        validate_cipher_blob(recovery_wrap)?;
    }
    if let Some(pin_wrap) = &file.pin_wrap {
        crate::crypto::validate_kdf_params(&pin_wrap.kdf)
            .map_err(|_| "That backup has invalid PIN key-derivation settings.".to_string())?;
        validate_cipher_blob(&pin_wrap.key_wrap)?;
    }
    validate_cipher_blob(&file.payload)?;
    Ok(())
}

fn validate_cipher_blob(blob: &CipherBlob) -> VaultResult<()> {
    let nonce = URL_SAFE_NO_PAD
        .decode(&blob.nonce)
        .map_err(|_| "That backup contains invalid encrypted data.".to_string())?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .map_err(|_| "That backup contains invalid encrypted data.".to_string())?;
    if nonce.len() != 24 || ciphertext.len() < 16 {
        return Err("That backup contains invalid encrypted data.".into());
    }
    Ok(())
}
