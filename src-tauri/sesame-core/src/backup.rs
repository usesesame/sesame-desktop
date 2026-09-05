use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, Zeroizing};

use crate::loader::{Credential, VaultLoader};
use crate::platform::unprotect_for_device;
use crate::storage::write_vault_file;
use crate::{
    types::*,
    util::{random_id, unix_timestamp},
};
use crate::{VaultFile, VaultPayload, VaultResult};

pub fn unwrap_vault_key(file: &VaultFile, secret: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
    VaultLoader::unwrap_key(file, Credential::PasswordOrRecoveryKit(secret)).map_err(Into::into)
}

pub fn authenticate_vault_file(file: &VaultFile, secret: &str) -> VaultResult<()> {
    VaultLoader::authenticate(file, Credential::PasswordOrRecoveryKit(secret))
        .map(|_| ())
        .map_err(Into::into)
}

pub fn verify_backup_file(path: &Path, secret: &str) -> VaultResult<BackupVerification> {
    let file = read_backup_file(path)?;
    let authenticated =
        VaultLoader::authenticate(&file, Credential::PasswordOrRecoveryKit(secret))?;
    let payload = authenticated.payload();
    Ok(BackupVerification {
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
    })
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
    VaultLoader::read(path).map_err(Into::into)
}

pub fn validate_backup_file(file: &VaultFile) -> VaultResult<()> {
    VaultLoader::validate(file).map_err(Into::into)
}
