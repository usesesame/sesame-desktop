use std::path::PathBuf;

use tauri::{AppHandle, State};
use zeroize::{Zeroize, Zeroizing};

use super::lifecycle::{discard_pin_throttle_state, establish_pin_throttle_state};
use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::backup::{
    apply_restored_vault_file, csv_export_bytes, identities_csv_bytes, managed_vault_paths,
    prepare_backup_for_restore, read_backup_file, stage_managed_vault_files, verify_backup_file,
};
use crate::vault::platform::{copy_private_file, create_private_dir, securely_delete};
use crate::vault::recovery_health;
use crate::vault::storage::{vault_path, write_export_file};
use crate::vault::util::{backup_file_name, random_id, unix_timestamp};
use crate::vault::{
    BackupInspection, BackupVerification, RestoreBackupRequest, RestoreBackupResult, VaultResult,
    VaultState,
};

#[tauri::command]
pub fn create_backup(state: State<'_, VaultState>) -> VaultResult<String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault before creating a backup.")?;
    let backup_dir = session
        .path
        .parent()
        .ok_or("Sesame could not find the vault folder.")?
        .join("backups");
    create_private_dir(&backup_dir)?;
    let backup_name = format!("sesame-backup-{}-{}.sesame", unix_timestamp(), random_id());
    copy_private_file(&session.path, &backup_dir.join(&backup_name))
        .map_err(|_| "Sesame could not create the encrypted backup.".to_string())?;
    Ok(backup_name)
}

#[tauri::command]
pub fn export_backup(
    app: AppHandle,
    destination: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    require_release_presence(&state, &presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault before exporting a backup.")?;
    let destination = PathBuf::from(destination);
    if destination
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("sesame")
    {
        return Err("Save the encrypted backup with a .sesame extension.".into());
    }
    if destination == session.path {
        return Err("Choose a different location for the backup.".into());
    }
    let parent = destination
        .parent()
        .ok_or("Choose a valid location for the backup.")?;
    if !parent.exists() {
        return Err("The selected backup folder no longer exists.".into());
    }
    copy_private_file(&session.path, &destination)
        .map_err(|_| "Sesame could not write the encrypted backup to that location.".to_string())?;
    let snapshot = session.snapshot();
    if let (Some(vault_id), revision) = (snapshot.vault_id.as_deref(), snapshot.revision) {
        let _ = recovery_health::update_after_export_with_payload(&app, vault_id, revision);
    }
    destination
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or("Sesame could not name the exported backup.".into())
}

/// Returns every file actually written, so the interface can say what it produced.
#[tauri::command]
pub fn export_vault_csv(
    destination: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<Vec<String>> {
    require_release_presence(&state, &presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault before exporting it.")?;
    let destination = PathBuf::from(destination);
    if destination
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("csv")
    {
        return Err("Save the readable export with a .csv extension.".into());
    }
    let parent = destination
        .parent()
        .ok_or("Choose a valid location for the export.")?;
    if !parent.exists() {
        return Err("The selected export folder no longer exists.".into());
    }
    let payload = session.open_payload()?;
    let bytes = csv_export_bytes(&payload)?;
    write_export_file(&destination, &bytes)?;
    let mut written = vec![backup_file_name(&destination)?];

    if !payload.identities.is_empty() {
        let identities_destination = identities_export_path(&destination)
            .ok_or("Sesame could not name the exported identities file.")?;
        let identities_bytes = identities_csv_bytes(&payload)?;
        write_export_file(&identities_destination, &identities_bytes)?;
        written.push(backup_file_name(&identities_destination)?);
    }

    Ok(written)
}

/// `sesame-export.csv` becomes `sesame-export-identities.csv`, beside it.
fn identities_export_path(logins_destination: &std::path::Path) -> Option<PathBuf> {
    let stem = logins_destination.file_stem()?.to_str()?;
    Some(logins_destination.with_file_name(format!("{stem}-identities.csv")))
}

/// `kit` is the plaintext already on screen; only an unlocked mid-onboarding session is required.
#[tauri::command]
pub fn export_recovery_kit(
    destination: String,
    kit: String,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    require_release_presence(&state, &presence)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    if session.is_none() {
        return Err("Unlock your vault before saving the recovery kit.".into());
    }
    if kit.trim().is_empty() {
        return Err("There is no recovery kit to save.".into());
    }
    let destination = PathBuf::from(destination);
    if destination
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("txt")
    {
        return Err("Save the recovery kit with a .txt extension.".into());
    }
    let parent = destination
        .parent()
        .ok_or("Choose a valid location for the recovery kit.")?;
    if !parent.exists() {
        return Err("The selected folder no longer exists.".into());
    }
    let body = format!(
        "Sesame recovery kit\n\n{kit}\n\nKeep this file somewhere Sesame cannot reach: a password \
         manager entry elsewhere, printed and stored safely, or an encrypted drive Sesame does not \
         have access to. Anyone who has this kit and your device can open your vault.\n"
    );
    write_export_file(&destination, body.as_bytes())?;
    backup_file_name(&destination)
}

#[tauri::command]
pub fn delete_local_vault(
    app: AppHandle,
    master_password: String,
    state: State<'_, VaultState>,
) -> VaultResult<()> {
    let vault = vault_path(&app)?;
    // Re-authenticate against the vault file rather than the open session, so an
    // unattended unlocked window cannot destroy the vault and its backups, and so
    // a locked window cannot either.
    let master_password = Zeroizing::new(master_password);
    let file = sesame_core::loader::VaultLoader::read(&vault)?;
    let mut key =
        sesame_core::api::unwrap_key_with_password(&file, &master_password).map_err(|_| {
            "That master password is not correct. The vault was not removed.".to_string()
        })?;
    key.zeroize();
    let parent = vault
        .parent()
        .ok_or("Sesame could not find the vault folder.")?;

    // Guard held through staging so a racing save can never recreate the vault.
    let session = state.begin_destructive_lifecycle_change()?;
    state.cache_pin_unlock(false);
    state.cache_hello_unlock(false);
    let staged = stage_managed_vault_files(&vault, parent);
    drop(session);
    // Never recreate a PIN throttle file after the vault and its PIN wrapper are gone.
    discard_pin_throttle_state(&app, &state);
    let staged = staged?;
    if securely_delete(&staged.staging_dir).is_err() {
        return Err("Sesame removed the local vault from its normal location, but could not finish deleting its staged data. Restart Sesame and try deleting the vault again.".into());
    }
    for path in managed_vault_paths(&vault) {
        if path.exists() {
            return Err("Sesame removed the local vault, but a file reappeared at its original location. Restart Sesame and try deleting the vault again.".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub fn inspect_backup(
    app: AppHandle,
    source: String,
    state: State<'_, VaultState>,
) -> VaultResult<BackupInspection> {
    // Session required: a locked renderer must not use this as a file-format oracle.
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?
        .is_some();
    if !unlocked && vault_path(&app)?.exists() {
        return Err("Unlock your vault before inspecting a backup.".into());
    }
    let source = PathBuf::from(source);
    let file = read_backup_file(&source)?;
    Ok(BackupInspection {
        file_name: backup_file_name(&source)?,
        format_version: file.format_version,
    })
}

#[tauri::command]
pub fn verify_backup(
    app: AppHandle,
    request: RestoreBackupRequest,
    state: State<'_, VaultState>,
) -> VaultResult<BackupVerification> {
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?
        .is_some();
    if !unlocked {
        return Err("Unlock your vault before verifying a backup.".into());
    }
    let source = PathBuf::from(request.source);
    let mut secret = request.secret;
    let result = verify_backup_file(&source, &secret);
    secret.zeroize();
    let verification = result?;
    let current_vault_id = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?
        .as_ref()
        .map(|vault| vault.open_payload())
        .transpose()?
        .and_then(|payload| payload.vault_id.clone());
    if let (Some(vault_id), Some(current_id)) = (
        verification.vault_id.as_deref(),
        current_vault_id.as_deref(),
    ) {
        if vault_id == current_id {
            let _ = recovery_health::update_after_verification_with_payload(
                &app,
                vault_id,
                verification.revision,
            );
        }
    }
    Ok(verification)
}

#[tauri::command]
pub fn restore_backup(
    app: AppHandle,
    request: RestoreBackupRequest,
    state: State<'_, VaultState>,
) -> VaultResult<RestoreBackupResult> {
    let source = PathBuf::from(request.source);
    let destination = vault_path(&app)?;
    let mut secret = request.secret;

    // Authenticate before invalidating anything: a failure must not lock the user out.
    let prepared = prepare_backup_for_restore(&source, &destination, &secret);
    secret.zeroize();
    let prepared = prepared?;

    let installed =
        state.apply_lifecycle_replacement(|| apply_restored_vault_file(&destination, &prepared))?;
    state.cache_pin_unlock(installed.pin_unlock_available);
    state.cache_hello_unlock(installed.hello_unlock_available);
    if installed.pin_unlock_available {
        let _ = establish_pin_throttle_state(&app, &state);
    } else {
        discard_pin_throttle_state(&app, &state);
    }
    Ok(RestoreBackupResult {
        safety_backup_name: installed.safety_backup_name,
        pin_unlock_available: installed.pin_unlock_available,
        hello_unlock_available: installed.hello_unlock_available,
    })
}

#[tauri::command]
pub fn lock_vault(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<()> {
    crate::vault::lock_and_notify(&state, &app)
}

#[tauri::command]
pub fn get_recovery_health(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<recovery_health::RecoveryHealth> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let current_id = session
        .as_ref()
        .map(|vault| vault.open_payload())
        .transpose()?
        .and_then(|payload| payload.vault_id.clone());
    recovery_health::get_health(&app, current_id.as_deref())
}
