use tauri::{AppHandle, State};

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::application::backups::{
    create_backup_in_state, delete_local_vault_in_state, export_backup_in_state,
    export_recovery_kit_in_state, export_vault_csv_in_state, export_vault_json_in_state,
    inspect_backup_in_state, recovery_health_in_state, restore_backup_in_state,
    verify_backup_in_state,
};
use crate::commands::file_selection::FileSelectionState;
use crate::release::ReleasePresence;
use crate::vault::recovery_health;
use crate::vault::{
    BackupInspection, BackupVerification, RestoreBackupRequest, RestoreBackupResult, VaultResult,
    VaultState,
};

#[tauri::command]
pub fn create_backup(state: State<'_, VaultState>) -> VaultResult<String> {
    create_backup_in_state(&state)
}

#[tauri::command]
pub fn export_backup(
    app: AppHandle,
    token: Option<String>,
    destination: Option<String>,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    export_backup_in_state(
        &state,
        &presence,
        &DesktopHostEffects::new(&app),
        &selection,
        token.as_deref(),
        destination.as_deref(),
    )
}

#[tauri::command]
pub fn export_vault_csv(
    token: Option<String>,
    destination: Option<String>,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<Vec<String>> {
    export_vault_csv_in_state(
        &state,
        &presence,
        &selection,
        token.as_deref(),
        destination.as_deref(),
    )
}

#[tauri::command]
pub fn export_vault_json(
    token: Option<String>,
    destination: Option<String>,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    export_vault_json_in_state(
        &state,
        &presence,
        &selection,
        token.as_deref(),
        destination.as_deref(),
    )
}

#[tauri::command]
pub fn export_recovery_kit(
    token: Option<String>,
    destination: Option<String>,
    kit: String,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    export_recovery_kit_in_state(
        &state,
        &presence,
        &selection,
        kit,
        token.as_deref(),
        destination.as_deref(),
    )
}

#[tauri::command]
pub fn delete_local_vault(
    app: AppHandle,
    master_password: String,
    state: State<'_, VaultState>,
) -> VaultResult<()> {
    delete_local_vault_in_state(&state, &DesktopHostEffects::new(&app), master_password)
}

#[tauri::command]
pub fn inspect_backup(
    app: AppHandle,
    token: Option<String>,
    source: Option<String>,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
) -> VaultResult<BackupInspection> {
    inspect_backup_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        &selection,
        token.as_deref(),
        source.as_deref(),
    )
}

#[tauri::command]
pub fn verify_backup(
    app: AppHandle,
    request: RestoreBackupRequest,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
) -> VaultResult<BackupVerification> {
    verify_backup_in_state(&state, &DesktopHostEffects::new(&app), &selection, request)
}

#[tauri::command]
pub fn restore_backup(
    app: AppHandle,
    request: RestoreBackupRequest,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    selection: State<'_, FileSelectionState>,
) -> VaultResult<RestoreBackupResult> {
    restore_backup_in_state(
        &state,
        &presence,
        &DesktopHostEffects::new(&app),
        &selection,
        request,
    )
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
    recovery_health_in_state(&state, &DesktopHostEffects::new(&app))
}
