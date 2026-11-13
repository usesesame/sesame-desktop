use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::application::unlock::{
    change_master_password_in_state, complete_recovery_setup_in_state, create_vault_in_state,
    disable_windows_hello_in_state, enable_windows_hello_in_state, get_vault_status_in_state,
    remove_unlock_pin_in_state, resume_recovery_setup_in_state, set_auto_lock_minutes_in_state,
    set_unlock_pin_in_state, unlock_pin_vault_in_state, unlock_recovery_vault_in_state,
    unlock_with_windows_hello_in_state,
};
use crate::release::ReleasePresence;
use crate::vault::{
    ChangeMasterPasswordRequest, ChangeMasterPasswordResult, MasterPasswordRequest,
    RecoveryKitRequest, UnlockPinRequest, VaultResult, VaultSetup, VaultSnapshot, VaultState,
    VaultStatus,
};

#[tauri::command]
pub fn get_vault_status(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<VaultStatus> {
    get_vault_status_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub fn create_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSetup> {
    create_vault_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        Zeroizing::new(request.master_password),
    )
}

#[tauri::command]
pub fn resume_recovery_setup(state: State<'_, VaultState>) -> VaultResult<String> {
    resume_recovery_setup_in_state(&state)
}

#[tauri::command]
pub fn complete_recovery_setup(
    state: State<'_, VaultState>,
    request: RecoveryKitRequest,
) -> VaultResult<()> {
    complete_recovery_setup_in_state(&state, Zeroizing::new(request.recovery_kit))
}

#[tauri::command]
pub fn unlock_recovery_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: RecoveryKitRequest,
) -> VaultResult<VaultSnapshot> {
    unlock_recovery_vault_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        Zeroizing::new(request.recovery_kit),
    )
}

#[tauri::command]
pub fn set_unlock_pin(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: UnlockPinRequest,
) -> VaultResult<()> {
    set_unlock_pin_in_state(&state, &DesktopHostEffects::new(&app), request.pin)
}

#[tauri::command]
pub fn remove_unlock_pin(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<()> {
    remove_unlock_pin_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub fn enable_windows_hello(state: State<'_, VaultState>) -> VaultResult<()> {
    enable_windows_hello_in_state(&state)
}

#[tauri::command]
pub fn disable_windows_hello(state: State<'_, VaultState>) -> VaultResult<()> {
    disable_windows_hello_in_state(&state)
}

#[tauri::command]
pub fn unlock_with_windows_hello(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<VaultSnapshot> {
    unlock_with_windows_hello_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub fn unlock_pin_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: UnlockPinRequest,
) -> VaultResult<VaultSnapshot> {
    unlock_pin_vault_in_state(&state, &DesktopHostEffects::new(&app), request.pin)
}

#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSnapshot> {
    crate::application::lifecycle::unlock_vault_in_state(
        &state,
        &presence,
        &DesktopHostEffects::new(&app),
        Zeroizing::new(request.master_password),
    )
}

#[tauri::command]
pub fn change_master_password(
    app: AppHandle,
    state: State<'_, VaultState>,
    request: ChangeMasterPasswordRequest,
) -> VaultResult<ChangeMasterPasswordResult> {
    change_master_password_in_state(&state, &DesktopHostEffects::new(&app), request)
}

#[tauri::command]
pub fn record_activity() {
    crate::application::unlock::record_activity();
}

#[tauri::command]
pub fn set_auto_lock_minutes(minutes: u64, state: State<'_, VaultState>) -> VaultResult<()> {
    set_auto_lock_minutes_in_state(&state, minutes)
}
