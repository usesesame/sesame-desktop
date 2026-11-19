use tauri::{AppHandle, Manager, State};
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

pub(crate) const STOPPED_BEFORE_FINISHING: &str =
    "Sesame stopped this task before it finished. Try again.";

pub(crate) async fn off_window_thread<T: Send + 'static>(
    app: AppHandle,
    work: impl FnOnce(&AppHandle) -> VaultResult<T> + Send + 'static,
) -> VaultResult<T> {
    tauri::async_runtime::spawn_blocking(move || work(&app))
        .await
        .map_err(|_| STOPPED_BEFORE_FINISHING.to_string())?
}

#[tauri::command]
pub fn get_vault_status(app: AppHandle, state: State<'_, VaultState>) -> VaultResult<VaultStatus> {
    get_vault_status_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSetup> {
    let master_password = Zeroizing::new(request.master_password);
    off_window_thread(app, move |app| {
        create_vault_in_state(
            &app.state::<VaultState>(),
            &DesktopHostEffects::new(app),
            master_password,
        )
    })
    .await
}

#[tauri::command]
pub async fn resume_recovery_setup(app: AppHandle) -> VaultResult<String> {
    off_window_thread(app, |app| {
        resume_recovery_setup_in_state(&app.state::<VaultState>())
    })
    .await
}

#[tauri::command]
pub async fn complete_recovery_setup(
    app: AppHandle,
    request: RecoveryKitRequest,
) -> VaultResult<()> {
    let recovery_kit = Zeroizing::new(request.recovery_kit);
    off_window_thread(app, move |app| {
        complete_recovery_setup_in_state(&app.state::<VaultState>(), recovery_kit)
    })
    .await
}

#[tauri::command]
pub async fn unlock_recovery_vault(
    app: AppHandle,
    request: RecoveryKitRequest,
) -> VaultResult<VaultSnapshot> {
    let recovery_kit = Zeroizing::new(request.recovery_kit);
    off_window_thread(app, move |app| {
        unlock_recovery_vault_in_state(
            &app.state::<VaultState>(),
            &DesktopHostEffects::new(app),
            recovery_kit,
        )
    })
    .await
}

#[tauri::command]
pub async fn set_unlock_pin(app: AppHandle, request: UnlockPinRequest) -> VaultResult<()> {
    let mut pin = Zeroizing::new(request.pin);
    off_window_thread(app, move |app| {
        set_unlock_pin_in_state(
            &app.state::<VaultState>(),
            &DesktopHostEffects::new(app),
            std::mem::take(&mut *pin),
        )
    })
    .await
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
pub async fn unlock_pin_vault(
    app: AppHandle,
    request: UnlockPinRequest,
) -> VaultResult<VaultSnapshot> {
    let mut pin = Zeroizing::new(request.pin);
    off_window_thread(app, move |app| {
        unlock_pin_vault_in_state(
            &app.state::<VaultState>(),
            &DesktopHostEffects::new(app),
            std::mem::take(&mut *pin),
        )
    })
    .await
}

#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    request: MasterPasswordRequest,
) -> VaultResult<VaultSnapshot> {
    let master_password = Zeroizing::new(request.master_password);
    off_window_thread(app, move |app| {
        crate::application::lifecycle::unlock_vault_in_state(
            &app.state::<VaultState>(),
            &app.state::<ReleasePresence>(),
            &DesktopHostEffects::new(app),
            master_password,
        )
    })
    .await
}

#[tauri::command]
pub async fn change_master_password(
    app: AppHandle,
    request: ChangeMasterPasswordRequest,
) -> VaultResult<ChangeMasterPasswordResult> {
    off_window_thread(app, move |app| {
        change_master_password_in_state(
            &app.state::<VaultState>(),
            &DesktopHostEffects::new(app),
            request,
        )
    })
    .await
}

#[tauri::command]
pub fn record_activity() {
    crate::application::unlock::record_activity();
}

#[tauri::command]
pub fn set_auto_lock_minutes(minutes: u64, state: State<'_, VaultState>) -> VaultResult<()> {
    set_auto_lock_minutes_in_state(&state, minutes)
}
