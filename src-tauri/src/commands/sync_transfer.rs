use tauri::AppHandle;

use super::sync::local_data_dir;
use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::adapters::network::sync::connect;
use crate::application::sync::SyncStore;
use crate::application::sync_transfer::classify_transfer_failure;
use crate::sync::key_change::PreparedKeyChange;
use crate::vault::VaultState;

pub use crate::application::sync::{SyncCoordinatorView, SyncPreparedKit, SyncTransferResult};
pub use crate::application::sync_recovery::SyncBackupView;
pub use crate::application::sync_transfer::{
    SyncConflictView, SyncResolutionResult, SyncTakeKeyResult,
};

const ALREADY_SYNCING: &str = "Sesame is already syncing. Try again in a moment.";

async fn upload_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    store.require_no_pending_key_change()?;
    let client = connect(&app).await?;
    crate::application::sync_transfer::upload_vault_in_state(&state, &store, &client).await
}

#[tauri::command]
pub async fn sync_upload_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncTransferResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    upload_vault(app, state).await
}

async fn download_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncTransferResult, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    store.require_no_pending_key_change()?;
    let client = connect(&app).await?;
    crate::application::sync_transfer::download_vault_in_state(
        &state,
        &store,
        &client,
        &DesktopHostEffects::new(&app),
    )
    .await
}

#[tauri::command]
pub async fn sync_download_vault(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncTransferResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    download_vault(app, state).await
}

#[tauri::command]
pub async fn sync_take_new_key(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    master_password: String,
) -> Result<SyncTakeKeyResult, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    let client = connect(&app).await?;
    let result = crate::application::sync_transfer::take_new_key_in_state(
        &state,
        &store,
        &DesktopHostEffects::new(&app),
        &client,
        master_password,
    )
    .await?;
    coordinator.key_taken();
    Ok(result)
}

#[tauri::command]
pub async fn sync_prepare_key_change(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    prepared: tauri::State<'_, PreparedKeyChange>,
    master_password: String,
) -> Result<SyncPreparedKit, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync::prepare_key_change_in_state(
        &state,
        &store,
        &prepared,
        &master_password,
    )
}

#[tauri::command]
pub fn sync_cancel_key_change(prepared: tauri::State<'_, PreparedKeyChange>) {
    prepared.discard();
}

#[tauri::command]
pub async fn sync_remove_device(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    prepared: tauri::State<'_, PreparedKeyChange>,
    device_id: String,
    master_password: String,
) -> Result<(), String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    let identity = store.this_identity()?;
    crate::application::sync::refuse_self_removal(&device_id, &identity.device_id)?;
    let client = connect(&app).await?;
    crate::application::sync_transfer::rekey_without_in_state(
        &state,
        &store,
        &DesktopHostEffects::new(&app),
        &client,
        crate::application::sync_transfer::RekeyRequest {
            prepared: &prepared,
            subject: Some(&device_id),
            master_password: &master_password,
            adopt_locally: true,
        },
    )
    .await
}

#[tauri::command]
pub async fn sync_rotate_vault_key(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    prepared: tauri::State<'_, PreparedKeyChange>,
    master_password: String,
) -> Result<(), String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    let client = connect(&app).await?;
    crate::application::sync_transfer::rekey_without_in_state(
        &state,
        &store,
        &DesktopHostEffects::new(&app),
        &client,
        crate::application::sync_transfer::RekeyRequest {
            prepared: &prepared,
            subject: None,
            master_password: &master_password,
            adopt_locally: true,
        },
    )
    .await
}

#[tauri::command]
pub async fn sync_upgrade_device_key(app: AppHandle) -> Result<(), String> {
    let client = connect(&app).await?;
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync::upgrade_device_key_in_state(&store, &client).await
}

pub(super) async fn leave_vault(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
    master_password: &str,
) -> Result<(), String> {
    let store = SyncStore::new(local_data_dir(app)?);
    let identity = store.this_identity()?;
    let client = connect(app).await?;
    crate::application::sync_transfer::leave_vault_in_state(
        state,
        &store,
        &DesktopHostEffects::new(app),
        &client,
        &identity.device_id,
        master_password,
    )
    .await
}

#[tauri::command]
pub async fn sync_conflict_details(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<SyncConflictView, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    let client = connect(&app).await?;
    crate::application::sync_transfer::sync_conflict_details_in_state(&state, &store, &client).await
}

#[tauri::command]
pub async fn sync_resolve_conflict(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    keep: String,
) -> Result<SyncResolutionResult, String> {
    let _run = coordinator
        .begin_manual()
        .ok_or_else(|| ALREADY_SYNCING.to_string())?;
    crate::application::sync_transfer::conflict_choice(&keep)?;
    let store = SyncStore::new(local_data_dir(&app)?);
    store.require_no_pending_key_change()?;
    let client = connect(&app).await?;
    let resolved = crate::application::sync_transfer::resolve_conflict_in_state(
        &state,
        &store,
        &DesktopHostEffects::new(&app),
        &client,
        keep,
    )
    .await?;
    coordinator.resume();
    Ok(resolved)
}

#[tauri::command]
pub async fn sync_coordinator_status(
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
) -> Result<SyncCoordinatorView, String> {
    Ok(crate::application::sync::coordinator_view(
        &coordinator.status(),
    ))
}

#[tauri::command]
pub async fn sync_now(
    app: AppHandle,
    state: tauri::State<'_, VaultState>,
    coordinator: tauri::State<'_, crate::sync::coordinator::Coordinator>,
    manual: Option<bool>,
) -> Result<SyncCoordinatorView, String> {
    if manual.unwrap_or(false) {
        coordinator.retry_after_user_action();
    }
    if !coordinator.begin() {
        return sync_coordinator_status(coordinator).await;
    }
    let outcome = match run_one_transfer(&app, &state).await {
        Ok(outcome) => outcome,
        Err(message) => classify_transfer_failure(&message),
    };
    coordinator.finish(outcome);
    sync_coordinator_status(coordinator).await
}

async fn run_one_transfer(
    app: &AppHandle,
    state: &tauri::State<'_, VaultState>,
) -> Result<crate::sync::coordinator::Outcome, String> {
    use crate::sync::coordinator::Outcome;

    let store = SyncStore::new(local_data_dir(app)?);
    let Some(local) = store.load_state()? else {
        return Ok(Outcome::AlreadyCurrent);
    };
    let client = connect(app).await?;
    crate::application::sync_transfer::run_one_transfer_in_state(
        state,
        &store,
        &client,
        &DesktopHostEffects::new(app),
        local,
        || connect(app),
    )
    .await
}

include!("sync_transfer_recovery.rs");
