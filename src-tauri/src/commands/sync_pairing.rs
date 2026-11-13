use std::time::{Duration, Instant};

use tauri::AppHandle;

use super::sync::local_data_dir;
use super::sync_adopt::SyncAdoptResult;
use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::application::sync::SyncStore;
use crate::application::sync_pairing::{
    cancel_pairing, clear_shown_code, pairing_code, take_shown_code,
};
use crate::sync::client::SyncClient;
use crate::vault::VaultState;

pub use crate::application::sync_pairing::{ApprovedDeviceView, PairingCodeView};

const POLL: Duration = Duration::from_secs(2);

async fn pause() {
    let _ = tauri::async_runtime::spawn_blocking(|| std::thread::sleep(POLL)).await;
}

#[tauri::command]
pub async fn sync_pairing_code() -> Result<PairingCodeView, String> {
    pairing_code()
}

#[tauri::command]
pub async fn sync_cancel_pairing() -> Result<(), String> {
    cancel_pairing()
}

#[tauri::command]
pub async fn sync_approve_with_code(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    allow_classical: Option<bool>,
) -> Result<ApprovedDeviceView, String> {
    let outcome = approve(&app, &vault, allow_classical.unwrap_or(false)).await;
    clear_shown_code();
    outcome
}

async fn approve(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
    allow_classical: bool,
) -> Result<ApprovedDeviceView, String> {
    let code = take_shown_code()?;
    let started = Instant::now();
    let client = SyncClient::connect(app).await?;
    let store = SyncStore::new(local_data_dir(app)?);
    let identity = store.this_identity()?;
    crate::application::sync_pairing::approve_in_state(
        vault,
        &store,
        &client,
        &identity,
        crate::application::sync_pairing::ApproveRequest {
            code: &code,
            started,
            allow_classical,
        },
        pause,
    )
    .await
}

#[tauri::command]
pub async fn sync_join_with_code(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    code: String,
    label: String,
    master_password: String,
) -> Result<SyncAdoptResult, String> {
    let code = zeroize::Zeroizing::new(code);
    let master_password = zeroize::Zeroizing::new(master_password);
    let store = SyncStore::new(local_data_dir(&app)?);
    let (label, pending) = crate::application::sync_join::join_preflight_in_state(
        &vault,
        &store,
        &label,
        &master_password,
    )?;
    let client = SyncClient::connect(&app).await?;
    crate::application::sync_join::join_with_code_in_state(
        &vault,
        &store,
        &DesktopHostEffects::new(&app),
        &client,
        crate::application::sync_join::JoinRequest {
            code: &code,
            label: &label,
            master_password: &master_password,
            pending,
        },
        pause,
    )
    .await
}
