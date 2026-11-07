use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::adapters::network::trusted_time::{linked_time_source, trusted_time, LinkedTimeSource};
use crate::application::recovery_replacement::{
    begin_recovery_replacement_completion_in_state, begin_recovery_replacement_request_in_state,
    cancel_recovery_replacement_in_state, complete_recovery_replacement_in_state,
    pending_recovery_replacement_in_state, recovery_replacement_status,
    write_recovery_replacement_request_in_state,
};
use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

pub use crate::application::recovery_replacement::{
    RecoveryReplacementResult, RecoveryReplacementStatus,
};

fn linked_source(app: &AppHandle) -> Option<LinkedTimeSource> {
    use zeroize::Zeroize;

    let connection = crate::vault::service::read_service_connection(app).ok()?;
    let source = linked_time_source(&connection)?;
    let mut token = crate::vault::service::read_service_token(&connection).ok()?;
    token.zeroize();
    Some(source)
}

async fn status_for(app: &AppHandle, requested_at: Option<u64>) -> RecoveryReplacementStatus {
    let Some(requested_at) = requested_at else {
        return RecoveryReplacementStatus::default();
    };
    let confirmed = trusted_time(linked_source(app)).await.ok();
    recovery_replacement_status(Some(requested_at), confirmed)
}

#[tauri::command]
pub async fn get_recovery_replacement_status(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<RecoveryReplacementStatus> {
    let effects = DesktopHostEffects::new(&app);
    let pending = pending_recovery_replacement_in_state(&state, &effects)?;
    Ok(status_for(&app, pending).await)
}

#[tauri::command]
pub async fn request_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<RecoveryReplacementStatus> {
    let effects = DesktopHostEffects::new(&app);
    if let Some(requested_at) =
        begin_recovery_replacement_request_in_state(&state, &presence, &effects)?
    {
        return Ok(status_for(&app, Some(requested_at)).await);
    }
    let requested_at = trusted_time(linked_source(&app)).await?.latest;
    write_recovery_replacement_request_in_state(&state, &effects, requested_at)?;
    Ok(status_for(&app, Some(requested_at)).await)
}

#[tauri::command]
pub fn cancel_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<()> {
    cancel_recovery_replacement_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub async fn complete_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    master_password: String,
    prune_backups: bool,
) -> VaultResult<RecoveryReplacementResult> {
    let master_password = Zeroizing::new(master_password);
    let effects = DesktopHostEffects::new(&app);
    begin_recovery_replacement_completion_in_state(&state, &presence, &effects)?;
    let now = trusted_time(linked_source(&app)).await?.earliest;
    complete_recovery_replacement_in_state(
        &state,
        &presence,
        &effects,
        master_password,
        now,
        prune_backups,
    )
}
