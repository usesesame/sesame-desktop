use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::adapters::network::trusted_time::trusted_time;
use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::backup::RECOVERY_REPLACEMENT_FILE;
use crate::vault::storage::{
    atomic_replace, open_recovery_replacement_request, recovery_replacement_ready,
    replace_recovery_kit_for_session, seal_recovery_replacement_request, vault_path,
    RECOVERY_REPLACEMENT_DELAY_SECS,
};
use crate::vault::types::CipherBlob;
use crate::vault::util::read_file_with_limit;
use crate::vault::{UnlockedVault, VaultResult, VaultState};

const MAX_REQUEST_BYTES: u64 = 4 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRequest {
    vault_id: String,
    sealed: CipherBlob,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReplacementStatus {
    pub requested_at: Option<u64>,
    pub available_at: Option<u64>,
    pub ready: bool,
    pub time_confirmed: bool,
}

fn request_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let vault = vault_path(app)?;
    let parent = vault
        .parent()
        .ok_or("Sesame could not locate the vault folder.")?;
    Ok(parent.join(RECOVERY_REPLACEMENT_FILE))
}

fn remove_request(app: &AppHandle) -> VaultResult<()> {
    match std::fs::remove_file(request_path(app)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not cancel the recovery kit request.".into()),
    }
}

fn pending_request(app: &AppHandle, session: &UnlockedVault) -> VaultResult<Option<u64>> {
    let bytes = match read_file_with_limit(&request_path(app)?, MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Sesame could not read the recovery kit request.".into()),
    };
    let current_id = session.snapshot().vault_id;
    let opened = serde_json::from_slice::<StoredRequest>(&bytes)
        .ok()
        .filter(|stored| current_id.as_deref() == Some(stored.vault_id.as_str()))
        .and_then(|stored| open_recovery_replacement_request(session, &stored.sealed).ok());
    if opened.is_none() {
        remove_request(app)?;
    }
    Ok(opened)
}

fn pending_for_unlocked(app: &AppHandle, state: &VaultState) -> VaultResult<Option<u64>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    pending_request(app, session)
}

async fn status_for(requested_at: Option<u64>) -> RecoveryReplacementStatus {
    let Some(requested_at) = requested_at else {
        return RecoveryReplacementStatus::default();
    };
    let confirmed = trusted_time().await.ok();
    RecoveryReplacementStatus {
        requested_at: Some(requested_at),
        available_at: Some(requested_at.saturating_add(RECOVERY_REPLACEMENT_DELAY_SECS)),
        ready: confirmed
            .is_some_and(|time| recovery_replacement_ready(requested_at, time.earliest)),
        time_confirmed: confirmed.is_some(),
    }
}

#[tauri::command]
pub async fn get_recovery_replacement_status(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<RecoveryReplacementStatus> {
    let pending = pending_for_unlocked(&app, &state)?;
    Ok(status_for(pending).await)
}

#[tauri::command]
pub async fn request_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<RecoveryReplacementStatus> {
    require_release_presence(&state, &presence)?;
    if let Some(requested_at) = pending_for_unlocked(&app, &state)? {
        return Ok(status_for(Some(requested_at)).await);
    }
    let requested_at = trusted_time().await?.latest;
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session.as_ref().ok_or("Unlock your vault first.")?;
        if !session.setup_complete {
            return Err("Finish recovery setup before requesting a new recovery kit.".into());
        }
        let stored = StoredRequest {
            vault_id: session.snapshot().vault_id.ok_or(
                "This vault has no identifier, so a new recovery kit cannot be requested.",
            )?,
            sealed: seal_recovery_replacement_request(session, requested_at)?,
        };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| "Sesame could not save the recovery kit request.".to_string())?;
        atomic_replace(&request_path(&app)?, &bytes)?;
    }
    Ok(status_for(Some(requested_at)).await)
}

#[tauri::command]
pub fn cancel_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
) -> VaultResult<()> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    session.as_ref().ok_or("Unlock your vault first.")?;
    remove_request(&app)
}

#[tauri::command]
pub async fn complete_recovery_replacement(
    app: AppHandle,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
) -> VaultResult<String> {
    require_release_presence(&state, &presence)?;
    pending_for_unlocked(&app, &state)?.ok_or("There is no recovery kit request to complete.")?;
    let now = trusted_time().await?.earliest;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_mut().ok_or("Unlock your vault first.")?;
    let requested_at =
        pending_request(&app, session)?.ok_or("There is no recovery kit request to complete.")?;
    let recovery_kit = replace_recovery_kit_for_session(session, requested_at, now)?;
    let _ = remove_request(&app);
    Ok(recovery_kit)
}

pub(crate) fn discard_recovery_replacement(app: &AppHandle) {
    let _ = remove_request(app);
}
