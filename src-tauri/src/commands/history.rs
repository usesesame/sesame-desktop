//! Restoring a prior version of an edited item.
//! Capturing happens in each item type's own `save_*` command, atomically with the new version.

use tauri::State;

use crate::vault::history::restore_version;
use crate::vault::types::{ItemPreview, RestoreHistoryVersionResult};
use crate::vault::{VaultResult, VaultState};

/// Non-secret preview of one prior version before confirming a restore.
#[tauri::command]
pub fn preview_history_version(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<ItemPreview> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a version to preview.".into());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session.history_item_preview(id)
}

#[tauri::command]
pub fn restore_history_version(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<RestoreHistoryVersionResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a version to restore.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before restoring a version.")?;
    let payload = session.open_payload()?;
    let (next_payload, restored_id) = restore_version(&payload, id)?;
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(RestoreHistoryVersionResult {
        restored_id,
        snapshot: session.snapshot(),
    })
}
