//! Reading and restoring deleted items.
//! Deleting happens through each item type's own command, moving the record into trash atomically.

use tauri::State;

use crate::vault::snapshot::snapshot_for;
use crate::vault::trash::{restore_item, trash_item_preview};
use crate::vault::types::{ItemPreview, RestoreTrashedItemResult};
use crate::vault::{VaultResult, VaultState};

/// Non-secret preview of one deleted item before confirming a restore.
#[tauri::command]
pub fn preview_trashed_item(id: String, state: State<'_, VaultState>) -> VaultResult<ItemPreview> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a deleted item to preview.".into());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    trash_item_preview(&session.payload, id)
}

#[tauri::command]
pub fn restore_trashed_item(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<RestoreTrashedItemResult> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a deleted item to restore.".into());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before restoring an item.")?;
    let next_payload = restore_item(&session.payload, id)?;
    crate::vault::storage::commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(RestoreTrashedItemResult {
        restored_id: id.to_string(),
        snapshot: snapshot_for(&session.payload),
    })
}
