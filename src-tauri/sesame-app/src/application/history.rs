use crate::vault::history::restore_version;
use crate::vault::storage::commit_payload_change;
use crate::vault::trash::restore_item;
use crate::vault::{
    ItemPreview, RestoreHistoryVersionResult, RestoreTrashedItemResult, VaultResult, VaultState,
};

pub fn preview_history_version_in_state(state: &VaultState, id: &str) -> VaultResult<ItemPreview> {
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

pub fn restore_history_version_in_state(
    state: &VaultState,
    id: &str,
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
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(RestoreHistoryVersionResult {
        restored_id,
        snapshot: session.snapshot(),
    })
}

pub fn preview_trashed_item_in_state(state: &VaultState, id: &str) -> VaultResult<ItemPreview> {
    let id = id.trim();
    if id.is_empty() {
        return Err("Choose a deleted item to preview.".into());
    }
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    session.trash_item_preview(id)
}

pub fn restore_trashed_item_in_state(
    state: &VaultState,
    id: &str,
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
    let payload = session.open_payload()?;
    let next_payload = restore_item(&payload, id)?;
    commit_payload_change(session, next_payload)?;
    state.advance_session_epoch();
    Ok(RestoreTrashedItemResult {
        restored_id: id.to_string(),
        snapshot: session.snapshot(),
    })
}
