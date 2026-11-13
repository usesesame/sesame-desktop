//! Reading and restoring deleted items.
//! Deleting happens through each item type's own command, moving the record into trash atomically.

use tauri::State;

use crate::application::history::{preview_trashed_item_in_state, restore_trashed_item_in_state};
use crate::vault::types::{ItemPreview, RestoreTrashedItemResult};
use crate::vault::{VaultResult, VaultState};

/// Non-secret preview of one deleted item before confirming a restore.
#[tauri::command]
pub fn preview_trashed_item(id: String, state: State<'_, VaultState>) -> VaultResult<ItemPreview> {
    preview_trashed_item_in_state(&state, &id)
}

#[tauri::command]
pub fn restore_trashed_item(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<RestoreTrashedItemResult> {
    restore_trashed_item_in_state(&state, &id)
}
