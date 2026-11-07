//! Restoring a prior version of an edited item.
//! Capturing happens in each item type's own `save_*` command, atomically with the new version.

use tauri::State;

use crate::application::history::{
    preview_history_version_in_state, restore_history_version_in_state,
};
use crate::vault::types::{ItemPreview, RestoreHistoryVersionResult};
use crate::vault::{VaultResult, VaultState};

/// Non-secret preview of one prior version before confirming a restore.
#[tauri::command]
pub fn preview_history_version(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<ItemPreview> {
    preview_history_version_in_state(&state, &id)
}

#[tauri::command]
pub fn restore_history_version(
    id: String,
    state: State<'_, VaultState>,
) -> VaultResult<RestoreHistoryVersionResult> {
    restore_history_version_in_state(&state, &id)
}
