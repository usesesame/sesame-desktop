use tauri::State;

use crate::application::file_choices::FileSelectionState;
use crate::application::imports::{
    cancel_import_in_state, commit_import_in_state, preview_import_in_state,
};
use crate::vault::{ImportPreviewResult, ImportResult, VaultResult, VaultState};

#[tauri::command]
pub fn preview_import(
    token: Option<String>,
    path: Option<String>,
    source: String,
    state: State<'_, VaultState>,
    selection: State<'_, FileSelectionState>,
) -> VaultResult<ImportPreviewResult> {
    preview_import_in_state(
        &state,
        &selection,
        token.as_deref(),
        path.as_deref(),
        &source,
    )
}

#[tauri::command]
pub fn cancel_import(state: State<'_, VaultState>) -> VaultResult<()> {
    cancel_import_in_state(&state)
}

#[tauri::command]
pub fn commit_import(
    import_id: String,
    skip_exact_duplicates: bool,
    state: State<'_, VaultState>,
) -> VaultResult<ImportResult> {
    commit_import_in_state(&state, &import_id, skip_exact_duplicates)
}
