use tauri::State;

use crate::application::search::search_items_in_state;
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn search_items(query: String, state: State<'_, VaultState>) -> VaultResult<Vec<String>> {
    search_items_in_state(&state, &query)
}
