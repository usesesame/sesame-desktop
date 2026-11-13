use tauri::{AppHandle, Emitter, State, WebviewWindow};

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::adapters::platform::desktop_shell::show_main_window;
use crate::application::quick_access::{
    copy_quick_access_field_in_state, open_quick_access_item_in_state,
    quick_access_status_in_state, require_quick_access, search_quick_access_items_in_state,
    QuickAccessItem, QuickAccessStatus,
};
use crate::release::ReleasePresence;
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn get_quick_access_status(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
) -> VaultResult<QuickAccessStatus> {
    require_quick_access(window.label())?;
    quick_access_status_in_state(&state, &DesktopHostEffects::new(&app))
}

#[tauri::command]
pub fn search_quick_access_items(
    window: WebviewWindow,
    state: State<'_, VaultState>,
    query: String,
) -> VaultResult<Vec<QuickAccessItem>> {
    require_quick_access(window.label())?;
    search_quick_access_items_in_state(&state, &query)
}

#[tauri::command]
pub fn copy_quick_access_field(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    id: String,
    field: String,
    clear_after_ms: Option<u64>,
) -> VaultResult<()> {
    require_quick_access(window.label())?;
    copy_quick_access_field_in_state(
        &state,
        &presence,
        &DesktopHostEffects::new(&app),
        &id,
        &field,
        clear_after_ms,
    )
    .map(|_| ())
}

/// A note, document, or custom record opens in Sesame rather than exposing its
/// contents in a search window.
#[tauri::command]
pub fn open_quick_access_item(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
    id: String,
) -> VaultResult<()> {
    require_quick_access(window.label())?;
    let id = open_quick_access_item_in_state(&state, &id)?;
    let _ = window.hide();
    show_main_window(&app);
    app.emit("quick-access-open-item", id)
        .map_err(|_| "Sesame could not open that item in the main window.".to_string())
}
