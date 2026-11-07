use tauri::{AppHandle, State};

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::application::browser_fill::{
    resolve_browser_card_fill_in_state, resolve_browser_fill_in_state,
    resolve_browser_identity_fill_in_state, resolve_browser_save_in_state,
    resolve_browser_totp_fill_in_state,
};
use crate::application::file_choices::{resolve_path, FilePurpose, FileSelectionState};
use crate::vault::{SaveLoginResult, VaultResult, VaultState};
use crate::{browser_fill, browser_host, diagnostics};

#[tauri::command]
pub fn record_diagnostic(app: AppHandle, input: diagnostics::DiagnosticInput) -> VaultResult<()> {
    diagnostics::record(&app, input)
}

#[tauri::command]
pub fn get_diagnostic_status(app: AppHandle) -> VaultResult<diagnostics::DiagnosticStatus> {
    diagnostics::status(&app)
}

#[tauri::command]
pub fn export_diagnostics(
    app: AppHandle,
    token: Option<String>,
    destination: Option<String>,
    selection: State<'_, FileSelectionState>,
) -> VaultResult<String> {
    let destination = resolve_path(
        &selection,
        token.as_deref(),
        destination.as_deref(),
        FilePurpose::DiagnosticsExport,
        true,
    )?;
    diagnostics::export(&app, &destination)
}

#[tauri::command]
pub fn clear_diagnostics(app: AppHandle) -> VaultResult<()> {
    diagnostics::clear(&app)
}

#[tauri::command]
pub fn get_browser_integration_status() -> VaultResult<browser_host::BrowserIntegrationStatus> {
    Ok(browser_host::status())
}

#[tauri::command]
pub fn repair_browser_integration(
    app: AppHandle,
) -> VaultResult<browser_host::BrowserIntegrationStatus> {
    match browser_host::repair() {
        Ok(status) => {
            diagnostics::record_browser_host_registration(&app, "registration_ok");
            Ok(status)
        }
        Err(error) => {
            diagnostics::record_browser_host_registration(&app, error.diagnostic_code());
            Err(error.message().to_string())
        }
    }
}

#[tauri::command]
pub fn resolve_browser_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    login_id: Option<String>,
) -> VaultResult<()> {
    resolve_browser_fill_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        &approval_id,
        login_id,
    )
}

#[tauri::command]
pub fn get_browser_approval_wait(state: State<'_, browser_fill::BrowserFillState>) -> u64 {
    state.approval_wait().as_millis() as u64
}

#[tauri::command]
pub fn get_pending_browser_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserFillRequestEvent> {
    browser_fill::pending(state)
}

#[tauri::command]
pub fn resolve_browser_save(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    vault: State<'_, VaultState>,
    approval_id: String,
    approved: bool,
    selected_id: Option<String>,
) -> VaultResult<Option<SaveLoginResult>> {
    resolve_browser_save_in_state(
        &state,
        &vault,
        &DesktopHostEffects::new(&app),
        &approval_id,
        approved,
        selected_id,
    )
}

#[tauri::command]
pub fn get_pending_browser_save(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserSaveRequestEvent> {
    browser_fill::pending_save(state)
}

#[tauri::command]
pub fn resolve_browser_identity_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    identity_id: Option<String>,
) -> VaultResult<()> {
    resolve_browser_identity_fill_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        &approval_id,
        identity_id,
    )
}

#[tauri::command]
pub fn get_pending_browser_identity_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserIdentityRequestEvent> {
    browser_fill::pending_identity(state)
}

#[tauri::command]
pub fn resolve_browser_card_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    card_id: Option<String>,
) -> VaultResult<()> {
    resolve_browser_card_fill_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        &approval_id,
        card_id,
    )
}

#[tauri::command]
pub fn get_pending_browser_card_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserCardRequestEvent> {
    browser_fill::pending_card(state)
}

#[tauri::command]
pub fn resolve_browser_totp_fill(
    app: AppHandle,
    state: State<'_, browser_fill::BrowserFillState>,
    approval_id: String,
    login_id: Option<String>,
) -> VaultResult<()> {
    resolve_browser_totp_fill_in_state(
        &state,
        &DesktopHostEffects::new(&app),
        &approval_id,
        login_id,
    )
}

#[tauri::command]
pub fn get_pending_browser_totp_fill(
    state: State<'_, browser_fill::BrowserFillState>,
) -> Option<browser_fill::BrowserTotpRequestEvent> {
    browser_fill::pending_totp(state)
}
