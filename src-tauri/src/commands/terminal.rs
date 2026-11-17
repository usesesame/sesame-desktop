use tauri::{AppHandle, State};

use crate::application::browser_fill::{APPROVAL_TOO_SOON, APPROVAL_TOO_SOON_MESSAGE};
use crate::application::cli_broker::{CliApprovalRequestEvent, CliDecisionInput};
use crate::application::terminal_allowances::TerminalAllowanceList;
use crate::terminal::{CliApprovalState, TerminalAllowances, TerminalListener, TerminalToolStatus};
use crate::vault::{VaultResult, VaultState};

#[tauri::command]
pub fn get_pending_terminal_request(
    approvals: State<'_, CliApprovalState>,
) -> Option<CliApprovalRequestEvent> {
    approvals.pending_request()
}

#[tauri::command]
pub fn get_terminal_approval_wait(approvals: State<'_, CliApprovalState>) -> u64 {
    approvals.approval_wait().as_millis() as u64
}

#[tauri::command]
pub fn resolve_terminal_request(
    decision: CliDecisionInput,
    approvals: State<'_, CliApprovalState>,
) -> VaultResult<()> {
    approvals.decide(decision).map_err(|error| match error {
        APPROVAL_TOO_SOON => APPROVAL_TOO_SOON_MESSAGE.to_string(),
        "selectionNotOffered" => "Choose one of the items Sesame offered.".to_string(),
        _ => "This terminal request is no longer waiting in Sesame.".to_string(),
    })
}

#[tauri::command]
pub fn list_terminal_permissions(
    allowances: State<'_, TerminalAllowances>,
    vault: State<'_, VaultState>,
) -> TerminalAllowanceList {
    allowances.list(vault.session_epoch())
}

#[tauri::command]
pub fn forget_terminal_permissions(app: AppHandle) {
    crate::terminal::forget_permissions(&app);
}

#[tauri::command]
pub fn get_terminal_status(listener: State<'_, TerminalListener>) -> TerminalToolStatus {
    listener.status()
}
