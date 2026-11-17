use tauri::{AppHandle, Emitter, Manager};

pub(crate) use crate::application::cli_broker::CliApprovalState;
pub(crate) use crate::application::terminal_allowances::TerminalAllowances;

pub(crate) const PERMISSIONS_CHANGED: &str = "terminal-permissions-changed";

pub(crate) fn forget_permissions(app: &AppHandle) {
    if let Some(allowances) = app.try_state::<TerminalAllowances>() {
        allowances.forget_all();
    }
    let _ = app.emit_to("main", PERMISSIONS_CHANGED, ());
}

pub(crate) fn cancel_pending_approval(app: &AppHandle) {
    if let Some(approvals) = app.try_state::<CliApprovalState>() {
        approvals.cancel_pending();
    }
}
