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

#[cfg(any(target_os = "linux", windows))]
mod listener {
    use std::io;
    use std::path::PathBuf;

    use tauri::{AppHandle, Emitter, Manager};

    use super::{CliApprovalState, TerminalAllowances, PERMISSIONS_CHANGED};
    use crate::adapters::desktop_effects::DesktopHostEffects;
    use crate::adapters::platform::terminal_origin::origin_of;
    use crate::application::cli_broker::{
        CliApprovalCancelledEvent, CliApprovalRequestEvent, CliUnlockEndedEvent,
        CliUnlockRequestEvent,
    };
    use crate::application::cli_requests::{serve_cli_request, CliContext, CliHost};
    use crate::application::terminal_allowances::TerminalOrigin;
    use crate::browser_pipe::TerminalConnection;
    use crate::cli_protocol::CliReply;
    use crate::release::ReleasePresence;
    use crate::vault::VaultState;

    pub(crate) const APPROVAL_REQUEST: &str = "terminal-approval-request";
    pub(crate) const APPROVAL_CANCELLED: &str = "terminal-approval-cancelled";
    pub(crate) const UNLOCK_REQUEST: &str = "terminal-unlock-request";
    pub(crate) const UNLOCK_ENDED: &str = "terminal-unlock-ended";

    struct WindowHost<'a> {
        app: &'a AppHandle,
        connection: &'a TerminalConnection,
    }

    impl CliHost for WindowHost<'_> {
        fn peer_connected(&self) -> bool {
            self.connection.peer().is_connected()
        }

        fn send(&self, reply: &CliReply) -> bool {
            reply
                .to_bytes()
                .is_ok_and(|bytes| self.connection.send(&bytes).is_ok())
        }

        fn unlock_requested(&self, event: &CliUnlockRequestEvent) {
            crate::desktop_shell::show_main_window(self.app);
            let _ = self.app.emit_to("main", UNLOCK_REQUEST, event.clone());
        }

        fn unlock_ended(&self, reason: &'static str) {
            let _ = self.app.emit_to(
                "main",
                UNLOCK_ENDED,
                CliUnlockEndedEvent {
                    reason: reason.to_string(),
                },
            );
        }

        fn approval_requested(&self, event: &CliApprovalRequestEvent) {
            bring_to_foreground(self.app);
            let _ = self.app.emit_to("main", APPROVAL_REQUEST, event.clone());
        }

        fn approval_cancelled(&self, approval_id: &str, reason: &'static str) {
            let _ = self.app.emit_to(
                "main",
                APPROVAL_CANCELLED,
                CliApprovalCancelledEvent {
                    approval_id: approval_id.to_string(),
                    reason: reason.to_string(),
                },
            );
        }

        fn allowances_changed(&self) {
            let _ = self.app.emit_to("main", PERMISSIONS_CHANGED, ());
        }
    }

    fn bring_to_foreground(app: &AppHandle) {
        if let Some(window) = crate::desktop_shell::ensure_main_window(app) {
            app.state::<CliApprovalState>()
                .window_focus_changed(window.is_focused().unwrap_or(false));
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
            let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
        }
    }

    #[cfg(target_os = "linux")]
    fn origin(connection: &TerminalConnection) -> TerminalOrigin {
        origin_of(connection.peer().pid(), connection.peer().start_time())
    }

    #[cfg(windows)]
    fn origin(connection: &TerminalConnection) -> TerminalOrigin {
        origin_of(connection.peer().pid())
    }

    fn handle(app: &AppHandle, payload: &[u8], connection: &TerminalConnection) {
        let origin = origin(connection);
        let vault = app.state::<VaultState>();
        let presence = app.state::<ReleasePresence>();
        let approvals = app.state::<CliApprovalState>();
        let allowances = app.state::<TerminalAllowances>();
        let effects = DesktopHostEffects::new(app);
        let host = WindowHost { app, connection };
        let record_before = vault.release_record.mark();
        let context = CliContext::new(&vault, &presence, &effects, &approvals, &allowances, &host);
        serve_cli_request(&context, payload, &origin);
        if vault.release_record.mark() != record_before {
            crate::commands::announce_release_record(app);
        }
    }

    #[cfg(target_os = "linux")]
    fn expected_client() -> io::Result<PathBuf> {
        std::env::current_exe()
    }

    #[cfg(windows)]
    fn expected_client() -> io::Result<PathBuf> {
        Ok(std::env::current_exe()?
            .with_file_name("cli")
            .join("sesame.exe"))
    }

    pub(crate) fn start(app: AppHandle) -> io::Result<()> {
        let expected_client = expected_client()?;
        std::thread::Builder::new()
            .name("sesame-terminal-broker".into())
            .spawn(move || {
                let server_app = app.clone();
                let _ = crate::browser_pipe::serve_terminal(
                    &expected_client,
                    move |payload, connection| handle(&server_app, &payload, connection),
                );
            })?;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", windows))]
pub(crate) use listener::start;

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn start(_app: AppHandle) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::application::browser_fill::NormalizedOrigin;
    use crate::application::browser_fill_broker::ApprovalRequest;
    use crate::application::cli_broker::{
        ApprovalSubject, CliApprovalRequestEvent, CliCommandKind, CliDecision,
    };
    use crate::cli_protocol::CliErrorCode;
    use std::time::Duration;

    fn subject(request_id: &str) -> ApprovalSubject {
        ApprovalSubject {
            request_id: request_id.to_string(),
            epoch: 1,
            offered: Vec::new(),
            not_found: false,
            terminal_allowed: false,
            event: CliApprovalRequestEvent {
                approval_id: String::new(),
                command: CliCommandKind::List,
                field: None,
                field_hidden: false,
                copy: false,
                candidates: Vec::new(),
                not_found: None,
                terminal: None,
                program: None,
                remote: false,
                can_allow_terminal: false,
                needs_presence: false,
                allowed: false,
                expires_in_ms: 0,
            },
        }
    }

    #[test]
    fn the_desktop_gives_the_browser_and_the_terminal_one_approval_slot() {
        let (browser, terminal) = crate::approval_states();
        let origin = NormalizedOrigin::from_request("https://northwind.example").expect("origin");
        let held = browser
            .begin("fill-wiring-1", origin.clone(), 1, ApprovalRequest::Create)
            .expect("a browser approval");
        assert_eq!(
            terminal.begin(subject("wiring-a")).err(),
            Some(CliErrorCode::Busy)
        );
        browser.revoke(&held.0);

        let offer = terminal.begin(subject("wiring-b")).expect("a free slot");
        let preempting = browser
            .begin("fill-wiring-2", origin, 1, ApprovalRequest::Create)
            .expect("the browser goes first");
        assert_eq!(
            offer.receiver.recv_timeout(Duration::from_secs(1)),
            Ok(CliDecision::Preempted)
        );
        assert!(terminal.pending_request().is_none());
        browser.revoke(&preempting.0);
    }
}
