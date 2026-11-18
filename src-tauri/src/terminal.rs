use std::sync::atomic::{AtomicU8, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

pub(crate) use crate::application::cli_broker::CliApprovalState;
pub(crate) use crate::application::terminal_allowances::TerminalAllowances;

pub(crate) const PERMISSIONS_CHANGED: &str = "terminal-permissions-changed";
pub(crate) const STATUS_CHANGED: &str = "terminal-status-changed";

const STARTING: u8 = 0;
const LISTENING: u8 = 1;
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
const STOPPED: u8 = 2;

#[derive(Default)]
pub(crate) struct TerminalListener {
    state: AtomicU8,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TerminalToolStatus {
    supported: bool,
    available: bool,
    served_elsewhere: bool,
    #[ts(type = "'ready' | 'starting' | 'servedElsewhere' | 'failed' | 'unsupported'")]
    code: &'static str,
}

fn tool_status(supported: bool, state: u8, served_elsewhere: bool) -> TerminalToolStatus {
    let code = if !supported {
        "unsupported"
    } else {
        match state {
            LISTENING => "ready",
            STARTING => "starting",
            _ if served_elsewhere => "servedElsewhere",
            _ => "failed",
        }
    };
    TerminalToolStatus {
        supported,
        available: code == "ready",
        served_elsewhere: code == "servedElsewhere",
        code,
    }
}

impl TerminalListener {
    pub(crate) fn status(&self) -> TerminalToolStatus {
        tool_status(
            cfg!(any(target_os = "linux", windows)),
            self.state.load(Ordering::Acquire),
            crate::browser_pipe::terminal_served_elsewhere(),
        )
    }

    fn set(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }
}

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

    use super::{
        CliApprovalState, TerminalAllowances, TerminalListener, LISTENING, PERMISSIONS_CHANGED,
        STATUS_CHANGED, STOPPED,
    };
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
            self.connection.is_connected()
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

    fn stopped(app: &AppHandle) {
        app.state::<TerminalListener>().set(STOPPED);
        crate::diagnostics::record_terminal_listener(
            app,
            if crate::browser_pipe::terminal_served_elsewhere() {
                "pipe_served_elsewhere"
            } else {
                "pipe_server_failed"
            },
        );
        let _ = app.emit_to(
            "main",
            STATUS_CHANGED,
            app.state::<TerminalListener>().status(),
        );
    }

    pub(crate) fn start(app: AppHandle) -> io::Result<()> {
        let started = expected_client().and_then(|expected_client| {
            let thread_app = app.clone();
            std::thread::Builder::new()
                .name("sesame-terminal-broker".into())
                .spawn(move || {
                    let listening_app = thread_app.clone();
                    let server_app = thread_app.clone();
                    let _ = crate::browser_pipe::serve_terminal(
                        &expected_client,
                        move || {
                            listening_app.state::<TerminalListener>().set(LISTENING);
                            crate::diagnostics::record_terminal_listener(
                                &listening_app,
                                "pipe_server_started",
                            );
                            let _ = listening_app.emit_to(
                                "main",
                                STATUS_CHANGED,
                                listening_app.state::<TerminalListener>().status(),
                            );
                        },
                        move |payload, connection| handle(&server_app, &payload, connection),
                    );
                    stopped(&thread_app);
                })
                .map(|_| ())
        });
        if started.is_err() {
            stopped(&app);
        }
        started
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
    use super::*;
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

    #[test]
    fn a_listener_that_stopped_says_whether_another_sesame_holds_the_connection() {
        assert_eq!(tool_status(true, LISTENING, false).code, "ready");
        assert!(tool_status(true, LISTENING, false).available);
        assert_eq!(tool_status(true, STARTING, false).code, "starting");
        let elsewhere = tool_status(true, STOPPED, true);
        assert_eq!(elsewhere.code, "servedElsewhere");
        assert!(elsewhere.served_elsewhere);
        assert!(!elsewhere.available);
        assert_eq!(tool_status(true, STOPPED, false).code, "failed");
        assert_eq!(tool_status(false, LISTENING, false).code, "unsupported");
    }
}
