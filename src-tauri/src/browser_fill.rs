use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::{
    application::browser_replies::{self, BrowserApproval, BrowserReply},
    browser_pipe::PipePeer,
    browser_protocol::{BrowserRequest, BrowserResponse, MAX_NATIVE_MESSAGE_BYTES},
    diagnostics,
    vault::VaultState,
};

pub(crate) use crate::application::browser_fill::{
    BrowserCardRequestEvent, BrowserFillRequestEvent, BrowserIdentityRequestEvent,
    BrowserSaveRequestEvent, BrowserTotpRequestEvent,
};
pub(crate) use crate::application::browser_fill_broker::BrowserFillState;

use crate::application::browser_fill::{ApprovalDecision, ApprovalKind, NormalizedOrigin};
use crate::application::browser_fill_broker::ApprovalEvent;
use crate::application::DesktopEffects;

use crate::browser_host::HOST_FILE_NAME;

const APPROVAL_POLL: Duration = Duration::from_millis(200);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserApprovalCancelledEvent {
    approval_id: String,
    reason: &'static str,
}

pub fn cancel_pending_approvals(app: &tauri::AppHandle) {
    app.state::<BrowserFillState>().cancel_pending();
}

#[allow(clippy::too_many_arguments)]
fn wait_for_decision(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    vault: &VaultState,
    approval_id: &str,
    request_id: &str,
    origin: &NormalizedOrigin,
    epoch: u64,
    deadline: Instant,
    receiver: Receiver<ApprovalDecision>,
    peer: &PipePeer,
    kind: ApprovalKind,
) -> Result<ApprovalDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, kind.connection_closed_code());
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, kind.timeout_code());
            return Err("approvalTimeout");
        }
        if !fill_state.is_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, kind.vault_changed_code());
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub(crate) fn emit_approval_cancelled(
    app: &AppHandle,
    kind: ApprovalKind,
    approval_id: &str,
    reason: &'static str,
) {
    let _ = app.emit(
        kind.cancelled_event(),
        BrowserApprovalCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
}

pub fn start(app: AppHandle) -> io::Result<()> {
    if !crate::browser_host::is_supported() {
        return Ok(());
    }
    let expected_client = std::env::current_exe()?.with_file_name(HOST_FILE_NAME);
    thread::Builder::new()
        .name("sesame-browser-broker".into())
        .spawn(move || {
            diagnostics::record_browser_host_registration(&app, "pipe_server_started");
            let server_app = app.clone();
            if crate::browser_pipe::serve_forever(&expected_client, move |payload, peer| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle_pipe_payload(&server_app, payload, peer)
                })) {
                    Ok(response) => response,
                    Err(_) => {
                        diagnostics::record_browser_host_registration(
                            &server_app,
                            "pipe_handler_panicked",
                        );
                        zeroize::Zeroizing::new(Vec::new())
                    }
                }
            })
            .is_err()
            {
                diagnostics::record_browser_host_registration(&app, "pipe_server_failed");
            }
        })?;
    Ok(())
}

pub fn pending_save(state: State<'_, BrowserFillState>) -> Option<BrowserSaveRequestEvent> {
    state.pending_save_request()
}

pub fn pending(state: State<'_, BrowserFillState>) -> Option<BrowserFillRequestEvent> {
    state.pending_fill_request()
}

pub fn pending_identity(state: State<'_, BrowserFillState>) -> Option<BrowserIdentityRequestEvent> {
    state.pending_identity_request()
}

pub fn pending_card(state: State<'_, BrowserFillState>) -> Option<BrowserCardRequestEvent> {
    state.pending_card_request()
}

pub fn pending_totp(state: State<'_, BrowserFillState>) -> Option<BrowserTotpRequestEvent> {
    state.pending_totp_request()
}

fn handle_pipe_payload(
    app: &AppHandle,
    payload: Vec<u8>,
    peer: &PipePeer,
) -> zeroize::Zeroizing<Vec<u8>> {
    let mut request = match serde_json::from_slice::<BrowserRequest>(&payload) {
        Ok(request) if request.validate() => request,
        _ => {
            return response_bytes(BrowserResponse::error(
                "invalid",
                "Invalid browser request.",
            ))
        }
    };
    let vault = app.state::<VaultState>();
    let fill_state = app.state::<BrowserFillState>();
    let effects = crate::adapters::desktop_effects::DesktopHostEffects::new(app);
    let response = match request.message_type.as_str() {
        "capabilities" => browser_replies::capabilities_response(&request),
        "activate" => activation_response(app, &fill_state, &request),
        "fill" => fill_response(app, &vault, &fill_state, &effects, &request, peer),
        "save" => save_response(app, &vault, &fill_state, &effects, &mut request, peer),
        "identity" => identity_response(app, &vault, &fill_state, &effects, &request, peer),
        "card" => card_response(app, &vault, &fill_state, &effects, &request, peer),
        "totp" => totp_response(app, &vault, &fill_state, &effects, &request, peer),
        _ => BrowserResponse::error_for(&request, "Unsupported browser request."),
    };
    response_bytes(response)
}

fn activation_response(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    request: &BrowserRequest,
) -> BrowserResponse {
    let reply = browser_replies::activation_response_in_state(fill_state, request, Instant::now());
    if reply.show_window {
        crate::desktop_shell::show_main_window(app);
    }
    reply.response
}

fn fill_response(
    app: &AppHandle,
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    match browser_replies::fill_response_in_state(vault, fill_state, effects, request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(offer) => {
            bring_to_foreground(app);
            emit_browser_approval_request(app, &offer.approval);
            let decision = match wait_for_decision(
                app,
                fill_state,
                vault,
                offer.approval.approval_id(),
                &request.request_id,
                offer.approval.origin(),
                offer.approval.epoch(),
                offer.deadline,
                offer.receiver,
                peer,
                offer.approval.kind(),
            ) {
                Ok(decision) => decision,
                Err(reason) => return BrowserResponse::unavailable(request, reason),
            };
            browser_replies::complete_fill_in_state(
                vault,
                effects,
                request,
                &offer.approval,
                decision,
                &|| peer.is_connected(),
            )
        }
    }
}

fn save_response(
    app: &AppHandle,
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &mut BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    match browser_replies::save_response_in_state(vault, fill_state, effects, request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(offer) => {
            bring_to_foreground(app);
            emit_browser_approval_request(app, &offer.approval);
            let decision = match wait_for_decision(
                app,
                fill_state,
                vault,
                offer.approval.approval_id(),
                &request.request_id,
                offer.approval.origin(),
                offer.approval.epoch(),
                offer.deadline,
                offer.receiver,
                peer,
                offer.approval.kind(),
            ) {
                Ok(decision) => decision,
                Err(reason) => {
                    return BrowserResponse::save_unavailable(&request.request_id, reason)
                }
            };
            browser_replies::complete_save_in_state(request, decision)
        }
    }
}

fn card_response(
    app: &AppHandle,
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    match browser_replies::card_response_in_state(vault, fill_state, effects, request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(offer) => {
            bring_to_foreground(app);
            emit_browser_approval_request(app, &offer.approval);
            let decision = match wait_for_decision(
                app,
                fill_state,
                vault,
                offer.approval.approval_id(),
                &request.request_id,
                offer.approval.origin(),
                offer.approval.epoch(),
                offer.deadline,
                offer.receiver,
                peer,
                offer.approval.kind(),
            ) {
                Ok(decision) => decision,
                Err(reason) => {
                    return BrowserResponse::card_unavailable(&request.request_id, reason)
                }
            };
            browser_replies::complete_card_in_state(
                vault,
                effects,
                request,
                &offer.approval,
                decision,
                &|| peer.is_connected(),
            )
        }
    }
}

fn identity_response(
    app: &AppHandle,
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    match browser_replies::identity_response_in_state(vault, fill_state, effects, request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(offer) => {
            bring_to_foreground(app);
            emit_browser_approval_request(app, &offer.approval);
            let decision = match wait_for_decision(
                app,
                fill_state,
                vault,
                offer.approval.approval_id(),
                &request.request_id,
                offer.approval.origin(),
                offer.approval.epoch(),
                offer.deadline,
                offer.receiver,
                peer,
                offer.approval.kind(),
            ) {
                Ok(decision) => decision,
                Err(reason) => {
                    return BrowserResponse::identity_unavailable(&request.request_id, reason)
                }
            };
            browser_replies::complete_identity_in_state(
                vault,
                effects,
                request,
                &offer.approval,
                decision,
                &|| peer.is_connected(),
            )
        }
    }
}

fn totp_response(
    app: &AppHandle,
    vault: &VaultState,
    fill_state: &BrowserFillState,
    effects: &dyn DesktopEffects,
    request: &BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    match browser_replies::totp_response_in_state(vault, fill_state, effects, request) {
        BrowserReply::Response(response) => *response,
        BrowserReply::Approval(offer) => {
            bring_to_foreground(app);
            emit_browser_approval_request(app, &offer.approval);
            let decision = match wait_for_decision(
                app,
                fill_state,
                vault,
                offer.approval.approval_id(),
                &request.request_id,
                offer.approval.origin(),
                offer.approval.epoch(),
                offer.deadline,
                offer.receiver,
                peer,
                offer.approval.kind(),
            ) {
                Ok(decision) => decision,
                Err(reason) => {
                    return BrowserResponse::totp_unavailable(&request.request_id, reason)
                }
            };
            browser_replies::complete_totp_in_state(
                vault,
                effects,
                request,
                &offer.approval,
                decision,
                &|| peer.is_connected(),
            )
        }
    }
}

fn emit_browser_approval_request(app: &AppHandle, approval: &BrowserApproval) {
    match approval.event() {
        ApprovalEvent::Fill(event) => {
            let _ = app.emit("browser-fill-request", event.clone());
        }
        ApprovalEvent::Save(event) => {
            let _ = app.emit("browser-save-request", event.clone());
        }
        ApprovalEvent::Identity(event) => {
            let _ = app.emit("browser-identity-request", event.clone());
        }
        ApprovalEvent::Card(event) => {
            let _ = app.emit("browser-card-request", event.clone());
        }
        ApprovalEvent::Totp(event) => {
            let _ = app.emit("browser-totp-request", event.clone());
        }
    }
}

fn bring_to_foreground(app: &AppHandle) {
    if let Some(window) = crate::desktop_shell::ensure_main_window(app) {
        app.state::<BrowserFillState>()
            .window_focus_changed(window.is_focused().unwrap_or(false));
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
    }
}

fn response_bytes(response: BrowserResponse) -> zeroize::Zeroizing<Vec<u8>> {
    let version = response.version;
    let request_id = response.request_id.clone();
    let bytes = response
        .to_zeroizing_bytes()
        .unwrap_or_else(|_| zeroize::Zeroizing::new(Vec::new()));
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_MESSAGE_BYTES {
        zeroize::Zeroizing::new(
            serde_json::to_vec(&BrowserResponse::error_with_version(
                version,
                &request_id,
                "Browser response unavailable.",
            ))
            .unwrap_or_default(),
        )
    } else {
        bytes
    }
}
