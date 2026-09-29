use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::{
        mpsc::{self, Receiver, SyncSender, TryRecvError},
        Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use url::{Host, Url};
use zeroize::Zeroize;

use crate::{
    browser_pipe::{PeerIdentity, PipePeer},
    browser_protocol::{
        fill_carries_match_kind, parse_card_fields, parse_identity_fields, BrowserRequest,
        BrowserResponse, CardFillFields, IdentityFillFields, LOOKALIKE_PROTOCOL_VERSION,
        MAX_CREDENTIAL_FIELD_BYTES, MAX_NATIVE_MESSAGE_BYTES,
    },
    diagnostics,
    vault::snapshot::{current_totp, totp_from_value},
    vault::{random_id, Card, Identity, TaggedItem, VaultEntry, VaultState},
};

use crate::browser_host::HOST_FILE_NAME;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
const APPROVAL_POLL: Duration = Duration::from_millis(200);
const ACTIVATE_MIN_INTERVAL: Duration = Duration::from_secs(5);
const REPLAY_CACHE_SIZE: usize = 128;
/// How long an explicit "allow this site" choice lasts. Memory only, and never written to disk.
const FILL_GRANT_DURATION: Duration = Duration::from_secs(15 * 60);
const MAX_MATCHING_CANDIDATES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedOrigin {
    scheme: &'static str,
    hostname: String,
    port: u16,
}

impl NormalizedOrigin {
    fn from_request(value: &str) -> Option<Self> {
        let url = Url::parse(value).ok()?;
        if url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        Self::from_url(&url)
    }

    fn from_saved_url(value: &str) -> Option<Self> {
        let url = Url::parse(value.trim()).ok()?;
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        Self::from_url(&url)
    }

    fn from_url(url: &Url) -> Option<Self> {
        let host = url.host()?;
        let local_development_host = matches!(
            &host,
            Host::Domain(domain) if domain.eq_ignore_ascii_case("localhost")
        ) || matches!(&host, Host::Ipv4(address) if address.octets() == [127, 0, 0, 1])
            || matches!(&host, Host::Ipv6(address) if address.is_loopback());
        let scheme = match url.scheme() {
            "https" => "https",
            "http" if local_development_host => "http",
            _ => return None,
        };
        let hostname = match host {
            // A trailing-dot host is a distinct origin; reject it rather than silently matching.
            Host::Domain(domain) if domain.ends_with('.') => return None,
            Host::Domain(domain) => domain.to_ascii_lowercase(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        if hostname.is_empty() || hostname.len() > 253 || hostname.chars().any(char::is_control) {
            return None;
        }
        Some(Self {
            scheme,
            hostname,
            port: url.port_or_known_default()?,
        })
    }

    fn canonical(&self) -> String {
        let hostname = if self.hostname.contains(':') {
            format!("[{}]", self.hostname)
        } else {
            self.hostname.clone()
        };
        if (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80)
        {
            format!("{}://{}", self.scheme, hostname)
        } else {
            format!("{}://{}:{}", self.scheme, hostname, self.port)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginMatchKind {
    Exact,
    WwwAlias,
}

impl OriginMatchKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::WwwAlias => "wwwAlias",
        }
    }
}

fn origin_match_kind(
    saved: &NormalizedOrigin,
    requested: &NormalizedOrigin,
) -> Option<OriginMatchKind> {
    if saved == requested {
        return Some(OriginMatchKind::Exact);
    }
    if saved.scheme != requested.scheme || saved.port != requested.port {
        return None;
    }

    let saved_without_www = saved.hostname.strip_prefix("www.");
    let requested_without_www = requested.hostname.strip_prefix("www.");
    let base = match (saved_without_www, requested_without_www) {
        (Some(saved_base), None) if saved_base == requested.hostname => saved_base,
        (None, Some(requested_base)) if saved.hostname == requested_base => requested_base,
        _ => return None,
    };
    // Do not apply this convenience rule to localhost or single-label hosts.
    base.contains('.').then_some(OriginMatchKind::WwwAlias)
}

#[derive(Clone, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFillCandidate {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) username: String,
    /// Never crosses the pipe to the extension; only the desktop's own approval modal.
    email: String,
    saved_origin: String,
    #[ts(type = "'exact' | 'wwwAlias'")]
    match_kind: &'static str,
}

#[cfg(test)]
pub(crate) fn test_update_candidate(id: &str, saved_origin: &str) -> BrowserFillCandidate {
    BrowserFillCandidate {
        id: id.to_string(),
        title: "Northwind".to_string(),
        username: "fictional-user".to_string(),
        email: String::new(),
        saved_origin: saved_origin.to_string(),
        match_kind: "exact",
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFillRequestEvent {
    approval_id: String,
    origin: String,
    hostname: String,
    candidates: Vec<BrowserFillCandidate>,
    expires_in_seconds: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserApprovalCancelledEvent {
    approval_id: String,
    reason: &'static str,
}

/// `new` versus `update`, decided by the extension from the page's own form structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveKind {
    New,
    Update,
}

impl SaveKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Update => "update",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "new" => Some(Self::New),
            "update" => Some(Self::Update),
            _ => None,
        }
    }
}

/// Display-safe save prompt: the captured password never appears, and `candidates` are exact-origin targets for `update` only.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSaveRequestEvent {
    approval_id: String,
    origin: String,
    hostname: String,
    kind: &'static str,
    title: String,
    username: String,
    candidates: Vec<BrowserFillCandidate>,
    expires_in_seconds: u64,
    expires_at_unix_ms: u64,
}

/// Names only; identity values are read from the vault after the user picks.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityFillCandidate {
    id: String,
    label: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserIdentityRequestEvent {
    approval_id: String,
    origin: String,
    hostname: String,
    requested_fields: Vec<String>,
    candidates: Vec<IdentityFillCandidate>,
    expires_in_seconds: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardFillCandidate {
    id: String,
    title: String,
    brand: String,
    last_four: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCardRequestEvent {
    approval_id: String,
    origin: String,
    hostname: String,
    requested_fields: Vec<String>,
    candidates: Vec<CardFillCandidate>,
    expires_in_seconds: u64,
    expires_at_unix_ms: u64,
}

/// Display fields only: neither the seed nor a derived code enters the prompt.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpFillCandidate {
    id: String,
    title: String,
    username: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTotpRequestEvent {
    approval_id: String,
    origin: String,
    hostname: String,
    candidates: Vec<TotpFillCandidate>,
    expires_in_seconds: u64,
    expires_at_unix_ms: u64,
}

include!("browser_fill_broker.rs");

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
                handle_pipe_payload(&server_app, payload, peer)
            })
            .is_err()
            {
                diagnostics::record_browser_host_registration(&app, "pipe_server_failed");
            }
        })?;
    Ok(())
}

/// Releases the approval after the vault commit succeeds or is declined.
pub fn resolve_save(
    app: &AppHandle,
    state: &BrowserFillState,
    approval_id: &str,
    approved: bool,
) -> Result<(), String> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err("That browser approval is no longer available.".into());
    }
    let decision = if approved {
        ApprovalDecision::Saved
    } else {
        ApprovalDecision::Denied
    };
    match state.decide(approval_id, decision, false) {
        Ok(()) => {
            diagnostics::record_browser_host_registration(
                app,
                if approved {
                    "save_approved"
                } else {
                    "save_denied"
                },
            );
            if !approved {
                emit_approval_cancelled(app, ApprovalKind::Save, approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_approval_cancelled(app, ApprovalKind::Save, approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
}

/// The approval stays registered; the caller must finish with `resolve_save` either way.
pub fn save_payload(state: &BrowserFillState, approval_id: &str) -> Option<SavePayload> {
    state.save_payload_if_bound(approval_id)
}

/// Re-verifies at commit time that the target is still a saved login at this exact origin (or its www. alias).
pub fn verify_update_target(
    entries: &[VaultEntry],
    origin_canonical: &str,
    target_id: &str,
) -> bool {
    let Some(origin) = NormalizedOrigin::from_request(origin_canonical) else {
        return false;
    };
    entries.iter().any(|entry| {
        entry.id == target_id
            && NormalizedOrigin::from_saved_url(&entry.url)
                .as_ref()
                .and_then(|saved| origin_match_kind(saved, &origin))
                .is_some()
    })
}

pub fn pending_save(state: State<'_, BrowserFillState>) -> Option<BrowserSaveRequestEvent> {
    state.pending_save_request()
}

pub fn resolve(
    app: &AppHandle,
    state: State<'_, BrowserFillState>,
    approval_id: String,
    login_id: Option<String>,
    remember: bool,
) -> Result<(), String> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err("That browser approval is no longer available.".into());
    }
    let denied = login_id.is_none();
    let decision = login_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(&approval_id, decision, remember) {
        Ok(()) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "fill_denied"
                } else {
                    "fill_approved"
                },
            );
            if denied {
                emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
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

pub fn resolve_identity(
    app: &AppHandle,
    state: State<'_, BrowserFillState>,
    approval_id: String,
    identity_id: Option<String>,
) -> Result<(), String> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err("That browser approval is no longer available.".into());
    }
    let denied = identity_id.is_none();
    let decision = identity_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(&approval_id, decision, false) {
        Ok(()) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "identity_denied"
                } else {
                    "identity_approved"
                },
            );
            if denied {
                emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
}

pub fn resolve_card(
    app: &AppHandle,
    state: State<'_, BrowserFillState>,
    approval_id: String,
    card_id: Option<String>,
) -> Result<(), String> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err("That browser approval is no longer available.".into());
    }
    let denied = card_id.is_none();
    let decision = card_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(&approval_id, decision, false) {
        Ok(()) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "card_denied"
                } else {
                    "card_approved"
                },
            );
            if denied {
                emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
}

/// Every TOTP release needs its own approval; no grant is ever recorded.
pub fn resolve_totp(
    app: &AppHandle,
    state: State<'_, BrowserFillState>,
    approval_id: String,
    login_id: Option<String>,
) -> Result<(), String> {
    if approval_id.is_empty() || approval_id.len() > 64 {
        return Err("That browser approval is no longer available.".into());
    }
    let denied = login_id.is_none();
    let decision = login_id
        .map(ApprovalDecision::Selected)
        .unwrap_or(ApprovalDecision::Denied);
    match state.decide(&approval_id, decision, false) {
        Ok(()) => {
            diagnostics::record_browser_host_registration(
                app,
                if denied {
                    "totp_denied"
                } else {
                    "totp_approved"
                },
            );
            if denied {
                emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "denied");
            }
            Ok(())
        }
        Err(_) => {
            emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "expired");
            Err("That browser approval expired or is no longer available.".into())
        }
    }
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
    let response = match request.message_type.as_str() {
        "capabilities" => capabilities_response(&request),
        "activate" => activation_response(app, &request),
        "fill" => fill_response(app, &request, peer),
        "save" => save_response(app, &mut request, peer),
        "identity" => identity_response(app, &request, peer),
        "card" => card_response(app, &request, peer),
        "totp" => totp_response(app, &request, peer),
        _ => BrowserResponse::error_for(&request, "Unsupported browser request."),
    };
    response_bytes(response)
}

fn activation_response(app: &AppHandle, request: &BrowserRequest) -> BrowserResponse {
    let state = app.state::<BrowserFillState>();
    if !state.note_activation(Instant::now()) {
        return BrowserResponse::activated(&request.request_id, false);
    }
    crate::desktop_shell::show_main_window(app);
    BrowserResponse::activated(&request.request_id, true)
}

fn capabilities_response(request: &BrowserRequest) -> BrowserResponse {
    BrowserResponse::capabilities(&request.request_id, true)
}

fn fill_response(app: &AppHandle, request: &BrowserRequest, peer: &PipePeer) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "fill_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    let vault = app.state::<VaultState>();
    let (epoch, candidates, lookalike) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => return BrowserResponse::unavailable(request, "approvalUnavailable"),
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "fill_locked");
            return BrowserResponse::unavailable(request, "noMatch");
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => return BrowserResponse::unavailable(request, "approvalUnavailable"),
        };
        let candidates = matching_entries(&payload.entries, &origin);
        let lookalike = if candidates.is_empty() && request.version == LOOKALIKE_PROTOCOL_VERSION {
            lookalike_host(&payload.entries, &origin)
        } else {
            None
        };
        (vault.session_epoch(), candidates, lookalike)
    };
    if candidates.is_empty() {
        if let Some(lookalike) = lookalike {
            return BrowserResponse::lookalike_unavailable(request, lookalike);
        }
        diagnostics::record_browser_host_registration(app, "fill_no_match");
        return BrowserResponse::unavailable(request, "noMatch");
    }
    if candidates.len() > MAX_MATCHING_CANDIDATES {
        return BrowserResponse::unavailable(request, "noMatch");
    }

    let candidate_ids: HashSet<String> = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let fill_state = app.state::<BrowserFillState>();
    let granted = fill_state.granted_login(&peer.identity(), &origin, epoch, &candidate_ids);
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        peer.identity(),
        ApprovalRequest::Fill { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::unavailable(request, reason),
    };

    // A live grant resolves the approval without prompting. Every check after the
    // decision still runs, so the vault, origin, and peer are revalidated as usual.
    if let Some(login_id) = granted {
        if fill_state
            .decide(&approval_id, ApprovalDecision::Selected(login_id), false)
            .is_err()
        {
            fill_state.revoke(&approval_id);
            return BrowserResponse::unavailable(request, "approvalUnavailable");
        }
        diagnostics::record_browser_host_registration(app, "fill_auto_approved");
    } else {
        let event = BrowserFillRequestEvent {
            approval_id: approval_id.clone(),
            origin: origin.canonical(),
            hostname: origin.hostname.clone(),
            candidates,
            expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
            expires_at_unix_ms: approval_expires_at_unix_ms(),
        };
        if fill_state
            .publish(&approval_id, ApprovalEvent::Fill(event.clone()))
            .is_err()
        {
            fill_state.revoke(&approval_id);
            return BrowserResponse::unavailable(request, "approvalUnavailable");
        }
        // Publish before focus change: Chromium closes the popup when Sesame comes forward.
        bring_to_foreground(app);
        // The webview also polls the durable request so a listener race cannot hide the prompt.
        let _ = app.emit("browser-fill-request", event);
    }

    let decision = match wait_for_decision(
        app,
        &fill_state,
        &vault,
        &approval_id,
        &request.request_id,
        &origin,
        epoch,
        deadline,
        receiver,
        peer,
        ApprovalKind::Fill,
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::unavailable(request, reason),
    };
    let login_id = match decision {
        ApprovalDecision::Selected(login_id) => login_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::unavailable(request, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::unavailable(request, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "connectionClosed");
        return BrowserResponse::unavailable(request, "staleRequest");
    }

    // Bindings rechecked after approval under the vault lock; no credential is copied before this.
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => return BrowserResponse::unavailable(request, "approvalUnavailable"),
    };
    if vault.session_epoch() != epoch {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "locked");
    };
    let Ok(item) = session.open_item(&login_id) else {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    let TaggedItem::Login(entry) = &*item else {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    let Some(match_kind) = NormalizedOrigin::from_saved_url(&entry.url)
        .as_ref()
        .and_then(|saved| origin_match_kind(saved, &origin))
    else {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "staleRequest");
    };
    if !credential_fields_valid(entry) {
        emit_approval_cancelled(app, ApprovalKind::Fill, &approval_id, "vaultChanged");
        return BrowserResponse::unavailable(request, "staleRequest");
    }
    if fill_carries_match_kind(request.version) {
        BrowserResponse::fill_with_match_kind(
            request,
            identity_value(entry),
            entry.password.clone(),
            match_kind.as_str(),
        )
    } else {
        BrowserResponse::fill_for(request, identity_value(entry), entry.password.clone())
    }
}

fn identity_value(entry: &VaultEntry) -> String {
    if entry.username.is_empty() {
        entry.email.clone()
    } else {
        entry.username.clone()
    }
}

fn bring_to_foreground(app: &AppHandle) {
    if let Some(window) = crate::desktop_shell::ensure_main_window(app) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
    }
}

/// The secret never leaves the broker; the renderer sees only display fields while the approval is bound.
fn save_response(
    app: &AppHandle,
    request: &mut BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "save_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::save_unavailable(&request.request_id, "staleRequest");
    };
    let Some(kind) = request.kind.as_deref().and_then(SaveKind::parse) else {
        return BrowserResponse::save_unavailable(&request.request_id, "staleRequest");
    };

    let vault = app.state::<VaultState>();
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::save_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "save_locked");
            return BrowserResponse::save_unavailable(&request.request_id, "noMatch");
        };
        // `update` candidates come from the vault, never from the extension.
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::save_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let candidates = match kind {
            SaveKind::New => Vec::new(),
            SaveKind::Update => matching_entries(&payload.entries, &origin),
        };
        (vault.session_epoch(), candidates)
    };
    if kind == SaveKind::Update && candidates.is_empty() {
        diagnostics::record_browser_host_registration(app, "save_update_no_match");
        return BrowserResponse::save_unavailable(&request.request_id, "noMatch");
    }
    if candidates.len() > MAX_MATCHING_CANDIDATES {
        return BrowserResponse::save_unavailable(&request.request_id, "noMatch");
    }

    // Bound to the vault's own input limits so an approved save cannot fail validation later.
    let title = bounded_display(
        request
            .title
            .take()
            .unwrap_or_else(|| origin.hostname.clone())
            .trim(),
        160,
    );
    let username = bounded_display(request.username.take().unwrap_or_default().trim(), 2048);
    let password = zeroize::Zeroizing::new(request.password.take().unwrap_or_default());

    let fill_state = app.state::<BrowserFillState>();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        peer.identity(),
        ApprovalRequest::Save {
            kind,
            title: title.clone(),
            username: username.clone(),
            password,
            candidates: candidates.clone(),
        },
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::save_unavailable(&request.request_id, reason),
    };

    let event = BrowserSaveRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        kind: kind.as_str(),
        title,
        username,
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish(&approval_id, ApprovalEvent::Save(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::save_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-save-request", event);

    match wait_for_decision(
        app,
        &fill_state,
        &vault,
        &approval_id,
        &request.request_id,
        &origin,
        epoch,
        deadline,
        receiver,
        peer,
        ApprovalKind::Save,
    ) {
        Ok(ApprovalDecision::Saved) => BrowserResponse::saved(&request.request_id),
        Ok(ApprovalDecision::Denied) => {
            BrowserResponse::save_unavailable(&request.request_id, "approvalDeclined")
        }
        Ok(_) => BrowserResponse::save_unavailable(&request.request_id, "invalidSelection"),
        Err(reason) => BrowserResponse::save_unavailable(&request.request_id, reason),
    }
}

fn card_response(app: &AppHandle, request: &BrowserRequest, peer: &PipePeer) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "card_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    let Some(requested_fields) = request.fields.as_deref().and_then(parse_card_fields) else {
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    let vault = app.state::<VaultState>();
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::card_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "card_locked");
            return BrowserResponse::card_unavailable(&request.request_id, "noMatch");
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::card_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let candidates = payload
            .cards
            .iter()
            .filter(|card| card_supports_fields(card, &requested_fields))
            .take(MAX_MATCHING_CANDIDATES)
            .map(card_candidate)
            .collect::<Vec<_>>();
        (vault.session_epoch(), candidates)
    };
    if candidates.is_empty() {
        diagnostics::record_browser_host_registration(app, "card_no_match");
        return BrowserResponse::card_unavailable(&request.request_id, "noMatch");
    }
    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let fill_state = app.state::<BrowserFillState>();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        peer.identity(),
        ApprovalRequest::Card { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::card_unavailable(&request.request_id, reason),
    };
    let event = BrowserCardRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        requested_fields: requested_fields.clone(),
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish(&approval_id, ApprovalEvent::Card(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-card-request", event);
    let decision = match wait_for_decision(
        app,
        &fill_state,
        &vault,
        &approval_id,
        &request.request_id,
        &origin,
        epoch,
        deadline,
        receiver,
        peer,
        ApprovalKind::Card,
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::card_unavailable(&request.request_id, reason),
    };
    let card_id = match decision {
        ApprovalDecision::Selected(card_id) => card_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::card_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "connectionClosed");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::card_unavailable(&request.request_id, "approvalUnavailable")
        }
    };
    if vault.session_epoch() != epoch {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&card_id) else {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Card(card) = &*item else {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    };
    if !card_supports_fields(card, &requested_fields) {
        emit_approval_cancelled(app, ApprovalKind::Card, &approval_id, "vaultChanged");
        return BrowserResponse::card_unavailable(&request.request_id, "staleRequest");
    }
    BrowserResponse::card_for(request, selected_card_fields(card, &requested_fields))
}

fn card_candidate(card: &Card) -> CardFillCandidate {
    let digits = card
        .number
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    let last_four = digits
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    CardFillCandidate {
        id: card.id.clone(),
        title: bounded_display(&card.title, 128),
        brand: bounded_display(&card.brand, 64),
        last_four,
    }
}

fn card_supports_fields(card: &Card, requested: &[String]) -> bool {
    requested.iter().all(|field| match field.as_str() {
        "cardholderName" => {
            !card.cardholder_name.is_empty()
                && card.cardholder_name.len() <= MAX_CREDENTIAL_FIELD_BYTES
        }
        "number" => !card.number.is_empty() && card.number.len() <= MAX_CREDENTIAL_FIELD_BYTES,
        "expiryMonth" => {
            !card.expiry_month.is_empty() && card.expiry_month.len() <= MAX_CREDENTIAL_FIELD_BYTES
        }
        "expiryYear" => {
            !card.expiry_year.is_empty() && card.expiry_year.len() <= MAX_CREDENTIAL_FIELD_BYTES
        }
        "securityCode" => {
            !card.security_code.is_empty() && card.security_code.len() <= MAX_CREDENTIAL_FIELD_BYTES
        }
        _ => false,
    })
}

fn selected_card_fields(card: &Card, requested: &[String]) -> CardFillFields {
    let mut fields = CardFillFields::default();
    for key in requested {
        match key.as_str() {
            "cardholderName" => fields.cardholder_name = Some(card.cardholder_name.clone()),
            "number" => fields.number = Some(card.number.clone()),
            "expiryMonth" => fields.expiry_month = Some(card.expiry_month.clone()),
            "expiryYear" => fields.expiry_year = Some(card.expiry_year.clone()),
            "securityCode" => fields.security_code = Some(card.security_code.clone()),
            _ => {}
        }
    }
    fields
}

include!("browser_fill_identity_approval.rs");
include!("browser_fill_totp_approval.rs");

fn approval_expires_at_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(APPROVAL_TIMEOUT)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
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

#[cfg(test)]
mod grant_tests {
    use super::*;

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("origin")
    }

    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn live_peer() -> PeerIdentity {
        crate::browser_pipe::current_process_identity()
    }

    fn begin_fill(
        state: &BrowserFillState,
        request_id: &str,
        epoch: u64,
    ) -> (String, Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
                live_peer(),
                ApprovalRequest::Fill {
                    candidate_ids: ids(&["login-a"]),
                },
            )
            .expect("begin");
        (approval_id, receiver)
    }

    fn begin_card(
        state: &BrowserFillState,
        request_id: &str,
    ) -> (String, Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://checkout.example.test"),
                7,
                live_peer(),
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            )
            .expect("begin card");
        (approval_id, receiver)
    }

    /// Approve once with remember, and the next request for the same origin and login needs no prompt.
    fn approve(state: &BrowserFillState, request_id: &str, epoch: u64, remember: bool) {
        let (approval_id, _receiver) = begin_fill(state, request_id, epoch);
        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("login-a".to_string()),
                remember,
            )
            .expect("decide");
    }

    /// Approve once with remember for a caller-chosen peer identity.
    fn approve_for(state: &BrowserFillState, request_id: &str, epoch: u64, peer: PeerIdentity) {
        let (approval_id, _, _receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
                peer,
                ApprovalRequest::Fill {
                    candidate_ids: ids(&["login-a"]),
                },
            )
            .expect("begin");
        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("login-a".to_string()),
                true,
            )
            .expect("decide");
    }

    #[test]
    fn a_remembered_approval_answers_the_next_request_for_the_same_login() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            Some("login-a".to_string())
        );
    }

    #[test]
    fn an_approval_without_remember_grants_nothing() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, false);
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
    }

    #[test]
    fn a_grant_does_not_cross_to_another_origin() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://other.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
    }

    #[test]
    fn a_grant_does_not_cover_a_login_it_was_not_given_for() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                7,
                &ids(&["login-b"])
            ),
            None
        );
    }

    /// Locking the vault advances the session epoch, so a grant cannot survive it.
    #[test]
    fn a_grant_dies_when_the_session_epoch_moves() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                8,
                &ids(&["login-a"])
            ),
            None
        );
        // The stale grant is pruned rather than left waiting for the epoch to come back.
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
    }

    #[test]
    fn cancelling_pending_approvals_clears_every_grant() {
        let state = BrowserFillState::default();
        approve(&state, "req-1", 7, true);
        state.cancel_pending();
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
    }

    #[test]
    fn a_grant_does_not_transfer_to_another_peer() {
        let state = BrowserFillState::default();
        let granted_peer = live_peer();
        approve_for(&state, "req-1", 7, granted_peer);
        let other_peer = PeerIdentity {
            pid: 0,
            start_time: 0,
        };

        assert_eq!(
            state.granted_login(
                &other_peer,
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
        assert_eq!(
            state.granted_login(
                &granted_peer,
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            Some("login-a".to_string())
        );
    }

    #[test]
    fn a_grant_for_a_peer_that_is_gone_is_cleared() {
        let state = BrowserFillState::default();
        let gone_peer = PeerIdentity {
            pid: u32::MAX,
            start_time: 1,
        };
        approve_for(&state, "req-1", 7, gone_peer);

        assert_eq!(
            state.granted_login(
                &gone_peer,
                &origin("https://example.test"),
                7,
                &ids(&["login-a"])
            ),
            None
        );
        assert!(state.inner.lock().expect("inner").grants.is_empty());
    }

    #[test]
    fn a_card_approval_is_consumed_and_cannot_be_replayed() {
        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_card(&state, "card-request-1");

        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("card-a".to_string()),
                false,
            )
            .expect("approve card");
        assert!(
            matches!(receiver.recv(), Ok(ApprovalDecision::Selected(card_id)) if card_id == "card-a")
        );
        assert!(state.pending_card_request().is_none());
        assert!(matches!(
            state.begin(
                "card-request-1",
                origin("https://checkout.example.test"),
                7,
                live_peer(),
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_card_not_offered_for_approval_is_never_released() {
        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_card(&state, "card-request-2");

        assert_eq!(
            state.decide(
                &approval_id,
                ApprovalDecision::Selected("card-b".to_string()),
                false,
            ),
            Err("selectionNotOffered")
        );
        assert!(matches!(
            receiver.recv(),
            Ok(ApprovalDecision::InvalidSelection)
        ));
        assert!(state.pending_card_request().is_none());
    }

    #[test]
    fn a_second_prompt_is_refused_while_one_waits() {
        let state = BrowserFillState::default();
        let (_approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert!(matches!(
            state.begin(
                "req-2",
                origin("https://example.test"),
                7,
                live_peer(),
                ApprovalRequest::Save {
                    kind: SaveKind::New,
                    title: "Fictional".to_string(),
                    username: String::new(),
                    password: zeroize::Zeroizing::new(String::new()),
                    candidates: Vec::new(),
                },
            ),
            Err("approvalUnavailable")
        ));
        assert!(matches!(
            state.begin(
                "req-1",
                origin("https://example.test"),
                7,
                live_peer(),
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_stale_or_replayed_decision_is_refused() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert_eq!(
            state.decide("not-the-approval", ApprovalDecision::Denied, false),
            Err("approvalExpired")
        );
        assert!(state
            .decide(&approval_id, ApprovalDecision::Denied, false)
            .is_ok());
        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied, false),
            Err("approvalExpired")
        );
    }

    #[test]
    fn an_expired_approval_refuses_every_step() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);
        {
            let mut inner = state.inner.lock().expect("inner");
            let pending = inner.pending.as_mut().expect("pending");
            pending.deadline = Instant::now() - Duration::from_secs(1);
        }

        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied, false),
            Err("approvalExpired")
        );
        assert!(state.save_payload_if_bound(&approval_id).is_none());
        assert!(state.pending_fill_request().is_none());
    }

    #[test]
    fn cancelling_wakes_the_waiter_and_clears_the_binding() {
        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_fill(&state, "req-1", 7);

        state.cancel_pending();

        assert!(matches!(receiver.recv(), Ok(ApprovalDecision::Denied)));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 7));
    }

    #[test]
    fn a_binding_requires_the_same_request_origin_and_epoch() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert!(state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-2", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://other.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 8));
    }

    #[test]
    fn a_save_payload_is_only_returned_for_its_own_pending_save() {
        let state = BrowserFillState::default();
        let (approval_id, _, _receiver) = state
            .begin(
                "save-1",
                origin("https://example.test"),
                7,
                live_peer(),
                ApprovalRequest::Save {
                    kind: SaveKind::Update,
                    title: "Fictional".to_string(),
                    username: "casey".to_string(),
                    password: zeroize::Zeroizing::new("fictional-secret".to_string()),
                    candidates: Vec::new(),
                },
            )
            .expect("begin save");

        let payload = state.save_payload_if_bound(&approval_id).expect("payload");
        assert_eq!(payload.password.as_str(), "fictional-secret");
        assert_eq!(payload.kind, SaveKind::Update);
        assert!(state.save_payload_if_bound("not-the-approval").is_none());

        state
            .decide(&approval_id, ApprovalDecision::Saved, false)
            .expect("decide");
        assert!(state.save_payload_if_bound(&approval_id).is_none());
    }

    #[test]
    fn a_published_prompt_is_readable_until_it_is_decided() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);
        assert!(state.pending_fill_request().is_none());

        let event = BrowserFillRequestEvent {
            approval_id: approval_id.clone(),
            origin: "https://example.test".to_string(),
            hostname: "example.test".to_string(),
            candidates: Vec::new(),
            expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
            expires_at_unix_ms: 0,
        };
        state
            .publish(&approval_id, ApprovalEvent::Fill(event))
            .expect("publish");
        assert!(state.pending_fill_request().is_some());
        assert!(state.pending_save_request().is_none());

        state
            .decide(&approval_id, ApprovalDecision::Denied, false)
            .expect("decide");
        assert!(state.pending_fill_request().is_none());
    }

    #[test]
    fn a_remembered_grant_is_only_recorded_for_a_fill_selection() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_card(&state, "card-request-3");
        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("card-a".to_string()),
                true,
            )
            .expect("decide");
        assert_eq!(
            state.granted_login(
                &live_peer(),
                &origin("https://checkout.example.test"),
                7,
                &ids(&["card-a"])
            ),
            None
        );
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    #[test]
    fn activation_raises_are_rate_limited_to_one_per_interval() {
        let state = BrowserFillState::default();
        let now = Instant::now();

        assert!(state.note_activation(now));
        assert!(!state.note_activation(now));
        assert!(!state.note_activation(now + ACTIVATE_MIN_INTERVAL - Duration::from_millis(1)));
        assert!(state.note_activation(now + ACTIVATE_MIN_INTERVAL));
    }
}

#[cfg(test)]
mod origin_attacks {
    use super::*;

    const CANARY_PASSWORD: &str = "fictional-secret-canary";

    fn request(value: &str) -> Option<NormalizedOrigin> {
        NormalizedOrigin::from_request(value)
    }

    fn saved(value: &str) -> Option<NormalizedOrigin> {
        NormalizedOrigin::from_saved_url(value)
    }

    fn entry(id: &str, url: &str, password: &str) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            title: format!("Entry {id}"),
            username: "casey".to_string(),
            email: "casey@example.test".to_string(),
            password: password.to_string(),
            url: url.to_string(),
            ..VaultEntry::default()
        }
    }

    #[test]
    fn fill_requests_must_be_bare_origins() {
        for rejected in [
            "https://casey:fictional@example.test/",
            "https://casey@example.test/",
            "https://example.test/sign-in",
            "https://example.test/?next=/vault",
            "https://example.test/#settings",
            "ftp://example.test/",
            "http://example.test/",
            "javascript:alert(1)",
            "https://example.test./",
            "file:///etc/fictional",
        ] {
            assert!(
                request(rejected).is_none(),
                "{rejected} was accepted as a fill origin"
            );
        }
    }

    #[test]
    fn saved_urls_cannot_smuggle_credentials_or_a_trailing_dot() {
        assert!(saved("https://casey:fictional@example.test/").is_none());
        assert!(saved("https://casey@example.test/").is_none());
        assert!(saved("https://example.test./").is_none());
        assert!(saved("  https://example.test  ").is_some());
    }

    #[test]
    fn lookalike_origins_never_match_a_saved_site() {
        let cases = [
            ("https://example.test", "https://example.test.evil.test"),
            ("https://example.test", "https://examp1e.test"),
            ("https://example.test", "https://examplextest"),
            ("https://example.test", "https://evil.test"),
            (
                "https://www.example.test",
                "https://www.example.test.evil.test",
            ),
            ("https://example.test", "https://example.test:8443"),
            ("https://example.test:8443", "https://example.test"),
            ("https://example.test", "https://www.not-example.test"),
            ("https://127.0.0.1", "https://127.0.0.1.evil.test"),
            ("https://example.test", "https://[::1]"),
        ];
        for (saved_url, request_url) in cases {
            let saved_origin =
                saved(saved_url).unwrap_or_else(|| panic!("{saved_url} did not parse"));
            let requested = request(request_url)
                .unwrap_or_else(|| panic!("{request_url} did not parse as a request origin"));
            assert!(
                origin_match_kind(&saved_origin, &requested).is_none(),
                "{saved_url} matched {request_url}"
            );
        }
    }

    #[test]
    fn only_exact_origins_and_the_www_alias_match() {
        let matches = [
            ("https://example.test", "https://example.test"),
            ("https://example.test", "https://example.test:443"),
            ("https://EXAMPLE.test", "https://example.test"),
            ("https://www.example.test", "https://example.test"),
            ("https://example.test", "https://www.example.test"),
            ("https://www.example.test", "https://WWW.Example.test"),
        ];
        for (saved_url, request_url) in matches {
            let saved_origin = saved(saved_url).expect("saved origin");
            let requested = request(request_url).expect("request origin");
            let kind = origin_match_kind(&saved_origin, &requested)
                .unwrap_or_else(|| panic!("{saved_url} did not match {request_url}"));
            let expected = if saved_origin == requested {
                "exact"
            } else {
                "wwwAlias"
            };
            assert_eq!(
                kind.as_str(),
                expected,
                "{saved_url} matched {request_url} with the wrong rule"
            );
        }
    }

    #[test]
    fn a_version_five_fill_response_reports_the_rule_that_matched() {
        let cases = [
            ("https://example.test", "https://example.test", "exact"),
            (
                "https://www.example.test",
                "https://example.test",
                "wwwAlias",
            ),
            (
                "https://example.test",
                "https://www.example.test",
                "wwwAlias",
            ),
        ];
        for (saved_url, request_url, expected) in cases {
            let saved_origin = saved(saved_url).expect("saved origin");
            let requested = request(request_url).expect("request origin");
            let kind = origin_match_kind(&saved_origin, &requested)
                .unwrap_or_else(|| panic!("{saved_url} did not match {request_url}"));
            let fill = BrowserRequest {
                version: LOOKALIKE_PROTOCOL_VERSION,
                message_type: "fill".to_string(),
                request_id: "fill-1".to_string(),
                origin: Some(request_url.to_string()),
                fields: None,
                username: None,
                password: None,
                title: None,
                kind: None,
            };
            assert!(fill.validate());

            let response = BrowserResponse::fill_with_match_kind(
                &fill,
                "person@example.test".to_string(),
                "fictional-example-value".to_string(),
                kind.as_str(),
            );
            assert_eq!(response.match_kind.as_deref(), Some(expected));
            assert!(response.validate_for(&fill));
            let wire = String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec())
                .expect("utf8");
            assert!(wire.contains(&format!("\"matchKind\":\"{expected}\"")));
        }
    }

    #[test]
    fn the_candidate_labels_match_the_fill_match_kinds() {
        let entries = vec![
            entry("login-exact", "https://example.test", CANARY_PASSWORD),
            entry("login-www", "https://www.example.test", CANARY_PASSWORD),
        ];
        let candidates =
            matching_entries(&entries, &request("https://example.test").expect("origin"));

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| (candidate.id.as_str(), candidate.match_kind))
                .collect::<Vec<_>>(),
            vec![
                ("login-exact", OriginMatchKind::Exact.as_str()),
                ("login-www", OriginMatchKind::WwwAlias.as_str()),
            ]
        );
    }

    #[test]
    fn http_is_local_development_only() {
        assert!(request("http://localhost:3000/").is_some());
        assert!(request("http://127.0.0.1:3000/").is_some());
        assert!(request("http://[::1]:3000/").is_some());
        assert!(request("http://example.test/").is_none());
        assert!(request("http://192.168.1.10/").is_none());

        let local = saved("http://localhost:3000/").expect("local saved origin");
        let loopback_http = saved("http://[::1]/").expect("loopback saved origin");
        assert!(
            origin_match_kind(&local, &request("http://localhost:3000/").expect("local")).is_some()
        );
        assert!(origin_match_kind(
            &loopback_http,
            &request("https://[::1]/").expect("loopback https")
        )
        .is_none());
    }

    #[test]
    fn a_login_only_fills_its_own_site() {
        let entries = vec![
            entry("login-bank", "https://bank.test", CANARY_PASSWORD),
            entry("login-evil", "https://bank.test.evil.test", CANARY_PASSWORD),
        ];
        let requested = request("https://bank.test").expect("request origin");

        let candidates = matching_entries(&entries, &requested);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.id.as_str())
                .collect::<Vec<_>>(),
            vec!["login-bank"]
        );
    }

    #[test]
    fn a_login_without_a_usable_password_never_fills() {
        let oversized_username = {
            let mut value = entry("login-huge-user", "https://example.test", CANARY_PASSWORD);
            value.username = "u".repeat(MAX_CREDENTIAL_FIELD_BYTES + 1);
            value
        };
        let entries = vec![
            entry("login-empty", "https://example.test", ""),
            entry(
                "login-huge-password",
                "https://example.test",
                &"A".repeat(MAX_CREDENTIAL_FIELD_BYTES + 1),
            ),
            oversized_username,
        ];

        let candidates =
            matching_entries(&entries, &request("https://example.test").expect("origin"));

        assert!(candidates.is_empty());
    }

    #[test]
    fn a_candidate_carries_no_secret() {
        let entries = vec![entry("login-a", "https://example.test", CANARY_PASSWORD)];

        let candidates =
            matching_entries(&entries, &request("https://example.test").expect("origin"));

        let wire = serde_json::to_string(&candidates).expect("serialized candidates");
        assert!(!wire.contains(CANARY_PASSWORD));
        assert!(wire.contains("casey"));
    }

    #[test]
    fn the_candidate_list_is_bounded() {
        let entries: Vec<VaultEntry> = (0..64)
            .map(|index| {
                entry(
                    &format!("login-{index}"),
                    "https://example.test",
                    CANARY_PASSWORD,
                )
            })
            .collect();

        let candidates =
            matching_entries(&entries, &request("https://example.test").expect("origin"));

        assert_eq!(candidates.len(), MAX_MATCHING_CANDIDATES);
    }
}

#[cfg(test)]
mod totp_flow_tests {
    use super::*;
    use crate::browser_protocol::TOTP_PROTOCOL_VERSION;

    const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("origin")
    }

    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn live_peer() -> PeerIdentity {
        crate::browser_pipe::current_process_identity()
    }

    fn totp_entry(id: &str, url: &str, seed: Option<&str>) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            title: format!("Entry {id}"),
            username: "casey".to_string(),
            url: url.to_string(),
            totp: seed.map(str::to_string),
            ..VaultEntry::default()
        }
    }

    fn totp_request(origin_url: &str) -> BrowserRequest {
        BrowserRequest {
            version: TOTP_PROTOCOL_VERSION,
            message_type: "totp".to_string(),
            request_id: "totp-1".to_string(),
            origin: Some(origin_url.to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    fn begin_totp(
        state: &BrowserFillState,
        request_id: &str,
        epoch: u64,
    ) -> (String, Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
                live_peer(),
                ApprovalRequest::Totp {
                    candidate_ids: ids(&["login-a"]),
                },
            )
            .expect("begin totp");
        (approval_id, receiver)
    }

    #[test]
    fn a_totp_request_only_offers_logins_saved_at_that_origin() {
        let entries = vec![
            totp_entry("login-a", "https://bank.test", Some(RFC_KEY)),
            totp_entry("login-other", "https://other.test", Some(RFC_KEY)),
            totp_entry(
                "login-lookalike",
                "https://bank.test.evil.test",
                Some(RFC_KEY),
            ),
            totp_entry("login-trailing-dot", "https://bank.test./", Some(RFC_KEY)),
            totp_entry("login-port", "https://bank.test:8443", Some(RFC_KEY)),
            totp_entry("login-http", "http://bank.test", Some(RFC_KEY)),
            totp_entry("login-www", "https://www.bank.test", Some(RFC_KEY)),
            totp_entry("login-local-http", "http://localhost:3000", Some(RFC_KEY)),
        ];

        let offered = |value: &str| {
            matching_totp_entries(&entries, &origin(value))
                .into_iter()
                .map(|candidate| candidate.id)
                .collect::<Vec<_>>()
        };

        assert_eq!(offered("https://bank.test"), vec!["login-a", "login-www"]);
        assert_eq!(
            offered("https://www.bank.test"),
            vec!["login-www", "login-a"]
        );
        assert_eq!(offered("https://other.test"), vec!["login-other"]);
        assert_eq!(
            offered("https://bank.test.evil.test"),
            vec!["login-lookalike"]
        );
        assert_eq!(offered("https://bank.test:8443"), vec!["login-port"]);
        assert_eq!(offered("http://localhost:3000"), vec!["login-local-http"]);
        assert!(offered("https://localhost:3000").is_empty());
        assert!(offered("https://bank.test.evil.test.evil.test").is_empty());
        assert!(NormalizedOrigin::from_request("https://bank.test./").is_none());
        assert!(
            !offered("https://bank.test").contains(&"login-trailing-dot".to_string()),
            "a trailing-dot login leaked into the candidates"
        );
    }

    #[test]
    fn a_login_without_a_usable_totp_secret_is_never_offered_or_selected() {
        let entries = vec![
            totp_entry("login-nothing", "https://example.test", None),
            totp_entry("login-empty", "https://example.test", Some("")),
            totp_entry("login-short", "https://example.test", Some("GEZDGNBV")),
            totp_entry(
                "login-garbage",
                "https://example.test",
                Some("not base32 at all!!"),
            ),
            totp_entry("login-valid", "https://example.test", Some(RFC_KEY)),
        ];

        let candidates = matching_totp_entries(&entries, &origin("https://example.test"));
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.id.as_str())
                .collect::<Vec<_>>(),
            vec!["login-valid"]
        );

        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_totp(&state, "totp-1", 7);
        assert_eq!(
            state.decide(
                &approval_id,
                ApprovalDecision::Selected("login-short".to_string()),
                false,
            ),
            Err("selectionNotOffered")
        );
        assert!(matches!(
            receiver.recv(),
            Ok(ApprovalDecision::InvalidSelection)
        ));
        assert!(state.pending_totp_request().is_none());
    }

    #[test]
    fn a_totp_approval_is_consumed_and_cannot_be_replayed() {
        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_totp(&state, "totp-1", 7);
        let event = BrowserTotpRequestEvent {
            approval_id: approval_id.clone(),
            origin: "https://example.test".to_string(),
            hostname: "example.test".to_string(),
            candidates: Vec::new(),
            expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
            expires_at_unix_ms: 0,
        };
        state
            .publish(&approval_id, ApprovalEvent::Totp(event))
            .expect("publish");
        assert!(state.pending_totp_request().is_some());

        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("login-a".to_string()),
                false,
            )
            .expect("decide");
        assert!(
            matches!(receiver.recv(), Ok(ApprovalDecision::Selected(login_id)) if login_id == "login-a")
        );
        assert!(state.pending_totp_request().is_none());
        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied, false),
            Err("approvalExpired")
        );
        assert!(matches!(
            state.begin(
                "totp-1",
                origin("https://example.test"),
                7,
                live_peer(),
                ApprovalRequest::Totp {
                    candidate_ids: ids(&["login-a"]),
                },
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_second_totp_prompt_is_refused_while_one_waits() {
        let state = BrowserFillState::default();
        let (_approval_id, _receiver) = begin_totp(&state, "totp-1", 7);

        assert!(matches!(
            state.begin(
                "totp-2",
                origin("https://example.test"),
                7,
                live_peer(),
                ApprovalRequest::Totp {
                    candidate_ids: ids(&["login-a"]),
                },
            ),
            Err("approvalUnavailable")
        ));
    }

    #[test]
    fn an_expired_totp_approval_refuses_every_step() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_totp(&state, "totp-1", 7);
        {
            let mut inner = state.inner.lock().expect("inner");
            let pending = inner.pending.as_mut().expect("pending");
            pending.deadline = Instant::now() - Duration::from_secs(1);
        }

        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied, false),
            Err("approvalExpired")
        );
        assert!(state.pending_totp_request().is_none());
        assert_eq!(
            state.publish(
                &approval_id,
                ApprovalEvent::Totp(BrowserTotpRequestEvent {
                    approval_id: approval_id.clone(),
                    origin: "https://example.test".to_string(),
                    hostname: "example.test".to_string(),
                    candidates: Vec::new(),
                    expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
                    expires_at_unix_ms: 0,
                }),
            ),
            Err("approvalExpired")
        );
    }

    #[test]
    fn a_totp_binding_requires_the_same_request_origin_and_epoch() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_totp(&state, "totp-1", 7);

        assert!(state.is_bound(&approval_id, "totp-1", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "totp-2", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "totp-1", &origin("https://other.test"), 7));
        assert!(!state.is_bound(&approval_id, "totp-1", &origin("https://example.test"), 8));
    }

    #[test]
    fn the_released_code_equals_current_totp_for_the_approved_secret() {
        let request = totp_request("https://example.test");
        assert!(request.validate());

        let mut matched = false;
        for _ in 0..4 {
            let before = current_totp(RFC_KEY).expect("a current code");
            let response = totp_response_for_secret(&request, RFC_KEY).expect("a response");
            let after = current_totp(RFC_KEY).expect("a current code");
            if before != after {
                continue;
            }
            assert_eq!(response.version, TOTP_PROTOCOL_VERSION);
            assert_eq!(response.message_type, "totp");
            assert_eq!(response.code.as_deref(), Some(before.0.as_str()));
            assert_eq!(response.remaining_seconds, Some(before.1));
            assert!((1..=before.2).contains(&before.1));
            assert!(response.validate_for(&request));
            let wire = String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec())
                .expect("utf8");
            assert!(wire.contains(&before.0));
            assert!(!wire.contains(RFC_KEY));
            matched = true;
            break;
        }
        assert!(
            matched,
            "the clock crossed a window boundary on every attempt"
        );

        assert!(totp_response_for_secret(&request, "").is_none());
        assert!(totp_response_for_secret(&request, "not base32 at all!!").is_none());
    }

    #[test]
    fn a_totp_prompt_and_candidate_carry_no_secret() {
        let candidate = TotpFillCandidate {
            id: "login-a".to_string(),
            title: "Northwind".to_string(),
            username: "casey".to_string(),
        };
        let event = BrowserTotpRequestEvent {
            approval_id: "approval-a".to_string(),
            origin: "https://example.test".to_string(),
            hostname: "example.test".to_string(),
            candidates: vec![candidate],
            expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
            expires_at_unix_ms: 0,
        };
        let wire = serde_json::to_string(&event).expect("serialized prompt");
        assert!(!wire.contains(RFC_KEY));
        assert!(wire.contains("casey"));
    }

    #[test]
    fn the_totp_candidate_list_is_bounded() {
        let entries: Vec<VaultEntry> = (0..64)
            .map(|index| {
                totp_entry(
                    &format!("login-{index}"),
                    "https://example.test",
                    Some(RFC_KEY),
                )
            })
            .collect();

        let candidates = matching_totp_entries(&entries, &origin("https://example.test"));

        assert_eq!(candidates.len(), MAX_MATCHING_CANDIDATES);
    }
}
